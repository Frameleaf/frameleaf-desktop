use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use tauri::{AppHandle, Manager, WebviewWindow};
use tauri_plugin_updater::{Error, Update, UpdaterExt};

use crate::{host_setup::HostSetup, require_local, runtime_store};

const PENDING: &str = "pending.json";
const RECEIPT: &str = "last-verified-restart.json";
const MAX_RESTART_DELAY: u64 = 60 * 60;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingRestart {
    previous_version: String,
    expected_version: String,
    executable_location_sha256: String,
    initiating_pid: u32,
    prepared_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RestartReceipt<'a> {
    previous_version: &'a str,
    installed_version: &'a str,
    verified_at: u64,
}

fn unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| "update_restart_clock_unavailable".into())
}

fn executable_id(app: &AppHandle) -> Result<String, String> {
    // Tauri resolves AppImage relaunches to the installed image, not its transient mount.
    let path = tauri::process::current_binary(&app.env())
        .map_err(|_| "update_restart_executable_unavailable")?;
    if !path.is_absolute() {
        return Err("update_restart_executable_unavailable".into());
    }
    Ok(format!(
        "{:x}",
        Sha256::digest(path.as_os_str().as_encoded_bytes())
    ))
}

fn diagnostics_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_local_data_dir()
        .map(|path| path.join("update-diagnostics"))
        .map_err(|_| "update_restart_diagnostics_unavailable".into())
}

fn write_record(directory: &Path, name: &str, record: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(record).map_err(|_| "update_restart_record_invalid")?;
    let temporary = directory.join(format!(".update-{}.json", uuid::Uuid::new_v4()));
    let result = runtime_store::write_new(&temporary, &bytes).and_then(|()| {
        fs::rename(&temporary, directory.join(name))
            .map_err(|_| "update_restart_record_unavailable".into())
    });
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn prepare_restart(app: &AppHandle, update: &Update) -> Result<PathBuf, String> {
    let previous_version = app.package_info().version.to_string();
    if update.current_version != previous_version || update.version == previous_version {
        return Err("update_restart_version_invalid".into());
    }
    let directory = diagnostics_path(app)?;
    let parent = directory
        .parent()
        .ok_or("update_restart_diagnostics_unavailable")?;
    if !parent.exists() {
        runtime_store::private_directory(parent)?;
    }
    runtime_store::private_directory(&directory)?;
    write_record(
        &directory,
        PENDING,
        &PendingRestart {
            previous_version,
            expected_version: update.version.clone(),
            executable_location_sha256: executable_id(app)?,
            initiating_pid: std::process::id(),
            prepared_at: unix_seconds()?,
        },
    )?;
    Ok(directory.join(PENDING))
}

fn confirm_restart(
    directory: &Path,
    installed_version: &str,
    executable: &str,
    pid: u32,
    now: u64,
) -> Result<bool, String> {
    let path = directory.join(PENDING);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("update_restart_record_unavailable".into()),
        Ok(_) => {}
    }
    runtime_store::private_directory(directory)?;
    let raw = runtime_store::read_bounded(&path, 2048);
    // Consume the attempt even if startup is stale, incomplete or cannot be attributed.
    fs::remove_file(&path).map_err(|_| "update_restart_record_unavailable")?;
    let record: PendingRestart =
        serde_json::from_slice(&raw?).map_err(|_| "update_restart_record_invalid")?;
    if record.expected_version != installed_version
        || record.previous_version == installed_version
        || record.executable_location_sha256 != executable
        || record.initiating_pid == pid
        || now
            .checked_sub(record.prepared_at)
            .is_none_or(|age| age > MAX_RESTART_DELAY)
    {
        return Ok(false);
    }
    write_record(
        directory,
        RECEIPT,
        &RestartReceipt {
            previous_version: &record.previous_version,
            installed_version,
            verified_at: now,
        },
    )?;
    Ok(true)
}

pub(crate) fn observe_restart(app: &AppHandle) {
    if cfg!(debug_assertions) || tauri::utils::platform::bundle_type().is_none() {
        return;
    }
    let outcome = (|| {
        let directory = diagnostics_path(app)?;
        if !directory
            .join(PENDING)
            .try_exists()
            .map_err(|_| "update_restart_record_unavailable")?
        {
            return Ok(false);
        }
        confirm_restart(
            &directory,
            &app.package_info().version.to_string(),
            &executable_id(app)?,
            std::process::id(),
            unix_seconds()?,
        )
    })();
    match outcome {
        Ok(true) => eprintln!(
            "Desktop update restart verified: {}",
            app.package_info().version
        ),
        Ok(false) => {}
        Err(_) => eprintln!("Desktop update restart receipt unavailable"),
    }
}

async fn latest(app: &AppHandle) -> Result<Option<Update>, String> {
    if cfg!(debug_assertions) || tauri::utils::platform::bundle_type().is_none() {
        return Ok(None);
    }
    let updater = app
        .updater_builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "update_check_failed")?;
    match updater.check().await {
        Ok(update) => Ok(update),
        Err(Error::ReleaseNotFound | Error::TargetsNotFound(_)) => Ok(None),
        Err(error) => {
            eprintln!("Desktop update check failed: {error}");
            Err("update_check_failed".into())
        }
    }
}

#[tauri::command]
pub(crate) async fn check_desktop_update(
    window: WebviewWindow,
    app: AppHandle,
) -> Result<Option<String>, String> {
    require_local(&window)?;
    Ok(latest(&app).await?.map(|update| update.version))
}

#[tauri::command]
pub(crate) async fn install_desktop_update(
    window: WebviewWindow,
    app: AppHandle,
    version: String,
) -> Result<(), String> {
    require_local(&window)?;
    let host = app.state::<HostSetup>();
    let _owner = host.lock_for_update()?;
    let media_copy = app
        .state::<crate::media_copy::MediaCopy>()
        .lock_for_update()?;
    let mut update = latest(&app)
        .await?
        .filter(|update| update.version == version)
        .ok_or("update_changed")?;
    let url = &update.download_url;
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.port().is_some()
        || !url
            .path()
            .starts_with("/Frameleaf/frameleaf-desktop/releases/download/")
    {
        return Err("update_install_failed".into());
    }
    update.timeout = Some(Duration::from_secs(60 * 60));
    let bytes = update.download(|_, _| {}, || {}).await.map_err(|error| {
        eprintln!("Desktop update download failed: {error}");
        "update_install_failed"
    })?;
    let restart = app.clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        let _media_copy = media_copy;
        // Download verifies the signed version. Prepare the one-shot handoff before
        // installation because the Windows updater exits after launching its installer.
        let pending = prepare_restart(&restart, &update).ok();
        if pending.is_none() {
            eprintln!("Desktop update restart handoff unavailable");
        }
        update.install(bytes).map_err(|error| {
            if let Some(path) = pending {
                let _ = fs::remove_file(path);
            }
            eprintln!("Desktop update installation failed: {error}");
            "update_install_failed"
        })?;
        // Keep the local host locked until the app has exited.
        restart.restart();
    })
    .await
    .map_err(|_| "update_install_failed")?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> runtime_store::Staging {
        runtime_store::Staging::create(
            std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-update-restart-{}", uuid::Uuid::new_v4())),
        )
        .unwrap()
    }

    fn pending(directory: &Path) {
        write_record(
            directory,
            PENDING,
            &PendingRestart {
                previous_version: "1.0.0".into(),
                expected_version: "1.0.1".into(),
                executable_location_sha256: "installed-location".into(),
                initiating_pid: 41,
                prepared_at: 100,
            },
        )
        .unwrap();
    }

    #[test]
    fn verified_new_process_replaces_the_local_receipt_only_once() {
        let root = fixture();
        let directory = root.path();
        pending(directory);
        assert!(!directory.join(RECEIPT).exists());
        assert!(confirm_restart(directory, "1.0.1", "installed-location", 42, 103).unwrap());
        let expected = serde_json::json!({
            "previousVersion": "1.0.0", "installedVersion": "1.0.1", "verifiedAt": 103
        });
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(directory.join(RECEIPT)).unwrap()
            )
            .unwrap(),
            expected
        );
        assert!(!confirm_restart(directory, "1.0.1", "installed-location", 43, 104).unwrap());
    }

    #[test]
    fn old_wrong_same_process_and_expired_launches_do_not_confirm() {
        let root = fixture();
        let directory = root.path();
        for (version, path, pid, now) in [
            ("1.0.0", "installed-location", 42, 103),
            ("1.0.2", "installed-location", 42, 103),
            ("1.0.1", "other-location", 42, 103),
            ("1.0.1", "installed-location", 41, 103),
            ("1.0.1", "installed-location", 42, 99),
            ("1.0.1", "installed-location", 42, 101 + MAX_RESTART_DELAY),
        ] {
            pending(directory);
            assert!(!confirm_restart(directory, version, path, pid, now).unwrap());
            assert!(!directory.join(PENDING).exists());
            assert!(!directory.join(RECEIPT).exists());
        }
    }
}
