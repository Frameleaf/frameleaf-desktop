use std::time::Duration;

use tauri::{AppHandle, Manager, WebviewWindow};
use tauri_plugin_updater::{Error, Update, UpdaterExt};

use crate::{host_setup::HostSetup, require_local};

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
    // Windows stops the library itself, below, once the update is downloaded. Everywhere else
    // the library must already be idle.
    #[cfg(not(windows))]
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
    // Installing ends this app and, on Windows, everything in Manager's job. The photo server
    // and database are closed in order first; without the journal's proof that they are,
    // nothing is installed and the reason is returned. The gate is then taken as everywhere
    // else, and still refuses anything it cannot prove idle.
    #[cfg(windows)]
    let _owner = {
        host.stop_for_update().await.map_err(stop_refused)?;
        host.lock_for_update()?
    };
    let restart = app.clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        let _media_copy = media_copy;
        update.install(bytes).map_err(|error| {
            eprintln!("Desktop update installation failed: {error}");
            "update_install_failed"
        })?;
        // Keep the local host locked until the app has exited.
        restart.restart();
    })
    .await
    .map_err(|_| "update_install_failed")?
}

/// The update was not installed because the library on this computer could not be stopped
/// first; `code` is why, and the interface says both.
#[cfg(any(windows, test))]
fn stop_refused(code: String) -> String {
    format!("update_library_stop_{code}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_refused_library_stop_keeps_its_reason() {
        assert_eq!(
            super::stop_refused("manager_pairing_required".into()),
            "update_library_stop_manager_pairing_required"
        );
    }
}
