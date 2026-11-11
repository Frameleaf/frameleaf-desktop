//! Owner-scoped preservation copies. Archive paths are used only to verify ZIP entries.
mod archive;
mod destination;

use crate::{connection::SavedConnection, require_local, transport, DesktopState};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tauri::{AppHandle, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

const TRANSFER: &str = "media_copy_download_failed";
const CANCELLED: &str = "media_copy_cancelled";
const SPACE_RESERVE: u64 = 64 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct MediaCopy {
    active: Arc<tokio::sync::Mutex<()>>,
    cancelled: Arc<AtomicBool>,
}

impl MediaCopy {
    pub(crate) fn is_active(&self) -> bool {
        self.active.try_lock().is_err()
    }

    pub(crate) fn lock_for_update(&self) -> Result<tokio::sync::OwnedMutexGuard<()>, String> {
        self.active
            .clone()
            .try_lock_owned()
            .map_err(|_| "update_media_copy_active".into())
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Package {
    id: Uuid,
    name: String,
    created_at: String,
    origin: String,
    status: String,
    downloadable: bool,
    locked_content: bool,
    manifest: Option<PackageManifest>,
    verification: Option<PackageVerification>,
}

#[derive(Deserialize, Serialize)]
struct PackageManifest {
    complete: bool,
    exported: usize,
}

#[derive(Deserialize, Serialize)]
struct PackageVerification {
    status: String,
}

impl Package {
    fn eligible(&self) -> bool {
        self.id.get_version_num() == 7
            && self.name.len() <= 1024
            && self.created_at.len() <= 64
            && self.origin == "export"
            && self.status == "ready"
            && self.downloadable
            && !self.locked_content
            && self
                .manifest
                .as_ref()
                .is_some_and(|manifest| manifest.complete && manifest.exported > 0)
            && self
                .verification
                .as_ref()
                .is_some_and(|verification| verification.status == "verified")
    }
}

fn same_session(current: Option<&SavedConnection>, saved: &SavedConnection) -> bool {
    current.is_some_and(|current| {
        current.server == saved.server
            && current.server_id == saved.server_id
            && current.account_id == saved.account_id
            && current.token == saved.token
    })
}

async fn client(saved: &SavedConnection) -> Result<(reqwest::Client, url::Url), String> {
    let client = transport::client()?;
    let origin = crate::normalize_server(&saved.server)?;
    if saved.server_id.is_empty() || transport::capabilities(&client, saved).await?.is_none() {
        return Err("media_copy_server_unavailable".into());
    }
    Ok((client, origin))
}

#[tauri::command]
pub(crate) async fn preservation_copy_packages(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<Vec<Package>, String> {
    require_local(&window)?;
    let saved = state.0.lock().await.clone().ok_or("sign_in_required")?;
    let (client, origin) = client(&saved).await?;
    let response = client
        .get(origin.join("api/preservation/packages").unwrap())
        .bearer_auth(&saved.token)
        .send()
        .await
        .map_err(|_| TRANSFER)?;
    let mut packages: Vec<Package> = transport::json_limit(response, 4 * 1024 * 1024).await?;
    if !same_session(state.0.lock().await.as_ref(), &saved) {
        return Err("media_copy_session_changed".into());
    }
    packages.retain(Package::eligible);
    Ok(packages)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SavedCopy {
    path: String,
    originals: usize,
    bytes: u64,
}

#[tauri::command]
pub(crate) async fn save_preservation_copy(
    app: AppHandle,
    window: WebviewWindow,
    package_id: String,
    state: State<'_, DesktopState>,
    job: State<'_, MediaCopy>,
) -> Result<Option<SavedCopy>, String> {
    require_local(&window)?;
    let package = Uuid::parse_str(&package_id)
        .ok()
        .filter(|id| id.get_version_num() == 7 && id.to_string() == package_id)
        .ok_or("media_copy_package_unavailable")?;
    let active = job
        .active
        .clone()
        .try_lock_owned()
        .map_err(|_| "media_copy_busy")?;
    let saved = {
        let state = state.0.lock().await;
        let saved = state.as_ref().ok_or("sign_in_required")?.clone();
        job.cancelled.store(false, Ordering::Release);
        saved
    };
    let cancelled = job.cancelled.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _active = active;
        let Some(path) = app
            .dialog()
            .file()
            .set_parent(&window)
            .set_title("Choose a folder for the verified media copy")
            .blocking_pick_folder()
        else {
            return Ok(None);
        };
        let path = path
            .into_path()
            .map_err(|_| "media_copy_destination_invalid")?;
        tauri::async_runtime::block_on(copy(&app, &saved, package, path, &cancelled)).map(Some)
    })
    .await
    .map_err(|_| TRANSFER)?
}

#[tauri::command]
pub(crate) fn cancel_preservation_copy(
    window: WebviewWindow,
    job: State<'_, MediaCopy>,
) -> Result<(), String> {
    require_local(&window)?;
    job.cancel();
    Ok(())
}

async fn chunk(
    response: &mut reqwest::Response,
    cancelled: &AtomicBool,
) -> Result<Option<impl AsRef<[u8]>>, &'static str> {
    tokio::select! {
        value = response.chunk() => value.map_err(|_| TRANSFER),
        _ = async {
            while !cancelled.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        } => Err(CANCELLED),
    }
}

async fn send(
    request: reqwest::RequestBuilder,
    cancelled: &AtomicBool,
) -> Result<reqwest::Response, &'static str> {
    crate::copy_upload::send(request, cancelled)
        .await
        .map_err(|error| {
            if error == "source_copy_cancelled" {
                CANCELLED
            } else {
                TRANSFER
            }
        })
}

async fn copy(
    app: &AppHandle,
    saved: &SavedConnection,
    package: Uuid,
    path: PathBuf,
    cancelled: &AtomicBool,
) -> Result<SavedCopy, String> {
    let check = || {
        if cancelled.load(Ordering::Acquire) {
            Err(CANCELLED)
        } else {
            Ok(())
        }
    };
    check()?;
    let destination = destination::Destination::open(path)?;
    let (client, origin) = client(saved).await?;
    let request = |suffix: &str| {
        client
            .get(
                origin
                    .join(&format!("api/preservation/packages/{package}{suffix}"))
                    .unwrap(),
            )
            .bearer_auth(&saved.token)
    };
    let entry: Package = transport::json(send(request(""), cancelled).await?).await?;
    if entry.id != package || !entry.eligible() {
        return Err("media_copy_package_unavailable".into());
    }
    let mut response = send(request("/manifest"), cancelled).await?;
    if !response.status().is_success() {
        return Err(TRANSFER.into());
    }
    let mut authoritative = Vec::new();
    while let Some(chunk) = chunk(&mut response, cancelled).await? {
        check()?;
        let chunk = chunk.as_ref();
        if authoritative.len() + chunk.len() > archive::MAX_MANIFEST {
            return Err("media_copy_archive_invalid".into());
        }
        authoritative.extend_from_slice(chunk);
    }
    let manifest = archive::Manifest::parse(&authoritative, package)?;
    let limit = manifest.download_limit(authoritative.len())?;
    destination.space(limit + SPACE_RESERVE)?;
    let mut partial = destination.start(package)?;
    let mut response = send(
        request("/download").timeout(Duration::from_secs(24 * 60 * 60)),
        cancelled,
    )
    .await?;
    if !response.status().is_success() || response.content_length().is_some_and(|size| size > limit)
    {
        return Err(TRANSFER.into());
    }
    let mut received = 0_u64;
    let mut next_space_check = SPACE_RESERVE;
    while let Some(chunk) = chunk(&mut response, cancelled).await? {
        check()?;
        let chunk = chunk.as_ref();
        let length = chunk.len() as u64;
        if received + length > limit {
            return Err("media_copy_archive_invalid".into());
        }
        if received >= next_space_check {
            partial.space(limit - received + SPACE_RESERVE)?;
            next_space_check = received + SPACE_RESERVE;
        }
        partial
            .file
            .as_mut()
            .ok_or(TRANSFER)?
            .write_all(chunk)
            .map_err(|_| "media_copy_write_failed")?;
        received += length;
    }
    let file = partial.file.as_ref().ok_or(TRANSFER)?;
    file.sync_all().map_err(|_| "media_copy_write_failed")?;
    let stamp = crate::copy_source::opened_stamp(file)?;
    archive::verify(
        file.try_clone().map_err(|_| TRANSFER)?,
        &manifest,
        &authoritative,
        check,
    )?;
    if crate::copy_source::opened_stamp(file)? != stamp {
        return Err("media_copy_archive_invalid".into());
    }
    let state = app.state::<DesktopState>();
    let current = state.0.lock().await;
    check()?;
    if !same_session(current.as_ref(), saved) {
        return Err("media_copy_session_changed".into());
    }
    let path = partial.publish(&stamp)?;
    Ok(SavedCopy {
        path,
        originals: manifest.item_count(),
        bytes: received,
    })
}

#[cfg(test)]
mod lifecycle_tests {
    use super::MediaCopy;

    #[test]
    fn update_and_media_copy_cannot_run_together() {
        let copy = MediaCopy::default();
        let active = copy.active.try_lock().unwrap();
        assert_eq!(
            copy.lock_for_update().err().as_deref(),
            Some("update_media_copy_active")
        );
        drop(active);

        let update = copy.lock_for_update().unwrap();
        assert!(copy.active.try_lock().is_err());
        drop(update);
        assert!(copy.active.try_lock().is_ok());
    }
}
