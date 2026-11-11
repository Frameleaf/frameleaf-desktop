//! One-time import authority issued only by native drops in the trusted Desktop window.
use crate::{
    connection::SavedConnection,
    credentials,
    photo_sources::{self, FolderInventory, FolderScan, SourceFile},
    source_consent::{Consent, ConsentView},
    source_import::{ImportView, SourceJobs},
    source_metadata::{self, AvailabilitySummary},
    DesktopState,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Mutex,
};
use tauri::{AppHandle, DragDropEvent, Emitter, Manager, State, WebviewWindow};

pub(crate) const CREDENTIAL: &str = "photo-source-drop";
const MAX_FILES: usize = 100;

#[derive(Default)]
struct Pending {
    drop: Option<DropSelection>,
    preview: Option<(String, Plan)>,
}

struct DropSelection {
    id: String,
    session: [u8; 32],
    paths: Vec<PathBuf>,
}

struct Plan {
    root: PathBuf,
    identity: String,
    scan: FolderScan,
    folder: bool,
}

pub(crate) struct DropImport {
    pending: Mutex<Pending>,
    jobs: SourceJobs,
}

impl Default for DropImport {
    fn default() -> Self {
        Self {
            pending: Mutex::default(),
            jobs: SourceJobs::with_credential(CREDENTIAL),
        }
    }
}

impl DropImport {
    pub(crate) async fn stop(&self) {
        self.jobs.stop().await;
        if let Ok(mut pending) = self.pending.lock() {
            *pending = Pending::default();
        }
    }
}

fn session(saved: &SavedConnection) -> [u8; 32] {
    Sha256::digest(saved.token.as_bytes()).into()
}

pub(crate) fn native_event(window: &WebviewWindow, event: &DragDropEvent) {
    let DragDropEvent::Drop { paths, .. } = event else {
        return;
    };
    if crate::require_local(window).is_err() {
        return;
    }
    let connection = window.state::<DesktopState>();
    let Ok(connection) = connection.0.try_lock() else {
        let _ = window.emit("photo-drop-pending", "busy");
        return;
    };
    let Some(saved) = connection.as_ref() else {
        return;
    };
    let drops = window.state::<DropImport>();
    let Ok(mut pending) = drops.pending.lock() else {
        return;
    };
    if pending
        .drop
        .as_ref()
        .is_some_and(|selection| selection.session == session(saved) && selection.paths == *paths)
    {
        return;
    }
    let valid = !paths.is_empty() && paths.len() <= MAX_FILES;
    *pending = Pending::default();
    if valid {
        pending.drop = Some(DropSelection {
            id: uuid::Uuid::new_v4().to_string(),
            session: session(saved),
            paths: paths.clone(),
        });
    }
    let _ = window.emit("photo-drop-pending", if valid { "ready" } else { "limit" });
}

fn preview_paths(paths: &[PathBuf]) -> Result<Plan, String> {
    #[cfg(target_os = "macos")]
    let _policy = photo_sources::metadata_only::Guard::new()?;
    if paths.is_empty() || paths.len() > MAX_FILES {
        return Err("source_drop_limit".into());
    }
    let first = &paths[0];
    let metadata = std::fs::symlink_metadata(first).map_err(|_| "source_item_unavailable")?;
    let folder = metadata.is_dir() && !metadata.is_symlink();
    let root = if folder {
        if paths.len() != 1 {
            return Err("source_drop_mixed".into());
        }
        first.clone()
    } else {
        first.parent().ok_or("source_folder_invalid")?.to_path_buf()
    };
    if root.components().any(|part| {
        let name = part.as_os_str().to_string_lossy().to_ascii_lowercase();
        [".photoslibrary", ".photolibrary", ".app", ".bundle"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
    }) {
        return Err("source_package_requires_provider".into());
    }
    let directory = source_metadata::open_preview_root(&root)?;
    let identity = crate::copy_source::root_identity(&directory)?;
    let scan = if folder {
        let scan = photo_sources::scan_approved(&root, &identity)?;
        if scan.inventory.truncated || scan.unreadable > 0 {
            return Err("source_inventory_partial".into());
        }
        scan
    } else {
        if !crate::host_storage::is_local(
            &directory
                .try_clone()
                .map_err(|_| "source_folder_unavailable")?
                .into_std_file(),
        )? {
            return Err("source_watch_local_required".into());
        }
        let mut unique = BTreeSet::new();
        let mut files = Vec::new();
        let mut logical_bytes = 0u64;
        let mut availability = AvailabilitySummary::default();
        for path in paths {
            if path.parent() != Some(root.as_path()) {
                return Err("source_drop_mixed".into());
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.starts_with('.') && photo_sources::is_media_filename(name))
                .ok_or("source_item_invalid")?;
            if !unique.insert(name) {
                continue;
            }
            let meta = directory
                .symlink_metadata(name)
                .map_err(|_| "source_item_unavailable")?;
            let item = source_metadata::probe(&directory, Path::new(name), &meta)?;
            if !meta.is_file()
                || meta.len() == 0
                || item.excluded
                || !crate::copy_source::watchable(&meta, item)
            {
                return Err("source_item_invalid".into());
            }
            let version = crate::copy_source::watch_version(&directory, Path::new(name), &meta)?;
            availability.record(item, meta.len());
            logical_bytes = logical_bytes
                .checked_add(meta.len())
                .ok_or("source_inventory_size_invalid")?;
            files.push(SourceFile {
                relative: name.into(),
                bytes: meta.len(),
                watch_version: Some(version),
            });
        }
        FolderScan {
            inventory: FolderInventory {
                path: root.to_str().ok_or("source_folder_name_invalid")?.into(),
                photos: files.len() as u64,
                logical_bytes,
                skipped: 0,
                truncated: false,
                availability,
                root_identity: None,
            },
            files,
            unreadable: 0,
        }
    };
    if scan.files.is_empty() {
        return Err("source_no_media".into());
    }
    Ok(Plan {
        root,
        identity,
        scan,
        folder,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Preview {
    selection_id: String,
    path: String,
    count: u64,
    bytes: u64,
    skipped: u64,
    folder: bool,
    names: Vec<String>,
}

#[tauri::command]
pub(crate) async fn preview_photo_drop(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<Option<Preview>, String> {
    crate::require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let drops = app.state::<DropImport>();
    if credentials::load::<Consent>(CREDENTIAL)?.is_some() {
        return Err("source_drop_existing".into());
    }
    let Some((id, paths)) = drops
        .pending
        .lock()
        .map_err(|_| "source_selection_unavailable")?
        .drop
        .as_ref()
        .filter(|selection| selection.session == session(saved))
        .map(|selection| (selection.id.clone(), selection.paths.clone()))
    else {
        return Ok(None);
    };
    let plan = tauri::async_runtime::spawn_blocking(move || preview_paths(&paths))
        .await
        .map_err(|_| "source_inventory_failed")??;
    let mut pending = drops
        .pending
        .lock()
        .map_err(|_| "source_selection_unavailable")?;
    if pending
        .drop
        .as_ref()
        .is_none_or(|selection| selection.id != id || selection.session != session(saved))
    {
        return Err("source_selection_changed".into());
    }
    let preview = Preview {
        selection_id: id.clone(),
        path: plan.scan.inventory.path.clone(),
        count: plan.scan.inventory.photos,
        bytes: plan.scan.inventory.logical_bytes,
        skipped: plan.scan.inventory.skipped,
        folder: plan.folder,
        names: if plan.folder {
            Vec::new()
        } else {
            plan.scan
                .files
                .iter()
                .map(|file| file.relative.clone())
                .collect()
        },
    };
    pending.preview = Some((id, plan));
    Ok(Some(preview))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    consent: ConsentView,
    job: Option<ImportView>,
}

fn status(app: &AppHandle, saved: &SavedConnection, consent: &Consent) -> Result<Status, String> {
    consent.require(saved, &credentials::identity()?)?;
    let job = if consent.registered {
        app.state::<DropImport>()
            .jobs
            .status(&crate::import_base(app)?, saved)?
    } else {
        None
    };
    Ok(Status {
        consent: consent.view(),
        job,
    })
}

#[tauri::command]
pub(crate) async fn photo_drop_status(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<Option<Status>, String> {
    crate::require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    credentials::load::<Consent>(CREDENTIAL)?
        .as_ref()
        .map(|consent| status(&app, saved, consent))
        .transpose()
}

#[tauri::command]
pub(crate) async fn approve_photo_drop(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    selection_id: Option<String>,
) -> Result<Status, String> {
    crate::require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let identity = credentials::identity()?;
    let drops = app.state::<DropImport>();
    let existing = credentials::load::<Consent>(CREDENTIAL)?;
    let mut consent = if let Some(id) = selection_id {
        if existing.is_some() {
            return Err("source_drop_existing".into());
        }
        let plan =
            {
                let mut pending = drops
                    .pending
                    .lock()
                    .map_err(|_| "source_selection_unavailable")?;
                if pending.drop.as_ref().is_none_or(|selection| {
                    selection.id != id || selection.session != session(saved)
                }) || pending
                    .preview
                    .as_ref()
                    .is_none_or(|(preview, _)| preview != &id)
                {
                    return Err("source_selection_changed".into());
                }
                pending.drop = None;
                pending.preview.take().unwrap().1
            };
        let name = if plan.folder {
            plan.root
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("source_folder_name_invalid")?
        } else {
            "Dropped files"
        };
        let consent = Consent::dropped(saved, &identity, &plan.root, &plan.identity, name)?;
        drops.jobs.prepare_drop(
            &crate::import_base(&app)?,
            saved,
            &identity,
            &consent,
            plan.scan,
        )?;
        credentials::save(CREDENTIAL, &consent)?;
        consent
    } else {
        existing.ok_or("source_approval_required")?
    };
    if !consent.registered {
        consent.register(saved, &identity).await?;
        credentials::save(CREDENTIAL, &consent)?;
    }
    status(&app, saved, &consent)
}

#[tauri::command]
pub(crate) async fn control_photo_drop(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    action: String,
    selection_id: Option<String>,
) -> Result<Option<ImportView>, String> {
    crate::require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let drops = app.state::<DropImport>();
    if action == "discard-preview" {
        let mut pending = drops
            .pending
            .lock()
            .map_err(|_| "source_selection_unavailable")?;
        if pending.preview.is_none()
            && pending.drop.as_ref().is_some_and(|selection| {
                selection_id.as_deref() == Some(&selection.id)
                    && selection.session == session(saved)
            })
        {
            *pending = Pending::default();
        }
        return Ok(None);
    }
    let base = crate::import_base(&app)?;
    let status = match action.as_str() {
        "resume" => {
            return drops
                .jobs
                .start(app.clone(), base, saved.clone())
                .await
                .map(Some)
        }
        "pause" | "cancel" => drops
            .jobs
            .control(&base, saved, action == "cancel")
            .await
            .map(Some),
        "approve-upload" => drops.jobs.approve_upload(&base, saved).await.map(Some),
        "remove" => {
            drops.stop().await;
            let consent = credentials::load::<Consent>(CREDENTIAL)?;
            credentials::delete(CREDENTIAL)?;
            if let Some(consent) = consent {
                let _ = consent.revoke(saved, &credentials::identity()?).await;
            }
            Ok(None)
        }
        _ => Err("source_control_invalid".into()),
    }?;
    crate::tray::set_drop_status(&app, status.as_ref());
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::DeviceIdentity;

    struct Folder(PathBuf);
    impl Folder {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-drop-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Folder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn explicit_drop_excludes_neighbours_and_keeps_previewed_versions() {
        let folder = Folder::new();
        let photo = folder.0.join("photo.jpg");
        let video = folder.0.join("video.mp4");
        std::fs::write(&photo, b"image").unwrap();
        std::fs::write(&video, b"video").unwrap();
        std::fs::write(folder.0.join("neighbour.jpg"), b"private").unwrap();
        let first = preview_paths(&[photo.clone(), video.clone(), photo.clone()]).unwrap();
        assert_eq!(first.scan.inventory.photos, 2);
        assert_eq!(first.scan.files[0].relative, "photo.jpg");
        assert_eq!(first.scan.files[1].relative, "video.mp4");
        std::fs::rename(&photo, folder.0.join("old.jpg")).unwrap();
        std::fs::write(&photo, b"other").unwrap();
        let replacement = preview_paths(&[photo.clone(), video]).unwrap();
        assert_ne!(
            first.scan.files[0].watch_version,
            replacement.scan.files[0].watch_version
        );
        assert_eq!(first.scan.files[0].bytes, replacement.scan.files[0].bytes);
        assert_eq!(std::fs::read(photo).unwrap(), b"other");
    }

    #[test]
    fn mixed_parents_and_replaced_folder_are_refused() {
        let folder = Folder::new();
        let first = folder.0.join("first");
        let second = folder.0.join("second");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        let one = first.join("one.jpg");
        let two = second.join("two.jpg");
        std::fs::write(&one, b"one").unwrap();
        std::fs::write(&two, b"two").unwrap();
        assert_eq!(
            preview_paths(&[one, two]).err().as_deref(),
            Some("source_drop_mixed")
        );
        let preview = preview_paths(std::slice::from_ref(&first)).unwrap();
        std::fs::rename(&first, folder.0.join("old")).unwrap();
        std::fs::create_dir(&first).unwrap();
        let saved = SavedConnection {
            server: "https://nas.test/".into(),
            server_id: "nas".into(),
            account_id: "owner".into(),
            name: "Fixture".into(),
            token: "synthetic-token".into(),
            device_name: "Fixture".into(),
            mode: "client-worker".into(),
            device_id: Some("device".into()),
        };
        assert_eq!(
            Consent::dropped(
                &saved,
                &DeviceIdentity::generate(),
                &preview.root,
                &preview.identity,
                "Dropped folder"
            )
            .err()
            .as_deref(),
            Some("source_root_changed")
        );
    }
}
