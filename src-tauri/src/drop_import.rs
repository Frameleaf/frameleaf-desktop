//! One-time import authority issued by native drops and file manager actions.
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
pub(crate) const MAX_FILES: usize = 100;
pub(crate) type FileSelection = Result<Vec<PathBuf>, &'static str>;

#[derive(Default)]
struct Pending {
    drop: Option<DropSelection>,
    preview: Option<(String, Plan)>,
    launch: Option<FileSelection>,
}

impl Pending {
    fn set_selection(&mut self, paths: Vec<PathBuf>, session: [u8; 32]) {
        self.drop = Some(DropSelection {
            id: uuid::Uuid::new_v4().to_string(),
            session,
            paths,
        });
        self.preview = None;
    }

    #[cfg(any(target_os = "macos", windows, test))]
    fn enqueue_launch(&mut self, incoming: FileSelection) -> bool {
        if self.launch.as_ref() == Some(&incoming) {
            return false;
        }
        self.launch = Some(incoming);
        true
    }

    fn apply_launch(&mut self, session: Option<[u8; 32]>) -> Result<(), &'static str> {
        if let Some(launch) = self.launch.take() {
            self.drop = None;
            self.preview = None;
            let session = session.ok_or("sign_in_required")?;
            self.set_selection(launch?, session);
        }
        Ok(())
    }

    fn discard(&mut self, id: &str, session: [u8; 32]) {
        if self
            .drop
            .as_ref()
            .is_some_and(|selection| selection.id == id && selection.session == session)
        {
            self.drop = None;
            self.preview = None;
        }
    }
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
    pub(crate) jobs: SourceJobs,
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
    pub(crate) async fn reset_for_restore(&self) {
        self.jobs.stop().await;
        if let Ok(mut pending) = self.pending.lock() {
            pending.drop = None;
            pending.preview = None;
        }
    }

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
        pending.set_selection(paths.clone(), session(saved));
    }
    let _ = window.emit("photo-drop-pending", if valid { "ready" } else { "limit" });
}

#[cfg(any(target_os = "macos", windows))]
pub(crate) fn launch_event(app: &AppHandle, selection: FileSelection) {
    let drops = app.state::<DropImport>();
    let queued = drops
        .pending
        .lock()
        .is_ok_and(|mut pending| pending.enqueue_launch(selection));
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        if queued {
            let _ = window.emit("photo-drop-pending", "ready");
        }
    }
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
        // A one-time drop may come from a card, USB drive or network share, as a camera import may.
        let scan = photo_sources::scan_batch(&root, photo_sources::Pin::Dropped(&identity), None)?;
        if scan.inventory.truncated {
            return Err("source_inventory_partial".into());
        }
        scan
    } else {
        let mut unique = BTreeSet::new();
        let mut files = Vec::new();
        let mut logical_bytes = 0u64;
        let mut empty = 0u64;
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
            if !meta.is_file() || item.excluded || !crate::copy_source::watchable(&meta, item) {
                return Err("source_item_invalid".into());
            }
            // An empty file has nothing to copy; the other dropped files still import.
            if meta.len() == 0 {
                empty += 1;
                continue;
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
                skipped: empty,
                truncated: false,
                availability,
                root_identity: None,
                media_identity: None,
                empty,
            },
            files,
            unreadable: Default::default(),
            more: false,
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
    // The folder scan below must not hold the connection lock.
    let current = state.0.lock().await.clone();
    let saved = current.as_ref();
    let drops = app.state::<DropImport>();
    let (saved, id, paths) = {
        let mut pending = drops
            .pending
            .lock()
            .map_err(|_| "source_selection_unavailable")?;
        pending.apply_launch(saved.map(session))?;
        let Some(saved) = saved else {
            return Ok(None);
        };
        let Some(selection) = pending
            .drop
            .as_ref()
            .filter(|value| value.session == session(saved))
        else {
            return Ok(None);
        };
        (saved, selection.id.clone(), selection.paths.clone())
    };
    let result = async {
        if credentials::load::<Consent>(CREDENTIAL)?.is_some() {
            return Err("source_drop_existing".into());
        }
        tauri::async_runtime::spawn_blocking(move || preview_paths(&paths))
            .await
            .map_err(|_| "source_inventory_failed")?
    }
    .await;
    let mut pending = drops
        .pending
        .lock()
        .map_err(|_| "source_selection_unavailable")?;
    if pending.launch.is_some()
        || pending
            .drop
            .as_ref()
            .is_none_or(|selection| selection.id != id || selection.session != session(saved))
    {
        return Err("source_selection_changed".into());
    }
    let plan = result.inspect_err(|_| pending.discard(&id, session(saved)))?;
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
    album: Option<crate::import_album::Destination>,
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
        let destination = crate::import_album::approve(saved, album).await?;
        let plan = {
            let mut pending = drops
                .pending
                .lock()
                .map_err(|_| "source_selection_unavailable")?;
            if pending.launch.is_some()
                || pending.drop.as_ref().is_none_or(|selection| {
                    selection.id != id || selection.session != session(saved)
                })
                || pending
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
            "Selected files"
        };
        let consent = Consent::dropped(
            saved,
            &identity,
            &plan.root,
            &plan.identity,
            name,
            destination,
        )?;
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
        if album.is_some() {
            return Err("source_album_selection_changed".into());
        }
        existing.ok_or("source_approval_required")?
    };
    if !consent.registered {
        consent.register(saved, &identity).await?;
        credentials::save(CREDENTIAL, &consent)?;
    }
    let _ = app.emit_to("main", "photo-import-history", ());
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
        if let Some(id) = selection_id {
            pending.discard(&id, session(saved));
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
            crate::source_import::history::retire(&base, saved, &drops.jobs);
            credentials::delete(CREDENTIAL)?;
            if let Some(consent) = consent {
                let _ = consent.revoke(saved, &credentials::identity()?).await;
            }
            Ok(None)
        }
        _ => Err("source_control_invalid".into()),
    }?;
    crate::tray::set_drop_status(&app, status.as_ref());
    let _ = app.emit_to("main", "photo-import-history", ());
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
    fn discard_only_clears_the_matching_selection_and_session() {
        let folder = Folder::new();
        let photo = folder.0.join("photo.jpg");
        std::fs::write(&photo, b"image").unwrap();
        let paths = vec![photo];
        let mut pending = Pending {
            launch: None,
            preview: Some(("current".into(), preview_paths(&paths).unwrap())),
            drop: Some(DropSelection {
                id: "current".into(),
                session: [1; 32],
                paths,
            }),
        };
        pending.discard("old", [1; 32]);
        pending.discard("current", [0; 32]);
        assert!(pending.drop.is_some() && pending.preview.is_some());
        pending.discard("current", [1; 32]);
        assert!(pending.drop.is_none() && pending.preview.is_none());
    }

    #[test]
    fn cold_and_repeated_launches_keep_one_preview_and_never_cross_sign_in() {
        let folder = Folder::new();
        let first = folder.0.join("first.jpg");
        let second = folder.0.join("second.jpg");
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&second, b"second").unwrap();
        let mut pending = Pending::default();

        assert!(pending.enqueue_launch(Ok(vec![first.clone()])));
        assert!(!pending.enqueue_launch(Ok(vec![first.clone()])));
        assert!(pending.drop.is_none() && pending.preview.is_none());
        assert_eq!(pending.apply_launch(None), Err("sign_in_required"));
        pending.apply_launch(Some([2; 32])).unwrap();
        assert!(pending.drop.is_none() && pending.preview.is_none() && pending.launch.is_none());

        assert!(pending.enqueue_launch(Ok(vec![first.clone()])));
        pending.apply_launch(Some([2; 32])).unwrap();
        let id = pending.drop.as_ref().unwrap().id.clone();
        pending.preview = Some((
            id.clone(),
            preview_paths(std::slice::from_ref(&first)).unwrap(),
        ));
        std::fs::write(&first, b"updated photo").unwrap();
        assert!(pending.enqueue_launch(Ok(vec![first.clone()])));
        pending.apply_launch(Some([2; 32])).unwrap();
        let repeated = pending.drop.as_ref().unwrap();
        assert_ne!(repeated.id, id);
        assert_eq!(repeated.paths, vec![first]);
        assert!(pending.preview.is_none());
        pending.discard(&id, [2; 32]);
        assert!(pending.drop.is_some());
        assert!(pending.enqueue_launch(Ok(vec![second.clone()])));
        pending.discard(&id, [2; 32]);
        pending.apply_launch(Some([2; 32])).unwrap();
        assert!(pending.preview.is_none());
        let selected = pending.drop.unwrap();
        assert_ne!(selected.id, id);
        assert_eq!(selected.session, [2; 32]);
        assert_eq!(selected.paths, vec![second]);
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
                "Dropped folder",
                None
            )
            .err()
            .as_deref(),
            Some("source_root_changed")
        );
    }
}
