use crate::camera_identity::MediaIdentity;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, path::Path};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderInventory {
    pub path: String,
    pub photos: u64,
    pub logical_bytes: u64,
    pub skipped: u64,
    pub truncated: bool,
    pub availability: crate::source_metadata::AvailabilitySummary,
    #[serde(skip)]
    pub(crate) root_identity: Option<String>,
    #[serde(skip)]
    pub(crate) media_identity: Option<MediaIdentity>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SourceFile {
    pub relative: String,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch_version: Option<String>,
}
pub(crate) struct FolderScan {
    pub inventory: FolderInventory,
    pub files: Vec<SourceFile>,
    pub unreadable: u64,
}

/// A bounded metadata preview, never a content read or a persistent source grant.
pub fn inventory(root: &Path, limit: usize) -> Result<FolderInventory, String> {
    scan(root, limit).map(|scan| scan.inventory)
}
pub(crate) fn scan(root: &Path, limit: usize) -> Result<FolderScan, String> {
    scan_inner(root, limit, None, false, None)
}

/// Bind a removable-media preview to the directory that was actually scanned.
pub(crate) fn camera_inventory(root: &Path, limit: usize) -> Result<FolderInventory, String> {
    scan_inner(root, limit, None, true, None).map(|scan| scan.inventory)
}

pub(crate) fn scan_approved(root: &Path, root_identity: &str) -> Result<FolderScan, String> {
    scan_inner(root, 10_000, Some(root_identity), false, None)
}

pub(crate) fn scan_camera(root: &Path, media: &MediaIdentity) -> Result<FolderScan, String> {
    scan_inner(root, 10_000, None, false, Some(media))
}

fn scan_inner(
    root: &Path,
    limit: usize,
    approved_root: Option<&str>,
    bind_identity: bool,
    media: Option<&MediaIdentity>,
) -> Result<FolderScan, String> {
    #[cfg(target_os = "macos")]
    let _policy = metadata_only::Guard::new()?;
    if !root.is_absolute() || root.parent().is_none() || limit == 0 || limit > 10_000 {
        return Err("source_folder_invalid".into());
    }
    if root.components().any(|part| {
        let value = part.as_os_str().to_string_lossy().to_lowercase();
        [".photoslibrary", ".photolibrary", ".app", ".bundle"]
            .iter()
            .any(|suffix| value.ends_with(suffix))
    }) {
        return Err("source_package_requires_provider".into());
    }
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" });
    if home
        .as_ref()
        .is_some_and(|home| covers_home(root, Path::new(home)))
    {
        return Err("source_choose_photo_subfolder".into());
    }
    let dir = crate::source_metadata::open_preview_root(root)?;
    if let Some(expected) = approved_root {
        if crate::copy_source::root_identity(&dir)? != expected {
            return Err("source_root_changed".into());
        }
        let directory = dir
            .try_clone()
            .map_err(|_| "source_folder_unavailable")?
            .into_std_file();
        if !crate::host_storage::is_local(&directory)? {
            return Err("source_watch_local_required".into());
        }
    }
    let mounted = if let Some(media) = media {
        media.require(&dir)?;
        Some(crate::copy_source::root_identity(&dir)?)
    } else {
        None
    };
    let pinned_root = approved_root.or(mounted.as_deref());
    let root_meta = dir
        .dir_metadata()
        .map_err(|_| "source_folder_unavailable")?;
    if crate::source_metadata::probe(&dir, Path::new("."), &root_meta)?.excluded {
        return Err("source_folder_excluded".into());
    }
    let mut result = FolderInventory {
        path: root.to_str().ok_or("source_folder_name_invalid")?.into(),
        photos: 0,
        logical_bytes: 0,
        skipped: 0,
        truncated: false,
        availability: Default::default(),
        root_identity: bind_identity
            .then(|| crate::copy_source::root_identity(&dir))
            .transpose()?,
        media_identity: bind_identity
            .then(|| MediaIdentity::read(&dir).ok())
            .flatten(),
    };
    let mut files = Vec::new();
    let mut unreadable = 0;
    let mut pending = VecDeque::from([(dir, std::path::PathBuf::new(), 0usize)]);
    let mut visited = 0;
    while let Some((dir, relative, depth)) = pending.pop_front() {
        let entries = match dir.entries() {
            Ok(entries) => entries,
            Err(_) => {
                unreadable += 1;
                result.skipped += 1;
                continue;
            }
        };
        for entry in entries {
            if visited == limit {
                result.truncated = true;
                return Ok(FolderScan {
                    inventory: result,
                    files,
                    unreadable,
                });
            }
            visited += 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    unreadable += 1;
                    result.skipped += 1;
                    continue;
                }
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                unreadable += 1;
                result.skipped += 1;
                continue;
            };
            let lower = name.to_lowercase();
            if name.starts_with('.')
                || [".photoslibrary", ".photolibrary", ".app", ".bundle"]
                    .iter()
                    .any(|suffix| lower.ends_with(suffix))
            {
                result.skipped += 1;
                continue;
            }
            let meta = match dir.symlink_metadata(name) {
                Ok(meta) => meta,
                Err(_) => {
                    unreadable += 1;
                    result.skipped += 1;
                    continue;
                }
            };
            if meta.is_symlink() {
                result.skipped += 1;
                continue;
            }
            if !(meta.is_dir() || meta.is_file() && is_media_filename(name)) {
                continue;
            }
            let observation = match crate::source_metadata::probe(&dir, Path::new(name), &meta) {
                Ok(observation) => observation,
                Err(_) => {
                    unreadable += 1;
                    result.skipped += 1;
                    continue;
                }
            };
            if observation.excluded {
                result.skipped += 1;
                continue;
            }
            if meta.is_dir() {
                if depth == 16 || pending.len() == 256 {
                    result.truncated = true;
                    result.skipped += 1;
                    continue;
                }
                match crate::source_metadata::open_preview_child(&dir, Path::new(name), true) {
                    Ok(child) => {
                        if let Some(expected) = pinned_root {
                            let actual = crate::copy_source::root_identity(&child)?;
                            if actual.split(':').next() != expected.split(':').next() {
                                result.skipped += 1;
                                continue;
                            }
                        }
                        pending.push_back((child, relative.join(name), depth + 1));
                    }
                    Err(_) => {
                        unreadable += 1;
                        result.skipped += 1;
                    }
                }
            } else if meta.is_file() && is_media_filename(name) {
                let watch_version = if pinned_root.is_some() {
                    if meta.len() == 0 || !crate::copy_source::watchable(&meta, observation) {
                        result.skipped += 1;
                        continue;
                    }
                    let version = if media.is_some() {
                        crate::copy_source::camera_version
                    } else {
                        crate::copy_source::watch_version
                    };
                    Some(version(&dir, Path::new(name), &meta)?)
                } else {
                    None
                };
                files.push(SourceFile {
                    relative: relative
                        .join(name)
                        .to_str()
                        .ok_or("source_item_invalid")?
                        .into(),
                    bytes: meta.len(),
                    watch_version,
                });
                result.photos += 1;
                result.availability.record(observation, meta.len());
                result.logical_bytes = result
                    .logical_bytes
                    .checked_add(meta.len())
                    .ok_or("source_inventory_size_invalid")?;
            }
        }
    }
    files.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(FolderScan {
        inventory: result,
        files,
        unreadable,
    })
}

#[derive(Debug, Serialize)]
pub struct RootHint {
    pub label: String,
    pub path: String,
}

pub fn known_onedrive_roots(home: &Path, supplied: &[std::path::PathBuf]) -> Vec<RootHint> {
    #[cfg(target_os = "macos")]
    let Ok(_policy) = metadata_only::Guard::new() else {
        return Vec::new();
    };
    let mut candidates = supplied.to_vec();
    #[cfg(target_os = "macos")]
    if let Ok(entries) = std::fs::read_dir(home.join("Library/CloudStorage")) {
        candidates.extend(
            entries
                .take(100)
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("OneDrive-"))
                .map(|entry| entry.path()),
        );
    }
    #[cfg(not(target_os = "macos"))]
    let _ = home;
    candidates.sort();
    candidates.dedup();
    let mut result: Vec<RootHint> = Vec::new();
    for path in candidates {
        if result.len() == 16 {
            break;
        }
        if !path.is_absolute() || crate::source_metadata::open_preview_root(&path).is_err() {
            continue;
        }
        if result
            .iter()
            .any(|entry| path.starts_with(&entry.path) || Path::new(&entry.path).starts_with(&path))
        {
            continue;
        }
        if let (Some(label), Some(path)) =
            (path.file_name().and_then(|v| v.to_str()), path.to_str())
        {
            result.push(RootHint {
                label: label.into(),
                path: path.into(),
            });
        }
    }
    result
}

pub(crate) fn is_media_filename(name: &str) -> bool {
    matches!(
        name.to_lowercase().rsplit('.').next(),
        Some(
            "jpg"
                | "jpeg"
                | "heic"
                | "heif"
                | "png"
                | "gif"
                | "webp"
                | "avif"
                | "tif"
                | "tiff"
                | "dng"
                | "cr2"
                | "cr3"
                | "nef"
                | "arw"
                | "raf"
                | "orf"
                | "rw2"
                | "mp4"
                | "mov"
                | "m4v"
        )
    )
}

fn covers_home(root: &Path, home: &Path) -> bool {
    home.starts_with(root) || std::fs::canonicalize(home).is_ok_and(|home| home.starts_with(root))
}

#[cfg(target_os = "macos")]
pub(crate) mod metadata_only {
    use std::{marker::PhantomData, rc::Rc};
    // Darwin sys/resource.h; Apple TN3150 requires disabling directory materialization too.
    const KIND: libc::c_int = 3; // IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES
    const THREAD: libc::c_int = 1; // IOPOL_SCOPE_THREAD
    unsafe extern "C" {
        fn getiopolicy_np(kind: libc::c_int, scope: libc::c_int) -> libc::c_int;
        fn setiopolicy_np(
            kind: libc::c_int,
            scope: libc::c_int,
            policy: libc::c_int,
        ) -> libc::c_int;
    }
    pub(super) fn current() -> Result<libc::c_int, String> {
        let value = unsafe { getiopolicy_np(KIND, THREAD) };
        if value < 0 {
            Err("source_preview_policy_unavailable".into())
        } else {
            Ok(value)
        }
    }
    pub(crate) struct Guard {
        previous: libc::c_int,
        // The policy must be restored on the same OS thread, never across an await.
        _thread: PhantomData<Rc<()>>,
    }
    impl Guard {
        pub(crate) fn new() -> Result<Self, String> {
            let previous = current()?;
            if unsafe { setiopolicy_np(KIND, THREAD, 1) } != 0 {
                return Err("source_preview_policy_unavailable".into());
            }
            Ok(Self {
                previous,
                _thread: PhantomData,
            })
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            // A restore failure leaves the restrictive policy in place.
            unsafe {
                setiopolicy_np(KIND, THREAD, self.previous);
            }
        }
    }
}

#[cfg(test)]
mod root_tests {
    #[cfg(target_os = "macos")]
    #[test]
    fn os_hidden_files_and_directories_are_excluded_before_content_access() {
        use std::os::unix::ffi::OsStrExt;
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("frameleaf-hidden-preview-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("private")).unwrap();
        let _cleanup = Cleanup(root.clone());
        for name in ["visible.jpg", "hidden.jpg", "private/secret.jpg"] {
            std::fs::write(root.join(name), b"synthetic original").unwrap();
        }
        for name in ["hidden.jpg", "private"] {
            let path = std::ffi::CString::new(root.join(name).as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chflags(path.as_ptr(), 0x8000) }, 0);
        }
        let result = super::inventory(&root, 100).unwrap();
        assert_eq!(result.photos, 1);
        assert_eq!(result.skipped, 2);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn metadata_preview_policy_is_thread_scoped_nested_and_restored_after_errors() {
        let before = super::metadata_only::current().unwrap();
        let (start, wait) = std::sync::mpsc::channel();
        let (report, observations) = std::sync::mpsc::channel();
        let other = std::thread::spawn(move || {
            report
                .send(super::metadata_only::current().unwrap())
                .unwrap();
            wait.recv().unwrap();
            report
                .send(super::metadata_only::current().unwrap())
                .unwrap();
        });
        let other_before = observations.recv().unwrap();
        let outer = super::metadata_only::Guard::new().unwrap();
        assert_eq!(super::metadata_only::current().unwrap(), 1);
        {
            let _inner = super::metadata_only::Guard::new().unwrap();
            assert_eq!(super::metadata_only::current().unwrap(), 1);
        }
        assert_eq!(super::metadata_only::current().unwrap(), 1);
        start.send(()).unwrap();
        assert_eq!(observations.recv().unwrap(), other_before);
        other.join().unwrap();
        drop(outer);
        assert_eq!(super::metadata_only::current().unwrap(), before);
        let preview = || -> Result<(), &str> {
            let _policy = super::metadata_only::Guard::new().unwrap();
            Err("preview failed")
        };
        let result = preview();
        assert!(result.is_err());
        assert_eq!(super::metadata_only::current().unwrap(), before);
    }
    #[test]
    fn copy_manifest_reuses_bounded_metadata_traversal_and_records_only_relative_media_names() {
        let parent =
            std::env::temp_dir().join(format!("frameleaf-manifest-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(parent.join("nested")).unwrap();
        let root = std::fs::canonicalize(&parent).unwrap();
        std::fs::write(root.join("nested/photo.jpg"), b"original").unwrap();
        std::fs::write(root.join("notes.txt"), b"excluded").unwrap();
        let scan = super::scan(&root, 100).unwrap();
        assert_eq!(scan.files.len(), 1);
        assert_eq!(
            super::Path::new(&scan.files[0].relative),
            super::Path::new("nested/photo.jpg")
        );
        assert_eq!(scan.files[0].bytes, 8);
        assert_eq!(scan.unreadable, 0);
        assert!(super::scan(&root, 1).unwrap().inventory.truncated);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn home_directory_alias_does_not_allow_a_whole_home_scan() {
        let parent =
            std::env::temp_dir().join(format!("frameleaf-home-scope-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&parent).unwrap();
        let actual = parent.join("actual-home");
        std::fs::create_dir(&actual).unwrap();
        let actual = std::fs::canonicalize(actual).unwrap();
        let alias = parent.join("home-alias");
        std::os::unix::fs::symlink(&actual, &alias).unwrap();
        assert!(super::covers_home(&actual, &alias));
        assert!(!super::covers_home(&actual.join("Photos"), &alias));
        std::fs::remove_dir_all(parent).unwrap();
    }
}
