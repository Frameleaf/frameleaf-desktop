use crate::camera_identity::MediaIdentity;
use serde::{Deserialize, Serialize};
use std::path::Path;

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
    /// Zero-byte media files, already counted in `skipped`.
    #[serde(skip)]
    pub(crate) empty: u64,
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
    /// Media files beyond this batch were found; a later batch starts after the last file here.
    pub more: bool,
}

/// One signed manifest holds at most this many files, so its journal stays small.
pub(crate) const BATCH_FILES: usize = 10_000;
/// Guards against a runaway tree, far above an ordinary library (500,000 files and more).
pub(crate) const MAX_ENTRIES: usize = 2_000_000;
/// Open directory handles are bounded by this depth, never by the number of subfolders.
const MAX_DEPTH: usize = 64;

/// How a traversal is bound to the directory that was approved.
#[derive(Clone, Copy)]
pub(crate) enum Pin<'a> {
    /// A one-time folder copy; every file is checked again when it is staged.
    Unpinned,
    /// A watched folder: the same root on a local volume.
    Watched(&'a str),
    /// A dropped folder: the same root, on any volume a camera import may use.
    Dropped(&'a str),
    Camera(&'a MediaIdentity),
}

/// A bounded metadata preview, never a content read or a persistent source grant.
pub fn inventory(root: &Path, limit: usize) -> Result<FolderInventory, String> {
    walk(root, limit, Pin::Unpinned, false, &mut |_| Ok(())).map(|scan| scan.inventory)
}

/// Bind a removable-media preview to the directory that was actually scanned.
pub(crate) fn camera_inventory(root: &Path, limit: usize) -> Result<FolderInventory, String> {
    walk(root, limit, Pin::Unpinned, true, &mut |_| Ok(())).map(|scan| scan.inventory)
}

/// Visits every media file once without keeping the list, so memory does not grow with the folder.
pub(crate) fn scan_each(
    root: &Path,
    pin: Pin<'_>,
    each: &mut dyn FnMut(SourceFile) -> Result<(), String>,
) -> Result<FolderScan, String> {
    walk(root, MAX_ENTRIES, pin, false, each)
}

/// The next `BATCH_FILES` files in path order after `after`. The whole tree is counted, but only
/// one batch is held in memory.
pub(crate) fn scan_batch(
    root: &Path,
    pin: Pin<'_>,
    after: Option<&str>,
) -> Result<FolderScan, String> {
    let mut batch = std::collections::BinaryHeap::new();
    let mut more = false;
    let mut scan = scan_each(root, pin, &mut |file| {
        if after.is_some_and(|after| file.relative.as_str() <= after) {
            return Ok(());
        }
        batch.push((file.relative, file.bytes, file.watch_version));
        if batch.len() > BATCH_FILES {
            batch.pop();
            more = true;
        }
        Ok(())
    })?;
    scan.files = batch
        .into_sorted_vec()
        .into_iter()
        .map(|(relative, bytes, watch_version)| SourceFile {
            relative,
            bytes,
            watch_version,
        })
        .collect();
    scan.more = more;
    Ok(scan)
}

struct Level {
    dir: cap_std::fs::Dir,
    relative: std::path::PathBuf,
    /// Subfolder names still to visit. Each is opened only when its turn comes.
    children: Vec<String>,
}

fn walk(
    root: &Path,
    limit: usize,
    pin: Pin<'_>,
    bind_identity: bool,
    each: &mut dyn FnMut(SourceFile) -> Result<(), String>,
) -> Result<FolderScan, String> {
    #[cfg(target_os = "macos")]
    let _policy = metadata_only::Guard::new()?;
    if !root.is_absolute() || root.parent().is_none() || limit == 0 || limit > MAX_ENTRIES {
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
    let approved_root = match pin {
        Pin::Watched(expected) | Pin::Dropped(expected) => Some(expected),
        _ => None,
    };
    let media = match pin {
        Pin::Camera(media) => Some(media),
        _ => None,
    };
    if let Some(expected) = approved_root {
        if crate::copy_source::root_identity(&dir)? != expected {
            return Err("source_root_changed".into());
        }
    }
    if matches!(pin, Pin::Watched(_)) {
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
    let mut scan = FolderScan {
        inventory: FolderInventory {
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
            empty: 0,
        },
        files: Vec::new(),
        unreadable: 0,
        more: false,
    };
    let mut visited = 0;
    // Depth first: only the folders on the current path stay open, however many folders exist.
    let mut stack: Vec<Level> = Vec::new();
    let mut next = Some((dir, std::path::PathBuf::new()));
    loop {
        if let Some((dir, relative)) = next.take() {
            let mut children = Vec::new();
            let listed = list(
                &dir,
                &relative,
                Listing {
                    depth: stack.len(),
                    limit,
                    pinned: pinned_root.is_some(),
                    camera: media.is_some(),
                },
                &mut visited,
                &mut scan,
                &mut children,
                each,
            )?;
            if !listed {
                scan.inventory.truncated = true;
                return Ok(scan);
            }
            stack.push(Level {
                dir,
                relative,
                children,
            });
        }
        let Some(level) = stack.last_mut() else {
            return Ok(scan);
        };
        let Some(name) = level.children.pop() else {
            stack.pop();
            continue;
        };
        match crate::source_metadata::open_preview_child(&level.dir, Path::new(&name), true) {
            Ok(child) => {
                if let Some(expected) = pinned_root {
                    let actual = crate::copy_source::root_identity(&child)?;
                    if actual.split(':').next() != expected.split(':').next()
                        || (media.is_some_and(MediaIdentity::uses_content_fingerprint)
                            && !crate::camera_identity::camera_mount_matches(&level.dir, &child)?)
                    {
                        scan.inventory.skipped += 1;
                        continue;
                    }
                }
                next = Some((child, level.relative.join(name)));
            }
            Err(_) => {
                scan.unreadable += 1;
                scan.inventory.skipped += 1;
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Listing {
    depth: usize,
    limit: usize,
    pinned: bool,
    camera: bool,
}

/// Lists one directory to its end, so no listing stays open while its subfolders are visited.
/// Returns false when the entry limit was reached.
fn list(
    dir: &cap_std::fs::Dir,
    relative: &Path,
    listing: Listing,
    visited: &mut usize,
    scan: &mut FolderScan,
    children: &mut Vec<String>,
    each: &mut dyn FnMut(SourceFile) -> Result<(), String>,
) -> Result<bool, String> {
    let entries = match dir.entries() {
        Ok(entries) => entries,
        Err(_) => {
            scan.unreadable += 1;
            scan.inventory.skipped += 1;
            return Ok(true);
        }
    };
    for entry in entries {
        if *visited == listing.limit {
            return Ok(false);
        }
        *visited += 1;
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                scan.unreadable += 1;
                scan.inventory.skipped += 1;
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            scan.unreadable += 1;
            scan.inventory.skipped += 1;
            continue;
        };
        let lower = name.to_lowercase();
        if name.starts_with('.')
            || [".photoslibrary", ".photolibrary", ".app", ".bundle"]
                .iter()
                .any(|suffix| lower.ends_with(suffix))
        {
            scan.inventory.skipped += 1;
            continue;
        }
        let meta = match dir.symlink_metadata(name) {
            Ok(meta) => meta,
            Err(_) => {
                scan.unreadable += 1;
                scan.inventory.skipped += 1;
                continue;
            }
        };
        // Links are never followed, so a link back to a parent cannot loop the traversal.
        if meta.is_symlink() {
            scan.inventory.skipped += 1;
            continue;
        }
        if !(meta.is_dir() || meta.is_file() && is_media_filename(name)) {
            continue;
        }
        let observation = match crate::source_metadata::probe(dir, Path::new(name), &meta) {
            Ok(observation) => observation,
            Err(_) => {
                scan.unreadable += 1;
                scan.inventory.skipped += 1;
                continue;
            }
        };
        if observation.excluded {
            scan.inventory.skipped += 1;
            continue;
        }
        if meta.is_dir() {
            if listing.depth == MAX_DEPTH {
                scan.inventory.truncated = true;
                scan.inventory.skipped += 1;
                continue;
            }
            children.push(name.into());
            continue;
        }
        // An empty file has no original to copy; it may still be being written.
        if meta.len() == 0 {
            scan.inventory.skipped += 1;
            scan.inventory.empty += 1;
            continue;
        }
        let watch_version = if listing.pinned {
            if !crate::copy_source::watchable(&meta, observation) {
                scan.inventory.skipped += 1;
                continue;
            }
            let version = if listing.camera {
                crate::copy_source::camera_version
            } else {
                crate::copy_source::watch_version
            };
            Some(version(dir, Path::new(name), &meta)?)
        } else {
            None
        };
        scan.inventory.photos += 1;
        scan.inventory.availability.record(observation, meta.len());
        scan.inventory.logical_bytes = scan
            .inventory
            .logical_bytes
            .checked_add(meta.len())
            .ok_or("source_inventory_size_invalid")?;
        each(SourceFile {
            relative: relative
                .join(name)
                .to_str()
                .ok_or("source_item_invalid")?
                .into(),
            bytes: meta.len(),
            watch_version,
        })?;
    }
    Ok(true)
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
        std::fs::write(root.join("nested/empty.jpg"), b"").unwrap();
        let scan = super::scan_batch(&root, super::Pin::Unpinned, None).unwrap();
        assert_eq!(scan.files.len(), 1);
        assert_eq!(
            super::Path::new(&scan.files[0].relative),
            super::Path::new("nested/photo.jpg")
        );
        assert_eq!(scan.files[0].bytes, 8);
        assert_eq!(scan.unreadable, 0);
        assert!(!scan.more);
        assert_eq!((scan.inventory.empty, scan.inventory.skipped), (1, 1));
        assert!(super::inventory(&root, 1).unwrap().truncated);
        std::fs::remove_dir_all(parent).unwrap();
    }

    struct Tree(std::path::PathBuf);
    impl Tree {
        fn new(name: &str) -> Self {
            let parent = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("frameleaf-{name}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&parent).unwrap();
            Self(parent)
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_large_library_scans_completely_in_batches_without_holding_every_folder_open() {
        // 1,000 subfolders is far more than the 256 open files a process may be allowed.
        let tree = Tree::new("large-scan");
        for folder in 0..1000 {
            let path = tree.0.join(format!("roll-{folder:04}"));
            std::fs::create_dir(&path).unwrap();
            for photo in 0..20 {
                std::fs::write(path.join(format!("{photo:02}.jpg")), b"x").unwrap();
            }
        }
        let mut seen = 0u64;
        let all = super::scan_each(&tree.0, super::Pin::Unpinned, &mut |_| {
            seen += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!((seen, all.inventory.photos), (20_000, 20_000));
        assert!(!all.inventory.truncated);
        assert_eq!((all.unreadable, all.inventory.skipped), (0, 0));
        assert!(all.files.is_empty(), "a streamed scan keeps no file list");

        let first = super::scan_batch(&tree.0, super::Pin::Unpinned, None).unwrap();
        assert_eq!(first.files.len(), super::BATCH_FILES);
        assert!(first.more && !first.inventory.truncated);
        assert!(first
            .files
            .windows(2)
            .all(|pair| pair[0].relative < pair[1].relative));
        let last = first.files.last().unwrap().relative.clone();
        let second = super::scan_batch(&tree.0, super::Pin::Unpinned, Some(&last)).unwrap();
        assert_eq!(second.files.len(), 10_000);
        assert!(!second.more);
        assert!(second.files[0].relative > last);
        let end = second.files.last().unwrap().relative.clone();
        let done = super::scan_batch(&tree.0, super::Pin::Unpinned, Some(&end)).unwrap();
        assert!(done.files.is_empty() && !done.more);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_back_to_a_parent_folder_is_skipped_and_the_scan_ends() {
        let tree = Tree::new("link-loop");
        std::fs::create_dir_all(tree.0.join("album/inner")).unwrap();
        std::fs::write(tree.0.join("album/inner/photo.jpg"), b"original").unwrap();
        std::os::unix::fs::symlink(&tree.0, tree.0.join("album/inner/loop")).unwrap();
        std::os::unix::fs::symlink(tree.0.join("album"), tree.0.join("again")).unwrap();
        let scan = super::scan_batch(&tree.0, super::Pin::Unpinned, None).unwrap();
        assert_eq!(scan.files.len(), 1);
        assert_eq!(scan.inventory.skipped, 2);
        assert!(!scan.inventory.truncated);
    }

    #[test]
    fn folders_nested_past_the_depth_guard_are_reported_as_a_partial_scan() {
        let tree = Tree::new("deep-scan");
        let mut path = tree.0.clone();
        for _ in 0..=super::MAX_DEPTH {
            path.push("d");
        }
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("photo.jpg"), b"original").unwrap();
        std::fs::write(path.parent().unwrap().join("photo.jpg"), b"original").unwrap();
        let scan = super::scan_batch(&tree.0, super::Pin::Unpinned, None).unwrap();
        assert!(scan.inventory.truncated);
        assert_eq!(scan.files.len(), 1);
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
