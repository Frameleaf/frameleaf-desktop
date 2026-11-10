//! Mounted camera storage hints. Discovery inspects directory metadata only.
use crate::photo_sources::RootHint;
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Offer conventional camera folders on mounted drives, leaving other folders to the picker.
pub(crate) fn discover(home: &Path) -> Vec<RootHint> {
    let mut hints: Vec<_> = volumes(home)
        .into_iter()
        .filter_map(|root| {
            let path = camera_folder(&root)?;
            let label = root.file_name().and_then(|name| name.to_str());
            Some(RootHint {
                label: label
                    .unwrap_or_else(|| root.to_str().unwrap_or("Camera storage"))
                    .into(),
                path: path.to_str()?.into(),
            })
        })
        .collect();
    hints.sort_by(|a, b| a.path.cmp(&b.path));
    hints.dedup_by(|a, b| a.path == b.path);
    hints.truncate(16);
    hints
}

/// Refuse links before suggesting a folder. The existing picker verifies the actual selection.
fn camera_folder(root: &Path) -> Option<PathBuf> {
    ["DCIM", "dcim"]
        .into_iter()
        .map(|name| root.join(name))
        .find(|path| {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return false;
            };
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return false;
                }
            }
            metadata.is_dir()
        })
}

#[cfg(unix)]
fn mounted_children(parent: &Path) -> Vec<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let Ok(parent_meta) = fs::symlink_metadata(parent) else {
        return Vec::new();
    };
    if !parent_meta.is_dir() {
        return Vec::new();
    }
    fs::read_dir(parent)
        .into_iter()
        .flatten()
        .take(64)
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).ok()?;
            (metadata.is_dir() && metadata.dev() != parent_meta.dev()).then_some(path)
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn volumes(_home: &Path) -> Vec<PathBuf> {
    mounted_children(Path::new("/Volumes"))
}

#[cfg(target_os = "linux")]
fn volumes(home: &Path) -> Vec<PathBuf> {
    let mut roots = mounted_children(Path::new("/media"));
    if let Some(user) = home.file_name() {
        roots.extend(mounted_children(&Path::new("/media").join(user)));
        roots.extend(mounted_children(&Path::new("/run/media").join(user)));
    }
    roots
}

#[cfg(windows)]
fn volumes(_home: &Path) -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    let drives = unsafe { GetLogicalDrives() };
    (0..26)
        .filter(|index| drives & (1 << index) != 0)
        .filter_map(|index| {
            let letter = b'A' + index as u8;
            let path = [u16::from(letter), u16::from(b':'), u16::from(b'\\'), 0];
            // DRIVE_REMOVABLE. Fixed disks and network drives are available in Add Folder.
            (unsafe { GetDriveTypeW(path.as_ptr()) } == 2)
                .then(|| PathBuf::from(format!("{}:\\", char::from(letter))))
        })
        .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn volumes(_home: &Path) -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_requires_a_camera_directory() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir(&root).unwrap();
        let camera = root.join("DCIM");
        assert!(camera_folder(&root).is_none());
        fs::write(&camera, b"file").unwrap();
        assert!(camera_folder(&root).is_none());
        fs::remove_file(&camera).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&root, &camera).unwrap();
            assert!(camera_folder(&root).is_none());
            fs::remove_file(&camera).unwrap();
        }
        fs::create_dir(&camera).unwrap();
        assert_eq!(camera_folder(&root), Some(camera));
        fs::remove_dir_all(root).unwrap();
    }
}
