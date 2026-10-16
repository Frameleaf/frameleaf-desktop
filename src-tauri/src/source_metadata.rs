//! Metadata hints are snapshots; pinning intent and allocated blocks are not proof of residency.
use cap_std::fs::{Dir, Metadata};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
// Non-Windows probes cannot establish every availability state.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) enum Availability {
    Available,
    NeedsDownload,
    NotReady,
    #[default]
    Unknown,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Observation {
    pub availability: Availability,
    pub pinned: bool,
    pub excluded: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AvailabilitySummary {
    pub available: u64,
    pub needs_download: u64,
    pub not_ready: u64,
    pub unknown: u64,
    pub pinned: u64,
    pub download_bytes: u64,
}
impl AvailabilitySummary {
    pub(crate) fn record(&mut self, item: Observation, bytes: u64) {
        match item.availability {
            Availability::Available => self.available += 1,
            Availability::NeedsDownload => {
                self.needs_download += 1;
                self.download_bytes = self.download_bytes.saturating_add(bytes);
            }
            Availability::NotReady => self.not_ready += 1,
            Availability::Unknown => self.unknown += 1,
        }
        self.pinned += u64::from(item.pinned);
    }
}
#[cfg(any(windows, test))]
fn windows_state(attributes: u32, placeholder: u32) -> Observation {
    // cfapi.h: PARTIAL can mean downloaded-but-awaiting-validation; UNPINNED is not cloud-only.
    let valid_placeholder = placeholder != u32::MAX && placeholder & 1 != 0;
    let availability =
        if attributes & (0x1000 | 0x400000) != 0 || (valid_placeholder && placeholder & 32 != 0) {
            Availability::NeedsDownload
        } else if valid_placeholder && (placeholder & 16 != 0 || attributes & 0x40000 != 0) {
            Availability::NotReady
        } else if valid_placeholder {
            Availability::Available
        } else {
            Availability::Unknown
        };
    Observation {
        availability,
        pinned: attributes & 0x80000 != 0,
        excluded: attributes & (2 | 4) != 0 || (attributes & 0x400 != 0 && !valid_placeholder),
    }
}
#[cfg(any(target_os = "macos", test))]
fn mac_state(flags: u32) -> Observation {
    Observation {
        availability: if flags & 0x40000000 != 0 {
            Availability::NeedsDownload
        } else {
            Availability::Unknown
        },
        pinned: false,
        excluded: flags & 0x8000 != 0,
    }
}
pub(crate) fn probe(dir: &Dir, name: &Path, meta: &Metadata) -> Result<Observation, String> {
    if name != Path::new(".")
        && (name.components().count() != 1
            || !matches!(name.components().next(), Some(Component::Normal(_))))
    {
        return Err("source_item_invalid".into());
    }
    #[cfg(target_os = "macos")]
    {
        use cap_std::fs::MetadataExt;
        use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};
        let name = std::ffi::CString::new(name.as_os_str().as_bytes())
            .map_err(|_| "source_item_invalid")?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err("source_metadata_unavailable".into());
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_dev as u64 != meta.dev()
            || stat.st_ino != meta.ino()
            || stat.st_size as u64 != meta.len()
        {
            return Err("source_item_changed".into());
        }
        Ok(mac_state(stat.st_flags))
    }
    #[cfg(windows)]
    {
        use cap_std::fs::{MetadataExt, OpenOptions, OpenOptionsExt};
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::{
            CloudFilters::CfGetPlaceholderStateFromAttributeTag,
            FileSystem::{
                FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_TAG_INFO,
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_NO_RECALL, FILE_FLAG_OPEN_REPARSE_POINT,
                FILE_READ_ATTRIBUTES,
            },
        };
        let mut options = OpenOptions::new();
        options
            .read(true)
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(7)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | FILE_FLAG_OPEN_NO_RECALL
                    | FILE_FLAG_BACKUP_SEMANTICS,
            );
        let file = dir
            .open_with(name, &options)
            .map_err(|_| "source_metadata_unavailable")?;
        let opened = file.metadata().map_err(|_| "source_metadata_unavailable")?;
        if opened.len() != meta.len()
            || opened.is_dir() != meta.is_dir()
            || opened.file_attributes() != meta.file_attributes()
            || opened
                .modified()
                .map_err(|_| "source_metadata_unavailable")?
                != meta.modified().map_err(|_| "source_metadata_unavailable")?
        {
            return Err("source_item_changed".into());
        }
        let mut info = std::mem::MaybeUninit::<FILE_ATTRIBUTE_TAG_INFO>::uninit();
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileAttributeTagInfo,
                info.as_mut_ptr().cast(),
                std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        } == 0
        {
            return Err("source_metadata_unavailable".into());
        }
        let info = unsafe { info.assume_init() };
        Ok(windows_state(info.FileAttributes, unsafe {
            CfGetPlaceholderStateFromAttributeTag(info.FileAttributes, info.ReparseTag)
        }))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (dir, name, meta);
        Ok(Observation::default())
    }
}

/// Source previews have their own cloud-aware opener; runtime and staging roots stay strict.
pub(crate) fn open_preview_root(path: &Path) -> Result<Dir, String> {
    #[cfg(not(windows))]
    {
        crate::native_runtime::absolute_directory(path)?;
        Dir::open_ambient_dir(path, cap_std::ambient_authority())
            .map_err(|_| "source_folder_unavailable".into())
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        let mut parts = path.components();
        let Some(Component::Prefix(prefix)) = parts.next() else {
            return Err("source_folder_invalid".into());
        };
        if !matches!(
            prefix.kind(),
            Prefix::Disk(_)
                | Prefix::VerbatimDisk(_)
                | Prefix::UNC(_, _)
                | Prefix::VerbatimUNC(_, _)
        ) || !matches!(parts.next(), Some(Component::RootDir))
        {
            return Err("source_folder_invalid".into());
        }
        // Only the OS volume/share anchor is opened ambiently; every named child is handle-relative.
        let mut anchor = std::path::PathBuf::from(prefix.as_os_str());
        anchor.push(std::path::MAIN_SEPARATOR_STR);
        let mut dir = Dir::open_ambient_dir(anchor, cap_std::ambient_authority())
            .map_err(|_| "source_folder_unavailable")?;
        for part in parts {
            if !matches!(part, Component::Normal(_)) {
                return Err("source_folder_invalid".into());
            }
            dir = open_preview_child(&dir, Path::new(part.as_os_str()))?;
        }
        Ok(dir)
    }
}
pub(crate) fn open_preview_child(dir: &Dir, name: &Path) -> Result<Dir, String> {
    if name.components().count() != 1
        || !matches!(name.components().next(), Some(Component::Normal(_)))
    {
        return Err("source_item_invalid".into());
    }
    #[cfg(not(windows))]
    {
        let meta = dir
            .symlink_metadata(name)
            .map_err(|_| "source_metadata_unavailable")?;
        if !meta.is_dir() || meta.is_symlink() || probe(dir, name, &meta)?.excluded {
            return Err("source_folder_excluded".into());
        }
        dir.open_dir(name)
            .map_err(|_| "source_folder_unavailable".into())
    }
    #[cfg(windows)]
    {
        use cap_std::fs::{OpenOptions, OpenOptionsExt};
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::{
            Foundation::INVALID_HANDLE_VALUE,
            Storage::FileSystem::{
                ReOpenFile, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_NO_RECALL,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
                SYNCHRONIZE,
            },
        };
        let flags =
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_OPEN_REPARSE_POINT;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(3)
            .custom_flags(flags);
        // Attribute access cannot read an original if a file replaces the directory during traversal.
        let file = dir
            .open_with(name, &options)
            .map_err(|_| "source_folder_unavailable")?;
        let candidate = Dir::from_std_file(file.into_std());
        let meta = candidate
            .dir_metadata()
            .map_err(|_| "source_metadata_unavailable")?;
        if !meta.is_dir() || meta.is_symlink() || probe(&candidate, Path::new("."), &meta)?.excluded
        {
            return Err("source_folder_excluded".into());
        }
        // Reopen the validated object rather than resolving its name again with directory-list rights.
        let handle = unsafe {
            ReOpenFile(
                candidate.as_raw_handle(),
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                3,
                flags,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err("source_folder_unavailable".into());
        }
        Ok(Dir::from_std_file(unsafe {
            std::fs::File::from_raw_handle(handle)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preview_root_requires_a_directory_and_child_names_cannot_escape() {
        let path =
            std::env::temp_dir().join(format!("frameleaf-source-dir-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("photo.jpg"), b"not opened by preview").unwrap();
        std::fs::create_dir(path.join("child")).unwrap();
        let root = std::fs::canonicalize(&path).unwrap();
        let dir = open_preview_root(&root).unwrap();
        assert!(open_preview_child(&dir, Path::new("photo.jpg")).is_err());
        assert!(open_preview_child(&dir, Path::new("child")).is_ok());
        assert!(open_preview_child(&dir, Path::new("..")).is_err());
        assert!(open_preview_child(&dir, Path::new("child/..")).is_err());
        assert!(open_preview_root(&root.join("photo.jpg")).is_err());
        drop(dir);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn windows_preview_rejects_device_paths_and_link_reparse_tags() {
        for path in [
            r"C:relative",
            r"\\.\NUL",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1",
        ] {
            assert!(open_preview_root(Path::new(path)).is_err());
        }
        use windows_sys::Win32::Storage::CloudFilters::CfGetPlaceholderStateFromAttributeTag;
        // winnt.h: mount point and symbolic-link tags must never acquire cloud-placeholder authority.
        for tag in [0xa0000003, 0xa000000c] {
            let attributes = 0x400 | 0x10;
            let state = unsafe { CfGetPlaceholderStateFromAttributeTag(attributes, tag) };
            assert!(windows_state(attributes, state).excluded);
        }
    }
    #[test]
    fn cloud_state_and_pinning_intent_are_separate_and_never_inferred_from_allocation() {
        let pinned_missing = windows_state(0x80000 | 0x400000, 1 | 16 | 32);
        assert!(pinned_missing.pinned);
        assert_eq!(pinned_missing.availability, Availability::NeedsDownload);
        assert_eq!(
            windows_state(0x80000, 1).availability,
            Availability::Available
        );
        assert_eq!(
            windows_state(0, 1 | 16).availability,
            Availability::NotReady
        );
        assert_eq!(
            windows_state(0x100000, 0).availability,
            Availability::Unknown
        );
        assert_eq!(
            windows_state(0, u32::MAX).availability,
            Availability::Unknown
        );
        assert!(windows_state(2, 0).excluded);
        assert!(windows_state(4, 0).excluded);
        assert!(!windows_state(0, 0).excluded);
        assert_eq!(
            mac_state(0x40000000).availability,
            Availability::NeedsDownload
        );
        assert_eq!(mac_state(0).availability, Availability::Unknown);
        assert!(mac_state(0x8000).excluded);
        let mut summary = AvailabilitySummary::default();
        summary.record(pinned_missing, 100);
        summary.record(mac_state(0), 300);
        summary.record(windows_state(0, 1), 400);
        summary.record(windows_state(0, 1 | 16), 500);
        assert_eq!(summary.needs_download, 1);
        assert_eq!(summary.download_bytes, 100);
        assert_eq!(summary.pinned, 1);
        assert_eq!(summary.unknown, 1);
        assert_eq!(summary.available, 1);
        assert_eq!(summary.not_ready, 1);
    }
}
