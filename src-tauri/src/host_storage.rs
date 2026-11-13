//! Admission for database state, separate from external photo-library storage.
use std::path::Path;

// shortcut: startup floor only; add library/model/backup sizing before enabling full-host setup.
pub(crate) const MINIMUM_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug)]
struct Volume {
    filesystem: String,
    local: bool,
    read_only: bool,
    available_bytes: u64,
}

fn admit_cleanup(volume: &Volume) -> Result<(), String> {
    let supported = match std::env::consts::OS {
        "macos" => matches!(volume.filesystem.as_str(), "apfs" | "hfs"),
        "linux" => matches!(volume.filesystem.as_str(), "ext" | "xfs" | "btrfs" | "zfs"),
        "windows" => volume.filesystem == "NTFS",
        _ => false,
    };
    if !supported || !volume.local || volume.read_only {
        return Err("host_database_volume_unsupported".into());
    }
    Ok(())
}

fn admit(volume: &Volume) -> Result<(), String> {
    admit_cleanup(volume)?;
    if volume.available_bytes < MINIMUM_FREE_BYTES {
        return Err("host_database_space_insufficient".into());
    }
    Ok(())
}

pub(crate) fn check(path: &Path) -> Result<(), String> {
    let directory = directory(path)?;
    cloud_storage_check(path, &directory)?;
    admit(&inspect(&directory)?)
}

/// A watched folder must be on a local volume. Its files remain subject to source admission.
pub(crate) fn is_local(directory: &std::fs::File) -> Result<bool, String> {
    Ok(inspect(directory)?.local)
}

pub(crate) fn media_destination(path: &Path, directory: &std::fs::File) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let volume = inspect(directory)?;
    #[cfg(target_os = "linux")]
    let volume = inspect_linux(directory, true)?;
    #[cfg(windows)]
    let volume = inspect_windows(directory, true)?;
    if !volume.local || volume.read_only {
        return Err("media_copy_destination_invalid".into());
    }
    #[cfg(not(windows))]
    cloud_storage_check(path, directory)?;
    #[cfg(windows)]
    if !["FAT", "FAT32", "exFAT"]
        .iter()
        .any(|kind| volume.filesystem.eq_ignore_ascii_case(kind))
    {
        cloud_storage_check(path, directory)?;
    }
    Ok(())
}

/// Retirement may reclaim storage below the startup floor; all volume and cloud checks still apply.
pub(crate) fn check_cleanup(path: &Path) -> Result<(), String> {
    let directory = directory(path)?;
    cloud_storage_check(path, &directory)?;
    admit_cleanup(&inspect(&directory)?)
}

/// The bytes an ordinary user may still write on the volume that holds `path`.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
pub(crate) fn available_bytes(path: &Path) -> Result<u64, String> {
    Ok(inspect(&directory(path)?)?.available_bytes)
}

/// Open the physical directory without following links; inspection does not require startup headroom.
pub(crate) fn directory(path: &Path) -> Result<std::fs::File, String> {
    crate::native_runtime::absolute_directory(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
        .open(path)
        .map_err(|_| "host_storage_unavailable".into())
}

#[cfg(any(target_os = "macos", test))]
fn mac_provider_path(path: &Path) -> bool {
    let parts: Vec<_> = path.components().collect();
    parts.windows(2).any(|pair| {
        pair[0].as_os_str().eq_ignore_ascii_case("Library")
            && (pair[1].as_os_str().eq_ignore_ascii_case("CloudStorage")
                || pair[1].as_os_str().eq_ignore_ascii_case("Mobile Documents"))
    })
}

#[cfg(any(windows, test))]
fn windows_sync_result(result: i32) -> Result<(), String> {
    match result as u32 {
        0 => Err("host_database_cloud_storage_forbidden".into()),
        // HRESULT_FROM_WIN32: NOT_A_CLOUD_FILE, CLOUD_FILE_NOT_UNDER_SYNC_ROOT, NOT_A_CLOUD_SYNC_ROOT.
        0x80070178 | 0x80070186 | 0x80070195 => Ok(()),
        _ => Err("host_database_cloud_state_unknown".into()),
    }
}

#[cfg(windows)]
fn cloud_storage_check(_path: &Path, directory: &std::fs::File) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::CloudFilters::{
        CfGetSyncRootInfoByHandle, CF_SYNC_ROOT_BASIC_INFO, CF_SYNC_ROOT_INFO_BASIC,
    };
    let mut info = CF_SYNC_ROOT_BASIC_INFO::default();
    let result = unsafe {
        CfGetSyncRootInfoByHandle(
            directory.as_raw_handle(),
            CF_SYNC_ROOT_INFO_BASIC,
            (&mut info as *mut CF_SYNC_ROOT_BASIC_INFO).cast(),
            std::mem::size_of_val(&info) as u32,
            std::ptr::null_mut(),
        )
    };
    #[cfg(test)]
    eprintln!("native cloud-storage probe HRESULT: {result:#010x}");
    windows_sync_result(result)
}

#[cfg(target_os = "macos")]
fn cloud_storage_check(path: &Path, _directory: &std::fs::File) -> Result<(), String> {
    use core_foundation::{
        array::CFArray,
        base::{CFType, TCFType},
        boolean::CFBoolean,
        dictionary::CFDictionary,
        string::CFString,
        url::{kCFURLIsUbiquitousItemKey, CFURLCopyResourcePropertiesForKeys, CFURL},
    };
    // shortcut: legacy sync roots outside iCloud/standard File Provider paths need qualification before enabling setup.
    if mac_provider_path(path) {
        return Err("host_database_cloud_storage_forbidden".into());
    }
    // Check ancestors too: an existing empty subdirectory may not have its own iCloud metadata yet.
    for ancestor in path.ancestors() {
        let url = CFURL::from_path(ancestor, true).ok_or("host_database_cloud_state_unknown")?;
        let key = unsafe { CFString::wrap_under_get_rule(kCFURLIsUbiquitousItemKey) };
        let keys = CFArray::from_CFTypes(std::slice::from_ref(&key));
        let raw = unsafe {
            CFURLCopyResourcePropertiesForKeys(
                url.as_concrete_TypeRef(),
                keys.as_concrete_TypeRef(),
                std::ptr::null_mut(),
            )
        };
        if raw.is_null() {
            return Err("host_database_cloud_state_unknown".into());
        }
        let properties: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_create_rule(raw) };
        // Core Foundation omits unavailable keys without an error on ordinary local directories.
        if let Some(value) = properties.find(&key) {
            let value = value
                .downcast::<CFBoolean>()
                .ok_or("host_database_cloud_state_unknown")?;
            if bool::from(value) {
                return Err("host_database_cloud_storage_forbidden".into());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cloud_storage_check(_path: &Path, _directory: &std::fs::File) -> Result<(), String> {
    // shortcut: local user-space sync has no generic Linux registry; qualify the fixed app-state root before enabling setup.
    Ok(())
}

#[cfg(target_os = "macos")]
fn inspect(directory: &std::fs::File) -> Result<Volume, String> {
    use std::os::fd::AsRawFd;
    let mut info = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::fstatfs(directory.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err("host_storage_unavailable".into());
    }
    let info = unsafe { info.assume_init() };
    let filesystem: Vec<_> = info
        .f_fstypename
        .iter()
        .take_while(|v| **v != 0)
        .map(|v| *v as u8)
        .collect();
    Ok(Volume {
        filesystem: String::from_utf8(filesystem).map_err(|_| "host_storage_unavailable")?,
        local: info.f_flags & libc::MNT_LOCAL as u32 != 0,
        read_only: info.f_flags & libc::MNT_RDONLY as u32 != 0,
        available_bytes: info
            .f_bavail
            .checked_mul(u64::from(info.f_bsize))
            .ok_or("host_storage_unavailable")?,
    })
}

#[cfg(target_os = "linux")]
fn inspect(directory: &std::fs::File) -> Result<Volume, String> {
    inspect_linux(directory, false)
}

#[cfg(target_os = "linux")]
fn inspect_linux(directory: &std::fs::File, allow_removable: bool) -> Result<Volume, String> {
    use std::os::fd::AsRawFd;
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    let mut capacity = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    if unsafe { libc::fstatfs(directory.as_raw_fd(), fs.as_mut_ptr()) } != 0
        || unsafe { libc::fstatvfs(directory.as_raw_fd(), capacity.as_mut_ptr()) } != 0
    {
        return Err("host_storage_unavailable".into());
    }
    let fs = unsafe { fs.assume_init() };
    let capacity = unsafe { capacity.assume_init() };
    const EXFAT: u64 = 0x2011_bab0;
    const NTFS3: u64 = 0x7366_746e;
    const FAT: u64 = libc::MSDOS_SUPER_MAGIC as u64;
    // ext2/3/4 share the same kernel filesystem identity; unknown/FUSE/network types stay refused.
    let filesystem = match fs.f_type as u64 {
        0xef53 => "ext",
        0x58465342 => "xfs",
        0x9123683e => "btrfs",
        0x2fc12fc1 => "zfs",
        EXFAT if allow_removable => "exfat",
        FAT if allow_removable => "fat",
        NTFS3 if allow_removable => "ntfs3",
        _ => "unknown",
    };
    Ok(Volume {
        filesystem: filesystem.into(),
        local: filesystem != "unknown",
        read_only: capacity.f_flag & libc::ST_RDONLY != 0,
        available_bytes: u64::try_from(
            u128::from(capacity.f_bavail) * u128::from(capacity.f_frsize),
        )
        .map_err(|_| "host_storage_unavailable")?,
    })
}

#[cfg(windows)]
fn inspect(directory: &std::fs::File) -> Result<Volume, String> {
    inspect_windows(directory, false)
}

#[cfg(windows)]
fn inspect_windows(directory: &std::fs::File, allow_removable: bool) -> Result<Volume, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetDriveTypeW, GetFinalPathNameByHandleW,
        GetVolumeInformationByHandleW, GetVolumePathNameW,
    };
    let handle = directory.as_raw_handle();
    let mut path = vec![0u16; 32768];
    let length =
        unsafe { GetFinalPathNameByHandleW(handle, path.as_mut_ptr(), path.len() as u32, 0) }
            as usize;
    if length == 0 || length >= path.len() {
        return Err("host_storage_unavailable".into());
    }
    let mut root = vec![0u16; 32768];
    let mut filesystem = [0u16; 256];
    let mut flags = 0;
    let mut available = 0;
    if unsafe { GetVolumePathNameW(path.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0
        || unsafe {
            GetVolumeInformationByHandleW(
                handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut flags,
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            )
        } == 0
        || unsafe {
            GetDiskFreeSpaceExW(
                root.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
    {
        return Err("host_storage_unavailable".into());
    }
    let end = filesystem
        .iter()
        .position(|v| *v == 0)
        .ok_or("host_storage_unavailable")?;
    let drive = unsafe { GetDriveTypeW(root.as_ptr()) };
    Ok(Volume {
        filesystem: String::from_utf16(&filesystem[..end])
            .map_err(|_| "host_storage_unavailable")?,
        local: drive == 3 || (allow_removable && drive == 2), // DRIVE_FIXED or DRIVE_REMOVABLE.
        read_only: flags & 0x00080000 != 0,                   // FILE_READ_ONLY_VOLUME.
        available_bytes: available,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_provider_roots_are_refused_even_when_fully_downloaded() {
        for path in [
            "/Users/example/Library/CloudStorage/OneDrive-Personal/Frameleaf",
            "/Users/example/Library/Mobile Documents/com~apple~CloudDocs/Frameleaf",
            "/Volumes/External/library/cloudstorage/Provider/database",
        ] {
            assert!(mac_provider_path(Path::new(path)));
        }
        for path in [
            "/Users/example/Library/Application Support/Frameleaf",
            "/Volumes/CloudStorage/Frameleaf",
            "/Users/example/Library/CloudStorage-old/Frameleaf",
        ] {
            assert!(!mac_provider_path(Path::new(path)));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn database_storage_refuses_a_local_directory_under_a_provider_root() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-cloud-storage-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let mut provider = root.clone();
        for part in ["Library", "CloudStorage", "FixtureProvider", "Frameleaf"] {
            provider.push(part);
            crate::runtime_store::private_directory(&provider).unwrap();
        }
        assert_eq!(
            check(&provider).unwrap_err(),
            "host_database_cloud_storage_forbidden"
        );
        assert!(std::fs::read_dir(&provider).unwrap().next().is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn windows_sync_root_probe_refuses_membership_and_unexpected_errors() {
        assert_eq!(
            windows_sync_result(0).unwrap_err(),
            "host_database_cloud_storage_forbidden"
        );
        for code in [376, 390, 405] {
            assert!(windows_sync_result((0x80070000u32 | code) as i32).is_ok());
        }
        for result in [
            0x80070001u32 as i32,
            0x80070005u32 as i32,
            0x80070002u32 as i32,
            -1,
            1,
        ] {
            assert_eq!(
                windows_sync_result(result).unwrap_err(),
                "host_database_cloud_state_unknown"
            );
        }
    }

    #[test]
    fn database_storage_refuses_network_readonly_unknown_and_low_capacity() {
        let mut volume = Volume {
            filesystem: if cfg!(target_os = "macos") {
                "apfs"
            } else if cfg!(windows) {
                "NTFS"
            } else {
                "ext"
            }
            .into(),
            local: true,
            read_only: false,
            available_bytes: MINIMUM_FREE_BYTES,
        };
        assert!(admit(&volume).is_ok());
        volume.local = false;
        assert_eq!(
            admit(&volume).unwrap_err(),
            "host_database_volume_unsupported"
        );
        volume.local = true;
        volume.read_only = true;
        assert_eq!(
            admit(&volume).unwrap_err(),
            "host_database_volume_unsupported"
        );
        volume.read_only = false;
        volume.filesystem = "unknown".into();
        assert_eq!(
            admit(&volume).unwrap_err(),
            "host_database_volume_unsupported"
        );
        volume.filesystem = "nfs".into();
        assert_eq!(
            admit(&volume).unwrap_err(),
            "host_database_volume_unsupported"
        );
    }

    #[test]
    fn cleanup_storage_keeps_volume_safety_without_startup_headroom() {
        let mut volume = Volume {
            filesystem: if cfg!(target_os = "macos") {
                "apfs"
            } else if cfg!(windows) {
                "NTFS"
            } else {
                "ext"
            }
            .into(),
            local: true,
            read_only: false,
            available_bytes: 0,
        };
        assert_eq!(
            admit(&volume).unwrap_err(),
            "host_database_space_insufficient"
        );
        assert!(admit_cleanup(&volume).is_ok());
        volume.local = false;
        assert_eq!(
            admit_cleanup(&volume).unwrap_err(),
            "host_database_volume_unsupported"
        );
        volume.local = true;
        volume.read_only = true;
        assert!(admit_cleanup(&volume).is_err());
        volume.read_only = false;
        volume.filesystem = "nfs".into();
        assert!(admit_cleanup(&volume).is_err());
        assert!(check_cleanup(Path::new("relative")).is_err());
    }

    #[test]
    fn database_storage_headroom_is_available_to_the_current_user() {
        let fs = if cfg!(target_os = "macos") {
            "apfs"
        } else if cfg!(windows) {
            "NTFS"
        } else {
            "ext"
        };
        for bytes in [0, MINIMUM_FREE_BYTES - 1] {
            let volume = Volume {
                filesystem: fs.into(),
                local: true,
                read_only: false,
                available_bytes: bytes,
            };
            assert_eq!(
                admit(&volume).unwrap_err(),
                "host_database_space_insufficient"
            );
        }
    }

    #[test]
    fn database_storage_inspects_the_actual_private_directory() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-storage-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let outcome = check(&root);
        std::fs::remove_dir(&root).unwrap();
        // CI temp storage may be unsupported, short of space, or lack a working Windows cloud probe.
        if let Err(code) = outcome {
            assert!(
                matches!(
                    code.as_str(),
                    "host_database_volume_unsupported" | "host_database_space_insufficient"
                ) || (cfg!(windows) && code == "host_database_cloud_state_unknown"),
                "{code}"
            );
        }
        assert!(check(&root).is_err());
        assert!(check(Path::new("relative")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn database_storage_never_follows_a_linked_directory() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-storage-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let alias = root.with_extension("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        assert!(check(&alias).is_err());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
