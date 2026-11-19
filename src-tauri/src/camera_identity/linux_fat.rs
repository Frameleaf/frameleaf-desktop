use super::UNAVAILABLE;
use cap_std::fs::Dir;
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    io::Read,
    os::{
        fd::AsRawFd,
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Component, Path, PathBuf},
};

pub(super) const PREFIX: &str = "linux-fat-v1:";
const MAX_MOUNTS: u64 = 1024 * 1024;

pub(super) fn folder(dir: &Dir) -> Result<Option<String>, String> {
    let mut info = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::fstatfs(dir.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err(UNAVAILABLE.into());
    }
    // Linux's VFAT and exFAT drivers allocate inodes anew on remount.
    let filesystem = match unsafe { info.assume_init() }.f_type {
        0x4d44 => b"vfat".as_slice(),
        0x2011_bab0 => b"exfat".as_slice(),
        _ => return Ok(None),
    };
    let metadata = metadata(dir)?;
    let fd_path = std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .map_err(|_| UNAVAILABLE)?;
    if !fd_path.is_absolute() || fd_path.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return Err(UNAVAILABLE.into());
    }
    let mut mounts = Vec::new();
    std::fs::File::open("/proc/self/mountinfo")
        .map_err(|_| UNAVAILABLE)?
        .take(MAX_MOUNTS + 1)
        .read_to_end(&mut mounts)
        .map_err(|_| UNAVAILABLE)?;
    if mounts.len() as u64 > MAX_MOUNTS {
        return Err(UNAVAILABLE.into());
    }
    let mount = mount_point(&mounts, metadata.stx_mnt_id, filesystem)?;
    let relative = fd_path.strip_prefix(mount).map_err(|_| UNAVAILABLE)?;
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(UNAVAILABLE.into());
    }
    // A filesystem root has no directory-entry creation time. The volume ID supplies its identity.
    let birth = if relative.as_os_str().is_empty() {
        "root".into()
    } else {
        birth(&metadata).ok_or(UNAVAILABLE)?
    };
    let mut hash = Sha256::new();
    hash.update(filesystem);
    hash.update([0]);
    hash.update(birth.as_bytes());
    hash.update([0]);
    hash.update(relative.as_os_str().as_bytes());
    Ok(Some(format!("{PREFIX}{:x}", hash.finalize())))
}

pub(super) fn same_mount(left: &impl AsRawFd, right: &impl AsRawFd) -> Result<bool, String> {
    Ok(metadata(left)?.stx_mnt_id == metadata(right)?.stx_mnt_id)
}

pub(super) fn file_birth(file: &cap_std::fs::File) -> Result<String, String> {
    // Some cameras leave creation time empty. Those files still require a full content hash.
    Ok(birth(&metadata(file)?).unwrap_or_else(|| "unset".into()))
}

fn metadata(handle: &impl AsRawFd) -> Result<libc::statx, String> {
    let mut value = std::mem::MaybeUninit::<libc::statx>::zeroed();
    if unsafe {
        libc::statx(
            handle.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID | libc::STATX_BTIME,
            value.as_mut_ptr(),
        )
    } != 0
    {
        return Err(UNAVAILABLE.into());
    }
    let value = unsafe { value.assume_init() };
    if value.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(UNAVAILABLE.into());
    }
    Ok(value)
}

fn birth(value: &libc::statx) -> Option<String> {
    let birth = value.stx_btime;
    (value.stx_mask & libc::STATX_BTIME != 0 && (birth.tv_sec != 0 || birth.tv_nsec != 0))
        .then(|| format!("{}:{}", birth.tv_sec, birth.tv_nsec))
}

fn mount_point(records: &[u8], id: u64, filesystem: &[u8]) -> Result<PathBuf, String> {
    let id = id.to_string();
    for line in records.split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b' ');
        if fields.next() != Some(id.as_bytes()) {
            continue;
        }
        // A bind mount of a subdirectory does not establish the whole volume's pathname.
        if fields.nth(2) != Some(b"/".as_slice()) {
            return Err(UNAVAILABLE.into());
        }
        let path = fields.next().ok_or(UNAVAILABLE)?;
        if !fields.any(|field| field == b"-") || fields.next() != Some(filesystem) {
            return Err(UNAVAILABLE.into());
        }
        return unescape(path);
    }
    Err(UNAVAILABLE.into())
}

fn unescape(path: &[u8]) -> Result<PathBuf, String> {
    let mut bytes = Vec::with_capacity(path.len());
    let mut remaining = path;
    while let Some((&byte, tail)) = remaining.split_first() {
        remaining = tail;
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        let (escape, tail) = remaining.split_at_checked(3).ok_or(UNAVAILABLE)?;
        bytes.push(match escape {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err(UNAVAILABLE.into()),
        });
        remaining = tail;
    }
    let path = PathBuf::from(OsString::from_vec(bytes));
    if !Path::new(&path).is_absolute() {
        return Err(UNAVAILABLE.into());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_lookup_uses_the_open_descriptor_mount_and_rejects_subdirectory_binds() {
        let rows = b"20 1 7:1 / /mnt/other rw - exfat /dev/loop0 rw\n\
            21 1 7:1 / /mnt/camera\\040card rw shared:7 - exfat /dev/loop0 rw\n\
            22 1 7:1 /DCIM /mnt/bind rw - exfat /dev/loop0 rw";
        assert_eq!(
            mount_point(rows, 21, b"exfat").unwrap(),
            Path::new("/mnt/camera card")
        );
        assert!(mount_point(rows, 21, b"vfat").is_err());
        assert!(mount_point(rows, 22, b"exfat").is_err());
    }
}
