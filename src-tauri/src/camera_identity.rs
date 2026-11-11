//! Durable identity from the opened camera folder, independent of its current mount path.
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
mod linux_fat;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MediaIdentity {
    volume: String,
    folder: String,
}

const UNAVAILABLE: &str = "source_camera_identity_unavailable";

impl MediaIdentity {
    pub(crate) fn read(dir: &Dir) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        if let Some(folder) = linux_fat::folder(dir)? {
            return Ok(Self {
                volume: volume(dir)?,
                folder,
            });
        }
        Self::legacy(dir)
    }

    fn legacy(dir: &Dir) -> Result<Self, String> {
        let mounted = crate::copy_source::root_identity(dir)?;
        let (_, folder) = mounted.split_once(':').ok_or(UNAVAILABLE)?;
        Ok(Self {
            volume: volume(dir)?,
            folder: folder.into(),
        })
    }

    pub(crate) fn uses_content_fingerprint(&self) -> bool {
        self.folder.starts_with("linux-fat-v1:")
    }

    pub(crate) fn require(&self, dir: &Dir) -> Result<(), String> {
        // Existing signed grants retain their original inode-based verification.
        let actual = if self.uses_content_fingerprint() {
            Self::read(dir)?
        } else {
            Self::legacy(dir)?
        };
        if *self != actual {
            return Err("source_camera_changed".into());
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn volume(dir: &Dir) -> Result<String, String> {
    use std::os::fd::AsRawFd;
    let mut attrs = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    // The buffer contains its length followed by the fixed 16-byte volume UUID.
    let mut data = [0u8; 20];
    let result = unsafe {
        libc::fgetattrlist(
            dir.as_raw_fd(),
            (&mut attrs as *mut libc::attrlist).cast(),
            data.as_mut_ptr().cast(),
            data.len(),
            0,
        )
    };
    if result != 0 || u32::from_ne_bytes(data[..4].try_into().unwrap()) as usize != data.len() {
        return Err(UNAVAILABLE.into());
    }
    let id = uuid::Uuid::from_bytes(data[4..].try_into().unwrap());
    if id.is_nil() {
        return Err(UNAVAILABLE.into());
    }
    Ok(id.to_string())
}

#[cfg(target_os = "linux")]
fn volume(dir: &Dir) -> Result<String, String> {
    use cap_std::fs::MetadataExt as CapMetadataExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let device = dir.dir_metadata().map_err(|_| UNAVAILABLE)?.dev();
    // udev binds a filesystem UUID to the block device. A mount name or st_dev alone can be reused.
    let mut selected = None;
    let entries = std::fs::read_dir("/dev/disk/by-uuid").map_err(|_| UNAVAILABLE)?;
    for (index, entry) in entries.enumerate() {
        if index >= 256 {
            return Err(UNAVAILABLE.into());
        }
        let entry = entry.map_err(|_| UNAVAILABLE)?;
        let Ok(target) = std::fs::metadata(entry.path()) else {
            continue;
        };
        if !target.file_type().is_block_device() || target.rdev() != device {
            continue;
        }
        let id = entry.file_name().into_string().map_err(|_| UNAVAILABLE)?;
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
            || selected.replace(id.to_ascii_lowercase()).is_some()
        {
            return Err(UNAVAILABLE.into());
        }
    }
    selected.ok_or_else(|| UNAVAILABLE.into())
}

#[cfg(windows)]
fn volume(dir: &Dir) -> Result<String, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_OPENED, VOLUME_NAME_GUID,
    };
    let mut path = vec![0u16; 32768];
    let written = unsafe {
        GetFinalPathNameByHandleW(
            dir.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            FILE_NAME_OPENED | VOLUME_NAME_GUID,
        )
    } as usize;
    if written == 0 || written >= path.len() {
        return Err(UNAVAILABLE.into());
    }
    let text = String::from_utf16(&path[..written]).map_err(|_| UNAVAILABLE)?;
    let raw = text
        .strip_prefix(r"\\?\Volume{")
        .and_then(|path| path.split_once(r"}\").map(|(id, _)| id))
        .ok_or(UNAVAILABLE)?;
    let id = uuid::Uuid::parse_str(raw).map_err(|_| UNAVAILABLE)?;
    if id.is_nil() {
        return Err(UNAVAILABLE.into());
    }
    let mounted = crate::copy_source::root_identity(dir)?;
    let (serial, _) = mounted.split_once(':').ok_or(UNAVAILABLE)?;
    Ok(format!("{id}:{serial}"))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn volume(_dir: &Dir) -> Result<String, String> {
    Err(UNAVAILABLE.into())
}

pub(crate) fn camera_mount_matches(root: &Dir, child: &Dir) -> Result<bool, String> {
    #[cfg(target_os = "linux")]
    {
        linux_fat::same_mount(root, child)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, child);
        Err(UNAVAILABLE.into())
    }
}

pub(crate) fn camera_file_birth(dir: &Dir, file: &cap_std::fs::File) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        if !linux_fat::same_mount(dir, file)? {
            return Err("source_camera_changed".into());
        }
        linux_fat::file_birth(file)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dir, file);
        Err(UNAVAILABLE.into())
    }
}
