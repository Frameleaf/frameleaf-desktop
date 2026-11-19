use cap_std::fs::{Dir, File, OpenOptions};
use std::{
    ffi::{OsStr, OsString},
    io,
    path::{Path, PathBuf},
};
use uuid::Uuid;

const INVALID: &str = "media_copy_destination_invalid";
const WRITE: &str = "media_copy_write_failed";

pub(super) struct Destination {
    directory: Dir,
    path: PathBuf,
    identity: String,
}

impl Destination {
    pub(super) fn open(path: PathBuf) -> Result<Self, &'static str> {
        let directory = open(&path)?;
        crate::host_storage::media_destination(&path, &directory).map_err(|_| INVALID)?;
        Self::from_directory(path, directory)
    }

    fn from_directory(path: PathBuf, directory: std::fs::File) -> Result<Self, &'static str> {
        #[cfg(target_os = "macos")]
        require_exclusive_rename(&directory)?;
        let directory = Dir::from_std_file(directory);
        let identity = crate::copy_source::root_identity(&directory).map_err(|_| INVALID)?;
        Ok(Self {
            directory,
            path,
            identity,
        })
    }

    pub(super) fn space(&self, required: u64) -> Result<(), &'static str> {
        if crate::copy_source::available_bytes(&self.directory).map_err(|_| INVALID)? < required {
            return Err("media_copy_space_insufficient");
        }
        Ok(())
    }

    fn reopen(&self) -> Result<Dir, &'static str> {
        let current = Dir::from_std_file(open(&self.path)?);
        if crate::copy_source::root_identity(&current).map_err(|_| INVALID)? != self.identity {
            return Err(INVALID);
        }
        Ok(current)
    }

    pub(super) fn start(self, package: Uuid) -> Result<Partial, &'static str> {
        self.start_named(
            format!("Frameleaf-{package}.frameleaf-preservation.zip").into(),
            ".frameleaf-preservation-copy",
        )
    }

    fn start_named(self, name: OsString, prefix: &str) -> Result<Partial, &'static str> {
        match self.directory.symlink_metadata(&name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err("media_copy_destination_exists"),
            Err(_) => return Err(INVALID),
        }
        // On FAT, renaming to a longer name can change the open file's identifier.
        let temporary = format!("{prefix}-{}.zip.partial", Uuid::new_v4());
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = self
            .directory
            .open_with(&temporary, &options)
            .map_err(|_| WRITE)?;
        Ok(Partial {
            destination: self,
            temporary,
            name,
            file: Some(file),
        })
    }
}

pub(crate) fn start_export(path: &Path) -> Result<Partial, &'static str> {
    let parent = path.parent().ok_or(INVALID)?;
    let name = path.file_name().ok_or(INVALID)?;
    Destination::from_directory(parent.to_owned(), open(parent)?)?
        .start_named(name.to_owned(), ".frameleaf-original")
}

pub(crate) struct Partial {
    destination: Destination,
    temporary: String,
    name: OsString,
    pub(crate) file: Option<File>,
}

impl Partial {
    pub(super) fn space(&self, required: u64) -> Result<(), &'static str> {
        self.destination.space(required)
    }

    pub(crate) fn publish(mut self, verified_stamp: &str) -> Result<String, &'static str> {
        let _current = self.destination.reopen()?;
        let file = self.file.take().ok_or(WRITE)?;
        if crate::copy_source::opened_stamp(&file).map_err(|_| INVALID)? != verified_stamp {
            return Err(INVALID);
        }
        same_file(
            &self.destination.directory,
            OsStr::new(&self.temporary),
            &file,
        )?;
        publish_exclusive(&self.destination, OsStr::new(&self.temporary), &self.name).map_err(
            |error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    "media_copy_destination_exists"
                } else {
                    WRITE
                }
            },
        )?;
        self.temporary.clear();
        same_file(&self.destination.directory, &self.name, &file)?;
        #[cfg(unix)]
        self.destination
            .reopen()?
            .into_std_file()
            .sync_all()
            .map_err(|_| WRITE)?;
        #[cfg(windows)]
        self.destination.reopen()?;
        Ok(self
            .destination
            .path
            .join(&self.name)
            .to_string_lossy()
            .into())
    }
}

fn same_file(directory: &Dir, name: &OsStr, file: &File) -> Result<(), &'static str> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let observed = directory.open_with(name, &options).map_err(|_| INVALID)?;
    if crate::copy_source::opened_stamp(&observed).map_err(|_| INVALID)?
        != crate::copy_source::opened_stamp(file).map_err(|_| INVALID)?
    {
        return Err(INVALID);
    }
    Ok(())
}

impl Drop for Partial {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.temporary.is_empty() {
            let _ = self.destination.directory.remove_file(&self.temporary);
        }
    }
}

fn open(path: &Path) -> Result<std::fs::File, &'static str> {
    #[cfg(not(windows))]
    return crate::host_storage::directory(path).map_err(|_| INVALID);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };
        crate::native_runtime::absolute_directory(path).map_err(|_| INVALID)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| INVALID)?;
        if !file.metadata().map_err(|_| INVALID)?.is_dir() {
            return Err(INVALID);
        }
        Ok(file)
    }
}

#[cfg(target_os = "macos")]
fn require_exclusive_rename(directory: &std::fs::File) -> Result<(), &'static str> {
    use std::os::fd::AsRawFd;

    #[repr(C)]
    struct Capabilities {
        length: u32,
        flags: libc::vol_capabilities_attr_t,
    }
    let mut query = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut result: Capabilities = unsafe { std::mem::zeroed() };
    let status = unsafe {
        libc::fgetattrlist(
            directory.as_raw_fd(),
            (&mut query as *mut libc::attrlist).cast(),
            (&mut result as *mut Capabilities).cast(),
            std::mem::size_of::<Capabilities>(),
            0,
        )
    };
    let index = libc::VOL_CAPABILITIES_INTERFACES;
    let flag = libc::VOL_CAP_INT_RENAME_EXCL;
    if status != 0
        || result.length as usize != std::mem::size_of::<Capabilities>()
        || result.flags.valid[index] & result.flags.capabilities[index] & flag == 0
    {
        return Err("media_copy_destination_unsupported");
    }
    Ok(())
}

#[cfg(unix)]
fn publish_exclusive(destination: &Destination, temporary: &OsStr, name: &OsStr) -> io::Result<()> {
    use std::{
        ffi::CString,
        os::{fd::AsRawFd, unix::ffi::OsStrExt},
    };
    let temporary = CString::new(temporary.as_bytes())?;
    let name = CString::new(name.as_bytes())?;
    let fd = destination.directory.as_raw_fd();
    #[cfg(target_os = "macos")]
    let result =
        unsafe { libc::renameatx_np(fd, temporary.as_ptr(), fd, name.as_ptr(), libc::RENAME_EXCL) }
            as i64;
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            fd,
            temporary.as_ptr(),
            fd,
            name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn publish_exclusive(destination: &Destination, temporary: &OsStr, name: &OsStr) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
    let utf16 = |path: PathBuf| {
        path.as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>()
    };
    let source = utf16(destination.path.join(temporary));
    let target = utf16(destination.path.join(name));
    if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Write};

    #[test]
    fn partial_copies_never_replace_existing_files_and_are_removed_when_cancelled() {
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("frameleaf-media-copy-test-{}", Uuid::new_v4()));
        fs::create_dir(&base).unwrap();
        let package = Uuid::new_v4();
        let open = || {
            Destination::open(base.clone())
                .unwrap()
                .start(package)
                .unwrap()
        };
        let mut cancelled = open();
        cancelled
            .file
            .as_mut()
            .unwrap()
            .write_all(b"incomplete")
            .unwrap();
        let temporary = base.join(&cancelled.temporary);
        drop(cancelled);
        assert!(!temporary.exists());

        let mut competing = open();
        competing
            .file
            .as_mut()
            .unwrap()
            .write_all(b"new bytes")
            .unwrap();
        let target = base.join(&competing.name);
        fs::write(&target, b"existing bytes").unwrap();
        let stamp = crate::copy_source::opened_stamp(competing.file.as_ref().unwrap()).unwrap();
        assert_eq!(
            competing.publish(&stamp),
            Err("media_copy_destination_exists")
        );
        assert_eq!(fs::read(&target).unwrap(), b"existing bytes");
        assert_eq!(fs::read_dir(&base).unwrap().count(), 1);

        fs::remove_file(&target).unwrap();
        let mut valid = open();
        let file = valid.file.as_mut().unwrap();
        file.write_all(b"verified bytes").unwrap();
        file.sync_all().unwrap();
        let stamp = crate::copy_source::opened_stamp(file).unwrap();
        assert_eq!(PathBuf::from(valid.publish(&stamp).unwrap()), target);
        assert_eq!(fs::read(&target).unwrap(), b"verified bytes");
        assert_eq!(fs::read_dir(&base).unwrap().count(), 1);
        fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_destination_replaced_after_approval() {
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("frameleaf-media-copy-test-{}", Uuid::new_v4()));
        let approved = base.join("approved");
        let moved = base.join("moved");
        fs::create_dir_all(&approved).unwrap();
        let mut partial = Destination::open(approved.clone())
            .unwrap()
            .start(Uuid::new_v4())
            .unwrap();
        let file = partial.file.as_mut().unwrap();
        file.write_all(b"verified bytes").unwrap();
        let stamp = crate::copy_source::opened_stamp(file).unwrap();
        fs::rename(&approved, &moved).unwrap();
        fs::create_dir(&approved).unwrap();
        assert_eq!(partial.publish(&stamp), Err(INVALID));
        assert_eq!(fs::read_dir(&approved).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
        fs::remove_dir_all(base).unwrap();
    }
}
