//! A process crash releases this lock; runtime-file restoration never chooses its location.
#[cfg(test)]
static FIXTURE_DIRECTORY: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
#[cfg(test)]
pub(crate) fn isolate_for_fixture() {
    FIXTURE_DIRECTORY.get_or_init(|| {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "frameleaf-memory-credentials-{}",
            uuid::Uuid::new_v4()
        ));
        crate::runtime_store::private_directory(&root).unwrap();
        root
    });
}
#[cfg(test)]
pub(crate) fn fixture_directory() -> Option<&'static std::path::Path> {
    FIXTURE_DIRECTORY.get().map(std::path::PathBuf::as_path)
}
#[cfg(unix)]
pub(crate) struct Guard(std::fs::File);
#[cfg(unix)]
pub(crate) fn acquire() -> Result<Guard, String> {
    use std::{
        fs::OpenOptions,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let uid = unsafe { libc::geteuid() };
    let directory = directory()?;
    crate::runtime_store::private_directory(&directory)?;
    let path = directory.join("runtime-epochs.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| "credential_store_lock_unavailable")?;
    let info = file
        .metadata()
        .map_err(|_| "credential_store_lock_unavailable")?;
    let named =
        std::fs::symlink_metadata(&path).map_err(|_| "credential_store_lock_unavailable")?;
    if !info.is_file()
        || info.uid() != uid
        || info.mode() & 0o7777 != 0o600
        || info.nlink() != 1
        || info.dev() != named.dev()
        || info.ino() != named.ino()
    {
        return Err("credential_store_lock_invalid".into());
    }
    file.try_lock().map_err(|_| "credential_store_busy")?;
    Ok(Guard(file))
}
#[cfg(unix)]
pub(crate) fn directory() -> Result<std::path::PathBuf, String> {
    #[cfg(test)]
    if let Some(directory) = fixture_directory() {
        return Ok(directory.to_path_buf());
    }

    let uid = unsafe { libc::geteuid() };
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 65536];
    let mut result = std::ptr::null_mut();
    if unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    } != 0
        || result.is_null()
        || entry.pw_dir.is_null()
    {
        return Err("credential_store_lock_unavailable".into());
    }
    use std::os::unix::ffi::OsStrExt;
    let home = std::path::Path::new(std::ffi::OsStr::from_bytes(
        unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }.to_bytes(),
    ));
    Ok(home.join(crate::app_profile().security_directory()))
}

#[cfg(unix)]
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

#[cfg(windows)]
pub(crate) struct Guard(std::os::windows::io::OwnedHandle);
#[cfg(windows)]
pub(crate) fn acquire() -> Result<Guard, String> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{CreateMutexW, WaitForSingleObject},
    };
    let sid = crate::windows_protection::process_user_sid()
        .map_err(|_| "credential_store_lock_unavailable")?;
    let name: Vec<u16> = crate::app_profile()
        .mutex_name(&sid)
        .encode_utf16()
        .collect();
    let raw = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if raw.is_null() {
        return Err("credential_store_lock_unavailable".into());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    match unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Guard(handle)),
        WAIT_TIMEOUT => Err("credential_store_busy".into()),
        _ => Err("credential_store_lock_unavailable".into()),
    }
}
#[cfg(windows)]
impl Drop for Guard {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        unsafe {
            windows_sys::Win32::System::Threading::ReleaseMutex(self.0.as_raw_handle());
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn independent_open_cannot_bypass_a_live_epoch_lock_and_drop_releases_it() {
        let first = super::acquire().unwrap();
        #[cfg(unix)]
        assert!(super::acquire().is_err());
        // Windows mutex acquisition is recursive on one thread; use another thread.
        #[cfg(windows)]
        assert!(std::thread::spawn(|| super::acquire().is_err())
            .join()
            .unwrap());
        let blocked = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "credential_lock::tests::child_lock_probe",
                "--ignored",
            ])
            .env("FRAMELEAF_EPOCH_LOCK_PROBE", "blocked")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(blocked.code(), Some(73));
        drop(first);
        let crash = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "credential_lock::tests::child_lock_probe",
                "--ignored",
            ])
            .env("FRAMELEAF_EPOCH_LOCK_PROBE", "crash")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(crash.code(), Some(73));
        assert!(super::acquire().is_ok());
    }
    #[test]
    #[ignore = "child-only OS lock probe; invoked by parent test"]
    fn child_lock_probe() {
        match std::env::var("FRAMELEAF_EPOCH_LOCK_PROBE").as_deref() {
            Ok("blocked") => assert!(super::acquire().is_err()),
            Ok("crash") => {
                let _guard = super::acquire().unwrap();
                std::process::exit(73);
            }
            _ => panic!("missing child mode"),
        }
        std::process::exit(73);
    }
}
