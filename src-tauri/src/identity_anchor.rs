//! Enrollment survives loss of the keyring entry and is independent of selected runtime roots.
fn valid(value: String) -> Result<String, String> {
    if uuid::Uuid::parse_str(&value).is_ok_and(|id| !id.is_nil() && id.to_string() == value) {
        Ok(value)
    } else {
        Err("runtime_epoch_binding_invalid".into())
    }
}
#[cfg(unix)]
pub(crate) fn read() -> Result<Option<String>, String> {
    let path = crate::credential_lock::directory()?.join("installation.json");
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("runtime_epoch_binding_invalid".into()),
        Ok(_) => valid(
            serde_json::from_slice(&crate::runtime_store::read_bounded(&path, 128)?)
                .map_err(|_| "runtime_epoch_binding_invalid")?,
        )
        .map(Some),
    }
}
#[cfg(unix)]
pub(crate) fn write(value: &str) -> Result<(), String> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let directory = crate::credential_lock::directory()?;
    let temporary = directory.join(format!(".installation-{}.json", uuid::Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|_| "runtime_epoch_binding_invalid")?;
    let written = file
        .write_all(&serde_json::to_vec(value).map_err(|_| "runtime_epoch_binding_invalid")?)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::hard_link(&temporary, directory.join("installation.json")));
    let _ = std::fs::remove_file(&temporary);
    written.map_err(|_| "runtime_epoch_binding_invalid")?;
    std::fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| "runtime_epoch_binding_invalid".into())
}
#[cfg(windows)]
mod native {
    use windows_sys::Win32::System::Registry::*;
    const ERROR: &str = "runtime_epoch_binding_invalid";
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    fn name() -> Vec<u16> {
        "Software\\Frameleaf\\DesktopSecurity\0"
            .encode_utf16()
            .collect()
    }
    fn value() -> Vec<u16> {
        "InstallationId\0".encode_utf16().collect()
    }
    pub(crate) fn read() -> Result<Option<String>, String> {
        let mut raw = std::ptr::null_mut();
        let result = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                name().as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut raw,
            )
        };
        if result == 2 {
            return Ok(None);
        }
        if result != 0 || raw.is_null() {
            return Err(ERROR.into());
        }
        let key = Key(raw);
        let mut kind = 0;
        let mut bytes = [0u16; 64];
        let mut size = std::mem::size_of_val(&bytes) as u32;
        let result = unsafe {
            RegQueryValueExW(
                key.0,
                value().as_ptr(),
                std::ptr::null(),
                &mut kind,
                bytes.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if result == 2 {
            return Ok(None);
        }
        if result != 0
            || kind != REG_SZ
            || size < 2
            || size % 2 != 0
            || size as usize > std::mem::size_of_val(&bytes)
        {
            return Err(ERROR.into());
        }
        let words = &bytes[..size as usize / 2];
        if words.last() != Some(&0) || words[..words.len() - 1].contains(&0) {
            return Err(ERROR.into());
        }
        super::valid(String::from_utf16(&words[..words.len() - 1]).map_err(|_| ERROR)?).map(Some)
    }
    pub(crate) fn write(value: &str) -> Result<(), String> {
        let mut raw = std::ptr::null_mut();
        if unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                name().as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_QUERY_VALUE,
                std::ptr::null(),
                &mut raw,
                std::ptr::null_mut(),
            )
        } != 0
            || raw.is_null()
        {
            return Err(ERROR.into());
        }
        let key = Key(raw);
        let words: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
        if unsafe {
            RegSetValueExW(
                key.0,
                self::value().as_ptr(),
                0,
                REG_SZ,
                words.as_ptr().cast(),
                (words.len() * 2) as u32,
            )
        } != 0
            || unsafe { RegFlushKey(key.0) } != 0
        {
            return Err(ERROR.into());
        }
        Ok(())
    }
}
#[cfg(windows)]
pub(crate) use native::{read, write};
