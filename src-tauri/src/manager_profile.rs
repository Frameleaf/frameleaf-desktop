//! Database and backup credentials live only in the OS keystore; disk holds a nonsecret reservation hash.
use crate::manager_host::{validate_configuration, validate_paths, Configuration};
use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::Mutex,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
#[cfg(any(windows, test))]
mod windows_binding;

pub(crate) fn check_start(config: &Configuration) -> Result<(), String> {
    validate_configuration(config)?;
    match std::fs::symlink_metadata(&config.state) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("native_profile_unavailable".into()),
        Ok(_) => crate::host_state::no_update(&cap_std::fs::Dir::from_std_file(
            crate::host_storage::directory(&config.state)?,
        )),
    }
}
mod configuration;
pub(crate) mod update;
pub(crate) use configuration::configuration_id;
pub(crate) use update::{Keystore, UpdateStore};
const ACCOUNT: &str = "native-host-profile";
static LOCK: Mutex<()> = Mutex::new(());
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Profile {
    schema_version: u32,
    #[serde(default)]
    secure_installation_id: Option<String>,
    binding_sha256: String,
    database_password: String,
    #[serde(default)]
    backup_key: Option<String>,
    #[serde(skip)]
    #[zeroize(skip)]
    guard: Option<ProfileGuard>,
}
pub(crate) struct ProfileGuard {
    _lease: File,
    #[cfg(unix)]
    inherited: std::sync::atomic::AtomicBool,
    state: cap_std::fs::Dir,
    data: cap_std::fs::Dir,
}
impl Drop for ProfileGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.inherited.load(std::sync::atomic::Ordering::Acquire) {
            // The owned child retains this same lock after supervisor loss.
            return;
        }
        let _ = self._lease.unlock();
    }
}
impl ProfileGuard {
    pub(crate) fn acquire(config: &Configuration) -> Result<Self, String> {
        validate_configuration(config)?;
        crate::runtime_store::private_directory(&config.state)?;
        crate::runtime_store::private_directory(&config.data)?;
        let data = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&config.data)?);
        let lease = data
            .open_with(".setup.lock", &crate::host_state::options(true))
            .map_err(|_| "native_profile_unavailable")?
            .into_std();
        #[cfg(unix)]
        let lease = {
            use std::os::fd::{AsRawFd, FromRawFd};
            if lease.as_raw_fd() <= 2 {
                let fd = unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
                if fd == -1 {
                    return Err("native_profile_unavailable".into());
                }
                unsafe { File::from_raw_fd(fd) }
            } else {
                lease
            }
        };
        crate::host_state::valid_file(&lease).map_err(|_| "native_profile_unavailable")?;
        if lease
            .metadata()
            .map_err(|_| "native_profile_unavailable")?
            .len()
            != 0
        {
            return Err("native_profile_binding_changed".into());
        }
        lease
            .try_lock()
            .map_err(|_| "native_profile_already_owned")?;
        let guard = Self {
            _lease: lease,
            state: cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&config.state)?),
            data,
            #[cfg(unix)]
            inherited: std::sync::atomic::AtomicBool::new(false),
        };
        guard.require_current(config)?;
        Ok(guard)
    }
    pub(crate) fn require_current(&self, config: &Configuration) -> Result<(), String> {
        crate::host_state::valid_file(&self._lease)
            .map_err(|_| "native_profile_binding_changed")?;
        if self
            ._lease
            .metadata()
            .map_err(|_| "native_profile_binding_changed")?
            .len()
            != 0
        {
            return Err("native_profile_binding_changed".into());
        }
        let fresh_state =
            cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&config.state)?);
        let fresh_data =
            cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&config.data)?);
        if crate::copy_source::root_identity(&fresh_state)?
            != crate::copy_source::root_identity(&self.state)?
            || crate::copy_source::root_identity(&fresh_data)?
                != crate::copy_source::root_identity(&self.data)?
        {
            return Err("native_profile_binding_changed".into());
        }
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt as _;
            use std::os::unix::fs::MetadataExt as _;
            let named = self
                .data
                .symlink_metadata(".setup.lock")
                .map_err(|_| "native_profile_binding_changed")?;
            let held = self
                ._lease
                .metadata()
                .map_err(|_| "native_profile_binding_changed")?;
            if !named.is_file() || named.dev() != held.dev() || named.ino() != held.ino() {
                return Err("native_profile_binding_changed".into());
            }
        }
        Ok(())
    }
    #[cfg(unix)]
    pub(crate) fn inherit(&self, command: &mut std::process::Command) {
        use std::os::{fd::AsRawFd, unix::process::CommandExt};
        let fd = self._lease.as_raw_fd();
        command.env("FRAMELEAF_MANAGER_PROFILE_FD", fd.to_string());
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags == -1 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(unix)]
    pub(crate) fn child_spawned(&self) {
        self.inherited
            .store(true, std::sync::atomic::Ordering::Release);
    }
}
impl Profile {
    pub(crate) fn installation_identity(&self) -> Result<&str, String> {
        self.secure_installation_id
            .as_deref()
            .ok_or("native_profile_recovery_required".into())
    }
    pub(crate) fn binding(&self) -> &str {
        &self.binding_sha256
    }
    pub(crate) fn require_current(&self, config: &Configuration) -> Result<(), String> {
        self.guard
            .as_ref()
            .ok_or("native_profile_unavailable")?
            .require_current(config)
    }
    pub(crate) fn take_guard(&mut self) -> Result<ProfileGuard, String> {
        self.guard.take().ok_or("native_profile_unavailable".into())
    }
    pub(crate) fn password(&self) -> Zeroizing<String> {
        Zeroizing::new(self.database_password.clone())
    }
    pub(crate) fn backup_key(&self) -> Result<Zeroizing<String>, String> {
        let key = self
            .backup_key
            .as_deref()
            .ok_or("native_backup_key_unavailable")?;
        if !valid_backup_key(key) || key == self.database_password {
            return Err("native_backup_key_invalid".into());
        }
        Ok(Zeroizing::new(key.to_owned()))
    }
    pub(crate) fn from_keystore(
        config: &Configuration,
        candidate: &Path,
        manifest: &str,
    ) -> Result<Self, String> {
        check_start(config)?;
        let secure_id = crate::host_epochs::HostEpochAuthority::installation_id(
            &crate::credentials::CredentialEpochAuthority,
        )?;
        if config.secure_installation_id != secure_id {
            return Err("native_profile_identity_changed".into());
        }
        Self::load_or_create(
            config,
            candidate,
            manifest,
            &secure_id,
            crate::credentials::load,
            crate::credentials::save,
        )
    }
    fn load_or_create(
        config: &Configuration,
        candidate: &Path,
        manifest: &str,
        secure_installation_id: &str,
        mut load: impl FnMut(&str) -> Result<Option<Self>, String>,
        mut persist: impl FnMut(&str, &Self) -> Result<(), String>,
    ) -> Result<Self, String> {
        if !uuid::Uuid::parse_str(secure_installation_id)
            .is_ok_and(|id| !id.is_nil() && id.to_string() == secure_installation_id)
        {
            return Err("native_profile_identity_invalid".into());
        }
        validate_configuration(config)?;
        if config.secure_installation_id != secure_installation_id {
            return Err("native_profile_identity_changed".into());
        }
        if !crate::native_runtime::digest_valid(manifest, 64) {
            return Err("native_profile_binding_invalid".into());
        }
        validate_paths(candidate, &config.state, &config.data)?;
        let _lock = LOCK.lock().map_err(|_| "native_profile_unavailable")?;
        let guard = ProfileGuard::acquire(config)?;
        crate::host_state::no_update(&guard.state)?;
        validate_paths(candidate, &config.state, &config.data)?;
        let state = &guard.state;
        let data = &guard.data;
        let (legacy_account, binding_sha256, account) =
            profile_accounts(config, candidate, manifest, secure_installation_id, &guard)?;
        let saved = load(&account)?;
        let mut profile = if let Some(saved) = saved {
            if saved.schema_version == 1 || saved.secure_installation_id.is_none() {
                return Err("native_profile_recovery_required".into());
            }
            if saved.secure_installation_id.as_deref() != Some(secure_installation_id) {
                return Err("native_profile_identity_changed".into());
            }
            if saved.schema_version != 2
                || saved.binding_sha256 != binding_sha256
                || !(24..=256).contains(&saved.database_password.len())
                || saved.database_password.contains(['\r', '\n', '\0'])
            {
                return Err("native_profile_binding_changed".into());
            }
            if saved.backup_key.is_some() {
                saved.backup_key()?;
            }
            saved
        } else {
            // Interrupted old setup can have a credential without its reservation marker.
            if load(&legacy_account)?.is_some() {
                return Err("native_profile_recovery_required".into());
            }
            if state
                .entries()
                .map_err(|_| "native_profile_unavailable")?
                .next()
                .is_some()
                || data
                    .entries()
                    .map_err(|_| "native_profile_unavailable")?
                    .any(|entry| {
                        entry
                            .map(|e| e.file_name() != std::ffi::OsStr::new(".setup.lock"))
                            .unwrap_or(true)
                    })
            {
                return Err("native_profile_recovery_required".into());
            }
            let mut bytes = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(bytes.as_mut());
            let profile = Self {
                schema_version: 2,
                secure_installation_id: Some(secure_installation_id.into()),
                binding_sha256,
                database_password: STANDARD_NO_PAD.encode(bytes.as_ref()),
                backup_key: Some(new_backup_key()),
                guard: None,
            };
            persist(&account, &profile)?;
            profile
        };
        match data.open_with(".host-profile", &crate::host_state::options(false)) {
            Ok(file) => {
                let file = file.into_std();
                crate::host_state::valid_file(&file)
                    .map_err(|_| "native_profile_binding_changed")?;
                let mut bytes = Vec::new();
                file.take(65)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "native_profile_unavailable")?;
                if bytes != profile.binding_sha256.as_bytes() {
                    return Err("native_profile_binding_changed".into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let temp = format!(".host-profile-{}.tmp", uuid::Uuid::new_v4());
                let result = (|| -> Result<(), String> {
                    let mut options = crate::host_state::options(true);
                    options.create_new(true);
                    let mut file = data
                        .open_with(&temp, &options)
                        .map_err(|_| "native_profile_unavailable")?
                        .into_std();
                    file.write_all(profile.binding_sha256.as_bytes())
                        .and_then(|_| file.sync_all())
                        .map_err(|_| "native_profile_unavailable")?;
                    drop(file);
                    publish_marker(data, &temp, ".host-profile")?;
                    Ok(())
                })();
                let cleanup = data.remove_file(&temp);
                result?;
                if cleanup.is_err_and(|error| error.kind() != std::io::ErrorKind::NotFound) {
                    return Err("native_profile_unavailable".into());
                }
                #[cfg(unix)]
                crate::host_storage::directory(&config.data)?
                    .sync_all()
                    .map_err(|_| "native_profile_unavailable")?;
            }
            Err(_) => return Err("native_profile_binding_changed".into()),
        }
        if profile.backup_key.is_none() {
            // Existing encryption must be recovered, never silently assigned a replacement key.
            for path in ["recovery-key", "backups/frameleaf-database"] {
                match data.symlink_metadata(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err("native_backup_key_recovery_required".into()),
                }
            }
            profile.backup_key = Some(new_backup_key());
            persist(&account, &profile)?;
        }
        profile.guard = Some(guard);
        profile.require_current(config)?;
        profile
            .guard
            .as_ref()
            .ok_or("native_profile_unavailable")?
            .persist_configuration(config, profile.binding())?;
        Ok(profile)
    }
}

fn profile_accounts(
    config: &Configuration,
    candidate: &Path,
    manifest: &str,
    secure_installation_id: &str,
    guard: &ProfileGuard,
) -> Result<(String, String, String), String> {
    validate_configuration(config)?;
    validate_paths(candidate, &config.state, &config.data)?;
    guard.require_current(config)?;
    if config.secure_installation_id != secure_installation_id
        || !crate::native_runtime::digest_valid(manifest, 64)
    {
        return Err("native_profile_binding_invalid".into());
    }
    let state = &guard.state;
    let data = &guard.data;
    #[cfg(not(windows))]
    let binding = serde_json::json!({"schemaVersion":1,"configuration":config,"candidate":candidate,"manifestSha256":manifest,
            "stateIdentity":crate::copy_source::root_identity(state)?,"managerIdentity":crate::copy_source::root_identity(data)?});
    #[cfg(windows)]
    let binding = {
        let candidate = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(candidate)?);
        let controller = File::open(crate::windows_protection::stable_path(&config.controller)?)
            .map_err(|_| "native_profile_binding_invalid")?;
        windows_binding::value(
            config,
            manifest,
            [
                crate::copy_source::root_identity(state)?,
                crate::copy_source::root_identity(data)?,
            ],
            [
                crate::windows_protection::durable_name(&candidate)?,
                crate::windows_protection::durable_name(&controller)?,
                crate::windows_protection::durable_name(state)?,
                crate::windows_protection::durable_name(data)?,
            ],
        )?
    };
    let legacy_account = format!(
        "{ACCOUNT}-{:x}",
        Sha256::digest(
            serde_json_canonicalizer::to_vec(&binding)
                .map_err(|_| "native_profile_binding_invalid")?
        )
    );
    let binding = serde_json::json!({"schemaVersion":1,"secureInstallationId":secure_installation_id,"profile":binding});
    let binding_sha256 = format!(
        "{:x}",
        Sha256::digest(
            serde_json_canonicalizer::to_vec(&binding)
                .map_err(|_| "native_profile_binding_invalid")?
        )
    );
    let account = format!("{ACCOUNT}-{binding_sha256}");
    Ok((legacy_account, binding_sha256, account))
}

pub(crate) fn valid_backup_key(key: &str) -> bool {
    key.len() == 43
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn new_backup_key() -> String {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(bytes.as_mut());
    URL_SAFE_NO_PAD.encode(bytes.as_ref())
}

// Publish in one operation: an interrupted setup must never leave a two-link marker.
pub(crate) fn publish_marker(
    data: &cap_std::fs::Dir,
    temp: &str,
    destination: &str,
) -> Result<(), String> {
    if ![
        ".host-profile",
        "host-update.json",
        "host-update-recovery.json",
        "host-update-selection.json",
        ".host-configuration.json",
    ]
    .contains(&destination)
        && !crate::host_state::valid_update_history_name(destination)
    {
        return Err("native_profile_binding_changed".into());
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::os::fd::AsRawFd;
        let name = std::ffi::CString::new(temp).map_err(|_| "native_profile_unavailable")?;
        let destination =
            std::ffi::CString::new(destination).map_err(|_| "native_profile_unavailable")?;
        let fd = data.as_raw_fd();
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                fd,
                name.as_ptr(),
                fd,
                destination.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                fd,
                name.as_ptr(),
                fd,
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            return Err("native_profile_binding_changed".into());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::{
            Wdk::Storage::FileSystem::{
                FileRenameInformation, NtSetInformationFile, FILE_RENAME_INFORMATION,
            },
            Win32::{
                Storage::FileSystem::{DELETE, FILE_GENERIC_READ},
                System::IO::IO_STATUS_BLOCK,
            },
        };
        let mut options = crate::host_state::options(false);
        options.access_mode(DELETE | FILE_GENERIC_READ);
        let source = data
            .open_with(temp, &options)
            .map_err(|_| "native_profile_unavailable")?
            .into_std();
        crate::host_state::valid_file(&source).map_err(|_| "native_profile_binding_changed")?;
        let name: Vec<u16> = destination
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let size = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName) + name.len() * 2;
        let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let mut status = IO_STATUS_BLOCK::default();
        // Use the native relative-handle operation; never resolve the target through a mutable path.
        let result = unsafe {
            (*info).Anonymous.ReplaceIfExists = false;
            (*info).RootDirectory = data.as_raw_handle();
            (*info).FileNameLength = ((name.len() - 1) * 2) as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                name.len(),
            );
            NtSetInformationFile(
                source.as_raw_handle(),
                &mut status,
                info.cast(),
                size as u32,
                FileRenameInformation,
            )
        };
        if result != 0 {
            #[cfg(test)]
            eprintln!("native marker publication NTSTATUS: {result:#010x}");
            return Err("native_profile_binding_changed".into());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (data, temp, destination);
        Err("native_profile_platform_unsupported".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager_host::Configuration;
    const SECURE_ID: &str = "11111111-1111-4111-8111-111111111111";
    struct Fixture(std::path::PathBuf, Configuration);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-profile-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(root.join("runtime")).unwrap();
            let config = Configuration {
                installation_id: "a".repeat(12),
                secure_installation_id: "11111111-1111-4111-8111-111111111111".into(),
                name: "Synthetic".into(),
                release: "frameleaf-v3.0.0-1".into(),
                controller: if cfg!(windows) {
                    std::env::current_exe().unwrap()
                } else {
                    std::path::PathBuf::from("/bin/echo")
                },
                state: root.join("state"),
                data: root.join("manager"),
                origin: "https://127.0.0.1:9443".into(),
                database_port: 54329,
                api_port: 2283,
            };
            Self(root, config)
        }
        fn create(&self) -> Profile {
            Profile::load_or_create(
                &self.1,
                &self.0.join("runtime"),
                &"b".repeat(64),
                SECURE_ID,
                |_account: &str| Ok(None),
                |_account, _profile| Ok(()),
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn backup_key_is_independent_reused_and_never_written_to_profile_files() {
        let f = Fixture::new();
        let profile = f.create();
        let key = profile.backup_key().unwrap();
        assert_ne!(key.as_str(), profile.password().as_str());
        assert_eq!(key.len(), 43);
        let saved = serde_json::to_string(&profile).unwrap();
        drop(profile);
        let restored = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_| Ok(Some(serde_json::from_str(&saved).unwrap())),
            |_, _| panic!("must not replace backup key"),
        )
        .unwrap();
        assert_eq!(key.as_str(), restored.backup_key().unwrap().as_str());
        drop(restored);
        for entry in std::fs::read_dir(&f.1.data).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                assert!(!std::fs::read(path)
                    .unwrap()
                    .windows(key.len())
                    .any(|v| v == key.as_bytes()));
            }
        }
    }
    #[test]
    fn legacy_backup_key_migration_preserves_database_password_and_fails_closed_if_persistence_is_locked(
    ) {
        let f = Fixture::new();
        let profile = f.create();
        let expected = profile.password();
        let mut legacy = serde_json::to_value(&profile).unwrap();
        legacy.as_object_mut().unwrap().remove("backupKey");
        drop(profile);
        let load = |_account: &str| Ok(Some(serde_json::from_value(legacy.clone()).unwrap()));
        assert!(Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            load,
            |_, _| Err("credential_store_locked".into())
        )
        .is_err());
        let saved = std::cell::RefCell::new(None);
        let upgraded = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            load,
            |_, value| {
                *saved.borrow_mut() = Some(serde_json::to_string(value).unwrap());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(upgraded.password().as_str(), expected.as_str());
        let key = upgraded.backup_key().unwrap();
        drop(upgraded);
        let restored = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_| {
                Ok(Some(
                    serde_json::from_str(saved.borrow().as_ref().unwrap()).unwrap(),
                ))
            },
            |_, _| panic!("must not migrate twice"),
        )
        .unwrap();
        assert_eq!(key.as_str(), restored.backup_key().unwrap().as_str());
    }
    #[test]
    fn legacy_backup_key_refuses_existing_encryption_or_changed_marker_without_persisting() {
        for existing in [
            "recovery-key",
            "backups/frameleaf-database/config",
            "backups/frameleaf-database/data/pack",
            ".host-profile",
        ] {
            let f = Fixture::new();
            let profile = f.create();
            let mut legacy = serde_json::to_value(&profile).unwrap();
            legacy.as_object_mut().unwrap().remove("backupKey");
            drop(profile);
            let path = f.1.data.join(existing);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"existing bytes").unwrap();
            let result = Profile::load_or_create(
                &f.1,
                &f.0.join("runtime"),
                &"b".repeat(64),
                SECURE_ID,
                |_| Ok(Some(serde_json::from_value(legacy.clone()).unwrap())),
                |_, _| panic!("must not replace existing encryption"),
            );
            assert!(result.is_err());
            assert_eq!(std::fs::read(path).unwrap(), b"existing bytes");
        }
    }
    #[test]
    fn populated_invalid_backup_key_is_never_regenerated() {
        let f = Fixture::new();
        let profile = f.create();
        let mut saved = serde_json::to_value(&profile).unwrap();
        drop(profile);
        for key in [
            "short".to_owned(),
            "x".repeat(44),
            "x".repeat(42) + "\n",
            saved["databasePassword"].as_str().unwrap().to_owned(),
        ] {
            saved["backupKey"] = key.into();
            let result = Profile::load_or_create(
                &f.1,
                &f.0.join("runtime"),
                &"b".repeat(64),
                SECURE_ID,
                |_| Ok(Some(serde_json::from_value(saved.clone()).unwrap())),
                |_, _| panic!("must not replace corrupted credentials"),
            );
            assert!(result.is_err());
        }
    }
    #[test]
    fn persisted_profile_is_reused_and_bound_to_configuration_and_directory_identity() {
        let mut f = Fixture::new();
        let profile = f.create();
        let saved = serde_json::to_string(&profile).unwrap();
        let expected = profile.password();
        drop(profile);
        let reload = |_account: &str| Ok(Some(serde_json::from_str(&saved).unwrap()));
        let restored = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            reload,
            |_account, _profile| panic!("must not replace"),
        )
        .unwrap();
        assert_eq!(expected.as_str(), restored.password().as_str());
        // Windows byte-range locks prohibit reading the lease until its owner releases it.
        drop(restored);
        for entry in std::fs::read_dir(&f.1.data).unwrap() {
            let p = entry.unwrap().path();
            if p.is_file() {
                let bytes = std::fs::read(p).unwrap();
                assert!(!bytes
                    .windows(expected.len())
                    .any(|v| v == expected.as_bytes()));
            }
        }
        f.1.api_port = 2284;
        assert!(Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            reload,
            |_account, _profile| panic!("must not replace")
        )
        .is_err());
        f.1.api_port = 2283;
        std::fs::rename(&f.1.state, f.0.join("old-state")).unwrap();
        std::fs::create_dir(&f.1.state).unwrap();
        assert!(Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            reload,
            |_account, _profile| panic!("must not replace")
        )
        .is_err());
    }
    #[cfg(windows)]
    #[test]
    fn old_windows_reservation_without_matching_secret_requires_recovery() {
        let f = Fixture::new();
        let profile = f.create();
        drop(profile);
        let marker = f.1.data.join(".host-profile");
        let old_binding = "e".repeat(64);
        std::fs::write(&marker, &old_binding).unwrap();
        let result = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_| Ok(None),
            |_, _| panic!("never replace an existing Windows reservation"),
        );
        assert!(matches!(result, Err(ref code) if code == "native_profile_recovery_required"));
        assert_eq!(std::fs::read(marker).unwrap(), old_binding.as_bytes());
    }
    #[test]
    fn missing_or_locked_credentials_never_replace_an_existing_profile_or_database() {
        let f = Fixture::new();
        let _ = f.create();
        assert!(Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_account: &str| Ok(None),
            |_account, _profile| panic!("must refuse missing credential")
        )
        .is_err());
        assert!(Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_account: &str| Err("credential_store_locked".into()),
            |_account, _profile| panic!("must refuse locked store")
        )
        .is_err());
        let g = Fixture::new();
        std::fs::create_dir(&g.1.state).unwrap();
        std::fs::write(g.1.state.join("existing-database"), b"untouched").unwrap();
        assert!(Profile::load_or_create(
            &g.1,
            &g.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_account: &str| Ok(None),
            |_account, _profile| panic!("must refuse existing data")
        )
        .is_err());
        assert_eq!(
            std::fs::read(g.1.state.join("existing-database")).unwrap(),
            b"untouched"
        );
    }
    #[test]
    fn failed_persistence_does_not_publish_a_profile_marker() {
        let f = Fixture::new();
        assert!(Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_account: &str| Ok(None),
            |_account, _profile| Err("credential_store_unavailable".into())
        )
        .is_err());
        assert!(!f.1.data.join(".host-profile").exists());
    }
    #[test]
    fn marker_repair_reuses_saved_secret_and_refuses_a_changed_reservation() {
        let f = Fixture::new();
        let profile = f.create();
        let saved = serde_json::to_string(&profile).unwrap();
        let expected = profile.password();
        drop(profile);
        let marker = f.1.data.join(".host-profile");
        std::fs::remove_file(&marker).unwrap();
        let reload = |_account: &str| Ok(Some(serde_json::from_str(&saved).unwrap()));
        let restored = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            reload,
            |_account, _profile| panic!("repair must not replace secret"),
        )
        .unwrap();
        assert_eq!(expected.as_str(), restored.password().as_str());
        drop(restored);
        std::fs::write(&marker, b"changed reservation").unwrap();
        assert!(Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            reload,
            |_account, _profile| panic!("must not replace")
        )
        .is_err());
        assert_eq!(std::fs::read(&marker).unwrap(), b"changed reservation");
    }
    #[test]
    fn competing_setup_lease_refuses_before_credential_read_and_recovers_after_release() {
        let f = Fixture::new();
        crate::runtime_store::private_directory(&f.1.data).unwrap();
        let dir =
            cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&f.1.data).unwrap());
        let lease = dir
            .open_with(".setup.lock", &crate::host_state::options(true))
            .unwrap()
            .into_std();
        lease.try_lock().unwrap();
        let error = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_account: &str| panic!("must not read credentials while another setup owns lease"),
            |_account, _profile| panic!("must not save"),
        )
        .err()
        .unwrap();
        assert_eq!(error, "native_profile_already_owned");
        drop(lease);
        let _ = f.create();
    }
    #[test]
    fn profile_retains_setup_lease_until_bootstrap_owner_has_used_it() {
        let f = Fixture::new();
        let profile = f.create();
        let dir =
            cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&f.1.data).unwrap());
        let competing = dir
            .open_with(".setup.lock", &crate::host_state::options(true))
            .unwrap()
            .into_std();
        assert!(
            competing.try_lock().is_err(),
            "returned profile released setup authority before bootstrap"
        );
        drop(profile);
        competing.try_lock().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn profile_drop_releases_setup_lease_with_a_fork_style_descriptor_copy() {
        let f = Fixture::new();
        let profile = f.create();
        let inherited = profile.guard.as_ref().unwrap()._lease.try_clone().unwrap();
        let dir =
            cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&f.1.data).unwrap());
        let competing = dir
            .open_with(".setup.lock", &crate::host_state::options(true))
            .unwrap()
            .into_std();
        assert!(competing.try_lock().is_err());
        drop(profile);
        competing.try_lock().unwrap();
        drop(inherited);
    }

    #[test]
    fn different_profile_directories_with_same_installation_id_use_distinct_accounts() {
        let first = Fixture::new();
        let second = Fixture::new();
        let account_one = std::cell::RefCell::new(String::new());
        let account_two = std::cell::RefCell::new(String::new());
        let _a = Profile::load_or_create(
            &first.1,
            &first.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |account| {
                if account_one.borrow().is_empty() {
                    *account_one.borrow_mut() = account.into();
                }
                Ok(None)
            },
            |account, _| {
                assert_eq!(account, &*account_one.borrow());
                Ok(())
            },
        )
        .unwrap();
        let _b = Profile::load_or_create(
            &second.1,
            &second.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |account| {
                if account_two.borrow().is_empty() {
                    *account_two.borrow_mut() = account.into();
                }
                Ok(None)
            },
            |account, _| {
                assert_eq!(account, &*account_two.borrow());
                Ok(())
            },
        )
        .unwrap();
        assert_ne!(*account_one.borrow(), *account_two.borrow());
    }
    #[test]
    fn directory_replacement_during_keystore_delay_is_refused_at_bootstrap_boundary() {
        let f = Fixture::new();
        let profile = f.create();
        std::fs::rename(&f.1.state, f.0.join("moved-state")).unwrap();
        std::fs::create_dir(&f.1.state).unwrap();
        assert!(profile.require_current(&f.1).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn marker_publication_stays_with_the_held_directory_after_path_replacement() {
        let f = Fixture::new();
        crate::runtime_store::private_directory(&f.1.data).unwrap();
        let dir =
            cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&f.1.data).unwrap());
        let mut file = dir
            .open_with(".first.tmp", &crate::host_state::options(true))
            .unwrap();
        file.write_all(b"held directory").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let moved = f.0.join("moved-manager");
        std::fs::rename(&f.1.data, &moved).unwrap();
        std::fs::create_dir(&f.1.data).unwrap();
        publish_marker(&dir, ".first.tmp", ".host-profile").unwrap();
        assert_eq!(
            std::fs::read(moved.join(".host-profile")).unwrap(),
            b"held directory"
        );
        assert!(!f.1.data.join(".host-profile").exists());
        assert!(!moved.join(".first.tmp").exists());
    }

    #[test]
    fn marker_publication_moves_single_link_and_never_overwrites_existing_reservation() {
        let f = Fixture::new();
        crate::runtime_store::private_directory(&f.1.data).unwrap();
        let dir =
            cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&f.1.data).unwrap());
        let mut first = dir
            .open_with(".first.tmp", &crate::host_state::options(true))
            .unwrap();
        first.write_all(b"first").unwrap();
        first.sync_all().unwrap();
        drop(first);
        publish_marker(&dir, ".first.tmp", ".host-profile").unwrap();
        assert!(!f.1.data.join(".first.tmp").exists());
        let marker = dir
            .open_with(".host-profile", &crate::host_state::options(false))
            .unwrap()
            .into_std();
        crate::host_state::valid_file(&marker).unwrap();
        drop(marker);
        let mut second = dir
            .open_with(".second.tmp", &crate::host_state::options(true))
            .unwrap();
        second.write_all(b"second").unwrap();
        drop(second);
        assert!(publish_marker(&dir, ".second.tmp", ".host-profile").is_err());
        assert_eq!(
            std::fs::read(f.1.data.join(".host-profile")).unwrap(),
            b"first"
        );
        assert_eq!(
            std::fs::read(f.1.data.join(".second.tmp")).unwrap(),
            b"second"
        );
    }
    #[test]
    fn interrupted_marker_publication_reuses_saved_credential_without_adopting_orphan_file() {
        let f = Fixture::new();
        let profile = f.create();
        let saved = serde_json::to_string(&profile).unwrap();
        let expected = profile.password();
        drop(profile);
        std::fs::rename(
            f.1.data.join(".host-profile"),
            f.1.data.join(".host-profile-interrupted.tmp"),
        )
        .unwrap();
        let restored = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_| Ok(Some(serde_json::from_str(&saved).unwrap())),
            |_, _| panic!("interrupted publication must reuse saved credential"),
        )
        .unwrap();
        assert_eq!(restored.password().as_str(), expected.as_str());
        assert_eq!(
            std::fs::read(f.1.data.join(".host-profile-interrupted.tmp")).unwrap(),
            restored.binding().as_bytes()
        );
        let marker = std::fs::File::open(f.1.data.join(".host-profile")).unwrap();
        crate::host_state::valid_file(&marker).unwrap();
    }
    #[test]
    fn fresh_profile_binds_secure_uuid_separately_from_configuration_id() {
        let f = Fixture::new();
        let profile = f.create();
        let record = serde_json::to_value(&profile).unwrap();
        assert_eq!(record["schemaVersion"], 2);
        assert_eq!(
            record["secureInstallationId"],
            "11111111-1111-4111-8111-111111111111"
        );
        assert_ne!(record["secureInstallationId"], f.1.installation_id);
    }
    #[cfg(not(windows))]
    #[test]
    fn pre_uuid_configuration_legacy_account_is_still_found_without_a_reservation() {
        let f = Fixture::new();
        crate::runtime_store::private_directory(&f.1.state).unwrap();
        crate::runtime_store::private_directory(&f.1.data).unwrap();
        let state =
            cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&f.1.state).unwrap());
        let data =
            cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&f.1.data).unwrap());
        // Literal pre-field configuration: do not derive the expected account from today's serializer.
        let configuration = serde_json::json!({"installationId":f.1.installation_id,"name":f.1.name,
            "release":f.1.release,"controller":f.1.controller,"state":f.1.state,"data":f.1.data,
            "origin":f.1.origin,"databasePort":f.1.database_port,"apiPort":f.1.api_port});
        let binding = serde_json::json!({"schemaVersion":1,"configuration":configuration,
            "candidate":f.0.join("runtime"),"manifestSha256":"b".repeat(64),
            "stateIdentity":crate::copy_source::root_identity(&state).unwrap(),
            "managerIdentity":crate::copy_source::root_identity(&data).unwrap()});
        let account = format!(
            "{ACCOUNT}-{:x}",
            Sha256::digest(serde_json_canonicalizer::to_vec(&binding).unwrap())
        );
        let found = std::cell::Cell::new(false);
        let result = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |requested| {
                if requested == account {
                    found.set(true);
                    Ok(Some(serde_json::from_value(serde_json::json!({"schemaVersion":1,
                    "bindingSha256":"a".repeat(64),"databasePassword":"synthetic-existing-password-with-enough-length"})).unwrap()))
                } else {
                    Ok(None)
                }
            },
            |_, _| panic!("historical credentials must not be replaced"),
        );
        assert!(matches!(result,Err(ref code) if code=="native_profile_recovery_required"));
        assert!(found.get());
        assert!(!f.1.data.join(".host-profile").exists());
    }

    #[test]
    fn interrupted_unbound_profile_credential_is_not_silently_assigned_a_secure_uuid() {
        let f = Fixture::new();
        let profile = f.create();
        let mut legacy = serde_json::to_value(&profile).unwrap();
        legacy["schemaVersion"] = serde_json::json!(1);
        legacy
            .as_object_mut()
            .unwrap()
            .remove("secureInstallationId");
        drop(profile);
        std::fs::remove_file(f.1.data.join(".host-profile")).unwrap();
        let reads = std::cell::Cell::new(0);
        let result = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_| {
                reads.set(reads.get() + 1);
                if reads.get() == 1 {
                    Ok(None)
                } else {
                    Ok(Some(serde_json::from_value(legacy.clone()).unwrap()))
                }
            },
            |_, _| panic!("must recover interrupted unbound credentials, never assign new keys"),
        );
        assert!(matches!(result, Err(ref code) if code=="native_profile_recovery_required"));
        assert_eq!(reads.get(), 2);
        assert!(!f.1.data.join(".host-profile").exists());
    }

    #[test]
    fn mismatched_configuration_uuid_refuses_before_any_profile_io_or_store_access() {
        let f = Fixture::new();
        let result = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            "22222222-2222-4222-8222-222222222222",
            |_| panic!("mismatched configuration must not read credentials"),
            |_, _| panic!("mismatched configuration must not write credentials"),
        );
        assert!(matches!(result, Err(ref code) if code=="native_profile_identity_changed"));
        assert!(!f.1.state.exists());
        assert!(!f.1.data.exists());
    }

    #[test]
    fn invalid_secure_identity_refuses_before_any_profile_io_or_credential_access() {
        for invalid in [
            "",
            "aaaaaaaaaaaa",
            "00000000-0000-0000-0000-000000000000",
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
            "../escape",
        ] {
            let f = Fixture::new();
            let result = Profile::load_or_create(
                &f.1,
                &f.0.join("runtime"),
                &"b".repeat(64),
                invalid,
                |_| panic!("invalid UUID must not read credentials"),
                |_, _| panic!("invalid UUID must not persist"),
            );
            assert!(matches!(result, Err(ref code) if code=="native_profile_identity_invalid"));
            assert!(!f.1.state.exists());
            assert!(!f.1.data.exists());
        }
    }

    #[test]
    fn changed_secure_identity_never_rekeys_existing_profile_or_changes_journal_generation() {
        let mut f = Fixture::new();
        let saved = std::cell::RefCell::new(std::collections::BTreeMap::<String, String>::new());
        let profile = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |account| {
                saved
                    .borrow()
                    .get(account)
                    .map(|value| serde_json::from_str(value).map_err(|_| "invalid".into()))
                    .transpose()
            },
            |account, profile| {
                saved
                    .borrow_mut()
                    .insert(account.into(), serde_json::to_string(profile).unwrap());
                Ok(())
            },
        )
        .unwrap();
        let password = profile.password();
        let backup = profile.backup_key().unwrap();
        drop(profile);
        let mut owner = crate::host_state::Owner::acquire(
            &f.1.state,
            true,
            "11111111-1111-4111-8111-111111111111",
        )
        .unwrap();
        owner
            .activate(
                &f.1.installation_id,
                &"b".repeat(64),
                crate::host_runtime::HostMode::Server,
            )
            .unwrap();
        owner.clean_stop().unwrap();
        drop(owner);
        let journal = std::fs::read(f.1.state.join("controller-state.json")).unwrap();
        let reservation = std::fs::read(f.1.data.join(".host-profile")).unwrap();
        let old_records = saved.borrow().clone();
        let current = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |account| {
                saved
                    .borrow()
                    .get(account)
                    .map(|value| serde_json::from_str(value).map_err(|_| "invalid".into()))
                    .transpose()
            },
            |_, _| panic!("matching UUID must reuse both keys"),
        )
        .unwrap();
        assert_eq!(current.password().as_str(), password.as_str());
        assert_eq!(current.backup_key().unwrap().as_str(), backup.as_str());
        drop(current);
        f.1.secure_installation_id = "22222222-2222-4222-8222-222222222222".into();
        let requested = std::cell::RefCell::new(Vec::<String>::new());
        let result = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            "22222222-2222-4222-8222-222222222222",
            |account| {
                requested.borrow_mut().push(account.into());
                saved
                    .borrow()
                    .get(account)
                    .map(|value| serde_json::from_str(value).map_err(|_| "invalid".into()))
                    .transpose()
            },
            |_, _| panic!("changed UUID must never create replacement credentials"),
        );
        assert!(matches!(result, Err(ref code) if code=="native_profile_recovery_required"));
        assert_ne!(&requested.borrow()[0], old_records.keys().next().unwrap());
        assert_eq!(*saved.borrow(), old_records);
        assert_eq!(
            std::fs::read(f.1.state.join("controller-state.json")).unwrap(),
            journal
        );
        assert_eq!(
            std::fs::read(f.1.data.join(".host-profile")).unwrap(),
            reservation
        );
    }

    #[test]
    fn legacy_missing_wrong_and_unknown_profile_identity_never_rewrite_credentials_or_reservation()
    {
        for mode in ["legacy", "missing", "wrong", "unknown"] {
            let f = Fixture::new();
            let profile = f.create();
            let mut record = serde_json::to_value(&profile).unwrap();
            drop(profile);
            match mode {
                "legacy" => {
                    record["schemaVersion"] = serde_json::json!(1);
                    record
                        .as_object_mut()
                        .unwrap()
                        .remove("secureInstallationId");
                }
                "missing" => {
                    record
                        .as_object_mut()
                        .unwrap()
                        .remove("secureInstallationId");
                }
                "wrong" => {
                    record["secureInstallationId"] =
                        serde_json::json!("22222222-2222-4222-8222-222222222222")
                }
                "unknown" => record["futureMetadata"] = serde_json::json!("must retain"),
                _ => unreachable!(),
            }
            let before = record.clone();
            let marker = std::fs::read(f.1.data.join(".host-profile")).unwrap();
            let result = Profile::load_or_create(
                &f.1,
                &f.0.join("runtime"),
                &"b".repeat(64),
                SECURE_ID,
                |_| {
                    serde_json::from_value(record.clone())
                        .map(Some)
                        .map_err(|_| "credential_record_invalid".into())
                },
                |_, _| panic!("unbound or foreign profile must not be rewritten"),
            );
            assert!(result.is_err(), "{mode}");
            assert_eq!(record, before);
            assert_eq!(
                std::fs::read(f.1.data.join(".host-profile")).unwrap(),
                marker
            );
        }
    }
    #[test]
    fn transferred_session_guard_outlives_credentials_without_changing_serialization() {
        let f = Fixture::new();
        let mut profile = f.create();
        let saved = serde_json::to_vec(&profile).unwrap();
        let guard = profile.take_guard().unwrap();
        assert_eq!(serde_json::to_vec(&profile).unwrap(), saved);
        drop(profile);
        guard.require_current(&f.1).unwrap();
        assert!(
            matches!(ProfileGuard::acquire(&f.1), Err(e) if e == "native_profile_already_owned")
        );
        drop(guard);
        drop(ProfileGuard::acquire(&f.1).unwrap());
    }
    #[test]
    fn pending_update_refuses_profile_bootstrap_before_any_credential_read() {
        let f = Fixture::new();
        drop(f.create());
        std::fs::write(f.1.state.join("host-update.json"), b"pending").unwrap();
        let result = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_| panic!("pending update must not read credentials"),
            |_, _| panic!("pending update must not persist credentials"),
        );
        assert!(matches!(result, Err(e) if e == "host_update_pending"));
    }
    #[test]
    fn startup_fence_check_is_available_before_installation_identity_access() {
        let f = Fixture::new();
        check_start(&f.1).unwrap();
        assert!(!f.1.state.exists());
        drop(f.create());
        std::fs::write(f.1.state.join("host-update.json"), b"pending").unwrap();
        assert!(matches!(check_start(&f.1), Err(e) if e == "host_update_pending"));
    }
    #[test]
    fn validated_profile_persists_identity_and_allows_recovery_bootstrap_after_unclean_exit() {
        for torn in [false, true] {
            let f = Fixture::new();
            let profile = f.create();
            let saved = serde_json::to_vec(&profile).unwrap();
            let password = profile.password();
            let key = profile.backup_key().unwrap();
            let identity_path = f.1.data.join(".host-configuration.json");
            assert!(
                identity_path.exists(),
                "validated profile did not persist independent library identity"
            );
            let record = std::fs::read(&identity_path).unwrap();
            drop(profile);
            let mut owner = crate::host_state::Owner::acquire(&f.1.state, true, SECURE_ID).unwrap();
            owner
                .activate(
                    &f.1.installation_id,
                    &"b".repeat(64),
                    crate::host_runtime::HostMode::Server,
                )
                .unwrap();
            drop(owner); // Model supervisor loss without a clean-stop receipt.
            if torn {
                std::fs::write(f.1.state.join("controller-state.json"), b"{").unwrap();
            }
            let journal = std::fs::read(f.1.state.join("controller-state.json")).unwrap();
            let recovered = Profile::load_or_create(
                &f.1,
                &f.0.join("runtime"),
                &"b".repeat(64),
                SECURE_ID,
                |_| Ok(Some(serde_json::from_slice(&saved).unwrap())),
                |_, _| panic!("recovery must not replace credentials"),
            )
            .unwrap();
            assert_eq!(recovered.password(), password);
            assert_eq!(recovered.backup_key().unwrap(), key);
            assert_eq!(std::fs::read(identity_path).unwrap(), record);
            assert_eq!(
                std::fs::read(f.1.state.join("controller-state.json")).unwrap(),
                journal
            );
            let mut controller =
                crate::host_state::Owner::acquire(&f.1.state, false, SECURE_ID).unwrap();
            assert!(
                controller
                    .inspect(&f.1.installation_id, &"b".repeat(64))
                    .is_err(),
                "identity metadata admitted an unclean host"
            );
        }
    }
    #[test]
    fn changed_or_malformed_independent_identity_is_not_repaired_by_normal_bootstrap() {
        for field in [
            "schemaVersion",
            "secureInstallationId",
            "stateIdentity",
            "managerIdentity",
            "profileBindingSha256",
            "unknown",
            "torn",
        ] {
            let f = Fixture::new();
            let profile = f.create();
            let saved = serde_json::to_vec(&profile).unwrap();
            drop(profile);
            let path = f.1.data.join(".host-configuration.json");
            let mut record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            record[field] = if field == "schemaVersion" {
                serde_json::json!(99)
            } else {
                serde_json::json!("changed")
            };
            let bytes = if field == "torn" {
                b"{".to_vec()
            } else {
                serde_json::to_vec(&record).unwrap()
            };
            std::fs::write(&path, &bytes).unwrap();
            assert!(configuration_id(&f.1.state, &f.1.data, SECURE_ID).is_err());
            assert!(Profile::load_or_create(
                &f.1,
                &f.0.join("runtime"),
                &"b".repeat(64),
                SECURE_ID,
                |_| Ok(Some(serde_json::from_slice(&saved).unwrap())),
                |_, _| panic!("must not overwrite secrets")
            )
            .is_err());
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
    }
    #[test]
    fn substituted_identity_selector_cannot_authorize_a_different_profile_account() {
        let mut f = Fixture::new();
        let profile = f.create();
        let saved = serde_json::to_vec(&profile).unwrap();
        drop(profile);
        let path = f.1.data.join(".host-configuration.json");
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["installationId"] = serde_json::json!("b".repeat(12));
        let bytes = serde_json::to_vec(&record).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        f.1.installation_id = configuration_id(&f.1.state, &f.1.data, SECURE_ID)
            .unwrap()
            .unwrap();
        assert!(Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_| Ok(Some(serde_json::from_slice(&saved).unwrap())),
            |_, _| panic!("forged selector must not write credentials")
        )
        .is_err());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    #[test]
    fn validated_legacy_profile_adds_metadata_without_replacing_credentials_or_rewriting_journal() {
        let f = Fixture::new();
        let profile = f.create();
        let saved = serde_json::to_vec(&profile).unwrap();
        let password = profile.password();
        let key = profile.backup_key().unwrap();
        drop(profile);
        let path = f.1.data.join(".host-configuration.json");
        std::fs::remove_file(&path).unwrap();
        std::fs::write(f.1.state.join("controller-state.json"), b"{").unwrap();
        assert_eq!(
            configuration_id(&f.1.state, &f.1.data, SECURE_ID).unwrap(),
            None
        );
        let profile = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
            SECURE_ID,
            |_| Ok(Some(serde_json::from_slice(&saved).unwrap())),
            |_, _| panic!("must not migrate or replace stored secrets"),
        )
        .unwrap();
        assert_eq!(profile.password(), password);
        assert_eq!(profile.backup_key().unwrap(), key);
        assert_eq!(
            configuration_id(&f.1.state, &f.1.data, SECURE_ID)
                .unwrap()
                .as_deref(),
            Some(f.1.installation_id.as_str())
        );
        assert_eq!(
            std::fs::read(f.1.state.join("controller-state.json")).unwrap(),
            b"{"
        );
    }
    #[cfg(unix)]
    #[test]
    fn independent_identity_refuses_links_and_directory_replacement() {
        use std::os::unix::fs::symlink;
        for shape in ["symlink", "hardlink", "directory", "root"] {
            let f = Fixture::new();
            let profile = f.create();
            drop(profile);
            let path = f.1.data.join(".host-configuration.json");
            let original = std::fs::read(&path).unwrap();
            if shape == "root" {
                let moved = f.0.join("retained-manager");
                std::fs::rename(&f.1.data, &moved).unwrap();
                crate::runtime_store::private_directory(&f.1.data).unwrap();
                std::fs::copy(moved.join(".host-configuration.json"), &path).unwrap();
                std::fs::copy(moved.join(".host-profile"), f.1.data.join(".host-profile")).unwrap();
            } else {
                let saved = f.1.data.join("saved-configuration");
                std::fs::rename(&path, &saved).unwrap();
                match shape {
                    "symlink" => symlink(&saved, &path).unwrap(),
                    "hardlink" => std::fs::hard_link(&saved, &path).unwrap(),
                    _ => std::fs::create_dir(&path).unwrap(),
                }
            }
            assert!(configuration_id(&f.1.state, &f.1.data, SECURE_ID).is_err());
            if shape != "directory" {
                assert_eq!(std::fs::read(path).unwrap(), original);
            }
        }
    }
}
