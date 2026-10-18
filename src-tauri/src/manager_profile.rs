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

const ACCOUNT: &str = "native-host-profile";
static LOCK: Mutex<()> = Mutex::new(());
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Profile {
    schema_version: u32,
    binding_sha256: String,
    database_password: String,
    #[serde(default)]
    backup_key: Option<String>,
    #[serde(skip)]
    #[zeroize(skip)]
    guard: Option<ProfileGuard>,
}
struct ProfileGuard {
    _lease: File,
    state: cap_std::fs::Dir,
    data: cap_std::fs::Dir,
}
impl Drop for ProfileGuard {
    fn drop(&mut self) {
        // A concurrent fork can retain the open file description until its CLOEXEC copies close.
        let _ = self._lease.unlock();
    }
}
impl Profile {
    pub(crate) fn binding(&self) -> &str {
        &self.binding_sha256
    }
    pub(crate) fn require_current(&self, config: &Configuration) -> Result<(), String> {
        let guard = self.guard.as_ref().ok_or("native_profile_unavailable")?;
        crate::host_state::valid_file(&guard._lease)
            .map_err(|_| "native_profile_binding_changed")?;
        let fresh_state =
            cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&config.state)?);
        let fresh_data =
            cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&config.data)?);
        if crate::copy_source::root_identity(&fresh_state)?
            != crate::copy_source::root_identity(&guard.state)?
            || crate::copy_source::root_identity(&fresh_data)?
                != crate::copy_source::root_identity(&guard.data)?
        {
            return Err("native_profile_binding_changed".into());
        }
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt as _;
            use std::os::unix::fs::MetadataExt as _;
            let named = guard
                .data
                .symlink_metadata(".setup.lock")
                .map_err(|_| "native_profile_binding_changed")?;
            let held = guard
                ._lease
                .metadata()
                .map_err(|_| "native_profile_binding_changed")?;
            if !named.is_file() || named.dev() != held.dev() || named.ino() != held.ino() {
                return Err("native_profile_binding_changed".into());
            }
        }
        Ok(())
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
        Self::load_or_create(
            config,
            candidate,
            manifest,
            crate::credentials::load,
            crate::credentials::save,
        )
    }
    fn load_or_create(
        config: &Configuration,
        candidate: &Path,
        manifest: &str,
        load: impl FnOnce(&str) -> Result<Option<Self>, String>,
        mut persist: impl FnMut(&str, &Self) -> Result<(), String>,
    ) -> Result<Self, String> {
        validate_configuration(config)?;
        if !crate::native_runtime::digest_valid(manifest, 64) {
            return Err("native_profile_binding_invalid".into());
        }
        validate_paths(candidate, &config.state, &config.data)?;
        let _lock = LOCK.lock().map_err(|_| "native_profile_unavailable")?;
        crate::runtime_store::private_directory(&config.state)?;
        crate::runtime_store::private_directory(&config.data)?;
        validate_paths(candidate, &config.state, &config.data)?;
        let data = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&config.data)?);
        let lease = data
            .open_with(".setup.lock", &crate::host_state::options(true))
            .map_err(|_| "native_profile_unavailable")?
            .into_std();
        crate::host_state::valid_file(&lease).map_err(|_| "native_profile_unavailable")?;
        lease
            .try_lock()
            .map_err(|_| "native_profile_already_owned")?;
        let state = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&config.state)?);
        #[cfg(not(windows))]
        let binding = serde_json::json!({"schemaVersion":1,"configuration":config,"candidate":candidate,"manifestSha256":manifest,
            "stateIdentity":crate::copy_source::root_identity(&state)?,"managerIdentity":crate::copy_source::root_identity(&data)?});
        #[cfg(windows)]
        let binding = {
            let candidate =
                cap_std::fs::Dir::from_std_file(crate::host_storage::directory(candidate)?);
            let controller =
                File::open(crate::windows_protection::stable_path(&config.controller)?)
                    .map_err(|_| "native_profile_binding_invalid")?;
            windows_binding::value(
                config,
                manifest,
                [
                    crate::copy_source::root_identity(&state)?,
                    crate::copy_source::root_identity(&data)?,
                ],
                [
                    crate::windows_protection::durable_name(&candidate)?,
                    crate::windows_protection::durable_name(&controller)?,
                    crate::windows_protection::durable_name(&state)?,
                    crate::windows_protection::durable_name(&data)?,
                ],
            )?
        };
        let binding_sha256 = format!(
            "{:x}",
            Sha256::digest(
                serde_json_canonicalizer::to_vec(&binding)
                    .map_err(|_| "native_profile_binding_invalid")?
            )
        );
        let account = format!("{ACCOUNT}-{binding_sha256}");
        let saved = load(&account)?;
        let mut profile = if let Some(saved) = saved {
            if saved.schema_version != 1
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
                schema_version: 1,
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
                    publish_marker(&data, &temp)?;
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
        profile.guard = Some(ProfileGuard {
            _lease: lease,
            state,
            data,
        });
        profile.require_current(config)?;
        Ok(profile)
    }
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
fn publish_marker(data: &cap_std::fs::Dir, temp: &str) -> Result<(), String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::os::fd::AsRawFd;
        let name = std::ffi::CString::new(temp).map_err(|_| "native_profile_unavailable")?;
        let fd = data.as_raw_fd();
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                fd,
                name.as_ptr(),
                fd,
                c".host-profile".as_ptr(),
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
                c".host-profile".as_ptr(),
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
        let name: Vec<u16> = ".host-profile\0".encode_utf16().collect();
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
        let _ = (data, temp);
        Err("native_profile_platform_unsupported".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager_host::Configuration;
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
            load,
            |_, _| Err("credential_store_locked".into())
        )
        .is_err());
        let saved = std::cell::RefCell::new(None);
        let upgraded = Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
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
            |_account: &str| Ok(None),
            |_account, _profile| panic!("must refuse missing credential")
        )
        .is_err());
        assert!(Profile::load_or_create(
            &f.1,
            &f.0.join("runtime"),
            &"b".repeat(64),
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
            |account| {
                *account_one.borrow_mut() = account.into();
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
            |account| {
                *account_two.borrow_mut() = account.into();
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
        publish_marker(&dir, ".first.tmp").unwrap();
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
        publish_marker(&dir, ".first.tmp").unwrap();
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
        assert!(publish_marker(&dir, ".second.tmp").is_err());
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
}
