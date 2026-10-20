use super::*;
use serde::de::DeserializeOwned;

pub(crate) trait UpdateStore {
    fn load<T: DeserializeOwned>(&mut self, account: &str) -> Result<Option<T>, String>;
    fn save<T: Serialize>(&mut self, account: &str, value: &T) -> Result<(), String>;
}
pub(crate) struct Keystore;
impl UpdateStore for Keystore {
    fn load<T: DeserializeOwned>(&mut self, account: &str) -> Result<Option<T>, String> {
        crate::credentials::load(account)
    }
    fn save<T: Serialize>(&mut self, account: &str, value: &T) -> Result<(), String> {
        crate::credentials::save(account, value)
    }
}

pub(crate) struct CredentialFacts {
    pub(crate) source_binding: String,
    pub(crate) target_binding: String,
    pub(crate) tls_certificate_sha256: String,
    pub(crate) credentials_sha256: String,
}
// Borrowed only while the profile and credential locks remain held; never a wire value.
pub(crate) struct PreparedCredentials<'a> {
    pub(crate) backup_key: &'a str,
    pub(crate) database_password: &'a str,
    pub(crate) profile: &'a ProfileGuard,
}
fn validate_profile(
    profile: &Profile,
    config: &Configuration,
    binding: &str,
) -> Result<(), String> {
    if profile.schema_version != 2
        || profile.secure_installation_id.as_deref() != Some(config.secure_installation_id.as_str())
        || profile.binding_sha256 != binding
        || !(24..=256).contains(&profile.database_password.len())
        || profile.database_password.contains(['\r', '\n', '\0'])
    {
        return Err("native_profile_binding_changed".into());
    }
    profile.backup_key()?;
    Ok(())
}
impl ProfileGuard {
    pub(crate) fn approval_key(
        &self,
        config: &Configuration,
        candidate: &Path,
        manifest: &str,
        store: &mut impl UpdateStore,
    ) -> Result<Zeroizing<String>, String> {
        let _lock = LOCK.lock().map_err(|_| "native_profile_unavailable")?;
        let (_, binding, account) = profile_accounts(
            config,
            candidate,
            manifest,
            &config.secure_installation_id,
            self,
        )?;
        if super::configuration::bytes(&self.data, ".host-profile", 64)?.as_deref()
            != Some(binding.as_bytes())
        {
            return Err("native_profile_binding_changed".into());
        }
        let profile: Profile = store
            .load(&account)?
            .ok_or("native_profile_recovery_required")?;
        validate_profile(&profile, config, &binding)?;
        self.require_current(config)?;
        profile.backup_key()
    }
    pub(crate) fn prepare_credentials(
        &self,
        profiles: [(&Configuration, &Path, &str); 2],
        store: &mut impl UpdateStore,
        begin: impl FnMut(&CredentialFacts) -> Result<(), String>,
    ) -> Result<CredentialFacts, String> {
        self.prepare_credentials_with(profiles, store, false, begin, |_, _| Ok(()))
    }
    pub(crate) fn review_prepared_credentials(
        &self,
        profiles: [(&Configuration, &Path, &str); 2],
        store: &mut impl UpdateStore,
        review: impl FnOnce(&CredentialFacts, &PreparedCredentials<'_>) -> Result<(), String>,
    ) -> Result<(), String> {
        self.review_update_credentials(profiles, store, false, review)
    }
    // Only the authenticated selection recovery caller may accept an interrupted target marker.
    pub(crate) fn review_update_credentials(
        &self,
        profiles: [(&Configuration, &Path, &str); 2],
        store: &mut impl UpdateStore,
        publication: bool,
        review: impl FnOnce(&CredentialFacts, &PreparedCredentials<'_>) -> Result<(), String>,
    ) -> Result<(), String> {
        self.prepare_credentials_with(
            profiles,
            &mut ReadOnlyStore(store),
            publication,
            |_| Ok(()),
            review,
        )
        .map(|_| ())
    }
    fn prepare_credentials_with(
        &self,
        profiles: [(&Configuration, &Path, &str); 2],
        store: &mut impl UpdateStore,
        publication: bool,
        mut begin: impl FnMut(&CredentialFacts) -> Result<(), String>,
        finish: impl FnOnce(&CredentialFacts, &PreparedCredentials<'_>) -> Result<(), String>,
    ) -> Result<CredentialFacts, String> {
        let _lock = LOCK.lock().map_err(|_| "native_profile_unavailable")?;
        let [(source, source_candidate, source_manifest), (target, target_candidate, target_manifest)] =
            profiles;
        let stable = |config: &Configuration| -> Result<serde_json::Value, String> {
            let mut value =
                serde_json::to_value(config).map_err(|_| "native_profile_binding_invalid")?;
            let object = value
                .as_object_mut()
                .ok_or("native_profile_binding_invalid")?;
            object.remove("release");
            object.remove("controller");
            Ok(value)
        };
        if stable(source)? != stable(target)?
            || source.secure_installation_id != target.secure_installation_id
        {
            return Err("native_profile_identity_changed".into());
        }
        let (_, source_binding, source_account) = profile_accounts(
            source,
            source_candidate,
            source_manifest,
            &source.secure_installation_id,
            self,
        )?;
        let (_, target_binding, target_account) = profile_accounts(
            target,
            target_candidate,
            target_manifest,
            &target.secure_installation_id,
            self,
        )?;
        let marker = super::configuration::bytes(&self.data, ".host-profile", 64)?
            .ok_or("native_profile_binding_changed")?;
        if source_account == target_account
            || (marker != source_binding.as_bytes()
                && !(publication && target_binding.as_bytes().starts_with(&marker)))
        {
            return Err("native_profile_binding_changed".into());
        }
        let source_profile: Profile = store
            .load(&source_account)?
            .ok_or("native_profile_recovery_required")?;
        validate_profile(&source_profile, source, &source_binding)?;
        let tls = crate::manager_tls::TlsUpdate::existing(
            &source.installation_id,
            &source.origin,
            [&source_binding, &target_binding],
            store,
        )?;
        let encoded = Zeroizing::new(
            serde_json_canonicalizer::to_vec(&source_profile)
                .map_err(|_| "native_profile_binding_invalid")?,
        );
        let facts = CredentialFacts {
            source_binding,
            target_binding: target_binding.clone(),
            tls_certificate_sha256: tls.fingerprint(),
            credentials_sha256: tls.commitment(encoded.as_slice())?,
        };
        begin(&facts)?;
        self.require_current(source)?;
        let expected = Profile {
            schema_version: 2,
            secure_installation_id: source_profile.secure_installation_id.clone(),
            binding_sha256: target_binding,
            database_password: source_profile.database_password.clone(),
            backup_key: source_profile.backup_key.clone(),
            guard: None,
        };
        let matches = |current: &Profile| -> Result<(), String> {
            validate_profile(current, target, &expected.binding_sha256)?;
            if current.database_password != expected.database_password
                || current.backup_key != expected.backup_key
            {
                return Err("native_profile_binding_changed".into());
            }
            Ok(())
        };
        if let Some(current) = store.load::<Profile>(&target_account)? {
            matches(&current)?;
        } else {
            store.save(&target_account, &expected)?;
        }
        let readback: Profile = store
            .load(&target_account)?
            .ok_or("native_profile_recovery_required")?;
        matches(&readback)?;
        tls.copy(store)?;
        self.require_current(source)?;
        let key = source_profile.backup_key()?;
        finish(
            &facts,
            &PreparedCredentials {
                backup_key: key.as_str(),
                database_password: &readback.database_password,
                profile: self,
            },
        )?;
        self.require_current(source)?;
        Ok(facts)
    }
}

// Review must never repair missing target accounts or perform a secure-store write.
struct ReadOnlyStore<'a, T>(&'a mut T);
impl<T: UpdateStore> UpdateStore for ReadOnlyStore<'_, T> {
    fn load<V: DeserializeOwned>(&mut self, account: &str) -> Result<Option<V>, String> {
        self.0.load(account)
    }
    fn save<V: Serialize>(&mut self, _account: &str, _value: &V) -> Result<(), String> {
        Err("host_update_credentials_missing".into())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[derive(Default)]
    pub(crate) struct Store(pub BTreeMap<String, Zeroizing<String>>);
    impl UpdateStore for Store {
        fn load<T: DeserializeOwned>(&mut self, account: &str) -> Result<Option<T>, String> {
            self.0
                .get(account)
                .map(|s| serde_json::from_str(s).map_err(|_| "synthetic_decode".into()))
                .transpose()
        }
        fn save<T: Serialize>(&mut self, account: &str, value: &T) -> Result<(), String> {
            self.0.insert(
                account.into(),
                Zeroizing::new(serde_json::to_string(value).unwrap()),
            );
            Ok(())
        }
    }
    pub(crate) fn seed(
        config: &Configuration,
        candidate: &Path,
        manifest: &str,
        store: &mut Store,
    ) {
        let guard = ProfileGuard::acquire(config).unwrap();
        let (_, binding, account) = profile_accounts(
            config,
            candidate,
            manifest,
            &config.secure_installation_id,
            &guard,
        )
        .unwrap();
        let profile = Profile {
            schema_version: 2,
            secure_installation_id: Some(config.secure_installation_id.clone()),
            binding_sha256: binding.clone(),
            database_password: "synthetic existing database password".into(),
            backup_key: Some("k".repeat(43)),
            guard: None,
        };
        store.save(&account, &profile).unwrap();
        let mut opts = crate::host_state::options(true);
        opts.truncate(true);
        guard
            .data
            .open_with(".host-profile", &opts)
            .unwrap()
            .write_all(binding.as_bytes())
            .unwrap();
        let tls = crate::manager_tls::TlsIdentity::load_or_create(
            &config.installation_id,
            &config.origin,
            || Ok(None),
            |_| Ok(()),
        )
        .unwrap();
        store
            .save(&format!("native-manager-tls-{binding}"), &tls)
            .unwrap();
    }
    #[test]
    fn preparation_copies_existing_credentials_only_after_durable_begin_and_checks_readback() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-update-keys-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let state = root.join("state");
        let data = root.join("manager");
        let config = Configuration {
            installation_id: "aaaaaaaaaaaa".into(),
            secure_installation_id: "11111111-1111-4111-8111-111111111111".into(),
            name: "Synthetic".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: if cfg!(windows) {
                std::env::current_exe().unwrap()
            } else {
                "/bin/echo".into()
            },
            state,
            data,
            origin: "https://127.0.0.1:9443".into(),
            database_port: 54329,
            api_port: 2283,
        };
        let candidate = root.join("candidate");
        let target = root.join("target");
        crate::runtime_store::private_directory(&candidate).unwrap();
        crate::runtime_store::private_directory(&target).unwrap();
        let mut store = Store::default();
        let cells = std::cell::RefCell::new(&mut store);
        let mut profile = Profile::load_or_create(
            &config,
            &candidate,
            &"a".repeat(64),
            &config.secure_installation_id,
            |a| cells.borrow_mut().load(a),
            |a, v| cells.borrow_mut().save(a, v),
        )
        .unwrap();
        let source_binding = profile.binding().to_owned();
        let tls = crate::manager_tls::TlsIdentity::load_or_create(
            &config.installation_id,
            &config.origin,
            || Ok(None),
            |_| Ok(()),
        )
        .unwrap();
        cells
            .borrow_mut()
            .save(&format!("native-manager-tls-{source_binding}"), &tls)
            .unwrap();
        let guard = profile.take_guard().unwrap();
        let target_config = Configuration {
            installation_id: config.installation_id.clone(),
            secure_installation_id: config.secure_installation_id.clone(),
            name: config.name.clone(),
            release: "frameleaf-v3.0.0-2".into(),
            controller: config.controller.clone(),
            state: config.state.clone(),
            data: config.data.clone(),
            origin: config.origin.clone(),
            database_port: config.database_port,
            api_port: config.api_port,
        };
        let mut began = false;
        let before = std::fs::read(config.data.join(".host-profile")).unwrap();
        guard
            .prepare_credentials(
                [
                    (&config, &candidate, "a".repeat(64).as_str()),
                    (&target_config, &target, "b".repeat(64).as_str()),
                ],
                &mut **cells.borrow_mut(),
                |facts| {
                    assert_eq!(facts.source_binding, source_binding);
                    assert_eq!(facts.tls_certificate_sha256.len(), 64);
                    began = true;
                    Ok(())
                },
            )
            .unwrap();
        assert!(began);
        assert_eq!(
            std::fs::read(config.data.join(".host-profile")).unwrap(),
            before
        );
        let accounts = cells.borrow().0.clone();
        for fail_child in [true, false] {
            let result = guard.review_prepared_credentials(
                [(&config, &candidate, &"a".repeat(64)), (&target_config, &target, &"b".repeat(64))],
                &mut **cells.borrow_mut(),
                |facts, credentials| {
                    assert_eq!(facts.source_binding, source_binding);
                    assert_eq!(credentials.database_password, profile.database_password);
                    assert_eq!(credentials.backup_key, profile.backup_key()?.as_str());
                    assert!(std::ptr::eq(credentials.profile, &guard));
                    assert!(matches!(ProfileGuard::acquire(&config), Err(code) if code == "native_profile_already_owned"));
                    if fail_child { Err("synthetic_child_failed".into()) } else { Ok(()) }
                },
            );
            assert_eq!(
                result.err().as_deref(),
                if fail_child {
                    Some("synthetic_child_failed")
                } else {
                    None
                }
            );
            assert_eq!(cells.borrow().0, accounts);
            assert_eq!(
                std::fs::read(config.data.join(".host-profile")).unwrap(),
                before
            );
        }
        drop(guard);
        drop(profile);
        std::fs::remove_dir_all(root).unwrap();
    }
}
