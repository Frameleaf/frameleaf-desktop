use crate::connection::DeviceIdentity;
use crate::worker::{persist_checkpoint, SavedWorker};
use keyring::{Entry, Error};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "credential_epoch_qualification.rs"]
mod qualification;

static INSTALLATION_LOCK: Mutex<()> = Mutex::new(());
static WORKER_LOCK: Mutex<()> = Mutex::new(());
fn worker_lock(account: &str) -> Result<Option<MutexGuard<'static, ()>>, String> {
    if account == "worker-session" {
        return WORKER_LOCK
            .lock()
            .map(Some)
            .map_err(|_| "credential_store_unavailable".into());
    }
    Ok(None)
}

const SERVICE: &str = "app.frameleaf.desktop";
pub fn load<T: DeserializeOwned>(account: &str) -> Result<Option<T>, String> {
    let _lock = worker_lock(account)?;
    load_record(account)
}
fn load_record<T: DeserializeOwned>(account: &str) -> Result<Option<T>, String> {
    let entry = Entry::new(SERVICE, account).map_err(|_| "credential_store_unavailable")?;
    match entry.get_password() {
        Ok(value) => serde_json::from_str(&Zeroizing::new(value))
            .map(Some)
            .map_err(|_| "credential_record_invalid".into()),
        Err(Error::NoEntry) => Ok(None),
        Err(_) => Err("credential_store_locked_or_unavailable".into()),
    }
}
pub fn save<T: Serialize>(account: &str, value: &T) -> Result<(), String> {
    let _lock = worker_lock(account)?;
    save_record(account, value)
}
fn save_record<T: Serialize>(account: &str, value: &T) -> Result<(), String> {
    let data =
        Zeroizing::new(serde_json::to_string(value).map_err(|_| "credential_record_invalid")?);
    Entry::new(SERVICE, account)
        .map_err(|_| "credential_store_unavailable")?
        .set_password(&data)
        .map_err(|_| "credential_store_locked_or_unavailable".into())
}
pub fn delete(account: &str) -> Result<(), String> {
    let _lock = worker_lock(account)?;
    match Entry::new(SERVICE, account)
        .map_err(|_| "credential_store_unavailable")?
        .delete_credential()
    {
        Ok(()) | Err(Error::NoEntry) => Ok(()),
        Err(_) => Err("credential_store_locked_or_unavailable".into()),
    }
}
pub fn identity() -> Result<DeviceIdentity, String> {
    let _lock = installation_lock()?;
    identity_with(
        || load_record("installation"),
        |identity| save_record("installation", identity),
        crate::identity_anchor::read,
        crate::identity_anchor::write,
    )
}
fn identity_with(
    load: impl FnOnce() -> Result<Option<DeviceIdentity>, String>,
    save: impl FnOnce(&DeviceIdentity) -> Result<(), String>,
    marker: impl FnOnce() -> Result<Option<String>, String>,
    mark: impl FnOnce(&str) -> Result<(), String>,
) -> Result<DeviceIdentity, String> {
    let marker = marker()?;
    let identity = match load()? {
        Some(identity) => identity,
        None if marker.is_some() => return Err("runtime_epoch_credential_missing".into()),
        None => {
            let identity = DeviceIdentity::generate();
            save(&identity)?;
            identity
        }
    };
    if let Some(marker) = marker {
        if marker != identity.installation_id {
            return Err("runtime_epoch_identity_changed".into());
        }
    } else {
        mark(&identity.installation_id)?;
    }
    Ok(identity)
}

pub fn save_worker_checkpoint(expected: &SavedWorker, next: &SavedWorker) -> Result<(), String> {
    let _lock = worker_lock("worker-session")?;
    let current = load_record::<SavedWorker>("worker-session")?;
    persist_checkpoint(current.as_ref(), expected, next, |value| {
        save_record("worker-session", value)
    })
}

fn installation_lock() -> Result<(MutexGuard<'static, ()>, crate::credential_lock::Guard), String> {
    let process = INSTALLATION_LOCK
        .lock()
        .map_err(|_| "credential_store_unavailable")?;
    let system = crate::credential_lock::acquire()?;
    Ok((process, system))
}
pub(crate) struct CredentialEpochAuthority;
fn runtime_identity() -> Result<DeviceIdentity, String> {
    let identity: DeviceIdentity =
        load_record("installation")?.ok_or("runtime_epoch_credential_missing")?;
    identity
        .runtime_epochs
        .as_ref()
        .ok_or("runtime_epoch_recovery_required")?
        .validate()?;
    if crate::identity_anchor::read()?.as_deref() != Some(identity.installation_id.as_str()) {
        return Err("runtime_epoch_recovery_required".into());
    }
    Ok(identity)
}
impl crate::runtime_epochs::EpochAuthority for CredentialEpochAuthority {
    fn installation_id(&self) -> Result<String, String> {
        let _lock = installation_lock()?;
        Ok(runtime_identity()?.installation_id.clone())
    }
    fn with_current(
        &self,
        installation_id: &str,
        runtime: &crate::native_runtime::VerifiedRuntime,
        operation: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let _lock = installation_lock()?;
        let identity = runtime_identity()?;
        if identity.installation_id != installation_id {
            return Err("runtime_epoch_identity_changed".into());
        }
        identity
            .runtime_epochs
            .as_ref()
            .ok_or("runtime_epoch_recovery_required")?
            .check(runtime)?;
        operation()
    }
    fn activate(
        &self,
        installation_id: &str,
        runtime: &crate::native_runtime::VerifiedRuntime,
        publish: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let _lock = installation_lock()?;
        let mut identity = runtime_identity()?;
        if identity.installation_id != installation_id {
            return Err("runtime_epoch_identity_changed".into());
        }
        identity
            .runtime_epochs
            .as_mut()
            .ok_or("runtime_epoch_recovery_required")?
            .admit(runtime)?;
        save_record("installation", &identity)?;
        publish()
    }
}

#[cfg(any(test, debug_assertions))]
fn disposable(github: &str, environment: &str, opt_in: &str) -> Result<(), &'static str> {
    if github == "true" && environment == "github-hosted" && opt_in == "1" {
        Ok(())
    } else {
        Err("disposable_keystore_runner_required")
    }
}

#[cfg(any(test, debug_assertions))]
fn controller_access_receipt(
    identity: &DeviceIdentity,
    expected: &str,
) -> Result<serde_json::Value, String> {
    if uuid::Uuid::parse_str(expected).is_err() || identity.installation_id != expected {
        return Err("runtime_epoch_identity_changed".into());
    }
    let epochs = identity
        .runtime_epochs
        .as_ref()
        .ok_or("runtime_epoch_recovery_required")?;
    epochs.validate()?;
    Ok(
        serde_json::json!({"protocolVersion":1,"installationId":identity.installation_id,
        "publicKey":identity.public_key(),"runtimeEpochs":epochs}),
    )
}

#[cfg(debug_assertions)]
pub(crate) fn qualify_controller_access(expected: &str) -> Result<serde_json::Value, String> {
    disposable(
        &std::env::var("GITHUB_ACTIONS").unwrap_or_default(),
        &std::env::var("RUNNER_ENVIRONMENT").unwrap_or_default(),
        &std::env::var("FRAMELEAF_TEST_DISPOSABLE_KEYSTORE").unwrap_or_default(),
    )?;
    #[cfg(target_os = "macos")]
    let _interaction = qualification_keychain::NonInteractive::enter()?;
    eprintln!("credential_probe_phase=installation_lock");
    let _lock = installation_lock()?;
    eprintln!("credential_probe_phase=identity_read");
    let identity = runtime_identity()?;
    eprintln!("credential_probe_phase=public_receipt");
    controller_access_receipt(&identity, expected)
}

#[cfg(all(debug_assertions, target_os = "macos"))]
mod qualification_keychain {
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecKeychainGetUserInteractionAllowed(state: *mut u8) -> i32;
        fn SecKeychainSetUserInteractionAllowed(state: u8) -> i32;
    }

    pub(super) struct NonInteractive(u8);
    impl NonInteractive {
        pub(super) fn enter() -> Result<Self, &'static str> {
            let mut previous = 0;
            if unsafe { SecKeychainGetUserInteractionAllowed(&mut previous) } != 0 {
                return Err("credential_probe_interaction_state_unavailable");
            }
            if unsafe { SecKeychainSetUserInteractionAllowed(0) } != 0 {
                return Err("credential_probe_interaction_disable_failed");
            }
            Ok(Self(previous))
        }
    }
    impl Drop for NonInteractive {
        fn drop(&mut self) {
            if unsafe { SecKeychainSetUserInteractionAllowed(self.0) } != 0 {
                eprintln!("credential_probe_interaction_restore_failed");
            }
        }
    }
}

#[cfg(test)]
mod epoch_enrollment_tests {
    use super::*;
    #[test]
    fn deleted_credential_cannot_turn_normal_sign_in_into_fresh_enrollment() {
        let identity = DeviceIdentity::generate();
        let marker = identity.installation_id.clone();
        let saved = std::cell::Cell::new(false);
        let result = identity_with(
            || Ok(None),
            |_| {
                saved.set(true);
                Ok(())
            },
            || Ok(Some(marker)),
            |_| panic!("must not replace enrollment marker"),
        );
        assert_eq!(result.err().unwrap(), "runtime_epoch_credential_missing");
        assert!(
            !saved.get(),
            "no replacement identity exists to bind to a fresh runtime root"
        );
    }
    #[test]
    fn interrupted_first_enrollment_can_finish_marker_without_replacing_saved_key() {
        let identity = DeviceIdentity::generate();
        let id = identity.installation_id.clone();
        let finished = std::cell::Cell::new(false);
        let result = identity_with(
            || Ok(Some(identity)),
            |_| panic!("must retain saved key"),
            || Ok(None),
            |value| {
                assert_eq!(value, id);
                finished.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(result.installation_id, id);
        assert!(finished.get());
    }
}
