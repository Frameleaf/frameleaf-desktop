use crate::connection::DeviceIdentity;
use crate::worker::{persist_checkpoint, SavedWorker};
#[cfg(any(not(target_os = "macos"), test))]
use keyring::{Entry, Error};
#[cfg(target_os = "macos")]
#[path = "macos_keychain.rs"]
mod macos;
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

#[cfg(any(not(target_os = "macos"), test))]
const SERVICE: &str = "app.frameleaf.desktop";
pub fn load<T: DeserializeOwned>(account: &str) -> Result<Option<T>, String> {
    let _lock = worker_lock(account)?;
    load_record(account)
}
fn load_record<T: DeserializeOwned>(account: &str) -> Result<Option<T>, String> {
    read_record(account, Prompt::Silent)
}

#[repr(u32)]
#[derive(Clone, Copy)]
pub(super) enum Prompt {
    Silent,
    Foreground,
    Retry,
}

/// Interactive access is requested only by local foreground credential commands.
pub fn load_interactive<T: DeserializeOwned>(
    account: &str,
    window: &tauri::WebviewWindow,
    retry: bool,
) -> Result<Option<T>, String> {
    let _lock = worker_lock(account)?;
    read_record(account, foreground_prompt(window, retry))
}

fn foreground_prompt(window: &tauri::WebviewWindow, retry: bool) -> Prompt {
    if !window.is_focused().unwrap_or(false) {
        Prompt::Silent
    } else if retry {
        Prompt::Retry
    } else {
        Prompt::Foreground
    }
}

/// New user-presence items are added without a grant. Read the actual item once before
/// using the sign-in so subsequent noninteractive refreshes inherit the authorized context.
pub fn confirm_new_sign_in<T: Serialize>(
    _account: &str,
    _value: &T,
    _window: &tauri::WebviewWindow,
) -> Result<(), String> {
    #[cfg(all(target_os = "macos", not(test)))]
    {
        let bytes =
            Zeroizing::new(serde_json::to_vec(_value).map_err(|_| "credential_record_invalid")?);
        macos::confirm(_account, &bytes, foreground_prompt(_window, true))?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", not(test)))]
fn read_record<T: DeserializeOwned>(account: &str, prompt: Prompt) -> Result<Option<T>, String> {
    macos::read(account, prompt)
}

#[cfg(any(not(target_os = "macos"), test))]
fn read_record<T: DeserializeOwned>(account: &str, _prompt: Prompt) -> Result<Option<T>, String> {
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
    #[cfg(all(target_os = "macos", not(test)))]
    return macos::write(account, data.as_bytes());
    #[cfg(any(not(target_os = "macos"), test))]
    Entry::new(SERVICE, account)
        .map_err(|_| "credential_store_unavailable")?
        .set_password(&data)
        .map_err(|_| "credential_store_locked_or_unavailable".into())
}
pub fn delete(account: &str) -> Result<(), String> {
    let _lock = worker_lock(account)?;
    #[cfg(all(target_os = "macos", not(test)))]
    return macos::delete(account);
    #[cfg(any(not(target_os = "macos"), test))]
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

#[cfg(test)]
fn disposable(github: &str, environment: &str, opt_in: &str) -> Result<(), &'static str> {
    if github == "true" && environment == "github-hosted" && opt_in == "1" {
        Ok(())
    } else {
        Err("disposable_keystore_runner_required")
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
