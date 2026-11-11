use crate::connection::{photo_session_scope, DeviceIdentity, SavedConnection};
use crate::worker::{persist_checkpoint, SavedWorker};
#[cfg(any(not(target_os = "macos"), test))]
use keyring::{Entry, Error};
#[cfg(target_os = "macos")]
#[path = "macos_keychain.rs"]
mod macos;
use serde::{de::DeserializeOwned, Serialize};
use std::borrow::Cow;
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
    load_record(&source_account(account)?)
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
    save_record(&source_account(account)?, value)
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
    delete_record(&source_account(account)?)
}

fn delete_record(account: &str) -> Result<(), String> {
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
const SOURCE_APPROVALS: [&str; 2] = [
    crate::source_consent::CREDENTIAL,
    crate::drop_import::CREDENTIAL,
];

fn scoped_source_account(account: &str, saved: &SavedConnection) -> String {
    // Consent is signed for the precise photo session, even when the same account signs in again.
    format!("{account}-{}", photo_session_scope(saved))
}

fn source_account(account: &str) -> Result<Cow<'_, str>, String> {
    if SOURCE_APPROVALS.contains(&account) {
        if let Some(saved) = load_record::<SavedConnection>("connection")? {
            if !saved.server_id.is_empty() {
                return Ok(Cow::Owned(scoped_source_account(account, &saved)));
            }
        }
    }
    Ok(Cow::Borrowed(account))
}

pub(crate) fn migrate_source_approvals(saved: &SavedConnection) -> Result<(), String> {
    if saved.server_id.is_empty() {
        return Ok(());
    }
    for account in SOURCE_APPROVALS {
        if let Some(consent) = load_record::<crate::source_consent::Consent>(account)? {
            if consent.require(saved, &identity()?).is_ok() {
                let scoped = scoped_source_account(account, saved);
                if load_record::<crate::source_consent::Consent>(&scoped)?.is_none() {
                    save_record(&scoped, &consent)?;
                }
                delete_record(account)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn delete_parked_source_approvals(saved: &SavedConnection) -> Result<(), String> {
    for account in SOURCE_APPROVALS {
        delete_record(&scoped_source_account(account, saved))?;
    }
    Ok(())
}

pub(crate) fn delete_source_approvals(saved: Option<&SavedConnection>) -> bool {
    let mut cleared = true;
    for account in SOURCE_APPROVALS {
        if let Some(saved) = saved {
            cleared &= delete_record(&scoped_source_account(account, saved)).is_ok();
        }
        cleared &= delete_record(account).is_ok();
    }
    cleared
}

pub fn identity() -> Result<DeviceIdentity, String> {
    identity_with_prompt(Prompt::Silent)
}

// An explicitly requested sign-in can authorize the old installation key during migration.
// The migrated operational item needs no user-presence prompt for subsequent worker reads.
pub fn foreground_identity(window: &tauri::WebviewWindow) -> Result<DeviceIdentity, String> {
    identity_with_prompt(foreground_prompt(window, true)).map_err(|code| {
        if code == "credential_unlock_required" {
            "credential_device_unlock_required".into()
        } else {
            code
        }
    })
}
pub fn unlock_existing_identity(window: &tauri::WebviewWindow) -> Result<(), String> {
    let _lock = installation_lock()?;
    read_record::<DeviceIdentity>("installation", foreground_prompt(window, true)).map(|_| ())
}
fn identity_with_prompt(prompt: Prompt) -> Result<DeviceIdentity, String> {
    let _lock = installation_lock()?;
    identity_with(
        || read_record("installation", prompt),
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

#[cfg(test)]
mod library_switch_source_scope_tests {
    use super::*;

    #[test]
    fn source_approvals_follow_only_the_original_library_account_and_session() {
        let original = SavedConnection {
            server: "https://example.invalid/".into(),
            server_id: "server".into(),
            account_id: "account".into(),
            name: "Fixture".into(),
            token: "fixture".into(),
            device_name: "Desktop".into(),
            mode: "client-worker".into(),
            device_id: None,
        };
        let account = crate::source_consent::CREDENTIAL;
        let original_key = scoped_source_account(account, &original);
        let mut different = original.clone();
        different.server_id = "different-library".into();
        assert_ne!(scoped_source_account(account, &different), original_key);
        different.server_id = original.server_id.clone();
        different.account_id = "different-account".into();
        assert_ne!(scoped_source_account(account, &different), original_key);
        different.account_id = original.account_id.clone();
        different.token = "new-session".into();
        assert_ne!(scoped_source_account(account, &different), original_key);
        different.token = original.token.clone();
        assert_eq!(scoped_source_account(account, &different), original_key);
    }
}
