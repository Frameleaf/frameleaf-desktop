use crate::connection::DeviceIdentity;
use crate::worker::{persist_checkpoint, SavedWorker};
use keyring::{Entry, Error};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

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
    if let Some(identity) = load("installation")? {
        return Ok(identity);
    }
    let identity = DeviceIdentity::generate();
    save("installation", &identity)?;
    Ok(identity)
}

pub fn save_worker_checkpoint(expected: &SavedWorker, next: &SavedWorker) -> Result<(), String> {
    let _lock = worker_lock("worker-session")?;
    let current = load_record::<SavedWorker>("worker-session")?;
    persist_checkpoint(current.as_ref(), expected, next, |value| {
        save_record("worker-session", value)
    })
}
