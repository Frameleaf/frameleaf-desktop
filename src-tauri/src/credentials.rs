use crate::connection::DeviceIdentity;
use keyring::{Entry, Error};
use serde::{de::DeserializeOwned, Serialize};
use zeroize::Zeroizing;

const SERVICE: &str = "app.frameleaf.desktop";
pub fn load<T: DeserializeOwned>(account: &str) -> Result<Option<T>, String> {
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
    let data =
        Zeroizing::new(serde_json::to_string(value).map_err(|_| "credential_record_invalid")?);
    Entry::new(SERVICE, account)
        .map_err(|_| "credential_store_unavailable")?
        .set_password(&data)
        .map_err(|_| "credential_store_locked_or_unavailable".into())
}
pub fn delete(account: &str) -> Result<(), String> {
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
