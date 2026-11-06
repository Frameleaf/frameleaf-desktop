//! Private Manager identity: generated in-process and persisted only through the existing OS keystore.
use rcgen::{CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};
use zeroize::{Zeroize, ZeroizeOnDrop};

static IDENTITY_LOCK: Mutex<()> = Mutex::new(());
fn account_for_profile(binding: &str) -> Result<String, String> {
    if !crate::native_runtime::digest_valid(binding, 64) {
        return Err("native_tls_binding_invalid".into());
    }
    Ok(format!("native-manager-tls-{binding}"))
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TlsIdentity {
    schema_version: u32,
    installation_id: String,
    origin: String,
    certificate_pem: String,
    private_key_pem: String,
    expires_at: i64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapTls<'a> {
    certificate_pem: &'a str,
    private_key_pem: &'a str,
}
fn hostname(id: &str, origin: &str) -> Result<String, String> {
    if id.len() != 12
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || origin.len() > 2048
    {
        return Err("native_tls_binding_invalid".into());
    }
    let address = url::Url::parse(origin).map_err(|_| "native_tls_binding_invalid")?;
    if address.scheme() != "https"
        || address.origin().ascii_serialization() != origin
        || !address.username().is_empty()
        || address.password().is_some()
        || address.path() != "/"
        || address.query().is_some()
        || address.fragment().is_some()
    {
        return Err("native_tls_binding_invalid".into());
    }
    Ok(address
        .host_str()
        .ok_or("native_tls_binding_invalid")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned())
}
impl TlsIdentity {
    /// The certificate Manager last served for a profile binding, if it ever started.
    pub(crate) fn saved_certificate(binding: &str) -> Result<Option<String>, String> {
        Ok(
            crate::credentials::load::<Self>(&account_for_profile(binding)?)?
                .map(|saved| saved.certificate_pem.clone()),
        )
    }
    /// Keep the paired Manager certificate when a profile moves to a newer package.
    pub(crate) fn carry_forward(previous: &str, next: &str) -> Result<(), String> {
        Self::carry_forward_with(
            previous,
            next,
            crate::credentials::load,
            crate::credentials::save,
        )
    }
    fn carry_forward_with(
        previous: &str,
        next: &str,
        load: impl Fn(&str) -> Result<Option<Self>, String>,
        persist: impl FnOnce(&str, &Self) -> Result<(), String>,
    ) -> Result<(), String> {
        let (from, to) = (account_for_profile(previous)?, account_for_profile(next)?);
        let _lock = IDENTITY_LOCK
            .lock()
            .map_err(|_| "credential_store_unavailable")?;
        if load(&to)?.is_some() {
            return Ok(());
        }
        // No saved certificate means Manager mints one at start; Desktop then asks to pair again.
        match load(&from)? {
            Some(saved) => persist(&to, &saved),
            None => Ok(()),
        }
    }
    pub fn from_keystore(
        installation_id: &str,
        origin: &str,
        binding: &str,
    ) -> Result<Self, String> {
        let account = account_for_profile(binding)?;
        Self::load_or_create(
            installation_id,
            origin,
            || crate::credentials::load(&account),
            |value| crate::credentials::save(&account, value),
        )
    }
    pub fn load_or_create(
        installation_id: &str,
        origin: &str,
        load: impl FnOnce() -> Result<Option<Self>, String>,
        persist: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<Self, String> {
        let host = hostname(installation_id, origin)?;
        let _lock = IDENTITY_LOCK
            .lock()
            .map_err(|_| "credential_store_unavailable")?;
        if let Some(saved) = load()? {
            if saved.schema_version != 1
                || saved.installation_id != installation_id
                || saved.origin != origin
            {
                return Err("native_tls_identity_changed".into());
            }
            if saved.expires_at <= OffsetDateTime::now_utc().unix_timestamp() {
                return Err("native_tls_identity_expired".into());
            }
            if saved.certificate_pem.len() > 8192
                || saved.private_key_pem.len() > 8192
                || KeyPair::from_pem(&saved.private_key_pem).is_err()
                || crate::manager::certificate_fingerprint(&saved.certificate_pem).is_err()
            {
                return Err("native_tls_identity_invalid".into());
            }
            return Ok(saved);
        }
        let key = KeyPair::generate().map_err(|_| "native_tls_generation_failed")?;
        let mut params =
            CertificateParams::new(vec![host]).map_err(|_| "native_tls_generation_failed")?;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::minutes(5);
        params.not_after = now + Duration::days(365);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Frameleaf Manager");
        let certificate = params
            .self_signed(&key)
            .map_err(|_| "native_tls_generation_failed")?;
        let saved = Self {
            schema_version: 1,
            installation_id: installation_id.into(),
            origin: origin.into(),
            certificate_pem: certificate.pem(),
            private_key_pem: key.serialize_pem(),
            expires_at: params.not_after.unix_timestamp(),
        };
        persist(&saved)?;
        Ok(saved)
    }
    pub fn certificate(&self) -> &str {
        &self.certificate_pem
    }
    /// This wire record is for the private native bootstrap pipe only, never a Tauri response.
    pub fn wire(&self) -> BootstrapTls<'_> {
        BootstrapTls {
            certificate_pem: &self.certificate_pem,
            private_key_pem: &self.private_key_pem,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn moved_profile_keeps_its_paired_certificate_without_replacing_a_newer_one() {
        let (old, new) = ("a".repeat(64), "b".repeat(64));
        let identity = || {
            TlsIdentity::load_or_create(
                "aaaaaaaaaaaa",
                "https://127.0.0.1:9443",
                || Ok(None),
                |_| Ok(()),
            )
            .unwrap()
        };
        let saved = identity();
        let copied = std::cell::RefCell::new(None);
        TlsIdentity::carry_forward_with(
            &old,
            &new,
            |account| {
                Ok((account == account_for_profile(&old).unwrap()).then(|| {
                    serde_json::from_value(serde_json::to_value(&saved).unwrap()).unwrap()
                }))
            },
            |account, value| {
                assert_eq!(account, account_for_profile(&new).unwrap());
                *copied.borrow_mut() = Some(value.certificate_pem.clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            copied.borrow().as_deref(),
            Some(saved.certificate_pem.as_str())
        );
        let existing = identity();
        TlsIdentity::carry_forward_with(
            &old,
            &new,
            |_| {
                Ok(Some(
                    serde_json::from_value(serde_json::to_value(&existing).unwrap()).unwrap(),
                ))
            },
            |_, _| panic!("an existing certificate is never replaced"),
        )
        .unwrap();
        TlsIdentity::carry_forward_with(&old, &new, |_| Ok(None), |_, _| panic!("nothing to copy"))
            .unwrap();
    }
    #[test]
    fn tls_keystore_account_is_scoped_to_the_full_profile_binding() {
        let first = account_for_profile(&"a".repeat(64)).unwrap();
        let second = account_for_profile(&"b".repeat(64)).unwrap();
        assert_ne!(first, second);
        assert!(TlsIdentity::from_keystore(
            "aaaaaaaaaaaa",
            "https://127.0.0.1:9443",
            "invalid-binding"
        )
        .is_err());
    }
}
