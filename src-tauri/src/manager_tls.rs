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
            saved.validate(installation_id, origin)?;
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
    fn validate(&self, installation_id: &str, origin: &str) -> Result<(), String> {
        hostname(installation_id, origin)?;
        if self.schema_version != 1
            || self.installation_id != installation_id
            || self.origin != origin
        {
            return Err("native_tls_identity_changed".into());
        }
        if self.expires_at <= OffsetDateTime::now_utc().unix_timestamp() {
            return Err("native_tls_identity_expired".into());
        }
        if self.certificate_pem.len() > 8192
            || self.private_key_pem.len() > 8192
            || KeyPair::from_pem(&self.private_key_pem).is_err()
            || crate::manager::certificate_fingerprint(&self.certificate_pem).is_err()
        {
            return Err("native_tls_identity_invalid".into());
        }
        Ok(())
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

pub(crate) struct TlsUpdate {
    _lock: std::sync::MutexGuard<'static, ()>,
    source: TlsIdentity,
    destination: String,
}
impl TlsUpdate {
    pub(crate) fn existing(
        id: &str,
        origin: &str,
        bindings: [&str; 2],
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<Self, String> {
        let lock = IDENTITY_LOCK
            .lock()
            .map_err(|_| "credential_store_unavailable")?;
        let source: TlsIdentity = store
            .load(&account_for_profile(bindings[0])?)?
            .ok_or("native_tls_recovery_required")?;
        source.validate(id, origin)?;
        Ok(Self {
            _lock: lock,
            source,
            destination: account_for_profile(bindings[1])?,
        })
    }
    pub(crate) fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        format!(
            "{:x}",
            Sha256::digest(self.source.certificate_pem.as_bytes())
        )
    }
    pub(crate) fn commitment(&self, profile: &[u8]) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        // Profile includes the random 256-bit backup key; this binds retries without persisting secrets.
        let mut hash = Sha256::new();
        hash.update(b"frameleaf-update-credentials-v1\0");
        hash.update((profile.len() as u64).to_be_bytes());
        hash.update(profile);
        let tls = zeroize::Zeroizing::new(
            serde_json_canonicalizer::to_vec(&self.source)
                .map_err(|_| "native_tls_identity_invalid")?,
        );
        hash.update(tls.as_slice());
        Ok(format!("{:x}", hash.finalize()))
    }
    pub(crate) fn copy(
        &self,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<(), String> {
        let expected = zeroize::Zeroizing::new(
            serde_json::to_vec(&self.source).map_err(|_| "native_tls_identity_invalid")?,
        );
        let current: Option<TlsIdentity> = store.load(&self.destination)?;
        if let Some(current) = current {
            if zeroize::Zeroizing::new(
                serde_json::to_vec(&current).map_err(|_| "native_tls_identity_invalid")?,
            )
            .as_slice()
                != expected.as_slice()
            {
                return Err("native_tls_identity_changed".into());
            }
        } else {
            store.save(&self.destination, &self.source)?;
        }
        let readback: TlsIdentity = store
            .load(&self.destination)?
            .ok_or("native_tls_recovery_required")?;
        readback.validate(&self.source.installation_id, &self.source.origin)?;
        if zeroize::Zeroizing::new(
            serde_json::to_vec(&readback).map_err(|_| "native_tls_identity_invalid")?,
        )
        .as_slice()
            != expected.as_slice()
        {
            return Err("native_tls_identity_changed".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
