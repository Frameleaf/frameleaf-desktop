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
/// The first released Manager stores the certificate's hash in its installation descriptor and
/// refuses to start when it changes, so the identity is renewed only for a Manager that
/// declares it accepts a handed-over certificate. For any other, the person is told this many
/// days ahead that it runs out. The same period is when a renewal is made.
const EXPIRY_NOTICE_DAYS: i64 = 30;
const DAY: i64 = 24 * 60 * 60;
/// A renewed identity that Manager has not been seen to accept yet. It is saved before Manager
/// is first shown it and stays until a start with it, or with the identity it replaces, has
/// succeeded: Manager may already have accepted it when this app last stopped.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    schema_version: u32,
    operation_id: uuid::Uuid,
    identity: TlsIdentity,
    /// Renewed identities that ran out while they were still pending. Manager may have
    /// accepted any of them, so their keys are kept to hand over from, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    earlier: Vec<TlsIdentity>,
}
/// The bootstrap's `tlsRotation`: the key of the certificate Manager holds signs the hash of
/// the certificate that replaces it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Handover {
    operation_id: uuid::Uuid,
    previous_certificate_pem: String,
    signature: String,
}
/// The identity one start presents.
pub(crate) struct StartIdentity {
    pub identity: TlsIdentity,
    /// Sent while Manager may still hold the certificate this identity replaces.
    pub handover: Option<Handover>,
    /// A renewed identity is waiting and this start does not present it.
    pub set_aside: bool,
    /// How many identities Manager may hold that the presented one can be handed over from.
    /// Which one Manager holds is not known, so a start that fails is tried with the next.
    pub signers: usize,
    /// Every certificate this library's Manager may be serving, the presented one first.
    pub certificates: Vec<String>,
}
/// Where identities are kept; the OS keystore outside tests.
pub(crate) trait Vault {
    fn load<T: serde::de::DeserializeOwned>(&self, account: &str) -> Result<Option<T>, String>;
    fn save<T: Serialize>(&self, account: &str, value: &T) -> Result<(), String>;
    fn delete(&self, account: &str) -> Result<(), String>;
}
pub(crate) struct Keystore;
impl Vault for Keystore {
    fn load<T: serde::de::DeserializeOwned>(&self, account: &str) -> Result<Option<T>, String> {
        crate::credentials::load(account)
    }
    fn save<T: Serialize>(&self, account: &str, value: &T) -> Result<(), String> {
        crate::credentials::save(account, value)
    }
    fn delete(&self, account: &str) -> Result<(), String> {
        crate::credentials::delete(account)
    }
}
fn pending_account(binding: &str) -> Result<String, String> {
    if !crate::native_runtime::digest_valid(binding, 64) {
        return Err("native_tls_binding_invalid".into());
    }
    Ok(format!("native-manager-tls-next-{binding}"))
}
/// The exact text Manager verifies: the hashes are of the PEM text the bootstrap carries.
fn handover_message(
    installation_id: &str,
    operation_id: &uuid::Uuid,
    previous: &str,
    next: &str,
) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let hash = |pem: &str| format!("{:x}", Sha256::digest(pem.as_bytes()));
    serde_json::to_string(&(
        "frameleaf-manager/tls-rotation/v1",
        installation_id,
        operation_id.to_string(),
        hash(previous),
        hash(next),
    ))
    .map_err(|_| "native_tls_generation_failed".into())
}
/// Whole days left (rounded up, so the last day reads 1) once expiry is within the notice
/// period. None while it is further away, and once it has passed: an expired identity already
/// refuses the start with its own error.
pub(crate) fn expiry_notice_days(expires_at: i64, now: i64) -> Option<u32> {
    let left = expires_at.checked_sub(now)?;
    if left <= 0 || left > EXPIRY_NOTICE_DAYS * DAY {
        return None;
    }
    u32::try_from((left + DAY - 1) / DAY).ok()
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
        )?;
        // A renewal Manager may already have accepted moves with the profile.
        let (from, to) = (pending_account(previous)?, pending_account(next)?);
        let _lock = IDENTITY_LOCK
            .lock()
            .map_err(|_| "credential_store_unavailable")?;
        if crate::credentials::load::<Pending>(&to)?.is_some() {
            return Ok(());
        }
        match crate::credentials::load::<Pending>(&from)? {
            Some(pending) => crate::credentials::save(&to, &pending),
            None => Ok(()),
        }
    }
    /// `carry_forward` with injectable keystore access for tests.
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
            if saved.origin != origin {
                return Err("native_tls_identity_changed".into());
            }
            saved.usable(installation_id)?;
            if saved.expires_at <= OffsetDateTime::now_utc().unix_timestamp() {
                return Err("native_tls_identity_expired".into());
            }
            return Ok(saved);
        }
        let saved = Self::mint(
            installation_id,
            origin,
            host,
            OffsetDateTime::now_utc().unix_timestamp(),
        )?;
        persist(&saved)?;
        Ok(saved)
    }
    /// A saved identity that is whole and is this installation's. Its expiry is the caller's.
    fn usable(&self, installation_id: &str) -> Result<(), String> {
        if self.schema_version != 1 || self.installation_id != installation_id {
            return Err("native_tls_identity_changed".into());
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
    /// The identity for this start, renewing it when `renew` says Manager accepts a handover.
    ///
    /// Without `renew` this is the saved identity, exactly as before. With it, an identity in
    /// its last thirty days (or already expired) is replaced: the new one is saved as pending
    /// before anything else, then presented together with a handover signed by the old key.
    /// A pending identity found from an earlier start is presented again with the same
    /// handover, because Manager may or may not have accepted it.
    pub(crate) fn for_start(
        installation_id: &str,
        origin: &str,
        binding: &str,
        renew: bool,
        signer: usize,
    ) -> Result<StartIdentity, String> {
        Self::for_start_in(
            &Keystore,
            installation_id,
            origin,
            binding,
            renew,
            signer,
            OffsetDateTime::now_utc().unix_timestamp(),
        )
    }
    fn for_start_in(
        vault: &impl Vault,
        installation_id: &str,
        origin: &str,
        binding: &str,
        renew: bool,
        signer: usize,
        now: i64,
    ) -> Result<StartIdentity, String> {
        let host = hostname(installation_id, origin)?;
        let (account, next) = (account_for_profile(binding)?, pending_account(binding)?);
        let _lock = IDENTITY_LOCK
            .lock()
            .map_err(|_| "credential_store_unavailable")?;
        let mut current: Option<Self> = vault.load(&account)?;
        if let Some(saved) = current.as_mut() {
            saved.usable(installation_id)?;
            if saved.origin != origin {
                // Manager's port is configuration: the certificate names the host only.
                if hostname(installation_id, &saved.origin)? != host {
                    return Err("native_tls_identity_changed".into());
                }
                saved.origin = origin.into();
                vault.save(&account, saved)?;
            }
        }
        let expired = |identity: &Self| identity.expires_at <= now;
        let mut pending: Option<Pending> = vault.load(&next)?;
        if let Some(pending) = &pending {
            if pending.schema_version != 1 || pending.operation_id.is_nil() {
                return Err("native_tls_identity_invalid".into());
            }
            for identity in std::iter::once(&pending.identity).chain(&pending.earlier) {
                identity.usable(installation_id)?;
            }
        }
        if !renew {
            // Not renewing: the identity Manager is known to have accepted, if it can still
            // be used. A waiting one is kept until this start has succeeded.
            return match (current, pending) {
                (Some(current), _) if expired(&current) => {
                    Err("native_tls_identity_expired".into())
                }
                (Some(current), pending) => Ok(StartIdentity {
                    certificates: std::iter::once(&current)
                        .chain(pending.iter().flat_map(|pending| {
                            std::iter::once(&pending.identity).chain(&pending.earlier)
                        }))
                        .map(|identity| identity.certificate_pem.clone())
                        .collect(),
                    handover: None,
                    set_aside: pending.is_some(),
                    signers: 0,
                    identity: current,
                }),
                (None, Some(_)) => Err("native_tls_identity_invalid".into()),
                (None, None) => {
                    let identity = Self::mint(installation_id, origin, host, now)?;
                    vault.save(&account, &identity)?;
                    Ok(StartIdentity {
                        certificates: vec![identity.certificate_pem.clone()],
                        handover: None,
                        set_aside: false,
                        signers: 0,
                        identity,
                    })
                }
            };
        }
        let due = |identity: &Self| {
            identity
                .expires_at
                .checked_sub(now)
                .is_none_or(|left| left <= EXPIRY_NOTICE_DAYS * DAY)
        };
        // A renewal is made when the saved identity is due, and made again when the one that
        // was waiting has itself run out. Nothing is discarded: Manager may hold the saved
        // identity or any renewal it was ever shown, so each of their keys stays available.
        let renewal = match pending.take() {
            Some(waiting) if !expired(&waiting.identity) => Some(waiting),
            waiting if waiting.is_some() || current.as_ref().is_some_and(due) => {
                let mut earlier = Vec::new();
                if let Some(Pending {
                    identity,
                    earlier: older,
                    ..
                }) = waiting
                {
                    earlier = older;
                    earlier.push(identity);
                }
                let renewal = Pending {
                    schema_version: 1,
                    operation_id: uuid::Uuid::new_v4(),
                    identity: Self::mint(installation_id, origin, host.clone(), now)?,
                    earlier,
                };
                // Durable before Manager is shown it: the key must outlive a crash.
                vault.save(&next, &renewal)?;
                Some(renewal)
            }
            _ => None,
        };
        let Some(renewal) = renewal else {
            return match current {
                Some(current) => Ok(StartIdentity {
                    certificates: vec![current.certificate_pem.clone()],
                    handover: None,
                    set_aside: false,
                    signers: 0,
                    identity: current,
                }),
                None => {
                    let identity = Self::mint(installation_id, origin, host, now)?;
                    vault.save(&account, &identity)?;
                    Ok(StartIdentity {
                        certificates: vec![identity.certificate_pem.clone()],
                        handover: None,
                        set_aside: false,
                        signers: 0,
                        identity,
                    })
                }
            };
        };
        // Whoever Manager holds signs: the saved identity first, then the newest earlier one.
        let signers: Vec<&Self> = current.iter().chain(renewal.earlier.iter().rev()).collect();
        let handover = match signers.get(signer) {
            Some(holder) => Some(holder.hand_over(&renewal.identity, renewal.operation_id)?),
            None if signers.is_empty() => None,
            None => return Err("native_tls_identity_invalid".into()),
        };
        let certificates = std::iter::once(&renewal.identity)
            .chain(signers.iter().copied())
            .map(|identity| identity.certificate_pem.clone())
            .collect();
        let signers = signers.len();
        let Pending { identity, .. } = renewal;
        Ok(StartIdentity {
            identity,
            handover,
            set_aside: false,
            signers,
            certificates,
        })
    }
    /// Sign the handover from this identity to `next` with this identity's key.
    fn hand_over(&self, next: &Self, operation_id: uuid::Uuid) -> Result<Handover, String> {
        use base64::Engine as _;
        use rcgen::SigningKey as _;
        let message = handover_message(
            &self.installation_id,
            &operation_id,
            &self.certificate_pem,
            &next.certificate_pem,
        )?;
        let signature = KeyPair::from_pem(&self.private_key_pem)
            .and_then(|key| key.sign(message.as_bytes()))
            .map_err(|_| "native_tls_generation_failed")?;
        Ok(Handover {
            operation_id,
            previous_certificate_pem: self.certificate_pem.clone(),
            signature: base64::engine::general_purpose::STANDARD.encode(signature),
        })
    }
    /// Manager was seen ready with the renewed identity: it is the identity from now on.
    pub(crate) fn promote(binding: &str) -> Result<(), String> {
        Self::promote_in(&Keystore, binding)
    }
    fn promote_in(vault: &impl Vault, binding: &str) -> Result<(), String> {
        let (account, next) = (account_for_profile(binding)?, pending_account(binding)?);
        let _lock = IDENTITY_LOCK
            .lock()
            .map_err(|_| "credential_store_unavailable")?;
        let Some(pending) = vault.load::<Pending>(&next)? else {
            return Ok(());
        };
        vault.save(&account, &pending.identity)?;
        vault.delete(&next)
    }
    /// Manager was seen ready with the identity a renewal would have replaced, so whatever it
    /// held before, that identity is what it holds now: the waiting one is dropped.
    pub(crate) fn discard_pending(binding: &str) -> Result<(), String> {
        Self::discard_pending_in(&Keystore, binding)
    }
    fn discard_pending_in(vault: &impl Vault, binding: &str) -> Result<(), String> {
        let next = pending_account(binding)?;
        let _lock = IDENTITY_LOCK
            .lock()
            .map_err(|_| "credential_store_unavailable")?;
        vault.delete(&next)
    }
    fn mint(installation_id: &str, origin: &str, host: String, now: i64) -> Result<Self, String> {
        let key = KeyPair::generate().map_err(|_| "native_tls_generation_failed")?;
        let mut params =
            CertificateParams::new(vec![host]).map_err(|_| "native_tls_generation_failed")?;
        let now =
            OffsetDateTime::from_unix_timestamp(now).map_err(|_| "native_tls_generation_failed")?;
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
        Ok(Self {
            schema_version: 1,
            installation_id: installation_id.into(),
            origin: origin.into(),
            certificate_pem: certificate.pem(),
            private_key_pem: key.serialize_pem(),
            expires_at: params.not_after.unix_timestamp(),
        })
    }
    /// An identity as a start at `now` would have made it, for the opt-in end-to-end run to
    /// stand in for time passing: identities last a year and nothing else can age one.
    #[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
    pub(crate) fn issued_at(installation_id: &str, origin: &str, now: i64) -> Result<Self, String> {
        Self::mint(
            installation_id,
            origin,
            hostname(installation_id, origin)?,
            now,
        )
    }
    #[cfg(test)]
    pub(crate) fn private_key(&self) -> &str {
        &self.private_key_pem
    }
    pub fn certificate(&self) -> &str {
        &self.certificate_pem
    }
    /// When this identity stops being accepted, in seconds since the Unix epoch.
    pub(crate) fn expires_at(&self) -> i64 {
        self.expires_at
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
    fn expiry_is_announced_only_in_its_last_thirty_days_and_never_after() {
        const DAY: i64 = 24 * 60 * 60;
        let expires = 1_800_000_000;
        // A new identity lasts a year: nothing to say.
        let identity = TlsIdentity::load_or_create(
            "aaaaaaaaaaaa",
            "https://127.0.0.1:9443",
            || Ok(None),
            |_| Ok(()),
        )
        .unwrap();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert_eq!(expiry_notice_days(identity.expires_at(), now), None);
        assert_eq!(
            expiry_notice_days(identity.expires_at(), now + 340 * DAY),
            Some(25)
        );
        for (before, days) in [
            (31 * DAY, None),
            (30 * DAY + 1, None),
            (30 * DAY, Some(30)),
            (29 * DAY + 1, Some(30)),
            (DAY + 1, Some(2)),
            (DAY, Some(1)),
            (1, Some(1)),
            // Expired: the start itself refuses, so there is no countdown to show.
            (0, None),
            (-DAY, None),
        ] {
            assert_eq!(expiry_notice_days(expires, expires - before), days);
        }
        // A clock or record that makes no sense announces nothing rather than a wrong number.
        assert_eq!(expiry_notice_days(i64::MAX, i64::MIN), None);
        assert_eq!(expiry_notice_days(i64::MIN, i64::MAX), None);
    }
    /// An in-memory keystore that records every write, in order.
    #[derive(Default)]
    struct Memory {
        values: std::cell::RefCell<std::collections::BTreeMap<String, String>>,
        writes: std::cell::RefCell<Vec<String>>,
        refuse_saves: std::cell::Cell<bool>,
    }
    impl Vault for Memory {
        fn load<T: serde::de::DeserializeOwned>(&self, account: &str) -> Result<Option<T>, String> {
            Ok(self
                .values
                .borrow()
                .get(account)
                .map(|value| serde_json::from_str(value).unwrap()))
        }
        fn save<T: Serialize>(&self, account: &str, value: &T) -> Result<(), String> {
            if self.refuse_saves.get() {
                return Err("credential_store_unavailable".into());
            }
            self.writes.borrow_mut().push(format!("save {account}"));
            self.values
                .borrow_mut()
                .insert(account.into(), serde_json::to_string(value).unwrap());
            Ok(())
        }
        fn delete(&self, account: &str) -> Result<(), String> {
            self.writes.borrow_mut().push(format!("delete {account}"));
            self.values.borrow_mut().remove(account);
            Ok(())
        }
    }
    const ID: &str = "aaaaaaaaaaaa";
    const ORIGIN: &str = "https://127.0.0.1:9443";
    fn binding() -> String {
        "a".repeat(64)
    }
    fn start(vault: &Memory, renew: bool, now: i64) -> Result<StartIdentity, String> {
        TlsIdentity::for_start_in(vault, ID, ORIGIN, &binding(), renew, 0, now)
    }
    fn start_signed_by(vault: &Memory, signer: usize, now: i64) -> Result<StartIdentity, String> {
        TlsIdentity::for_start_in(vault, ID, ORIGIN, &binding(), true, signer, now)
    }
    /// Verify a handover exactly as Manager does: the replaced certificate's key over the text.
    fn handed_over(handover: &Handover, previous: &TlsIdentity, next: &TlsIdentity) -> bool {
        use base64::Engine as _;
        use rcgen::PublicKeyData as _;
        let message = handover_message(
            ID,
            &handover.operation_id,
            &previous.certificate_pem,
            &next.certificate_pem,
        )
        .unwrap();
        let key = KeyPair::from_pem(&previous.private_key_pem).unwrap();
        handover.previous_certificate_pem == previous.certificate_pem
            && ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_ASN1,
                key.der_bytes(),
            )
            .verify(
                message.as_bytes(),
                &base64::engine::general_purpose::STANDARD
                    .decode(&handover.signature)
                    .unwrap(),
            )
            .is_ok()
    }
    #[test]
    fn the_handover_text_is_the_one_manager_verifies() {
        // The same vector is asserted in the server repository's native-installation test.
        assert_eq!(
            handover_message(
                ID,
                &uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
                "previous certificate",
                "next certificate",
            )
            .unwrap(),
            r#"["frameleaf-manager/tls-rotation/v1","aaaaaaaaaaaa","11111111-1111-4111-8111-111111111111","2bc7e50b728123932b06aab01b3da0ca6252a1d098a6acddb0cb49d7259736b1","dd63fac2b87aa649854359fe02d928d097ca45fcb5d85aaa472d064cb67ad69b"]"#
        );
    }
    /// Interoperability with the real verifier: writes two throwaway identities and the
    /// handover between them, for the server repository's Manager to admit.
    #[test]
    #[ignore = "set FRAMELEAF_HANDOVER_OUT to a file, then admit it with the server repository's Manager"]
    fn writes_a_handover_for_managers_own_verifier() {
        let out = std::env::var_os("FRAMELEAF_HANDOVER_OUT").expect("an output file");
        let vault = Memory::default();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first = start(&vault, true, now).unwrap();
        let renewed = start(&vault, true, now + 350 * DAY).unwrap();
        let wire = |identity: &TlsIdentity| serde_json::to_value(identity.wire()).unwrap();
        std::fs::write(
            out,
            serde_json::to_vec(&serde_json::json!({
                "installationId": ID,
                "previous": wire(&first.identity),
                "next": wire(&renewed.identity),
                "tlsRotation": renewed.handover,
            }))
            .unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn an_identity_is_never_renewed_for_a_manager_that_does_not_accept_a_handover() {
        let vault = Memory::default();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first = start(&vault, false, now).unwrap();
        assert!(first.handover.is_none() && !first.set_aside);
        assert_eq!(
            first.certificates,
            std::slice::from_ref(&first.identity.certificate_pem)
        );
        assert_eq!(
            *vault.writes.borrow(),
            [format!("save native-manager-tls-{}", binding())]
        );
        // In its last days, and after it has run out, the saved identity is all there is.
        for later in [340 * DAY, 364 * DAY] {
            let again = start(&vault, false, now + later).unwrap();
            assert_eq!(
                again.identity.certificate_pem,
                first.identity.certificate_pem
            );
            assert!(again.handover.is_none());
        }
        assert_eq!(
            start(&vault, false, now + 366 * DAY).err().unwrap(),
            "native_tls_identity_expired"
        );
        assert_eq!(vault.writes.borrow().len(), 1, "nothing was written again");
    }
    #[test]
    fn a_renewal_is_saved_before_it_is_presented_and_handed_over_by_the_old_key() {
        let vault = Memory::default();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first = start(&vault, true, now).unwrap();
        // A year left: nothing to renew, with or without the capability.
        assert!(start(&vault, true, now + 334 * DAY)
            .unwrap()
            .handover
            .is_none());
        assert_eq!(vault.writes.borrow().len(), 1);
        // Thirty days left: a new identity, saved as pending before anything is returned.
        let renewed = start(&vault, true, now + 336 * DAY).unwrap();
        let handover = renewed.handover.clone().expect("a handover is sent");
        assert_ne!(
            renewed.identity.certificate_pem,
            first.identity.certificate_pem
        );
        assert!(handed_over(&handover, &first.identity, &renewed.identity));
        assert!(!handover.operation_id.is_nil());
        assert_eq!(
            renewed.certificates,
            [
                renewed.identity.certificate_pem.clone(),
                first.identity.certificate_pem.clone()
            ],
            "both certificates may be what Manager serves until this start has settled"
        );
        assert_eq!(
            vault.writes.borrow().last().unwrap(),
            &format!("save native-manager-tls-next-{}", binding())
        );
        // The saved identity is untouched until Manager has been seen with the new one.
        let saved: TlsIdentity = vault
            .load(&format!("native-manager-tls-{}", binding()))
            .unwrap()
            .unwrap();
        assert_eq!(saved.certificate_pem, first.identity.certificate_pem);
        // A later start (a crash, a failed start) presents the same renewal with the same
        // handover operation, whether or not Manager accepted it the first time.
        let again = start(&vault, true, now + 337 * DAY).unwrap();
        assert_eq!(
            again.identity.certificate_pem,
            renewed.identity.certificate_pem
        );
        assert_eq!(
            again.handover.as_ref().unwrap().operation_id,
            handover.operation_id
        );
        assert!(handed_over(
            again.handover.as_ref().unwrap(),
            &first.identity,
            &again.identity
        ));
        // Once Manager is seen ready with it, it is the identity and nothing is pending.
        TlsIdentity::promote_in(&vault, &binding()).unwrap();
        // (It was minted on the real clock, so it has a year from the real now.)
        let settled = start(&vault, true, now).unwrap();
        assert_eq!(
            settled.identity.certificate_pem,
            renewed.identity.certificate_pem
        );
        assert!(settled.handover.is_none() && !settled.set_aside);
        assert_eq!(settled.certificates.len(), 1);
        assert!(vault
            .load::<Pending>(&format!("native-manager-tls-next-{}", binding()))
            .unwrap()
            .is_none());
        // Promoting with nothing pending changes nothing.
        let writes = vault.writes.borrow().len();
        TlsIdentity::promote_in(&vault, &binding()).unwrap();
        assert_eq!(vault.writes.borrow().len(), writes);
    }
    #[test]
    fn a_renewal_that_cannot_be_saved_is_not_presented_and_an_expired_identity_can_be_renewed() {
        let vault = Memory::default();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first = start(&vault, true, now).unwrap();
        vault.refuse_saves.set(true);
        assert_eq!(
            start(&vault, true, now + 350 * DAY).err().unwrap(),
            "credential_store_unavailable",
            "a key that would not survive a crash is never shown to Manager"
        );
        vault.refuse_saves.set(false);
        // Past its expiry the old key can still hand over: the library is not left unstartable.
        let renewed = start(&vault, true, now + 400 * DAY).unwrap();
        assert!(handed_over(
            renewed.handover.as_ref().unwrap(),
            &first.identity,
            &renewed.identity
        ));
    }
    #[test]
    fn a_rolled_back_start_presents_the_old_identity_and_keeps_the_new_one_until_it_succeeds() {
        let vault = Memory::default();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first = start(&vault, true, now).unwrap();
        let renewed = start(&vault, true, now + 340 * DAY).unwrap();
        // The retry after a failed renewal: the identity it would have replaced, no handover.
        let fallback = start(&vault, false, now + 340 * DAY).unwrap();
        assert_eq!(
            fallback.identity.certificate_pem,
            first.identity.certificate_pem
        );
        assert!(fallback.handover.is_none() && fallback.set_aside);
        assert_eq!(
            fallback.certificates,
            [
                first.identity.certificate_pem.clone(),
                renewed.identity.certificate_pem.clone()
            ]
        );
        // Nothing is dropped by asking: Manager may already hold the new certificate.
        assert_eq!(
            start(&vault, true, now + 340 * DAY)
                .unwrap()
                .identity
                .certificate_pem,
            renewed.identity.certificate_pem
        );
        // Only a start that succeeded with the old identity drops the waiting one.
        TlsIdentity::discard_pending_in(&vault, &binding()).unwrap();
        let after = start(&vault, false, now + 340 * DAY).unwrap();
        assert!(!after.set_aside && after.certificates.len() == 1);
        // Once the old identity has run out it cannot be the fallback.
        start(&vault, true, now + 340 * DAY).unwrap();
        assert_eq!(
            start(&vault, false, now + 366 * DAY).err().unwrap(),
            "native_tls_identity_expired"
        );
    }
    /// Every state of the saved identity (C) and a waiting renewal (P) against what Manager
    /// may hold. Manager holding X starts with X, or with anything handed over by X's key.
    #[test]
    fn every_identity_state_leaves_a_start_manager_accepts_whichever_identity_it_holds() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        // What a Manager holding `held` does with each attempt of one start; true if any works.
        let startable = |vault: &Memory, held: &TlsIdentity, at: i64| -> bool {
            let first = start_signed_by(vault, 0, at).unwrap();
            (0..first.signers.max(1)).any(|signer| {
                let attempt = start_signed_by(vault, signer, at).unwrap();
                attempt.identity.expires_at > at
                    && (attempt.identity.certificate_pem == held.certificate_pem
                        || attempt
                            .handover
                            .as_ref()
                            .is_some_and(|handover| handed_over(handover, held, &attempt.identity)))
            })
        };
        let saved = |vault: &Memory| -> TlsIdentity {
            vault
                .load(&format!("native-manager-tls-{}", binding()))
                .unwrap()
                .unwrap()
        };
        let waiting = |vault: &Memory| -> Option<Pending> {
            vault
                .load(&format!("native-manager-tls-next-{}", binding()))
                .unwrap()
        };
        // C valid or expired, no P: Manager can only hold C.
        for at in [now + 10 * DAY, now + 340 * DAY, now + 400 * DAY] {
            let vault = Memory::default();
            start(&vault, true, now).unwrap();
            let c = saved(&vault);
            assert!(startable(&vault, &c, at), "C only, at {at}");
        }
        // P waiting: (when P was made, when the start happens). C runs out at 365 days and a
        // P made at day 340 at day 705, so these cover C valid or expired with P valid or
        // expired; in each, Manager may hold C (it never saw P) or P (it accepted it).
        for (made, at) in [
            (340, 341), // C valid, P valid
            (340, 400), // C expired, P valid
            (340, 720), // C expired, P expired
            (336, 720), // the same, a little earlier
        ] {
            for holds_pending in [false, true] {
                let vault = Memory::default();
                start(&vault, true, now).unwrap();
                let c = saved(&vault);
                let p = start(&vault, true, now + made * DAY).unwrap().identity;
                let held = if holds_pending { &p } else { &c };
                assert!(
                    startable(&vault, held, now + at * DAY),
                    "made {made}, start {at}, Manager holds the pending one: {holds_pending}"
                );
                // Nothing Manager might hold was discarded by asking.
                let kept = waiting(&vault).unwrap();
                let keys: Vec<String> = std::iter::once(&kept.identity)
                    .chain(&kept.earlier)
                    .map(|identity| identity.certificate_pem.clone())
                    .chain([saved(&vault).certificate_pem.clone()])
                    .collect();
                assert!(keys.contains(&c.certificate_pem) && keys.contains(&p.certificate_pem));
            }
        }
        // C valid with an expired P cannot arise from the clock alone (P always outlives C),
        // but a saved record can say so: the same recovery applies.
        for holds_pending in [false, true] {
            let vault = Memory::default();
            start(&vault, true, now).unwrap();
            let c = saved(&vault);
            let p = TlsIdentity::mint(ID, ORIGIN, "127.0.0.1".into(), now - 400 * DAY).unwrap();
            vault
                .save(
                    &format!("native-manager-tls-next-{}", binding()),
                    &Pending {
                        schema_version: 1,
                        operation_id: uuid::Uuid::new_v4(),
                        identity: serde_json::from_value(serde_json::to_value(&p).unwrap())
                            .unwrap(),
                        earlier: Vec::new(),
                    },
                )
                .unwrap();
            let held = if holds_pending { &p } else { &c };
            assert!(startable(&vault, held, now + DAY), "C valid, P expired");
            // And the start that does not renew still presents C.
            assert_eq!(
                start(&vault, false, now + DAY)
                    .unwrap()
                    .identity
                    .certificate_pem,
                c.certificate_pem
            );
        }
    }
    #[test]
    fn a_renewal_that_ran_out_while_waiting_is_replaced_without_losing_its_key() {
        let vault = Memory::default();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let c = start(&vault, true, now).unwrap().identity;
        let p = start(&vault, true, now + 340 * DAY).unwrap().identity;
        // Two years offline: both have run out. The start is not refused.
        let recovered = start_signed_by(&vault, 0, now + 720 * DAY).unwrap();
        assert_eq!(recovered.signers, 2);
        assert!(recovered.identity.expires_at > now + 720 * DAY);
        assert!(handed_over(
            recovered.handover.as_ref().unwrap(),
            &c,
            &recovered.identity
        ));
        // The second attempt of the same start hands over from the renewal that ran out.
        let second = start_signed_by(&vault, 1, now + 720 * DAY).unwrap();
        assert_eq!(
            second.identity.certificate_pem,
            recovered.identity.certificate_pem
        );
        assert!(handed_over(
            second.handover.as_ref().unwrap(),
            &p,
            &second.identity
        ));
        assert_eq!(
            second.certificates,
            [
                second.identity.certificate_pem.clone(),
                c.certificate_pem.clone(),
                p.certificate_pem.clone()
            ]
        );
        assert!(start_signed_by(&vault, 2, now + 720 * DAY).is_err());
        // Once Manager is seen with the new identity, it is the identity and the rest goes.
        TlsIdentity::promote_in(&vault, &binding()).unwrap();
        let settled = start(&vault, true, now + 721 * DAY).unwrap();
        assert_eq!(
            settled.identity.certificate_pem,
            recovered.identity.certificate_pem
        );
        assert!(settled.handover.is_none() && settled.signers == 0);
        // An older Manager is still never renewed, and says the identity has expired.
        let vault = Memory::default();
        start(&vault, false, now).unwrap();
        assert_eq!(
            start(&vault, false, now + 720 * DAY).err().unwrap(),
            "native_tls_identity_expired"
        );
    }
    #[test]
    fn a_saved_identity_follows_managers_port_and_nothing_else() {
        let vault = Memory::default();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let first = start(&vault, false, now).unwrap();
        let moved = TlsIdentity::for_start_in(
            &vault,
            ID,
            "https://127.0.0.1:9444",
            &binding(),
            false,
            0,
            now,
        )
        .unwrap();
        assert_eq!(
            moved.identity.certificate_pem,
            first.identity.certificate_pem
        );
        assert_eq!(moved.identity.origin, "https://127.0.0.1:9444");
        for (id, origin) in [
            (ID, "https://[::1]:9444"),
            ("bbbbbbbbbbbb", "https://127.0.0.1:9444"),
        ] {
            assert_eq!(
                TlsIdentity::for_start_in(&vault, id, origin, &binding(), false, 0, now)
                    .err()
                    .unwrap(),
                "native_tls_identity_changed"
            );
        }
        for origin in ["http://127.0.0.1:9444", "https://127.0.0.1:9444/"] {
            assert!(
                TlsIdentity::for_start_in(&vault, ID, origin, &binding(), true, 0, now).is_err()
            );
        }
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
