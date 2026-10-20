//! Verifies backup/migration approval only; no execution, database or epoch authority.
use super::*;
use crate::{
    host_epochs::HostExecution, manager_host::Configuration, manager_profile::ProfileGuard,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
const DOMAIN: &[u8] = b"frameleaf-native-update-approval-v1\0";
const INVALID: &str = "host_update_approval_invalid";
const MAX_SAFE: u64 = 9_007_199_254_740_991;
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalCheckpoint {
    protocol_version: u32,
    state: String,
    schema_version: u32,
    operation_id: String,
    manifest_sha256: String,
    source_revision: String,
    postgres_major: String,
    database_format: String,
    dump: CheckpointDump,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::host_runtime) struct Payload {
    schema_version: u32,
    approval_id: String,
    installation_id: String,
    secure_installation_id: String,
    library_id: String,
    source_manifest_sha256: String,
    source_revision: String,
    target_manifest_sha256: String,
    manager_fingerprint: String,
    backup_operation_id: String,
    snapshot_id: String,
    recovery_sha256: String,
    checkpoint: ApprovalCheckpoint,
    controller_state_sha256: String,
    generation: String,
    migrations_approved: bool,
    issued_at: u64,
    expires_at: u64,
}
impl Payload {
    fn validate(&self, now: u64) -> Result<(), String> {
        let cp = &self.checkpoint;
        if self.schema_version != 1
            || !self.migrations_approved
            || !digest_valid(&self.installation_id, 12)
            || self.library_id != self.installation_id
            || [
                &self.approval_id,
                &self.secure_installation_id,
                &self.backup_operation_id,
                &self.generation,
            ]
            .iter()
            .any(|v| !checkpoint_operation_id(v))
            || [
                &self.source_manifest_sha256,
                &self.target_manifest_sha256,
                &self.manager_fingerprint,
                &self.snapshot_id,
                &self.recovery_sha256,
                &self.controller_state_sha256,
            ]
            .iter()
            .any(|v| !digest_valid(v, 64))
            || !digest_valid(&self.source_revision, 40)
            || self.source_manifest_sha256 == self.target_manifest_sha256
            || self.issued_at == 0
            || self.issued_at > now
            || self.expires_at > MAX_SAFE
            || self.expires_at <= now
            || self.expires_at.checked_sub(self.issued_at) != Some(300_000)
            || now > MAX_SAFE
            || cp.protocol_version != 1
            || cp.state != "checkpoint"
            || cp.operation_id != self.backup_operation_id
            || cp.manifest_sha256 != self.source_manifest_sha256
            || cp.source_revision != self.source_revision
        {
            return Err(INVALID.into());
        }
        CheckpointReceipt {
            schema_version: cp.schema_version,
            operation_id: cp.operation_id.clone(),
            manifest_sha256: cp.manifest_sha256.clone(),
            source_revision: cp.source_revision.clone(),
            postgres_major: cp.postgres_major.clone(),
            database_format: cp.database_format.clone(),
            dump: cp.dump.clone(),
        }
        .validate()
        .map_err(|_| INVALID.to_owned())
    }
}
fn split(sealed: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    if sealed.len() > 6144 {
        return Err(INVALID.into());
    }
    let (encoded, tag) = sealed.split_once('.').ok_or(INVALID)?;
    if !digest_valid(tag, 64) {
        return Err(INVALID.into());
    }
    let raw = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| INVALID)?;
    if raw.is_empty() || raw.len() > 4096 || URL_SAFE_NO_PAD.encode(&raw) != encoded {
        return Err(INVALID.into());
    }
    let tag = tag
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| INVALID)?, 16)
                .map_err(|_| INVALID)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((raw, tag))
}
fn parse(raw: &[u8], now: u64) -> Result<Payload, String> {
    let payload: Payload = serde_json::from_slice(raw).map_err(|_| INVALID)?;
    payload.validate(now)?;
    Ok(payload)
}
fn decode_verified(sealed: &str, key: &str, now: u64) -> Result<Payload, String> {
    if !crate::manager_profile::valid_backup_key(key) {
        return Err(INVALID.into());
    }
    let (raw, tag) = split(sealed)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| INVALID)?;
    mac.update(DOMAIN);
    mac.update(&raw);
    mac.verify_slice(&tag).map_err(|_| INVALID)?;
    parse(&raw, now)
}
/// Structural transport checking only. The updater must independently verify the MAC with its OS key.
pub(crate) fn inspect_request(
    sealed: &str,
    id: &str,
    approval_id: &str,
    backup_id: &str,
    target: &str,
    now: u64,
) -> Result<(), String> {
    let (raw, _) = split(sealed)?;
    let payload = parse(&raw, now)?;
    if payload.installation_id != id
        || payload.approval_id != approval_id
        || payload.backup_operation_id != backup_id
        || payload.target_manifest_sha256 != target
    {
        return Err(INVALID.into());
    }
    Ok(())
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostUpdateApproval {
    protocol_version: u32,
    state: &'static str,
    approval: Payload,
    database_identity: String,
}
impl VerifiedHostRuntime {
    /// Read-only fresh source validation; does not consume approval or authorize apply/recovery.
    pub fn verify_update_approval(
        &self,
        target: &Self,
        config: &Configuration,
        execution: &HostExecution<'_>,
        sealed: &str,
    ) -> Result<HostUpdateApproval, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| INVALID)?
            .as_millis()
            .try_into()
            .map_err(|_| INVALID)?;
        let verified = self.verify_update_approval_with(
            target,
            config,
            execution,
            sealed,
            now,
            &mut crate::manager_profile::Keystore,
        )?;
        let fresh = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| INVALID)?
            .as_millis()
            .try_into()
            .map_err(|_| INVALID)?;
        verified.approval.validate(fresh)?;
        Ok(verified)
    }
    pub(super) fn verify_update_approval_with(
        &self,
        target: &Self,
        config: &Configuration,
        execution: &HostExecution<'_>,
        sealed: &str,
        now: u64,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateApproval, String> {
        split(sealed)?;
        crate::manager_host::validate_configuration(config)?;
        if execution.installation_id() != config.secure_installation_id {
            return Err(INVALID.into());
        }
        self.check_update_target(target, &config.installation_id)?;
        let source = self.root.parent().ok_or(INVALID)?;
        let destination = target.root.parent().ok_or(INVALID)?;
        crate::host_control::separate_paths(source, destination)?;
        for candidate in [source, destination] {
            crate::manager_host::validate_paths(candidate, &config.state, &config.data)?;
        }
        let _state = crate::host_storage::directory(&config.state)?;
        let _data = crate::host_storage::directory(&config.data)?;
        let _source_lease = crate::package_lease::CodeLease::acquire(source)?;
        let _target_lease = crate::package_lease::CodeLease::acquire(destination)?;
        self.check_files()?;
        target.check_files()?;
        let guard = ProfileGuard::acquire(config)?;
        let mut owner =
            crate::host_state::Owner::acquire_update(&config.state, execution.installation_id())?;
        let mut verified = None;
        execution.with_admitted(self, &mut || {
            let (marker, database_identity) =
                owner.review_reserved_update(&config.installation_id, self.manifest_sha256())?;
            super::update::host_state(&config.state, self, &marker.profile_identity)?;
            let key = guard.approval_key(config, source, self.manifest_sha256(), store)?;
            let payload = decode_verified(sealed, &key, now)?;
            if payload.installation_id != config.installation_id
                || payload.secure_installation_id != config.secure_installation_id
                || payload.source_manifest_sha256 != self.manifest_sha256()
                || payload.source_revision != self.source_revision()
                || payload.target_manifest_sha256 != target.manifest_sha256()
                || payload.generation != marker.generation.to_string()
                || payload.controller_state_sha256 != owner.approval_journal_sha256()?
            {
                return Err(INVALID.into());
            }
            guard.require_current(config)?;
            target.check_files()?;
            verified = Some(HostUpdateApproval {
                protocol_version: 1,
                state: "verified",
                approval: payload,
                database_identity,
            });
            Ok(())
        })?;
        verified.ok_or_else(|| INVALID.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/native-update-approval.json"
        ))
        .unwrap()
    }
    #[test]
    fn node_sealed_approval_verifies_exact_bytes_and_refuses_changed_key_or_mac() {
        let f = fixture();
        let token = f["approval"].as_str().unwrap();
        let now = f["now"].as_u64().unwrap();
        let key = f["key"].as_str().unwrap();
        let proof = decode_verified(token, key, now).unwrap();
        assert_eq!(proof.approval_id, f["payload"]["approvalId"]);
        assert_eq!(proof.checkpoint.operation_id, proof.backup_operation_id);
        assert!(decode_verified(token, &"j".repeat(43), now).is_err());
        let mut changed = token.as_bytes().to_vec();
        let end = changed.len() - 1;
        changed[end] = if changed[end] == b'0' { b'1' } else { b'0' };
        assert!(decode_verified(std::str::from_utf8(&changed).unwrap(), key, now).is_err());
        assert!(decode_verified(token, key, f["payload"]["expiresAt"].as_u64().unwrap()).is_err());
        assert!(
            decode_verified(token, key, f["payload"]["issuedAt"].as_u64().unwrap() - 1).is_err()
        );
    }
    fn seal(raw: &[u8], key: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(DOMAIN);
        mac.update(raw);
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(raw),
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }
    #[test]
    fn valid_mac_never_permits_unknown_duplicate_or_inconsistent_approval_fields() {
        let f = fixture();
        let key = f["key"].as_str().unwrap();
        let now = f["now"].as_u64().unwrap();
        for (field, value) in [
            ("extra", serde_json::json!("must not echo")),
            ("schemaVersion", serde_json::json!(2)),
            ("migrationsApproved", serde_json::json!(false)),
            ("libraryId", serde_json::json!("bbbbbbbbbbbb")),
            (
                "approvalId",
                serde_json::json!("00000000-0000-0000-0000-000000000000"),
            ),
            (
                "generation",
                serde_json::json!("44444444-4444-4444-8444-44444444444A"),
            ),
            ("expiresAt", serde_json::json!(1700000300001u64)),
            ("issuedAt", serde_json::json!(1700000000000.5)),
            ("snapshotId", serde_json::json!("not-a-snapshot")),
        ] {
            let mut value_payload = f["payload"].clone();
            value_payload[field] = value;
            assert!(
                decode_verified(&seal(value_payload.to_string().as_bytes(), key), key, now)
                    .is_err(),
                "accepted {field}"
            );
        }
        for field in [
            "operationId",
            "manifestSha256",
            "sourceRevision",
            "protocolVersion",
            "dump",
        ] {
            let mut payload = f["payload"].clone();
            payload["checkpoint"][field] = serde_json::json!(null);
            assert!(decode_verified(&seal(payload.to_string().as_bytes(), key), key, now).is_err());
        }
        let raw = f["payload"].to_string().replace(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
        );
        assert!(decode_verified(&seal(raw.as_bytes(), key), key, now).is_err());
        let token = f["approval"].as_str().unwrap();
        let (encoded, tag) = token.split_once('.').unwrap();
        assert!(decode_verified(&format!("{encoded}=.{tag}"), key, now).is_err());
        assert!(decode_verified(&"a".repeat(6145), key, now).is_err());
    }
}

#[path = "update_consumption.rs"]
mod consumption;

#[path = "update_backup.rs"]
mod backup;

pub use consumption::{HostUpdateCandidate, HostUpdateInput};
