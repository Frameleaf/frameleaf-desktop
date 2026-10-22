//! Source-only credentials and installation proofs; these do not authorize a local original read.
use crate::connection::{normalize_server, DeviceIdentity, SavedConnection};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const MAX_SEQUENCE: u32 = 2_147_483_647;
const MAX_TIMESTAMP: u64 = 9_007_199_254_740_991;
fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
fn uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}
fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "source_clock_invalid")?
        .as_millis()
        .try_into()
        .map_err(|_| "source_clock_invalid".into())
}
fn expires_at(value: &str) -> Option<u64> {
    if value.len() > 64 {
        return None;
    }
    let date =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()?;
    (date.unix_timestamp_nanos() / 1_000_000).try_into().ok()
}
fn connection_valid(saved: &SavedConnection) -> bool {
    normalize_server(&saved.server).is_ok()
        && !saved.server_id.is_empty()
        && saved.server_id.encode_utf16().count() <= 128
        && !saved.server_id.chars().any(char::is_control)
        && uuid(&saved.account_id)
        && saved.device_id.as_deref().is_some_and(uuid)
        && matches!(saved.mode.as_str(), "local-server" | "client-worker")
        && !saved.token.is_empty()
        && saved.token.len() <= 8192
        && !saved.token.chars().any(char::is_control)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantRequest {
    source_id: String,
    device_id: String,
    scope_fingerprint: String,
    request_id: String,
    timestamp: u64,
    signature: String,
}
fn grant_message(saved: &SavedConnection, request: &GrantRequest) -> String {
    [
        "frameleaf-source/grant/v1",
        &saved.server_id,
        &saved.account_id,
        &request.source_id,
        &request.device_id,
        &request.scope_fingerprint,
        &request.request_id,
        &request.timestamp.to_string(),
    ]
    .join("\n")
}
fn request_at(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    source_id: &str,
    scope: &str,
    request_id: &str,
    timestamp: u64,
) -> Result<GrantRequest, String> {
    if !connection_valid(saved)
        || !uuid(source_id)
        || !crate::native_runtime::digest_valid(scope, 64)
        || !Uuid::parse_str(request_id)
            .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == request_id)
        || timestamp == 0
        || timestamp > MAX_TIMESTAMP
        || !uuid(&identity.installation_id)
    {
        return Err("source_grant_request_invalid".into());
    }
    let mut request = GrantRequest {
        source_id: source_id.into(),
        device_id: saved
            .device_id
            .clone()
            .ok_or("desktop_enrollment_required")?,
        scope_fingerprint: scope.into(),
        request_id: request_id.into(),
        timestamp,
        signature: String::new(),
    };
    request.signature = identity.sign(&grant_message(saved, &request));
    Ok(request)
}

#[derive(Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantResponse {
    grant_id: String,
    source_id: String,
    device_id: String,
    owner_id: String,
    server_id: String,
    source_token: String,
    scope_fingerprint: String,
    authorization_epoch: u32,
    expires_at: String,
    scopes: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedSource {
    server: String,
    server_id: String,
    owner_id: String,
    device_id: String,
    source_id: String,
    scope_fingerprint: String,
    installation_id: String,
    public_key: String,
    photo_session_fingerprint: String,
    grant_id: String,
    source_token: String,
    authorization_epoch: u32,
    expires_at: String,
    next_sequence: u32,
}
fn token_valid(value: &str) -> bool {
    value
        .strip_prefix("flsrc1_")
        .is_some_and(|value| crate::native_runtime::digest_valid(value, 64))
}
fn bind_at(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    request: &GrantRequest,
    response: &GrantResponse,
    timestamp: u64,
) -> Result<SavedSource, String> {
    if !connection_valid(saved)
        || !uuid(&response.grant_id)
        || !uuid(&request.source_id)
        || !crate::native_runtime::digest_valid(&request.scope_fingerprint, 64)
        || response.server_id != saved.server_id
        || response.owner_id != saved.account_id
        || Some(&response.device_id) != saved.device_id.as_ref()
        || request.device_id != response.device_id
        || response.source_id != request.source_id
        || response.scope_fingerprint != request.scope_fingerprint
        || request.signature != identity.sign(&grant_message(saved, request))
        || response.authorization_epoch == 0
        || response.authorization_epoch > MAX_SEQUENCE
        || response.scopes != ["source-original-read"]
        || !token_valid(&response.source_token)
        || !expires_at(&response.expires_at).is_some_and(|expiry| {
            expiry > timestamp
                && timestamp
                    .checked_add(3_720_000)
                    .is_some_and(|maximum| expiry <= maximum)
        })
    {
        return Err("source_grant_response_invalid".into());
    }
    Ok(SavedSource {
        server: normalize_server(&saved.server)?.to_string(),
        server_id: saved.server_id.clone(),
        owner_id: saved.account_id.clone(),
        device_id: response.device_id.clone(),
        source_id: response.source_id.clone(),
        scope_fingerprint: response.scope_fingerprint.clone(),
        installation_id: identity.installation_id.clone(),
        public_key: identity.public_key(),
        photo_session_fingerprint: digest(&saved.token),
        grant_id: response.grant_id.clone(),
        source_token: response.source_token.clone(),
        authorization_epoch: response.authorization_epoch,
        expires_at: response.expires_at.clone(),
        next_sequence: 1,
    })
}

#[derive(Clone, Copy)]
pub enum SourceOperation {
    Poll,
    Deliver,
    Heartbeat,
}
impl SourceOperation {
    fn name(self) -> &'static str {
        match self {
            Self::Poll => "poll",
            Self::Deliver => "deliver",
            Self::Heartbeat => "heartbeat",
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceProof {
    grant_id: String,
    sequence: u32,
    timestamp: u64,
    signature: String,
}
impl SourceProof {
    pub fn header(&self) -> Result<String, String> {
        Ok(STANDARD.encode(serde_json::to_vec(self).map_err(|_| "source_proof_invalid")?))
    }
}
fn reserve_at(
    source: &mut SavedSource,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    operation: SourceOperation,
    payload: &str,
    persist: impl FnOnce(&SavedSource) -> Result<(), String>,
    timestamp: u64,
) -> Result<SourceProof, String> {
    if !connection_valid(saved)
        || normalize_server(&saved.server)?.as_str() != source.server
        || source.server_id != saved.server_id
        || source.owner_id != saved.account_id
        || Some(&source.device_id) != saved.device_id.as_ref()
        || source.installation_id != identity.installation_id
        || source.public_key != identity.public_key()
        || source.photo_session_fingerprint != digest(&saved.token)
        || !uuid(&source.source_id)
        || !uuid(&source.grant_id)
        || !crate::native_runtime::digest_valid(&source.scope_fingerprint, 64)
        || !token_valid(&source.source_token)
        || source.authorization_epoch == 0
        || source.authorization_epoch > MAX_SEQUENCE
        || source.next_sequence == 0
        || source.next_sequence > MAX_SEQUENCE
        || payload.len() > 65_536
        || timestamp == 0
        || timestamp > MAX_TIMESTAMP
        || expires_at(&source.expires_at).is_none_or(|expiry| expiry <= timestamp)
    {
        return Err("source_credential_invalid".into());
    }
    let mut proof = SourceProof {
        grant_id: source.grant_id.clone(),
        sequence: source.next_sequence,
        timestamp,
        signature: String::new(),
    };
    let mut checkpoint = source.clone();
    checkpoint.next_sequence += 1;
    // Reserve durably before exposing a proof; a crash may skip a number but cannot reuse it.
    persist(&checkpoint)?;
    source.next_sequence = checkpoint.next_sequence;
    proof.signature = identity.sign(
        &[
            "frameleaf-source/request/v1",
            &source.server_id,
            &source.owner_id,
            &source.source_id,
            &source.scope_fingerprint,
            &source.grant_id,
            &source.authorization_epoch.to_string(),
            &proof.sequence.to_string(),
            &timestamp.to_string(),
            operation.name(),
            &digest(payload),
            &digest(&source.source_token),
        ]
        .join("\n"),
    );
    Ok(proof)
}

fn credential_key(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    source_id: &str,
) -> Result<String, String> {
    if !connection_valid(saved) || !uuid(source_id) {
        return Err("source_credential_invalid".into());
    }
    let value = serde_json::to_string(&[
        normalize_server(&saved.server)?.as_str(),
        &saved.server_id,
        &saved.account_id,
        saved
            .device_id
            .as_deref()
            .ok_or("desktop_enrollment_required")?,
        &identity.installation_id,
        source_id,
    ])
    .map_err(|_| "source_credential_invalid")?;
    Ok(format!("source-read-grant-{}", digest(&value)))
}
pub async fn issue_grant(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    source_id: &str,
    scope: &str,
) -> Result<(), String> {
    let request = request_at(
        saved,
        identity,
        source_id,
        scope,
        &Uuid::new_v4().to_string(),
        now()?,
    )?;
    let response: GrantResponse = crate::transport::json(
        crate::transport::client()?
            .post(
                normalize_server(&saved.server)?
                    .join("api/source-resources/grants")
                    .map_err(|_| "source_grant_request_invalid")?,
            )
            .bearer_auth(&saved.token)
            .json(&request)
            .send()
            .await
            .map_err(|_| "source_grant_interrupted")?,
    )
    .await?;
    let source = bind_at(saved, identity, &request, &response, now()?)?;
    let _lock = crate::credential_lock::acquire()?;
    crate::credentials::save(&credential_key(saved, identity, source_id)?, &source)
}
pub struct SignedSourceRequest {
    pub token: zeroize::Zeroizing<String>,
    pub proof: SourceProof,
}
pub fn reserve_source_proof(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    source_id: &str,
    operation: SourceOperation,
    payload: &str,
) -> Result<SignedSourceRequest, String> {
    let key = credential_key(saved, identity, source_id)?;
    let _lock = crate::credential_lock::acquire()?;
    let mut source: SavedSource = crate::credentials::load(&key)?.ok_or("source_grant_required")?;
    if source.source_id != source_id {
        return Err("source_credential_invalid".into());
    }
    let proof = reserve_at(
        &mut source,
        saved,
        identity,
        operation,
        payload,
        |checkpoint| crate::credentials::save(&key, checkpoint),
        now()?,
    )?;
    Ok(SignedSourceRequest {
        token: zeroize::Zeroizing::new(source.source_token.clone()),
        proof,
    })
}

#[derive(Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadClaim {
    id: String,
    source_id: String,
    scope_fingerprint: String,
    authorization_epoch: u32,
    resource_key: String,
    version: String,
    sha256: String,
    bytes: u64,
    claim_fence: u32,
    claim_token: String,
    lease_until: String,
    deadline: String,
}
impl ReadClaim {
    pub fn validate(
        &self,
        source: &SavedSource,
        max_bytes: u64,
        timestamp: u64,
    ) -> Result<(), String> {
        let lease = expires_at(&self.lease_until);
        let deadline = expires_at(&self.deadline);
        if timestamp == 0
            || timestamp > MAX_TIMESTAMP
            || max_bytes == 0
            || max_bytes > MAX_TIMESTAMP
            || !uuid(&self.id)
            || !uuid(&self.source_id)
            || self.source_id != source.source_id
            || self.scope_fingerprint != source.scope_fingerprint
            || self.authorization_epoch != source.authorization_epoch
            || self.authorization_epoch == 0
            || self.authorization_epoch > MAX_SEQUENCE
            || self.claim_fence == 0
            || self.claim_fence > MAX_SEQUENCE
            || self.bytes == 0
            || self.bytes > max_bytes
            || [
                &self.scope_fingerprint,
                &self.resource_key,
                &self.version,
                &self.sha256,
                &self.claim_token,
            ]
            .iter()
            .any(|value| !crate::native_runtime::digest_valid(value, 64))
            || expires_at(&source.expires_at).is_none_or(|expiry| expiry <= timestamp)
            || lease.is_none_or(|lease| lease <= timestamp || lease > timestamp + 120_000)
            || deadline.is_none_or(|deadline| deadline > timestamp + 600_000)
            || !matches!((lease, deadline), (Some(lease), Some(deadline)) if lease <= deadline)
        {
            return Err("source_read_request_invalid".into());
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollResponse {
    #[serde(deserialize_with = "Option::deserialize")]
    pub request: Option<ReadClaim>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn fixture() -> (Value, SavedConnection, DeviceIdentity) {
        let wire: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/source-resource-wire-v1.json"
        ))
        .unwrap();
        let saved = SavedConnection {
            server: "https://synthetic.test/".into(),
            server_id: wire["serverId"].as_str().unwrap().into(),
            account_id: wire["ownerId"].as_str().unwrap().into(),
            device_id: Some(wire["request"]["deviceId"].as_str().unwrap().into()),
            name: "Fixture".into(),
            token: "synthetic-photo-session".into(),
            device_name: "Fixture".into(),
            mode: "client-worker".into(),
        };
        let identity = serde_json::from_value(
            json!({"installation_id":"66666666-6666-4666-8666-666666666666","secret":vec![7u8;32]}),
        )
        .unwrap();
        (wire, saved, identity)
    }
    fn bind(wire: &Value, saved: &SavedConnection, identity: &DeviceIdentity) -> SavedSource {
        bind_at(
            saved,
            identity,
            &serde_json::from_value(wire["request"].clone()).unwrap(),
            &serde_json::from_value(wire["response"].clone()).unwrap(),
            wire["request"]["timestamp"].as_u64().unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn native_signatures_match_the_servers_shared_utf8_vector() {
        let (wire, saved, identity) = fixture();
        assert_eq!(identity.public_key(), wire["publicKey"]);
        let now = wire["request"]["timestamp"].as_u64().unwrap();
        let request = request_at(
            &saved,
            &identity,
            wire["request"]["sourceId"].as_str().unwrap(),
            wire["request"]["scopeFingerprint"].as_str().unwrap(),
            wire["request"]["requestId"].as_str().unwrap(),
            now,
        )
        .unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(), wire["request"]);
        let mut source = bind(&wire, &saved, &identity);
        let mut checkpoint = None;
        let proof = reserve_at(
            &mut source,
            &saved,
            &identity,
            SourceOperation::Poll,
            wire["payload"].as_str().unwrap(),
            |value| {
                checkpoint = Some(value.next_sequence);
                Ok(())
            },
            now,
        )
        .unwrap();
        assert_eq!(checkpoint, Some(2));
        assert_eq!(source.next_sequence, 2);
        assert_eq!(serde_json::to_value(&proof).unwrap(), wire["proof"]);
        assert_eq!(proof.header().unwrap(), wire["proofHeader"]);
        let stored = serde_json::to_value(&source).unwrap().to_string();
        assert!(!stored.contains(&saved.token));
        assert!(!stored.contains("workerToken"));
    }
    #[test]
    fn grant_echo_and_scope_validation_refuse_foreign_or_worker_authority() {
        let (wire, saved, identity) = fixture();
        let request: GrantRequest = serde_json::from_value(wire["request"].clone()).unwrap();
        for (field, value) in [
            ("serverId", json!("other-server")),
            ("ownerId", json!("77777777-7777-4777-8777-777777777777")),
            ("deviceId", json!("77777777-7777-4777-8777-777777777777")),
            ("sourceId", json!("77777777-7777-4777-8777-777777777777")),
            ("scopeFingerprint", json!("c".repeat(64))),
            ("authorizationEpoch", json!(0)),
            ("scopes", json!(["library-inference"])),
            (
                "scopes",
                json!(["source-original-read", "library-inference"]),
            ),
            ("sourceToken", json!("a".repeat(64))),
            (
                "sourceToken",
                json!(format!(
                    "{}\n",
                    wire["response"]["sourceToken"].as_str().unwrap()
                )),
            ),
            ("expiresAt", json!("invalid")),
            ("expiresAt", json!("2020-01-01T00:00:00Z")),
        ] {
            let mut raw = wire["response"].clone();
            raw[field] = value;
            let response: GrantResponse = serde_json::from_value(raw).unwrap();
            assert!(
                bind_at(&saved, &identity, &request, &response, request.timestamp).is_err(),
                "{field}"
            );
        }
        let mut raw = wire["response"].clone();
        raw["root"] = json!("/private");
        assert!(serde_json::from_value::<GrantResponse>(raw).is_err());
    }
    #[test]
    fn request_reservation_checks_local_photo_authority_before_persisting() {
        let (wire, saved, identity) = fixture();
        let now = wire["request"]["timestamp"].as_u64().unwrap();
        for field in [
            "server",
            "serverId",
            "account",
            "device",
            "photoSession",
            "mode",
        ] {
            let mut connection: SavedConnection =
                serde_json::from_value(serde_json::to_value(&saved).unwrap()).unwrap();
            match field {
                "server" => connection.server = "https://other.test/".into(),
                "serverId" => connection.server_id = "other".into(),
                "account" => connection.account_id = "77777777-7777-4777-8777-777777777777".into(),
                "device" => connection.device_id = None,
                "photoSession" => connection.token = "new-session".into(),
                "mode" => connection.mode = "invalid".into(),
                _ => unreachable!(),
            }
            let mut source = bind(&wire, &saved, &identity);
            assert!(reserve_at(
                &mut source,
                &connection,
                &identity,
                SourceOperation::Poll,
                "{}",
                |_| panic!("persisted foreign authority"),
                now
            )
            .is_err());
        }
        let mut source = bind(&wire, &saved, &identity);
        let changed_identity = DeviceIdentity::generate();
        assert!(reserve_at(
            &mut source,
            &saved,
            &changed_identity,
            SourceOperation::Poll,
            "{}",
            |_| panic!("persisted foreign installation"),
            now
        )
        .is_err());
    }
    #[test]
    fn expired_oversized_or_unpersisted_proofs_are_never_returned() {
        let (wire, saved, identity) = fixture();
        let now = wire["request"]["timestamp"].as_u64().unwrap();
        let mut source = bind(&wire, &saved, &identity);
        assert!(reserve_at(
            &mut source,
            &saved,
            &identity,
            SourceOperation::Deliver,
            "{}",
            |_| Err("synthetic secure store failure".into()),
            now
        )
        .is_err());
        assert_eq!(source.next_sequence, 1);
        for (payload, time) in [("界".repeat(32_768), now), ("{}".into(), now + 3_600_000)] {
            assert!(reserve_at(
                &mut source,
                &saved,
                &identity,
                SourceOperation::Deliver,
                &payload,
                |_| panic!("persisted refused request"),
                time
            )
            .is_err());
        }
        for sequence in [0, 2_147_483_648] {
            source.next_sequence = sequence;
            assert!(reserve_at(
                &mut source,
                &saved,
                &identity,
                SourceOperation::Heartbeat,
                "{}",
                |_| panic!("persisted invalid sequence"),
                now
            )
            .is_err());
        }
        source.next_sequence = MAX_SEQUENCE;
        let proof = reserve_at(
            &mut source,
            &saved,
            &identity,
            SourceOperation::Heartbeat,
            "{}",
            |checkpoint| {
                assert_eq!(checkpoint.next_sequence, MAX_SEQUENCE + 1);
                Ok(())
            },
            now,
        )
        .unwrap();
        assert_eq!(proof.sequence, MAX_SEQUENCE);
    }

    #[test]
    fn secure_store_keys_separate_sources_and_installations() {
        let (wire, saved, identity) = fixture();
        let source_id = wire["request"]["sourceId"].as_str().unwrap();
        let key = credential_key(&saved, &identity, source_id).unwrap();
        assert!(key.starts_with("source-read-grant-"));
        assert_ne!(
            key,
            credential_key(&saved, &identity, "77777777-7777-4777-8777-777777777777").unwrap()
        );
        assert_ne!(
            key,
            credential_key(&saved, &DeviceIdentity::generate(), source_id).unwrap()
        );
        assert!(credential_key(&saved, &identity, "../other").is_err());
    }
    #[test]
    fn source_read_reply_matches_the_server_contract_and_refuses_foreign_or_unbounded_work() {
        let (wire, saved, identity) = fixture();
        let source = bind(&wire, &saved, &identity);
        let timestamp = wire["request"]["timestamp"].as_u64().unwrap();
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/source-read-v1.json")).unwrap();
        let parsed: PollResponse = serde_json::from_value(fixture.clone()).unwrap();
        assert!(parsed
            .request
            .unwrap()
            .validate(&source, 200_000, timestamp)
            .is_ok());
        for (key, value) in [
            ("id", json!("../private")),
            ("sourceId", json!("77777777-7777-4777-8777-777777777777")),
            ("scopeFingerprint", json!("f".repeat(64))),
            ("authorizationEpoch", json!(8)),
            ("resourceKey", json!("/private/original.jpg")),
            ("version", json!("C".repeat(64))),
            ("sha256", json!("not-a-digest")),
            ("bytes", json!(0)),
            ("bytes", json!(200_001)),
            ("claimFence", json!(0)),
            ("claimFence", json!(2_147_483_648u32)),
            ("claimToken", json!("E".repeat(64))),
            ("leaseUntil", json!("2027-01-15T08:00:00.000Z")),
            ("leaseUntil", json!("2027-01-15T08:03:00.000Z")),
            ("deadline", json!("2027-01-15T08:00:30.000Z")),
            ("deadline", json!("2027-01-15T08:10:01.000Z")),
        ] {
            let mut changed = fixture.clone();
            changed["request"][key] = value;
            let parsed: PollResponse = serde_json::from_value(changed).unwrap();
            assert!(
                parsed
                    .request
                    .unwrap()
                    .validate(&source, 200_000, timestamp)
                    .is_err(),
                "{key}"
            );
        }
        let parsed: PollResponse = serde_json::from_value(fixture.clone()).unwrap();
        let claim = parsed.request.unwrap();
        assert!(claim.validate(&source, 0, timestamp).is_err());
        assert!(claim
            .validate(&source, 9_007_199_254_740_992, timestamp)
            .is_err());
        assert!(claim
            .validate(&source, 200_000, timestamp + 3_600_000)
            .is_err());
        let mut unexpected = fixture.clone();
        unexpected["request"]["path"] = json!("/private");
        assert!(serde_json::from_value::<PollResponse>(unexpected).is_err());
        assert!(serde_json::from_value::<PollResponse>(json!({})).is_err());
        assert!(
            serde_json::from_value::<PollResponse>(json!({"request":null}))
                .unwrap()
                .request
                .is_none()
        );
    }
}
