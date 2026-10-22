//! Source-only credentials and installation proofs; these do not authorize a local original read.
use crate::connection::{normalize_server, DeviceIdentity, SavedConnection};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::Path,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const MAX_SEQUENCE: u32 = 2_147_483_647;
const MAX_TIMESTAMP: u64 = 9_007_199_254_740_991;
const MAX_DELIVERY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
fn uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}
pub(crate) fn now() -> Result<u64, String> {
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
fn validate_source_at(
    source: &SavedSource,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    timestamp: u64,
) -> Result<(), String> {
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
        || timestamp == 0
        || timestamp > MAX_TIMESTAMP
        || expires_at(&source.expires_at).is_none_or(|expiry| expiry <= timestamp)
    {
        return Err("source_credential_invalid".into());
    }
    Ok(())
}
fn load_current_source(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    source_id: &str,
) -> Result<SavedSource, String> {
    let source: SavedSource =
        crate::credentials::load(&credential_key(saved, identity, source_id)?)?
            .ok_or("source_grant_required")?;
    validate_source_at(&source, saved, identity, now()?)?;
    if source.source_id != source_id {
        return Err("source_credential_invalid".into());
    }
    Ok(source)
}
pub(crate) fn require_current_source(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    copy: &crate::copy_source::StagedCopy,
    epoch: u32,
) -> Result<(), String> {
    let source = load_current_source(saved, identity, copy.source_id())?;
    if source.scope_fingerprint != copy.scope_fingerprint() || source.authorization_epoch != epoch {
        return Err("source_credential_invalid".into());
    }
    Ok(())
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
    validate_source_at(source, saved, identity, timestamp)?;
    if payload.len() > 65_536 {
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
    source: SavedSource,
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
        source,
    })
}

fn source_request(
    signed: &SignedSourceRequest,
    operation: SourceOperation,
    payload: &str,
) -> Result<reqwest::RequestBuilder, String> {
    if matches!(operation, SourceOperation::Deliver) {
        return Err("source_binary_delivery_required".into());
    }
    let mut proof = reqwest::header::HeaderValue::from_str(&signed.proof.header()?)
        .map_err(|_| "source_proof_invalid")?;
    proof.set_sensitive(true);
    Ok(crate::transport::client()?
        .post(
            normalize_server(&signed.source.server)?
                .join(&format!("api/source-resources/{}", operation.name()))
                .map_err(|_| "source_request_invalid")?,
        )
        .bearer_auth(signed.token.as_str())
        .header("x-frameleaf-source-proof", proof)
        .json(&serde_json::json!({"payload": payload})))
}

pub async fn poll(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    source_id: &str,
    max_bytes: u64,
) -> Result<Option<ReadClaim>, String> {
    if max_bytes == 0 || max_bytes > MAX_TIMESTAMP {
        return Err("source_read_capacity_invalid".into());
    }
    let payload = serde_json::to_string(&serde_json::json!({"maxBytes": max_bytes}))
        .map_err(|_| "source_read_payload_invalid")?;
    let signed = reserve_source_proof(saved, identity, source_id, SourceOperation::Poll, &payload)?;
    let response: PollResponse = crate::transport::json(
        source_request(&signed, SourceOperation::Poll, &payload)?
            .send()
            .await
            .map_err(|_| "source_poll_interrupted")?,
    )
    .await?;
    if let Some(claim) = &response.request {
        claim.validate(&signed.source, max_bytes, now()?)?;
    }
    Ok(response.request)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadLease {
    lease_until: String,
    deadline: String,
}

pub async fn heartbeat(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    source_id: &str,
    max_bytes: u64,
    claim: &mut ReadClaim,
) -> Result<(), String> {
    let payload = serde_json::to_string(&serde_json::json!({
        "requestId": &claim.id, "claimFence": claim.claim_fence, "claimToken": &claim.claim_token,
    }))
    .map_err(|_| "source_read_payload_invalid")?;
    let signed = reserve_source_proof(
        saved,
        identity,
        source_id,
        SourceOperation::Heartbeat,
        &payload,
    )?;
    claim.validate(&signed.source, max_bytes, now()?)?;
    let response: ReadLease = crate::transport::json(
        source_request(&signed, SourceOperation::Heartbeat, &payload)?
            .send()
            .await
            .map_err(|_| "source_heartbeat_interrupted")?,
    )
    .await?;
    claim.renew(&signed.source, response, max_bytes, now()?)
}

#[derive(Clone, Deserialize, zeroize::ZeroizeOnDrop)]
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
    pub(crate) fn matches_resource(&self, copy: &crate::copy_source::StagedCopy) -> bool {
        copy.source_id() == self.source_id
            && copy.scope_fingerprint() == self.scope_fingerprint
            && copy.resource_key() == self.resource_key
            && copy.version() == self.version
            && copy.bytes == self.bytes
            && copy.sha256 == self.sha256
    }
    pub(crate) fn authorization_epoch(&self) -> u32 {
        self.authorization_epoch
    }
    pub(crate) fn lease_expiry(&self) -> Result<u64, String> {
        expires_at(&self.lease_until).ok_or_else(|| "source_read_request_invalid".into())
    }
    fn renew(
        &mut self,
        source: &SavedSource,
        lease: ReadLease,
        max_bytes: u64,
        timestamp: u64,
    ) -> Result<(), String> {
        if lease.deadline != self.deadline
            || !matches!((expires_at(&lease.lease_until), expires_at(&self.lease_until)),
                (Some(next), Some(previous)) if next >= previous)
        {
            return Err("source_read_request_invalid".into());
        }
        let previous = std::mem::replace(&mut self.lease_until, lease.lease_until);
        if let Err(error) = self.validate(source, max_bytes, timestamp) {
            self.lease_until = previous;
            return Err(error);
        }
        Ok(())
    }

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryMetadata<'a> {
    request_id: &'a str,
    claim_fence: u32,
    claim_token: &'a str,
    resource_key: &'a str,
    version: &'a str,
    sha256: &'a str,
    bytes: u64,
}
fn delivery_metadata(claim: &ReadClaim) -> Result<zeroize::Zeroizing<String>, String> {
    serde_json::to_string(&DeliveryMetadata {
        request_id: &claim.id,
        claim_fence: claim.claim_fence,
        claim_token: &claim.claim_token,
        resource_key: &claim.resource_key,
        version: &claim.version,
        sha256: &claim.sha256,
        bytes: claim.bytes,
    })
    .map(zeroize::Zeroizing::new)
    .map_err(|_| "source_read_payload_invalid".into())
}
fn delivery_request(
    signed: &SignedSourceRequest,
    payload: &str,
    bytes: u64,
    body: reqwest::Body,
    timeout_ms: u64,
) -> Result<reqwest::RequestBuilder, String> {
    let metadata = zeroize::Zeroizing::new(STANDARD.encode(payload.as_bytes()));
    if metadata.len() > 4096
        || bytes == 0
        || bytes > MAX_DELIVERY_BYTES
        || timeout_ms == 0
        || timeout_ms > 600_000
    {
        return Err("source_read_payload_invalid".into());
    }
    let mut proof = reqwest::header::HeaderValue::from_str(&signed.proof.header()?)
        .map_err(|_| "source_proof_invalid")?;
    proof.set_sensitive(true);
    let mut metadata = reqwest::header::HeaderValue::from_str(&metadata)
        .map_err(|_| "source_read_payload_invalid")?;
    metadata.set_sensitive(true);
    Ok(crate::transport::client()?
        .put(
            normalize_server(&signed.source.server)?
                .join("api/source-resources/deliver")
                .map_err(|_| "source_request_invalid")?,
        )
        .bearer_auth(signed.token.as_str())
        .header("x-frameleaf-source-proof", proof)
        .header("x-frameleaf-source-payload", metadata)
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .header(reqwest::header::CONTENT_LENGTH, bytes)
        .timeout(Duration::from_millis(timeout_ms))
        .body(body))
}

type DeliveryChunk = Result<Vec<u8>, std::io::Error>;
type DeliveryGate = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;
struct DeliveryShutdown {
    receiver: Arc<Mutex<tokio::sync::mpsc::Receiver<DeliveryChunk>>>,
    stopped: Arc<AtomicBool>,
}
impl DeliveryShutdown {
    fn close(&self) {
        self.stopped.store(true, Ordering::Release);
        self.receiver
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .close();
    }
}
impl Drop for DeliveryShutdown {
    fn drop(&mut self) {
        self.close();
    }
}
struct DeliveryStream {
    receiver: Arc<Mutex<tokio::sync::mpsc::Receiver<DeliveryChunk>>>,
}
impl futures_core::Stream for DeliveryStream {
    type Item = DeliveryChunk;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .poll_recv(cx)
    }
}
fn produce_delivery(
    mut file: std::fs::File,
    expected: u64,
    checksum: &str,
    sender: tokio::sync::mpsc::Sender<DeliveryChunk>,
    stop: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    gate: DeliveryGate,
) -> Result<(), String> {
    let check = || {
        if stop.load(Ordering::Acquire) || cancelled.load(Ordering::Acquire) {
            return Err("source_delivery_interrupted".into());
        }
        gate()
    };
    let result: Result<(), String> = (|| {
        let mut hash = Sha256::new();
        let mut copied = 0;
        while copied < expected {
            check()?;
            let mut chunk = vec![0u8; (expected - copied).min(65_536) as usize];
            file.read_exact(&mut chunk)
                .map_err(|_| "source_stage_changed")?;
            copied += chunk.len() as u64;
            hash.update(&chunk);
            if copied == expected {
                let mut extra = [0];
                if file.read(&mut extra).map_err(|_| "source_stage_changed")? != 0
                    || format!("{:x}", hash.clone().finalize()) != checksum
                {
                    return Err("source_stage_changed".into());
                }
                // Withhold the last bytes until local integrity and current permission have passed.
                check()?;
            }
            sender
                .blocking_send(Ok(chunk))
                .map_err(|_| "source_delivery_interrupted")?;
        }
        Ok(())
    })();
    if let Err(code) = &result {
        let _ = sender.blocking_send(Err(std::io::Error::other(code.clone())));
    }
    result
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryResponse {
    accepted: bool,
}

/// Owns an independently verified descriptor and source-bound proof; never deserialize a NAS path into this type.
pub struct PreparedDelivery {
    signed: SignedSourceRequest,
    payload: zeroize::Zeroizing<String>,
    file: std::fs::File,
    bytes: u64,
    checksum: String,
    lease_until: u64,
    until: u64,
}
/// Contains no request proof: slow verification may safely overlap claim renewal.
pub(crate) struct VerifiedDelivery {
    file: std::fs::File,
    copy: crate::copy_source::StagedCopy,
}
pub(crate) fn verify_delivery(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    copy: &crate::copy_source::StagedCopy,
    staging: &Path,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
) -> Result<VerifiedDelivery, String> {
    gate()?;
    if copy.bytes == 0 || copy.bytes > MAX_DELIVERY_BYTES {
        return Err("source_read_request_invalid".into());
    }
    copy.validate_current(saved, identity)?;
    let file = copy
        .verify_with_gate(saved, identity, staging, gate)?
        .into_std();
    copy.validate_current(saved, identity)?;
    gate()?;
    Ok(VerifiedDelivery {
        file,
        copy: copy.clone(),
    })
}
fn bind_verified(
    claim: &ReadClaim,
    verified: VerifiedDelivery,
    max_bytes: u64,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
    reserve: impl FnOnce(&str) -> Result<SignedSourceRequest, String>,
) -> Result<PreparedDelivery, String> {
    gate()?;
    if !claim.matches_resource(&verified.copy) {
        return Err("source_read_request_invalid".into());
    }
    let payload = delivery_metadata(claim)?;
    let signed = reserve(&payload)?;
    claim.validate(&signed.source, max_bytes, now()?)?;
    let until = expires_at(&claim.deadline)
        .ok_or("source_read_request_invalid")?
        .min(expires_at(&signed.source.expires_at).ok_or("source_credential_invalid")?);
    Ok(PreparedDelivery {
        signed,
        payload,
        file: verified.file,
        until,
        lease_until: claim.lease_expiry()?,
        bytes: claim.bytes,
        checksum: claim.sha256.clone(),
    })
}
pub(crate) fn bind_delivery(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    claim: &ReadClaim,
    verified: VerifiedDelivery,
    max_bytes: u64,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
) -> Result<PreparedDelivery, String> {
    bind_verified(claim, verified, max_bytes, gate, |payload| {
        reserve_source_proof(
            saved,
            identity,
            &claim.source_id,
            SourceOperation::Deliver,
            payload,
        )
    })
}
/// Blocking stage verification belongs on the coordinator's file worker, before starting an upload.
pub fn prepare_delivery(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    claim: &ReadClaim,
    copy: &crate::copy_source::StagedCopy,
    staging: &Path,
    max_bytes: u64,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
) -> Result<PreparedDelivery, String> {
    gate()?;
    claim.validate(
        &load_current_source(saved, identity, &claim.source_id)?,
        max_bytes,
        now()?,
    )?;
    if !claim.matches_resource(copy) {
        return Err("source_read_request_invalid".into());
    }
    let verified = verify_delivery(saved, identity, copy, staging, gate)?;
    bind_delivery(saved, identity, claim, verified, max_bytes, gate)
}
pub(crate) async fn wait_delivery<T>(
    future: impl std::future::Future<Output = Result<T, String>>,
    cancelled: &AtomicBool,
    gate: &(dyn Fn() -> Result<(), String> + Send + Sync),
) -> Result<T, String> {
    let check = || {
        if cancelled.load(Ordering::Acquire) {
            return Err("source_delivery_interrupted".into());
        }
        gate()
    };
    check()?;
    tokio::pin!(future);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => check()?,
            result = &mut future => { check()?; return result; }
        }
    }
}
/// The coordinator supplies a live consent/version gate, including its stop and sign-out state.
pub async fn deliver(
    prepared: PreparedDelivery,
    cancelled: Arc<AtomicBool>,
    gate: DeliveryGate,
) -> Result<bool, String> {
    gate()?;
    if cancelled.load(Ordering::Acquire) {
        return Err("source_delivery_interrupted".into());
    }
    let PreparedDelivery {
        signed,
        payload,
        file,
        bytes,
        checksum,
        lease_until,
        until,
    } = prepared;
    let timestamp = now()?;
    if lease_until <= timestamp
        || timestamp < signed.proof.timestamp
        || timestamp - signed.proof.timestamp > 120_000
    {
        return Err("source_read_request_invalid".into());
    }
    let timeout_ms = until
        .checked_sub(timestamp)
        .filter(|value| *value > 0 && *value <= 600_000)
        .ok_or("source_read_request_invalid")?;
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let receiver = Arc::new(Mutex::new(receiver));
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = DeliveryShutdown {
        receiver: receiver.clone(),
        stopped: stop.clone(),
    };
    let body = reqwest::Body::wrap_stream(DeliveryStream {
        receiver: receiver.clone(),
    });
    let request = delivery_request(&signed, &payload, bytes, body, timeout_ms)?;
    let stopped = stop.clone();
    let cancel = cancelled.clone();
    let read_gate = gate.clone();
    let producer = tokio::task::spawn_blocking(move || {
        produce_delivery(file, bytes, &checksum, sender, stopped, cancel, read_gate)
    });
    let response = wait_delivery(
        async move {
            request
                .send()
                .await
                .map_err(|_| String::from("source_delivery_interrupted"))
        },
        &cancelled,
        &*gate,
    )
    .await;
    // Close even if an early HTTP response leaves its request body alive in the connection task.
    shutdown.close();
    let produced = producer.await.map_err(|_| "source_delivery_interrupted")?;
    let result: DeliveryResponse =
        wait_delivery(crate::transport::json(response?), &cancelled, &*gate).await?;
    produced?;
    Ok(result.accepted)
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
    fn heartbeat_during_file_verification_precedes_the_delivery_proof_and_renewed_lease() {
        let (wire, saved, identity) = fixture();
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-proof-order-{}", Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        for name in ["source", "stage"] {
            crate::runtime_store::private_directory(&root.join(name)).unwrap();
        }
        std::fs::write(root.join("source/original.jpg"), b"abcdefghij").unwrap();
        let copy = crate::copy_source::CopyApproval::approve(
            &saved,
            &identity,
            &root.join("source"),
            1024,
            true,
        )
        .unwrap()
        .stage(
            &saved,
            &identity,
            "original.jpg",
            &root.join("stage"),
            &AtomicBool::new(false),
        )
        .unwrap();
        let timestamp = now().unwrap();
        let date = |millis: u64| {
            time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
                .unwrap()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        };
        let mut source = bind(&wire, &saved, &identity);
        source.source_id = copy.source_id().into();
        source.scope_fingerprint = copy.scope_fingerprint();
        source.expires_at = date(timestamp + 3_600_000);
        let source = Mutex::new(source);
        let during_verification = || {
            let mut source = source.lock().unwrap();
            reserve_at(
                &mut source,
                &saved,
                &identity,
                SourceOperation::Heartbeat,
                "synthetic-heartbeat",
                |_| Ok(()),
                timestamp,
            )?;
            Ok(())
        };
        let verified = verify_delivery(
            &saved,
            &identity,
            &copy,
            &root.join("stage"),
            &during_verification,
        )
        .unwrap();
        let mut source = source.into_inner().unwrap();
        let last_heartbeat = source.next_sequence - 1;
        assert!(last_heartbeat >= 2);
        let mut claim:ReadClaim=serde_json::from_value(json!({"id":Uuid::new_v4().to_string(),"sourceId":copy.source_id(),
            "scopeFingerprint":copy.scope_fingerprint(),"authorizationEpoch":source.authorization_epoch,
            "resourceKey":copy.resource_key(),"version":copy.version(),"sha256":copy.sha256,"bytes":copy.bytes,
            "claimFence":1,"claimToken":"a".repeat(64),"leaseUntil":date(timestamp+45_000),"deadline":date(timestamp+300_000)})).unwrap();
        claim
            .renew(
                &source,
                ReadLease {
                    lease_until: date(timestamp + 90_000),
                    deadline: claim.deadline.clone(),
                },
                copy.bytes,
                timestamp,
            )
            .unwrap();
        let prepared = bind_verified(&claim, verified, copy.bytes, &|| Ok(()), |payload| {
            let proof = reserve_at(
                &mut source,
                &saved,
                &identity,
                SourceOperation::Deliver,
                payload,
                |_| Ok(()),
                timestamp,
            )?;
            Ok(SignedSourceRequest {
                token: zeroize::Zeroizing::new(source.source_token.clone()),
                proof,
                source: source.clone(),
            })
        })
        .unwrap();
        assert_eq!(prepared.signed.proof.sequence, last_heartbeat + 1);
        assert_eq!(prepared.lease_until, timestamp + 90_000);
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
    #[test]
    fn source_control_requests_use_only_the_bound_https_origin_and_source_proof() {
        let (wire, saved, identity) = fixture();
        let mut source = bind(&wire, &saved, &identity);
        let payload = "{\"maxBytes\":200000}";
        let proof = reserve_at(
            &mut source,
            &saved,
            &identity,
            SourceOperation::Poll,
            payload,
            |_| Ok(()),
            wire["request"]["timestamp"].as_u64().unwrap(),
        )
        .unwrap();
        let mut signed = SignedSourceRequest {
            token: zeroize::Zeroizing::new(source.source_token.clone()),
            proof,
            source,
        };
        let request = source_request(&signed, SourceOperation::Poll, payload)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(
            request.url().as_str(),
            "https://synthetic.test/api/source-resources/poll"
        );
        assert_eq!(
            request.headers()["authorization"].to_str().unwrap(),
            format!("Bearer {}", signed.token.as_str())
        );
        assert_ne!(
            request.headers()["authorization"].to_str().unwrap(),
            format!("Bearer {}", saved.token)
        );
        assert!(request.headers()["x-frameleaf-source-proof"].is_sensitive());
        assert_eq!(
            request.headers()["x-frameleaf-source-proof"],
            signed.proof.header().unwrap()
        );
        assert_eq!(
            serde_json::from_slice::<Value>(request.body().unwrap().as_bytes().unwrap()).unwrap(),
            json!({"payload":payload})
        );
        signed.source.server = "http://synthetic.test/".into();
        assert!(source_request(&signed, SourceOperation::Poll, payload).is_err());
    }
    #[test]
    fn renewal_cannot_change_deadlines_or_install_invalid_lease_authority() {
        let (wire, saved, identity) = fixture();
        let source = bind(&wire, &saved, &identity);
        let timestamp = wire["request"]["timestamp"].as_u64().unwrap();
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/source-read-v1.json")).unwrap();
        for (until, deadline, capacity) in [
            (
                "2027-01-15T08:00:30.000Z",
                "2027-01-15T08:10:00.000Z",
                200_000,
            ),
            (
                "2027-01-15T08:03:00.000Z",
                "2027-01-15T08:10:00.000Z",
                200_000,
            ),
            ("invalid", "2027-01-15T08:10:00.000Z", 200_000),
            (
                "2027-01-15T08:01:30.000Z",
                "2027-01-15T08:11:00.000Z",
                200_000,
            ),
            ("2027-01-15T08:01:30.000Z", "2027-01-15T08:10:00.000Z", 1),
        ] {
            let mut claim = serde_json::from_value::<PollResponse>(fixture.clone())
                .unwrap()
                .request
                .unwrap();
            let before = claim.lease_until.clone();
            assert!(claim
                .renew(
                    &source,
                    ReadLease {
                        lease_until: until.into(),
                        deadline: deadline.into()
                    },
                    capacity,
                    timestamp
                )
                .is_err());
            assert_eq!(claim.lease_until, before);
        }
        let mut claim = serde_json::from_value::<PollResponse>(fixture)
            .unwrap()
            .request
            .unwrap();
        claim
            .renew(
                &source,
                ReadLease {
                    lease_until: "2027-01-15T08:01:30.000Z".into(),
                    deadline: claim.deadline.clone(),
                },
                200_000,
                timestamp,
            )
            .unwrap();
        assert_eq!(claim.lease_until, "2027-01-15T08:01:30.000Z");
    }
    #[test]
    fn original_delivery_is_binary_put_with_sensitive_metadata_and_no_url_credentials() {
        let (wire, saved, identity) = fixture();
        let mut source = bind(&wire, &saved, &identity);
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/source-read-v1.json")).unwrap();
        let claim: ReadClaim = serde_json::from_value(fixture["request"].clone()).unwrap();
        let payload = delivery_metadata(&claim).unwrap();
        let proof = reserve_at(
            &mut source,
            &saved,
            &identity,
            SourceOperation::Deliver,
            &payload,
            |_| Ok(()),
            wire["request"]["timestamp"].as_u64().unwrap(),
        )
        .unwrap();
        let signed = SignedSourceRequest {
            token: zeroize::Zeroizing::new(source.source_token.clone()),
            proof,
            source,
        };
        let body = vec![0, 255, 128, 10];
        let request = delivery_request(
            &signed,
            &payload,
            body.len() as u64,
            reqwest::Body::from(body.clone()),
            10_000,
        )
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(request.method(), reqwest::Method::PUT);
        assert_eq!(
            request.url().as_str(),
            "https://synthetic.test/api/source-resources/deliver"
        );
        assert_eq!(request.body().unwrap().as_bytes().unwrap(), body);
        assert_eq!(
            request.headers()["content-type"],
            "application/octet-stream"
        );
        assert_eq!(request.headers()["content-length"], "4");
        assert!(request.headers()["authorization"].is_sensitive());
        assert!(request.headers()["x-frameleaf-source-proof"].is_sensitive());
        assert!(request.headers()["x-frameleaf-source-payload"].is_sensitive());
        assert_eq!(
            STANDARD
                .decode(request.headers()["x-frameleaf-source-payload"].as_bytes())
                .unwrap(),
            payload.as_bytes()
        );
        assert_eq!(request.timeout().unwrap().as_millis(), 10_000);
        let metadata: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(metadata["requestId"], claim.id);
        assert_eq!(metadata["claimToken"], claim.claim_token);
        assert_eq!(metadata["resourceKey"], claim.resource_key);
        assert_eq!(metadata["version"], claim.version);
        assert_eq!(metadata["sha256"], claim.sha256);
        assert_eq!(metadata["bytes"], claim.bytes);
        assert_eq!(metadata.as_object().unwrap().len(), 7);
    }

    struct DeliveryFile(std::path::PathBuf);
    impl DeliveryFile {
        fn new(bytes: &[u8]) -> Self {
            let root = std::env::temp_dir().join(format!("frameleaf-delivery-{}", Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("input"), bytes).unwrap();
            Self(root)
        }
        fn open(&self) -> std::fs::File {
            std::fs::File::open(self.0.join("input")).unwrap()
        }
    }
    impl Drop for DeliveryFile {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[tokio::test]
    async fn delivery_body_is_bounded_verified_and_joined_before_completion() {
        let bytes = vec![42; 150_000];
        let fixture = DeliveryFile::new(&bytes);
        let file = fixture.open();
        let checksum = format!("{:x}", Sha256::digest(&bytes));
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let producer = tokio::task::spawn_blocking(move || {
            produce_delivery(
                file,
                150_000,
                &checksum,
                sender,
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
                Arc::new(|| Ok(())),
            )
        });
        let mut received = Vec::new();
        while let Some(chunk) = receiver.recv().await {
            let chunk = chunk.unwrap();
            assert!(chunk.len() <= 65_536);
            received.extend(chunk);
        }
        producer.await.unwrap().unwrap();
        assert_eq!(received, bytes);
    }
    #[tokio::test]
    async fn delivery_never_releases_its_last_bytes_on_integrity_or_permission_failure() {
        for failure in ["short", "long", "checksum", "cancelled", "revoked"] {
            let bytes: &[u8] = match failure {
                "short" => b"hell",
                "long" => b"helloo",
                _ => b"hello",
            };
            let fixture = DeliveryFile::new(bytes);
            let file = fixture.open();
            let checksum = if failure == "checksum" {
                "0".repeat(64)
            } else {
                format!("{:x}", Sha256::digest(b"hello"))
            };
            let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
            let producer = tokio::task::spawn_blocking(move || {
                produce_delivery(
                    file,
                    5,
                    &checksum,
                    sender,
                    Arc::new(AtomicBool::new(false)),
                    Arc::new(AtomicBool::new(failure == "cancelled")),
                    Arc::new(move || {
                        if failure == "revoked" {
                            Err("source_approval_required".into())
                        } else {
                            Ok(())
                        }
                    }),
                )
            });
            let mut count = 0;
            while let Some(chunk) = receiver.recv().await {
                if let Ok(chunk) = chunk {
                    count += chunk.len();
                }
            }
            assert!(producer.await.unwrap().is_err(), "{failure}");
            assert_eq!(count, 0, "{failure}");
        }
    }
    #[tokio::test]
    async fn delivery_checks_current_permission_again_before_exposing_the_final_chunk() {
        let bytes = vec![42; 100_000];
        let fixture = DeliveryFile::new(&bytes);
        let file = fixture.open();
        let checksum = format!("{:x}", Sha256::digest(&bytes));
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let producer = tokio::task::spawn_blocking(move || {
            produce_delivery(
                file,
                100_000,
                &checksum,
                sender,
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
                Arc::new(move || {
                    if calls.fetch_add(1, Ordering::SeqCst) == 2 {
                        Err("source_approval_required".into())
                    } else {
                        Ok(())
                    }
                }),
            )
        });
        let mut count = 0;
        while let Some(chunk) = receiver.recv().await {
            if let Ok(chunk) = chunk {
                count += chunk.len();
            }
        }
        assert!(producer.await.unwrap().is_err());
        assert_eq!(count, 65_536);
    }
    #[tokio::test]
    async fn dropping_an_upload_wakes_a_backpressured_reader_and_allows_it_to_close() {
        let bytes = vec![42; 1_000_000];
        let fixture = DeliveryFile::new(&bytes);
        let file = fixture.open();
        let checksum = format!("{:x}", Sha256::digest(&bytes));
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let receiver = Arc::new(Mutex::new(receiver));
        let stopped = Arc::new(AtomicBool::new(false));
        let shutdown = DeliveryShutdown {
            receiver,
            stopped: stopped.clone(),
        };
        let (ready, waiting) = tokio::sync::oneshot::channel();
        let ready = Mutex::new(Some(ready));
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let gate: DeliveryGate = Arc::new(move || {
            if calls.fetch_add(1, Ordering::SeqCst) == 2 {
                let _ = ready.lock().unwrap().take().unwrap().send(());
            }
            Ok(())
        });
        let producer = tokio::task::spawn_blocking(move || {
            produce_delivery(
                file,
                1_000_000,
                &checksum,
                sender,
                stopped,
                Arc::new(AtomicBool::new(false)),
                gate,
            )
        });
        tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .unwrap()
            .unwrap();
        drop(shutdown);
        assert!(tokio::time::timeout(Duration::from_secs(2), producer)
            .await
            .unwrap()
            .unwrap()
            .is_err());
    }
    #[test]
    fn delivery_response_and_control_path_cannot_silently_accept_another_contract() {
        for value in [
            "{}",
            "null",
            "{\"accepted\":true,\"path\":\"/private\"}",
            "{\"accepted\":\"true\"}",
        ] {
            assert!(serde_json::from_str::<DeliveryResponse>(value).is_err());
        }
        assert!(
            !serde_json::from_str::<DeliveryResponse>("{\"accepted\":false}")
                .unwrap()
                .accepted
        );
        let (wire, saved, identity) = fixture();
        let mut source = bind(&wire, &saved, &identity);
        let payload = "{}";
        let proof = reserve_at(
            &mut source,
            &saved,
            &identity,
            SourceOperation::Deliver,
            payload,
            |_| Ok(()),
            wire["request"]["timestamp"].as_u64().unwrap(),
        )
        .unwrap();
        let mut signed = SignedSourceRequest {
            token: zeroize::Zeroizing::new(source.source_token.clone()),
            proof,
            source,
        };
        assert!(source_request(&signed, SourceOperation::Deliver, payload).is_err());
        for (length, timeout) in [(0, 1), (MAX_DELIVERY_BYTES + 1, 1), (1, 0), (1, 600_001)] {
            assert!(delivery_request(
                &signed,
                payload,
                length,
                reqwest::Body::from(vec![0]),
                timeout
            )
            .is_err());
        }
        assert!(delivery_request(
            &signed,
            &"x".repeat(4096),
            1,
            reqwest::Body::from(vec![0]),
            1
        )
        .is_err());
        signed.source.server = "http://synthetic.test/".into();
        assert!(delivery_request(&signed, payload, 1, reqwest::Body::from(vec![0]), 1).is_err());
    }
    #[tokio::test]
    async fn a_late_delivery_reply_cannot_outlive_cancellation_or_current_permission() {
        for revoke in [false, true] {
            let changed = AtomicBool::new(false);
            let other = AtomicBool::new(false);
            let cancelled = if revoke { &other } else { &changed };
            let result = wait_delivery(
                async {
                    changed.store(true, Ordering::Release);
                    Ok(true)
                },
                cancelled,
                &|| {
                    if revoke && changed.load(Ordering::Acquire) {
                        Err("source_approval_required".into())
                    } else {
                        Ok(())
                    }
                },
            )
            .await;
            assert!(result.is_err());
        }
    }
    #[tokio::test]
    async fn a_stalled_delivery_reply_stops_when_the_coordinator_cancels() {
        let cancelled = AtomicBool::new(false);
        let (result, ()) = tokio::join!(
            tokio::time::timeout(
                Duration::from_millis(500),
                wait_delivery(
                    std::future::pending::<Result<(), String>>(),
                    &cancelled,
                    &|| Ok(())
                )
            ),
            async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                cancelled.store(true, Ordering::Release);
            }
        );
        assert_eq!(result.unwrap().unwrap_err(), "source_delivery_interrupted");
    }
}
