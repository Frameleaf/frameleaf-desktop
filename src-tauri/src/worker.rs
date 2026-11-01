use crate::connection::DeviceIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequest {
    pub device_id: String,
    pub request_id: String,
    pub timestamp: u64,
    pub signature: String,
}

pub fn session_request(
    identity: &DeviceIdentity,
    server: &str,
    account: &str,
    device: &str,
) -> Result<SessionRequest, String> {
    let mut request = SessionRequest {
        device_id: device.into(),
        request_id: Uuid::new_v4().to_string(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock_invalid")?
            .as_millis() as u64,
        signature: String::new(),
    };
    request.signature = identity.sign(
        &[
            "frameleaf-desktop/session/v1",
            server,
            account,
            device,
            &request.request_id,
            &request.timestamp.to_string(),
        ]
        .join("\n"),
    );
    Ok(request)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerProof {
    pub session_id: String,
    pub sequence: u32,
    pub timestamp: u64,
    pub signature: String,
}

pub fn worker_message(
    server: &str,
    epoch: u32,
    token: &str,
    proof: &WorkerProof,
    operation: &str,
    payload: &str,
) -> String {
    [
        "frameleaf-desktop/request/v1",
        server,
        &proof.session_id,
        &epoch.to_string(),
        &proof.sequence.to_string(),
        &proof.timestamp.to_string(),
        operation,
        &format!("{:x}", Sha256::digest(payload.as_bytes())),
        &format!("{:x}", Sha256::digest(token.as_bytes())),
    ]
    .join("\n")
}

#[derive(Clone, PartialEq, Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct SavedWorker {
    pub server_id: String,
    pub account_id: String,
    pub device_id: String,
    pub session_id: String,
    pub authorization_epoch: u32,
    pub worker_token: String,
    pub expires_at: String,
    pub next_sequence: u32,
}

pub fn reserve_proof(
    saved: &mut SavedWorker,
    identity: &DeviceIdentity,
    operation: &str,
    payload: &str,
    persist: impl FnOnce(&SavedWorker) -> Result<(), String>,
) -> Result<WorkerProof, String> {
    if saved.next_sequence == 0 || saved.next_sequence > 2_147_483_647 {
        return Err("worker_session_renewal_required".into());
    }
    let mut proof = WorkerProof {
        session_id: saved.session_id.clone(),
        sequence: saved.next_sequence,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock_invalid")?
            .as_millis() as u64,
        signature: String::new(),
    };
    let mut checkpoint = saved.clone();
    checkpoint.next_sequence += 1;
    // Reserve before sending so a crash can skip a counter but can never replay one.
    persist(&checkpoint)?;
    saved.next_sequence = checkpoint.next_sequence;
    proof.signature = identity.sign(&worker_message(
        &saved.server_id,
        saved.authorization_epoch,
        &saved.worker_token,
        &proof,
        operation,
        payload,
    ));
    Ok(proof)
}

#[derive(Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub session_id: String,
    pub authorization_epoch: u32,
    pub worker_token: String,
    pub expires_at: String,
    pub scopes: Vec<String>,
}

fn validate_response(response: &SessionResponse) -> Result<(), String> {
    if Uuid::parse_str(&response.session_id).is_err()
        || response.authorization_epoch == 0
        || response.worker_token.len() != 64
        || !response
            .worker_token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || response.scopes != ["library-inference"]
        || response.expires_at.len() > 64
        || response.expires_at.is_empty()
    {
        return Err("worker_session_response_invalid".into());
    }
    Ok(())
}

pub fn bind_session(
    saved: &crate::connection::SavedConnection,
    response: &SessionResponse,
) -> Result<SavedWorker, String> {
    let device = saved
        .device_id
        .as_ref()
        .ok_or("desktop_enrollment_required")?;
    if saved.server_id.is_empty()
        || saved.account_id.is_empty()
        || saved.mode != "client-worker"
        || Uuid::parse_str(device).is_err()
    {
        return Err("worker_session_response_invalid".into());
    }
    validate_response(response)?;
    Ok(SavedWorker {
        server_id: saved.server_id.clone(),
        account_id: saved.account_id.clone(),
        device_id: device.clone(),
        session_id: response.session_id.clone(),
        authorization_epoch: response.authorization_epoch,
        worker_token: response.worker_token.clone(),
        expires_at: response.expires_at.clone(),
        next_sequence: 1,
    })
}

pub fn bind_renewal(
    saved: &SavedWorker,
    response: &SessionResponse,
) -> Result<SavedWorker, String> {
    validate_response(response)?;
    if response.session_id != saved.session_id
        || response.authorization_epoch != saved.authorization_epoch
    {
        return Err("worker_association_changed".into());
    }
    Ok(SavedWorker {
        server_id: saved.server_id.clone(),
        account_id: saved.account_id.clone(),
        device_id: saved.device_id.clone(),
        session_id: response.session_id.clone(),
        authorization_epoch: response.authorization_epoch,
        worker_token: response.worker_token.clone(),
        expires_at: response.expires_at.clone(),
        next_sequence: 1,
    })
}

pub fn persist_checkpoint(
    current: Option<&SavedWorker>,
    expected: &SavedWorker,
    next: &SavedWorker,
    save: impl FnOnce(&SavedWorker) -> Result<(), String>,
) -> Result<(), String> {
    if current != Some(expected) {
        return Err("worker_association_changed".into());
    }
    save(next)
}
