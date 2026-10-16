use crate::{
    connection::{normalize_server, DeviceIdentity, SavedConnection},
    credentials, transport,
    worker::{bind_renewal, reserve_proof, SavedWorker, SessionResponse},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{Client, Method, Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

use crate::{
    model_catalogue::ApprovedProfile, native_runtime::QualifiedRuntime,
    runtime_store::RuntimeAttestation,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChallengeResponse {
    id: String,
    model_key: String,
    spec_json: String,
    binding_sha256: String,
    fixture_base64: String,
    manifest_sha256: String,
    expires_at: String,
    report_sha256: Option<String>,
}

struct ChallengeAuthority {
    server_id: String,
    account_id: String,
    device_id: String,
    session_id: String,
    authorization_epoch: u32,
    credential_sha256: String,
}
impl ChallengeAuthority {
    fn from_worker(worker: &SavedWorker) -> Self {
        Self {
            server_id: worker.server_id.clone(),
            account_id: worker.account_id.clone(),
            device_id: worker.device_id.clone(),
            session_id: worker.session_id.clone(),
            authorization_epoch: worker.authorization_epoch,
            credential_sha256: hash(worker.worker_token.as_bytes()),
        }
    }
    fn matches_association(&self, worker: &SavedWorker) -> bool {
        self.server_id == worker.server_id
            && self.account_id == worker.account_id
            && self.device_id == worker.device_id
            && self.session_id == worker.session_id
            && self.authorization_epoch == worker.authorization_epoch
    }
    fn matches(&self, worker: &SavedWorker) -> bool {
        self.matches_association(worker)
            && self.credential_sha256 == hash(worker.worker_token.as_bytes())
    }
}

/// Bound to a compiled profile and a locally verified signed runtime; no NAS-selected code or fixture.
/// ```compile_fail
/// let _: frameleaf_desktop::ml_transport::QualificationChallenge = serde_json::from_str("{}").unwrap();
/// ```
pub struct QualificationChallenge {
    authority: ChallengeAuthority,
    id: String,
    spec: Vec<u8>,
    fixture: Vec<u8>,
    binding_sha256: String,
    manifest_sha256: String,
    expires_at: i64,
    report_sha256: Option<String>,
}
impl QualificationChallenge {
    pub fn bind(
        worker: &SavedWorker,
        profile: &ApprovedProfile,
        attestation: &RuntimeAttestation,
        raw: &[u8],
        at: i64,
    ) -> Result<Self, String> {
        if raw.is_empty() || raw.len() > 4 * 1024 * 1024 {
            return Err("worker_challenge_invalid".into());
        }
        let response: ChallengeResponse =
            serde_json::from_slice(raw).map_err(|_| "worker_challenge_invalid")?;
        let (spec, fixture) = profile.challenge(&response.id)?;
        let expires_at = millis(&response.expires_at)?;
        let digest_valid = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if response.model_key != profile.model_key()
            || response.spec_json.as_bytes() != spec
            || response.binding_sha256 != hash(&spec)
            || response.manifest_sha256 != attestation.manifest_sha256()
            || response.fixture_base64 != STANDARD.encode(&fixture)
            || response
                .report_sha256
                .as_ref()
                .is_some_and(|value| !digest_valid(value))
            || expires_at <= at
            || expires_at > at + 720_000
            || expires_at > millis(&worker.expires_at)?
        {
            return Err("worker_challenge_invalid".into());
        }
        Ok(Self {
            authority: ChallengeAuthority::from_worker(worker),
            id: response.id,
            spec,
            fixture,
            binding_sha256: response.binding_sha256,
            manifest_sha256: response.manifest_sha256,
            expires_at,
            report_sha256: response.report_sha256,
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn specification(&self) -> &[u8] {
        &self.spec
    }
    pub fn fixture(&self) -> &[u8] {
        &self.fixture
    }
    pub fn report_sha256(&self) -> Option<&str> {
        self.report_sha256.as_deref()
    }
    pub fn validate_authority(&self, worker: &SavedWorker) -> Result<(), String> {
        if !self.authority.matches(worker) {
            return Err("worker_challenge_association_changed".into());
        }
        Ok(())
    }
    pub fn validate_submission(
        &self,
        worker: &SavedWorker,
        qualified: &QualifiedRuntime,
        at: i64,
    ) -> Result<(), String> {
        self.validate_authority(worker)?;
        if at >= self.expires_at
            || millis(&worker.expires_at)? <= at
            || qualified.manifest_sha256() != self.manifest_sha256
            || qualified.specification() != self.spec
            || qualified.report()["bindingSha256"] != self.binding_sha256
        {
            return Err("worker_qualification_changed_or_expired".into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcceptedResponse {
    id: String,
    device_id: String,
    session_id: String,
    authorization_epoch: u32,
    model_key: String,
    config_sha256: String,
    input_kind: InputKind,
    binding_sha256: String,
    manifest_sha256: String,
    runtime_fingerprint: String,
    report_sha256: String,
    qualified_at: String,
    expires_at: String,
}
fn canonical_hash(value: &serde_json::Value) -> Result<String, String> {
    serde_json_canonicalizer::to_vec(value)
        .map(|bytes| hash(&bytes))
        .map_err(|_| "worker_qualification_invalid".into())
}
/// Accepted runtime evidence, never a renderer-supplied grant or a promise of processing scope.
/// ```compile_fail
/// let _: frameleaf_desktop::ml_transport::AcceptedQualification = serde_json::from_str("{}").unwrap();
/// ```
pub struct AcceptedQualification {
    authority: ChallengeAuthority,
    id: String,
    model_key: String,
    config_sha256: String,
    input_kind: InputKind,
    binding_sha256: String,
    manifest_sha256: String,
    runtime_fingerprint: String,
    report_sha256: String,
    expires_at: i64,
}
impl AcceptedQualification {
    pub fn bind(
        worker: &SavedWorker,
        profile: &ApprovedProfile,
        qualified: &QualifiedRuntime,
        raw: &[u8],
        at: i64,
    ) -> Result<Self, String> {
        if raw.is_empty() || raw.len() > 65_536 {
            return Err("worker_qualification_invalid".into());
        }
        let response: AcceptedResponse =
            serde_json::from_slice(raw).map_err(|_| "worker_qualification_invalid")?;
        let (spec, _) = profile.challenge(&response.id)?;
        let specification: serde_json::Value =
            serde_json::from_slice(&spec).map_err(|_| "worker_qualification_invalid")?;
        let expires_at = millis(&response.expires_at)?;
        let qualified_at = millis(&response.qualified_at)?;
        if response.device_id != worker.device_id
            || response.session_id != worker.session_id
            || response.authorization_epoch != worker.authorization_epoch
            || response.model_key != profile.model_key()
            || spec != qualified.specification()
            || response.config_sha256 != canonical_hash(&specification["entries"])?
            || serde_json::to_value(&response.input_kind)
                .map_err(|_| "worker_qualification_invalid")?
                != specification["fixtureKind"]
            || response.binding_sha256 != hash(&spec)
            || response.manifest_sha256 != qualified.manifest_sha256()
            || qualified.report()["runtimeFingerprint"] != response.runtime_fingerprint
            || response.report_sha256 != canonical_hash(qualified.report())?
            || qualified_at > at + 120_000
            || expires_at <= at
            || expires_at <= qualified_at
            || expires_at > qualified_at + 3_600_000
        {
            return Err("worker_qualification_invalid".into());
        }
        let accepted = Self {
            authority: ChallengeAuthority::from_worker(worker),
            id: response.id,
            model_key: response.model_key,
            config_sha256: response.config_sha256,
            input_kind: response.input_kind,
            binding_sha256: response.binding_sha256,
            manifest_sha256: response.manifest_sha256,
            runtime_fingerprint: response.runtime_fingerprint,
            report_sha256: response.report_sha256,
            expires_at,
        };
        accepted.validate_authority(worker, at)?;
        Ok(accepted)
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn validate_authority(&self, worker: &SavedWorker, at: i64) -> Result<(), String> {
        // Accepted evidence survives token renewal; a new sign-in replaces the session UUID.
        if !self.authority.matches_association(worker)
            || at >= self.expires_at
            || millis(&worker.expires_at)? <= at
        {
            return Err("worker_qualification_association_changed_or_expired".into());
        }
        Ok(())
    }
    pub fn validate_runtime(&self, qualified: &QualifiedRuntime, at: i64) -> Result<(), String> {
        if at >= self.expires_at
            || qualified.manifest_sha256() != self.manifest_sha256
            || hash(qualified.specification()) != self.binding_sha256
            || qualified.report()["runtimeFingerprint"] != self.runtime_fingerprint
            || canonical_hash(qualified.report())? != self.report_sha256
        {
            return Err("worker_qualified_runtime_changed_or_expired".into());
        }
        Ok(())
    }
    pub fn validate_task(
        &self,
        worker: &SavedWorker,
        task: &ClaimedTask,
        at: i64,
    ) -> Result<(), String> {
        self.validate_authority(worker, at)?;
        task.validate_result_at(worker, std::slice::from_ref(&self.model_key), at)?;
        if task.qualification_id != self.id
            || millis(&task.qualification_expires_at)? != self.expires_at
            || task.config_sha256 != self.config_sha256
            || task.input_kind != self.input_kind
        {
            return Err("worker_task_qualification_changed".into());
        }
        Ok(())
    }
}

const MAX_INPUT: usize = 16 * 1024 * 1024;
fn millis(value: &str) -> Result<i64, String> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|v| (v.unix_timestamp_nanos() / 1_000_000) as i64)
        .map_err(|_| "worker_deadline_invalid".into())
}
fn now() -> Result<i64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock_invalid")?
        .as_millis() as i64)
}
fn hash(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimedTask {
    pub id: String,
    pub task_id: String,
    pub device_id: String,
    pub session_id: String,
    pub authorization_epoch: u32,
    pub generation: u32,
    pub qualification_id: String,
    pub qualification_expires_at: String,
    pub model_key: String,
    pub config_json: String,
    pub config_sha256: String,
    pub input_sha256: String,
    pub input_kind: InputKind,
    pub max_input_bytes: usize,
    pub expires_at: String,
    pub execution_deadline: String,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InputKind {
    Text,
    Image,
}
impl ClaimedTask {
    pub fn validate_at(
        &self,
        saved: &SavedWorker,
        qualified: &[String],
        now: i64,
    ) -> Result<(), String> {
        self.validate_result_at(saved, qualified, now)?;
        if millis(&self.expires_at)? <= now {
            return Err("worker_lease_expired".into());
        }
        Ok(())
    }
    pub fn validate_result_at(
        &self,
        saved: &SavedWorker,
        qualified: &[String],
        now: i64,
    ) -> Result<(), String> {
        let expires = millis(&self.expires_at)?;
        let deadline = millis(&self.execution_deadline)?;
        let qualification_expiry = millis(&self.qualification_expires_at)?;
        let config: serde_json::Value =
            serde_json::from_str(&self.config_json).map_err(|_| "worker_config_invalid")?;
        if self.device_id != saved.device_id
            || self.session_id != saved.session_id
            || self.authorization_epoch != saved.authorization_epoch
            || Uuid::parse_str(&self.id).is_err()
            || Uuid::parse_str(&self.task_id).is_err()
            || Uuid::parse_str(&self.qualification_id).is_err()
            || qualification_expiry <= now
            || qualification_expiry < expires
            || self.generation == 0
            || self.generation > 2_147_483_647
            || self.model_key.len() > 256
            || !qualified.contains(&self.model_key)
            || !config.is_object()
            || self.config_json.len() > 65_536
            || hash(self.config_json.as_bytes()) != self.config_sha256
            || self.input_sha256.len() != 64
            || !self
                .input_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.max_input_bytes == 0
            || self.max_input_bytes > MAX_INPUT
            || deadline <= now
            || deadline < expires
            || deadline > now + 720_000
        {
            return Err("worker_claim_invalid".into());
        }
        Ok(())
    }
    pub fn renew_lease(&mut self, expires_at: &str, now: i64) -> Result<(), String> {
        let expires = millis(expires_at)?;
        if expires <= now
            || expires > millis(&self.execution_deadline)?
            || expires > millis(&self.qualification_expires_at)?
        {
            return Err("worker_lease_invalid".into());
        }
        self.expires_at = expires_at.into();
        Ok(())
    }
    pub fn verify_input(&self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty()
            || bytes.len() > self.max_input_bytes
            || hash(bytes) != self.input_sha256
        {
            return Err("worker_input_invalid".into());
        }
        Ok(())
    }
}
#[derive(Deserialize)]
struct ClaimResponse {
    task: Option<ClaimedTask>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ack {
    accepted: bool,
    expires_at: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerFailure {
    InferenceFailed,
    InputInvalid,
    ModelUnavailable,
    Cancelled,
}

// Leave room for the 20-second claim and the longest ten-minute execution.
const RENEW_BEFORE_MS: i64 = 15 * 60 * 1000;
fn renewal_due(worker: &SavedWorker, at: i64) -> Result<bool, String> {
    let remaining = millis(&worker.expires_at)? - at;
    if remaining <= 0 || worker.next_sequence == 0 || worker.next_sequence > 2_147_483_647 {
        return Err("worker_session_renewal_required".into());
    }
    Ok(remaining <= RENEW_BEFORE_MS || worker.next_sequence >= 2_147_483_646)
}
fn renewed_worker(
    worker: &SavedWorker,
    response: &SessionResponse,
    at: i64,
) -> Result<SavedWorker, String> {
    let renewed = bind_renewal(worker, response)?;
    let remaining = millis(&renewed.expires_at)? - at;
    if renewed.worker_token == worker.worker_token
        || remaining <= RENEW_BEFORE_MS
        || remaining > 3_720_000
    {
        return Err("worker_session_response_invalid".into());
    }
    Ok(renewed)
}

struct Connection {
    client: Client,
    base: Url,
    worker: SavedWorker,
    identity: DeviceIdentity,
}
impl Connection {
    async fn ensure_current(&mut self) -> Result<(), String> {
        if renewal_due(&self.worker, now()?)? {
            self.renew().await?;
        }
        Ok(())
    }
    async fn renew(&mut self) -> Result<(), String> {
        let response = self
            .request(Method::POST, "api/desktop/worker/session", "renew", "{}")
            .await?;
        let session: SessionResponse = transport::json(response).await?;
        let worker = renewed_worker(&self.worker, &session, now()?)?;
        credentials::save_worker_checkpoint(&self.worker, &worker)?;
        self.worker = worker;
        Ok(())
    }
    async fn request(
        &mut self,
        method: Method,
        path: &str,
        operation: &str,
        payload: &str,
    ) -> Result<Response, String> {
        let expected = self.worker.clone();
        let proof = reserve_proof(
            &mut self.worker,
            &self.identity,
            operation,
            payload,
            |value| credentials::save_worker_checkpoint(&expected, value),
        )?;
        let header =
            STANDARD.encode(serde_json::to_vec(&proof).map_err(|_| "worker_proof_invalid")?);
        let mut request = self
            .client
            .request(
                method.clone(),
                self.base.join(path).map_err(|_| "worker_path_invalid")?,
            )
            .bearer_auth(&self.worker.worker_token)
            .header("x-frameleaf-desktop-proof", header);
        if method == Method::POST {
            request = request.json(&serde_json::json!({"payload":payload}));
        }
        request
            .send()
            .await
            .map_err(|_| "worker_request_interrupted".into())
    }
}

pub struct WorkerTransport(Mutex<Connection>);

fn qualification_refusal(status: u16, message: &str) -> Option<String> {
    if status == 409
        && matches!(
            message,
            "desktop_nas_producer_unavailable"
                | "desktop_nas_face_producer_unavailable"
                | "desktop_nas_fixture_mismatch"
                | "desktop_nas_model_unavailable"
                | "desktop_nas_producer_changed"
                | "desktop_nas_producer_expired"
                | "desktop_model_profile_unavailable"
                | "desktop_model_profile_changed"
                | "desktop_clip_profile_unavailable"
                | "desktop_face_profile_unavailable"
                | "desktop_clip_space_unavailable"
                | "desktop_clip_index_changed"
                | "desktop_clip_index_dimensions"
                | "desktop_clip_index_incompatible"
                | "desktop_clip_index_invalid"
                | "desktop_pool_config_changed"
                | "desktop_pool_destination_changed"
                | "desktop_pool_model_unavailable"
                | "desktop_pool_route_changed"
                | "desktop_route_review_required"
        )
    {
        Some(format!("workload_{message}"))
    } else {
        None
    }
}
#[test]
fn scopes_only_explicit_model_refusals_to_one_workload() {
    assert_eq!(
        qualification_refusal(409, "desktop_nas_face_producer_unavailable").as_deref(),
        Some("workload_desktop_nas_face_producer_unavailable")
    );
    for (status, message) in [
        (401, "desktop_nas_face_producer_unavailable"),
        (403, "desktop_pool_policy_required"),
        (409, "desktop_pool_policy_changed"),
        (409, "desktop_worker_activation_invalid"),
        (409, "desktop_runtime_attestation_invalid"),
        (500, "desktop_nas_face_producer_unavailable"),
    ] {
        assert!(qualification_refusal(status, message).is_none());
    }
}
async fn qualification_json<T: serde::de::DeserializeOwned>(
    mut response: Response,
    limit: usize,
) -> Result<T, String> {
    if response.status().as_u16() == 409 {
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "server_response_interrupted")?
        {
            if bytes.len() + chunk.len() > 4096 {
                return Err("server_response_too_large".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "server_response_invalid")?;
        return Err(
            qualification_refusal(409, value["message"].as_str().unwrap_or(""))
                .unwrap_or("server_http_409".into()),
        );
    }
    transport::json_limit(response, limit).await
}
fn claim_models(
    qualifications: &[&AcceptedQualification],
    worker: &SavedWorker,
    at: i64,
) -> Result<Vec<String>, String> {
    if qualifications.is_empty() || qualifications.len() > 64 {
        return Err("worker_models_unavailable".into());
    }
    let mut keys = Vec::new();
    for qualification in qualifications {
        qualification.validate_authority(worker, at)?;
        if keys.contains(&qualification.model_key) {
            return Err("worker_models_ambiguous".into());
        }
        keys.push(qualification.model_key.clone());
    }
    Ok(keys)
}
fn bind_claim(
    qualifications: &[&AcceptedQualification],
    task: &ClaimedTask,
    worker: &SavedWorker,
    at: i64,
) -> Result<usize, String> {
    let keys = claim_models(qualifications, worker, at)?;
    task.validate_at(worker, &keys, at)?;
    let index = qualifications
        .iter()
        .position(|q| q.model_key == task.model_key && q.id == task.qualification_id)
        .ok_or("worker_task_qualification_changed")?;
    qualifications[index].validate_task(worker, task, at)?;
    Ok(index)
}
impl WorkerTransport {
    pub(crate) async fn model_inventory(
        &self,
        source: &str,
        provider: &str,
    ) -> Result<serde_json::Value, String> {
        let mut connection = self.0.lock().await;
        connection.ensure_current().await?;
        let payload =
            serde_json::json!({"runtimeSourceRevision":source,"provider":provider}).to_string();
        let response = connection
            .request(
                Method::POST,
                "api/desktop/worker/models",
                "models",
                &payload,
            )
            .await?;
        transport::json_limit(response, 65_536).await
    }
    pub(crate) async fn maintain_session(&self) -> Result<(), String> {
        self.0.lock().await.ensure_current().await
    }
    pub fn load(saved: &SavedConnection) -> Result<Self, String> {
        let worker: SavedWorker =
            credentials::load("worker-session")?.ok_or("worker_session_required")?;
        if worker.server_id != saved.server_id
            || worker.account_id != saved.account_id
            || Some(&worker.device_id) != saved.device_id.as_ref()
            || saved.mode != "client-worker"
        {
            return Err("worker_association_changed".into());
        }
        let identity = credentials::load("installation")?.ok_or("installation_identity_missing")?;
        Ok(Self(Mutex::new(Connection {
            client: transport::client()?,
            base: normalize_server(&saved.server)?,
            worker,
            identity,
        })))
    }
    pub async fn request_qualification(
        &self,
        profile: &ApprovedProfile,
        attestation: &RuntimeAttestation,
        request_id: &str,
    ) -> Result<QualificationChallenge, String> {
        let id = Uuid::parse_str(request_id).map_err(|_| "worker_challenge_request_invalid")?;
        if id.get_version_num() != 4 || id.to_string() != request_id {
            return Err("worker_challenge_request_invalid".into());
        }
        let payload = serde_json::json!({ "requestId":request_id, "modelKey":profile.model_key(),
            "provider":profile.provider(), "runtimeSourceRevision":profile.runtime_source_revision(), "runtime":attestation }).to_string();
        if payload.len() > 4 * 1024 * 1024 {
            return Err("worker_payload_invalid".into());
        }
        let mut connection = self.0.lock().await;
        connection.ensure_current().await?;
        let response = connection
            .request(
                Method::POST,
                "api/desktop/worker/challenges",
                "challenge",
                &payload,
            )
            .await?;
        let value: serde_json::Value = qualification_json(response, 4 * 1024 * 1024).await?;
        let raw = serde_json::to_vec(&value).map_err(|_| "worker_challenge_invalid")?;
        QualificationChallenge::bind(&connection.worker, profile, attestation, &raw, now()?)
    }
    pub async fn read_qualification(
        &self,
        profile: &ApprovedProfile,
        attestation: &RuntimeAttestation,
        id: &str,
    ) -> Result<QualificationChallenge, String> {
        profile.challenge(id)?;
        let mut connection = self.0.lock().await;
        let response = connection
            .request(
                Method::GET,
                &format!("api/desktop/worker/challenges/{id}"),
                &format!("challenge:{id}"),
                "",
            )
            .await?;
        let value: serde_json::Value = transport::json_limit(response, 4 * 1024 * 1024).await?;
        let raw = serde_json::to_vec(&value).map_err(|_| "worker_challenge_invalid")?;
        let challenge =
            QualificationChallenge::bind(&connection.worker, profile, attestation, &raw, now()?)?;
        if challenge.id() != id {
            return Err("worker_challenge_invalid".into());
        }
        Ok(challenge)
    }
    pub async fn submit_qualification(
        &self,
        challenge: &QualificationChallenge,
        qualified: &QualifiedRuntime,
    ) -> Result<bool, String> {
        let mut connection = self.0.lock().await;
        challenge.validate_submission(&connection.worker, qualified, now()?)?;
        let payload = serde_json::json!({"report":qualified.report()}).to_string();
        if payload.len() > 4 * 1024 * 1024 {
            return Err("worker_payload_invalid".into());
        }
        let response = connection
            .request(
                Method::POST,
                &format!("api/desktop/worker/challenges/{}/report", challenge.id()),
                &format!("qualification:{}", challenge.id()),
                &payload,
            )
            .await?;
        Ok(qualification_json::<Ack>(response, 65_536).await?.accepted)
    }

    pub async fn read_accepted_qualification(
        &self,
        profile: &ApprovedProfile,
        qualified: &QualifiedRuntime,
        id: &str,
    ) -> Result<AcceptedQualification, String> {
        profile.challenge(id)?;
        let mut connection = self.0.lock().await;
        let response = connection
            .request(
                Method::GET,
                &format!("api/desktop/worker/qualifications/{id}"),
                &format!("accepted-qualification:{id}"),
                "",
            )
            .await?;
        let value: serde_json::Value = qualification_json(response, 65_536).await?;
        let raw = serde_json::to_vec(&value).map_err(|_| "worker_qualification_invalid")?;
        let accepted =
            AcceptedQualification::bind(&connection.worker, profile, qualified, &raw, now()?)?;
        if accepted.id() != id {
            return Err("worker_qualification_invalid".into());
        }
        Ok(accepted)
    }

    pub async fn claim(
        &self,
        qualification: &AcceptedQualification,
    ) -> Result<Option<ClaimedTask>, String> {
        Ok(self
            .claim_many(&[qualification])
            .await?
            .map(|(_, task)| task))
    }
    pub async fn claim_many(
        &self,
        qualifications: &[&AcceptedQualification],
    ) -> Result<Option<(usize, ClaimedTask)>, String> {
        let mut connection = self.0.lock().await;
        let at = now()?;
        let keys = claim_models(qualifications, &connection.worker, at)?;
        connection.ensure_current().await?;
        claim_models(qualifications, &connection.worker, now()?)?;
        let payload = serde_json::json!({"modelKeys":keys,"waitMs":20000}).to_string();
        let response = connection
            .request(Method::POST, "api/desktop/worker/claim", "claim", &payload)
            .await?;
        let claim: ClaimResponse = transport::json_limit(response, 256 * 1024).await?;
        claim
            .task
            .map(|task| {
                Ok((
                    bind_claim(qualifications, &task, &connection.worker, now()?)?,
                    task,
                ))
            })
            .transpose()
    }
    pub async fn input(
        &self,
        task: &ClaimedTask,
        qualification: &AcceptedQualification,
    ) -> Result<Vec<u8>, String> {
        let mut connection = self.0.lock().await;
        qualification.validate_task(&connection.worker, task, now()?)?;
        task.validate_at(
            &connection.worker,
            std::slice::from_ref(&task.model_key),
            now()?,
        )?;
        let mut response = connection
            .request(
                Method::GET,
                &format!("api/desktop/tasks/{}/input", task.id),
                &format!("input:{}", task.id),
                "",
            )
            .await?;
        if !response.status().is_success() {
            return Err(format!("server_http_{}", response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|len| len > task.max_input_bytes as u64)
        {
            return Err("worker_input_too_large".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "worker_input_interrupted")?
        {
            if bytes.len() + chunk.len() > task.max_input_bytes {
                return Err("worker_input_too_large".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        task.verify_input(&bytes)?;
        Ok(bytes)
    }
    async fn acknowledge(
        &self,
        task: &ClaimedTask,
        qualification: &AcceptedQualification,
        path: &str,
        operation: &str,
        payload: String,
    ) -> Result<Ack, String> {
        if payload.len() > 4 * 1024 * 1024 {
            return Err("worker_result_too_large".into());
        }
        let mut connection = self.0.lock().await;
        qualification.validate_task(&connection.worker, task, now()?)?;
        task.validate_result_at(
            &connection.worker,
            std::slice::from_ref(&task.model_key),
            now()?,
        )?;
        let response = connection
            .request(Method::POST, path, operation, &payload)
            .await?;
        transport::json::<Ack>(response).await
    }
    pub async fn heartbeat(
        &self,
        task: &mut ClaimedTask,
        qualification: &AcceptedQualification,
    ) -> Result<bool, String> {
        let ack = self
            .acknowledge(
                task,
                qualification,
                "api/desktop/worker/heartbeat",
                "heartbeat",
                serde_json::json!({"id":task.id}).to_string(),
            )
            .await?;
        if ack.accepted {
            task.renew_lease(
                ack.expires_at.as_deref().ok_or("worker_lease_invalid")?,
                now()?,
            )?;
        }
        Ok(ack.accepted)
    }
    pub async fn complete(
        &self,
        task: &ClaimedTask,
        result: &serde_json::Value,
        qualification: &AcceptedQualification,
    ) -> Result<bool, String> {
        if !result.is_object() {
            return Err("worker_result_invalid".into());
        }
        self.acknowledge(
            task,
            qualification,
            &format!("api/desktop/tasks/{}/result", task.id),
            &format!("result:{}", task.id),
            serde_json::json!({"result":result}).to_string(),
        )
        .await
        .map(|ack| ack.accepted)
    }
    pub async fn fail(
        &self,
        task: &ClaimedTask,
        code: WorkerFailure,
        qualification: &AcceptedQualification,
    ) -> Result<bool, String> {
        self.acknowledge(
            task,
            qualification,
            &format!("api/desktop/tasks/{}/fail", task.id),
            &format!("fail:{}", task.id),
            serde_json::json!({"code":code}).to_string(),
        )
        .await
        .map(|ack| ack.accepted)
    }
    pub async fn renew(&self) -> Result<(), String> {
        self.0.lock().await.renew().await
    }
    pub async fn revoke(&self) -> Result<bool, String> {
        let mut connection = self.0.lock().await;
        let response = connection
            .request(Method::DELETE, "api/desktop/worker/session", "revoke", "")
            .await?;
        Ok(transport::json::<Ack>(response).await?.accepted)
    }
}

#[cfg(test)]
mod renewal_tests {
    use super::*;
    use serde_json::json;

    const AT: i64 = 1_792_094_400_000;
    #[test]
    fn multi_model_claim_selects_only_its_exact_qualification_and_rechecks_every_association() {
        let worker = worker();
        let accepted = |key: &str, id: &str| AcceptedQualification {
            authority: ChallengeAuthority::from_worker(&worker),
            id: id.into(),
            model_key: key.into(),
            config_sha256: hash(b"{}"),
            input_kind: InputKind::Text,
            binding_sha256: "a".repeat(64),
            manifest_sha256: "b".repeat(64),
            runtime_fingerprint: "c".repeat(64),
            report_sha256: "d".repeat(64),
            expires_at: AT + 600000,
        };
        let first = accepted("first", "c1a52b82-60da-4fa2-8814-e028a088206f");
        let mut second = accepted("second", "c4d607b0-20de-4c68-bb05-c68cc5bfecb9");
        let task:ClaimedTask=serde_json::from_value(json!({"id":"a793f54d-394c-49be-af87-509cceddfdd9","taskId":"15ee79b9-c6ab-4d34-bade-67f654136396","deviceId":worker.device_id,"sessionId":worker.session_id,"authorizationEpoch":2,"generation":1,"qualificationId":second.id,"qualificationExpiresAt":"2026-10-15T20:10:00Z","modelKey":"second","configJson":"{}","configSha256":hash(b"{}"),"inputSha256":"e".repeat(64),"inputKind":"text","maxInputBytes":1024,"expiresAt":"2026-10-15T20:01:00Z","executionDeadline":"2026-10-15T20:02:00Z"})).unwrap();
        assert_eq!(
            bind_claim(&[&first, &second], &task, &worker, AT).unwrap(),
            1
        );
        let mut changed = task.clone();
        changed.qualification_id = first.id.clone();
        assert!(bind_claim(&[&first, &second], &changed, &worker, AT).is_err());
        second.authority.account_id = "other".into();
        assert!(bind_claim(&[&first, &second], &task, &worker, AT).is_err());
        assert!(claim_models(&[], &worker, AT).is_err());
        assert!(claim_models(&[&first, &first], &worker, AT).is_err());
        assert!(claim_models(&[&first], &worker, AT + 600000).is_err());
    }
    fn worker() -> SavedWorker {
        serde_json::from_value(
            json!({"serverId":"server","accountId":"account","deviceId":"device",
          "sessionId":"1117c1ca-0495-46e9-b579-f321520c2b1a","authorizationEpoch":2,
          "workerToken":"a".repeat(64),"expiresAt":"2026-10-15T21:00:00Z","nextSequence":1}),
        )
        .unwrap()
    }
    #[test]
    fn renews_before_the_longest_claim_and_execution_or_counter_exhaustion() {
        let mut worker = worker();
        assert!(!renewal_due(&worker, AT + 2_699_999).unwrap());
        assert!(renewal_due(&worker, AT + 2_700_000).unwrap());
        worker.next_sequence = 2_147_483_646;
        assert!(renewal_due(&worker, AT).unwrap());
    }
    #[test]
    fn expired_invalid_or_exhausted_credentials_cannot_attempt_renewal() {
        let mut worker = worker();
        assert!(renewal_due(&worker, AT + 3_600_000).is_err());
        worker.expires_at = "invalid".into();
        assert!(renewal_due(&worker, AT).is_err());
        worker = self::worker();
        for sequence in [0, 2_147_483_648] {
            worker.next_sequence = sequence;
            assert!(renewal_due(&worker, AT).is_err());
        }
    }
    #[test]
    fn renewal_requires_a_new_token_and_a_bounded_future_lifetime_on_the_same_association() {
        let worker = worker();
        let response = json!({"sessionId":worker.session_id,"authorizationEpoch":2,
          "workerToken":"b".repeat(64),"expiresAt":"2026-10-15T21:00:00Z","scopes":["library-inference"]});
        let renewed = renewed_worker(
            &worker,
            &serde_json::from_value(response.clone()).unwrap(),
            AT,
        )
        .unwrap();
        assert_eq!(renewed.worker_token, "b".repeat(64));
        assert_eq!(renewed.next_sequence, 1);
        assert_eq!(renewed.session_id, worker.session_id);
        assert_eq!(renewed.device_id, worker.device_id);
        for (field, value) in [
            ("workerToken", json!("a".repeat(64))),
            ("expiresAt", json!("2026-10-15T20:15:00Z")),
            ("expiresAt", json!("2026-10-15T19:59:00Z")),
            ("expiresAt", json!("2026-10-15T21:03:00Z")),
            ("expiresAt", json!("invalid")),
            ("sessionId", json!("445bc2b6-f4cd-439e-b8bb-7e84d7ee0550")),
            ("authorizationEpoch", json!(3)),
            ("scopes", json!(["photos"])),
        ] {
            let mut changed = response.clone();
            changed[field] = value;
            assert!(
                renewed_worker(&worker, &serde_json::from_value(changed).unwrap(), AT).is_err(),
                "{field}"
            );
        }
    }
}

#[cfg(test)]
mod native_nas_tests;
