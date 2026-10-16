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
    fn matches(&self, worker: &SavedWorker) -> bool {
        self.server_id == worker.server_id
            && self.account_id == worker.account_id
            && self.device_id == worker.device_id
            && self.session_id == worker.session_id
            && self.authorization_epoch == worker.authorization_epoch
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
    pub model_key: String,
    pub config_json: String,
    pub config_sha256: String,
    pub input_sha256: String,
    pub input_kind: InputKind,
    pub max_input_bytes: usize,
    pub expires_at: String,
    pub execution_deadline: String,
}
#[derive(Clone, Deserialize)]
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
        let config: serde_json::Value =
            serde_json::from_str(&self.config_json).map_err(|_| "worker_config_invalid")?;
        if self.device_id != saved.device_id
            || self.session_id != saved.session_id
            || self.authorization_epoch != saved.authorization_epoch
            || Uuid::parse_str(&self.id).is_err()
            || Uuid::parse_str(&self.task_id).is_err()
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
        if expires <= now || expires > millis(&self.execution_deadline)? {
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

struct Connection {
    client: Client,
    base: Url,
    worker: SavedWorker,
    identity: DeviceIdentity,
}
impl Connection {
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
impl WorkerTransport {
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
        let response = connection
            .request(
                Method::POST,
                "api/desktop/worker/challenges",
                "challenge",
                &payload,
            )
            .await?;
        let value: serde_json::Value = transport::json_limit(response, 4 * 1024 * 1024).await?;
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
        Ok(transport::json::<Ack>(response).await?.accepted)
    }

    pub async fn claim(&self, qualified: &[String]) -> Result<Option<ClaimedTask>, String> {
        if qualified.len() > 64 || qualified.iter().any(|m| m.is_empty() || m.len() > 256) {
            return Err("worker_model_scope_invalid".into());
        }
        let payload =
            serde_json::to_string(&serde_json::json!({"modelKeys":qualified,"waitMs":20000}))
                .map_err(|_| "worker_payload_invalid")?;
        let mut connection = self.0.lock().await;
        let response = connection
            .request(Method::POST, "api/desktop/worker/claim", "claim", &payload)
            .await?;
        let claim: ClaimResponse = transport::json_limit(response, 256 * 1024).await?;
        if let Some(task) = &claim.task {
            task.validate_at(&connection.worker, qualified, now()?)?;
        }
        Ok(claim.task)
    }
    pub async fn input(&self, task: &ClaimedTask) -> Result<Vec<u8>, String> {
        let mut connection = self.0.lock().await;
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
        path: &str,
        operation: &str,
        payload: String,
    ) -> Result<Ack, String> {
        if payload.len() > 4 * 1024 * 1024 {
            return Err("worker_result_too_large".into());
        }
        let mut connection = self.0.lock().await;
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
    pub async fn heartbeat(&self, task: &mut ClaimedTask) -> Result<bool, String> {
        let ack = self
            .acknowledge(
                task,
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
    ) -> Result<bool, String> {
        if !result.is_object() {
            return Err("worker_result_invalid".into());
        }
        self.acknowledge(
            task,
            &format!("api/desktop/tasks/{}/result", task.id),
            &format!("result:{}", task.id),
            serde_json::json!({"result":result}).to_string(),
        )
        .await
        .map(|ack| ack.accepted)
    }
    pub async fn fail(&self, task: &ClaimedTask, code: WorkerFailure) -> Result<bool, String> {
        self.acknowledge(
            task,
            &format!("api/desktop/tasks/{}/fail", task.id),
            &format!("fail:{}", task.id),
            serde_json::json!({"code":code}).to_string(),
        )
        .await
        .map(|ack| ack.accepted)
    }
    pub async fn renew(&self) -> Result<(), String> {
        let mut connection = self.0.lock().await;
        let response = connection
            .request(Method::POST, "api/desktop/worker/session", "renew", "{}")
            .await?;
        let session: SessionResponse = transport::json(response).await?;
        let worker = bind_renewal(&connection.worker, &session)?;
        credentials::save_worker_checkpoint(&connection.worker, &worker)?;
        connection.worker = worker;
        Ok(())
    }
    pub async fn revoke(&self) -> Result<bool, String> {
        let mut connection = self.0.lock().await;
        let response = connection
            .request(Method::DELETE, "api/desktop/worker/session", "revoke", "")
            .await?;
        Ok(transport::json::<Ack>(response).await?.accepted)
    }
}
