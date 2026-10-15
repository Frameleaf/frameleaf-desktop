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
