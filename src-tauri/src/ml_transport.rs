use crate::{
    connection::{normalize_server, DeviceIdentity, SavedConnection},
    credentials, transport,
    worker::{bind_renewal, reserve_proof_at, SavedWorker, SessionResponse},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{Client, Method, Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

use crate::{
    model_catalogue::ApprovedProfile,
    native_runtime::QualifiedRuntime,
    runtime_store::{InstalledRuntime, RuntimeAttestation, Staging},
};

// Every field is compared with what this computer derives itself; a field a newer server adds
// is not one of them and is ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
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
    qualified_at: i64,
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
            qualified_at,
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
    /// Record the observed fixture result without persisting association details or raw reports.
    pub(crate) fn write_evidence(
        &self,
        root: &std::path::Path,
        app_version: &str,
        profile: &ApprovedProfile,
        installed: &InstalledRuntime,
        qualified: &QualifiedRuntime,
        // The server's time (`WorkerTransport::now`), as when the grant was bound.
        at: i64,
    ) -> Result<(), String> {
        self.validate_runtime(qualified, at)?;
        let report = qualified.report();
        let provider = installed.provider();
        if profile.model_key() != self.model_key
            || report["provider"] != provider
            || profile.runtime_source_revision() != installed.source_revision()
            || installed.manifest_sha256() != self.manifest_sha256
        {
            return Err("worker_qualification_evidence_mismatch".into());
        }
        let evidence = serde_json::json!({
            "schemaVersion": 1,
            "kind": "nas-accepted-native-fixture",
            "targetOs": std::env::consts::OS,
            "targetArch": std::env::consts::ARCH,
            "appVersion": app_version,
            "modelKey": self.model_key,
            "modelName": profile.model_name(),
            "modelSnapshotRevision": profile.model_snapshot_revision(),
            "provider": provider,
            "executionState": report["state"],
            "runtimeSourceRevision": installed.source_revision(),
            "runtimeEpoch": installed.epoch(),
            "manifestSha256": self.manifest_sha256,
            "runtimeFingerprint": self.runtime_fingerprint,
            "qualificationId": self.id,
            "qualifiedAtUnixMs": self.qualified_at,
            "expiresAtUnixMs": self.expires_at,
            "inputKind": self.input_kind,
            "configSha256": self.config_sha256,
            "fixtureSha256": report["fixtureSha256"],
            "preprocessingSha256": report["preprocessingSha256"],
            "bindingSha256": self.binding_sha256,
            "reportSha256": self.report_sha256,
        });
        let name = hash(format!("{}\0{provider}", self.model_key).as_bytes());
        crate::runtime_store::private_directory(root)?;
        let staging = Staging::create(root.join(format!(".pending-{}", Uuid::new_v4())))?;
        let staged = staging.path().join("evidence.json");
        let bytes = serde_json::to_vec_pretty(&evidence)
            .map_err(|_| "worker_qualification_evidence_encode_failed")?;
        crate::runtime_store::write_new(&staged, &bytes)?;
        std::fs::rename(staged, root.join(format!("{name}.json")))
            .map_err(|_| "worker_qualification_evidence_write_failed".into())
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
    /// Durable sequence and token checkpoints; tests keep them out of the OS credential store.
    checkpoint: fn(&SavedWorker, &SavedWorker) -> Result<(), String>,
    /// The server's clock, kept current from every response.
    clock: Arc<ServerClock>,
    /// The server understands `reportWithdrawn` on a claim (`features.workerWithdrawalNotice`).
    report_withdrawn: bool,
}
/// How far the server's clock is ahead of this computer's (`transport::clock_skew`), and when
/// that was read. The difference only holds while this computer's clock keeps time: after it is
/// corrected, or the computer sleeps, the server's time is read again before it is relied on.
#[derive(Default)]
pub(crate) struct ServerClock {
    skew_ms: AtomicI64,
    read: std::sync::Mutex<Option<(SystemTime, std::time::Instant)>>,
}
/// This computer's clock moved against steady time by more than the server tolerates being
/// guessed: it was set, or the computer slept.
fn clock_moved(wall_elapsed_ms: i64, steady_elapsed_ms: i64) -> bool {
    (wall_elapsed_ms - steady_elapsed_ms).abs() > 30_000
}
impl ServerClock {
    /// As after the OS set this computer's clock an hour forward, with the old difference kept.
    #[cfg(test)]
    fn set_back_an_hour_ago(&self) {
        let hour = std::time::Duration::from_secs(3600);
        *self.read.lock().unwrap() = Some((SystemTime::now() - hour, std::time::Instant::now()));
    }
    fn set(&self, skew_ms: i64) {
        self.skew_ms.store(skew_ms, Ordering::Release);
        *self.read.lock().unwrap() = Some((SystemTime::now(), std::time::Instant::now()));
    }
    fn skew_ms(&self) -> i64 {
        self.skew_ms.load(Ordering::Acquire)
    }
    fn suspect(&self) -> bool {
        let Some((wall, steady)) = *self.read.lock().unwrap() else {
            return false;
        };
        let wall_elapsed = match SystemTime::now().duration_since(wall) {
            Ok(forward) => forward.as_millis() as i64,
            Err(back) => -(back.duration().as_millis() as i64),
        };
        clock_moved(wall_elapsed, steady.elapsed().as_millis() as i64)
    }
}
#[test]
fn a_corrected_clock_or_a_sleep_makes_the_server_time_be_read_again() {
    // Ordinary running: both clocks advance together.
    assert!(!clock_moved(600_000, 600_000));
    assert!(!clock_moved(600_000, 590_000));
    // The OS set the clock forward or back by an hour.
    assert!(clock_moved(3_600_000 + 5_000, 5_000));
    assert!(clock_moved(-3_600_000 + 5_000, 5_000));
    // The computer slept: wall time passed, steady time did not.
    assert!(clock_moved(1_800_000, 2_000));
    let clock = ServerClock::default();
    assert!(!clock.suspect());
    clock.set(3_600_000);
    assert_eq!(clock.skew_ms(), 3_600_000);
    assert!(!clock.suspect());
}
impl Connection {
    /// The server's time now. Every deadline it sends is read against this, and every request is
    /// timed by it, so a wrong clock on this computer does not stop the worker.
    fn now(&self) -> Result<i64, String> {
        Ok(now()? + self.clock.skew_ms())
    }
    /// After this computer's clock moved, ask the server the time again before judging any
    /// deadline: one unsigned request whose `Date` header is all that is read. When the server
    /// can't be asked, no deadline is judged by a difference that may no longer hold: the
    /// caller gets the same error as for any request that did not get through.
    async fn resync(&mut self) -> Result<(), String> {
        if !self.clock.suspect() {
            return Ok(());
        }
        let url = self
            .base
            .join("api/server/ping")
            .map_err(|_| "worker_path_invalid")?;
        let asked = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            self.client.get(url).send().await
        });
        let Ok(Ok(response)) = asked.await else {
            return Err("worker_request_interrupted".into());
        };
        match transport::clock_skew(&response) {
            Some(skew) => self.clock.set(skew),
            // No usable `Date`, and no correction was in use: this computer's clock is all
            // there is to go by, as it was before.
            None if self.clock.skew_ms() == 0 => self.clock.set(0),
            // A correction was in use and can't be confirmed (a proxy's page, a broken
            // header): judge nothing by it; ask again on the next call.
            None => return Err("worker_request_interrupted".into()),
        }
        Ok(())
    }
    async fn ensure_current(&mut self) -> Result<(), String> {
        self.resync().await?;
        if renewal_due(&self.worker, self.now()?)? {
            self.renew().await?;
        }
        Ok(())
    }
    async fn renew(&mut self) -> Result<(), String> {
        let response = self
            .request(Method::POST, "api/desktop/worker/session", "renew", "{}")
            .await?;
        let session: SessionResponse = worker_json(response, 65_536).await?;
        let worker = renewed_worker(&self.worker, &session, self.now()?)?;
        (self.checkpoint)(&self.worker, &worker)?;
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
        let checkpoint = self.checkpoint;
        let proof = reserve_proof_at(
            &mut self.worker,
            &self.identity,
            operation,
            payload,
            self.clock.skew_ms(),
            |value| checkpoint(&expected, value),
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
        let response = request
            .send()
            .await
            .map_err(|_| "worker_request_interrupted")?;
        if let Some(skew) = transport::clock_skew(&response) {
            self.clock.set(skew);
        }
        Ok(response)
    }
}

/// One signed request at a time, in sequence order: the lock is held from the moment a sequence
/// number is reserved until that request's response has arrived, so a heartbeat and a result can
/// never reach the server out of order (it refuses the lower sequence).
pub struct WorkerTransport(Mutex<Connection>, Arc<ServerClock>);

/// A refusal of one task's model, by name. The others carry on.
fn qualification_refusal(message: &str) -> Option<String> {
    match message {
        // Only servers from before desktop auto-setup refuse a task over their own AI or its
        // routing: the fix is a server update, never a setting on this computer.
        "desktop_nas_producer_unavailable"
        | "desktop_nas_face_producer_unavailable"
        | "desktop_nas_fixture_mismatch"
        | "desktop_nas_model_unavailable"
        | "desktop_nas_producer_changed"
        | "desktop_nas_producer_expired"
        | "desktop_pool_config_changed"
        | "desktop_pool_destination_changed"
        | "desktop_pool_route_changed"
        | "desktop_route_review_required" => Some("workload_server_update_required".into()),
        "desktop_model_profile_unavailable"
        | "desktop_model_profile_changed"
        | "desktop_clip_profile_unavailable"
        | "desktop_face_profile_unavailable"
        | "desktop_clip_space_unavailable"
        | "desktop_clip_index_changed"
        | "desktop_clip_index_dimensions"
        | "desktop_clip_index_incompatible"
        | "desktop_clip_index_invalid"
        | "desktop_pool_model_unavailable"
        // The server withdrew this model after failed tasks and takes no new check for it
        // for five minutes. The other tasks carry on.
        | "desktop_qualification_hold" => Some(format!("workload_{message}")),
        _ => None,
    }
}
#[test]
fn scopes_only_explicit_model_refusals_to_one_workload() {
    assert_eq!(
        qualification_refusal("desktop_model_profile_unavailable").as_deref(),
        Some("workload_desktop_model_profile_unavailable")
    );
    assert_eq!(
        qualification_refusal("desktop_qualification_hold").as_deref(),
        Some("workload_desktop_qualification_hold")
    );
    // An older server's refusals over its own AI or routing ask for a server update.
    for message in [
        "desktop_nas_face_producer_unavailable",
        "desktop_route_review_required",
        "desktop_pool_route_changed",
    ] {
        assert_eq!(
            qualification_refusal(message).as_deref(),
            Some("workload_server_update_required")
        );
    }
    for message in [
        "desktop_pool_policy_required",
        "desktop_pool_policy_changed",
        "desktop_worker_activation_invalid",
        "desktop_runtime_attestation_invalid",
        "Internal server error",
        "",
    ] {
        assert!(qualification_refusal(message).is_none());
    }
}
/// Refusals the worker acts on, by the server's `message`. The HTTP status is not part of the
/// name: servers have sent the same refusal under different statuses (policy-off as 401, 403 and
/// 409), and the name is what both sides agree on (docs/desktop-worker-setup-protocol.md).
/// A refusal without a known name stays `server_http_<status>`.
///
/// `desktop_worker_credential_invalid` here is about the worker session, never the device: only
/// issuing a new session (`session_refusal`) can show that the device itself is refused.
pub(crate) fn worker_refusal(status: u16, message: &str) -> String {
    let code = match message {
        "desktop_worker_credential_invalid" => "worker_session_rejected",
        "desktop_lease_invalid" => "worker_lease_refused",
        "desktop_pool_policy_required" => "worker_policy_required",
        "desktop_worker_lan_required" => "worker_lan_required",
        "desktop_pool_policy_changed" => "worker_policy_changed",
        "desktop_runtime_attestation_invalid" => "worker_runtime_unsigned",
        "desktop_qualification_report_invalid" => "worker_qualification_report_refused",
        // The challenge or qualification is no longer the server's (it expired, or was issued
        // to a session since replaced): ask for a new challenge for that model.
        "desktop_challenge_invalid"
        | "desktop_qualification_invalid"
        | "desktop_worker_activation_invalid" => "worker_qualification_restart",
        // The same answer every time for this model and runtime (its fixture is too large, or
        // the runtime is not the one this device enrolled): tried a few times, then named.
        "desktop_challenge_too_large" | "desktop_challenge_runtime_invalid" => {
            "worker_challenge_rejected"
        }
        // The server refuses a request timed more than two minutes from its own clock.
        "desktop_proof_expired" => "clock_invalid",
        // On a claim: one of the models asked for was withdrawn from this computer after
        // failed tasks. (On a challenge or report the same name is that model's hold.)
        "desktop_qualification_hold" => "worker_model_withdrawn",
        // Challenge bookkeeping the server clears by itself: ask again shortly.
        "desktop_challenge_conflict"
        | "desktop_challenge_capacity"
        | "desktop_qualification_capacity"
        // The grant collided with another one being published: the server says to retry.
        | "desktop_clip_publication_isolation" => "worker_challenge_busy",
        _ => return format!("server_http_{status}"),
    };
    code.into()
}
/// A refusal to issue a worker session (`POST /api/desktop/devices/session`). The policy and
/// home-network refusals keep the names the worker waits out; a refused credential here is the
/// device or its sign-in, which a new session cannot cure.
pub(crate) fn session_refusal(status: u16, message: &str) -> String {
    match message {
        "desktop_worker_credential_invalid" | "desktop_identity_revoked_or_changed" => {
            "worker_device_refused".into()
        }
        "desktop_worker_photo_session_required" | "desktop_photo_session_required" => {
            "worker_sign_in_required".into()
        }
        // Any other 401 here is the server's ordinary sign-in check, before the device is
        // looked at: the photo sign-in has expired.
        _ if status == 401 && !message.starts_with("desktop_") => "worker_sign_in_required".into(),
        _ => worker_refusal(status, message),
    }
}
#[test]
fn refusals_are_named_by_message_whatever_the_status() {
    for (status, message, expected) in [
        (
            400,
            "desktop_runtime_attestation_invalid",
            "worker_runtime_unsigned",
        ),
        (
            400,
            "desktop_qualification_report_invalid",
            "worker_qualification_report_refused",
        ),
        // Policy-off has been a 401, a 403 and a 409 on different endpoints and servers.
        (
            401,
            "desktop_pool_policy_required",
            "worker_policy_required",
        ),
        (
            403,
            "desktop_pool_policy_required",
            "worker_policy_required",
        ),
        (
            409,
            "desktop_pool_policy_required",
            "worker_policy_required",
        ),
        (
            401,
            "desktop_challenge_invalid",
            "worker_qualification_restart",
        ),
        (
            401,
            "desktop_qualification_invalid",
            "worker_qualification_restart",
        ),
        (
            401,
            "desktop_worker_activation_invalid",
            "worker_qualification_restart",
        ),
        (409, "desktop_challenge_conflict", "worker_challenge_busy"),
        (409, "desktop_challenge_capacity", "worker_challenge_busy"),
        (
            409,
            "desktop_challenge_too_large",
            "worker_challenge_rejected",
        ),
        (
            409,
            "desktop_challenge_runtime_invalid",
            "worker_challenge_rejected",
        ),
        (
            409,
            "desktop_qualification_capacity",
            "worker_challenge_busy",
        ),
        (
            500,
            "desktop_qualification_capacity",
            "worker_challenge_busy",
        ),
        (
            409,
            "desktop_clip_publication_isolation",
            "worker_challenge_busy",
        ),
        (401, "desktop_lease_invalid", "worker_lease_refused"),
        (400, "other", "server_http_400"),
        (500, "Internal server error", "server_http_500"),
    ] {
        assert_eq!(
            worker_refusal(status, message),
            expected,
            "{status} {message}"
        );
    }
    // Issuing a session: policy and network keep their names, a refused device is not a
    // session to reissue, and an ended sign-in is named.
    for (status, message, expected) in [
        (
            401,
            "desktop_pool_policy_required",
            "worker_policy_required",
        ),
        (
            403,
            "desktop_pool_policy_required",
            "worker_policy_required",
        ),
        (403, "desktop_worker_lan_required", "worker_lan_required"),
        (
            401,
            "desktop_worker_credential_invalid",
            "worker_device_refused",
        ),
        (
            409,
            "desktop_identity_revoked_or_changed",
            "worker_device_refused",
        ),
        (
            403,
            "desktop_worker_photo_session_required",
            "worker_sign_in_required",
        ),
        (503, "", "server_http_503"),
        // A timestamp the server refuses, named apart from a refused device.
        (401, "desktop_proof_expired", "clock_invalid"),
        // The photo sign-in expired: refused by the ordinary sign-in check, with its own words.
        (401, "Authentication required", "worker_sign_in_required"),
        (401, "", "worker_sign_in_required"),
        (
            401,
            "desktop_pool_policy_required",
            "worker_policy_required",
        ),
    ] {
        assert_eq!(
            session_refusal(status, message),
            expected,
            "{status} {message}"
        );
    }
}
use transport::refused;
async fn worker_json<T: serde::de::DeserializeOwned>(
    response: Response,
    limit: usize,
) -> Result<T, String> {
    if !response.status().is_success() {
        let (status, message) = refused(response).await;
        return Err(worker_refusal(status, &message));
    }
    transport::json_limit(response, limit).await
}
async fn qualification_json<T: serde::de::DeserializeOwned>(
    response: Response,
    limit: usize,
) -> Result<T, String> {
    if !response.status().is_success() {
        let (status, message) = refused(response).await;
        return Err(
            qualification_refusal(&message).unwrap_or_else(|| worker_refusal(status, &message))
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
        // Protocol 2: the reply carries the server's catalogue profile of each model it selected.
        let payload = serde_json::json!({"runtimeSourceRevision":source,"provider":provider,"protocolVersion":2})
            .to_string();
        let response = connection
            .request(
                Method::POST,
                "api/desktop/worker/models",
                "models",
                &payload,
            )
            .await?;
        // Each profile carries its fixture (up to 2 MiB, base64): room for every task's profiles.
        worker_json(response, 32 * 1024 * 1024).await
    }
    pub(crate) async fn maintain_session(&self) -> Result<(), String> {
        self.0.lock().await.ensure_current().await
    }
    /// The server's time now, in milliseconds: this computer's clock corrected by what the
    /// server's own responses say (`transport::clock_skew`).
    pub(crate) fn now(&self) -> Result<i64, String> {
        Ok(now()? + self.1.skew_ms())
    }
    /// Start from the clock difference a response just showed (`Capabilities::clock_skew_ms`),
    /// so the first signed request is already timed by the server's clock.
    pub(crate) fn with_clock_skew(self, clock_skew_ms: i64) -> Self {
        self.1.set(clock_skew_ms);
        self
    }
    /// Ask the server to say so when a claim names a model it has withdrawn from this computer.
    /// Only for a server that advertises it: an older one refuses a claim with a field it
    /// does not know.
    pub(crate) fn with_withdrawal_notice(mut self, supported: bool) -> Self {
        self.0.get_mut().report_withdrawn = supported;
        self
    }
    fn over(connection: Connection) -> Self {
        let clock = connection.clock.clone();
        Self(Mutex::new(connection), clock)
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
        Ok(Self::over(Connection {
            client: transport::client()?,
            base: normalize_server(&saved.server)?,
            worker,
            identity,
            checkpoint: credentials::save_worker_checkpoint,
            clock: Arc::default(),
            report_withdrawn: false,
        }))
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
        QualificationChallenge::bind(
            &connection.worker,
            profile,
            attestation,
            &raw,
            connection.now()?,
        )
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
        let value: serde_json::Value = worker_json(response, 4 * 1024 * 1024).await?;
        let raw = serde_json::to_vec(&value).map_err(|_| "worker_challenge_invalid")?;
        let challenge = QualificationChallenge::bind(
            &connection.worker,
            profile,
            attestation,
            &raw,
            connection.now()?,
        )?;
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
        challenge.validate_submission(&connection.worker, qualified, connection.now()?)?;
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
        let accepted = AcceptedQualification::bind(
            &connection.worker,
            profile,
            qualified,
            &raw,
            connection.now()?,
        )?;
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
        connection.resync().await?;
        let at = connection.now()?;
        let keys = claim_models(qualifications, &connection.worker, at)?;
        connection.ensure_current().await?;
        claim_models(qualifications, &connection.worker, connection.now()?)?;
        let mut payload = serde_json::json!({"modelKeys":keys,"waitMs":20000});
        if connection.report_withdrawn {
            payload["reportWithdrawn"] = true.into();
        }
        let payload = payload.to_string();
        let response = connection
            .request(Method::POST, "api/desktop/worker/claim", "claim", &payload)
            .await?;
        let claim: ClaimResponse = worker_json(response, 256 * 1024).await?;
        claim
            .task
            .map(|task| {
                Ok((
                    bind_claim(qualifications, &task, &connection.worker, connection.now()?)?,
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
        connection.resync().await?;
        qualification.validate_task(&connection.worker, task, connection.now()?)?;
        task.validate_at(
            &connection.worker,
            std::slice::from_ref(&task.model_key),
            connection.now()?,
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
            let (status, message) = refused(response).await;
            return Err(worker_refusal(status, &message));
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
        connection.resync().await?;
        qualification.validate_task(&connection.worker, task, connection.now()?)?;
        task.validate_result_at(
            &connection.worker,
            std::slice::from_ref(&task.model_key),
            connection.now()?,
        )?;
        let response = connection
            .request(Method::POST, path, operation, &payload)
            .await?;
        worker_json::<Ack>(response, 65_536).await
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
                self.now()?,
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
        // A result is only for a lease still held: the last expiry the server granted must be
        // ahead, by the server's time (read again first if this computer's clock moved).
        self.0.lock().await.resync().await?;
        if millis(&task.expires_at)? <= self.now()? {
            return Err("worker_lease_expired".into());
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
        Ok(worker_json::<Ack>(response, 65_536).await?.accepted)
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
            qualified_at: AT,
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
pub(crate) mod native_nas_tests;

#[cfg(test)]
pub(crate) mod household_tests;
