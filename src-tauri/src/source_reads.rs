//! One source-owned original read, with durable allowances and locally signed resource selection.
use crate::{
    connection::{DeviceIdentity, SavedConnection},
    copy_source::StagedCopy,
    source_import::Journal,
};
use cap_std::{ambient_authority, fs::Dir};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Budget {
    used: u64,
    limit: u64,
}
impl Budget {
    fn reserve(&mut self, bytes: u64, code: &str) -> Result<(), String> {
        self.used = self
            .used
            .checked_add(bytes)
            .filter(|next| *next <= self.limit)
            .ok_or(code)?;
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    resource: StagedCopy,
    read: Budget,
    upload: Budget,
    stage: Option<String>,
}
impl State {
    fn new(resource: StagedCopy, read: u64, upload: u64) -> Result<Self, String> {
        if read > resource.read_cost().saturating_mul(2)
            || upload > resource.bytes.saturating_mul(2)
        {
            return Err("source_read_budget_invalid".into());
        }
        let state = Self {
            resource,
            read: Budget {
                used: 0,
                limit: read,
            },
            upload: Budget {
                used: 0,
                limit: upload,
            },
            stage: None,
        };
        state.validate()?;
        Ok(state)
    }
    fn validate(&self) -> Result<(), String> {
        if self.resource.bytes == 0
            || self.resource.bytes > 2 * 1024 * 1024 * 1024
            || self.resource.read_cost() < self.resource.bytes
            || self.read.limit > 9_007_199_254_740_991
            || self.upload.limit > 9_007_199_254_740_991
            || self.read.used > self.read.limit
            || self.upload.used > self.upload.limit
            || self.stage.as_ref().is_some_and(|id| !canonical_uuid(id))
        {
            return Err("source_read_budget_invalid".into());
        }
        Ok(())
    }
}
fn job_key(key: &str, version: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("{key}\n{version}").as_bytes())
    )
}
fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}
/// A locally approved resource and one OS-owned source lease; no original path comes from a request.
pub struct Job {
    journal: Journal,
    resource: StagedCopy,
    _owner: fs::File,
    source_root: std::path::PathBuf,
    source_identity: String,
    busy: AtomicBool,
}
impl Job {
    /// Allowances come from local user approval, never from a server read claim.
    pub fn approve(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        resource: StagedCopy,
        read_limit: u64,
        upload_limit: u64,
    ) -> Result<Self, String> {
        let consent = crate::source_import::current(saved, identity, resource.source_id())?;
        if consent.approval(saved, identity)?.fingerprint() != resource.scope_fingerprint() {
            return Err("source_approval_changed".into());
        }
        let source = resource.source_id().to_owned();
        let key = resource.resource_key();
        let version = resource.version();
        Self::open(
            base,
            saved,
            identity,
            &source,
            &key,
            &version,
            Some(State::new(resource, read_limit, upload_limit)?),
        )
    }
    pub fn resume(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        source: &str,
        key: &str,
        version: &str,
    ) -> Result<Self, String> {
        let consent = crate::source_import::current(saved, identity, source)?;
        let approval = consent.approval(saved, identity)?;
        if !approval.is_photos()
            && (base.starts_with(approval.root()) || approval.root().starts_with(base))
        {
            return Err("source_staging_overlap".into());
        }
        let job = Self::open(base, saved, identity, source, key, version, None)?;
        if job.resource.scope_fingerprint() != approval.fingerprint() {
            return Err("source_approval_changed".into());
        }
        Ok(job)
    }
    fn open(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        source: &str,
        key: &str,
        version: &str,
        initial: Option<State>,
    ) -> Result<Self, String> {
        if !canonical_uuid(source)
            || !crate::native_runtime::digest_valid(key, 64)
            || !crate::native_runtime::digest_valid(version, 64)
        {
            return Err("source_read_request_invalid".into());
        }
        if let Some(state) = &initial {
            state.resource.validate_current(saved, identity)?;
            state.resource.staging_root(base)?;
        }
        let source_root = base.join("photo-reads").join(source);
        let root = source_root.join(job_key(key, version));
        if initial.is_none() {
            crate::native_runtime::absolute_directory(&root.join("stage"))?;
        }
        crate::runtime_store::private_directory(&base.join("photo-reads"))?;
        crate::runtime_store::private_directory(&source_root)?;
        let dir = Dir::open_ambient_dir(&source_root, ambient_authority())
            .map_err(|_| "source_journal_invalid")?;
        let owner = dir
            .open_with(".owner.lock", &crate::host_state::options(true))
            .map_err(|_| "source_journal_invalid")?
            .into_std();
        crate::host_state::valid_file(&owner)?;
        owner
            .try_lock()
            .map_err(|_| "source_read_already_running")?;
        let source_identity = crate::copy_source::source_root_identity(&dir)?;
        if initial.is_some()
            && fs::read_dir(&source_root)
                .map_err(|_| "source_journal_invalid")?
                .count()
                > 10_000
        {
            return Err("source_inventory_partial".into());
        }
        crate::runtime_store::private_directory(&root)?;
        crate::runtime_store::private_directory(&root.join("stage"))?;
        let journal = Journal { root };
        if let Some(state) = initial {
            match fs::symlink_metadata(journal.root.join("state.json")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err("source_read_budget_already_approved".into()),
            }
            if fs::read_dir(journal.root.join("stage"))
                .map_err(|_| "source_journal_invalid")?
                .next()
                .is_some()
            {
                return Err("source_read_budget_required".into());
            }
            journal.write("state.json", &state, identity)?;
        }
        let state: State = journal.read("state.json", identity)?;
        state.validate()?;
        state.resource.validate_current(saved, identity)?;
        state.resource.staging_root(base)?;
        if state.resource.source_id() != source
            || state.resource.resource_key() != key
            || state.resource.version() != version
        {
            return Err("source_journal_invalid".into());
        }
        Ok(Self {
            journal,
            resource: state.resource,
            _owner: owner,
            source_root,
            source_identity,
            busy: AtomicBool::new(false),
        })
    }
    fn require_owner(&self) -> Result<(), String> {
        crate::native_runtime::absolute_directory(&self.source_root)?;
        let dir = Dir::open_ambient_dir(&self.source_root, ambient_authority())
            .map_err(|_| "source_journal_invalid")?;
        if crate::copy_source::source_root_identity(&dir)? != self.source_identity {
            return Err("source_journal_invalid".into());
        }
        crate::host_state::valid_file(&self._owner)?;
        if self
            ._owner
            .metadata()
            .map_err(|_| "source_journal_invalid")?
            .len()
            != 0
        {
            return Err("source_journal_invalid".into());
        }
        Ok(())
    }
    fn state(&self, saved: &SavedConnection, identity: &DeviceIdentity) -> Result<State, String> {
        self.require_owner()?;
        let state: State = self.journal.read("state.json", identity)?;
        state.validate()?;
        state.resource.validate_current(saved, identity)?;
        if state.resource.source_id() != self.resource.source_id()
            || state.resource.scope_fingerprint() != self.resource.scope_fingerprint()
            || state.resource.resource_key() != self.resource.resource_key()
            || state.resource.version() != self.resource.version()
            || state.resource.bytes != self.resource.bytes
            || state.resource.sha256 != self.resource.sha256
        {
            return Err("source_journal_invalid".into());
        }
        Ok(state)
    }
    fn stage(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        cancelled: &AtomicBool,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<StagedCopy, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("source_copy_cancelled".into());
        }
        gate()?;
        let mut state = self.state(saved, identity)?;
        let stage = self.journal.root.join("stage");
        if let Some(id) = &state.stage {
            match fs::symlink_metadata(stage.join(id)) {
                Ok(_) => {
                    if !stage.join(id).join("receipt.json").exists() {
                        return Err("source_cache_cleanup_pending".into());
                    }
                    let copy = StagedCopy::restore_with_gate(saved, identity, &stage, id, gate)?;
                    if copy.resource_key() != self.resource.resource_key()
                        || copy.version() != self.resource.version()
                        || copy.bytes != self.resource.bytes
                        || copy.sha256 != self.resource.sha256
                    {
                        return Err("source_item_changed".into());
                    }
                    copy.validate_current(saved, identity)?;
                    gate()?;
                    return Ok(copy);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("source_cache_cleanup_pending".into()),
            }
        }
        state
            .read
            .reserve(self.resource.read_cost(), "source_read_budget_exhausted")?;
        let id = uuid::Uuid::new_v4().to_string();
        state.stage = Some(id.clone());
        self.journal.write("state.json", &state, identity)?;
        gate()?;
        self.resource
            .stage_again(saved, identity, &stage, &id, cancelled, gate)
    }
}
struct Busy(Arc<Job>);
impl Drop for Busy {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
    }
}
struct Stop(Arc<AtomicBool>);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
struct Operation {
    owner: Arc<Busy>,
    saved: SavedConnection,
    identity: DeviceIdentity,
    cancelled: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    lease: std::sync::atomic::AtomicU64,
    epoch: u32,
    started: u64,
    policy: std::sync::Mutex<(std::time::Instant, Option<&'static str>)>,
}
impl Operation {
    fn check_stop(&self) -> Result<(), String> {
        if self.cancelled.load(Ordering::Acquire) || self.stop.load(Ordering::Acquire) {
            return Err("source_delivery_interrupted".into());
        }
        let now = crate::resource_bridge::now()?;
        if now < self.started || now >= self.lease.load(Ordering::Acquire) {
            return Err("source_read_request_invalid".into());
        }
        Ok(())
    }
    fn gate(&self) -> Result<(), String> {
        self.check_stop()?;
        let job = &self.owner.0;
        job.require_owner()?;
        let consent =
            crate::source_import::current(&self.saved, &self.identity, job.resource.source_id())?;
        if consent.approval(&self.saved, &self.identity)?.fingerprint()
            != job.resource.scope_fingerprint()
        {
            return Err("source_approval_changed".into());
        }
        crate::resource_bridge::require_current_source(
            &self.saved,
            &self.identity,
            &job.resource,
            self.epoch,
        )?;
        job.resource.validate_current(&self.saved, &self.identity)?;
        let mut policy = self.policy.lock().map_err(|_| "network_unknown")?;
        if policy.0.elapsed() >= std::time::Duration::from_secs(1) {
            *policy = (
                std::time::Instant::now(),
                crate::resource_policy::sample().refusal(64 * 1024 * 1024),
            );
        }
        if let Some(code) = policy.1 {
            return Err(code.into());
        }
        self.check_stop()
    }
    async fn renew(&self, claim: &mut crate::resource_bridge::ReadClaim) -> Result<(), String> {
        let heartbeat = crate::resource_bridge::heartbeat(
            &self.saved,
            &self.identity,
            self.owner.0.resource.source_id(),
            self.owner.0.resource.bytes,
            claim,
        );
        crate::resource_bridge::wait_delivery(heartbeat, &self.stop, &|| self.gate()).await?;
        self.lease.store(claim.lease_expiry()?, Ordering::Release);
        self.gate()
    }
}
async fn keep_alive<T>(
    operation: &Arc<Operation>,
    claim: &mut crate::resource_bridge::ReadClaim,
    work: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let mut tick = tokio::time::interval_at(
        tokio::time::Instant::now() + std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(30),
    );
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut policy = tokio::time::interval(std::time::Duration::from_millis(100));
    policy.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(work);
    loop {
        let result = tokio::select! {
            result=&mut work => return result,
            _=tick.tick() => operation.renew(claim).await,
            _=policy.tick() => operation.gate(),
        };
        if let Err(error) = result {
            operation.stop.store(true, Ordering::Release);
            let _ = work.await;
            return Err(error);
        }
    }
}
impl Job {
    fn begin(self: &Arc<Self>) -> Result<Arc<Busy>, String> {
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "source_read_already_running")?;
        Ok(Arc::new(Busy(self.clone())))
    }
    /// Adds only an explicitly approved allowance; retries cannot erase previous spending.
    pub fn approve_additional(
        self: &Arc<Self>,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        read: u64,
        upload: u64,
    ) -> Result<(), String> {
        let _owner = self.begin()?;
        let consent = crate::source_import::current(saved, identity, self.resource.source_id())?;
        if consent.approval(saved, identity)?.fingerprint() != self.resource.scope_fingerprint() {
            return Err("source_approval_changed".into());
        }
        self.extend(saved, identity, read, upload)
    }
    fn extend(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        read: u64,
        upload: u64,
    ) -> Result<(), String> {
        if (read == 0 && upload == 0)
            || read > self.resource.read_cost().saturating_mul(2)
            || upload > self.resource.bytes.saturating_mul(2)
        {
            return Err("source_read_budget_invalid".into());
        }
        let mut state = self.state(saved, identity)?;
        state.read.limit = state
            .read
            .limit
            .checked_add(read)
            .ok_or("source_read_budget_invalid")?;
        state.upload.limit = state
            .upload
            .limit
            .checked_add(upload)
            .ok_or("source_read_budget_invalid")?;
        state.validate()?;
        self.journal.write("state.json", &state, identity)
    }
    fn reserve_upload(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<(), String> {
        let mut state = self.state(saved, identity)?;
        state
            .upload
            .reserve(self.resource.bytes, "source_upload_budget_exhausted")?;
        self.journal.write("state.json", &state, identity)
    }
    /// Serves one claimed immutable resource. Acceptance is cache publication, never a backup receipt.
    pub async fn serve(
        self: Arc<Self>,
        saved: SavedConnection,
        identity: DeviceIdentity,
        mut claim: crate::resource_bridge::ReadClaim,
        cancelled: Arc<AtomicBool>,
    ) -> Result<bool, String> {
        let owner = self.begin()?;
        if !claim.matches_resource(&self.resource) {
            return Err("source_read_request_invalid".into());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let _shutdown = Stop(stop.clone());
        let operation = Arc::new(Operation {
            owner,
            saved,
            identity,
            cancelled,
            stop,
            lease: std::sync::atomic::AtomicU64::new(claim.lease_expiry()?),
            epoch: claim.authorization_epoch(),
            started: crate::resource_bridge::now()?,
            policy: std::sync::Mutex::new((
                std::time::Instant::now() - std::time::Duration::from_secs(2),
                Some("network_unknown"),
            )),
        });
        operation.renew(&mut claim).await?;
        let worker = operation.clone();
        let stage = tokio::task::spawn_blocking(move || {
            worker
                .owner
                .0
                .stage(&worker.saved, &worker.identity, &worker.stop, &|| {
                    worker.gate()
                })
        });
        let copy = keep_alive(&operation, &mut claim, async move {
            stage.await.map_err(|_| "source_delivery_interrupted")?
        })
        .await?;
        operation.renew(&mut claim).await?;
        let worker = operation.clone();
        let preparation = tokio::task::spawn_blocking(move || {
            crate::resource_bridge::verify_delivery(
                &worker.saved,
                &worker.identity,
                &copy,
                &worker.owner.0.journal.root.join("stage"),
                &|| worker.gate(),
            )
            .map(|verified| (copy, verified))
        });
        let (copy, verified) = keep_alive(&operation, &mut claim, async move {
            preparation
                .await
                .map_err(|_| "source_delivery_interrupted")?
        })
        .await?;
        operation.renew(&mut claim).await?;
        let worker = operation.clone();
        let delivery_claim = claim.clone();
        // No heartbeat may overtake the final nonce reservation before the request starts.
        let prepared = tokio::task::spawn_blocking(move || {
            worker.gate()?;
            worker
                .owner
                .0
                .reserve_upload(&worker.saved, &worker.identity)?;
            crate::resource_bridge::bind_delivery(
                &worker.saved,
                &worker.identity,
                &delivery_claim,
                verified,
                worker.owner.0.resource.bytes,
                &|| worker.gate(),
            )
        })
        .await
        .map_err(|_| "source_delivery_interrupted")??;
        let upload = operation.clone();
        let delivery = crate::resource_bridge::deliver(
            prepared,
            operation.stop.clone(),
            Arc::new(move || upload.gate()),
        );
        let accepted = keep_alive(&operation, &mut claim, delivery).await?;
        if accepted {
            let cleanup = operation.clone();
            tokio::task::spawn_blocking(move || {
                let job = &cleanup.owner.0;
                let mut state = job.state(&cleanup.saved, &cleanup.identity)?;
                if state.stage.as_deref() != Some(&copy.id) {
                    return Err("source_journal_invalid".into());
                }
                copy.release(
                    &cleanup.saved,
                    &cleanup.identity,
                    &job.journal.root.join("stage"),
                )?;
                state.stage = None;
                job.journal.write("state.json", &state, &cleanup.identity)
            })
            .await
            .map_err(|_| "source_delivery_interrupted")??;
        }
        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        connection::{DeviceIdentity, SavedConnection},
        source_consent::SourceConsent,
    };
    use std::{fs, sync::atomic::AtomicBool};
    struct Fixture {
        root: std::path::PathBuf,
        saved: SavedConnection,
        identity: DeviceIdentity,
        resource: crate::copy_source::StagedCopy,
        approval: crate::copy_source::CopyApproval,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-read-job-{}", uuid::Uuid::new_v4()));
            crate::runtime_store::private_directory(&root).unwrap();
            for name in ["source", "data", "seed"] {
                crate::runtime_store::private_directory(&root.join(name)).unwrap();
            }
            fs::write(root.join("source/original.jpg"), b"abcdefghij").unwrap();
            let saved = SavedConnection {
                server: "https://nas.test/".into(),
                server_id: "nas".into(),
                account_id: "owner".into(),
                name: "Synthetic".into(),
                token: "synthetic-session".into(),
                device_name: "Synthetic".into(),
                mode: "client-worker".into(),
                device_id: Some("device".into()),
            };
            let identity = DeviceIdentity::generate();
            let picker = SourceConsent::default();
            let selected = picker
                .select(picker.generation().unwrap(), root.join("source"))
                .unwrap();
            let mut consent = picker
                .approve(&saved, &identity, &selected.selection_id, true, |_| Ok(()))
                .unwrap();
            consent.registered = true;
            let approval = consent.approval(&saved, &identity).unwrap().clone();
            let resource = approval
                .stage(
                    &saved,
                    &identity,
                    "original.jpg",
                    &root.join("seed"),
                    &AtomicBool::new(false),
                )
                .unwrap();
            Self {
                root,
                saved,
                identity,
                resource,
                approval,
            }
        }
        fn job(&self, read: u64, upload: u64) -> Job {
            Job::open(
                &self.root.join("data"),
                &self.saved,
                &self.identity,
                self.resource.source_id(),
                &self.resource.resource_key(),
                &self.resource.version(),
                Some(State::new(self.resource.clone(), read, upload).unwrap()),
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    fn a_request_selects_only_the_exact_signed_local_resource() {
        let f = Fixture::new();
        let value = serde_json::json!({"id":uuid::Uuid::new_v4().to_string(),"sourceId":f.resource.source_id(),"scopeFingerprint":f.resource.scope_fingerprint(),"authorizationEpoch":1,"resourceKey":f.resource.resource_key(),"version":f.resource.version(),"sha256":f.resource.sha256,"bytes":10,"claimFence":1,"claimToken":"a".repeat(64),"leaseUntil":"2026-10-22T00:01:00Z","deadline":"2026-10-22T00:05:00Z"});
        let claim: crate::resource_bridge::ReadClaim =
            serde_json::from_value(value.clone()).unwrap();
        assert!(claim.matches_resource(&f.resource));
        for field in [
            "sourceId",
            "scopeFingerprint",
            "resourceKey",
            "version",
            "sha256",
            "bytes",
        ] {
            let mut changed = value.clone();
            changed[field] = if field == "bytes" {
                serde_json::json!(11)
            } else {
                serde_json::json!("wrong")
            };
            let claim: crate::resource_bridge::ReadClaim = serde_json::from_value(changed).unwrap();
            assert!(!claim.matches_resource(&f.resource), "{field}");
        }
    }
    #[test]
    fn original_allowance_is_persisted_before_read_and_cannot_reset_on_resume() {
        let f = Fixture::new();
        let job = f.job(10, 20);
        let copy = job
            .stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        let state = job.state(&f.saved, &f.identity).unwrap();
        assert_eq!(state.read.used, 10);
        assert_eq!(state.upload.used, 0);
        assert_eq!(copy.sha256, f.resource.sha256);
        copy.release(&f.saved, &f.identity, &job.journal.root.join("stage"))
            .unwrap();
        drop(job);
        let job = Job::open(
            &f.root.join("data"),
            &f.saved,
            &f.identity,
            f.resource.source_id(),
            &f.resource.resource_key(),
            &f.resource.version(),
            None,
        )
        .unwrap();
        assert_eq!(
            job.stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_read_budget_exhausted")
        );
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().read.used, 10);
        assert!(Job::open(
            &f.root.join("data"),
            &f.saved,
            &f.identity,
            f.resource.source_id(),
            &f.resource.resource_key(),
            &f.resource.version(),
            Some(State::new(f.resource.clone(), 20, 20).unwrap())
        )
        .is_err());
    }
    #[test]
    fn upload_allowance_survives_retry_and_unknown_resource_cannot_create_a_job() {
        let f = Fixture::new();
        let job = f.job(10, 20);
        job.reserve_upload(&f.saved, &f.identity).unwrap();
        job.reserve_upload(&f.saved, &f.identity).unwrap();
        assert_eq!(
            job.reserve_upload(&f.saved, &f.identity).unwrap_err(),
            "source_upload_budget_exhausted"
        );
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().upload.used, 20);
        drop(job);
        let key = "f".repeat(64);
        assert!(Job::open(
            &f.root.join("data"),
            &f.saved,
            &f.identity,
            f.resource.source_id(),
            &key,
            &f.resource.version(),
            None
        )
        .is_err());
        assert!(!f
            .root
            .join("data/photo-reads")
            .join(f.resource.source_id())
            .join(job_key(&key, &f.resource.version()))
            .exists());
    }
    #[test]
    fn a_blocking_worker_retains_exclusive_source_ownership_until_it_returns() {
        let f = Fixture::new();
        let job = Arc::new(f.job(10, 20));
        let busy = job.begin().unwrap();
        assert!(job.begin().is_err());
        let (finish, wait) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _busy = busy;
            wait.recv().unwrap();
        });
        drop(job);
        assert!(Job::open(
            &f.root.join("data"),
            &f.saved,
            &f.identity,
            f.resource.source_id(),
            &f.resource.resource_key(),
            &f.resource.version(),
            None
        )
        .is_err());
        finish.send(()).unwrap();
        worker.join().unwrap();
        assert!(Job::open(
            &f.root.join("data"),
            &f.saved,
            &f.identity,
            f.resource.source_id(),
            &f.resource.resource_key(),
            &f.resource.version(),
            None
        )
        .is_ok());
    }
    #[test]
    fn another_version_has_its_own_descriptor_and_explicit_allowances_preserve_spending() {
        let f = Fixture::new();
        let job = f.job(10, 20);
        let old_path = job.journal.root.clone();
        job.reserve_upload(&f.saved, &f.identity).unwrap();
        job.extend(&f.saved, &f.identity, 10, 20).unwrap();
        let state = job.state(&f.saved, &f.identity).unwrap();
        assert_eq!(
            (
                state.upload.used,
                state.upload.limit,
                state.read.used,
                state.read.limit
            ),
            (10, 40, 0, 20)
        );
        drop(job);
        fs::write(f.root.join("source/original.jpg"), b"0123456789").unwrap();
        let next = f
            .approval
            .stage(
                &f.saved,
                &f.identity,
                "original.jpg",
                &f.root.join("seed"),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(next.resource_key(), f.resource.resource_key());
        assert_ne!(next.version(), f.resource.version());
        let job = Job::open(
            &f.root.join("data"),
            &f.saved,
            &f.identity,
            next.source_id(),
            &next.resource_key(),
            &next.version(),
            Some(State::new(next.clone(), 10, 20).unwrap()),
        )
        .unwrap();
        assert_ne!(job.journal.root, old_path);
        assert!(old_path.join("state.json").is_file());
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().upload.used, 0);
    }
    #[tokio::test]
    async fn cancelled_or_mismatched_claims_refuse_before_credentials_network_or_spending() {
        let f = Fixture::new();
        let job = Arc::new(f.job(10, 20));
        let value = serde_json::json!({"id":uuid::Uuid::new_v4().to_string(),"sourceId":f.resource.source_id(),"scopeFingerprint":f.resource.scope_fingerprint(),"authorizationEpoch":1,"resourceKey":f.resource.resource_key(),"version":f.resource.version(),"sha256":f.resource.sha256,"bytes":10,"claimFence":1,"claimToken":"a".repeat(64),"leaseUntil":"2026-10-22T00:01:00Z","deadline":"2026-10-22T00:05:00Z"});
        let identity =
            || serde_json::from_slice(&serde_json::to_vec(&f.identity).unwrap()).unwrap();
        let claim: crate::resource_bridge::ReadClaim =
            serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            job.clone()
                .serve(
                    f.saved.clone(),
                    identity(),
                    claim,
                    Arc::new(AtomicBool::new(true))
                )
                .await
                .unwrap_err(),
            "source_delivery_interrupted"
        );
        let mut wrong = value;
        wrong["version"] = serde_json::json!("f".repeat(64));
        let claim = serde_json::from_value(wrong).unwrap();
        assert_eq!(
            job.clone()
                .serve(
                    f.saved.clone(),
                    identity(),
                    claim,
                    Arc::new(AtomicBool::new(false))
                )
                .await
                .unwrap_err(),
            "source_read_request_invalid"
        );
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().read.used, 0);
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().upload.used, 0);
        assert!(job.begin().is_ok());
    }
    #[test]
    fn verification_checks_stop_before_returning_the_owned_file() {
        let f = Fixture::new();
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let gate = || {
            if checks.fetch_add(1, Ordering::AcqRel) > 0 {
                Err("stopped".into())
            } else {
                Ok(())
            }
        };
        assert_eq!(
            f.resource
                .verify_with_gate(&f.saved, &f.identity, &f.root.join("seed"), &gate)
                .err()
                .as_deref(),
            Some("stopped")
        );
    }
    #[test]
    fn cached_stage_requires_current_permission_and_unknown_partial_is_retained() {
        let f = Fixture::new();
        let job = f.job(20, 20);
        let copy = job
            .stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        let reused = job
            .stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert_eq!(reused.id, copy.id);
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().read.used, 10);
        fs::rename(f.root.join("source"), f.root.join("offline")).unwrap();
        assert!(job
            .stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .is_err());
        fs::rename(f.root.join("offline"), f.root.join("source")).unwrap();
        fs::remove_file(
            job.journal
                .root
                .join("stage")
                .join(&copy.id)
                .join("receipt.json"),
        )
        .unwrap();
        assert_eq!(
            job.stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_cache_cleanup_pending")
        );
        assert!(job
            .journal
            .root
            .join("stage")
            .join(&copy.id)
            .join("original")
            .is_file());
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().read.used, 10);
    }
    #[test]
    fn stop_and_failed_checkpoint_refuse_before_original_read() {
        let f = Fixture::new();
        let job = f.job(10, 20);
        assert!(job
            .stage(&f.saved, &f.identity, &AtomicBool::new(true), &|| Ok(()))
            .is_err());
        assert!(job
            .stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Err(
                "revoked".into()
            ))
            .is_err());
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().read.used, 0);
        #[cfg(unix)]
        if unsafe { libc::geteuid() } != 0 {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&job.journal.root, fs::Permissions::from_mode(0o500)).unwrap();
            let result = job.stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()));
            fs::set_permissions(&job.journal.root, fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(result.err().as_deref(), Some("source_journal_write_failed"));
            assert_eq!(job.state(&f.saved, &f.identity).unwrap().read.used, 0);
            assert_eq!(
                fs::read_dir(job.journal.root.join("stage"))
                    .unwrap()
                    .count(),
                0
            );
        }
        fs::remove_file(job.journal.root.join("state.json")).unwrap();
        fs::create_dir(job.journal.root.join("state.json")).unwrap();
        assert!(job
            .stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .is_err());
        assert_eq!(
            fs::read_dir(job.journal.root.join("stage"))
                .unwrap()
                .count(),
            0
        );
    }
}
