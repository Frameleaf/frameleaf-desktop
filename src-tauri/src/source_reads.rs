//! One source-owned original read, with durable allowances and locally signed resource selection.
mod owner;
mod planner;
mod preparation;
use crate::{
    connection::{DeviceIdentity, SavedConnection},
    copy_source::StagedCopy,
    source_import::Journal,
};
use cap_std::{ambient_authority, fs::Dir};
pub use owner::{PreparationAction, Requests, View};
pub use planner::{Preparation, PreparationView, PreparedResource};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cleaned: Option<String>,
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
            cleaned: None,
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
            || self
                .cleaned
                .as_ref()
                .is_some_and(|id| !canonical_uuid(id) || self.stage.as_ref() == Some(id))
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
enum OpenMode {
    Create(Box<State>),
    Read,
    Inspect,
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
        if consent.reference_approval(saved, identity)?.fingerprint()
            != resource.scope_fingerprint()
        {
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
        let approval = consent.reference_approval(saved, identity)?;
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
        Self::open_owned(
            base,
            saved,
            identity,
            source,
            key,
            version,
            initial
                .map(|state| OpenMode::Create(Box::new(state)))
                .unwrap_or(OpenMode::Read),
        )
    }
    fn open_owned(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        source: &str,
        key: &str,
        version: &str,
        mode: OpenMode,
    ) -> Result<Self, String> {
        let inspect = matches!(&mode, OpenMode::Inspect);
        let initial = match mode {
            OpenMode::Create(state) => Some(*state),
            _ => None,
        };
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
        if owner
            .metadata()
            .map_err(|_| "source_journal_invalid")?
            .len()
            != 0
        {
            return Err("source_journal_invalid".into());
        }
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
        if inspect {
            state.resource.validate_receipt(saved, identity)?;
        } else {
            state.resource.validate_current(saved, identity)?;
        }
        state.resource.staging_root(base)?;
        if state.resource.source_id() != source
            || state.resource.resource_key() != key
            || state.resource.version() != version
        {
            return Err("source_journal_invalid".into());
        }
        let result = Self {
            journal,
            resource: state.resource,
            _owner: owner,
            source_root,
            source_identity,
            busy: AtomicBool::new(false),
        };
        result.require_owner()?;
        Ok(result)
    }
    fn require_owner(&self) -> Result<(), String> {
        crate::native_runtime::absolute_directory(&self.source_root)?;
        let dir = Dir::open_ambient_dir(&self.source_root, ambient_authority())
            .map_err(|_| "source_journal_invalid")?;
        if crate::copy_source::source_root_identity(&dir)? != self.source_identity {
            return Err("source_journal_invalid".into());
        }
        crate::host_state::valid_file(&self._owner)?;
        let named = dir
            .open_with(".owner.lock", &crate::host_state::options(false))
            .map_err(|_| "source_journal_invalid")?;
        let held = cap_std::fs::File::from_std(
            self._owner
                .try_clone()
                .map_err(|_| "source_journal_invalid")?,
        );
        if crate::copy_source::opened_stamp(&named)? != crate::copy_source::opened_stamp(&held)? {
            return Err("source_journal_invalid".into());
        }
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
        if let Some(id) = &state.cleaned {
            let base = self
                .source_root
                .parent()
                .and_then(Path::parent)
                .ok_or("source_journal_invalid")?;
            crate::private_inputs::InputBudget::open(base, identity)?
                .release(self.resource.source_id(), id)?;
            state.cleaned = None;
            self.journal.write("state.json", &state, identity)?;
        }
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
        let base = self
            .source_root
            .parent()
            .and_then(Path::parent)
            .ok_or("source_journal_invalid")?;
        let mut budget = crate::private_inputs::InputBudget::open(base, identity)?;
        if budget.remaining()? < self.resource.bytes {
            return Err("source_staging_budget_exceeded".into());
        }
        state
            .read
            .reserve(self.resource.read_cost(), "source_read_budget_exhausted")?;
        let id = uuid::Uuid::new_v4().to_string();
        state.stage = Some(id.clone());
        self.journal.write("state.json", &state, identity)?;
        gate()?;
        budget.reserve(self.resource.source_id(), &id, self.resource.bytes)?;
        self.resource
            .stage_again(saved, identity, &stage, &id, cancelled, &|| {
                gate()?;
                self.require_owner()?;
                budget.check()
            })
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
        if consent
            .reference_approval(&self.saved, &self.identity)?
            .fingerprint()
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
            if let Err(code) = work.await {
                if owner::unconfirmed(&code) {
                    return Err(code);
                }
            }
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
        if consent.reference_approval(saved, identity)?.fingerprint()
            != self.resource.scope_fingerprint()
        {
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
            stage
                .await
                .map_err(|_| "source_read_shutdown_unconfirmed")?
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
                .map_err(|_| "source_read_shutdown_unconfirmed")?
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
        .map_err(|_| "source_read_shutdown_unconfirmed")??;
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
                state.cleaned = Some(copy.id.clone());
                job.journal.write("state.json", &state, &cleanup.identity)?;
                let base = job
                    .source_root
                    .parent()
                    .and_then(Path::parent)
                    .ok_or("source_journal_invalid")?;
                crate::private_inputs::InputBudget::open(base, &cleanup.identity)?
                    .release(job.resource.source_id(), &copy.id)
            })
            .await
            .map_err(|_| "source_read_shutdown_unconfirmed")??;
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
                .approve_with_hydration(
                    &saved,
                    &identity,
                    &selected.selection_id,
                    crate::source_consent::SourceMode::Reference,
                    true,
                    false,
                    |_| Ok(()),
                )
                .unwrap();
            consent.registered = true;
            let approval = consent
                .reference_approval(&saved, &identity)
                .unwrap()
                .clone();
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
        fn prepared_job(&self, prep: &Preparation) -> Arc<Job> {
            let record: serde_json::Value = prep
                .journal
                .read("prepared-0.json", &self.identity)
                .unwrap();
            let resource: PreparedResource =
                serde_json::from_value(record["resource"].clone()).unwrap();
            Arc::new(
                Job::open(
                    &self.root.join("data"),
                    &self.saved,
                    &self.identity,
                    self.approval.source_id(),
                    &resource.resource_key,
                    &resource.version,
                    None,
                )
                .unwrap(),
            )
        }
        fn finish_cache(&self, job: &Arc<Job>) {
            let mut state = job.state(&self.saved, &self.identity).unwrap();
            let copy = StagedCopy::restore(
                &self.saved,
                &self.identity,
                &job.journal.root.join("stage"),
                state.stage.as_ref().unwrap(),
            )
            .unwrap();
            copy.release(&self.saved, &self.identity, &job.journal.root.join("stage"))
                .unwrap();
            state.stage = None;
            job.journal
                .write("state.json", &state, &self.identity)
                .unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    #[cfg(unix)]
    fn read_owner_replacement_refuses_before_staging_or_spending() {
        let f = Fixture::new();
        let job = f.job(10, 0);
        let named = job.source_root.join(".owner.lock");
        let retained = job.source_root.join(".retained-owner.lock");
        fs::rename(&named, &retained).unwrap();
        let dir = Dir::open_ambient_dir(&job.source_root, ambient_authority()).unwrap();
        let replacement = dir
            .open_with(".owner.lock", &crate::host_state::options(true))
            .unwrap()
            .into_std();
        replacement.try_lock().unwrap();
        assert_eq!(
            job.stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_journal_invalid")
        );
        let state: State = job.journal.read("state.json", &f.identity).unwrap();
        assert_eq!(state.read.used, 0);
        assert!(state.stage.is_none());
        assert_eq!(
            fs::read_dir(job.journal.root.join("stage"))
                .unwrap()
                .count(),
            0
        );
        drop(replacement);
        fs::remove_file(&named).unwrap();
        fs::rename(&retained, &named).unwrap();
        job.require_owner().unwrap();
        let copy = job
            .stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert_eq!(copy.bytes, 10);
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().read.used, 10);
        assert_eq!(
            fs::read(f.root.join("source/original.jpg")).unwrap(),
            b"abcdefghij"
        );
    }
    #[test]
    fn quota_recovery_shrinks_a_completed_receipt_before_handoff_without_new_reads() {
        let f = Fixture::new();
        let prep = Preparation::open_with(
            &f.root.join("data"),
            &f.saved,
            &f.identity,
            f.approval.clone(),
            crate::photo_sources::SourceFile {
                relative: "original.jpg".into(),
                bytes: 10,
            },
            true,
        )
        .unwrap();
        let mut budget =
            crate::private_inputs::InputBudget::open(&f.root.join("data"), &f.identity).unwrap();
        budget
            .reserve(f.approval.source_id(), &f.resource.id, 20)
            .unwrap();
        drop(budget);
        fs::rename(
            f.root.join("seed").join(&f.resource.id),
            prep.journal.root.join("stage").join(&f.resource.id),
        )
        .unwrap();
        let mut progress: serde_json::Value = prep
            .journal
            .read("preparation-state.json", &f.identity)
            .unwrap();
        progress["attempt"] = serde_json::json!(f.resource.id);
        progress["read"] = serde_json::json!({"used": 10, "limit": 10});
        prep.journal
            .write("preparation-state.json", &progress, &f.identity)
            .unwrap();
        let view = prep
            .finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert_eq!((view.spent, view.remaining, view.completed), (10, 0, 1));
        assert_eq!(
            crate::private_inputs::InputBudget::open(&f.root.join("data"), &f.identity)
                .unwrap()
                .remaining()
                .unwrap(),
            crate::private_inputs::LIMIT - 10
        );
        assert_eq!(
            prep.finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .unwrap()
                .spent,
            10
        );
    }
    #[test]
    fn quota_recovery_remembers_the_actual_cleaned_stage_after_restage() {
        let f = Fixture::new();
        let job = f.job(10, 0);
        let copy = job
            .stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert_ne!(copy.id, job.resource.id);
        copy.release(&f.saved, &f.identity, &job.journal.root.join("stage"))
            .unwrap();
        let mut state = job.state(&f.saved, &f.identity).unwrap();
        state.stage = None;
        state.cleaned = Some(copy.id);
        job.journal
            .write("state.json", &state, &f.identity)
            .unwrap();
        assert_eq!(
            job.stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_read_budget_exhausted")
        );
        assert_eq!(
            crate::private_inputs::InputBudget::open(&f.root.join("data"), &f.identity)
                .unwrap()
                .remaining()
                .unwrap(),
            crate::private_inputs::LIMIT
        );
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().read.used, 10);
    }
    #[test]
    fn shared_input_limit_precedes_preparation_and_read_attempts() {
        for prepare in [true, false] {
            let f = Fixture::new();
            let other_source = uuid::Uuid::new_v4().to_string();
            let other_input = uuid::Uuid::new_v4().to_string();
            let mut budget =
                crate::private_inputs::InputBudget::open(&f.root.join("data"), &f.identity)
                    .unwrap();
            budget
                .reserve(&other_source, &other_input, crate::private_inputs::LIMIT)
                .unwrap();
            drop(budget);
            if prepare {
                let mut prep = Preparation::open_with(
                    &f.root.join("data"),
                    &f.saved,
                    &f.identity,
                    f.approval.clone(),
                    crate::photo_sources::SourceFile {
                        relative: "original.jpg".into(),
                        bytes: 10,
                    },
                    true,
                )
                .unwrap();
                prep.approve_with(&f.saved, &f.identity, 10).unwrap();
                assert_eq!(
                    prep.stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                        .err()
                        .as_deref(),
                    Some("source_staging_budget_exceeded")
                );
                assert_eq!(prep.view(&f.saved, &f.identity).unwrap().spent, 0);
            } else {
                let job = f.job(10, 0);
                assert_eq!(
                    job.stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                        .err()
                        .as_deref(),
                    Some("source_staging_budget_exceeded")
                );
                let state = job.state(&f.saved, &f.identity).unwrap();
                assert_eq!(state.read.used, 0);
                assert!(state.stage.is_none());
            }
            assert_eq!(
                fs::read(f.root.join("source/original.jpg")).unwrap(),
                b"abcdefghij"
            );
        }
    }
    #[test]
    fn read_owner_nonempty_lock_refuses_before_creating_a_budget_checkpoint() {
        let f = Fixture::new();
        let source_root = f.root.join("data/photo-reads").join(f.resource.source_id());
        crate::runtime_store::private_directory(&f.root.join("data/photo-reads")).unwrap();
        crate::runtime_store::private_directory(&source_root).unwrap();
        let dir = Dir::open_ambient_dir(&source_root, ambient_authority()).unwrap();
        let mut owner = dir
            .open_with(".owner.lock", &crate::host_state::options(true))
            .unwrap();
        std::io::Write::write_all(&mut owner, b"unknown").unwrap();
        drop(owner);
        let result = Job::open(
            &f.root.join("data"),
            &f.saved,
            &f.identity,
            f.resource.source_id(),
            &f.resource.resource_key(),
            &f.resource.version(),
            Some(State::new(f.resource.clone(), 10, 0).unwrap()),
        );
        assert_eq!(result.err().as_deref(), Some("source_journal_invalid"));
        assert!(!source_root
            .join(job_key(&f.resource.resource_key(), &f.resource.version()))
            .exists());
    }
    #[test]
    fn reference_capacity_requires_idle_owner_and_positive_cleanup_without_original_access() {
        let f = Fixture::new();
        let entry = crate::photo_sources::SourceFile {
            relative: "original.jpg".into(),
            bytes: 10,
        };
        let mut prep = Preparation::open_with(
            &f.root.join("data"),
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry,
            true,
        )
        .unwrap();
        prep.approve_with(&f.saved, &f.identity, 10).unwrap();
        prep.finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        let job = f.prepared_job(&prep);
        assert_eq!(
            prep.reconcile_with(&f.saved, &f.identity, &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_read_already_running")
        );
        job.resource
            .release(&f.saved, &f.identity, &job.journal.root.join("stage"))
            .unwrap();
        drop(job);
        drop(
            prep.reconcile_with(&f.saved, &f.identity, &|| Ok(()))
                .unwrap(),
        );
        assert_eq!(
            prep.view(&f.saved, &f.identity).unwrap().staging_remaining,
            2 * 1024 * 1024 * 1024 - 10
        );
        let job = f.prepared_job(&prep);
        let mut state = job.state(&f.saved, &f.identity).unwrap();
        state.stage = None;
        job.journal
            .write("state.json", &state, &f.identity)
            .unwrap();
        drop(job);
        fs::remove_file(f.root.join("source/original.jpg")).unwrap();
        assert_eq!(
            prep.reconcile_with(&f.saved, &f.identity, &|| {
                let progress: serde_json::Value =
                    prep.journal.read("preparation-state.json", &f.identity)?;
                if progress["releasedBytes"] == 10 {
                    Err("source_copy_cancelled".into())
                } else {
                    Ok(())
                }
            })
            .err()
            .as_deref(),
            Some("source_copy_cancelled")
        );
        for _ in 0..2 {
            drop(
                prep.reconcile_with(&f.saved, &f.identity, &|| Ok(()))
                    .unwrap(),
            );
        }
        let view = prep.view(&f.saved, &f.identity).unwrap();
        assert_eq!(
            (
                view.spent,
                view.remaining,
                view.completed,
                view.staging_remaining
            ),
            (10, 0, 1, 2 * 1024 * 1024 * 1024)
        );
        let record: serde_json::Value = prep.journal.read("prepared-0.json", &f.identity).unwrap();
        assert_eq!(record["resource"]["bytes"], 10);
    }
    #[test]
    fn reference_capacity_rechecks_repopulated_cache_before_another_original_attempt() {
        let f = Fixture::new();
        let ceiling = 2 * 1024 * 1024 * 1024;
        let entries = vec![
            crate::photo_sources::SourceFile {
                relative: "original.jpg".into(),
                bytes: 10,
            },
            crate::photo_sources::SourceFile {
                relative: "missing.jpg".into(),
                bytes: ceiling - 5,
            },
        ];
        let mut prep = Preparation::open_selection(
            &f.root.join("data"),
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entries,
            true,
        )
        .unwrap();
        prep.approve_with(&f.saved, &f.identity, ceiling + 5)
            .unwrap();
        prep.finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        let job = f.prepared_job(&prep);
        let cache = job.journal.root.join("stage").join(&job.resource.id);
        let receipt = fs::read(cache.join("receipt.json")).unwrap();
        f.finish_cache(&job);
        drop(job);
        drop(
            prep.reconcile_with(&f.saved, &f.identity, &|| Ok(()))
                .unwrap(),
        );
        assert_eq!(
            prep.view(&f.saved, &f.identity).unwrap().staging_remaining,
            ceiling
        );
        let job = f.prepared_job(&prep);
        let mut budget =
            crate::private_inputs::InputBudget::open(&f.root.join("data"), &f.identity).unwrap();
        budget
            .reserve(f.approval.source_id(), &job.resource.id, job.resource.bytes)
            .unwrap();
        drop(budget);
        crate::runtime_store::private_directory(&cache).unwrap();
        fs::write(cache.join("original"), b"abcdefghij").unwrap();
        fs::write(cache.join("receipt.json"), receipt).unwrap();
        let mut state = job.state(&f.saved, &f.identity).unwrap();
        state.stage = Some(job.resource.id.clone());
        job.journal
            .write("state.json", &state, &f.identity)
            .unwrap();
        drop(job);
        assert_eq!(
            prep.finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_staging_budget_exceeded")
        );
        assert_eq!(prep.view(&f.saved, &f.identity).unwrap().spent, 10);
    }
    #[test]
    fn reference_capacity_keeps_unknown_staging_and_never_credits_it() {
        let f = Fixture::new();
        let entry = crate::photo_sources::SourceFile {
            relative: "original.jpg".into(),
            bytes: 10,
        };
        let mut prep = Preparation::open_with(
            &f.root.join("data"),
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry,
            true,
        )
        .unwrap();
        prep.approve_with(&f.saved, &f.identity, 10).unwrap();
        prep.finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        let job = f.prepared_job(&prep);
        f.finish_cache(&job);
        let unknown = job.journal.root.join("stage/unknown");
        fs::write(&unknown, b"keep").unwrap();
        drop(job);
        assert!(prep
            .reconcile_with(&f.saved, &f.identity, &|| Ok(()))
            .is_err());
        assert_eq!(
            prep.view(&f.saved, &f.identity).unwrap().staging_remaining,
            2 * 1024 * 1024 * 1024 - 10
        );
        assert_eq!(fs::read(&unknown).unwrap(), b"keep");
    }
    #[test]
    fn reference_selection_recovers_record_written_before_cursor_checkpoint() {
        let f = Fixture::new();
        let base = f.root.join("data");
        let entry = crate::photo_sources::SourceFile {
            relative: "original.jpg".into(),
            bytes: 10,
        };
        let mut prep = Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry.clone(),
            true,
        )
        .unwrap();
        prep.approve_with(&f.saved, &f.identity, 10).unwrap();
        prep.stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        let before: serde_json::Value = prep
            .journal
            .read("preparation-state.json", &f.identity)
            .unwrap();
        prep.finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        let record = fs::read(prep.journal.root.join("prepared-0.json")).unwrap();
        // Recreate the crash cutpoint after the record write and before cursor advancement.
        prep.journal
            .write("preparation-state.json", &before, &f.identity)
            .unwrap();
        drop(prep);
        let prep = Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry,
            false,
        )
        .unwrap();
        let done = prep
            .finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert_eq!(
            (
                done.completed,
                done.spent,
                done.remaining,
                done.staging_remaining
            ),
            (1, 10, 0, 2 * 1024 * 1024 * 1024 - 10)
        );
        assert_eq!(
            fs::read(prep.journal.root.join("prepared-0.json")).unwrap(),
            record
        );
    }
    #[test]
    fn reference_selection_keeps_legacy_single_resource_allowance_and_receipt() {
        let f = Fixture::new();
        let base = f.root.join("data");
        let entry = crate::photo_sources::SourceFile {
            relative: "original.jpg".into(),
            bytes: 10,
        };
        let mut prep = Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry.clone(),
            true,
        )
        .unwrap();
        prep.approve_with(&f.saved, &f.identity, 10).unwrap();
        prep.stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        let plan: serde_json::Value = prep
            .journal
            .read("preparation-plan.json", &f.identity)
            .unwrap();
        let state: serde_json::Value = prep
            .journal
            .read("preparation-state.json", &f.identity)
            .unwrap();
        assert!(plan.get("additional").is_none());
        assert!(state.get("completion").is_none());
        prep.journal
            .write("preparation-plan.json", &plan, &f.identity)
            .unwrap();
        prep.journal
            .write("preparation-state.json", &state, &f.identity)
            .unwrap();
        drop(prep);
        let prep = Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry,
            false,
        )
        .unwrap();
        let done = prep
            .finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert_eq!((done.completed, done.spent, done.remaining), (1, 10, 0));
    }
    #[test]
    fn reference_selection_rejects_replayed_inventory_records_without_resetting_progress() {
        let f = Fixture::new();
        fs::write(f.root.join("source/second.jpg"), b"second").unwrap();
        let base = f.root.join("data");
        let entries = vec![
            crate::photo_sources::SourceFile {
                relative: "original.jpg".into(),
                bytes: 10,
            },
            crate::photo_sources::SourceFile {
                relative: "second.jpg".into(),
                bytes: 6,
            },
        ];
        let mut prep = Preparation::open_selection(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entries.clone(),
            true,
        )
        .unwrap();
        prep.approve_with(&f.saved, &f.identity, 16).unwrap();
        for _ in 0..2 {
            prep.finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .unwrap();
        }
        fs::copy(
            prep.journal.root.join("prepared-0.json"),
            prep.journal.root.join("prepared-1.json"),
        )
        .unwrap();
        assert_eq!(prep.view(&f.saved, &f.identity).unwrap().spent, 16);
        let journal = prep.journal.root.clone();
        drop(prep);
        assert!(Preparation::open_selection(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entries,
            false
        )
        .is_err());
        let state: serde_json::Value = Journal { root: journal }
            .read("preparation-state.json", &f.identity)
            .unwrap();
        assert_eq!(state["read"]["used"], 16);
        assert_eq!(state["completion"]["position"], 2);
    }
    #[test]
    fn reference_selection_budget_and_progress_survive_restart() {
        let f = Fixture::new();
        fs::write(f.root.join("source/second.jpg"), b"second").unwrap();
        let base = f.root.join("data");
        let entries = vec![
            crate::photo_sources::SourceFile {
                relative: "original.jpg".into(),
                bytes: 10,
            },
            crate::photo_sources::SourceFile {
                relative: "second.jpg".into(),
                bytes: 6,
            },
        ];
        let mut prep = Preparation::open_selection(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entries.clone(),
            true,
        )
        .unwrap();
        assert_eq!(prep.view(&f.saved, &f.identity).unwrap().remaining, 0);
        prep.approve_with(&f.saved, &f.identity, 10).unwrap();
        let first = prep
            .finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert_eq!(
            (
                first.completed,
                first.resources,
                first.spent,
                first.remaining
            ),
            (1, 2, 10, 0)
        );
        assert!(!first.prepared);
        drop(prep);
        let mut prep = Preparation::open_selection(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entries,
            false,
        )
        .unwrap();
        assert_eq!(
            prep.finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_read_budget_exhausted")
        );
        assert_eq!(prep.view(&f.saved, &f.identity).unwrap().spent, 10);
        prep.approve_with(&f.saved, &f.identity, 6).unwrap();
        for _ in 0..2 {
            let done = prep
                .finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .unwrap();
            assert_eq!(
                (done.completed, done.resources, done.spent, done.remaining),
                (2, 2, 16, 0)
            );
            assert!(done.prepared);
        }
        let completed: Vec<serde_json::Value> = (0..2)
            .map(|index| {
                prep.journal
                    .read(&format!("prepared-{index}.json"), &f.identity)
                    .unwrap()
            })
            .collect();
        assert_ne!(
            completed[0]["resource"]["resourceKey"],
            completed[1]["resource"]["resourceKey"]
        );
    }
    #[test]
    fn reference_selection_staging_cap_precedes_another_original_read() {
        let f = Fixture::new();
        let ceiling = 2 * 1024 * 1024 * 1024;
        let entries = vec![
            crate::photo_sources::SourceFile {
                relative: "original.jpg".into(),
                bytes: 10,
            },
            crate::photo_sources::SourceFile {
                relative: "missing.jpg".into(),
                bytes: ceiling - 5,
            },
        ];
        let mut prep = Preparation::open_selection(
            &f.root.join("data"),
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entries,
            true,
        )
        .unwrap();
        prep.approve_with(&f.saved, &f.identity, ceiling + 5)
            .unwrap();
        prep.finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert_eq!(
            prep.finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_staging_budget_exceeded")
        );
        let view = prep.view(&f.saved, &f.identity).unwrap();
        assert_eq!(
            (view.completed, view.spent, view.staging_remaining),
            (1, 10, ceiling - 10)
        );
    }
    #[test]
    fn reference_selection_is_frozen_and_rejects_duplicate_entries() {
        let f = Fixture::new();
        let base = f.root.join("data");
        let a = crate::photo_sources::SourceFile {
            relative: "original.jpg".into(),
            bytes: 10,
        };
        let b = crate::photo_sources::SourceFile {
            relative: "second.jpg".into(),
            bytes: 6,
        };
        assert!(Preparation::open_selection(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            vec![a.clone(), a.clone()],
            true
        )
        .is_err());
        let prep = Preparation::open_selection(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            vec![a.clone(), b.clone()],
            true,
        )
        .unwrap();
        drop(prep);
        assert_eq!(
            Preparation::open_selection(
                &base,
                &f.saved,
                &f.identity,
                f.approval.clone(),
                vec![b, a],
                true
            )
            .err()
            .as_deref(),
            Some("source_approval_changed")
        );
    }
    #[test]
    fn reference_preparation_pipeline_resumes_after_move_with_lost_reply() {
        let f = Fixture::new();
        let base = f.root.join("data");
        let entry = crate::photo_sources::SourceFile {
            relative: "original.jpg".into(),
            bytes: 10,
        };
        let mut prep = Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry,
            true,
        )
        .unwrap();
        prep.approve_with(&f.saved, &f.identity, 10).unwrap();
        let stop_after_move = || {
            let state: serde_json::Value =
                prep.journal.read("preparation-state.json", &f.identity)?;
            if let Some(id) = state["resource"]["id"].as_str() {
                if !prep.journal.root.join("stage").join(id).exists() {
                    return Err("source_copy_cancelled".into());
                }
            }
            Ok(())
        };
        assert!(prep
            .finish_with(
                &f.saved,
                &f.identity,
                &AtomicBool::new(false),
                &stop_after_move
            )
            .is_err());
        assert_eq!(
            prep.finish_with(&f.saved, &f.identity, &AtomicBool::new(true), &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_copy_cancelled")
        );
        let view = prep
            .finish_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert!(view.prepared);
        assert_eq!((view.spent, view.remaining), (10, 0));
    }
    #[test]
    fn reference_preparation_requires_budget_and_preserves_spending_after_restart() {
        let f = Fixture::new();
        let base = f.root.join("data");
        let entry = crate::photo_sources::SourceFile {
            relative: "original.jpg".into(),
            bytes: 10,
        };
        let mut prep = Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry.clone(),
            true,
        )
        .unwrap();
        assert_eq!(prep.view(&f.saved, &f.identity).unwrap().remaining, 0);
        assert_eq!(
            prep.stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_read_budget_exhausted")
        );
        prep.approve_with(&f.saved, &f.identity, 10).unwrap();
        fs::remove_file(f.root.join("source/original.jpg")).unwrap();
        assert!(prep
            .stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .is_err());
        drop(prep);
        let mut prep = Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry,
            false,
        )
        .unwrap();
        assert_eq!(prep.view(&f.saved, &f.identity).unwrap().spent, 10);
        fs::write(f.root.join("source/original.jpg"), b"abcdefghij").unwrap();
        assert_eq!(
            prep.stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_read_budget_exhausted")
        );
        prep.approve_with(&f.saved, &f.identity, 10).unwrap();
        let copy = prep
            .stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        let again = prep
            .stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert_eq!(copy.id, again.id);
        assert_eq!(prep.view(&f.saved, &f.identity).unwrap().spent, 20);
    }
    #[test]
    fn reference_preparation_recovers_receipt_after_late_stop_and_hands_off_once() {
        let f = Fixture::new();
        let base = f.root.join("data");
        let entry = crate::photo_sources::SourceFile {
            relative: "original.jpg".into(),
            bytes: 10,
        };
        let mut prep = Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry.clone(),
            true,
        )
        .unwrap();
        prep.approve_with(&f.saved, &f.identity, 10).unwrap();
        let stage = prep.journal.root.join("stage");
        assert!(prep
            .stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| {
                if fs::read_dir(&stage)
                    .unwrap()
                    .any(|entry| entry.unwrap().path().join("receipt.json").exists())
                {
                    Err("source_copy_cancelled".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(prep.view(&f.saved, &f.identity).unwrap().spent, 10);
        drop(prep);
        let prep = Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry,
            false,
        )
        .unwrap();
        let copy = prep
            .stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        let job = prep
            .handoff_with(&f.saved, &f.identity, &|| Ok(()))
            .unwrap();
        drop(job);
        let job = prep
            .handoff_with(&f.saved, &f.identity, &|| Ok(()))
            .unwrap();
        assert!(prep
            .stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .is_err());
        assert_eq!(prep.view(&f.saved, &f.identity).unwrap().spent, 10);
        assert_eq!(
            job.stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .unwrap()
                .sha256,
            copy.sha256
        );
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().read.used, 0);
    }
    #[test]
    fn reference_preparation_rejects_rebound_selection_and_parallel_owner() {
        let f = Fixture::new();
        let base = f.root.join("data");
        let entry = crate::photo_sources::SourceFile {
            relative: "original.jpg".into(),
            bytes: 10,
        };
        let prep = Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry.clone(),
            true,
        )
        .unwrap();
        assert_eq!(
            Preparation::open_with(
                &base,
                &f.saved,
                &f.identity,
                f.approval.clone(),
                entry,
                true
            )
            .err()
            .as_deref(),
            Some("source_read_already_running")
        );
        drop(prep);
        let other = crate::photo_sources::SourceFile {
            relative: "other.jpg".into(),
            bytes: 10,
        };
        assert_eq!(
            Preparation::open_with(
                &base,
                &f.saved,
                &f.identity,
                f.approval.clone(),
                other,
                true
            )
            .err()
            .as_deref(),
            Some("source_approval_changed")
        );
    }
    #[test]
    #[cfg(unix)]
    fn reference_preparation_retains_dangling_attempt_without_spending() {
        let f = Fixture::new();
        let base = f.root.join("data");
        let entry = crate::photo_sources::SourceFile {
            relative: "original.jpg".into(),
            bytes: 10,
        };
        let mut prep = Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry,
            true,
        )
        .unwrap();
        prep.approve_with(&f.saved, &f.identity, 20).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let mut state: serde_json::Value = prep
            .journal
            .read("preparation-state.json", &f.identity)
            .unwrap();
        state["attempt"] = serde_json::json!(id);
        state["read"]["used"] = serde_json::json!(10);
        prep.journal
            .write("preparation-state.json", &state, &f.identity)
            .unwrap();
        let path = prep.journal.root.join("stage").join(&id);
        std::os::unix::fs::symlink(f.root.join("missing"), &path).unwrap();
        assert_eq!(
            prep.stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_cache_cleanup_pending")
        );
        assert_eq!(prep.view(&f.saved, &f.identity).unwrap().spent, 10);
        assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
    }
    #[test]
    fn reference_preparation_keeps_unknown_stage_and_refuses_missing_budget_checkpoint() {
        let f = Fixture::new();
        let base = f.root.join("data");
        let entry = crate::photo_sources::SourceFile {
            relative: "original.jpg".into(),
            bytes: 10,
        };
        let mut prep = Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry.clone(),
            true,
        )
        .unwrap();
        prep.approve_with(&f.saved, &f.identity, 10).unwrap();
        let stage = prep.journal.root.join("stage");
        fs::create_dir(stage.join("unknown")).unwrap();
        assert_eq!(
            prep.stage_with(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
                .err()
                .as_deref(),
            Some("source_cache_cleanup_pending")
        );
        assert_eq!(prep.view(&f.saved, &f.identity).unwrap().spent, 0);
        let journal = prep.journal.root.clone();
        drop(prep);
        fs::remove_file(journal.join("preparation-state.json")).unwrap();
        assert!(Preparation::open_with(
            &base,
            &f.saved,
            &f.identity,
            f.approval.clone(),
            entry,
            true
        )
        .is_err());
        assert!(stage.join("unknown").exists());
    }
    #[test]
    fn prepared_stage_is_handed_off_without_granting_or_spending_more_reads() {
        let f = Fixture::new();
        let job = Arc::new(f.job(0, 0));
        job.adopt(&f.saved, &f.identity, &f.root.join("seed"), &|| Ok(()))
            .unwrap();
        assert!(!f.root.join("seed").join(&f.resource.id).exists());
        let state = job.state(&f.saved, &f.identity).unwrap();
        assert_eq!(state.stage.as_deref(), Some(f.resource.id.as_str()));
        assert_eq!(
            (
                state.read.used,
                state.read.limit,
                state.upload.used,
                state.upload.limit
            ),
            (0, 0, 0, 0)
        );
        job.adopt(&f.saved, &f.identity, &f.root.join("seed"), &|| Ok(()))
            .unwrap();
        let copy = job
            .stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert_eq!(copy.sha256, f.resource.sha256);
        assert_eq!(
            fs::read(f.root.join("source/original.jpg")).unwrap(),
            b"abcdefghij"
        );
    }
    #[test]
    fn prepared_stage_corruption_and_unknown_destinations_are_retained() {
        for unknown_destination in [false, true] {
            let f = Fixture::new();
            let job = Arc::new(f.job(0, 0));
            let source = f.root.join("seed").join(&f.resource.id);
            let target = job.journal.root.join("stage").join(&f.resource.id);
            if unknown_destination {
                fs::create_dir(&target).unwrap();
                fs::write(target.join("unknown"), b"keep").unwrap();
            } else {
                fs::write(source.join("original"), b"corruption").unwrap();
            }
            assert!(job
                .adopt(&f.saved, &f.identity, &f.root.join("seed"), &|| Ok(()))
                .is_err());
            assert!(source.exists());
            if unknown_destination {
                assert_eq!(fs::read(target.join("unknown")).unwrap(), b"keep");
            }
            assert!(job.state(&f.saved, &f.identity).unwrap().stage.is_none());
        }
    }
    #[test]
    fn prepared_stage_handoff_recovers_after_a_late_stop_without_original_reads() {
        let f = Fixture::new();
        let job = Arc::new(f.job(0, 0));
        let target = job.journal.root.join("stage").join(&f.resource.id);
        assert!(job
            .adopt(&f.saved, &f.identity, &f.root.join("seed"), &|| {
                if target.exists() {
                    Err("source_copy_cancelled".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert!(target.join("original").is_file());
        job.adopt(&f.saved, &f.identity, &f.root.join("seed"), &|| Ok(()))
            .unwrap();
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().read.used, 0);
    }
    #[test]
    fn prepared_stage_with_unexpected_files_is_not_transferred() {
        let f = Fixture::new();
        let job = Arc::new(f.job(0, 0));
        let unknown = f.root.join("seed").join(&f.resource.id).join("unknown");
        fs::write(&unknown, b"keep").unwrap();
        assert!(job
            .adopt(&f.saved, &f.identity, &f.root.join("seed"), &|| Ok(()))
            .is_err());
        assert_eq!(fs::read(unknown).unwrap(), b"keep");
        assert!(job.state(&f.saved, &f.identity).unwrap().stage.is_none());
    }
    #[test]
    fn prepared_stage_survives_job_restart_with_unchanged_allowances() {
        let f = Fixture::new();
        let job = Arc::new(f.job(0, 0));
        job.adopt(&f.saved, &f.identity, &f.root.join("seed"), &|| Ok(()))
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
        job.stage(&f.saved, &f.identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert_eq!(job.state(&f.saved, &f.identity).unwrap().read.used, 0);
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
    #[tokio::test]
    async fn draining_preserves_unconfirmed_shutdown_over_the_cancel_error() {
        let f = Fixture::new();
        let job = Arc::new(f.job(10, 20));
        for code in [
            "source_copy_shutdown_unconfirmed",
            "source_read_shutdown_unconfirmed",
            "server_http_500",
        ] {
            let stop = Arc::new(AtomicBool::new(false));
            let operation = Arc::new(Operation {
                owner: job.begin().unwrap(),
                saved: f.saved.clone(),
                identity: serde_json::from_slice(&serde_json::to_vec(&f.identity).unwrap())
                    .unwrap(),
                cancelled: Arc::new(AtomicBool::new(true)),
                stop: stop.clone(),
                lease: std::sync::atomic::AtomicU64::new(
                    crate::resource_bridge::now().unwrap() + 60_000,
                ),
                epoch: 1,
                started: crate::resource_bridge::now().unwrap(),
                policy: std::sync::Mutex::new((std::time::Instant::now(), None)),
            });
            let mut claim:crate::resource_bridge::ReadClaim=serde_json::from_value(serde_json::json!({"id":uuid::Uuid::new_v4().to_string(),"sourceId":f.resource.source_id(),"scopeFingerprint":f.resource.scope_fingerprint(),"authorizationEpoch":1,"resourceKey":f.resource.resource_key(),"version":f.resource.version(),"sha256":f.resource.sha256,"bytes":10,"claimFence":1,"claimToken":"a".repeat(64),"leaseUntil":"2026-10-22T00:01:00Z","deadline":"2026-10-22T00:05:00Z"})).unwrap();
            let result = keep_alive(&operation, &mut claim, async {
                while !stop.load(Ordering::Acquire) {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                Err::<(), String>(code.into())
            })
            .await;
            assert_eq!(
                result.unwrap_err(),
                if code == "server_http_500" {
                    "source_delivery_interrupted"
                } else {
                    code
                }
            );
        }
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
