mod capacity;
mod discard;
mod inventory;
mod scans;
mod status;
use super::*;
use crate::{copy_source::CopyApproval, photo_sources::SourceFile};
pub use status::ReferenceStatus;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    source: String,
    scope: String,
    entry: SourceFile,
    export: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    additional: Vec<SourceFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generation: Option<scans::Generation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    photos_snapshots: Vec<scans::PhotoSnapshot>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Progress {
    plan_hash: String,
    #[serde(default, skip_serializing_if = "is_false")]
    abandoned: bool,
    // Absence is legacy; it cannot prove that a verified cache was never claimed by a job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handoff_started: Option<bool>,
    read: Budget,
    attempt: Option<String>,
    resource: Option<StagedCopy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion: Option<Completion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    released_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt_bytes: Option<u64>,
}
fn is_false(value: &bool) -> bool {
    !value
}
const STAGING_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Completion {
    position: usize,
    staged_bytes: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedResource {
    pub id: String,
    pub resource_key: String,
    pub version: String,
    pub sha256: String,
    pub bytes: u64,
}
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InventoryRecord {
    plan_hash: String,
    index: usize,
    resource: PreparedResource,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparationView {
    pub source_id: String,
    pub scan_id: String,
    pub abandoned: bool,
    pub maximum_bytes: u64,
    pub export: bool,
    pub spent: u64,
    pub remaining: u64,
    pub prepared: bool,
    pub resources: usize,
    pub completed: usize,
    pub staging_remaining: u64,
}
/// A frozen source selection, with one owned resource preparation at a time.
/// The application must drain and retain this owner through any blocking preparation task.
pub struct Preparation {
    pub(super) journal: Journal,
    approval: CopyApproval,
    plan: Plan,
    owner: fs::File,
    root_identity: String,
    plan_hash: String,
    total_bytes: u64,
}
impl Preparation {
    /// Metadata inventory creates no original-read or export allowance.
    pub fn plan(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        source: &str,
        relative: &str,
    ) -> Result<Self, String> {
        Self::plan_selection(base, saved, identity, source, &[relative.to_owned()])
    }
    pub fn plan_selection(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        source: &str,
        relatives: &[String],
    ) -> Result<Self, String> {
        let consent = crate::source_import::current(saved, identity, source)?;
        let approval = consent.reference_approval(saved, identity)?;
        let selected = Self::select(approval, relatives)?;
        Self::open_selection(base, saved, identity, approval.clone(), selected, true)
    }
    pub fn resume(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        source: &str,
    ) -> Result<Self, String> {
        let consent = crate::source_import::current(saved, identity, source)?;
        let approval = consent.reference_approval(saved, identity)?.clone();
        Self::open_recorded(base, saved, identity, approval, true)
    }
    pub fn resume_control(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        source: &str,
    ) -> Result<Self, String> {
        Self::open_recorded(
            base,
            saved,
            identity,
            Self::control_approval(saved, identity, source)?,
            false,
        )
    }
    fn control_approval(
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        source: &str,
    ) -> Result<CopyApproval, String> {
        let consent = crate::credentials::load::<crate::source_consent::Consent>(
            crate::source_consent::CREDENTIAL,
        )?
        .ok_or("source_approval_required")?;
        if consent.source_id() != source {
            return Err("source_approval_changed".into());
        }
        let approval = consent.reference_control_approval(saved, identity)?.clone();
        Ok(approval)
    }
    fn open_recorded(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        approval: CopyApproval,
        provider: bool,
    ) -> Result<Self, String> {
        let source = approval.source_id();
        if !canonical_uuid(source) {
            return Err("source_stage_invalid".into());
        }
        let journal = Journal {
            root: base.join("photo-preparations").join(source),
        };
        let plan: Plan = journal.read("preparation-plan.json", identity)?;
        let mut entries = vec![plan.entry];
        entries.extend(plan.additional);
        Self::open_selection_checked(base, saved, identity, approval, entries, false, provider)
    }
    #[cfg(test)]
    pub(super) fn open_with(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        approval: CopyApproval,
        entry: SourceFile,
        create: bool,
    ) -> Result<Self, String> {
        Self::open_selection(base, saved, identity, approval, vec![entry], create)
    }
    pub(super) fn open_selection(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        approval: CopyApproval,
        entries: Vec<SourceFile>,
        create: bool,
    ) -> Result<Self, String> {
        Self::open_selection_checked(base, saved, identity, approval, entries, create, true)
    }
    #[allow(clippy::too_many_arguments)]
    fn open_selection_checked(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        approval: CopyApproval,
        entries: Vec<SourceFile>,
        create: bool,
        provider: bool,
    ) -> Result<Self, String> {
        if provider {
            approval.validate_current(saved, identity)?;
        } else {
            approval.validate(saved, identity)?;
        }
        if !canonical_uuid(approval.source_id()) {
            return Err("source_read_budget_invalid".into());
        }
        let mut entries = entries.into_iter();
        let entry = entries.next().ok_or("source_selection_invalid")?;
        let mut plan = Plan {
            source: approval.source_id().into(),
            scope: approval.fingerprint(),
            entry,
            export: approval.is_photos(),
            additional: entries.collect(),
            generation: None,
            photos_snapshots: Vec::new(),
        };
        let total_bytes = plan.total()?;
        crate::native_runtime::absolute_directory(base)?;
        if !approval.is_photos()
            && (base.starts_with(approval.root()) || approval.root().starts_with(base))
        {
            return Err("source_staging_overlap".into());
        }
        let parent = base.join("photo-preparations");
        let root = parent.join(approval.source_id());
        if !create {
            crate::native_runtime::absolute_directory(&root)?;
        }
        crate::runtime_store::private_directory(&parent)?;
        crate::runtime_store::private_directory(&root)?;
        let dir = Dir::open_ambient_dir(&root, ambient_authority())
            .map_err(|_| "source_journal_invalid")?;
        let owner = dir
            .open_with(".owner.lock", &crate::host_state::options(true))
            .map_err(|_| "source_journal_invalid")?
            .into_std();
        crate::host_state::valid_file(&owner)?;
        owner
            .try_lock()
            .map_err(|_| "source_read_already_running")?;
        let root_identity = crate::copy_source::source_root_identity(&dir)?;
        let journal = Journal { root };
        let plan_path = journal.root.join("preparation-plan.json");
        if create && !super::preparation::present(&plan_path)? {
            // A missing checkpoint cannot silently reset a previously spent allowance.
            if dir
                .entries()
                .map_err(|_| "source_journal_invalid")?
                .take(2)
                .count()
                != 1
            {
                return Err("source_journal_invalid".into());
            }
            crate::runtime_store::private_directory(&journal.root.join("stage"))?;
            journal.write("preparation-plan.json", &plan, identity)?;
            journal.write(
                "preparation-state.json",
                &Progress {
                    plan_hash: hash(&plan)?,
                    abandoned: false,
                    handoff_started: None,
                    read: Budget { used: 0, limit: 0 },
                    attempt: None,
                    resource: None,
                    completion: None,
                    released_bytes: None,
                    attempt_bytes: None,
                },
                identity,
            )?;
        }
        let recorded: Plan = journal.read("preparation-plan.json", identity)?;
        plan.generation = recorded.generation.clone();
        plan.photos_snapshots = recorded.photos_snapshots.clone();
        plan.validate_photos(&approval)?;
        plan.total()?;
        let plan_hash = hash(&plan)?;
        if hash(&recorded)? != plan_hash {
            return Err("source_approval_changed".into());
        }
        let result = Self {
            journal,
            approval,
            plan,
            owner,
            root_identity,
            plan_hash,
            total_bytes,
        };
        result.resources_with(saved, identity)?;
        Ok(result)
    }
    fn require_owner(&self) -> Result<(), String> {
        crate::native_runtime::absolute_directory(&self.journal.root)?;
        let dir = Dir::open_ambient_dir(&self.journal.root, ambient_authority())
            .map_err(|_| "source_journal_invalid")?;
        if crate::copy_source::source_root_identity(&dir)? != self.root_identity {
            return Err("source_journal_invalid".into());
        }
        crate::host_state::valid_file(&self.owner)?;
        let named = dir
            .open_with(".owner.lock", &crate::host_state::options(false))
            .map_err(|_| "source_journal_invalid")?;
        let held = cap_std::fs::File::from_std(
            self.owner
                .try_clone()
                .map_err(|_| "source_journal_invalid")?,
        );
        if crate::copy_source::opened_stamp(&named)? != crate::copy_source::opened_stamp(&held)? {
            return Err("source_journal_invalid".into());
        }
        Ok(())
    }
    fn progress(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<Progress, String> {
        self.require_owner()?;
        let active: Plan = self.journal.read("preparation-plan.json", identity)?;
        if hash(&active)? != self.plan_hash {
            return Err("source_scan_changed".into());
        }
        self.recorded_progress(saved, identity, &self.plan, &self.plan_hash)
    }
    fn recorded_progress(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        plan: &Plan,
        expected: &str,
    ) -> Result<Progress, String> {
        self.require_owner()?;
        self.approval.validate(saved, identity)?;
        if plan.source != self.plan.source
            || plan.scope != self.plan.scope
            || plan.export != self.plan.export
            || hash(plan)? != expected
        {
            return Err("source_journal_invalid".into());
        }
        plan.validate_photos(&self.approval)?;
        let total_bytes = plan.total()?;
        let state: Progress = self.journal.read(&plan.state_name(), identity)?;
        if state.plan_hash != expected
            || state.read.used > state.read.limit
            || state.read.limit > 9_007_199_254_740_991
            || state.position() > plan.count()
            || state.completion.as_ref().is_some_and(|done| {
                done.position == 0
                    || done.staged_bytes < done.position as u64
                    || done.staged_bytes > total_bytes
            })
            || (state.position() == plan.count()
                && (state.resource.is_some() || state.attempt.is_some()))
            || state.released_bytes.unwrap_or(0) > state.staged_bytes()
            || state.attempt.as_ref().is_some_and(|id| !canonical_uuid(id))
            || (state.handoff_started.is_some() && state.attempt.is_none())
            || (state.handoff_started == Some(true) && state.resource.is_none())
            || state
                .resource
                .as_ref()
                .is_some_and(|copy| state.attempt.as_ref() != Some(&copy.id))
        {
            return Err("source_journal_invalid".into());
        }
        state.reservation(plan)?;
        Ok(state)
    }
    fn current(&self, saved: &SavedConnection, identity: &DeviceIdentity) -> Result<(), String> {
        self.require_owner()?;
        let consent = crate::source_import::current(saved, identity, &self.plan.source)?;
        if consent.reference_approval(saved, identity)?.fingerprint() != self.plan.scope {
            return Err("source_approval_changed".into());
        }
        Ok(())
    }
    pub fn view(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<PreparationView, String> {
        let state = self.progress(saved, identity)?;
        let reserved = state.reservation(&self.plan)?;
        let staging_remaining = STAGING_LIMIT.saturating_sub(
            state
                .retained_bytes()
                .checked_add(reserved)
                .ok_or("source_journal_invalid")?,
        );
        Ok(PreparationView {
            source_id: self.plan.source.clone(),
            scan_id: self.plan_hash.clone(),
            abandoned: state.abandoned,
            maximum_bytes: self.total_bytes,
            export: self.plan.export,
            spent: state.read.used,
            remaining: if state.abandoned {
                0
            } else {
                state.read.limit - state.read.used
            },
            prepared: !state.abandoned && state.position() == self.plan.count(),
            resources: self.plan.count(),
            completed: state.position(),
            staging_remaining,
        })
    }
    fn current_control(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<(), String> {
        self.require_owner()?;
        let consent = crate::credentials::load::<crate::source_consent::Consent>(
            crate::source_consent::CREDENTIAL,
        )?
        .ok_or("source_approval_required")?;
        if consent.source_id() != self.plan.source
            || consent.reference_metadata_scope(saved, identity)? != self.plan.scope
        {
            return Err("source_approval_changed".into());
        }
        Ok(())
    }
    pub fn abandon(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        expected: &str,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<PreparationView, String> {
        self.abandon_state(saved, identity, expected, &|| {
            self.current_control(saved, identity)?;
            gate()
        })
    }
    fn abandon_state(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        expected: &str,
        gate: &dyn Fn() -> Result<(), String>,
    ) -> Result<PreparationView, String> {
        gate()?;
        if expected != self.plan_hash {
            return Err("source_scan_changed".into());
        }
        let mut state = self.progress(saved, identity)?;
        if !state.abandoned {
            state.abandoned = true;
            gate()?;
            self.journal
                .write(&self.plan.state_name(), &state, identity)?;
        }
        self.view(saved, identity)
    }
    #[cfg(test)]
    pub(super) fn abandon_with(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        expected: &str,
        gate: &dyn Fn() -> Result<(), String>,
    ) -> Result<PreparationView, String> {
        self.abandon_state(saved, identity, expected, gate)
    }
    pub fn rescan(
        &mut self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        relatives: &[String],
        expected: &str,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<PreparationView, String> {
        self.current(saved, identity)?;
        let entries = Self::select(&self.approval, relatives)?;
        let next = scans::transition(self, saved, identity, entries, expected, &|| {
            self.current(saved, identity)?;
            gate()
        })?;
        self.plan = next.plan;
        self.plan_hash = next.hash;
        self.total_bytes = next.total;
        self.view(saved, identity)
    }
    #[cfg(test)]
    pub(super) fn rescan_with(
        &mut self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        entries: Vec<SourceFile>,
        expected: &str,
        gate: &dyn Fn() -> Result<(), String>,
    ) -> Result<PreparationView, String> {
        let next = scans::transition(self, saved, identity, entries, expected, gate)?;
        self.plan = next.plan;
        self.plan_hash = next.hash;
        self.total_bytes = next.total;
        self.view(saved, identity)
    }
    #[cfg(test)]
    pub(super) fn recorded_resources(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<Vec<PreparedResource>, String> {
        self.resources_with(saved, identity)
    }
    /// Reclaims only reservations whose signed job and empty staging prove cleanup completed.
    pub fn reconcile_capacity(
        &mut self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<PreparationView, String> {
        let _owner = self.reconcile_with(saved, identity, &|| {
            self.current(saved, identity)?;
            gate()
        })?;
        self.view(saved, identity)
    }
    pub(super) fn reconcile_with(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<Option<Job>, String> {
        capacity::reconcile(self, saved, identity, gate)
    }
    /// An additional local approval never replaces the already spent amount.
    pub fn approve(
        &mut self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        additional: u64,
    ) -> Result<(), String> {
        self.current(saved, identity)?;
        self.approve_with(saved, identity, additional)
    }
    pub(super) fn approve_with(
        &mut self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        additional: u64,
    ) -> Result<(), String> {
        let mut state = self.progress(saved, identity)?;
        if state.abandoned {
            return Err("source_scan_abandoned".into());
        }
        if additional == 0
            || additional > self.total_bytes.saturating_mul(2)
            || state.resource.is_some()
            || state.position() == self.plan.count()
        {
            return Err("source_read_budget_invalid".into());
        }
        state.read.limit = state
            .read
            .limit
            .checked_add(additional)
            .filter(|limit| *limit <= 9_007_199_254_740_991)
            .ok_or("source_read_budget_invalid")?;
        self.journal
            .write(&self.plan.state_name(), &state, identity)
    }
    pub fn stage(
        &mut self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        cancelled: &AtomicBool,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<StagedCopy, String> {
        self.stage_with(saved, identity, cancelled, &|| {
            self.current(saved, identity)?;
            gate()
        })
    }
    pub fn stage_and_handoff(
        &mut self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        cancelled: &AtomicBool,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<PreparationView, String> {
        self.finish_with(saved, identity, cancelled, &|| {
            self.current(saved, identity)?;
            gate()
        })
    }
    pub(super) fn finish_with(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        cancelled: &AtomicBool,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<PreparationView, String> {
        let check = || {
            if cancelled.load(Ordering::Acquire) {
                return Err("source_copy_cancelled".into());
            }
            gate()
        };
        check()?;
        let state = self.progress(saved, identity)?;
        if state.abandoned {
            return Err("source_scan_abandoned".into());
        }
        if state.position() == self.plan.count() {
            return self.view(saved, identity);
        }
        // A lost reply may leave the verified cache in its read job already.
        if state.resource.is_none() {
            self.stage_with(saved, identity, cancelled, &check)?;
        }
        let job = self.handoff_with(saved, identity, &check)?;
        check()?;
        self.complete(saved, identity, &job.resource)?;
        check()?;
        self.view(saved, identity)
    }
    /// Moves the prepared cache into a read job with no additional read or upload authority.
    pub fn handoff(
        &mut self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<Arc<Job>, String> {
        self.handoff_with(saved, identity, &|| {
            self.current(saved, identity)?;
            gate()
        })
    }
    pub(super) fn handoff_with(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<Arc<Job>, String> {
        gate()?;
        let mut state = self.progress(saved, identity)?;
        if state.abandoned {
            return Err("source_scan_abandoned".into());
        }
        let copy = state
            .resource
            .as_ref()
            .ok_or("source_stage_unavailable")?
            .clone();
        if state.handoff_started != Some(true) {
            state.handoff_started = Some(true);
            gate()?;
            self.journal
                .write(&self.plan.state_name(), &state, identity)?;
        }
        let base = self
            .journal
            .root
            .parent()
            .and_then(Path::parent)
            .ok_or("source_journal_invalid")?;
        let key = copy.resource_key();
        let version = copy.version();
        let record = base
            .join("photo-reads")
            .join(copy.source_id())
            .join(job_key(&key, &version))
            .join("state.json");
        let initial = if super::preparation::present(&record)? {
            None
        } else {
            Some(State::new(copy.clone(), 0, 0)?)
        };
        let job = Arc::new(Job::open(
            base,
            saved,
            identity,
            copy.source_id(),
            &key,
            &version,
            initial,
        )?);
        if job.resource.id != copy.id {
            return Err("source_cache_cleanup_pending".into());
        }
        job.adopt(
            saved,
            identity,
            &self.journal.root.join(self.plan.stage_name()),
            gate,
        )?;
        Ok(job)
    }
    pub(super) fn stage_with(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        cancelled: &AtomicBool,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<StagedCopy, String> {
        let check = || {
            if cancelled.load(Ordering::Acquire) {
                return Err("source_copy_cancelled".into());
            }
            self.require_owner()?;
            self.approval.validate_current(saved, identity)?;
            gate()
        };
        check()?;
        if self.progress(saved, identity)?.abandoned {
            return Err("source_scan_abandoned".into());
        }
        let _capacity_owner = self.reconcile_with(saved, identity, &check)?;
        let mut state = self.progress(saved, identity)?;
        let entry = self.plan.entry_at(state.position())?;
        let stage = self.journal.root.join(self.plan.stage_name());
        crate::native_runtime::absolute_directory(&stage)?;
        let dir = Dir::open_ambient_dir(&stage, ambient_authority())
            .map_err(|_| "source_stage_unavailable")?;
        for entry in dir.entries().map_err(|_| "source_stage_unavailable")? {
            let name = entry.map_err(|_| "source_stage_unavailable")?.file_name();
            if state.attempt.as_deref() != name.to_str() {
                return Err("source_cache_cleanup_pending".into());
            }
        }
        let existing = match state.attempt.as_ref() {
            Some(id) => match fs::symlink_metadata(stage.join(id)) {
                Ok(meta) if meta.is_dir() && !meta.is_symlink() => Some(id),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                _ => return Err("source_cache_cleanup_pending".into()),
            },
            None => None,
        };
        let base = self
            .journal
            .root
            .parent()
            .and_then(Path::parent)
            .ok_or("source_journal_invalid")?;
        let mut budget = crate::private_inputs::InputBudget::open(base, identity)?;
        let copy = if let Some(id) = existing {
            if !stage.join(id).join("receipt.json").exists() {
                return Err("source_cache_cleanup_pending".into());
            }
            StagedCopy::restore_with_gate(saved, identity, &stage, id, &check)?
        } else {
            if state.resource.is_some() {
                return Err("source_stage_unavailable".into());
            }
            let maximum = state.reserve_attempt(entry, self.plan.export, budget.remaining()?)?;
            let id = state.attempt.as_ref().ok_or("source_journal_invalid")?;
            self.journal
                .write(&self.plan.state_name(), &state, identity)?;
            check()?;
            budget.reserve(&self.plan.source, id, maximum)?;
            self.approval.stage_with_snapshot(
                saved,
                identity,
                &entry.relative,
                &stage,
                id,
                Some(maximum),
                self.plan.photo_snapshot(&entry.relative),
                cancelled,
                &|| {
                    check()?;
                    budget.check()
                },
            )?
        };
        if copy.source_id() != self.plan.source
            || copy.scope_fingerprint() != self.plan.scope
            || !copy.matches_entry(&entry.relative, entry.bytes)
            || copy.bytes > state.attempt_bytes.unwrap_or(entry.bytes)
            || state.resource.as_ref().is_some_and(|old| {
                old.resource_key() != copy.resource_key()
                    || old.version() != copy.version()
                    || old.sha256 != copy.sha256
                    || old.bytes != copy.bytes
            })
        {
            return Err("source_stage_changed".into());
        }
        if let Some((snapshot, key)) = self.plan.photo_snapshot(&entry.relative) {
            if copy.resource_key() != key || copy.photos_snapshot()?.as_ref() != Some(snapshot) {
                return Err("source_stage_changed".into());
            }
        }
        copy.validate_current(saved, identity)?;
        check()?;
        budget.shrink(&self.plan.source, &copy.id, copy.bytes)?;
        state.resource = Some(copy.clone());
        self.journal
            .write(&self.plan.state_name(), &state, identity)?;
        Ok(copy)
    }
}
fn hash(value: &Plan) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(
            serde_json_canonicalizer::to_vec(value).map_err(|_| "source_journal_invalid")?
        )
    ))
}
