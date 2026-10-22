use super::*;
use crate::{copy_source::CopyApproval, photo_sources::SourceFile};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    source: String,
    scope: String,
    entry: SourceFile,
    export: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Progress {
    plan_hash: String,
    read: Budget,
    attempt: Option<String>,
    resource: Option<StagedCopy>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparationView {
    pub source_id: String,
    pub maximum_bytes: u64,
    pub export: bool,
    pub spent: u64,
    pub remaining: u64,
    pub prepared: bool,
}
/// One selected resource per source, retained until its verified cache is handed off.
/// The application must drain and retain this owner through any blocking preparation task.
pub struct Preparation {
    pub(super) journal: Journal,
    approval: CopyApproval,
    plan: Plan,
    owner: fs::File,
    root_identity: String,
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
        let consent = crate::source_import::current(saved, identity, source)?;
        let approval = consent.approval(saved, identity)?;
        let scan = approval.files()?;
        if scan.inventory.truncated || scan.unreadable != 0 {
            return Err("source_inventory_partial".into());
        }
        let entry = scan
            .files
            .into_iter()
            .find(|entry| entry.relative == relative)
            .ok_or("source_item_unavailable")?;
        Self::open_with(base, saved, identity, approval.clone(), entry, true)
    }
    pub fn resume(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        source: &str,
    ) -> Result<Self, String> {
        let consent = crate::source_import::current(saved, identity, source)?;
        let approval = consent.approval(saved, identity)?.clone();
        if !canonical_uuid(source) {
            return Err("source_stage_invalid".into());
        }
        let journal = Journal {
            root: base.join("photo-preparations").join(source),
        };
        let plan: Plan = journal.read("preparation-plan.json", identity)?;
        Self::open_with(base, saved, identity, approval, plan.entry, false)
    }
    pub(super) fn open_with(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        approval: CopyApproval,
        entry: SourceFile,
        create: bool,
    ) -> Result<Self, String> {
        approval.validate_current(saved, identity)?;
        if !canonical_uuid(approval.source_id())
            || entry.bytes == 0
            || entry.bytes > 2 * 1024 * 1024 * 1024
        {
            return Err("source_read_budget_invalid".into());
        }
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
        let plan = Plan {
            source: approval.source_id().into(),
            scope: approval.fingerprint(),
            entry,
            export: approval.is_photos(),
        };
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
                    read: Budget { used: 0, limit: 0 },
                    attempt: None,
                    resource: None,
                },
                identity,
            )?;
        }
        let recorded: Plan = journal.read("preparation-plan.json", identity)?;
        if hash(&recorded)? != hash(&plan)? {
            return Err("source_approval_changed".into());
        }
        let result = Self {
            journal,
            approval,
            plan,
            owner,
            root_identity,
        };
        result.progress(saved, identity)?;
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
        self.approval.validate_current(saved, identity)?;
        let state: Progress = self.journal.read("preparation-state.json", identity)?;
        if state.plan_hash != hash(&self.plan)?
            || state.read.used > state.read.limit
            || state.read.limit > 9_007_199_254_740_991
            || state.attempt.as_ref().is_some_and(|id| !canonical_uuid(id))
            || state
                .resource
                .as_ref()
                .is_some_and(|copy| state.attempt.as_ref() != Some(&copy.id))
        {
            return Err("source_journal_invalid".into());
        }
        Ok(state)
    }
    fn current(&self, saved: &SavedConnection, identity: &DeviceIdentity) -> Result<(), String> {
        self.require_owner()?;
        let consent = crate::source_import::current(saved, identity, &self.plan.source)?;
        if consent.approval(saved, identity)?.fingerprint() != self.plan.scope {
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
        Ok(PreparationView {
            source_id: self.plan.source.clone(),
            maximum_bytes: self.plan.entry.bytes,
            export: self.plan.export,
            spent: state.read.used,
            remaining: state.read.limit - state.read.used,
            prepared: state.resource.is_some(),
        })
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
        if additional == 0
            || additional > self.plan.entry.bytes.saturating_mul(2)
            || state.resource.is_some()
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
            .write("preparation-state.json", &state, identity)
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
        // A lost reply may leave the verified cache in its read job already.
        if self.progress(saved, identity)?.resource.is_none() {
            self.stage_with(saved, identity, cancelled, &check)?;
        }
        self.handoff_with(saved, identity, &check)?;
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
        let state = self.progress(saved, identity)?;
        let copy = state.resource.ok_or("source_stage_unavailable")?;
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
        job.adopt(saved, identity, &self.journal.root.join("stage"), gate)?;
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
        let mut state = self.progress(saved, identity)?;
        let stage = self.journal.root.join("stage");
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
        let copy = if let Some(id) = existing {
            if !stage.join(id).join("receipt.json").exists() {
                return Err("source_cache_cleanup_pending".into());
            }
            StagedCopy::restore_with_gate(saved, identity, &stage, id, &check)?
        } else {
            if state.resource.is_some() {
                return Err("source_stage_unavailable".into());
            }
            state
                .read
                .reserve(self.plan.entry.bytes, "source_read_budget_exhausted")?;
            let id = uuid::Uuid::new_v4().to_string();
            state.attempt = Some(id.clone());
            self.journal
                .write("preparation-state.json", &state, identity)?;
            check()?;
            self.approval.stage_to(
                saved,
                identity,
                &self.plan.entry.relative,
                &stage,
                &id,
                Some(self.plan.entry.bytes),
                cancelled,
                &check,
            )?
        };
        if copy.source_id() != self.plan.source
            || copy.scope_fingerprint() != self.plan.scope
            || !copy.matches_entry(&self.plan.entry.relative, self.plan.entry.bytes)
            || state.resource.as_ref().is_some_and(|old| {
                old.resource_key() != copy.resource_key()
                    || old.version() != copy.version()
                    || old.sha256 != copy.sha256
                    || old.bytes != copy.bytes
            })
        {
            return Err("source_stage_changed".into());
        }
        copy.validate_current(saved, identity)?;
        check()?;
        state.resource = Some(copy.clone());
        self.journal
            .write("preparation-state.json", &state, identity)?;
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
