use super::*;

impl Preparation {
    /// Discards only an abandoned preparation attempt; job-owned resources remain independent.
    pub fn discard(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        expected: &str,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<PreparationView, String> {
        self.discard_state(saved, identity, expected, &|| {
            self.current_control(saved, identity)?;
            gate()
        })
    }
    #[cfg(test)]
    pub(in crate::source_reads) fn discard_with(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        expected: &str,
        gate: &dyn Fn() -> Result<(), String>,
    ) -> Result<PreparationView, String> {
        self.discard_state(saved, identity, expected, gate)
    }
    fn discard_state(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        expected: &str,
        gate: &dyn Fn() -> Result<(), String>,
    ) -> Result<PreparationView, String> {
        gate()?;
        if !crate::native_runtime::digest_valid(expected, 64) {
            return Err("source_scan_changed".into());
        }
        let plan = if expected == self.plan_hash {
            self.plan.clone()
        } else {
            self.journal
                .read(&format!("preparation-plan-{expected}.json"), identity)?
        };
        let state = self.recorded_progress(saved, identity, &plan, expected)?;
        if !state.abandoned {
            return Err("source_scan_not_abandoned".into());
        }
        let Some(id) = state.attempt.as_deref() else {
            return self.view(saved, identity);
        };
        if state.handoff_started == Some(true)
            || (state.resource.is_some() && state.handoff_started.is_none())
        {
            return Err("source_cache_cleanup_pending".into());
        }
        if let Some(copy) = &state.resource {
            copy.validate_receipt(saved, identity)?;
            if copy.source_id() != plan.source || copy.scope_fingerprint() != plan.scope {
                return Err("source_journal_invalid".into());
            }
        }
        let base = self
            .journal
            .root
            .parent()
            .and_then(Path::parent)
            .ok_or("source_journal_invalid")?;
        crate::runtime_store::private_directory(&base.join("photo-reads"))?;
        let root = base.join("photo-reads").join(&plan.source);
        if matches!(fs::symlink_metadata(&root), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            scans::require_no_job_history(self, gate)?;
        }
        crate::runtime_store::private_directory(&root)?;
        let dir = Dir::open_ambient_dir(&root, ambient_authority())
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
        let root_identity = crate::copy_source::source_root_identity(&dir)?;
        let check = || -> Result<(), String> {
            self.require_owner()?;
            gate()?;
            crate::native_runtime::absolute_directory(&root)?;
            let named_root = Dir::open_ambient_dir(&root, ambient_authority())
                .map_err(|_| "source_journal_invalid")?;
            let named = named_root
                .open_with(".owner.lock", &crate::host_state::options(false))
                .map_err(|_| "source_journal_invalid")?;
            let held = cap_std::fs::File::from_std(
                owner.try_clone().map_err(|_| "source_journal_invalid")?,
            );
            if crate::copy_source::source_root_identity(&named_root)? != root_identity
                || crate::copy_source::opened_stamp(&named)?
                    != crate::copy_source::opened_stamp(&held)?
            {
                return Err("source_journal_invalid".into());
            }
            Ok(())
        };
        check()?;
        // Even an intent written before the cache move belongs to the job, not this discard action.
        for (index, entry) in fs::read_dir(&root)
            .map_err(|_| "source_journal_invalid")?
            .enumerate()
        {
            if index >= 10_002 {
                return Err("source_inventory_partial".into());
            }
            check()?;
            let entry = entry.map_err(|_| "source_journal_invalid")?;
            let name = entry.file_name();
            if matches!(
                name.to_str(),
                Some(".owner.lock" | ".poll-owner.lock" | "publications")
            ) {
                continue;
            }
            if !name
                .to_str()
                .is_some_and(|name| crate::native_runtime::digest_valid(name, 64))
            {
                return Err("source_journal_invalid".into());
            }
            let job: State = Journal { root: entry.path() }.read("state.json", identity)?;
            job.validate()?;
            job.resource.validate_receipt(saved, identity)?;
            if job.resource.source_id() != plan.source
                || name.to_str()
                    != Some(&job_key(
                        &job.resource.resource_key(),
                        &job.resource.version(),
                    ))
            {
                return Err("source_journal_invalid".into());
            }
            if job.resource.id == id
                || job.stage.as_deref() == Some(id)
                || job.cleaned.as_deref() == Some(id)
            {
                return Err("source_cache_cleanup_pending".into());
            }
        }
        let mut budget = crate::private_inputs::InputBudget::open(base, identity)?;
        budget.remaining()?;
        check()?;
        crate::copy_source::release_stage(&self.journal.root.join(plan.stage_name()), id)?;
        check()?;
        budget.release(&plan.source, id)?;
        self.view(saved, identity)
    }
}
