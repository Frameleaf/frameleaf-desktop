use super::*;
impl Plan {
    pub(super) fn count(&self) -> usize {
        1 + self.additional.len()
    }
    pub(super) fn entry_at(&self, position: usize) -> Result<&SourceFile, String> {
        if position == 0 {
            Ok(&self.entry)
        } else {
            self.additional
                .get(position - 1)
                .ok_or("source_preparation_complete".into())
        }
    }
    pub(super) fn total(&self) -> Result<u64, String> {
        if self.generation.as_ref().is_some_and(|g| {
            !canonical_uuid(&g.id) || !crate::native_runtime::digest_valid(&g.previous, 64)
        }) {
            return Err("source_journal_invalid".into());
        }
        if !self.photos_snapshots.is_empty() {
            if !self.export
                || self.photos_snapshots.len() != self.count()
                || self.photos_snapshots.len() > 100
            {
                return Err("source_journal_invalid".into());
            }
            let mut seen = std::collections::HashSet::new();
            for photo in &self.photos_snapshots {
                photo.resource.validate_approved(&photo.resource)?;
                if !seen.insert(&photo.relative)
                    || !crate::native_runtime::digest_valid(&photo.key, 64)
                    || !std::iter::once(&self.entry)
                        .chain(&self.additional)
                        .any(|e| e.relative == photo.relative)
                {
                    return Err("source_journal_invalid".into());
                }
            }
        }
        if self.count() > 10_000 {
            return Err("source_inventory_partial".into());
        }
        let mut seen = std::collections::HashSet::new();
        std::iter::once(&self.entry)
            .chain(&self.additional)
            .try_fold(0u64, |total, entry| {
                if entry.relative.is_empty()
                    || !seen.insert(&entry.relative)
                    || entry.bytes == 0
                    || entry.bytes > STAGING_LIMIT
                {
                    return Err("source_selection_invalid".into());
                }
                total
                    .checked_add(entry.bytes)
                    .filter(|sum| *sum <= 1 << 41)
                    .ok_or("source_read_budget_invalid".into())
            })
    }
}
impl Progress {
    pub(super) fn reservation(&self, plan: &Plan) -> Result<u64, String> {
        if let Some(bytes) = self.attempt_bytes {
            if !plan.export
                || self.attempt.is_none()
                || bytes == 0
                || bytes > plan.entry_at(self.position())?.bytes
                || self
                    .resource
                    .as_ref()
                    .is_some_and(|copy| copy.bytes > bytes)
            {
                return Err("source_journal_invalid".into());
            }
        }
        match (&self.resource, &self.attempt) {
            (Some(copy), _) => Ok(copy.bytes),
            (None, Some(_)) => Ok(self
                .attempt_bytes
                .unwrap_or(plan.entry_at(self.position())?.bytes)),
            _ => Ok(0),
        }
    }
    pub(super) fn reserve_attempt(
        &mut self,
        entry: &SourceFile,
        export: bool,
        available: u64,
    ) -> Result<u64, String> {
        let remaining = STAGING_LIMIT
            .saturating_sub(self.retained_bytes())
            .min(available);
        let maximum = if export {
            entry.bytes.min(remaining)
        } else {
            entry.bytes
        };
        if maximum == 0 || maximum > remaining {
            return Err("source_staging_budget_exceeded".into());
        }
        // The original/hydration allowance remains the full ceiling, even when cache space is smaller.
        self.read
            .reserve(entry.bytes, "source_read_budget_exhausted")?;
        self.attempt = Some(uuid::Uuid::new_v4().to_string());
        self.attempt_bytes = (maximum < entry.bytes).then_some(maximum);
        Ok(maximum)
    }
    pub(super) fn retained_bytes(&self) -> u64 {
        self.staged_bytes() - self.released_bytes.unwrap_or(0)
    }
    pub(super) fn position(&self) -> usize {
        self.completion.as_ref().map_or(0, |done| done.position)
    }
    pub(super) fn staged_bytes(&self) -> u64 {
        self.completion.as_ref().map_or(0, |done| done.staged_bytes)
    }
}
impl Preparation {
    /// A verified snapshot; original access still requires current provider and source authority.
    pub fn prepared_resources(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<Vec<PreparedResource>, String> {
        self.current(saved, identity)?;
        if self.progress(saved, identity)?.abandoned {
            return Err("source_scan_abandoned".into());
        }
        self.resources_with(saved, identity)
    }
    pub(super) fn resources_with(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<Vec<PreparedResource>, String> {
        let state = self.progress(saved, identity)?;
        let mut result = Vec::new();
        let mut keys = std::collections::HashSet::new();
        let mut bytes = 0u64;
        for index in 0..state.position() {
            let record: InventoryRecord = self
                .journal
                .read(&self.plan.inventory_name(index), identity)?;
            let entry = self.plan.entry_at(index)?;
            let resource = &record.resource;
            if record.plan_hash != self.plan_hash
                || record.index != index
                || !canonical_uuid(&resource.id)
                || !crate::native_runtime::digest_valid(&resource.resource_key, 64)
                || !crate::native_runtime::digest_valid(&resource.version, 64)
                || !crate::native_runtime::digest_valid(&resource.sha256, 64)
                || !keys.insert(resource.resource_key.clone())
                || resource.bytes == 0
                || resource.bytes > entry.bytes
                || (!self.plan.export && resource.bytes != entry.bytes)
            {
                return Err("source_journal_invalid".into());
            }
            bytes = bytes
                .checked_add(resource.bytes)
                .ok_or("source_journal_invalid")?;
            result.push(record.resource);
        }
        if bytes != state.staged_bytes() {
            return Err("source_journal_invalid".into());
        }
        Ok(result)
    }
    pub(super) fn complete(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        copy: &StagedCopy,
    ) -> Result<(), String> {
        let mut state = self.progress(saved, identity)?;
        if state.abandoned {
            return Err("source_scan_abandoned".into());
        }
        if state
            .resource
            .as_ref()
            .is_none_or(|current| current.id != copy.id)
        {
            return Err("source_journal_invalid".into());
        }
        let index = state.position();
        let record = InventoryRecord {
            plan_hash: self.plan_hash.clone(),
            index,
            resource: PreparedResource {
                id: copy.id.clone(),
                resource_key: copy.resource_key(),
                version: copy.version(),
                sha256: copy.sha256.clone(),
                bytes: copy.bytes,
            },
        };
        let name = self.plan.inventory_name(index);
        if super::super::preparation::present(&self.journal.root.join(&name))? {
            let previous: InventoryRecord = self.journal.read(&name, identity)?;
            if previous != record {
                return Err("source_journal_invalid".into());
            }
        } else {
            self.journal.write(&name, &record, identity)?;
        }
        if state
            .retained_bytes()
            .checked_add(copy.bytes)
            .is_none_or(|bytes| bytes > STAGING_LIMIT)
        {
            return Err("source_staging_budget_exceeded".into());
        }
        state.completion = Some(Completion {
            position: index + 1,
            staged_bytes: state
                .staged_bytes()
                .checked_add(copy.bytes)
                .filter(|bytes| *bytes <= self.total_bytes)
                .ok_or("source_staging_budget_exceeded")?,
        });
        state.resource = None;
        state.attempt = None;
        state.attempt_bytes = None;
        self.journal
            .write(&self.plan.state_name(), &state, identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export_plan() -> Plan {
        Plan {
            source: "source".into(),
            scope: "scope".into(),
            entry: SourceFile {
                relative: "0/original.HEIC".into(),
                bytes: STAGING_LIMIT,
            },
            export: true,
            additional: Vec::new(),
            generation: None,
            photos_snapshots: Vec::new(),
        }
    }

    #[test]
    fn photos_snapshots_are_optional_for_legacy_plans_but_complete_and_bounded_when_present() {
        let mut plan = export_plan();
        assert!(serde_json::to_value(&plan)
            .unwrap()
            .get("photosSnapshots")
            .is_none());
        let resource = serde_json::from_value(serde_json::json!({"asset":"synthetic-private-id","created":1000,"modified":3000,"index":7,"kind":1,"filename":"original.HEIC"})).unwrap();
        plan.photos_snapshots
            .push(super::super::scans::PhotoSnapshot {
                relative: "0/original.HEIC".into(),
                key: "a".repeat(64),
                resource,
            });
        plan.total().unwrap();
        let mut duplicate = plan.clone();
        duplicate
            .photos_snapshots
            .push(duplicate.photos_snapshots[0].clone());
        assert!(duplicate.total().is_err());
        let mut missing = plan.clone();
        missing.additional.push(SourceFile {
            relative: "1/other.jpg".into(),
            bytes: 10,
        });
        assert!(missing.total().is_err());
        let mut foreign = plan.clone();
        foreign.photos_snapshots[0].relative = "1/other.jpg".into();
        assert!(foreign.total().is_err());
        let mut invalid_key = plan.clone();
        invalid_key.photos_snapshots[0].key = "invalid".into();
        assert!(invalid_key.total().is_err());
    }
    #[test]
    fn export_admission_uses_remaining_space_but_spends_the_full_read_ceiling() {
        let plan = export_plan();
        let mut progress: Progress = serde_json::from_value(serde_json::json!({
            "planHash": "signed-plan", "read": {"used": STAGING_LIMIT, "limit": STAGING_LIMIT * 2},
            "attempt": null, "resource": null,
            "completion": {"position": 1, "stagedBytes": STAGING_LIMIT - 6}
        }))
        .unwrap();
        assert_eq!(
            progress
                .reserve_attempt(&plan.entry, true, STAGING_LIMIT)
                .unwrap(),
            6
        );
        assert_eq!(progress.read.used, STAGING_LIMIT * 2);
        assert_eq!(progress.attempt_bytes, Some(6));
        // A partial export cannot free its reservation on restart or trigger another unapproved read.
        let mut resumed: Progress =
            serde_json::from_value(serde_json::to_value(&progress).unwrap()).unwrap();
        let mut plan = plan;
        plan.additional.push(SourceFile {
            relative: "1/original.HEIC".into(),
            bytes: STAGING_LIMIT,
        });
        assert_eq!(resumed.reservation(&plan).unwrap(), 6);
        assert_eq!(
            resumed
                .reserve_attempt(&plan.entry, true, STAGING_LIMIT)
                .unwrap_err(),
            "source_read_budget_exhausted"
        );
        assert_eq!(resumed.attempt, progress.attempt);
        assert_eq!(resumed.attempt_bytes, Some(6));
        assert!(resumed
            .reservation(&Plan {
                export: false,
                ..plan
            })
            .is_err());
    }

    #[test]
    fn full_cache_and_exact_folder_size_refuse_before_spending() {
        let plan = export_plan();
        let mut progress: Progress = serde_json::from_value(serde_json::json!({
            "planHash": "signed-plan", "read": {"used": 0, "limit": STAGING_LIMIT},
            "attempt": null, "resource": null,
            "completion": {"position": 1, "stagedBytes": STAGING_LIMIT - 6}
        }))
        .unwrap();
        assert_eq!(
            progress
                .reserve_attempt(&plan.entry, false, STAGING_LIMIT)
                .unwrap_err(),
            "source_staging_budget_exceeded"
        );
        progress.completion.as_mut().unwrap().staged_bytes = STAGING_LIMIT;
        assert_eq!(
            progress
                .reserve_attempt(&plan.entry, true, STAGING_LIMIT)
                .unwrap_err(),
            "source_staging_budget_exceeded"
        );
        assert_eq!(progress.read.used, 0);
        assert!(progress.attempt.is_none());
    }

    #[test]
    fn export_attempt_capacity_survives_serialization_without_refunding_reads() {
        let record = serde_json::json!({
            "planHash": "signed-plan", "read": {"used": STAGING_LIMIT, "limit": STAGING_LIMIT},
            "attempt": uuid::Uuid::new_v4().to_string(), "resource": null,
            "completion": {"position": 1, "stagedBytes": 10},
            "attemptBytes": STAGING_LIMIT - 10
        });
        let progress: Progress = serde_json::from_value(record.clone()).unwrap();
        assert_eq!(serde_json::to_value(progress).unwrap(), record);
    }
}
