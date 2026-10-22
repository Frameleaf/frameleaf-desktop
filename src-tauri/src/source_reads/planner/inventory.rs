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
                .read(&format!("prepared-{index}.json"), identity)?;
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
        let name = format!("prepared-{index}.json");
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
        self.journal
            .write("preparation-state.json", &state, identity)
    }
}
