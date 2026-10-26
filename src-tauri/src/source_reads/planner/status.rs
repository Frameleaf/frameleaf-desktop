use super::*;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceStatus {
    pub source_id: String,
    pub scans: Vec<ScanStatus>,
    pub publications: Vec<super::super::publication::PublicationStatus>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStatus {
    pub scan_id: String,
    pub current: bool,
    pub abandoned: bool,
    pub spent: u64,
    pub resources: usize,
    pub completed: usize,
    pub reserved_bytes: u64,
    pub discardable: bool,
    pub remaining: u64,
    pub next_read_bytes: Option<u64>,
    pub additional_read_allowance: u64,
    pub can_rescan: bool,
    pub prepared: bool,
}
impl Preparation {
    pub fn reference_status(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        source: &str,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<Option<ReferenceStatus>, String> {
        gate()?;
        let approval = Self::control_approval(saved, identity, source)?;
        let root = base.join("photo-preparations").join(source);
        if matches!(fs::symlink_metadata(&root), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(None);
        }
        let prep = Self::open_recorded(base, saved, identity, approval, false)?;
        prep.reference_status_with(saved, identity, &|| {
            prep.current_control(saved, identity)?;
            gate()
        })
        .map(Some)
    }
    pub(in crate::source_reads) fn reference_status_with(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        gate: &dyn Fn() -> Result<(), String>,
    ) -> Result<ReferenceStatus, String> {
        gate()?;
        self.progress(saved, identity)?;
        let base = self
            .journal
            .root
            .parent()
            .and_then(Path::parent)
            .ok_or("source_journal_invalid")?;
        let reservations = crate::private_inputs::InputBudget::open(base, identity)?
            .reservations(&self.plan.source)?;
        let mut scans =
            vec![self.scan_status(saved, identity, &self.plan, &self.plan_hash, &reservations)?];
        for (index, entry) in fs::read_dir(&self.journal.root)
            .map_err(|_| "source_journal_invalid")?
            .enumerate()
        {
            if index >= 50_000 {
                return Err("source_inventory_partial".into());
            }
            gate()?;
            let name = entry.map_err(|_| "source_journal_invalid")?.file_name();
            let Some(hash) = name
                .to_str()
                .and_then(|name| name.strip_prefix("preparation-plan-"))
                .and_then(|name| name.strip_suffix(".json"))
            else {
                continue;
            };
            if !crate::native_runtime::digest_valid(hash, 64) {
                return Err("source_journal_invalid".into());
            }
            if hash == self.plan_hash {
                continue;
            }
            let plan: Plan = self
                .journal
                .read(name.to_str().ok_or("source_journal_invalid")?, identity)?;
            let scan = self.scan_status(saved, identity, &plan, hash, &reservations)?;
            if scan.abandoned {
                scans.push(scan);
            }
        }
        scans[1..].sort_by(|a, b| a.scan_id.cmp(&b.scan_id));
        gate()?;
        self.require_owner()?;
        Ok(ReferenceStatus {
            source_id: self.plan.source.clone(),
            scans,
            publications: Vec::new(),
        })
    }
    fn scan_status(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        plan: &Plan,
        expected: &str,
        reservations: &std::collections::HashMap<String, u64>,
    ) -> Result<ScanStatus, String> {
        let state = self.recorded_progress(saved, identity, plan, expected)?;
        let reserved_bytes = state
            .attempt
            .as_ref()
            .and_then(|id| reservations.get(id))
            .copied()
            .unwrap_or(0);
        Ok(ScanStatus {
            scan_id: expected.into(),
            current: expected == self.plan_hash,
            abandoned: state.abandoned,
            spent: state.read.used,
            resources: plan.count(),
            completed: state.position(),
            reserved_bytes,
            remaining: if state.abandoned {
                0
            } else {
                state.read.limit - state.read.used
            },
            next_read_bytes: state.next_read_bytes(plan)?,
            additional_read_allowance: state.additional_read_allowance(plan)?,
            can_rescan: expected == self.plan_hash
                && (state.abandoned || state.position() == plan.count()),
            prepared: !state.abandoned && state.position() == plan.count(),
            discardable: state.abandoned
                && reserved_bytes > 0
                && state.handoff_started != Some(true)
                && (state.resource.is_none() || state.handoff_started == Some(false)),
        })
    }
}
