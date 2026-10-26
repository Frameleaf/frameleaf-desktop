use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Generation {
    pub id: String,
    pub previous: String,
}
pub(super) struct Next {
    pub plan: Plan,
    pub hash: String,
    pub total: u64,
}
impl Plan {
    fn suffix(&self) -> String {
        self.generation
            .as_ref()
            .map_or_else(String::new, |g| format!("-{}", g.id))
    }
    pub(super) fn state_name(&self) -> String {
        format!("preparation-state{}.json", self.suffix())
    }
    pub(super) fn stage_name(&self) -> String {
        format!("stage{}", self.suffix())
    }
    pub(super) fn inventory_name(&self, index: usize) -> String {
        format!("prepared{}-{index}.json", self.suffix())
    }
    fn entries(&self) -> Vec<SourceFile> {
        std::iter::once(&self.entry)
            .chain(&self.additional)
            .cloned()
            .collect()
    }
}
impl Preparation {
    pub(super) fn select(
        approval: &CopyApproval,
        relatives: &[String],
    ) -> Result<Vec<SourceFile>, String> {
        if relatives.is_empty() || relatives.len() > 10_000 {
            return Err("source_selection_invalid".into());
        }
        let scan = approval.files()?;
        if scan.inventory.truncated || scan.unreadable != 0 {
            return Err("source_inventory_partial".into());
        }
        let files: std::collections::HashMap<_, _> = scan
            .files
            .into_iter()
            .map(|e| (e.relative.clone(), e))
            .collect();
        relatives
            .iter()
            .map(|r| {
                files
                    .get(r)
                    .cloned()
                    .ok_or("source_item_unavailable".into())
            })
            .collect()
    }
}
fn same_selection(left: &[SourceFile], right: &[SourceFile]) -> bool {
    let sorted = |entries: &[SourceFile]| {
        let mut entries: Vec<_> = entries
            .iter()
            .map(|e| (e.relative.clone(), e.bytes))
            .collect();
        entries.sort();
        entries
    };
    sorted(left) == sorted(right)
}
// Keep the shared source job owner while observing its signed descriptors; no cache bytes are opened.
fn known(
    prep: &Preparation,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    entries: &[SourceFile],
    gate: &dyn Fn() -> Result<(), String>,
) -> Result<(std::collections::HashMap<String, StagedCopy>, Option<Job>), String> {
    let base = prep
        .journal
        .root
        .parent()
        .and_then(Path::parent)
        .ok_or("source_journal_invalid")?;
    let root = base.join("photo-reads").join(&prep.plan.source);
    crate::native_runtime::absolute_directory(&root)?;
    let mut owner: Option<Job> = None;
    let mut copies = std::collections::HashMap::new();
    for (index, entry) in fs::read_dir(&root)
        .map_err(|_| "source_journal_invalid")?
        .enumerate()
    {
        if index >= 10_002 {
            return Err("source_inventory_partial".into());
        }
        gate()?;
        let entry = entry.map_err(|_| "source_journal_invalid")?;
        let name = entry.file_name();
        if !name
            .to_str()
            .is_some_and(|s| crate::native_runtime::digest_valid(s, 64))
        {
            continue;
        }
        if !entry
            .file_type()
            .map_err(|_| "source_journal_invalid")?
            .is_dir()
        {
            return Err("source_journal_invalid".into());
        }
        let journal = Journal { root: entry.path() };
        let state: State = journal.read("state.json", identity)?;
        state.validate()?;
        let copy = state.resource;
        copy.validate_receipt(saved, identity)?;
        if copy.source_id() != prep.plan.source
            || name.to_str() != Some(&job_key(&copy.resource_key(), &copy.version()))
        {
            return Err("source_journal_invalid".into());
        }
        if owner.is_none() {
            owner = Some(Job::open_owned(
                base,
                saved,
                identity,
                &prep.plan.source,
                &copy.resource_key(),
                &copy.version(),
                OpenMode::Inspect,
            )?);
        }
        owner
            .as_ref()
            .ok_or("source_journal_invalid")?
            .require_owner()?;
        if copy.scope_fingerprint() == prep.plan.scope
            && entries
                .iter()
                .any(|e| copy.matches_entry(&e.relative, e.bytes))
            && copy.validate_current(saved, identity).is_ok()
        {
            let relative = entries
                .iter()
                .find(|e| copy.matches_entry(&e.relative, e.bytes))
                .ok_or("source_journal_invalid")?
                .relative
                .clone();
            if copies.insert(relative, copy).is_some() {
                return Err("source_reference_identity_ambiguous".into());
            }
        }
    }
    Ok((copies, owner))
}
pub(super) fn transition(
    prep: &Preparation,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    entries: Vec<SourceFile>,
    expected: &str,
    gate: &dyn Fn() -> Result<(), String>,
) -> Result<Next, String> {
    gate()?;
    let state = prep.progress(saved, identity)?;
    let unchanged = || {
        Ok(Next {
            plan: prep.plan.clone(),
            hash: prep.plan_hash.clone(),
            total: prep.total_bytes,
        })
    };
    if expected != prep.plan_hash {
        return if prep
            .plan
            .generation
            .as_ref()
            .is_some_and(|g| g.previous == expected)
            && same_selection(&prep.plan.entries(), &entries)
        {
            unchanged()
        } else {
            Err("source_scan_changed".into())
        };
    }
    if state.position() != prep.plan.count() {
        return Err("source_preparation_incomplete".into());
    }
    prep.resources_with(saved, identity)?;
    let mut plan = Plan {
        source: prep.plan.source.clone(),
        scope: prep.plan.scope.clone(),
        export: prep.plan.export,
        entry: entries.first().cloned().ok_or("source_selection_invalid")?,
        additional: entries.iter().skip(1).cloned().collect(),
        generation: Some(Generation {
            id: uuid::Uuid::new_v4().to_string(),
            previous: expected.into(),
        }),
    };
    let total = plan.total()?;
    let (mut copies, _owner) = known(prep, saved, identity, &entries, gate)?;
    let mut reusable = Vec::new();
    let mut changed = Vec::new();
    for entry in entries {
        if let Some(copy) = copies.remove(&entry.relative) {
            reusable.push((entry, copy));
        } else {
            changed.push(entry);
        }
    }
    let ordered: Vec<_> = reusable
        .iter()
        .map(|(e, _)| e.clone())
        .chain(changed)
        .collect();
    plan.entry = ordered[0].clone();
    plan.additional = ordered.into_iter().skip(1).collect();
    let plan_hash = hash(&plan)?;
    let mut bytes = 0u64;
    for (_, copy) in &reusable {
        bytes = bytes
            .checked_add(copy.bytes)
            .ok_or("source_journal_invalid")?;
        copy.validate_current(saved, identity)?;
    }
    let next = Next {
        plan,
        hash: plan_hash,
        total,
    };
    let archive = format!("preparation-plan-{}.json", prep.plan_hash);
    gate()?;
    if super::super::preparation::present(&prep.journal.root.join(&archive))? {
        if hash(&prep.journal.read::<Plan>(&archive, identity)?)? != prep.plan_hash {
            return Err("source_journal_invalid".into());
        }
    } else {
        prep.journal.write(&archive, &prep.plan, identity)?;
    }
    gate()?;
    crate::runtime_store::private_directory(&prep.journal.root.join(next.plan.stage_name()))?;
    for (index, (_, copy)) in reusable.iter().enumerate() {
        gate()?;
        prep.journal.write(
            &next.plan.inventory_name(index),
            &InventoryRecord {
                plan_hash: next.hash.clone(),
                index,
                resource: PreparedResource {
                    id: copy.id.clone(),
                    resource_key: copy.resource_key(),
                    version: copy.version(),
                    sha256: copy.sha256.clone(),
                    bytes: copy.bytes,
                },
            },
            identity,
        )?;
    }
    gate()?;
    prep.journal.write(
        &next.plan.state_name(),
        &Progress {
            plan_hash: next.hash.clone(),
            read: Budget { used: 0, limit: 0 },
            attempt: None,
            resource: None,
            completion: (!reusable.is_empty()).then_some(Completion {
                position: reusable.len(),
                staged_bytes: bytes,
            }),
            released_bytes: None,
            attempt_bytes: None,
        },
        identity,
    )?;
    // Until this atomic activation, an interruption leaves only unapproved metadata beside the old scan.
    gate()?;
    prep.journal
        .write("preparation-plan.json", &next.plan, identity)?;
    Ok(next)
}
