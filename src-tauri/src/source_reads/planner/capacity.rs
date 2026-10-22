use super::*;

pub(super) fn reconcile(
    prep: &Preparation,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
) -> Result<Option<Job>, String> {
    gate()?;
    let mut progress = prep.progress(saved, identity)?;
    let resources = prep.resources_with(saved, identity)?;
    let Some(first) = resources.first() else {
        return Ok(None);
    };
    let base = prep
        .journal
        .root
        .parent()
        .and_then(Path::parent)
        .ok_or("source_journal_invalid")?;
    // Every resource job uses this source-wide OS lease; keep it through admission and staging.
    let owner = Job::open_owned(
        base,
        saved,
        identity,
        &prep.plan.source,
        &first.resource_key,
        &first.version,
        OpenMode::Inspect,
    )?;
    let mut retained = 0u64;
    for resource in &resources {
        gate()?;
        owner.require_owner()?;
        if cache_retained(&owner.source_root, &prep.plan, resource, saved, identity)? {
            retained = retained
                .checked_add(resource.bytes)
                .ok_or("source_journal_invalid")?;
        }
    }
    let released = progress
        .staged_bytes()
        .checked_sub(retained)
        .ok_or("source_journal_invalid")?;
    let released = (released != 0).then_some(released);
    if progress.released_bytes != released {
        progress.released_bytes = released;
        gate()?;
        owner.require_owner()?;
        prep.journal
            .write("preparation-state.json", &progress, identity)?;
    }
    gate()?;
    owner.require_owner()?;
    Ok(Some(owner))
}
fn cache_retained(
    source_root: &Path,
    plan: &Plan,
    resource: &PreparedResource,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
) -> Result<bool, String> {
    let root = source_root.join(job_key(&resource.resource_key, &resource.version));
    let state: State = Journal { root: root.clone() }.read("state.json", identity)?;
    state.validate()?;
    state.resource.validate_receipt(saved, identity)?;
    if state.resource.source_id() != plan.source
        || state.resource.scope_fingerprint() != plan.scope
        || state.resource.id != resource.id
        || state.resource.resource_key() != resource.resource_key
        || state.resource.version() != resource.version
        || state.resource.sha256 != resource.sha256
        || state.resource.bytes != resource.bytes
    {
        return Err("source_journal_invalid".into());
    }
    let stage = root.join("stage");
    crate::native_runtime::absolute_directory(&stage)?;
    let dir = Dir::open_ambient_dir(&stage, ambient_authority())
        .map_err(|_| "source_stage_unavailable")?;
    let mut entries = dir.entries().map_err(|_| "source_stage_unavailable")?;
    let first = entries
        .next()
        .transpose()
        .map_err(|_| "source_stage_unavailable")?;
    if entries.next().is_some() {
        return Err("source_cache_cleanup_pending".into());
    }
    let Some(id) = state.stage else {
        return if first.is_none() {
            Ok(false)
        } else {
            Err("source_cache_cleanup_pending".into())
        };
    };
    // Absence alone is insufficient: a retained stage pointer has no positive cleanup receipt.
    let Some(first) = first else {
        return Ok(true);
    };
    if first.file_name().to_str() != Some(&id) {
        return Err("source_cache_cleanup_pending".into());
    }
    crate::native_runtime::absolute_directory(&stage.join(&id))?;
    let body = dir.open_dir(&id).map_err(|_| "source_stage_unavailable")?;
    for (index, entry) in body
        .entries()
        .map_err(|_| "source_stage_unavailable")?
        .enumerate()
    {
        let name = entry.map_err(|_| "source_stage_unavailable")?.file_name();
        if index >= 2 || !matches!(name.to_str(), Some("original" | "receipt.json")) {
            return Err("source_cache_cleanup_pending".into());
        }
        let file = crate::copy_source::staged_file(&body, Path::new(&name))?;
        let maximum = if name == "original" {
            resource.bytes
        } else {
            524_288
        };
        if file
            .metadata()
            .map_err(|_| "source_stage_unavailable")?
            .len()
            > maximum
        {
            return Err("source_cache_cleanup_pending".into());
        }
    }
    Ok(true)
}
