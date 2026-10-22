use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    id: String,
    bytes: u64,
    stopped: bool,
    scratch_identity: String,
}
pub(crate) struct WorkerInputs {
    base: PathBuf,
    identity: DeviceIdentity,
    journal: Journal,
    owner: fs::File,
    root_identity: String,
    state: State,
}
fn envelope(bindings: usize) -> Result<u64, String> {
    if !(1..=64).contains(&bindings) {
        return Err("worker_model_binding_invalid".into());
    }
    // Memory and scratch copies of bounded specs/reports, plus request and qualification buffers.
    // Model tensors and decoded working memory still require resource-policy admission.
    Ok((bindings as u64 * 16 + 128) * 1024 * 1024)
}
fn root(base: &Path) -> PathBuf {
    base.join("worker/private-input-owner")
}
fn scratch_identity(base: &Path) -> Result<String, String> {
    let path = base.join("worker/scratch");
    crate::native_runtime::absolute_directory(&path)?;
    let dir = Dir::open_ambient_dir(&path, ambient_authority())
        .map_err(|_| "source_input_budget_invalid")?;
    crate::copy_source::source_root_identity(&dir)
}
fn read(base: &Path, identity: &DeviceIdentity) -> Result<State, String> {
    let state: State = Journal { root: root(base) }.read("state.json", identity)?;
    if !uuid(&state.id)
        || state.bytes == 0
        || state.bytes > LIMIT
        || state.scratch_identity != scratch_identity(base)?
    {
        return Err("source_input_budget_invalid".into());
    }
    Ok(state)
}
fn empty(base: &Path) -> Result<bool, String> {
    crate::native_runtime::absolute_directory(&base.join("worker/scratch"))?;
    Ok(fs::read_dir(base.join("worker/scratch"))
        .map_err(|_| "source_input_budget_invalid")?
        .next()
        .is_none())
}
pub(super) fn completed(base: &Path, identity: &DeviceIdentity, id: &str) -> Result<(), String> {
    let state = read(base, identity)?;
    if state.id != id || !state.stopped {
        return Err("worker_shutdown_unconfirmed".into());
    }
    if !empty(base)? {
        return Err("source_cache_cleanup_pending".into());
    }
    Ok(())
}
impl WorkerInputs {
    pub(crate) fn acquire(
        base: &Path,
        identity: DeviceIdentity,
        bindings: usize,
    ) -> Result<Self, String> {
        let bytes = envelope(bindings)?;
        crate::native_runtime::absolute_directory(base)?;
        crate::runtime_store::private_directory(&base.join("worker"))?;
        crate::runtime_store::private_directory(&base.join("worker/scratch"))?;
        let path = root(base);
        let fresh = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Ok(_) => false,
            Err(_) => return Err("source_input_budget_invalid".into()),
        };
        crate::runtime_store::private_directory(&path)?;
        let dir = Dir::open_ambient_dir(&path, ambient_authority())
            .map_err(|_| "source_input_budget_invalid")?;
        let owner = dir
            .open_with(".owner.lock", &crate::host_state::options(true))
            .map_err(|_| "source_input_budget_invalid")?
            .into_std();
        crate::host_state::valid_file(&owner)?;
        if owner
            .metadata()
            .map_err(|_| "source_input_budget_invalid")?
            .len()
            != 0
        {
            return Err("source_input_budget_invalid".into());
        }
        owner.try_lock().map_err(|_| "source_input_budget_busy")?;
        let journal = Journal { root: path };
        if fresh {
            if !empty(base)? {
                return Err("source_input_budget_untracked".into());
            }
            journal.write(
                "state.json",
                &State {
                    id: uuid::Uuid::new_v4().to_string(),
                    bytes,
                    stopped: true,
                    scratch_identity: scratch_identity(base)?,
                },
                &identity,
            )?;
        }
        let mut state = read(base, &identity)?;
        if !state.stopped {
            return Err("worker_shutdown_unconfirmed".into());
        }
        if !empty(base)? {
            return Err("source_cache_cleanup_pending".into());
        }
        let mut budget = InputBudget::open(base, &identity)?;
        budget.release_kind(&identity.installation_id, &state.id, true)?;
        state.id = uuid::Uuid::new_v4().to_string();
        state.bytes = bytes;
        journal.write("state.json", &state, &identity)?;
        budget.reserve_kind(&identity.installation_id, &state.id, bytes, true)?;
        state.stopped = false;
        if let Err(error) = journal.write("state.json", &state, &identity) {
            state.stopped = true;
            journal
                .write("state.json", &state, &identity)
                .map_err(|_| "worker_shutdown_unconfirmed")?;
            return Err(error);
        }
        drop(budget);
        let result = Self {
            base: base.into(),
            identity,
            journal,
            owner,
            root_identity: crate::copy_source::source_root_identity(&dir)?,
            state,
        };
        result.check()?;
        Ok(result)
    }
    fn owner(&self) -> Result<(), String> {
        crate::native_runtime::absolute_directory(&self.journal.root)?;
        let dir = Dir::open_ambient_dir(&self.journal.root, ambient_authority())
            .map_err(|_| "source_input_budget_invalid")?;
        if crate::copy_source::source_root_identity(&dir)? != self.root_identity {
            return Err("source_input_budget_invalid".into());
        }
        crate::host_state::valid_file(&self.owner)?;
        if self
            .owner
            .metadata()
            .map_err(|_| "source_input_budget_invalid")?
            .len()
            != 0
        {
            return Err("source_input_budget_invalid".into());
        }
        let named = dir
            .open_with(".owner.lock", &crate::host_state::options(false))
            .map_err(|_| "source_input_budget_invalid")?;
        let held = cap_std::fs::File::from_std(
            self.owner
                .try_clone()
                .map_err(|_| "source_input_budget_invalid")?,
        );
        if crate::copy_source::opened_stamp(&named)? != crate::copy_source::opened_stamp(&held)? {
            return Err("source_input_budget_invalid".into());
        }
        Ok(())
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        self.owner()?;
        let state = read(&self.base, &self.identity)?;
        if state.id != self.state.id || state.bytes != self.state.bytes || state.stopped {
            return Err("worker_shutdown_unconfirmed".into());
        }
        Ok(())
    }
    /// Only after the owned association has joined every helper and returned a confirmed outcome.
    pub(crate) fn finish(&self) -> Result<(), String> {
        self.owner()?;
        let mut state = read(&self.base, &self.identity)?;
        if state.id != self.state.id || state.bytes != self.state.bytes {
            return Err("source_input_budget_invalid".into());
        }
        state.stopped = true;
        self.journal.write("state.json", &state, &self.identity)?;
        InputBudget::open(&self.base, &self.identity)?.release_kind(
            &self.identity.installation_id,
            &state.id,
            true,
        )
    }
}
pub(super) fn audit(base: &Path, identity: &DeviceIdentity, ledger: &Ledger) -> Result<(), String> {
    let workers: Vec<_> = ledger
        .allocations
        .iter()
        .filter(|entry| entry.worker)
        .collect();
    if workers.len() > 1 {
        return Err("source_input_budget_invalid".into());
    }
    let path = root(base).join("state.json");
    let state = match fs::symlink_metadata(&path) {
        Ok(_) => Some(read(base, identity)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("source_input_budget_invalid".into()),
    };
    if let Some(worker) = workers.first() {
        if state
            .as_ref()
            .is_none_or(|s| s.id != worker.id || s.bytes != worker.bytes)
        {
            return Err("source_input_budget_invalid".into());
        }
    } else if state.as_ref().is_some_and(|s| !s.stopped) {
        return Err("source_input_budget_untracked".into());
    }
    let bytes = scratch_bytes(base)?;
    if bytes > 0 && workers.is_empty() {
        return Err("source_input_budget_untracked".into());
    }
    if workers.first().is_some_and(|entry| bytes > entry.bytes) {
        return Err("source_input_budget_invalid".into());
    }
    Ok(())
}
fn scratch_bytes(base: &Path) -> Result<u64, String> {
    let root = base.join("worker/scratch");
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err("source_input_budget_invalid".into()),
        Ok(_) => {}
    }
    let mut pending = vec![root];
    let mut count = 0usize;
    let mut bytes = 0u64;
    while let Some(path) = pending.pop() {
        crate::native_runtime::absolute_directory(&path)?;
        let dir = Dir::open_ambient_dir(&path, ambient_authority())
            .map_err(|_| "source_input_budget_invalid")?;
        for entry in dir.entries().map_err(|_| "source_input_budget_invalid")? {
            count += 1;
            if count > 50_000 {
                return Err("source_inventory_partial".into());
            }
            let entry = entry.map_err(|_| "source_input_budget_invalid")?;
            if entry
                .file_type()
                .map_err(|_| "source_input_budget_invalid")?
                .is_dir()
            {
                pending.push(path.join(entry.file_name()));
            } else {
                let file = crate::copy_source::staged_file(&dir, Path::new(&entry.file_name()))?;
                bytes = bytes
                    .checked_add(
                        file.metadata()
                            .map_err(|_| "source_input_budget_invalid")?
                            .len(),
                    )
                    .ok_or("source_input_budget_invalid")?;
            }
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        base: PathBuf,
        identity: DeviceIdentity,
    }
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-worker-inputs-{}", uuid::Uuid::new_v4()));
            crate::runtime_store::private_directory(&base).unwrap();
            Self {
                base,
                identity: DeviceIdentity::generate(),
            }
        }
        fn acquire(&self) -> Result<WorkerInputs, String> {
            WorkerInputs::acquire(
                &self.base,
                serde_json::from_value(serde_json::to_value(&self.identity).unwrap()).unwrap(),
                1,
            )
        }
        fn remaining(&self) -> u64 {
            InputBudget::open(&self.base, &self.identity)
                .unwrap()
                .remaining()
                .unwrap()
        }
        fn scratch(&self) -> PathBuf {
            let path = self
                .base
                .join("worker/scratch")
                .join(format!("inference-{}", uuid::Uuid::new_v4()));
            crate::runtime_store::private_directory(&path).unwrap();
            fs::write(path.join("input"), b"synthetic").unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
    #[test]
    fn worker_drop_keeps_quota_and_unknown_owner_cannot_restart() {
        let f = Fixture::new();
        let input = f.acquire().unwrap();
        assert!(f.acquire().is_err());
        assert_eq!(f.remaining(), LIMIT - envelope(1).unwrap());
        let mut budget = InputBudget::open(&f.base, &f.identity).unwrap();
        assert!(budget
            .release(&f.identity.installation_id, &input.state.id)
            .is_err());
        assert!(budget
            .shrink(&f.identity.installation_id, &input.state.id, 1)
            .is_err());
        drop(budget);
        drop(input);
        assert_eq!(
            f.acquire().err().as_deref(),
            Some("worker_shutdown_unconfirmed")
        );
        assert_eq!(f.remaining(), LIMIT - envelope(1).unwrap());
    }
    #[test]
    fn confirmed_stop_keeps_quota_until_scratch_is_gone() {
        let f = Fixture::new();
        let input = f.acquire().unwrap();
        let scratch = f.scratch();
        assert_eq!(
            input.finish().err().as_deref(),
            Some("source_cache_cleanup_pending")
        );
        assert!(input.check().is_err());
        assert_eq!(f.remaining(), LIMIT - envelope(1).unwrap());
        assert_eq!(fs::read(scratch.join("input")).unwrap(), b"synthetic");
        fs::remove_file(scratch.join("input")).unwrap();
        fs::remove_dir(scratch).unwrap();
        input.finish().unwrap();
        input.finish().unwrap();
        assert_eq!(f.remaining(), LIMIT);
    }
    #[test]
    fn signed_stop_receipt_recovers_a_busy_quota_release() {
        let f = Fixture::new();
        let input = f.acquire().unwrap();
        let budget = InputBudget::open(&f.base, &f.identity).unwrap();
        assert_eq!(
            input.finish().err().as_deref(),
            Some("source_input_budget_busy")
        );
        drop(input);
        drop(budget);
        let next = f.acquire().unwrap();
        assert_eq!(f.remaining(), LIMIT - envelope(1).unwrap());
        next.finish().unwrap();
        assert_eq!(f.remaining(), LIMIT);
    }
    #[test]
    fn failed_admission_does_not_fence_a_worker_that_never_started() {
        let f = Fixture::new();
        let source = uuid::Uuid::new_v4().to_string();
        let id = uuid::Uuid::new_v4().to_string();
        let mut budget = InputBudget::open(&f.base, &f.identity).unwrap();
        budget.reserve(&source, &id, LIMIT).unwrap();
        drop(budget);
        assert_eq!(
            f.acquire().err().as_deref(),
            Some("source_staging_budget_exceeded")
        );
        let mut budget = InputBudget::open(&f.base, &f.identity).unwrap();
        budget.release(&source, &id).unwrap();
        drop(budget);
        let input = f.acquire().unwrap();
        input.finish().unwrap();
    }
    #[test]
    fn untracked_scratch_blocks_both_worker_and_source_admission() {
        let f = Fixture::new();
        crate::runtime_store::private_directory(&f.base.join("worker")).unwrap();
        crate::runtime_store::private_directory(&f.base.join("worker/scratch")).unwrap();
        let scratch = f.scratch();
        assert_eq!(
            f.acquire().err().as_deref(),
            Some("source_input_budget_untracked")
        );
        let budget = InputBudget::open(&f.base, &f.identity).unwrap();
        assert_eq!(
            budget.remaining().err().as_deref(),
            Some("source_input_budget_untracked")
        );
        assert_eq!(fs::read(scratch.join("input")).unwrap(), b"synthetic");
    }
    #[test]
    fn envelope_is_bounded_to_the_live_binding_limit() {
        assert!(envelope(0).is_err());
        assert!(envelope(65).is_err());
        assert!(envelope(64).unwrap() < LIMIT);
        assert!(envelope(64).unwrap() > envelope(1).unwrap());
    }
    #[cfg(unix)]
    #[test]
    fn replaced_worker_lease_or_scratch_cannot_confirm_cleanup() {
        for scratch in [false, true] {
            let f = Fixture::new();
            let input = f.acquire().unwrap();
            if scratch {
                fs::rename(
                    f.base.join("worker/scratch"),
                    f.base.join("worker/retained-scratch"),
                )
                .unwrap();
                crate::runtime_store::private_directory(&f.base.join("worker/scratch")).unwrap();
            } else {
                let path = root(&f.base);
                fs::rename(path.join(".owner.lock"), path.join(".old-owner.lock")).unwrap();
                Dir::open_ambient_dir(path, ambient_authority())
                    .unwrap()
                    .open_with(".owner.lock", &crate::host_state::options(true))
                    .unwrap();
            }
            assert!(input.check().is_err());
            assert!(input.finish().is_err());
        }
    }
}
