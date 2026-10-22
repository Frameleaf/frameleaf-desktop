//! Durable source-input reservations. Drop never frees capacity or deletes staged bytes.
// shortcut: source inputs only; include owned ML memory/scratch before claiming an app-wide limit.
use crate::{connection::DeviceIdentity, source_import::Journal};
use cap_std::{ambient_authority, fs::Dir};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

pub(crate) const LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Allocation {
    source: String,
    id: String,
    bytes: u64,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    allocations: Vec<Allocation>,
}
pub(crate) struct InputBudget<'a> {
    base: PathBuf,
    journal: Journal,
    identity: &'a DeviceIdentity,
    owner: fs::File,
    root_identity: String,
}
fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}
impl<'a> InputBudget<'a> {
    pub(crate) fn open(base: &Path, identity: &'a DeviceIdentity) -> Result<Self, String> {
        crate::native_runtime::absolute_directory(base)?;
        let root = base.join("private-inputs");
        let fresh = match fs::symlink_metadata(&root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Ok(_) => false,
            Err(_) => return Err("source_input_budget_invalid".into()),
        };
        crate::runtime_store::private_directory(&root)?;
        let dir = Dir::open_ambient_dir(&root, ambient_authority())
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
        let result = Self {
            base: base.into(),
            root_identity: crate::copy_source::source_root_identity(&dir)?,
            journal: Journal { root },
            identity,
            owner,
        };
        result.check()?;
        match fs::symlink_metadata(result.journal.root.join("budget.json")) {
            Err(error) if fresh && error.kind() == std::io::ErrorKind::NotFound => {
                result
                    .journal
                    .write("budget.json", &Ledger::default(), identity)?;
            }
            Err(_) => return Err("source_input_budget_invalid".into()),
            Ok(_) => {}
        }
        result.read()?;
        Ok(result)
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        crate::native_runtime::absolute_directory(&self.journal.root)?;
        let dir = Dir::open_ambient_dir(&self.journal.root, ambient_authority())
            .map_err(|_| "source_input_budget_invalid")?;
        if crate::copy_source::source_root_identity(&dir)? != self.root_identity {
            return Err("source_input_budget_invalid".into());
        }
        crate::host_state::valid_file(&self.owner)?;
        let named = dir
            .open_with(".owner.lock", &crate::host_state::options(false))
            .map_err(|_| "source_input_budget_invalid")?;
        let held = cap_std::fs::File::from_std(
            self.owner
                .try_clone()
                .map_err(|_| "source_input_budget_invalid")?,
        );
        if crate::copy_source::opened_stamp(&named)? != crate::copy_source::opened_stamp(&held)?
            || self
                .owner
                .metadata()
                .map_err(|_| "source_input_budget_invalid")?
                .len()
                != 0
        {
            return Err("source_input_budget_invalid".into());
        }
        Ok(())
    }
    fn read(&self) -> Result<Ledger, String> {
        self.check()?;
        let ledger: Ledger = self.journal.read("budget.json", self.identity)?;
        let mut ids = HashSet::new();
        if ledger.allocations.len() > MAX_RECORDS {
            return Err("source_input_budget_invalid".into());
        }
        let mut total = 0u64;
        for entry in &ledger.allocations {
            if !uuid(&entry.source)
                || !uuid(&entry.id)
                || !ids.insert(&entry.id)
                || entry.bytes == 0
            {
                return Err("source_input_budget_invalid".into());
            }
            total = total
                .checked_add(entry.bytes)
                .filter(|n| *n <= LIMIT)
                .ok_or("source_input_budget_invalid")?;
        }
        Ok(ledger)
    }
    pub(crate) fn remaining(&self) -> Result<u64, String> {
        let ledger = self.read()?;
        self.staged(&ledger)?;
        Ok(LIMIT
            - ledger
                .allocations
                .iter()
                .map(|entry| entry.bytes)
                .sum::<u64>())
    }
    pub(crate) fn reserve(&mut self, source: &str, id: &str, bytes: u64) -> Result<(), String> {
        if !uuid(source) || !uuid(id) || bytes == 0 || bytes > LIMIT {
            return Err("source_input_budget_invalid".into());
        }
        let mut ledger = self.read()?;
        self.staged(&ledger)?;
        if let Some(old) = ledger.allocations.iter().find(|entry| entry.id == id) {
            return if old.source == source && old.bytes == bytes {
                Ok(())
            } else {
                Err("source_input_budget_invalid".into())
            };
        }
        if ledger.allocations.len() == MAX_RECORDS
            || bytes
                > LIMIT
                    - ledger
                        .allocations
                        .iter()
                        .map(|entry| entry.bytes)
                        .sum::<u64>()
        {
            return Err("source_staging_budget_exceeded".into());
        }
        ledger.allocations.push(Allocation {
            source: source.into(),
            id: id.into(),
            bytes,
        });
        self.check()?;
        self.journal.write("budget.json", &ledger, self.identity)
    }
    pub(crate) fn shrink(&mut self, source: &str, id: &str, bytes: u64) -> Result<(), String> {
        let mut ledger = self.read()?;
        let entry = ledger
            .allocations
            .iter_mut()
            .find(|entry| entry.source == source && entry.id == id)
            .ok_or("source_input_budget_invalid")?;
        if bytes == 0 || bytes > entry.bytes {
            return Err("source_input_budget_invalid".into());
        }
        entry.bytes = bytes;
        self.staged(&ledger)?;
        self.check()?;
        self.journal.write("budget.json", &ledger, self.identity)
    }
    /// Caller must first join all producers/readers and confirm cleanup with authoritative job state.
    pub(crate) fn release(&mut self, source: &str, id: &str) -> Result<(), String> {
        if !uuid(source) || !uuid(id) {
            return Err("source_input_budget_invalid".into());
        }
        let mut ledger = self.read()?;
        if self.staged(&ledger)?.contains(id) {
            return Err("source_cache_cleanup_pending".into());
        }
        if let Some(index) = ledger.allocations.iter().position(|entry| entry.id == id) {
            if ledger.allocations[index].source != source {
                return Err("source_input_budget_invalid".into());
            }
            ledger.allocations.remove(index);
            self.check()?;
            self.journal.write("budget.json", &ledger, self.identity)?;
        }
        Ok(())
    }
    fn staged(&self, ledger: &Ledger) -> Result<HashSet<String>, String> {
        let mut seen = HashSet::new();
        let mut count = 0usize;
        for (prefix, reads) in [
            ("photo-imports", false),
            ("photo-preparations", false),
            ("photo-reads", true),
        ] {
            for source in directories(&self.base.join(prefix), &mut count, true)? {
                let id = source
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or("source_input_budget_invalid")?;
                if !uuid(id) {
                    return Err("source_input_budget_invalid".into());
                }
                if reads {
                    for job in directories(&source, &mut count, true)? {
                        if !job
                            .file_name()
                            .and_then(|s| s.to_str())
                            .is_some_and(|s| crate::native_runtime::digest_valid(s, 64))
                        {
                            return Err("source_input_budget_invalid".into());
                        }
                        inspect_stage(&job.join("stage"), id, ledger, &mut seen, &mut count)?;
                    }
                } else {
                    inspect_stage(&source.join("stage"), id, ledger, &mut seen, &mut count)?;
                }
            }
        }
        Ok(seen)
    }
}
fn directories(root: &Path, count: &mut usize, allow_files: bool) -> Result<Vec<PathBuf>, String> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("source_input_budget_invalid".into()),
        Ok(_) => {}
    }
    crate::native_runtime::absolute_directory(root)?;
    let mut result = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| "source_input_budget_invalid")? {
        *count += 1;
        if *count > 50_000 {
            return Err("source_inventory_partial".into());
        }
        let entry = entry.map_err(|_| "source_input_budget_invalid")?;
        let meta = fs::symlink_metadata(entry.path()).map_err(|_| "source_input_budget_invalid")?;
        if meta.file_type().is_symlink() {
            return Err("source_input_budget_invalid".into());
        }
        if meta.is_dir() {
            crate::native_runtime::absolute_directory(&entry.path())?;
            result.push(entry.path());
        } else if !meta.is_file() || !allow_files {
            return Err("source_input_budget_invalid".into());
        }
    }
    Ok(result)
}
fn inspect_stage(
    root: &Path,
    source: &str,
    ledger: &Ledger,
    seen: &mut HashSet<String>,
    count: &mut usize,
) -> Result<(), String> {
    for path in directories(root, count, false)? {
        let id = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("source_input_budget_invalid")?;
        let allocation = ledger
            .allocations
            .iter()
            .find(|entry| entry.source == source && entry.id == id)
            .ok_or("source_input_budget_untracked")?;
        if !seen.insert(id.into()) {
            return Err("source_input_budget_invalid".into());
        }
        let dir = Dir::open_ambient_dir(&path, ambient_authority())
            .map_err(|_| "source_input_budget_invalid")?;
        for (index, entry) in dir
            .entries()
            .map_err(|_| "source_input_budget_invalid")?
            .enumerate()
        {
            let name = entry
                .map_err(|_| "source_input_budget_invalid")?
                .file_name();
            if index >= 2 || !matches!(name.to_str(), Some("original" | "receipt.json")) {
                return Err("source_input_budget_untracked".into());
            }
            let file = crate::copy_source::staged_file(&dir, Path::new(&name))?;
            let limit = if name == "original" {
                allocation.bytes
            } else {
                524_288
            };
            if file
                .metadata()
                .map_err(|_| "source_input_budget_invalid")?
                .len()
                > limit
            {
                return Err("source_input_budget_invalid".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        base: std::path::PathBuf,
        identity: crate::connection::DeviceIdentity,
        source: String,
        id: String,
    }
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-private-inputs-{}", uuid::Uuid::new_v4()));
            crate::runtime_store::private_directory(&base).unwrap();
            Self {
                base,
                identity: crate::connection::DeviceIdentity::generate(),
                source: uuid::Uuid::new_v4().to_string(),
                id: uuid::Uuid::new_v4().to_string(),
            }
        }
        fn stage(&self, reads: bool) -> std::path::PathBuf {
            let mut path = self.base.clone();
            let mut parts = vec![
                if reads {
                    "photo-reads"
                } else {
                    "photo-preparations"
                },
                &self.source,
            ];
            let job = "a".repeat(64);
            if reads {
                parts.push(&job);
            }
            parts.extend(["stage", &self.id]);
            for part in parts {
                path.push(part);
                crate::runtime_store::private_directory(&path).unwrap();
            }
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn reservations_survive_restart_and_cannot_change_identity_or_size() {
        let f = Fixture::new();
        let mut budget = InputBudget::open(&f.base, &f.identity).unwrap();
        budget.reserve(&f.source, &f.id, LIMIT).unwrap();
        budget.reserve(&f.source, &f.id, LIMIT).unwrap();
        assert!(budget.reserve(&f.source, &f.id, 1).is_err());
        assert!(budget
            .reserve(&uuid::Uuid::new_v4().to_string(), &f.id, LIMIT)
            .is_err());
        drop(budget);
        let mut resumed = InputBudget::open(&f.base, &f.identity).unwrap();
        assert_eq!(resumed.remaining().unwrap(), 0);
        assert_eq!(
            resumed
                .reserve(&f.source, &uuid::Uuid::new_v4().to_string(), 1)
                .unwrap_err(),
            "source_staging_budget_exceeded"
        );
        resumed.release(&f.source, &f.id).unwrap();
        assert_eq!(resumed.remaining().unwrap(), LIMIT);
    }
    #[test]
    fn cache_move_keeps_reservation_and_only_absence_releases_it() {
        let f = Fixture::new();
        let mut budget = InputBudget::open(&f.base, &f.identity).unwrap();
        budget.reserve(&f.source, &f.id, 10).unwrap();
        let from = f.stage(false);
        std::fs::write(from.join("original"), b"bytes").unwrap();
        assert!(budget.release(&f.source, &f.id).is_err());
        let to = f.stage(true);
        std::fs::remove_dir(&to).unwrap();
        std::fs::rename(&from, &to).unwrap();
        assert_eq!(budget.remaining().unwrap(), LIMIT - 10);
        assert!(budget.release(&f.source, &f.id).is_err());
        std::fs::remove_file(to.join("original")).unwrap();
        std::fs::remove_dir(&to).unwrap();
        budget.release(&f.source, &f.id).unwrap();
        assert_eq!(budget.remaining().unwrap(), LIMIT);
    }
    #[test]
    fn untracked_and_oversized_cache_refuse_new_work_without_deletion() {
        let f = Fixture::new();
        let mut budget = InputBudget::open(&f.base, &f.identity).unwrap();
        let path = f.stage(false);
        std::fs::write(path.join("original"), b"keep").unwrap();
        assert!(budget.reserve(&f.source, &f.id, 3).is_err());
        assert_eq!(std::fs::read(path.join("original")).unwrap(), b"keep");
        std::fs::remove_file(path.join("original")).unwrap();
        std::fs::remove_dir(&path).unwrap();
        budget.reserve(&f.source, &f.id, 3).unwrap();
        let path = f.stage(false);
        std::fs::write(path.join("original"), b"keep").unwrap();
        assert!(budget.remaining().is_err());
        assert!(budget.release(&f.source, &f.id).is_err());
        assert_eq!(std::fs::read(path.join("original")).unwrap(), b"keep");
    }
    #[test]
    fn missing_or_foreign_checkpoint_cannot_reset_capacity() {
        let f = Fixture::new();
        let mut budget = InputBudget::open(&f.base, &f.identity).unwrap();
        budget.reserve(&f.source, &f.id, 10).unwrap();
        drop(budget);
        assert!(
            InputBudget::open(&f.base, &crate::connection::DeviceIdentity::generate()).is_err()
        );
        std::fs::remove_file(f.base.join("private-inputs/budget.json")).unwrap();
        assert!(InputBudget::open(&f.base, &f.identity).is_err());
    }
    #[test]
    fn one_global_owner_excludes_independent_admission() {
        let f = Fixture::new();
        let budget = InputBudget::open(&f.base, &f.identity).unwrap();
        assert!(InputBudget::open(&f.base, &f.identity).is_err());
        drop(budget);
        InputBudget::open(&f.base, &f.identity).unwrap();
    }
    #[test]
    fn verified_output_can_shrink_but_never_erase_or_expand_a_reservation() {
        let f = Fixture::new();
        let mut budget = InputBudget::open(&f.base, &f.identity).unwrap();
        budget.reserve(&f.source, &f.id, 10).unwrap();
        let path = f.stage(false);
        std::fs::write(path.join("original"), b"bytes").unwrap();
        assert!(budget.shrink(&f.source, &f.id, 4).is_err());
        budget.shrink(&f.source, &f.id, 5).unwrap();
        assert_eq!(budget.remaining().unwrap(), LIMIT - 5);
        assert!(budget.shrink(&f.source, &f.id, 0).is_err());
        assert!(budget.shrink(&f.source, &f.id, 6).is_err());
        drop(budget);
        assert_eq!(
            InputBudget::open(&f.base, &f.identity)
                .unwrap()
                .remaining()
                .unwrap(),
            LIMIT - 5
        );
    }
    #[cfg(unix)]
    #[test]
    fn replaced_global_lock_cannot_authorize_an_old_owner() {
        let f = Fixture::new();
        let budget = InputBudget::open(&f.base, &f.identity).unwrap();
        let root = f.base.join("private-inputs");
        std::fs::rename(root.join(".owner.lock"), root.join(".old-owner.lock")).unwrap();
        let dir = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
        let replacement = dir
            .open_with(".owner.lock", &crate::host_state::options(true))
            .unwrap()
            .into_std();
        replacement.try_lock().unwrap();
        assert!(budget.remaining().is_err());
    }
}
