//! Fixed-inode selection only. The authenticated update fence remains until later publication.
use super::*;
const RECORD: &str = "host-update-selection.json";
const FAILED: &str = "host_update_selection_invalid";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdateSelection {
    pub(crate) previous: Marker,
    pub(crate) next: Marker,
    previous_database_identity: String,
    media_identity: Option<String>,
}
impl UpdateSelection {
    pub(crate) fn reference(&self) -> Result<&crate::host_database::Reference, String> {
        self.next
            .database_reference
            .as_ref()
            .ok_or_else(|| FAILED.into())
    }
}
impl Owner {
    pub(crate) fn update_selection_record(&self) -> Result<Option<(Vec<u8>, String)>, String> {
        self.update_file_record(RECORD)
    }
    pub(crate) fn reserve_update_selection_record(&self, bytes: &[u8]) -> Result<(), String> {
        self.reserve_update_file_record(RECORD, bytes)
    }
    pub(crate) fn prepare_update_selection(
        &mut self,
        id: &str,
        source: &str,
        target: &str,
        reference: &crate::host_database::Reference,
    ) -> Result<UpdateSelection, String> {
        if !crate::native_runtime::digest_valid(target, 64) || source == target {
            return Err(FAILED.into());
        }
        let (previous, previous_database_identity) = self.review_reserved_update(id, source)?;
        let mut next = previous.clone();
        next.manifest_sha256 = target.into();
        next.generation = Uuid::new_v4();
        next.database_reference = Some(reference.clone());
        let selection = UpdateSelection {
            previous,
            next,
            previous_database_identity,
            media_identity: activation::media_identity(&self.root)?,
        };
        self.validate_update_selection(&selection)?;
        Ok(selection)
    }
    fn validate_update_selection(&self, selection: &UpdateSelection) -> Result<(), String> {
        if !self.writable || self.active.is_some() {
            return Err(FAILED.into());
        }
        no_activation(&self.root)?;
        let previous = &selection.previous;
        let next = &selection.next;
        let current = self.update_record()?.ok_or(FAILED)?.0;
        let consumed: serde_json::Value = serde_json::from_slice(&current).map_err(|_| FAILED)?;
        if consumed["state"] != "approvalConsumed"
            || consumed["approvalReceipt"]["receipt"]["databaseIdentity"]
                != selection.previous_database_identity
        {
            return Err(FAILED.into());
        }
        self.binding(
            previous,
            &previous.installation_id,
            &previous.manifest_sha256,
        )?;
        self.binding(next, &previous.installation_id, &next.manifest_sha256)?;
        if previous.phase != Phase::Stopped
            || previous.restore_pending
            || next.generation == previous.generation
            || !crate::native_runtime::digest_valid(&previous.manifest_sha256, 64)
            || !crate::native_runtime::digest_valid(&next.manifest_sha256, 64)
            || previous.manifest_sha256 == next.manifest_sha256
        {
            return Err(FAILED.into());
        }
        let reference = next.database_reference.as_ref().ok_or(FAILED)?;
        if previous.database_reference.as_ref() == Some(reference) {
            return Err(FAILED.into());
        }
        let mut expected = previous.clone();
        expected.manifest_sha256 = next.manifest_sha256.clone();
        expected.generation = next.generation;
        expected.database_reference = Some(reference.clone());
        if &expected != next {
            return Err(FAILED.into());
        }
        let original = match &previous.database_reference {
            Some(reference) => reference.resolve(&self.path)?,
            None => self.path.join("database"),
        };
        let selected = reference.resolve(&self.path)?;
        let root = Dir::from_std_file(crate::host_storage::directory(&original)?);
        if identity(&root)? != selection.previous_database_identity
            || activation::media_identity(&self.root)? != selection.media_identity
        {
            return Err(FAILED.into());
        }
        for database in [&original, &selected] {
            match std::fs::symlink_metadata(database.join("postmaster.pid")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(FAILED.into()),
            }
        }
        self.placement()
    }
    fn require_update_selection_records(
        &self,
        sealed: &[u8],
        consumption: &str,
    ) -> Result<(), String> {
        if !crate::native_runtime::digest_valid(consumption, 64)
            || self
                .update_selection_evidence()?
                .map(|value| value.0)
                .as_deref()
                != Some(sealed)
            || self
                .update_record()?
                .is_none_or(|value| format!("{:x}", Sha256::digest(value.0)) != consumption)
        {
            return Err(FAILED.into());
        }
        self.placement()
    }
    /// The caller authenticates the immutable capsule under matched credentials before invoking this.
    pub(crate) fn publish_update_selection(
        &mut self,
        selection: &UpdateSelection,
        sealed: &[u8],
        consumption: &str,
    ) -> Result<(), String> {
        self.validate_update_selection(selection)?;
        self.require_update_selection_records(sealed, consumption)?;
        let _host_lease = match self.root.open_with("lease.lock", &options(false)) {
            Ok(file) => {
                let file = file.into_std();
                valid_file(&file)?;
                file.try_lock().map_err(|_| "host_already_owned")?;
                Some(TransientHostLease(file))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(FAILED.into()),
        };
        self.file.rewind().map_err(|_| FAILED)?;
        let mut current = Vec::new();
        Read::by_ref(&mut self.file)
            .take(4097)
            .read_to_end(&mut current)
            .map_err(|_| FAILED)?;
        let previous = serde_json::to_vec(&selection.previous).map_err(|_| FAILED)?;
        let next = serde_json::to_vec(&selection.next).map_err(|_| FAILED)?;
        if current != previous
            && current != next
            && !(current.len() < next.len() && next.starts_with(&current))
        {
            return Err(FAILED.into());
        }
        self.validate_update_selection(selection)?;
        self.require_update_selection_records(sealed, consumption)?;
        if current != next {
            // The same authenticated intent repairs only a prefix left by this exact fixed-inode write.
            self.file
                .seek(SeekFrom::Start(0))
                .and_then(|_| self.file.set_len(0))
                .and_then(|_| self.file.write_all(&next))
                .and_then(|_| self.file.sync_all())
                .map_err(|_| "host_update_selection_write_failed")?;
        }
        if self.read()?.as_ref() != Some(&selection.next) {
            return Err(FAILED.into());
        }
        self.validate_update_selection(selection)?;
        self.require_update_selection_records(sealed, consumption)
    }
}

impl Owner {
    fn require_update_commit(
        &mut self,
        selection: &UpdateSelection,
        evidence: [&[u8]; 3],
    ) -> Result<(), String> {
        if self.update_record()?.as_ref().map(|r| r.0.as_slice()) != Some(evidence[0])
            || self
                .update_recovery_evidence()?
                .as_ref()
                .map(|r| r.0.as_slice())
                != Some(evidence[1])
            || self
                .update_selection_evidence()?
                .as_ref()
                .map(|r| r.0.as_slice())
                != Some(evidence[2])
        {
            return Err(FAILED.into());
        }
        self.validate_update_selection(selection)?;
        if self.read()?.as_ref() != Some(&selection.next) {
            return Err(FAILED.into());
        }
        self.placement()
    }
    /// Only the same authenticated context that freshly verified this selected target may commit.
    pub(crate) fn finalize_update_selection(
        &mut self,
        selection: &UpdateSelection,
        evidence: [&[u8]; 3],
        ready: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let _host_lease = match self.root.open_with("lease.lock", &options(false)) {
            Ok(file) => {
                let file = file.into_std();
                valid_file(&file)?;
                file.try_lock().map_err(|_| "host_already_owned")?;
                Some(TransientHostLease(file))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(FAILED.into()),
        };
        self.require_update_commit(selection, evidence)?;
        let operation = self.history_operation()?;
        let names = [
            "host-update.json",
            "host-update-recovery.json",
            "host-update-selection.json",
        ];
        for (name, expected) in names.iter().zip(evidence) {
            self.require_update_commit(selection, evidence)?;
            self.reserve_update_file_record(&history_name(&operation, name)?, expected)?;
        }
        for (name, expected) in names.iter().zip(evidence) {
            if self
                .update_file_record(&history_name(&operation, name)?)?
                .as_ref()
                .map(|r| r.0.as_slice())
                != Some(expected)
            {
                return Err(FAILED.into());
            }
        }
        for name in [names[2], names[1]] {
            self.require_update_commit(selection, evidence)?;
            if self.update_file_record(name)?.is_some() {
                self.root
                    .remove_file(name)
                    .map_err(|_| "host_update_commit_failed")?;
                activation::sync_directory(&self.root)?;
            }
        }
        ready()?;
        self.require_update_commit(selection, evidence)?;
        // The main record is the last writer fence; archived evidence survives every preceding cutpoint.
        self.root
            .remove_file(names[0])
            .map_err(|_| "host_update_commit_failed")?;
        activation::sync_directory(&self.root)?;
        self.placement()?;
        no_update(&self.root)?;
        if self.read()?.as_ref() != Some(&selection.next) {
            return Err(FAILED.into());
        }
        Ok(())
    }
}
