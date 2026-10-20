use super::*;

impl Owner {
    pub(crate) fn review_update(
        &mut self,
        id: &str,
        sha: &str,
    ) -> Result<(Marker, String), String> {
        no_update(&self.root)?;
        self.review_reserved_update(id, sha)
    }
    // Metadata only: the reservation retry/cancel path must inspect its still-fenced source.
    pub(crate) fn review_reserved_update(
        &mut self,
        id: &str,
        sha: &str,
    ) -> Result<(Marker, String), String> {
        no_activation(&self.root)?;
        let marker = self.inspect_stopped(id, sha)?;
        if marker.restore_pending {
            return Err("host_restore_activation_pending".into());
        }
        let database = match &marker.database_reference {
            Some(reference) => reference.resolve(&self.path)?,
            None => self.path.join("database"),
        };
        let root = Dir::from_std_file(crate::host_storage::directory(&database)?);
        let identity = identity(&root)?;
        no_activation(&self.root)?;
        self.placement()?;
        Ok((marker, identity))
    }
}

impl Owner {
    pub(crate) fn approval_journal_sha256(&self) -> Result<String, String> {
        self.placement()?;
        valid_file(&self.file)?;
        let mut file = self
            .file
            .try_clone()
            .map_err(|_| "host_update_approval_invalid")?;
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(0))
            .map_err(|_| "host_update_approval_invalid")?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| "host_update_approval_invalid")?;
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err("host_update_approval_invalid".into());
        }
        self.placement()?;
        Ok(format!("{:x}", sha2::Sha256::digest(bytes)))
    }
    pub(crate) fn update_record(&self) -> Result<Option<(Vec<u8>, String)>, String> {
        self.update_file_record("host-update.json")
    }
    fn update_file_record(&self, file_name: &str) -> Result<Option<(Vec<u8>, String)>, String> {
        self.placement()?;
        match self.root.symlink_metadata(file_name) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(_) => {}
            Err(_) => return Err("host_update_reservation_invalid".into()),
        }
        let name = Path::new(file_name);
        let mut file = crate::copy_source::staged_file(&self.root, name)?;
        valid_file(
            &file
                .try_clone()
                .map_err(|_| "host_update_reservation_invalid")?
                .into_std(),
        )?;
        let stamp = crate::copy_source::opened_stamp(&file)?;
        let length = file
            .metadata()
            .map_err(|_| "host_update_reservation_invalid")?
            .len();
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| "host_update_reservation_invalid")?;
        if bytes.len() > 4096 {
            return Err("host_update_reservation_invalid".into());
        }
        crate::copy_source::unchanged(&self.root, name, &file, &stamp, length, bytes.len() as u64)?;
        Ok(Some((bytes, stamp)))
    }
    pub(crate) fn reserve_update_record(&self, bytes: &[u8]) -> Result<(), String> {
        self.reserve_update_file_record("host-update.json", bytes)
    }
    pub(crate) fn reserve_update_recovery_record(&self, bytes: &[u8]) -> Result<(), String> {
        self.reserve_update_file_record("host-update-recovery.json", bytes)
    }
    fn reserve_update_file_record(&self, file_name: &str, bytes: &[u8]) -> Result<(), String> {
        if !self.writable || self.active.is_some() || bytes.len() > 4096 {
            return Err("host_update_reservation_invalid".into());
        }
        self.placement()?;
        if let Some((current, _)) = self.update_file_record(file_name)? {
            return if current == bytes {
                Ok(())
            } else {
                Err("host_update_reservation_changed".into())
            };
        }
        let temporary = format!(".host-update-{}.tmp", Uuid::new_v4());
        let result = (|| {
            let mut opts = options(true);
            opts.create_new(true);
            let mut file = self
                .root
                .open_with(&temporary, &opts)
                .map_err(|_| "host_update_reservation_write_failed")?
                .into_std();
            valid_file(&file)?;
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "host_update_reservation_write_failed")?;
            drop(file);
            crate::manager_profile::publish_marker(&self.root, &temporary, file_name)?;
            activation::sync_directory(&self.root)?;
            if self.update_file_record(file_name)?.map(|r| r.0).as_deref() != Some(bytes) {
                return Err("host_update_reservation_changed".into());
            }
            self.placement()
        })();
        let cleanup = self.root.remove_file(&temporary);
        result?;
        if cleanup.is_err_and(|e| e.kind() != std::io::ErrorKind::NotFound) {
            return Err("host_update_reservation_write_failed".into());
        }
        Ok(())
    }
    pub(crate) fn advance_update_record(
        &self,
        expected: &[u8],
        stamp: &str,
        next: &[u8],
    ) -> Result<(), String> {
        if !self.writable || self.active.is_some() || next.len() > 4096 {
            return Err("host_update_reservation_invalid".into());
        }
        self.placement()?;
        let current = self
            .update_record()?
            .ok_or("host_update_reservation_changed")?;
        if current.0 != expected || current.1 != stamp {
            return Err("host_update_reservation_changed".into());
        }
        let temporary = format!(".host-update-{}.tmp", Uuid::new_v4());
        let result = (|| -> Result<(), String> {
            let mut opts = options(true);
            opts.create_new(true);
            let mut file = self
                .root
                .open_with(&temporary, &opts)
                .map_err(|_| "host_update_reservation_write_failed")?
                .into_std();
            valid_file(&file)?;
            file.write_all(next)
                .and_then(|_| file.sync_all())
                .map_err(|_| "host_update_reservation_write_failed")?;
            drop(file);
            self.placement()?;
            let current = self
                .update_record()?
                .ok_or("host_update_reservation_changed")?;
            if current.0 != expected || current.1 != stamp {
                return Err("host_update_reservation_changed".into());
            }
            self.root
                .rename(&temporary, &self.root, "host-update.json")
                .map_err(|_| "host_update_reservation_write_failed")?;
            activation::sync_directory(&self.root)?;
            if self.update_record()?.map(|r| r.0).as_deref() != Some(next) {
                return Err("host_update_reservation_changed".into());
            }
            self.placement()
        })();
        let cleanup = self.root.remove_file(&temporary);
        result?;
        if cleanup.is_err_and(|e| e.kind() != std::io::ErrorKind::NotFound) {
            return Err("host_update_reservation_write_failed".into());
        }
        Ok(())
    }
    pub(crate) fn cancel_update_record(&self, bytes: &[u8], stamp: &str) -> Result<(), String> {
        if !self.writable || self.active.is_some() {
            return Err("host_update_reservation_invalid".into());
        }
        self.placement()?;
        let current = self
            .update_record()?
            .ok_or("host_update_reservation_changed")?;
        if current.0 != bytes || current.1 != stamp {
            return Err("host_update_reservation_changed".into());
        }
        self.root
            .remove_file("host-update.json")
            .map_err(|_| "host_update_reservation_write_failed")?;
        activation::sync_directory(&self.root)?;
        self.placement()
    }
}

#[path = "update_selection.rs"]
mod selection;
pub(crate) use selection::UpdateSelection;

fn history_name(operation: &str, active: &str) -> Result<String, String> {
    let kind = match active {
        "host-update.json" => "consumption",
        "host-update-recovery.json" => "recovery",
        "host-update-selection.json" => "selection",
        _ => return Err("host_update_history_invalid".into()),
    };
    if !valid_installation_id(operation) {
        return Err("host_update_history_invalid".into());
    }
    Ok(format!("host-update-history-{operation}-{kind}.json"))
}
pub(crate) fn valid_update_history_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("host-update-history-") else {
        return false;
    };
    rest.get(..36).is_some_and(valid_installation_id)
        && matches!(
            rest.get(36..),
            Some("-consumption.json" | "-recovery.json" | "-selection.json")
        )
}
impl Owner {
    pub(crate) fn update_selection_evidence(&self) -> Result<Option<(Vec<u8>, String)>, String> {
        self.update_evidence("host-update-selection.json")
    }
    pub(crate) fn update_recovery_evidence(&self) -> Result<Option<(Vec<u8>, String)>, String> {
        self.update_evidence("host-update-recovery.json")
    }
    fn history_operation(&self) -> Result<String, String> {
        let current = self.update_record()?.ok_or("host_update_history_invalid")?;
        let value: serde_json::Value =
            serde_json::from_slice(&current.0).map_err(|_| "host_update_history_invalid")?;
        let operation = value["operationId"]
            .as_str()
            .ok_or("host_update_history_invalid")?;
        if value["state"] != "approvalConsumed" || !valid_installation_id(operation) {
            return Err("host_update_history_invalid".into());
        }
        if self
            .update_file_record(&history_name(operation, "host-update.json")?)?
            .is_some_and(|record| record.0 != current.0)
        {
            return Err("host_update_history_invalid".into());
        }
        Ok(operation.into())
    }
    fn update_evidence(&self, name: &str) -> Result<Option<(Vec<u8>, String)>, String> {
        let operation = self.history_operation()?;
        let active = self.update_file_record(name)?;
        let archived = self.update_file_record(&history_name(&operation, name)?)?;
        if let (Some(active), Some(archived)) = (&active, &archived) {
            if active.0 != archived.0 {
                return Err("host_update_history_invalid".into());
            }
        }
        Ok(active.or(archived))
    }
}
