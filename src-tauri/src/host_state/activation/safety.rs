//! Independently read actual decrypted safety bytes; journal metadata alone never admits selection.
use super::*;
use crate::copy_source::{opened_stamp, parent_dir, root_identity, staged_file, unchanged};
fn private_directory(dir: &Dir) -> Result<(), String> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        if dir
            .dir_metadata()
            .map_err(|_| "host_restore_safety_invalid")?
            .mode()
            & 0o077
            != 0
        {
            return Err("host_restore_safety_invalid".into());
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}
fn opened(dir: &Dir, name: &str, maximum: u64) -> Result<cap_std::fs::File, String> {
    let file = staged_file(dir, Path::new(name))?;
    valid_sized_file(
        &file
            .try_clone()
            .map_err(|_| "host_restore_safety_invalid")?
            .into_std(),
        maximum,
    )?;
    Ok(file)
}
impl SafetySnapshot {
    pub(super) fn verify_readback(
        &self,
        root: &Dir,
        prepared: &PreparedRestore,
    ) -> Result<(), String> {
        self.readback(root, prepared)
            .map_err(|_| "host_restore_safety_invalid".into())
    }
    fn readback(&self, root: &Dir, prepared: &PreparedRestore) -> Result<(), String> {
        self.validate()?;
        let (parent, _) = parent_dir(root, Path::new("restore-safety/placeholder"))?;
        private_directory(&parent)?;
        let relative = PathBuf::from(&prepared.binding.operation_id).join("recovery.json");
        let (dir, _) = parent_dir(&parent, &relative)?;
        private_directory(&dir)?;
        let parent_id = root_identity(&parent)?;
        let dir_id = root_identity(&dir)?;
        let inventory = || -> Result<Vec<std::ffi::OsString>, String> {
            let mut names = dir
                .entries()
                .map_err(|_| "host_restore_safety_invalid")?
                .take(3)
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "host_restore_safety_invalid")?;
            names.sort();
            Ok(names)
        };
        let expected_names = vec![
            std::ffi::OsString::from("database.dump"),
            std::ffi::OsString::from("recovery.json"),
        ];
        if inventory()? != expected_names {
            return Err("host_restore_safety_invalid".into());
        }
        let mut record = opened(&dir, "recovery.json", 4096)?;
        let before = opened_stamp(&record)?;
        let length = record
            .metadata()
            .map_err(|_| "host_restore_safety_invalid")?
            .len();
        let mut bytes = Vec::new();
        Read::by_ref(&mut record)
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| "host_restore_safety_invalid")?;
        unchanged(
            &dir,
            Path::new("recovery.json"),
            &record,
            &before,
            length,
            bytes.len() as u64,
        )?;
        let json = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        // Manager hashes JSON.stringify(recovery); its stored file adds one LF, without sorting keys.
        if format!("{:x}", Sha256::digest(json)) != self.recovery_sha256 {
            return Err("host_restore_safety_invalid".into());
        }
        let recovery: serde_json::Value =
            serde_json::from_slice(json).map_err(|_| "host_restore_safety_invalid")?;
        let binding =
            serde_json::to_value(&prepared.binding).map_err(|_| "host_restore_safety_invalid")?;
        let checkpoint =
            serde_json::to_value(&self.checkpoint).map_err(|_| "host_restore_safety_invalid")?;
        let mut expected_checkpoint = checkpoint.clone();
        expected_checkpoint["protocolVersion"] = serde_json::json!(1);
        expected_checkpoint["state"] = serde_json::json!("checkpoint");
        if recovery["schemaVersion"] != 1
            || recovery["runtime"] != "native"
            || recovery["mediaIncluded"] != false
            || recovery["databaseFormat"] != "frameleaf-canonical"
            || recovery["libraryId"] != binding["libraryId"]
            || recovery["installation"]["id"] != binding["installationId"]
            || recovery["checkpoint"] != expected_checkpoint
        {
            return Err("host_restore_safety_invalid".into());
        }
        let expected = checkpoint["dump"]["bytes"]
            .as_u64()
            .ok_or("host_restore_safety_invalid")?;
        let mut file = opened(&dir, "database.dump", expected)?;
        let stamp = opened_stamp(&file)?;
        if file
            .metadata()
            .map_err(|_| "host_restore_safety_invalid")?
            .len()
            != expected
        {
            return Err("host_restore_safety_invalid".into());
        }
        let mut header = [0u8; 5];
        file.read_exact(&mut header)
            .map_err(|_| "host_restore_safety_invalid")?;
        if &header != b"PGDMP" {
            return Err("host_restore_safety_invalid".into());
        }
        let mut hash = Sha256::new();
        hash.update(header);
        let mut total = 5u64;
        let mut buffer = [0u8; 65536];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|_| "host_restore_safety_invalid")?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or("host_restore_safety_invalid")?;
            if total > expected {
                return Err("host_restore_safety_invalid".into());
            }
            hash.update(&buffer[..count]);
        }
        if format!("{:x}", hash.finalize())
            != checkpoint["dump"]["sha256"]
                .as_str()
                .ok_or("host_restore_safety_invalid")?
        {
            return Err("host_restore_safety_invalid".into());
        }
        unchanged(
            &dir,
            Path::new("database.dump"),
            &file,
            &stamp,
            expected,
            total,
        )?;
        unchanged(
            &dir,
            Path::new("recovery.json"),
            &record,
            &before,
            length,
            bytes.len() as u64,
        )?;
        let (fresh_parent, _) = parent_dir(root, Path::new("restore-safety/placeholder"))?;
        let (fresh_dir, _) = parent_dir(&fresh_parent, &relative)?;
        private_directory(&fresh_parent)?;
        private_directory(&fresh_dir)?;
        if root_identity(&fresh_parent)? != parent_id
            || root_identity(&fresh_dir)? != dir_id
            || inventory()? != expected_names
        {
            return Err("host_restore_safety_invalid".into());
        }
        Ok(())
    }
}
