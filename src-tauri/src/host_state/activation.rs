//! Selection stays fenced until independent finalization admits writers.
use super::*;
pub(super) mod safety;
use crate::host_runtime::{CheckpointReceipt, PreparedRestore, VerifiedRestore};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SafetySnapshot {
    snapshot_id: String,
    recovery_sha256: String,
    checkpoint: CheckpointReceipt,
}
impl SafetySnapshot {
    #[cfg(any(windows, test))]
    pub(super) fn operation_id(&self) -> &str {
        self.checkpoint.operation_id()
    }

    #[cfg(any(windows, test))]
    pub(super) fn checkpoint_matches_manifest(&self, manifest: &str) -> bool {
        self.checkpoint.matches_manifest(manifest)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        self.checkpoint.validate()?;
        if !crate::native_runtime::digest_valid(&self.snapshot_id, 64)
            || !crate::native_runtime::digest_valid(&self.recovery_sha256, 64)
        {
            return Err("host_restore_safety_invalid".into());
        }
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Intent {
    schema_version: u32,
    previous: Marker,
    next: Marker,
    previous_database_identity: String,
    media_identity: Option<String>,
    prepared: PreparedRestore,
    verification_id: String,
    safety: SafetySnapshot,
}
impl Intent {
    fn validate(&self, owner: &Owner, id: &str, sha: &str) -> Result<(), String> {
        owner.binding(&self.previous, id, sha)?;
        owner.binding(&self.next, id, sha)?;
        self.prepared.validate()?;
        self.safety.validate()?;
        if self.schema_version != 1
            || self.previous.phase != Phase::Stopped
            || self.next.phase != Phase::Stopped
            || !self.next.restore_pending
            || self.previous.generation == self.next.generation
            || !crate::host_runtime::checkpoint_operation_id(&self.verification_id)
            || !crate::native_runtime::digest_valid(&self.previous_database_identity, 64)
            || self
                .media_identity
                .as_ref()
                .is_some_and(|value| !crate::native_runtime::digest_valid(value, 64))
            || self.prepared.binding.installation_id != id
            || self.prepared.binding.manifest_sha256 != sha
            || !self
                .safety
                .checkpoint
                .matches_restore_runtime(&self.prepared)
        {
            return Err("host_restore_activation_requires_review".into());
        }
        let reference = self
            .next
            .database_reference
            .as_ref()
            .ok_or("host_restore_activation_requires_review")?;
        self.prepared.validate_reference(reference)?;
        let mut expected = self.previous.clone();
        expected.generation = self.next.generation;
        expected.restore_pending = true;
        expected.database_reference = Some(reference.clone());
        if expected != self.next {
            return Err("host_restore_activation_requires_review".into());
        }
        Ok(())
    }
}
pub(super) fn sync_directory(root: &Dir) -> Result<(), String> {
    #[cfg(unix)]
    root.try_clone()
        .and_then(|root| root.into_std_file().sync_all())
        .map_err(|_| "host_restore_activation_write_failed")?;
    #[cfg(not(unix))]
    let _ = root;
    Ok(())
}
pub(super) fn record(root: &Dir, name: &str, bytes: &[u8]) -> Result<(), String> {
    let mut opts = options(true);
    opts.create_new(true);
    let mut file = root
        .open_with(name, &opts)
        .map_err(|_| "host_restore_activation_requires_review")?
        .into_std();
    valid_file(&file)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "host_restore_activation_write_failed")?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "host_restore_activation_write_failed")?;
    let mut actual = Vec::new();
    file.take(4097)
        .read_to_end(&mut actual)
        .map_err(|_| "host_restore_activation_write_failed")?;
    if actual != bytes {
        return Err("host_restore_activation_write_failed".into());
    }
    sync_directory(root)
}
fn verify_record(root: &Dir, name: &str, expected: &[u8]) -> Result<(), String> {
    let file = root
        .open_with(name, &options(false))
        .map_err(|_| "host_restore_activation_requires_review")?
        .into_std();
    valid_file(&file)?;
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "host_restore_activation_requires_review")?;
    if bytes != expected {
        return Err("host_restore_activation_requires_review".into());
    }
    Ok(())
}
pub(super) fn read_record(root: &Dir, name: &str) -> Result<Option<Vec<u8>>, String> {
    let file = match root.open_with(name, &options(false)) {
        Ok(file) => file.into_std(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("host_restore_activation_requires_review".into()),
    };
    valid_file(&file)?;
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "host_restore_activation_requires_review")?;
    if bytes.len() > 4096 {
        return Err("host_restore_activation_requires_review".into());
    }
    Ok(Some(bytes))
}
fn recoverable_marker(owner: &mut Owner) -> Result<Option<Marker>, String> {
    owner.placement()?;
    owner
        .file
        .rewind()
        .map_err(|_| "host_restore_activation_requires_review")?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut owner.file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "host_restore_activation_requires_review")?;
    if bytes.len() > 4096 {
        return Err("host_restore_activation_requires_review".into());
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    match serde_json::from_slice(&bytes) {
        Ok(marker) => Ok(Some(marker)),
        Err(error) if error.is_eof() => Ok(None),
        _ => Err("host_restore_activation_requires_review".into()),
    }
}
fn same_selection(current: &Marker, expected: &Marker) -> bool {
    let mut value = current.clone();
    value.generation = expected.generation;
    !current.generation.is_nil() && current.phase == Phase::Stopped && value == *expected
}
fn stopped_databases(paths: [&Path; 2]) -> Result<(), String> {
    for path in paths {
        match std::fs::symlink_metadata(path.join("postmaster.pid")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("host_process_state_requires_review".into()),
        }
    }
    Ok(())
}
fn database_identity(path: &Path) -> Result<String, String> {
    let root = Dir::from_std_file(crate::host_storage::directory(path)?);
    identity(&root)
}
fn media_identity(root: &Dir) -> Result<Option<String>, String> {
    match root.symlink_metadata("media") {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => {}
        _ => return Err("host_restore_media_changed".into()),
    }
    let open = || {
        crate::copy_source::parent_dir(root, Path::new("media/placeholder"))
            .map(|(directory, _)| directory)
            .map_err(|_| "host_restore_media_changed".to_string())
    };
    let directory = open()?;
    let captured = identity(&directory)?;
    if identity(&open()?)? != captured {
        return Err("host_restore_media_changed".into());
    }
    Ok(Some(captured))
}
impl Owner {
    /// Recover only the retained selection. This never clears pending state or grants writers.
    pub(crate) fn reconcile_restore(
        &mut self,
        id: &str,
        sha: &str,
    ) -> Result<Option<Uuid>, String> {
        if self.active.is_some() || !self.writable {
            return Err("host_restore_activation_requires_review".into());
        }
        self.placement()?;
        let current = recoverable_marker(self)?;
        let global = read_record(&self.root, ACTIVATION)?;
        let bytes = match &global {
            Some(bytes) => bytes.clone(),
            None => match &current {
                Some(marker) if marker.restore_pending => {
                    self.binding(marker, id, sha)?;
                    let reference = marker
                        .database_reference
                        .as_ref()
                        .ok_or("host_restore_activation_requires_review")?;
                    read_record(
                        &reference.target_directory(&self.path)?,
                        "activation-intent.json",
                    )?
                    .ok_or("host_restore_activation_requires_review")?
                }
                _ => return Ok(None),
            },
        };
        let intent: Intent = serde_json::from_slice(&bytes)
            .map_err(|_| "host_restore_activation_requires_review")?;
        intent.validate(self, id, sha)?;
        if media_identity(&self.root)? != intent.media_identity {
            return Err("host_restore_media_changed".into());
        }
        let reference = intent
            .next
            .database_reference
            .as_ref()
            .ok_or("host_restore_activation_requires_review")?;
        intent.prepared.validate_reference(reference)?;
        let target = reference.target_directory(&self.path)?;
        let mut completed = intent.next.clone();
        completed.restore_pending = false;
        let finishing = current
            .as_ref()
            .is_some_and(|marker| same_selection(marker, &completed));
        if finishing
            && (global.is_none()
                || read_record(&target, "activation-complete.json")?.as_ref() != Some(&bytes))
        {
            return Err("host_restore_activation_requires_review".into());
        }
        if let Some(marker) = &current {
            if !same_selection(marker, &intent.previous)
                && !same_selection(marker, &intent.next)
                && !finishing
            {
                return Err("host_restore_activation_requires_review".into());
            }
            if global.is_none() && !same_selection(marker, &intent.next) {
                return Err("host_restore_activation_requires_review".into());
            }
        } else if global.is_none() {
            return Err("host_restore_activation_requires_review".into());
        }
        let host_lease = self
            .root
            .open_with("lease.lock", &options(false))
            .map_err(|_| "host_process_state_requires_review")?
            .into_std();
        valid_file(&host_lease)?;
        host_lease.try_lock().map_err(|_| "host_already_owned")?;
        let _host_lease = TransientHostLease(host_lease);
        let original = match &intent.previous.database_reference {
            Some(reference) => reference.resolve(&self.path)?,
            None => self.path.join("database"),
        };
        let selected = reference.resolve(&self.path)?;
        if database_identity(&original)? != intent.previous_database_identity {
            return Err("host_restore_activation_requires_review".into());
        }
        stopped_databases([&original, &selected])?;
        let target = reference.target_directory(&self.path)?;
        match read_record(&target, "activation-intent.json")? {
            Some(retained) if retained == bytes => {}
            Some(_) => return Err("host_restore_activation_requires_review".into()),
            None => {}
        }
        if global.is_none() {
            record(&self.root, ACTIVATION, &bytes)?;
        }
        if read_record(&target, "activation-intent.json")?.is_none() {
            record(&target, "activation-intent.json", &bytes)?;
        }
        verify_record(&self.root, ACTIVATION, &bytes)?;
        verify_record(&target, "activation-intent.json", &bytes)?;
        reference.resolve(&self.path)?;
        stopped_databases([&original, &selected])?;
        if database_identity(&original)? != intent.previous_database_identity {
            return Err("host_restore_activation_requires_review".into());
        }
        if media_identity(&self.root)? != intent.media_identity {
            return Err("host_restore_media_changed".into());
        }
        self.placement()?;
        let fresh = recoverable_marker(self)?;
        if fresh != current {
            return Err("host_restore_activation_requires_review".into());
        }
        let mut marker = current
            .filter(|marker| same_selection(marker, &intent.next) || finishing)
            .unwrap_or(intent.next);
        marker.restore_pending = true;
        self.write(&marker)?;
        if self.read()? != Some(marker.clone()) {
            return Err("host_restore_activation_requires_review".into());
        }
        verify_record(&self.root, ACTIVATION, &bytes)?;
        verify_record(&target, "activation-intent.json", &bytes)?;
        if media_identity(&self.root)? != intent.media_identity {
            return Err("host_restore_media_changed".into());
        }
        Ok(Some(marker.generation))
    }
    /// Fresh validation and a durable receipt precede removing the final writer fence.
    pub(crate) fn finalize_restore(
        &mut self,
        proof: VerifiedRestore,
        safety: SafetySnapshot,
    ) -> Result<Uuid, String> {
        let id = &proof.prepared.binding.installation_id;
        let sha = &proof.prepared.binding.manifest_sha256;
        self.reconcile_restore(id, sha)?;
        let current = self.inspect(id, sha)?;
        if current.generation != proof.generation
            || current.database_reference.as_ref() != Some(&proof.reference)
        {
            return Err("host_restore_proof_invalid".into());
        }
        let target = proof.reference.target_directory(&self.path)?;
        let bytes = read_record(&target, "activation-intent.json")?
            .ok_or("host_restore_activation_requires_review")?;
        let intent: Intent = serde_json::from_slice(&bytes)
            .map_err(|_| "host_restore_activation_requires_review")?;
        intent.validate(self, id, sha)?;
        if intent.prepared != proof.prepared || intent.safety != safety {
            return Err("host_restore_activation_requires_review".into());
        }
        safety.verify_readback(&self.root, &proof.prepared)?;
        let mut completed = intent.next.clone();
        completed.generation = current.generation;
        completed.restore_pending = false;
        let mut pending = completed.clone();
        pending.restore_pending = true;
        if current != completed && current != pending {
            return Err("host_restore_activation_requires_review".into());
        }
        let global = read_record(&self.root, ACTIVATION)?;
        if global.as_ref().is_some_and(|value| value != &bytes)
            || (current.restore_pending && global.is_none())
        {
            return Err("host_restore_activation_requires_review".into());
        }
        let host_lease = self
            .root
            .open_with("lease.lock", &options(false))
            .map_err(|_| "host_process_state_requires_review")?
            .into_std();
        valid_file(&host_lease)?;
        host_lease.try_lock().map_err(|_| "host_already_owned")?;
        let _host_lease = TransientHostLease(host_lease);
        let original = match &intent.previous.database_reference {
            Some(reference) => reference.resolve(&self.path)?,
            None => self.path.join("database"),
        };
        let selected = proof.reference.resolve(&self.path)?;
        stopped_databases([&original, &selected])?;
        if database_identity(&original)? != intent.previous_database_identity
            || media_identity(&self.root)? != intent.media_identity
        {
            return Err("host_restore_activation_requires_review".into());
        }
        match read_record(&target, "activation-complete.json")? {
            Some(value) if value == bytes => {}
            Some(_) => return Err("host_restore_activation_requires_review".into()),
            None if global.is_some() => record(&target, "activation-complete.json", &bytes)?,
            None => return Err("host_restore_activation_requires_review".into()),
        }
        verify_record(&target, "activation-intent.json", &bytes)?;
        verify_record(&target, "activation-complete.json", &bytes)?;
        if self.read()? != Some(current) {
            return Err("host_restore_activation_requires_review".into());
        }
        self.write(&completed)?;
        if self.read()? != Some(completed.clone()) {
            return Err("host_restore_activation_requires_review".into());
        }
        proof.reference.resolve(&self.path)?;
        stopped_databases([&original, &selected])?;
        if media_identity(&self.root)? != intent.media_identity
            || database_identity(&original)? != intent.previous_database_identity
        {
            return Err("host_restore_activation_requires_review".into());
        }
        if global.is_some() {
            verify_record(&self.root, ACTIVATION, &bytes)?;
            self.root
                .remove_file(ACTIVATION)
                .map_err(|_| "host_restore_activation_write_failed")?;
            sync_directory(&self.root)?;
        }
        no_activation(&self.root)?;
        Ok(completed.generation)
    }
    pub(crate) fn select_restore(
        &mut self,
        proof: VerifiedRestore,
        safety: SafetySnapshot,
    ) -> Result<Uuid, String> {
        if self.active.is_some() || !self.writable {
            return Err("host_restore_proof_invalid".into());
        }
        safety.validate()?;
        if !safety.checkpoint.matches_restore_runtime(&proof.prepared) {
            return Err("host_restore_safety_invalid".into());
        }
        let previous = self.inspect(
            &proof.prepared.binding.installation_id,
            &proof.prepared.binding.manifest_sha256,
        )?;
        if previous.generation != proof.generation {
            return Err("host_restore_proof_invalid".into());
        }
        safety.verify_readback(&self.root, &proof.prepared)?;
        let existing = read_record(&self.root, ACTIVATION)?;
        if existing.is_some() || previous.restore_pending {
            proof.prepared.validate_reference(&proof.reference)?;
            let target = proof.reference.target_directory(&self.path)?;
            let bytes = match existing {
                Some(bytes) => bytes,
                None => read_record(&target, "activation-intent.json")?
                    .ok_or("host_restore_activation_requires_review")?,
            };
            let intent: Intent = serde_json::from_slice(&bytes)
                .map_err(|_| "host_restore_activation_requires_review")?;
            if !previous.restore_pending
                || previous.database_reference.as_ref() != Some(&proof.reference)
                || intent.next.database_reference.as_ref() != Some(&proof.reference)
                || intent.prepared != proof.prepared
                || intent.safety != safety
            {
                return Err("host_restore_activation_requires_review".into());
            }
            // A fresh proof can acknowledge the same selection; the original fence stays immutable.
            let generation = self
                .reconcile_restore(
                    &proof.prepared.binding.installation_id,
                    &proof.prepared.binding.manifest_sha256,
                )?
                .ok_or("host_restore_activation_requires_review")?;
            if generation != proof.generation || self.read()? != Some(previous) {
                return Err("host_restore_activation_requires_review".into());
            }
            proof.reference.resolve(&self.path)?;
            verify_record(&self.root, ACTIVATION, &bytes)?;
            verify_record(&target, "activation-intent.json", &bytes)?;
            return Ok(generation);
        }
        no_activation(&self.root)?;
        let host_lease = self
            .root
            .open_with("lease.lock", &options(false))
            .map_err(|_| "host_process_state_requires_review")?
            .into_std();
        valid_file(&host_lease)?;
        host_lease.try_lock().map_err(|_| "host_already_owned")?;
        let _host_lease = TransientHostLease(host_lease);
        let database = match &previous.database_reference {
            Some(reference) => reference.resolve(&self.path)?,
            None => self.path.join("database"),
        };
        let previous_identity = database_identity(&database)?;
        let selected = proof.reference.resolve(&self.path)?;
        stopped_databases([&database, &selected])?;
        let mut next = previous.clone();
        next.generation = Uuid::new_v4();
        next.restore_pending = true;
        next.database_reference = Some(proof.reference.clone());
        let intent = Intent {
            schema_version: 1,
            previous,
            next,
            previous_database_identity: previous_identity,
            media_identity: media_identity(&self.root)?,
            prepared: proof.prepared,
            verification_id: proof.verification_id,
            safety,
        };
        let bytes =
            serde_json::to_vec(&intent).map_err(|_| "host_restore_activation_write_failed")?;
        if bytes.len() > 4096 {
            return Err("host_restore_activation_write_failed".into());
        }
        self.placement()?;
        if media_identity(&self.root)? != intent.media_identity {
            return Err("host_restore_media_changed".into());
        }
        // Publish and sync the global writer fence before any selection change.
        record(&self.root, ACTIVATION, &bytes)?;
        let target = proof.reference.target_directory(&self.path)?;
        record(&target, "activation-intent.json", &bytes)?;
        proof.reference.resolve(&self.path)?;
        if database_identity(&database)? != intent.previous_database_identity
            || media_identity(&self.root)? != intent.media_identity
            || self.read()? != Some(intent.previous.clone())
        {
            return Err("host_restore_activation_requires_review".into());
        }
        stopped_databases([&database, &selected])?;
        verify_record(&self.root, ACTIVATION, &bytes)?;
        verify_record(&target, "activation-intent.json", &bytes)?;
        self.write(&intent.next)?;
        if self.read()? != Some(intent.next.clone()) {
            return Err("host_restore_activation_requires_review".into());
        }
        proof.reference.resolve(&self.path)?;
        verify_record(&self.root, ACTIVATION, &bytes)?;
        verify_record(&target, "activation-intent.json", &bytes)?;
        // The immutable fence deliberately remains: this operation cannot admit writers.
        if media_identity(&self.root)? != intent.media_identity {
            return Err("host_restore_media_changed".into());
        }
        Ok(intent.next.generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    const ID: &str = "aaaaaaaaaaaa";
    const OP: &str = "11111111-1111-4111-8111-111111111111";
    const ATTEMPT: &str = "22222222-2222-4222-8222-222222222222";
    struct Fixture {
        path: PathBuf,
        target: PathBuf,
        owner: Owner,
        prepared: PreparedRestore,
    }
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-selection-{}", Uuid::new_v4()));
            crate::runtime_store::private_directory(&path).unwrap();
            let mut owner = Owner::acquire(&path, true).unwrap();
            owner
                .activate(
                    ID,
                    &"b".repeat(64),
                    crate::host_runtime::HostMode::RestorePrepare,
                )
                .unwrap();
            let target = path.join("restore-targets").join(OP).join(ATTEMPT);
            for directory in [
                path.join("database"),
                path.join("restore-targets"),
                path.join("restore-targets").join(OP),
                target.clone(),
                target.join("database"),
            ] {
                crate::runtime_store::private_directory(&directory).unwrap();
            }
            fs::write(path.join("database/sentinel"), b"original").unwrap();
            fs::write(target.join("database/sentinel"), b"prepared").unwrap();
            fs::write(path.join("profile.json"), b"configuration").unwrap();
            let _lease = owner.root.open_with("lease.lock", &options(true)).unwrap();
            let ids: Vec<_> = [&path, &target, &target.join("database")]
                .into_iter()
                .map(|path| {
                    let root = Dir::from_std_file(crate::host_storage::directory(path).unwrap());
                    let id = crate::copy_source::root_identity(&root).unwrap();
                    #[cfg(windows)]
                    let id = {
                        let parts: Vec<_> = id.split(':').collect();
                        format!(
                            "{}:{}",
                            parts[0],
                            (parts[1].parse::<u64>().unwrap() << 32)
                                | parts[2].parse::<u64>().unwrap()
                        )
                    };
                    id
                })
                .collect();
            let prepared = serde_json::from_value(serde_json::json!({"schemaVersion":1,"state":"restore-prepared",
                "binding":{"schemaVersion":1,"runtime":"native","operationId":OP,"reviewId":ATTEMPT,"snapshotId":"c".repeat(64),"installationId":ID,"manifestSha256":"b".repeat(64),"sourceRevision":"d".repeat(40),"libraryId":"e".repeat(12),"recoverySha256":"f".repeat(64)},
                "attemptId":ATTEMPT,"profileIdentity":ids[0],"targetIdentity":ids[1],"databaseIdentity":ids[2],
                "validation":{"postgresMajor":19,"vectorVersion":"0.8.7","canonical":true,"executionStateReconstructed":true}})).unwrap();
            Self {
                path,
                target,
                owner,
                prepared,
            }
        }
        fn proof(&mut self) -> VerifiedRestore {
            let generation = self.owner.active.as_ref().unwrap().generation;
            let proof =
                VerifiedRestore::test_capture(&self.path, generation, self.prepared.clone());
            self.owner.clean_stop().unwrap();
            proof
        }
        fn safety(&self) -> SafetySnapshot {
            let dump = b"PGDMP safety database";
            let checkpoint = serde_json::json!({"schemaVersion":1,"operationId":OP,"manifestSha256":"b".repeat(64),"sourceRevision":"d".repeat(40),"postgresMajor":"19","databaseFormat":"frameleaf-canonical","dump":{"bytes":dump.len(),"sha256":format!("{:x}",Sha256::digest(dump))}});
            let mut envelope = checkpoint.clone();
            envelope["protocolVersion"] = serde_json::json!(1);
            envelope["state"] = serde_json::json!("checkpoint");
            let recovery = serde_json::json!({"schemaVersion":1,"runtime":"native","mediaIncluded":false,"databaseFormat":"frameleaf-canonical","libraryId":"e".repeat(12),"createdAt":1,"installation":{"id":ID,"name":"Fixture","release":"frameleaf-v3.0.0-1"},"checkpoint":envelope});
            let bytes = serde_json::to_vec(&recovery).unwrap();
            let parent = self.path.join("restore-safety");
            let target = parent.join(OP);
            crate::runtime_store::private_directory(&parent).unwrap();
            crate::runtime_store::private_directory(&target).unwrap();
            fs::write(target.join("database.dump"), dump).unwrap();
            fs::write(
                target.join("recovery.json"),
                [bytes.as_slice(), b"\n"].concat(),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for name in ["database.dump", "recovery.json"] {
                    fs::set_permissions(target.join(name), fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
            }
            serde_json::from_value(serde_json::json!({"snapshotId":"1".repeat(64),"recoverySha256":format!("{:x}",Sha256::digest(&bytes)),"checkpoint":checkpoint})).unwrap()
        }
    }
    // Inject crash bytes through the held journal handle; Windows locks reject a second handle.
    fn journal_bytes(owner: &mut Owner) -> Vec<u8> {
        owner.file.rewind().unwrap();
        let mut bytes = Vec::new();
        Read::by_ref(&mut owner.file)
            .read_to_end(&mut bytes)
            .unwrap();
        bytes
    }
    fn inject_journal(owner: &mut Owner, bytes: &[u8]) {
        owner.file.rewind().unwrap();
        owner.file.set_len(0).unwrap();
        owner.file.write_all(bytes).unwrap();
        owner.file.sync_all().unwrap();
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
    #[test]
    fn fresh_final_validation_admits_only_the_selected_database_and_retains_recovery() {
        let mut f = Fixture::new();
        let proof = f.proof();
        let safety = f.safety();
        f.owner.select_restore(proof, safety.clone()).unwrap();
        f.owner
            .activate(
                ID,
                &"b".repeat(64),
                crate::host_runtime::HostMode::RestorePrepare,
            )
            .unwrap();
        let proof = f.proof();
        let generation = f.owner.finalize_restore(proof, safety).unwrap();
        assert_eq!(f.owner.read().unwrap().unwrap().generation, generation);
        assert!(!f.owner.read().unwrap().unwrap().restore_pending);
        assert!(!f.path.join(ACTIVATION).exists());
        assert!(f.target.join("activation-complete.json").is_file());
        assert_eq!(
            fs::read(f.path.join("database/sentinel")).unwrap(),
            b"original"
        );
        assert!(f
            .path
            .join("restore-safety")
            .join(OP)
            .join("database.dump")
            .is_file());
        f.owner
            .activate(ID, &"b".repeat(64), crate::host_runtime::HostMode::Server)
            .unwrap();
        assert_eq!(
            f.owner
                .launch_state(&"b".repeat(64), crate::host_runtime::HostMode::Server)
                .unwrap()
                .1
                .unwrap()
                .resolve(&f.path)
                .unwrap(),
            f.target.join("database")
        );
    }

    #[test]
    fn interrupted_final_marker_requires_matching_completion_and_revalidation() {
        let mut f = Fixture::new();
        let proof = f.proof();
        let safety = f.safety();
        f.owner.select_restore(proof, safety).unwrap();
        let bytes = fs::read(f.path.join(ACTIVATION)).unwrap();
        let target = Dir::from_std_file(crate::host_storage::directory(&f.target).unwrap());
        record(&target, "activation-complete.json", &bytes).unwrap();
        let mut marker = f.owner.read().unwrap().unwrap();
        marker.restore_pending = false;
        f.owner.write(&marker).unwrap();
        assert!(f
            .owner
            .activate(ID, &"b".repeat(64), crate::host_runtime::HostMode::Server)
            .is_err());
        f.owner.reconcile_restore(ID, &"b".repeat(64)).unwrap();
        assert!(f.owner.read().unwrap().unwrap().restore_pending);
        assert_eq!(fs::read(f.path.join(ACTIVATION)).unwrap(), bytes);
    }

    #[test]
    fn final_admission_lost_reply_reuses_the_selected_database_without_reselection() {
        let mut f = Fixture::new();
        let proof = f.proof();
        let safety = f.safety();
        f.owner.select_restore(proof, safety.clone()).unwrap();
        let intent = fs::read(f.path.join(ACTIVATION)).unwrap();
        let selected = f.owner.read().unwrap().unwrap().database_reference;
        let recovery = f.path.join("restore-safety").join(OP).join("recovery.json");
        let backup = fs::read(&recovery).unwrap();
        for _ in 0..2 {
            f.owner
                .activate(
                    ID,
                    &"b".repeat(64),
                    crate::host_runtime::HostMode::RestorePrepare,
                )
                .unwrap();
            let proof = f.proof();
            f.owner.finalize_restore(proof, safety.clone()).unwrap();
            assert!(!f.owner.read().unwrap().unwrap().restore_pending);
            assert!(!f.path.join(ACTIVATION).exists());
            assert_eq!(
                f.owner.read().unwrap().unwrap().database_reference,
                selected
            );
            assert_eq!(
                fs::read(f.target.join("activation-intent.json")).unwrap(),
                intent
            );
            assert_eq!(
                fs::read(f.target.join("activation-complete.json")).unwrap(),
                intent
            );
            assert_eq!(fs::read(&recovery).unwrap(), backup);
            safety.verify_readback(&f.owner.root, &f.prepared).unwrap();
        }
        assert_eq!(
            fs::read(f.target.join("activation-intent.json")).unwrap(),
            fs::read(f.target.join("activation-complete.json")).unwrap()
        );
    }

    #[test]
    fn final_admission_refuses_stale_proof_changed_safety_and_conflicting_completion() {
        for mutation in ["generation", "safety", "completion", "media", "target"] {
            let mut f = Fixture::new();
            let proof = f.proof();
            let safety = f.safety();
            f.owner.select_restore(proof, safety.clone()).unwrap();
            f.owner
                .activate(
                    ID,
                    &"b".repeat(64),
                    crate::host_runtime::HostMode::RestorePrepare,
                )
                .unwrap();
            let mut proof = f.proof();
            let before = fs::read(f.path.join(ACTIVATION)).unwrap();
            match mutation {
                "generation" => proof.generation = Uuid::new_v4(),
                "safety" => fs::write(
                    f.path.join("restore-safety").join(OP).join("database.dump"),
                    b"PGDMP corrupt",
                )
                .unwrap(),
                "completion" => {
                    let target =
                        Dir::from_std_file(crate::host_storage::directory(&f.target).unwrap());
                    record(&target, "activation-complete.json", b"{}").unwrap();
                }
                "media" => crate::runtime_store::private_directory(&f.path.join("media")).unwrap(),
                "target" => {
                    fs::write(f.target.join("database/postmaster.pid"), b"untrusted").unwrap()
                }
                _ => unreachable!(),
            }
            assert!(
                f.owner.finalize_restore(proof, safety).is_err(),
                "{mutation}"
            );
            assert_eq!(
                fs::read(f.path.join(ACTIVATION)).unwrap(),
                before,
                "{mutation}"
            );
            assert!(
                f.owner.read().unwrap().unwrap().restore_pending,
                "{mutation}"
            );
            assert!(f
                .owner
                .activate(ID, &"b".repeat(64), crate::host_runtime::HostMode::Server)
                .is_err());
        }
    }

    #[test]
    fn selection_persists_matching_intents_and_retains_originals_under_writer_fence() {
        let mut f = Fixture::new();
        let proof = f.proof();
        let safety = f.safety();
        let generation = f.owner.select_restore(proof, safety).unwrap();
        let marker = f.owner.read().unwrap().unwrap();
        assert_eq!(marker.generation, generation);
        assert_eq!(marker.phase, Phase::Stopped);
        assert_eq!(
            marker.database_reference.unwrap().resolve(&f.path).unwrap(),
            f.target.join("database")
        );
        let bytes = fs::read(f.path.join(ACTIVATION)).unwrap();
        assert_eq!(
            bytes,
            fs::read(f.target.join("activation-intent.json")).unwrap()
        );
        let intent: Intent = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(intent.schema_version, 1);
        assert_eq!(intent.next.generation, generation);
        assert!(intent.previous.database_reference.is_none());
        for (path, expected) in [
            (f.path.join("database/sentinel"), b"original".as_slice()),
            (f.target.join("database/sentinel"), b"prepared"),
            (f.path.join("profile.json"), b"configuration"),
        ] {
            assert_eq!(fs::read(path).unwrap(), expected);
        }
        assert!(f
            .owner
            .activate(ID, &"b".repeat(64), crate::host_runtime::HostMode::Server)
            .is_err());
        f.owner
            .activate(ID, &"b".repeat(64), crate::host_runtime::HostMode::Database)
            .unwrap();
        f.owner.clean_stop().unwrap();
        assert!(fs::read(f.path.join(ACTIVATION)).is_ok());
        fs::remove_file(f.path.join(ACTIVATION)).unwrap();
        assert!(f
            .owner
            .activate(ID, &"b".repeat(64), crate::host_runtime::HostMode::Server)
            .is_err());
    }
    #[test]
    fn stale_proof_changed_target_live_database_and_foreign_safety_have_no_selection_effect() {
        for mutation in ["generation", "target", "pid", "safety"] {
            let mut f = Fixture::new();
            let proof = f.proof();
            let mut safety = f.safety();
            let before = f.owner.read().unwrap();
            match mutation {
                "generation" => {
                    f.owner
                        .activate(
                            ID,
                            &"b".repeat(64),
                            crate::host_runtime::HostMode::RestorePrepare,
                        )
                        .unwrap();
                    f.owner.clean_stop().unwrap();
                }
                "target" => {
                    fs::rename(f.target.join("database"), f.target.join("retained")).unwrap();
                    crate::runtime_store::private_directory(&f.target.join("database")).unwrap();
                }
                "pid" => {
                    fs::write(f.target.join("database/postmaster.pid"), b"never adopted").unwrap()
                }
                _ => {
                    let mut value = serde_json::to_value(&safety).unwrap();
                    value["checkpoint"]["operationId"] = serde_json::json!(ATTEMPT);
                    safety = serde_json::from_value(value).unwrap();
                }
            }
            assert!(f.owner.select_restore(proof, safety).is_err(), "{mutation}");
            assert!(!f.path.join(ACTIVATION).exists());
            if mutation != "generation" {
                assert_eq!(f.owner.read().unwrap(), before);
            }
            assert_eq!(
                fs::read(f.path.join("database/sentinel")).unwrap(),
                b"original"
            );
        }
    }
    #[test]
    fn retained_intent_conflict_leaves_global_fence_before_any_pointer_change() {
        let mut f = Fixture::new();
        let proof = f.proof();
        let safety = f.safety();
        let before = f.owner.read().unwrap();
        fs::write(
            f.target.join("activation-intent.json"),
            b"foreign retained intent",
        )
        .unwrap();
        assert!(f.owner.select_restore(proof, safety).is_err());
        assert!(f.path.join(ACTIVATION).exists());
        assert_eq!(f.owner.read().unwrap(), before);
        assert_eq!(
            fs::read(f.target.join("activation-intent.json")).unwrap(),
            b"foreign retained intent"
        );
        assert!(f
            .owner
            .activate(ID, &"b".repeat(64), crate::host_runtime::HostMode::Server)
            .is_err());
    }
    #[test]
    fn partial_global_intent_is_never_overwritten_or_treated_as_writer_permission() {
        let mut f = Fixture::new();
        let proof = f.proof();
        let safety = f.safety();
        let before = f.owner.read().unwrap();
        fs::write(f.path.join(ACTIVATION), b"{").unwrap();
        assert!(f.owner.select_restore(proof, safety).is_err());
        assert_eq!(fs::read(f.path.join(ACTIVATION)).unwrap(), b"{");
        assert_eq!(f.owner.read().unwrap(), before);
        assert!(!f.target.join("activation-intent.json").exists());
    }
    #[test]
    fn reconcile_recovers_each_publication_boundary_without_admitting_writers() {
        for point in [
            "global-only",
            "retained",
            "selected",
            "torn",
            "empty",
            "missing-global",
            "maintenance-generation",
        ] {
            let mut f = Fixture::new();
            let proof = f.proof();
            let safety = f.safety();
            f.owner.select_restore(proof, safety).unwrap();
            let bytes = fs::read(f.path.join(ACTIVATION)).unwrap();
            let intent: Intent = serde_json::from_slice(&bytes).unwrap();
            match point {
                "global-only" => {
                    fs::remove_file(f.target.join("activation-intent.json")).unwrap();
                    f.owner.write(&intent.previous).unwrap();
                }
                "retained" => f.owner.write(&intent.previous).unwrap(),
                "torn" => inject_journal(&mut f.owner, b"{"),
                "empty" => inject_journal(&mut f.owner, b""),
                "missing-global" => fs::remove_file(f.path.join(ACTIVATION)).unwrap(),
                "maintenance-generation" => {
                    f.owner
                        .activate(ID, &"b".repeat(64), crate::host_runtime::HostMode::Database)
                        .unwrap();
                    f.owner.clean_stop().unwrap();
                }
                _ => {}
            }
            f.owner
                .reconcile_restore(ID, &"b".repeat(64))
                .unwrap()
                .unwrap();
            let selected = f.owner.read().unwrap().unwrap();
            assert!(selected.restore_pending, "{point}");
            assert_eq!(selected.database_reference, intent.next.database_reference);
            assert_eq!(selected.phase, Phase::Stopped);
            assert_eq!(fs::read(f.path.join(ACTIVATION)).unwrap(), bytes);
            assert_eq!(
                fs::read(f.target.join("activation-intent.json")).unwrap(),
                bytes
            );
            f.owner
                .reconcile_restore(ID, &"b".repeat(64))
                .unwrap()
                .unwrap();
            assert_eq!(f.owner.read().unwrap(), Some(selected));
            assert!(f
                .owner
                .activate(ID, &"b".repeat(64), crate::host_runtime::HostMode::Server)
                .is_err());
            assert_eq!(
                fs::read(f.path.join("database/sentinel")).unwrap(),
                b"original"
            );
            assert_eq!(
                fs::read(f.target.join("database/sentinel")).unwrap(),
                b"prepared"
            );
        }
    }
    #[test]
    fn reconcile_refuses_foreign_lineage_live_ownership_changed_directories_and_bad_intents() {
        for mutation in [
            "global",
            "retained",
            "schema",
            "pending",
            "profile",
            "prepared",
            "marker",
            "unknown-field",
            "wrong-type",
            "complete-empty",
            "active",
            "original",
            "database",
            "old-pid",
            "new-pid",
            "lease",
        ] {
            let mut f = Fixture::new();
            let proof = f.proof();
            let safety = f.safety();
            f.owner.select_restore(proof, safety).unwrap();
            let mut held_lease = None;
            match mutation {
                "global" => fs::write(f.path.join(ACTIVATION), b"{").unwrap(),
                "retained" => fs::write(f.target.join("activation-intent.json"), b"{}").unwrap(),
                "schema" | "pending" | "profile" | "prepared" => {
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&fs::read(f.path.join(ACTIVATION)).unwrap())
                            .unwrap();
                    match mutation {
                        "schema" => value["schemaVersion"] = serde_json::json!(2),
                        "pending" => value["next"]["restorePending"] = serde_json::json!(false),
                        "profile" => {
                            value["previous"]["profileIdentity"] = serde_json::json!("0".repeat(64))
                        }
                        _ => value["prepared"]["databaseIdentity"] = serde_json::json!("1:999"),
                    }
                    let bytes = serde_json::to_vec(&value).unwrap();
                    fs::write(f.path.join(ACTIVATION), &bytes).unwrap();
                    fs::write(f.target.join("activation-intent.json"), bytes).unwrap();
                }
                "unknown-field" | "wrong-type" | "complete-empty" => {
                    let mut value = serde_json::to_value(f.owner.read().unwrap().unwrap()).unwrap();
                    match mutation {
                        "unknown-field" => value["futureAuthority"] = serde_json::json!(true),
                        "wrong-type" => value["generation"] = serde_json::json!({"foreign":true}),
                        _ => value = serde_json::json!({}),
                    }
                    inject_journal(&mut f.owner, &serde_json::to_vec(&value).unwrap());
                }
                "marker" | "active" => {
                    let mut marker = f.owner.read().unwrap().unwrap();
                    if mutation == "marker" {
                        marker.installation_id = "f".repeat(12);
                    } else {
                        marker.phase = Phase::Active;
                    }
                    f.owner.write(&marker).unwrap();
                }
                "original" => {
                    fs::rename(f.path.join("database"), f.path.join("old-database")).unwrap();
                    crate::runtime_store::private_directory(&f.path.join("database")).unwrap();
                }
                "database" => {
                    fs::rename(f.target.join("database"), f.target.join("old-database")).unwrap();
                    crate::runtime_store::private_directory(&f.target.join("database")).unwrap();
                }
                "old-pid" => fs::write(f.path.join("database/postmaster.pid"), b"unknown").unwrap(),
                "new-pid" => {
                    fs::write(f.target.join("database/postmaster.pid"), b"unknown").unwrap()
                }
                _ => {
                    let lease = f
                        .owner
                        .root
                        .open_with("lease.lock", &options(false))
                        .unwrap()
                        .into_std();
                    lease.try_lock().unwrap();
                    held_lease = Some(lease);
                }
            }
            let before = journal_bytes(&mut f.owner);
            assert!(
                f.owner.reconcile_restore(ID, &"b".repeat(64)).is_err(),
                "{mutation}"
            );
            assert_eq!(journal_bytes(&mut f.owner), before, "{mutation}");
            assert!(f.path.join(ACTIVATION).exists());
            drop(held_lease);
        }
    }
    #[test]
    fn restore_prepare_admission_reconciles_a_torn_marker_and_preserves_the_writer_fence() {
        let mut f = Fixture::new();
        let proof = f.proof();
        let safety = f.safety();
        f.owner.select_restore(proof, safety).unwrap();
        inject_journal(&mut f.owner, b"{");
        f.owner
            .activate(
                ID,
                &"b".repeat(64),
                crate::host_runtime::HostMode::RestorePrepare,
            )
            .unwrap();
        assert!(f.owner.active.as_ref().unwrap().restore_pending);
        f.owner
            .launch_state(
                &"b".repeat(64),
                crate::host_runtime::HostMode::RestorePrepare,
            )
            .unwrap();
        f.owner.clean_stop().unwrap();
        assert!(f
            .owner
            .activate(ID, &"b".repeat(64), crate::host_runtime::HostMode::Server)
            .is_err());
    }
    #[test]
    fn fresh_proof_acknowledges_an_already_selected_restore_without_replacing_its_fence() {
        for missing_global in [false, true] {
            let mut f = Fixture::new();
            let proof = f.proof();
            let safety = f.safety();
            f.owner.select_restore(proof, safety.clone()).unwrap();
            let bytes = fs::read(f.path.join(ACTIVATION)).unwrap();
            f.owner
                .activate(
                    ID,
                    &"b".repeat(64),
                    crate::host_runtime::HostMode::RestorePrepare,
                )
                .unwrap();
            let proof = f.proof();
            let generation = proof.generation;
            if missing_global {
                fs::remove_file(f.path.join(ACTIVATION)).unwrap();
            }
            assert_eq!(f.owner.select_restore(proof, safety).unwrap(), generation);
            assert_eq!(fs::read(f.path.join(ACTIVATION)).unwrap(), bytes);
            assert_eq!(
                fs::read(f.target.join("activation-intent.json")).unwrap(),
                bytes
            );
            let marker = f.owner.read().unwrap().unwrap();
            assert_eq!(marker.generation, generation);
            assert!(marker.restore_pending);
            assert_eq!(
                fs::read(f.path.join("database/sentinel")).unwrap(),
                b"original"
            );
            assert!(f
                .owner
                .activate(ID, &"b".repeat(64), crate::host_runtime::HostMode::Server)
                .is_err());
        }
    }
    #[test]
    fn selection_retry_rejects_changed_safety_prepared_receipt_and_intent_without_mutation() {
        for mutation in [
            "safety",
            "prepared",
            "intent",
            "generation",
            "pid",
            "lease",
            "target",
        ] {
            let mut f = Fixture::new();
            let proof = f.proof();
            let safety = f.safety();
            f.owner.select_restore(proof, safety.clone()).unwrap();
            f.owner
                .activate(
                    ID,
                    &"b".repeat(64),
                    crate::host_runtime::HostMode::RestorePrepare,
                )
                .unwrap();
            let mut proof = f.proof();
            let mut safety = safety;
            let mut held_lease = None;
            match mutation {
                "safety" => safety.snapshot_id = "9".repeat(64),
                "prepared" => {
                    let mut value = serde_json::to_value(&proof.prepared).unwrap();
                    value["binding"]["snapshotId"] = serde_json::json!("9".repeat(64));
                    proof.prepared = serde_json::from_value(value).unwrap();
                }
                "generation" => proof.generation = Uuid::new_v4(),
                "pid" => fs::write(f.target.join("database/postmaster.pid"), b"unknown").unwrap(),
                "lease" => {
                    let file = f
                        .owner
                        .root
                        .open_with("lease.lock", &options(false))
                        .unwrap()
                        .into_std();
                    file.try_lock().unwrap();
                    held_lease = Some(file);
                }
                "target" => {
                    fs::rename(f.target.join("database"), f.target.join("changed-database"))
                        .unwrap();
                    crate::runtime_store::private_directory(&f.target.join("database")).unwrap();
                }
                _ => fs::write(f.path.join(ACTIVATION), b"{").unwrap(),
            }
            let global = fs::read(f.path.join(ACTIVATION)).unwrap();
            let retained = fs::read(f.target.join("activation-intent.json")).unwrap();
            let marker = journal_bytes(&mut f.owner);
            assert!(f.owner.select_restore(proof, safety).is_err(), "{mutation}");
            assert_eq!(fs::read(f.path.join(ACTIVATION)).unwrap(), global);
            assert_eq!(
                fs::read(f.target.join("activation-intent.json")).unwrap(),
                retained
            );
            assert_eq!(journal_bytes(&mut f.owner), marker);
            drop(held_lease);
        }
    }
    #[test]
    fn missing_safety_readback_cannot_publish_selection() {
        let mut f = Fixture::new();
        let proof = f.proof();
        let safety = f.safety();
        fs::remove_dir_all(f.path.join("restore-safety")).unwrap();
        assert!(f.owner.select_restore(proof, safety).is_err());
        assert!(!f.path.join(ACTIVATION).exists());
    }
    #[test]
    fn corrupt_foreign_linked_or_oversized_safety_artifacts_cannot_publish_selection() {
        for mutation in [
            "dump",
            "json",
            "large-json",
            "inventory",
            "hardlink",
            "library",
            "checkpoint",
            "header",
        ] {
            let mut f = Fixture::new();
            let proof = f.proof();
            let mut safety = f.safety();
            let artifact = f.path.join("restore-safety").join(OP);
            match mutation {
                "dump" => {
                    let mut bytes = fs::read(artifact.join("database.dump")).unwrap();
                    *bytes.last_mut().unwrap() ^= 1;
                    fs::write(artifact.join("database.dump"), bytes).unwrap();
                }
                "json" => fs::write(artifact.join("recovery.json"), b"{}").unwrap(),
                "large-json" => {
                    fs::write(artifact.join("recovery.json"), vec![b' '; 4097]).unwrap()
                }
                "inventory" => fs::write(artifact.join("foreign"), b"preserve").unwrap(),
                "hardlink" => {
                    fs::hard_link(artifact.join("database.dump"), f.path.join("linked.dump"))
                        .unwrap()
                }
                _ => {
                    let mut recovery: serde_json::Value =
                        serde_json::from_slice(&fs::read(artifact.join("recovery.json")).unwrap())
                            .unwrap();
                    if mutation == "library" {
                        recovery["libraryId"] = serde_json::json!("0".repeat(12));
                    } else if mutation == "checkpoint" {
                        recovery["checkpoint"]["sourceRevision"] =
                            serde_json::json!("0".repeat(40));
                    } else {
                        let mut dump = fs::read(artifact.join("database.dump")).unwrap();
                        dump[0] = b'X';
                        fs::write(artifact.join("database.dump"), &dump).unwrap();
                        recovery["checkpoint"]["dump"]["sha256"] =
                            serde_json::json!(format!("{:x}", Sha256::digest(&dump)));
                        let mut checkpoint = serde_json::to_value(&safety.checkpoint).unwrap();
                        checkpoint["dump"] = recovery["checkpoint"]["dump"].clone();
                        safety.checkpoint = serde_json::from_value(checkpoint).unwrap();
                    }
                    let bytes = serde_json::to_vec(&recovery).unwrap();
                    safety.recovery_sha256 = format!("{:x}", Sha256::digest(&bytes));
                    fs::write(artifact.join("recovery.json"), bytes).unwrap();
                }
            }
            let before = f.owner.read().unwrap();
            assert!(f.owner.select_restore(proof, safety).is_err(), "{mutation}");
            assert!(!f.path.join(ACTIVATION).exists(), "{mutation}");
            assert_eq!(f.owner.read().unwrap(), before);
        }
    }
    #[cfg(unix)]
    #[test]
    fn linked_or_nonprivate_safety_paths_never_follow_originals_or_select_a_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        for mutation in ["root-link", "file-link", "root-mode", "file-mode"] {
            let mut f = Fixture::new();
            let proof = f.proof();
            let safety = f.safety();
            let root = f.path.join("restore-safety");
            let artifact = root.join(OP);
            match mutation {
                "root-link" => {
                    fs::rename(&root, f.path.join("retained-safety")).unwrap();
                    symlink(f.path.join("retained-safety"), &root).unwrap();
                }
                "file-link" => {
                    fs::rename(artifact.join("database.dump"), f.path.join("saved.dump")).unwrap();
                    symlink(f.path.join("saved.dump"), artifact.join("database.dump")).unwrap();
                }
                "root-mode" => {
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap()
                }
                _ => fs::set_permissions(
                    artifact.join("database.dump"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap(),
            }
            assert!(f.owner.select_restore(proof, safety).is_err(), "{mutation}");
            assert!(!f.path.join(ACTIVATION).exists());
        }
    }
    #[test]
    fn safety_reader_accepts_actual_manager_serialization_and_rejects_sorted_key_replacement() {
        let mut f = Fixture::new();
        let proof = f.proof();
        let mut safety = f.safety();
        // Generated by Manager createNativeRecovery + digest, including its original JSON field order.
        let bytes = include_bytes!("activation/manager-safety-recovery.fixture.json");
        safety.recovery_sha256 =
            "caed8986d0779a8c2aed955d68d2767055e6c577acfb74831da8915c1ba124fd".into();
        let path = f.path.join("restore-safety").join(OP).join("recovery.json");
        fs::write(&path, bytes).unwrap();
        f.owner.select_restore(proof, safety.clone()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        f.owner
            .activate(
                ID,
                &"b".repeat(64),
                crate::host_runtime::HostMode::RestorePrepare,
            )
            .unwrap();
        let fresh = f.proof();
        assert!(f.owner.select_restore(fresh, safety).is_err());
        assert!(f.path.join(ACTIVATION).exists());
    }
    #[test]
    fn media_root_replacement_stops_reconciliation_without_changing_the_fence() {
        for mutation in ["replace", "missing"] {
            let mut f = Fixture::new();
            let media = f.path.join("media");
            crate::runtime_store::private_directory(&media).unwrap();
            let proof = f.proof();
            let safety = f.safety();
            f.owner.select_restore(proof, safety).unwrap();
            let fence = std::fs::read(f.path.join(ACTIVATION)).unwrap();
            let marker = f.owner.read().unwrap();
            std::fs::rename(&media, f.path.join("retained-media")).unwrap();
            if mutation == "replace" {
                crate::runtime_store::private_directory(&media).unwrap();
            }
            assert!(
                f.owner.reconcile_restore(ID, &"b".repeat(64)).is_err(),
                "{mutation}"
            );
            assert_eq!(f.owner.read().unwrap(), marker);
            assert_eq!(std::fs::read(f.path.join(ACTIVATION)).unwrap(), fence);
        }
    }
    #[test]
    fn absent_media_is_bound_and_unchanged_media_can_resume() {
        for present in [false, true] {
            let mut f = Fixture::new();
            if present {
                crate::runtime_store::private_directory(&f.path.join("media")).unwrap();
            }
            let proof = f.proof();
            let safety = f.safety();
            let generation = f.owner.select_restore(proof, safety).unwrap();
            assert_eq!(
                f.owner.reconcile_restore(ID, &"b".repeat(64)).unwrap(),
                Some(generation)
            );
            if !present {
                crate::runtime_store::private_directory(&f.path.join("media")).unwrap();
                assert!(f.owner.reconcile_restore(ID, &"b".repeat(64)).is_err());
            }
        }
    }
    #[cfg(unix)]
    #[test]
    fn media_links_are_refused_before_selection_changes() {
        use std::os::unix::fs::symlink;
        let mut f = Fixture::new();
        let alternate = f.path.join("alternate-media");
        crate::runtime_store::private_directory(&alternate).unwrap();
        symlink(&alternate, f.path.join("media")).unwrap();
        let proof = f.proof();
        let safety = f.safety();
        let before = f.owner.read().unwrap();
        assert!(f.owner.select_restore(proof, safety).is_err());
        assert_eq!(f.owner.read().unwrap(), before);
        assert!(!f.path.join(ACTIVATION).exists());
    }
}

#[cfg(test)]
mod restore_qualification;
