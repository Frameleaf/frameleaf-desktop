//! Selection stays fenced until independent finalization admits writers.
use super::*;
use crate::host_runtime::{CheckpointReceipt, PreparedRestore, VerifiedRestore};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SafetySnapshot {
    snapshot_id: String,
    recovery_sha256: String,
    checkpoint: CheckpointReceipt,
}
impl SafetySnapshot {
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
    prepared: PreparedRestore,
    verification_id: String,
    safety: SafetySnapshot,
}
fn sync_directory(root: &Dir) -> Result<(), String> {
    #[cfg(unix)]
    root.try_clone()
        .and_then(|root| root.into_std_file().sync_all())
        .map_err(|_| "host_restore_activation_write_failed")?;
    #[cfg(not(unix))]
    let _ = root;
    Ok(())
}
fn record(root: &Dir, name: &str, bytes: &[u8]) -> Result<(), String> {
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
impl Owner {
    pub(crate) fn select_restore(
        &mut self,
        proof: VerifiedRestore,
        safety: SafetySnapshot,
    ) -> Result<Uuid, String> {
        if self.active.is_some() || !self.writable {
            return Err("host_restore_proof_invalid".into());
        }
        no_activation(&self.root)?;
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
        let host_lease = self
            .root
            .open_with("lease.lock", &options(false))
            .map_err(|_| "host_process_state_requires_review")?
            .into_std();
        valid_file(&host_lease)?;
        host_lease.try_lock().map_err(|_| "host_already_owned")?;
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
        // Publish and sync the global writer fence before any selection change.
        record(&self.root, ACTIVATION, &bytes)?;
        let target = proof.reference.target_directory(&self.path)?;
        record(&target, "activation-intent.json", &bytes)?;
        proof.reference.resolve(&self.path)?;
        if database_identity(&database)? != intent.previous_database_identity
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
            serde_json::from_value(serde_json::json!({"snapshotId":"1".repeat(64),"recoverySha256":"2".repeat(64),
                "checkpoint":{"schemaVersion":1,"operationId":OP,"manifestSha256":"b".repeat(64),"sourceRevision":"d".repeat(40),"postgresMajor":"19","databaseFormat":"frameleaf-canonical","dump":{"bytes":27,"sha256":"3".repeat(64)}}})).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
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
}
