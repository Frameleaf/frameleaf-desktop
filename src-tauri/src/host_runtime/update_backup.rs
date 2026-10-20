//! Bounded encrypted-backup readback; optional staging owns its private output file.
use super::*;
use std::{
    ffi::OsString,
    io::{Read, Write},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
const BAD: &str = "host_update_backup_invalid";
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Installation {
    id: String,
    name: String,
    release: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Recovery {
    schema_version: u32,
    runtime: String,
    media_included: bool,
    database_format: String,
    library_id: String,
    created_at: u64,
    installation: Installation,
    checkpoint: ApprovalCheckpoint,
}
struct StreamProof {
    bytes: u64,
    sha256: String,
    header: [u8; 5],
    captured: Vec<u8>,
}
struct BackupReader<'a> {
    executable: &'a Path,
    repository: &'a Path,
    key: &'a str,
    cancel: &'a AtomicBool,
    lease: Option<&'a crate::package_lease::CodeLease>,
    deadline: Instant,
}
impl BackupReader<'_> {
    fn read(&self, args: &[&str], limit: u64, capture: bool) -> Result<StreamProof, String> {
        self.read_to(args, limit, capture, None)
    }
    fn read_to(
        &self,
        args: &[&str],
        limit: u64,
        capture: bool,
        mut sink: Option<std::fs::File>,
    ) -> Result<StreamProof, String> {
        if !crate::manager_profile::valid_backup_key(self.key)
            || (capture && sink.is_some())
            || (capture && limit > 65536)
            || self.cancel.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
        {
            return Err(BAD.into());
        }
        let mut repository = OsString::from("local:");
        repository.push(self.repository);
        let mut command = Command::new(self.executable);
        command
            .args([OsString::from("--repo"), repository])
            .args(["--no-cache", "--no-lock", "--quiet"])
            .args(args)
            .env_clear()
            .env("PATH", "")
            .env("GOMAXPROCS", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        crate::process_tree::configure(&mut command);
        #[cfg(unix)]
        if let Some(lease) = self.lease {
            lease.inherit(&mut command);
        }
        #[cfg(not(unix))]
        let _ = self.lease;
        let mut child = command.spawn().map_err(|_| BAD)?;
        let tree = match crate::process_tree::ProcessTree::attach(&child) {
            Ok(tree) => tree,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BAD.into());
            }
        };
        let stdout = child.stdout.take().ok_or(BAD);
        let (tx, rx) = mpsc::sync_channel(1);
        let reader = stdout.and_then(|mut pipe| {
            std::thread::Builder::new()
                .name("update-backup-read".into())
                .spawn(move || {
                    let result = (|| {
                        let mut bytes = 0u64;
                        let mut hash = Sha256::new();
                        let mut header = [0; 5];
                        let mut captured = Vec::new();
                        let mut buffer = [0; 65536];
                        loop {
                            let n = pipe.read(&mut buffer).map_err(|_| BAD)?;
                            if n == 0 {
                                break;
                            }
                            if (n as u64) > limit.saturating_sub(bytes) {
                                return Err(BAD.to_owned());
                            }
                            if bytes < 5 {
                                let count = (5 - bytes as usize).min(n);
                                header[bytes as usize..bytes as usize + count]
                                    .copy_from_slice(&buffer[..count]);
                            }
                            if let Some(file) = &mut sink {
                                file.write_all(&buffer[..n]).map_err(|_| BAD)?;
                            }
                            hash.update(&buffer[..n]);
                            if capture {
                                captured.extend_from_slice(&buffer[..n]);
                            }
                            bytes += n as u64;
                        }
                        if let Some(file) = &sink {
                            file.sync_all().map_err(|_| BAD)?;
                        }
                        Ok(StreamProof {
                            bytes,
                            sha256: format!("{:x}", hash.finalize()),
                            header,
                            captured,
                        })
                    })();
                    let _ = tx.send(result);
                })
                .map_err(|_| BAD)
        });
        let reader = match reader {
            Ok(reader) => reader,
            Err(_) => {
                tree.terminate();
                let _ = child.wait();
                return Err(BAD.into());
            }
        };
        let mut reaped = false;
        let result = (|| {
            // The engine cannot receive its key until process ownership and its bounded reader exist.
            let key = zeroize::Zeroizing::new(format!("{}\n", self.key));
            child
                .stdin
                .take()
                .ok_or(BAD)?
                .write_all(key.as_bytes())
                .map_err(|_| BAD)?;
            let mut output = None;
            loop {
                if self.cancel.load(Ordering::Acquire) || Instant::now() >= self.deadline {
                    return Err(BAD.to_owned());
                }
                if output.is_none() {
                    match rx.recv_timeout(Duration::from_millis(20)) {
                        Ok(value) => output = Some(value?),
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(_) => return Err(BAD.to_owned()),
                    }
                }
                // Reap only after stdout closes. Until then the unreaped leader pins the process-group ID for safe cancellation.
                if let Some(status) = child.try_wait().map_err(|_| BAD)? {
                    reaped = true;
                    return if status.success() {
                        output.take().ok_or_else(|| BAD.into())
                    } else {
                        Err(BAD.into())
                    };
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        })();
        if !reaped {
            tree.terminate();
            if child.wait().is_err() {
                let _ = reader.join();
                return Err(BAD.into());
            }
        }
        if reader.join().is_err() {
            return Err(BAD.into());
        }
        result
    }
}
fn snapshot(value: &serde_json::Value, payload: &Payload) -> Result<(), String> {
    let tags = value["tags"].as_array().ok_or(BAD)?;
    let expected = [
        "frameleaf-manager-database",
        "frameleaf-canonical",
        payload.backup_operation_id.as_str(),
    ];
    if value["id"].as_str() != Some(payload.snapshot_id.as_str())
        || tags.len() != 3
        || expected
            .iter()
            .any(|tag| tags.iter().filter(|v| v.as_str() == Some(*tag)).count() != 1)
    {
        return Err(BAD.into());
    }
    Ok(())
}
pub(in crate::host_runtime) fn recovery(
    bytes: &[u8],
    payload: &Payload,
    config: &Configuration,
) -> Result<(), String> {
    let value: Recovery = serde_json::from_slice(bytes).map_err(|_| BAD)?;
    if value.schema_version != 1
        || value.runtime != "native"
        || value.media_included
        || value.database_format != "frameleaf-canonical"
        || value.library_id != payload.library_id
        || value.created_at > MAX_SAFE
        || value.installation.id != payload.installation_id
        || value.installation.name != config.name.trim()
        || value.installation.release != config.release
        || serde_json::to_vec(&value.checkpoint).map_err(|_| BAD)?
            != serde_json::to_vec(&payload.checkpoint).map_err(|_| BAD)?
        || format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&value).map_err(|_| BAD)?)
        ) != payload.recovery_sha256
    {
        return Err(BAD.into());
    }
    Ok(())
}
fn repository(config: &Configuration) -> Result<Vec<(std::path::PathBuf, String)>, String> {
    [
        config.data.clone(),
        config.data.join("backups"),
        config.data.join("backups/frameleaf-database"),
    ]
    .into_iter()
    .map(|path| {
        crate::host_setup::require_leaf(&path)?;
        let root = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&path)?);
        let id = crate::copy_source::root_identity(&root)?;
        Ok((path, id))
    })
    .collect()
}
fn read_backup(
    reader: &BackupReader<'_>,
    config: &Configuration,
    payload: &Payload,
) -> Result<(), String> {
    read_backup_to(reader, config, payload, None).map(|_| ())
}
fn read_backup_to(
    reader: &BackupReader<'_>,
    config: &Configuration,
    payload: &Payload,
    sink: Option<std::fs::File>,
) -> Result<Vec<u8>, String> {
    let roots = repository(config)?;
    if roots.last().map(|v| v.0.as_path()) != Some(reader.repository) {
        return Err(BAD.into());
    }
    let snapshots = reader.read(&["snapshots", "--json", &payload.snapshot_id], 65536, true)?;
    let values: Vec<serde_json::Value> =
        serde_json::from_slice(&snapshots.captured).map_err(|_| BAD)?;
    if values.len() != 1 {
        return Err(BAD.into());
    }
    snapshot(&values[0], payload)?;
    let list = reader.read(&["ls", "--json", &payload.snapshot_id], 65536, true)?;
    let text = std::str::from_utf8(&list.captured).map_err(|_| BAD)?;
    let nodes = text
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).map_err(|_| BAD))
        .collect::<Result<Vec<_>, _>>()?;
    if nodes.len() != 3 || nodes[0]["message_type"] != "snapshot" {
        return Err(BAD.into());
    }
    snapshot(&nodes[0], payload)?;
    let mut files = std::collections::BTreeMap::new();
    for node in &nodes[1..] {
        let name = node["name"].as_str().ok_or(BAD)?;
        if node["message_type"] != "node"
            || node["type"] != "file"
            || node["path"].as_str() != Some(format!("/{name}").as_str())
            || !matches!(name, "database.dump" | "recovery.json")
            || files
                .insert(name, node["size"].as_u64().ok_or(BAD)?)
                .is_some()
        {
            return Err(BAD.into());
        }
    }
    if files.get("database.dump") != Some(&payload.checkpoint.dump.bytes)
        || !files
            .get("recovery.json")
            .is_some_and(|n| *n > 0 && *n <= 4096)
    {
        return Err(BAD.into());
    }
    let raw = reader.read(
        &["dump", &payload.snapshot_id, "/recovery.json"],
        4096,
        true,
    )?;
    if files["recovery.json"] != raw.bytes {
        return Err(BAD.into());
    }
    recovery(&raw.captured, payload, config)?;
    let dump = reader.read_to(
        &["dump", &payload.snapshot_id, "/database.dump"],
        payload.checkpoint.dump.bytes,
        false,
        sink,
    )?;
    if dump.bytes != payload.checkpoint.dump.bytes
        || dump.sha256 != payload.checkpoint.dump.sha256
        || &dump.header != b"PGDMP"
    {
        return Err(BAD.into());
    }
    if repository(config)? != roots {
        return Err(BAD.into());
    }
    Ok(raw.captured)
}
impl VerifiedHostRuntime {
    /// Only an admitted controller context supplies the newly created private sink.
    pub(in crate::host_runtime) fn stage_update_backup_held(
        &self,
        config: &Configuration,
        payload: &Payload,
        key: &str,
        cancel: &AtomicBool,
        deadline: Instant,
        sink: std::fs::File,
    ) -> Result<Vec<u8>, String> {
        let lease = crate::package_lease::CodeLease::acquire(self.root.parent().ok_or(BAD)?)?;
        let engine = self.backup_engine()?;
        let repo = config.data.join("backups/frameleaf-database");
        let reader = BackupReader {
            executable: &engine.executable,
            repository: &repo,
            key,
            cancel,
            lease: Some(&lease),
            deadline,
        };
        read_backup_to(&reader, config, payload, Some(sink))
    }

    /// Caller holds admitted update context; this helper never enters installation credentials.
    pub(in crate::host_runtime) fn read_update_backup_held(
        &self,
        config: &Configuration,
        payload: &Payload,
        key: &str,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<(), String> {
        let source = self.root.parent().ok_or(BAD)?;
        let lease = crate::package_lease::CodeLease::acquire(source)?;
        let engine = self.backup_engine()?;
        let repo = config.data.join("backups/frameleaf-database");
        let reader = BackupReader {
            executable: &engine.executable,
            repository: &repo,
            key,
            cancel,
            lease: Some(&lease),
            deadline,
        };
        read_backup(&reader, config, payload)
    }
    /// Independently decrypt and hash the consumed safety backup. No database execution or apply authority.
    pub fn verify_update_backup(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
    ) -> Result<HostUpdateApproval, String> {
        self.verify_update_backup_with(
            target,
            [source, destination],
            execution,
            cancel,
            &mut crate::manager_profile::Keystore,
        )
    }
    pub(in crate::host_runtime) fn verify_update_backup_with(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateApproval, String> {
        if cancel.load(Ordering::Acquire) {
            return Err(BAD.into());
        }
        let deadline = Instant::now() + Duration::from_secs(7200);
        let mut proof = self.with_update_approval(
            target,
            profiles,
            execution,
            None,
            super::consumption::clock,
            store,
            |payload, key| {
                self.read_update_backup_held(profiles[0], payload, key, cancel, deadline)
            },
        )?;
        if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(BAD.into());
        }
        proof.state = "backup-verified";
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/native-update-recovery.json"
        ))
        .unwrap()
    }
    fn payload() -> Payload {
        let mut value: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/native-update-approval.json"
        ))
        .unwrap();
        let f = fixture();
        value["payload"]["checkpoint"] = f["recovery"]["checkpoint"].clone();
        value["payload"]["recoverySha256"] = f["sha256"].clone();
        serde_json::from_value(value["payload"].clone()).unwrap()
    }
    fn config(data: std::path::PathBuf) -> Configuration {
        Configuration {
            installation_id: "aaaaaaaaaaaa".into(),
            secure_installation_id: "11111111-1111-4111-8111-111111111111".into(),
            name: "Synthetic update readback".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: std::env::current_exe().unwrap(),
            state: data.with_extension("state"),
            data,
            origin: "https://127.0.0.1:9443".into(),
            database_port: 54329,
            api_port: 2283,
        }
    }
    struct Root(std::path::PathBuf);
    impl Root {
        fn new() -> Self {
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "frameleaf-update-readback-{}",
                uuid::Uuid::new_v4()
            ));
            crate::runtime_store::private_directory(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn node_recovery_digest_matches_strict_rust_field_order_and_refuses_rebound_bad_metadata() {
        let f = fixture();
        let p = payload();
        let c = config("/unused".into());
        recovery(f["raw"].as_str().unwrap().as_bytes(), &p, &c).unwrap();
        for field in [
            "schemaVersion",
            "runtime",
            "mediaIncluded",
            "libraryId",
            "installation",
            "checkpoint",
            "unknown",
        ] {
            let mut value = f["recovery"].clone();
            value[field] = serde_json::json!(null);
            let raw = serde_json::to_vec(&value).unwrap();
            let mut p = payload();
            p.recovery_sha256 = format!("{:x}", Sha256::digest(&raw));
            assert!(recovery(&raw, &p, &c).is_err(), "accepted {field}");
        }
        let raw = f["raw"].as_str().unwrap().replace(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
        );
        assert!(recovery(raw.as_bytes(), &p, &c).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn bounded_reader_kills_reaps_and_joins_on_overflow_timeout_cancellation_and_nonzero_exit() {
        use std::os::unix::fs::PermissionsExt;
        for mode in ["overflow", "timeout", "cancel", "failure"] {
            let root = Root::new();
            let script = root.0.join("engine");
            let body = match mode {
                "overflow" => "while :; do printf 0123456789; done",
                "failure" => "exit 1",
                _ => "/bin/sleep 10",
            };
            fs::write(&script, format!("#!/bin/sh\nread key\n{body}\n")).unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
            let cancel = std::sync::Arc::new(AtomicBool::new(false));
            let flag = cancel.clone();
            let cancel_thread = (mode == "cancel").then(|| {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(40));
                    flag.store(true, Ordering::Release);
                })
            });
            let start = Instant::now();
            let reader = BackupReader {
                executable: &script,
                repository: &root.0,
                key: "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk",
                cancel: &cancel,
                lease: None,
                deadline: start + Duration::from_millis(if mode == "timeout" { 40 } else { 2000 }),
            };
            assert!(reader.read(&["dump"], 4, false).is_err(), "accepted {mode}");
            assert!(start.elapsed() < Duration::from_secs(3));
            if let Some(thread) = cancel_thread {
                thread.join().unwrap();
            }
        }
    }
    #[cfg(unix)]
    #[test]
    fn update_backup_sink_is_bounded_synced_and_refuses_process_or_write_failures() {
        use std::os::unix::fs::PermissionsExt;
        for mode in ["ok", "overflow", "failure", "readonly"] {
            let root = Root::new();
            let script = root.0.join("engine");
            fs::write(
                &script,
                format!(
                    "#!/bin/sh\nread key\nprintf PGDMPdata\n{}\n",
                    if mode == "failure" {
                        "exit 1"
                    } else {
                        "exit 0"
                    }
                ),
            )
            .unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
            let path = root.0.join("dump");
            let sink = if mode == "readonly" {
                fs::write(&path, b"").unwrap();
                fs::File::open(&path).unwrap()
            } else {
                fs::File::create(&path).unwrap()
            };
            let cancel = AtomicBool::new(false);
            let reader = BackupReader {
                executable: &script,
                repository: &root.0,
                key: "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk",
                cancel: &cancel,
                lease: None,
                deadline: Instant::now() + Duration::from_secs(2),
            };
            let result = reader.read_to(
                &["dump"],
                if mode == "overflow" { 4 } else { 9 },
                false,
                Some(sink),
            );
            assert_eq!(result.is_ok(), mode == "ok", "{mode}");
            if let Ok(proof) = result {
                assert_eq!(proof.bytes, 9);
                assert_eq!(&proof.header, b"PGDMP");
                assert_eq!(fs::read(path).unwrap(), b"PGDMPdata");
                assert!(proof.captured.is_empty());
            }
        }
    }
    fn inventory(path: &Path) -> std::collections::BTreeMap<std::path::PathBuf, String> {
        fn walk(
            root: &Path,
            path: &Path,
            files: &mut std::collections::BTreeMap<std::path::PathBuf, String>,
        ) {
            for entry in fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, files);
                } else {
                    files.insert(
                        path.strip_prefix(root).unwrap().to_owned(),
                        format!("{:x}", Sha256::digest(fs::read(&path).unwrap())),
                    );
                }
            }
        }
        let mut files = std::collections::BTreeMap::new();
        walk(path, path, &mut files);
        files
    }
    fn actual_backup_fixture() -> (Root, Configuration, Payload, std::path::PathBuf) {
        let executable = std::path::PathBuf::from(
            std::env::var_os("FRAMELEAF_TEST_RESTIC").expect("pinned restic"),
        );
        assert!(executable.is_absolute());
        let pins: serde_json::Value =
            serde_json::from_str(include_str!("../../../runtime/host-backup.json")).unwrap();
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            other => other,
        };
        let arch = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => other,
        };
        assert_eq!(
            format!("{:x}", Sha256::digest(fs::read(&executable).unwrap())),
            pins["artifacts"][format!("{os}_{arch}")]["binarySha256"]
                .as_str()
                .unwrap()
        );
        let root = Root::new();
        let c = config(root.0.join("manager"));
        let repo = c.data.join("backups/frameleaf-database");
        for path in [&c.data, &c.data.join("backups"), &repo] {
            crate::runtime_store::private_directory(path).unwrap();
        }
        let cancel = AtomicBool::new(false);
        let reader = BackupReader {
            executable: &executable,
            repository: &repo,
            key: "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk",
            cancel: &cancel,
            lease: None,
            deadline: Instant::now() + Duration::from_secs(60),
        };
        reader.read(&["init"], 65536, true).unwrap();
        let f = fixture();
        let checkpoint = root.0.join("checkpoint");
        crate::runtime_store::private_directory(&checkpoint).unwrap();
        fs::write(
            checkpoint.join("database.dump"),
            f["dump"].as_str().unwrap(),
        )
        .unwrap();
        fs::write(checkpoint.join("recovery.json"), f["raw"].as_str().unwrap()).unwrap();
        let mut child = Command::new(&executable)
            .args([
                "--repo",
                repo.to_str().unwrap(),
                "--no-cache",
                "--quiet",
                "backup",
                "--tag",
                "frameleaf-manager-database",
                "--tag",
                "frameleaf-canonical",
                "--tag",
                "33333333-3333-4333-8333-333333333333",
                ".",
            ])
            .current_dir(&checkpoint)
            .env_clear()
            .env("PATH", "")
            .env("GOMAXPROCS", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk\n")
            .unwrap();
        assert!(child.wait().unwrap().success());
        let snapshots = reader.read(&["snapshots", "--json"], 65536, true).unwrap();
        let snapshots: Vec<serde_json::Value> =
            serde_json::from_slice(&snapshots.captured).unwrap();
        let mut p = payload();
        p.snapshot_id = snapshots[0]["id"].as_str().unwrap().into();
        (root, c, p, executable)
    }
    #[test]
    #[ignore = "requires explicit digest-pinned restic executable; synthetic encrypted fixture only, no installed or OS-store claim"]
    fn actual_pinned_restic_decrypts_exact_update_backup_without_repository_or_plaintext_writes() {
        let (root, c, mut p, executable) = actual_backup_fixture();
        let repo = c.data.join("backups/frameleaf-database");
        let cancel = AtomicBool::new(false);
        let reader = BackupReader {
            executable: &executable,
            repository: &repo,
            key: "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk",
            cancel: &cancel,
            lease: None,
            deadline: Instant::now() + Duration::from_secs(60),
        };
        let before = inventory(&repo);
        read_backup(&reader, &c, &p).unwrap();
        assert_eq!(inventory(&repo), before);
        let wrong = BackupReader {
            key: "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj",
            ..reader
        };
        assert!(read_backup(&wrong, &c, &p).is_err());
        let expected = p.checkpoint.dump.sha256.clone();
        p.checkpoint.dump.sha256 = "0".repeat(64);
        assert!(read_backup(&reader, &c, &p).is_err());
        p.checkpoint.dump.sha256 = expected;
        assert!(reader
            .read(
                &["dump", &p.snapshot_id, "/database.dump"],
                p.checkpoint.dump.bytes - 1,
                false
            )
            .is_err());
        p.recovery_sha256 = "0".repeat(64);
        assert!(read_backup(&reader, &c, &p).is_err());
        assert_eq!(inventory(&repo), before);
        assert_eq!(
            fs::read_dir(&root.0).unwrap().count(),
            2,
            "readback created plaintext/cache outputs"
        );
    }
    #[test]
    #[ignore = "requires explicit digest-pinned restic executable; synthetic private file staging, no installed or OS-store claim"]
    fn actual_pinned_restic_streams_update_dump_into_private_file_without_repository_mutation() {
        let (root, c, p, executable) = actual_backup_fixture();
        let repo = c.data.join("backups/frameleaf-database");
        let before = inventory(&repo);
        let dir = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&root.0).unwrap());
        let mut opts = crate::host_state::options(true);
        opts.create_new(true);
        let sink = dir.open_with("staged.dump", &opts).unwrap().into_std();
        crate::host_state::valid_file(&sink).unwrap();
        let cancel = AtomicBool::new(false);
        let reader = BackupReader {
            executable: &executable,
            repository: &repo,
            key: "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk",
            cancel: &cancel,
            lease: None,
            deadline: Instant::now() + Duration::from_secs(60),
        };
        let raw = read_backup_to(&reader, &c, &p, Some(sink)).unwrap();
        assert_eq!(raw, fixture()["raw"].as_str().unwrap().as_bytes());
        let dump = fs::read(root.0.join("staged.dump")).unwrap();
        assert_eq!(dump.len() as u64, p.checkpoint.dump.bytes);
        assert_eq!(
            format!("{:x}", Sha256::digest(&dump)),
            p.checkpoint.dump.sha256
        );
        assert_eq!(dump, fixture()["dump"].as_str().unwrap().as_bytes());
        assert_eq!(inventory(&repo), before);
        let file = crate::copy_source::staged_file(&dir, Path::new("staged.dump"))
            .unwrap()
            .into_std();
        crate::host_state::valid_sized_file(&file, p.checkpoint.dump.bytes).unwrap();
    }
}
