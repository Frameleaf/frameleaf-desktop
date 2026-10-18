//! Private owner-pipe bridge for Manager. No listener, server token, shell command or PID authority.
use crate::{native_runtime, release_policy};
use serde::Deserialize;
use serde_json::json;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    protocol_version: u32,
    #[serde(default)]
    mode: crate::host_runtime::HostMode,
    installation_id: String,
    candidate: PathBuf,
    state: PathBuf,
    manifest_sha256: String,
    password: String,
    database_port: u16,
    api_port: u16,
}
impl Drop for Config {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
fn config(raw: &[u8]) -> Result<Config, String> {
    let config: Config = serde_json::from_slice(raw).map_err(|_| "host_control_config_invalid")?;
    if config.protocol_version != 1
        || !native_runtime::digest_valid(&config.installation_id, 12)
        || [&config.candidate, &config.state].iter().any(|path| {
            !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                || (cfg!(windows)
                    && path
                        .as_os_str()
                        .to_string_lossy()
                        .split(['\\', '/'])
                        .any(|part| part == ".."))
        })
        || !native_runtime::digest_valid(&config.manifest_sha256, 64)
        || !(24..=512).contains(&config.password.len())
        || config.password.contains(['\r', '\n', '\0'])
        || config.database_port == 0
        || config.api_port == 0
        || config.database_port == config.api_port
    {
        return Err("host_control_config_invalid".into());
    }
    Ok(config)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inspection {
    protocol_version: u32,
    installation_id: String,
    candidate: PathBuf,
    state: PathBuf,
    manifest_sha256: String,
}
fn physical_id(path: &Path) -> Result<String, String> {
    let directory = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(path)?);
    crate::copy_source::root_identity(&directory)
        .map_err(|_| "host_profile_identity_unavailable".into())
}
pub(crate) fn separate_paths(candidate: &Path, state: &Path) -> Result<(), String> {
    // Compare physical directory identities too: case aliases cannot bypass payload/state separation.
    let candidate_id = physical_id(candidate)?;
    let existing = if state.exists() {
        state
    } else {
        state.parent().ok_or("host_control_config_invalid")?
    };
    for ancestor in existing.ancestors() {
        if physical_id(ancestor)? == candidate_id {
            return Err("host_state_overlaps_runtime".into());
        }
    }
    if state.exists() {
        let state_id = physical_id(state)?;
        for ancestor in candidate.ancestors() {
            if physical_id(ancestor)? == state_id {
                return Err("host_state_overlaps_runtime".into());
            }
        }
    }
    Ok(())
}
fn verify_candidate(
    candidate: &Path,
    expected: &str,
) -> Result<crate::host_runtime::VerifiedHostRuntime, String> {
    native_runtime::absolute_directory(candidate)?;
    let raw = candidate_file(&candidate.join("manifest.json"), 16 * 1024 * 1024)?;
    let signature: [u8; 64] = candidate_file(&candidate.join("manifest.sig"), 64)?
        .try_into()
        .map_err(|_| "host_control_candidate_invalid")?;
    let runtime =
        release_policy::verify_host_runtime(&candidate.join("payload"), &raw, &signature)?;
    if runtime.manifest_sha256() != expected {
        return Err("host_control_candidate_changed".into());
    }
    Ok(runtime)
}

pub fn inspect_owner() -> Result<(), String> {
    let raw = line(&mut BufReader::new(std::io::stdin()), 16 * 1024)
        .map_err(|_| "host_control_config_invalid")?;
    let request: Inspection =
        serde_json::from_slice(&raw).map_err(|_| "host_control_config_invalid")?;
    if request.protocol_version != 1
        || !native_runtime::digest_valid(&request.installation_id, 12)
        || !native_runtime::digest_valid(&request.manifest_sha256, 64)
        || [&request.candidate, &request.state].iter().any(|path| {
            !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                || (cfg!(windows)
                    && path
                        .as_os_str()
                        .to_string_lossy()
                        .split(['\\', '/'])
                        .any(|part| part == ".."))
        })
    {
        return Err("host_control_config_invalid".into());
    }
    separate_paths(&request.candidate, &request.state)?;
    let mut owner = crate::host_state::Owner::acquire(&request.state, false)?;
    let runtime = verify_candidate(&request.candidate, &request.manifest_sha256)?;
    let marker = owner.inspect(&request.installation_id, &request.manifest_sha256)?;
    emit(
        json!({"protocolVersion":1,"state":"quiescent","installationId":marker.installation_id,
        "manifestSha256":runtime.manifest_sha256(),"sourceRevision":runtime.source_revision(),
        "certified":runtime.certified(),"profileIdentity":marker.profile_identity,"generation":marker.generation}),
    )
}

fn line(reader: &mut impl BufRead, limit: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(reader)
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "host_control_input_invalid")?;
    if bytes.len() > limit || !bytes.ends_with(b"\n") {
        return Err("host_control_input_invalid".into());
    }
    Ok(bytes)
}

fn candidate_file(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT.
    }
    let file: File = options
        .open(path)
        .map_err(|_| "host_control_candidate_invalid")?;
    let metadata = file
        .metadata()
        .map_err(|_| "host_control_candidate_invalid")?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err("host_control_candidate_invalid".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("host_control_candidate_invalid".into());
        }
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "host_control_candidate_invalid")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("host_control_candidate_invalid".into());
    }
    Ok(bytes)
}

fn emit(value: serde_json::Value) -> Result<(), String> {
    let mut output = std::io::stdout().lock();
    writeln!(output, "{value}")
        .and_then(|()| output.flush())
        .map_err(|_| "host_control_output_unavailable".into())
}
pub fn report_failure(code: &str) -> Result<(), String> {
    emit(json!({"protocolVersion":1,"state":"failed","code":code}))
}
fn stopped(invalid: &AtomicBool) -> Result<(), String> {
    if invalid.load(Ordering::Acquire) {
        return Err("host_control_command_invalid".into());
    }
    emit(json!({"protocolVersion":1,"state":"stopped"}))
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum CheckpointCommand {
    #[serde(rename_all = "camelCase")]
    Checkpoint {
        protocol_version: u32,
        operation_id: String,
    },
    #[serde(rename_all = "camelCase")]
    CleanupCheckpoint {
        protocol_version: u32,
        operation_id: String,
        checkpoint: crate::host_runtime::CheckpointReceipt,
    },
    #[serde(rename_all = "camelCase")]
    PrepareRestore {
        protocol_version: u32,
        operation_id: String,
        binding: crate::host_runtime::RestoreBinding,
    },
    #[serde(rename_all = "camelCase")]
    VerifyRestore {
        protocol_version: u32,
        operation_id: String,
        prepared: Box<crate::host_runtime::PreparedRestore>,
    },
    #[serde(rename_all = "camelCase")]
    SelectRestore {
        protocol_version: u32,
        operation_id: String,
        verification_id: String,
        safety: Box<crate::host_state::SafetySnapshot>,
    },
}
fn read_owner_command(input: &mut impl BufRead) -> Result<Option<CheckpointCommand>, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    let count = Read::by_ref(input)
        .take(4097)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "host_control_command_invalid")?;
    if count == 0 || bytes.as_slice() == b"stop\n" {
        return Ok(None);
    }
    if count > 4096 || !bytes.ends_with(b"\n") {
        return Err("host_control_command_invalid".into());
    }
    let command: CheckpointCommand =
        serde_json::from_slice(&bytes).map_err(|_| "host_control_command_invalid")?;
    let (protocol_version, operation_id) = match &command {
        CheckpointCommand::Checkpoint {
            protocol_version,
            operation_id,
        } => (protocol_version, operation_id),
        CheckpointCommand::CleanupCheckpoint {
            protocol_version,
            operation_id,
            checkpoint,
        } => {
            if checkpoint.validate().is_err() || checkpoint.operation_id() != operation_id {
                return Err("host_control_command_invalid".into());
            }
            (protocol_version, operation_id)
        }
        CheckpointCommand::PrepareRestore {
            protocol_version,
            operation_id,
            binding,
        } => {
            if binding.validate().is_err() || binding.operation_id != *operation_id {
                return Err("host_control_command_invalid".into());
            }
            (protocol_version, operation_id)
        }
        CheckpointCommand::VerifyRestore {
            protocol_version,
            operation_id,
            prepared,
        } => {
            if prepared.validate().is_err() || prepared.binding.operation_id != *operation_id {
                return Err("host_control_command_invalid".into());
            }
            (protocol_version, operation_id)
        }
        CheckpointCommand::SelectRestore {
            protocol_version,
            operation_id,
            verification_id,
            safety,
        } => {
            if !crate::host_runtime::checkpoint_operation_id(verification_id)
                || safety.validate().is_err()
            {
                return Err("host_control_command_invalid".into());
            }
            (protocol_version, operation_id)
        }
    };
    if *protocol_version != 1 || !crate::host_runtime::checkpoint_operation_id(operation_id) {
        return Err("host_control_command_invalid".into());
    }
    Ok(Some(command))
}
fn read_owner_commands(
    input: &mut impl BufRead,
    sender: mpsc::SyncSender<CheckpointCommand>,
    cancelled: &AtomicBool,
    invalid: &AtomicBool,
) {
    loop {
        match read_owner_command(input) {
            Ok(Some(operation)) => {
                if sender.try_send(operation).is_ok() {
                    continue;
                }
                invalid.store(true, Ordering::Release);
            }
            Ok(None) => {}
            _ => invalid.store(true, Ordering::Release),
        }
        cancelled.store(true, Ordering::Release);
        return;
    }
}

pub fn run() -> Result<(), String> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let invalid = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::sync_channel(1);
    let (commands, command_receiver) = mpsc::sync_channel(1);
    let input_cancelled = cancelled.clone();
    let input_invalid = invalid.clone();
    std::thread::spawn(move || {
        let mut input = BufReader::new(std::io::stdin());
        let parsed = line(&mut input, 16 * 1024)
            .map_err(|_| "host_control_config_invalid".into())
            .and_then(|raw| config(&raw));
        let valid = parsed.is_ok();
        if sender.send(parsed).is_err() || !valid {
            return;
        }
        // A missing owner or malformed command still cancels while a checkpoint is running.
        read_owner_commands(&mut input, commands, &input_cancelled, &input_invalid);
    });
    let mut config = receiver
        .recv()
        .map_err(|_| "host_control_config_invalid")??;
    let password = Zeroizing::new(std::mem::take(&mut config.password));
    if cancelled.load(Ordering::Acquire) {
        return stopped(&invalid);
    }
    separate_paths(&config.candidate, &config.state)?;
    let runtime = verify_candidate(&config.candidate, &config.manifest_sha256)?;
    let _code_lease = crate::package_lease::CodeLease::acquire(&config.candidate)?;
    if config.mode != crate::host_runtime::HostMode::Server {
        if config.mode == crate::host_runtime::HostMode::CheckpointCleanup {
            crate::host_storage::check_cleanup(&config.state)?;
        } else {
            crate::host_storage::check(&config.state)?;
        }
        candidate_file(&config.state.join("host-state.json"), 4096)?;
    }
    let mut owner = crate::host_state::Owner::acquire(&config.state, true)?;
    if cancelled.load(Ordering::Acquire) {
        return stopped(&invalid);
    }
    if config.mode == crate::host_runtime::HostMode::CheckpointCleanup {
        crate::host_storage::check_cleanup(&config.state)?;
    } else {
        crate::host_storage::check(&config.state)?;
    }
    owner.activate(
        &config.installation_id,
        &config.manifest_sha256,
        config.mode,
    )?;
    let mut process = runtime.start_mode(
        &config.state,
        &password,
        config.database_port,
        config.api_port,
        config.mode,
        Some(&mut owner),
    )?;
    if !process.wait_ready_or_cancel(Duration::from_secs(240), &cancelled)? {
        owner.clean_stop()?;
        return stopped(&invalid);
    }
    if emit(
        json!({"protocolVersion":1,"state":config.mode.ready_state(), "manifestSha256":runtime.manifest_sha256(),
        "sourceRevision":runtime.source_revision(),"certified":runtime.certified()}),
    )
    .is_err()
    {
        process.stop()?;
        owner.clean_stop()?;
        return Err("host_control_output_unavailable".into());
    }
    while !cancelled.load(Ordering::Acquire) {
        if let Ok(command) = command_receiver.try_recv() {
            let result = match command {
                CheckpointCommand::Checkpoint { operation_id, .. } => {
                    if matches!(
                        config.mode,
                        crate::host_runtime::HostMode::CheckpointCleanup
                            | crate::host_runtime::HostMode::RestorePrepare
                    ) {
                        Err("host_checkpoint_unavailable".into())
                    } else {
                        process.request_checkpoint(&operation_id)
                    }
                }
                CheckpointCommand::CleanupCheckpoint { checkpoint, .. } => {
                    if config.mode == crate::host_runtime::HostMode::RestorePrepare {
                        Err("host_checkpoint_unavailable".into())
                    } else {
                        process.request_checkpoint_cleanup(&checkpoint)
                    }
                }
                CheckpointCommand::PrepareRestore { binding, .. } => {
                    if binding.installation_id != config.installation_id {
                        Err("host_restore_request_invalid".into())
                    } else {
                        process.request_restore(&binding)
                    }
                }
                CheckpointCommand::VerifyRestore { prepared, .. } => {
                    if prepared.binding.installation_id != config.installation_id {
                        Err("host_restore_request_invalid".into())
                    } else {
                        process.request_verify_restore(&prepared)
                    }
                }
                CheckpointCommand::SelectRestore {
                    operation_id,
                    verification_id,
                    safety,
                    ..
                } => {
                    if config.mode != crate::host_runtime::HostMode::RestorePrepare {
                        return Err("host_restore_unavailable".into());
                    }
                    process.stop()?;
                    owner.clean_stop()?;
                    let proof = process.take_verified_restore(&operation_id, &verification_id)?;
                    let generation = owner.select_restore(proof, *safety)?;
                    emit(
                        json!({"protocolVersion":1,"state":"restore-activation-pending","operationId":operation_id,"generation":generation}),
                    )?;
                    return stopped(&invalid);
                }
            };
            if result.is_err() {
                invalid.store(true, Ordering::Release);
                break;
            }
        }
        match process.poll_checkpoint() {
            Ok(Some(mut receipt)) => {
                receipt
                    .as_object_mut()
                    .ok_or("host_checkpoint_protocol_invalid")?
                    .insert("protocolVersion".into(), json!(1));
                if let Err(error) = emit(receipt) {
                    process.stop()?;
                    owner.clean_stop()?;
                    return Err(error);
                }
            }
            Ok(None) => {}
            Err(error) => {
                if process.stop().is_ok() {
                    owner.clean_stop()?;
                }
                return Err(error);
            }
        }
        if !process.is_running()? {
            return Err("host_process_exited".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    process.stop()?;
    owner.clean_stop()?;
    stopped(&invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_input_is_identity_only_and_stop_or_eof_remain_immediate() {
        let operation = "11111111-1111-4111-8111-111111111111";
        let request = json!({"protocolVersion":1,"action":"checkpoint","operationId":operation});
        let bytes = format!("{request}\nstop\n");
        let mut input = BufReader::new(bytes.as_bytes());
        assert_eq!(
            read_owner_command(&mut input).unwrap(),
            Some(CheckpointCommand::Checkpoint {
                protocol_version: 1,
                operation_id: operation.to_owned()
            })
        );
        assert_eq!(read_owner_command(&mut input).unwrap(), None);
        assert_eq!(read_owner_command(&mut &b""[..]).unwrap(), None);
        for raw in ["{}\n".to_owned(), format!("{request}"), "x".repeat(1025),
            format!("{{\"protocolVersion\":1,\"action\":\"checkpoint\",\"operationId\":\"{operation}\",\"path\":\"/outside\"}}\n")] {
            assert!(read_owner_command(&mut raw.as_bytes()).is_err());
        }
    }

    #[test]
    fn cleanup_input_requires_a_strict_receipt_for_the_same_operation() {
        let operation = "11111111-1111-4111-8111-111111111111";
        let receipt = json!({"schemaVersion":1,"operationId":operation,"manifestSha256":"a".repeat(64),
            "sourceRevision":"b".repeat(40),"postgresMajor":"19","databaseFormat":"frameleaf-canonical",
            "dump":{"bytes":27,"sha256":"c".repeat(64)}});
        let request = json!({"protocolVersion":1,"action":"cleanup-checkpoint","operationId":operation,"checkpoint":receipt});
        assert!(read_owner_command(&mut format!("{request}\n").as_bytes()).is_ok());
        for (key, value) in [
            ("checkpoint", json!(null)),
            ("path", json!("/outside")),
            ("operationId", json!("22222222-2222-4222-8222-222222222222")),
        ] {
            let mut changed = request.clone();
            changed[key] = value;
            assert!(read_owner_command(&mut format!("{changed}\n").as_bytes()).is_err());
        }
        let mut changed = request.clone();
        changed["checkpoint"]["dump"]["bytes"] = json!(0);
        assert!(read_owner_command(&mut format!("{changed}\n").as_bytes()).is_err());
    }

    #[test]
    fn restore_input_requires_exact_binding_for_the_same_operation() {
        let operation = "11111111-1111-4111-8111-111111111111";
        let binding = json!({"schemaVersion":1,"runtime":"native","operationId":operation,
            "reviewId":"22222222-2222-4222-8222-222222222222","snapshotId":"c".repeat(64),"installationId":"d".repeat(12),
            "manifestSha256":"a".repeat(64),"sourceRevision":"b".repeat(40),"libraryId":"e".repeat(12),"recoverySha256":"f".repeat(64)});
        let request = json!({"protocolVersion":1,"action":"prepare-restore","operationId":operation,"binding":binding});
        assert!(read_owner_command(&mut format!("{request}\n").as_bytes()).is_ok());
        for changed in [
            {
                let mut v = request.clone();
                v["binding"]["runtime"] = json!("docker");
                v
            },
            {
                let mut v = request.clone();
                v["binding"]["path"] = json!("/outside");
                v
            },
            {
                let mut v = request.clone();
                v["operationId"] = json!("22222222-2222-4222-8222-222222222222");
                v
            },
        ] {
            assert!(read_owner_command(&mut format!("{changed}\n").as_bytes()).is_err());
        }
    }

    #[test]
    fn verification_command_is_bounded_and_binds_the_entire_prepared_receipt() {
        let operation = "11111111-1111-4111-8111-111111111111";
        let binding = json!({"schemaVersion":1,"runtime":"native","operationId":operation,
            "reviewId":"22222222-2222-4222-8222-222222222222","snapshotId":"c".repeat(64),"installationId":"d".repeat(12),
            "manifestSha256":"a".repeat(64),"sourceRevision":"b".repeat(40),"libraryId":"e".repeat(12),"recoverySha256":"f".repeat(64)});
        let prepared = json!({"schemaVersion":1,"state":"restore-prepared","binding":binding,
            "attemptId":"33333333-3333-4333-8333-333333333333","profileIdentity":"1:2","targetIdentity":"1:3","databaseIdentity":"1:4",
            "validation":{"postgresMajor":19,"vectorVersion":"0.8.7","canonical":true,"executionStateReconstructed":true}});
        let request = json!({"protocolVersion":1,"action":"verify-restore","operationId":operation,"prepared":prepared});
        assert!(read_owner_command(&mut format!("{request}\n").as_bytes()).is_ok());
        assert!(
            read_owner_command(&mut format!("{request}{}\n", " ".repeat(1024)).as_bytes()).is_ok()
        );
        assert!(
            read_owner_command(&mut format!("{request}{}\n", " ".repeat(4096)).as_bytes()).is_err()
        );
        for mutation in ["operation", "path", "canonical", "attempt"] {
            let mut changed = request.clone();
            match mutation {
                "operation" => {
                    changed["operationId"] = json!("22222222-2222-4222-8222-222222222222")
                }
                "path" => changed["prepared"]["path"] = json!("/outside"),
                "canonical" => changed["prepared"]["validation"]["canonical"] = json!(false),
                _ => changed["prepared"]["attemptId"] = json!("../outside"),
            }
            assert!(
                read_owner_command(&mut format!("{changed}\n").as_bytes()).is_err(),
                "{mutation}"
            );
        }
    }

    #[test]
    fn a_flooded_command_channel_cancels_without_blocking_the_input_thread() {
        let request = json!({"protocolVersion":1,"action":"checkpoint","operationId":"11111111-1111-4111-8111-111111111111"});
        let input = format!("{request}\n{request}\nstop\n");
        let (tx, rx) = mpsc::sync_channel(1);
        let cancelled = AtomicBool::new(false);
        let invalid = AtomicBool::new(false);
        read_owner_commands(&mut input.as_bytes(), tx, &cancelled, &invalid);
        assert!(cancelled.load(Ordering::Acquire));
        assert!(invalid.load(Ordering::Acquire));
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn state_cannot_overlap_the_physical_runtime_tree_before_journal_creation() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-separation-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let candidate = root.join("Candidate");
        std::fs::create_dir(&candidate).unwrap();
        for state in [candidate.clone(), candidate.join("state"), root.clone()] {
            assert_eq!(
                separate_paths(&candidate, &state).unwrap_err(),
                "host_state_overlaps_runtime"
            );
        }
        let alias = root.join("candidate");
        if alias.exists() {
            assert!(separate_paths(&candidate, &alias.join("state")).is_err());
        }
        assert!(separate_paths(&candidate, &root.join("state")).is_ok());
        assert!(!root.join("state").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn controller_configuration_cannot_expand_authority_or_accept_invalid_identity() {
        let root = std::env::temp_dir().canonicalize().unwrap();
        let good = json!({"protocolVersion":1,"installationId":"a".repeat(12),"candidate":root.join("candidate"),"state":root.join("state"),
            "manifestSha256":"a".repeat(64),"password":"synthetic-password-long-enough",
            "databasePort":54321,"apiPort":54322});
        assert!(config(&serde_json::to_vec(&good).unwrap()).is_ok());
        assert_eq!(
            config(&serde_json::to_vec(&good).unwrap()).unwrap().mode,
            crate::host_runtime::HostMode::Server
        );
        let mut maintenance = good.clone();
        maintenance["mode"] = json!("database");
        assert_eq!(
            config(&serde_json::to_vec(&maintenance).unwrap())
                .unwrap()
                .mode,
            crate::host_runtime::HostMode::Database
        );
        maintenance["mode"] = json!("checkpoint-cleanup");
        assert_eq!(
            config(&serde_json::to_vec(&maintenance).unwrap())
                .unwrap()
                .mode,
            crate::host_runtime::HostMode::CheckpointCleanup
        );
        maintenance["mode"] = json!("restore-prepare");
        assert_eq!(
            config(&serde_json::to_vec(&maintenance).unwrap())
                .unwrap()
                .mode,
            crate::host_runtime::HostMode::RestorePrepare
        );
        for invalid in [json!(null), json!("backup"), json!(true)] {
            maintenance["mode"] = invalid;
            assert!(config(&serde_json::to_vec(&maintenance).unwrap()).is_err());
        }
        // Joining a Windows verbatim path normalizes away the traversal before validation.
        let parent_path = |leaf: &str| {
            json!(format!(
                "{}{separator}parent{separator}..{separator}{leaf}",
                root.display(),
                separator = std::path::MAIN_SEPARATOR
            ))
        };
        for (field, value) in [
            ("protocolVersion", json!(2)),
            ("candidate", json!("relative")),
            ("state", json!("relative")),
            ("state", parent_path("state")),
            ("candidate", parent_path("candidate")),
            ("manifestSha256", json!("main")),
            ("password", json!("too-short")),
            ("password", json!("x".repeat(513))),
            ("password", json!("synthetic-password-with\ncontrol")),
            ("databasePort", json!(0)),
            ("apiPort", json!(54321)),
            ("trustedKeys", json!(["untrusted"])),
            ("command", json!("arbitrary command")),
        ] {
            let mut value_config = good.clone();
            value_config[field] = value;
            assert_eq!(
                config(&serde_json::to_vec(&value_config).unwrap())
                    .err()
                    .unwrap(),
                "host_control_config_invalid"
            );
        }
    }

    #[test]
    fn controller_lines_are_bounded_and_require_a_complete_message() {
        assert_eq!(&*line(&mut &b"stop\n"[..], 5).unwrap(), b"stop\n");
        for input in [&b"stop"[..], &b""[..], &b"stop\nx"[..]] {
            let result = line(&mut &input[..], 4);
            assert_eq!(result.err().unwrap(), "host_control_input_invalid");
        }
    }

    #[cfg(unix)]
    #[test]
    fn candidate_files_refuse_links_special_files_and_oversized_content() {
        use std::os::unix::ffi::OsStrExt;
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-control-file-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let file = root.join("file");
        std::fs::write(&file, b"fixture").unwrap();
        assert_eq!(candidate_file(&file, 7).unwrap(), b"fixture");
        assert!(candidate_file(&file, 6).is_err());
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&file, &alias).unwrap();
        assert!(candidate_file(&alias, 7).is_err());
        assert!(candidate_file(&root, 7).is_err());
        let fifo = root.join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(candidate_file(&fifo, 7).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn selection_pipe_accepts_only_a_nonce_and_bound_safety_metadata_never_boolean_proof_or_paths()
    {
        let op = "11111111-1111-4111-8111-111111111111";
        let request = json!({"protocolVersion":1,"action":"select-restore","operationId":op,
            "verificationId":"22222222-2222-4222-8222-222222222222",
            "safety":{"snapshotId":"a".repeat(64),"recoverySha256":"b".repeat(64),
                "checkpoint":{"schemaVersion":1,"operationId":op,"manifestSha256":"c".repeat(64),"sourceRevision":"d".repeat(40),"postgresMajor":"19","databaseFormat":"frameleaf-canonical","dump":{"bytes":27,"sha256":"e".repeat(64)}}}});
        assert!(matches!(
            read_owner_command(&mut format!("{request}\n").as_bytes()).unwrap(),
            Some(CheckpointCommand::SelectRestore { .. })
        ));
        for mutation in ["nonce", "version", "proof", "path", "safety", "checkpoint"] {
            let mut changed = request.clone();
            match mutation {
                "nonce" => changed["verificationId"] = json!(op.to_uppercase().replace('1', "A")),
                "version" => changed["protocolVersion"] = json!(2),
                "proof" => changed["offlineChecksums"] = json!(true),
                "path" => changed["databasePath"] = json!("/outside"),
                "safety" => changed["safety"]["recoverySha256"] = json!("invalid"),
                _ => changed["safety"]["checkpoint"]["dump"]["bytes"] = json!(0),
            }
            assert!(
                read_owner_command(&mut format!("{changed}\n").as_bytes()).is_err(),
                "{mutation}"
            );
        }
    }
}
