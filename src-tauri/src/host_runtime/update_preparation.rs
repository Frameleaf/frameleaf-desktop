//! Retained target preparation and verification; these receipts cannot activate an ordinary restore.
use super::*;
use crate::manager_profile::update::PreparedCredentials;
use std::{
    process::{Child, ChildStdin, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    thread::JoinHandle,
};
use zeroize::Zeroizing;

const FAILED: &str = "host_update_preparation_failed";
const UPDATE_AGENT: &str = include_str!("../../../runtime/host-update-agent.mjs");

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdatePrepared {
    schema_version: u32,
    state: String,
    binding: RestoreBinding,
    attempt_id: String,
    profile_identity: String,
    target_identity: String,
    database_identity: String,
    validation: RestoreValidation,
    update: serde_json::Value,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateVerified {
    state: String,
    prepared: UpdatePrepared,
    offline_checksums: bool,
    schema_validated: bool,
}
/// Verified candidate evidence only; authenticated selection is still required.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostUpdateCandidate {
    state: &'static str,
    offline_checksums: bool,
    schema_validated: bool,
    receipt: UpdatePrepared,
    reference: crate::host_database::Reference,
    #[serde(skip_serializing_if = "Option::is_none")]
    selection_generation: Option<uuid::Uuid>,
}
fn json_file(directory: &Directory, name: &str, maximum: u64) -> Result<Vec<u8>, String> {
    directory.check()?;
    let mut file = crate::copy_source::staged_file(&directory.dir, Path::new(name))?;
    let size = file.metadata().map_err(|_| FAILED)?.len();
    if size == 0 || size > maximum {
        return Err(FAILED.into());
    }
    crate::host_state::valid_sized_file(&file.try_clone().map_err(|_| FAILED)?.into_std(), size)?;
    let stamp = crate::copy_source::opened_stamp(&file)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| FAILED)?;
    crate::copy_source::unchanged(
        &directory.dir,
        Path::new(name),
        &file,
        &stamp,
        size,
        bytes.len() as u64,
    )?;
    directory.check()?;
    Ok(bytes)
}
fn inspect(
    target: &VerifiedHostRuntime,
    config: &Configuration,
    request: &HostUpdateInput,
    bytes: &[u8],
) -> Result<HostUpdateCandidate, String> {
    let verified: UpdateVerified = serde_json::from_slice(bytes).map_err(|_| FAILED)?;
    if verified.state != "update-verified"
        || !verified.offline_checksums
        || !verified.schema_validated
    {
        return Err(FAILED.into());
    }
    let receipt = verified.prepared;
    if receipt.schema_version != 1
        || receipt.state != "update-prepared"
        || receipt.binding != request.restore
        || receipt.update != serde_json::to_value(request).map_err(|_| FAILED)?
        || !checkpoint_operation_id(&receipt.attempt_id)
        || ![
            &receipt.profile_identity,
            &receipt.target_identity,
            &receipt.database_identity,
        ]
        .iter()
        .all(|value| restore_identity(value))
        || receipt.validation.postgres_major != 19
        || receipt.validation.vector_version != "0.8.7"
        || !receipt.validation.canonical
        || !receipt.validation.execution_state_reconstructed
    {
        return Err(FAILED.into());
    }
    let reference = crate::host_database::Reference::capture(
        &config.state,
        &receipt.binding.operation_id,
        &receipt.attempt_id,
    )?;
    if !reference.matches_node_identities([
        &receipt.profile_identity,
        &receipt.target_identity,
        &receipt.database_identity,
    ]) {
        return Err(FAILED.into());
    }
    let database = reference.resolve(&config.state)?;
    let directory = Directory::open(database.parent().ok_or(FAILED)?.into())?;
    let result: serde_json::Value =
        serde_json::from_slice(&json_file(&directory, "restore-result.json", 4096)?)
            .map_err(|_| FAILED)?;
    if result != serde_json::to_value(&receipt).map_err(|_| FAILED)? {
        return Err(FAILED.into());
    }
    let intent: serde_json::Value =
        serde_json::from_slice(&json_file(&directory, "restore-target.json", 4096)?)
            .map_err(|_| FAILED)?;
    if intent
        != serde_json::json!({"schemaVersion":1,"binding":receipt.binding,"attemptId":receipt.attempt_id,
        "profileIdentity":receipt.profile_identity,"targetIdentity":receipt.target_identity,"update":receipt.update})
    {
        return Err(FAILED.into());
    }
    let marker: serde_json::Value =
        serde_json::from_slice(&json_file(&directory, "host-state.json", 4096)?)
            .map_err(|_| FAILED)?;
    if marker
        != serde_json::json!({"schemaVersion":1,"manifestSha256":target.manifest_sha256(),"sourceRevision":target.source_revision(),"postgresMajor":"19"})
    {
        return Err(FAILED.into());
    }
    let database = Directory::open(database)?;
    if String::from_utf8(json_file(&database, "PG_VERSION", 16)?)
        .map_err(|_| FAILED)?
        .trim()
        != "19"
    {
        return Err(FAILED.into());
    }
    reference.resolve(&config.state)?;
    directory.check()?;
    Ok(HostUpdateCandidate {
        state: "candidate-verified",
        offline_checksums: true,
        schema_validated: true,
        receipt,
        reference,
        selection_generation: None,
    })
}
struct PreparationChild<'a> {
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    shutdown_unconfirmed: &'a std::cell::Cell<bool>,
    child: Child,
    owner: Arc<HostOwner>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
    #[cfg(unix)]
    reaped: bool,
}
impl Drop for PreparationChild<'_> {
    fn drop(&mut self) {
        #[cfg(windows)]
        if self.cleanup_windows().is_err() {
            return;
        }
        #[cfg(unix)]
        {
            self.owner.terminate();
            if !self.reaped {
                let _ = self.child.wait();
            }
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}
impl PreparationChild<'_> {
    #[cfg(any(windows, test))]
    fn cleanup_with(
        &mut self,
        confirm: impl FnOnce(&mut Child, &HostOwner) -> Result<(), String>,
    ) -> Result<(), String> {
        if self.shutdown_unconfirmed.get() {
            return Err("host_update_shutdown_unconfirmed".into());
        }
        if confirm(&mut self.child, &self.owner).is_err() {
            self.shutdown_unconfirmed.set(true);
            return Err("host_update_shutdown_unconfirmed".into());
        }
        Ok(())
    }
    #[cfg(windows)]
    fn cleanup_windows(&mut self) -> Result<(), String> {
        self.cleanup_with(|child, owner| {
            owner.tree.terminate_confirmed(Duration::from_secs(5))?;
            match child.try_wait() {
                Ok(Some(_)) => Ok(()),
                _ => Err(FAILED.into()),
            }
        })
    }
}
fn verify_candidate_stage(
    stage: &Stage,
    request: &HostUpdateInput,
    payload: &Payload,
    config: &Configuration,
    activity: (&AtomicBool, Instant),
) -> Result<(), String> {
    let (cancel, deadline) = activity;
    stage.input.verify(
        "database.dump",
        payload.checkpoint.dump.bytes,
        &payload.checkpoint.dump.sha256,
        cancel,
        deadline,
    )?;
    let raw = json_file(&stage.input, "recovery.json", 4096)?;
    backup::recovery(&raw, payload, config)?;
    stage
        .input
        .require_names(&["database.dump", "recovery.json"])?;
    stage
        .operation
        .require_names(&["input", "restore-intent.json"])?;
    let intent: serde_json::Value =
        serde_json::from_slice(&json_file(&stage.operation, "restore-intent.json", 4096)?)
            .map_err(|_| FAILED)?;
    if intent != serde_json::to_value(&request.restore).map_err(|_| FAILED)? {
        return Err(FAILED.into());
    }
    for directory in [&stage.profile, &stage.root, &stage.operation, &stage.input] {
        directory.check()?;
    }

    active(cancel, deadline)?;
    Ok(())
}
fn prepare_candidate_held(
    source: &VerifiedHostRuntime,
    target: &VerifiedHostRuntime,
    config: &Configuration,
    context: (
        &Payload,
        &PreparedCredentials<'_>,
        &mut crate::host_state::Owner,
        &std::cell::Cell<bool>,
    ),
    activity: (&AtomicBool, Instant),
    write: &mut impl FnMut(&Payload, &str, File) -> Result<Vec<u8>, String>,
) -> Result<(HostUpdateCandidate, Stage), String> {
    let (payload, credentials, owner, shutdown_unconfirmed) = context;
    let (cancel, deadline) = activity;
    let (request, stage) = stage_input_held(
        source,
        target,
        config,
        (payload, credentials.backup_key, owner),
        (cancel, deadline),
        write,
    )?;
    let candidate = target.prepare_child_held(
        config,
        (&request, None),
        credentials,
        shutdown_unconfirmed,
        cancel,
        deadline,
    )?;
    verify_candidate_stage(&stage, &request, payload, config, activity)?;
    candidate.reference.resolve(&config.state)?;
    active(cancel, deadline)?;
    Ok((candidate, stage))
}
impl VerifiedHostRuntime {
    /// Only this held authenticated callback may run the admitted target while source ownership remains reserved.
    fn prepare_child_held(
        &self,
        config: &Configuration,
        input: (&HostUpdateInput, Option<&UpdatePrepared>),
        credentials: &PreparedCredentials<'_>,
        shutdown_unconfirmed: &std::cell::Cell<bool>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<HostUpdateCandidate, String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let (request, prepared) = input;
        active(cancel, deadline)?;
        self.check_files()?;
        credentials.profile.require_current(config)?;
        let source = STANDARD.encode(format!("{AGENT}\n{UPDATE_AGENT}"));
        if source.len() > 262144 {
            return Err(FAILED.into());
        }
        #[derive(Serialize)]
        struct Request<'a> {
            configuration: HostStart<'a>,
            update: &'a HostUpdateInput,
            #[serde(skip_serializing_if = "Option::is_none")]
            prepared: Option<&'a UpdatePrepared>,
        }
        let message = Zeroizing::new(
            serde_json::to_vec(&Request {
                configuration: HostStart {
                    mode: HostMode::RestorePrepare,
                    state: &config.state,
                    database_reference: None,
                    runtime: &self.root,
                    manifest_sha256: &self.manifest_sha256,
                    source_revision: &self.manifest.source_revision,
                    postgres_major: "19",
                    password: credentials.database_password,
                    database_port: config.database_port,
                    api_port: config.api_port,
                    entry_points: &self.manifest.entry_points,
                },
                update: request,
                prepared,
            })
            .map_err(|_| FAILED)?,
        );
        if message.len() > 65536 {
            return Err(FAILED.into());
        }
        let lease = crate::package_lease::CodeLease::acquire(self.root.parent().ok_or(FAILED)?)?;
        let mut command = Command::new(self.root.join(relative(&self.manifest.entry_points.node)?));
        command
            .args(["--input-type=module", "--eval", AGENT_BOOTSTRAP])
            .env_clear()
            .env("FRAMELEAF_HOST_AGENT", "0")
            .current_dir(&config.state)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(private_file(
                &config.state.join("update-prepare.log"),
                true,
            )?);
        #[cfg(windows)]
        {
            if let Some(root) = std::env::var_os("SystemRoot") {
                command.env("SystemRoot", root);
            }
            command.env("NODE_OPTIONS", crate::windows_protection::NODE_PATH_OPTIONS);
        }
        lease.inherit(&mut command);
        #[cfg(unix)]
        credentials.profile.inherit(&mut command);
        crate::process_tree::configure(&mut command);
        active(cancel, deadline)?;
        self.check_files()?;
        credentials.profile.require_current(config)?;
        // Admission is already held by with_consumption_context; do not reenter installation credentials.
        let mut child = command.spawn().map_err(|_| FAILED)?;
        #[cfg(unix)]
        credentials.profile.child_spawned();
        let tree = match crate::process_tree::ProcessTree::attach(&child) {
            Ok(tree) => tree,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let owner = Arc::new(HostOwner {
            tree,
            terminated: Mutex::new(false),
            _code_lease: lease,
        });
        let mut owned = PreparationChild {
            shutdown_unconfirmed,
            child,
            owner,
            reader: None,
            writer: None,
            #[cfg(unix)]
            reaped: false,
        };
        let mut output = owned.child.stdout.take().ok_or(FAILED)?;
        let mut input = owned.child.stdin.take().ok_or(FAILED)?;
        let (read_tx, read_rx) = mpsc::sync_channel(1);
        owned.reader = Some(std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = output
                .by_ref()
                .take(16385)
                .read_to_end(&mut bytes)
                .map_err(|_| FAILED.to_string())
                .and_then(|_| {
                    if bytes.is_empty()
                        || bytes.len() > 16384
                        || !bytes.ends_with(b"\n")
                        || bytes[..bytes.len() - 1].contains(&b'\n')
                    {
                        Err(FAILED.into())
                    } else {
                        Ok(bytes)
                    }
                });
            let _ = read_tx.send(result);
        }));
        let (write_tx, write_rx) = mpsc::sync_channel(1);
        owned.writer = Some(std::thread::spawn(move || {
            let result = input
                .write_all(source.as_bytes())
                .and_then(|_| input.write_all(b"\n"))
                .and_then(|_| input.write_all(&message))
                .and_then(|_| input.write_all(b"\n"))
                .map(|_| input)
                .map_err(|_| FAILED.to_string());
            let _ = write_tx.send(result);
        }));
        let started = Instant::now();
        let mut pipe: Option<ChildStdin> = None;
        let mut stop_sent = false;
        let mut aborting = None;
        let mut result = None;
        loop {
            if pipe.is_none() {
                match write_rx.try_recv() {
                    Ok(value) => pipe = Some(value?),
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(_) => return Err(FAILED.into()),
                }
            }
            if result.is_none() {
                match read_rx.try_recv() {
                    Ok(value) => result = Some(value?),
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(_) => return Err(FAILED.into()),
                }
            }
            if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                aborting.get_or_insert_with(Instant::now);
            }
            if let Some(abort) = aborting {
                if !stop_sent {
                    if let Some(input) = pipe.as_mut() {
                        let _ = input.write_all(b"stop\n");
                        stop_sent = true;
                    }
                }
                if Instant::now().duration_since(abort) > Duration::from_secs(10) {
                    return Err(FAILED.into());
                }
            }
            if pipe.is_none() && started.elapsed() > Duration::from_secs(5) {
                return Err(FAILED.into());
            }
            if let Some(status) = owned_exit(&mut owned.child, &owned.owner)? {
                #[cfg(unix)]
                {
                    owned.reaped = true;
                }
                if !status.success() || aborting.is_some() {
                    return Err(FAILED.into());
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        #[cfg(windows)]
        owned.cleanup_windows()?;
        let bytes = match result {
            Some(bytes) => bytes,
            None => read_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| FAILED)??,
        };
        active(cancel, deadline)?;
        let result = inspect(self, config, request, &bytes)?;
        credentials.profile.require_current(config)?;
        self.check_files()?;
        Ok(result)
    }
    /// Restore and verify the approved backup in a fresh target. Does not select or start the photo server.
    pub fn prepare_update_candidate(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
    ) -> Result<HostUpdateCandidate, String> {
        let deadline = Instant::now() + Duration::from_secs(7200);
        self.prepare_candidate_with(
            target,
            [source, destination],
            execution,
            (cancel, deadline),
            &mut crate::manager_profile::Keystore,
            |payload, key, file| {
                target.stage_update_backup_held(source, payload, key, cancel, deadline, file)
            },
        )
    }
    #[cfg(test)]
    pub(in crate::host_runtime) fn prepare_update_candidate_test(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
        store: &mut impl crate::manager_profile::UpdateStore,
        write: impl FnMut(&Payload, &str, File) -> Result<Vec<u8>, String>,
    ) -> Result<HostUpdateCandidate, String> {
        self.prepare_candidate_with(
            target,
            profiles,
            execution,
            (cancel, Instant::now() + Duration::from_secs(30)),
            store,
            write,
        )
    }
    #[allow(clippy::too_many_arguments)] // Fixed authority tuple plus the approved backup reader, never a caller-supplied process.
    fn prepare_candidate_with(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        activity: (&AtomicBool, Instant),
        store: &mut impl crate::manager_profile::UpdateStore,
        mut write: impl FnMut(&Payload, &str, File) -> Result<Vec<u8>, String>,
    ) -> Result<HostUpdateCandidate, String> {
        let (cancel, deadline) = activity;
        active(cancel, deadline)?;
        if self.epoch() == 0 || target.epoch() <= self.epoch() || target.epoch() > MAX_SAFE {
            return Err(FAILED.into());
        }
        let mut result = None;
        self.with_consumption_context(
            target,
            profiles,
            (execution, ContextAdmission::TargetRecovery),
            None,
            clock,
            store,
            |payload, credentials, owner, shutdown_unconfirmed| {
                let (candidate, stage) = prepare_candidate_held(
                    self,
                    target,
                    profiles[0],
                    (payload, credentials, owner, shutdown_unconfirmed),
                    (cancel, deadline),
                    &mut write,
                )?;
                result = Some((candidate, stage));
                Ok(())
            },
        )?;
        active(cancel, deadline)?;
        let (candidate, stage) = result.ok_or(FAILED)?;
        for directory in [&stage.profile, &stage.root, &stage.operation, &stage.input] {
            directory.check()?;
        }
        candidate.reference.resolve(&profiles[0].state)?;
        active(cancel, deadline)?;
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_confirmation_keeps_exclusion_with_a_surviving_descendant() {
        const ROLE: &str = "FRAMELEAF_UPDATE_CLEANUP_TEST";
        const ROOT: &str = "FRAMELEAF_UPDATE_CLEANUP_ROOT";
        let test = format!(
            "{}::failed_confirmation_keeps_exclusion_with_a_surviving_descendant",
            module_path!().split_once("::").unwrap().1
        );
        if let Ok(role) = std::env::var(ROLE) {
            if role == "leaf" {
                std::thread::sleep(Duration::from_secs(30));
            } else {
                let mut gate = [0];
                std::io::stdin().read_exact(&mut gate).unwrap();
                assert_eq!(gate, [1]);
                let mut command = Command::new(std::env::current_exe().unwrap());
                command
                    .args(["--exact", &test])
                    .env(ROLE, "leaf")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                #[cfg(windows)]
                {
                    use std::os::windows::process::CommandExt;
                    command.creation_flags(windows_sys::Win32::System::Threading::DETACHED_PROCESS);
                }
                #[allow(clippy::zombie_processes)]
                // The leader must exit first; the test supervisor owns and kills the descendant.
                let leaf = command.spawn().unwrap();
                std::fs::write(
                    PathBuf::from(std::env::var_os(ROOT).unwrap()).join("leaf"),
                    leaf.id().to_string(),
                )
                .unwrap();
                // The owned leader exits while its descendant retains the Job/process group.
            }
            return;
        }
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-update-cleanup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", &test])
            .env(ROLE, "worker")
            .env(ROOT, &root)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        crate::process_tree::configure(&mut command);
        let child = command.spawn().unwrap();
        let owner = Arc::new(HostOwner {
            tree: crate::process_tree::ProcessTree::attach(&child).unwrap(),
            terminated: Mutex::new(false),
            _code_lease: crate::package_lease::CodeLease::acquire(&root).unwrap(),
        });
        let unconfirmed = std::cell::Cell::new(false);
        let mut owned = PreparationChild {
            shutdown_unconfirmed: &unconfirmed,
            child,
            owner,
            reader: None,
            writer: None,
            #[cfg(unix)]
            reaped: false,
        };
        owned.child.stdin.take().unwrap().write_all(&[1]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while owned.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "fixture leader did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        #[cfg(unix)]
        {
            owned.reaped = true;
        }
        let pid: u32 = std::fs::read_to_string(root.join("leaf"))
            .unwrap()
            .parse()
            .unwrap();
        #[cfg(unix)]
        assert_eq!(
            unsafe { libc::kill(pid as i32, 0) },
            0,
            "descendant not alive"
        );
        #[cfg(windows)]
        let leaf = {
            use std::os::windows::io::{FromRawHandle, OwnedHandle};
            use windows_sys::Win32::{
                Foundation::WAIT_TIMEOUT,
                System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE},
            };
            let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            assert!(!handle.is_null());
            assert_eq!(unsafe { WaitForSingleObject(handle, 0) }, WAIT_TIMEOUT);
            unsafe { OwnedHandle::from_raw_handle(handle) }
        };
        assert!(owned
            .cleanup_with(|child, _| {
                assert!(child.try_wait().unwrap().is_some());
                Err("synthetic failed Job confirmation".into())
            })
            .is_err());
        assert!(unconfirmed.get());
        assert!(owned
            .cleanup_with(|_, _| panic!("unconfirmed shutdown must not be cleared by a retry"))
            .is_err());
        // Explicit fixture cleanup; production retains outer exclusions until supervisor exit.
        owned.owner.terminate();
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            assert_eq!(
                unsafe {
                    windows_sys::Win32::System::Threading::WaitForSingleObject(
                        leaf.as_raw_handle(),
                        5000,
                    )
                },
                windows_sys::Win32::Foundation::WAIT_OBJECT_0
            );
        }
        drop(owned);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[path = "update_selection.rs"]
mod selection;
