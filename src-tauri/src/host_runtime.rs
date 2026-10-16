//! Host packs have separate authority and component requirements from ML packs.
use crate::native_runtime::{digest_valid, relative, verify_files, Artifact};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EntryPoints {
    node: String,
    server: String,
    postgres: String,
    initdb: String,
    pg_dump: String,
    pg_restore: String,
    pg_isready: String,
    pg_checksums: String,
    pg_ctl: String,
    createdb: String,
    psql: String,
    vector: String,
    hdr: String,
    ffmpeg: String,
    ffprobe: String,
    exiftool: String,
    raw_renderer: String,
    web_index: String,
    studio: String,
    core_plugin: String,
    ml_manifest: String,
}
impl EntryPoints {
    fn paths(&self) -> [&str; 21] {
        [
            &self.node,
            &self.server,
            &self.postgres,
            &self.initdb,
            &self.pg_dump,
            &self.pg_restore,
            &self.pg_isready,
            &self.pg_checksums,
            &self.pg_ctl,
            &self.createdb,
            &self.psql,
            &self.vector,
            &self.hdr,
            &self.ffmpeg,
            &self.ffprobe,
            &self.exiftool,
            &self.raw_renderer,
            &self.web_index,
            &self.studio,
            &self.core_plugin,
            &self.ml_manifest,
        ]
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostManifest {
    schema_version: u32,
    protocol_version: u32,
    epoch: u64,
    platform: String,
    architecture: String,
    source_revision: String,
    node_version: String,
    postgres_version: String,
    vector_version: String,
    certified: bool,
    entry_points: EntryPoints,
    files: BTreeMap<String, Artifact>,
}

pub struct VerifiedHostRuntime {
    root: PathBuf,
    manifest: HostManifest,
    manifest_sha256: String,
}
impl VerifiedHostRuntime {
    /// Keys and rollback floor are supplied by compiled desktop release authority, never by a server.
    pub fn verify(
        root: &Path,
        raw: &[u8],
        signature: &[u8; 64],
        trusted: &[VerifyingKey],
        minimum_epoch: u64,
    ) -> Result<Self, String> {
        if raw.is_empty()
            || raw.len() > 8 * 1024 * 1024
            || !trusted.iter().any(|key| {
                key.verify_strict(raw, &Signature::from_bytes(signature))
                    .is_ok()
            })
        {
            return Err("host_signature_invalid".into());
        }
        let manifest: HostManifest =
            serde_json::from_slice(raw).map_err(|_| "host_manifest_invalid")?;
        let pins: serde_json::Value =
            serde_json::from_str(include_str!("../../runtime/host-database.json"))
                .map_err(|_| "host_release_contract_invalid")?;
        if manifest.schema_version != 1
            || manifest.protocol_version != 1
            || minimum_epoch == 0
            || manifest.epoch < minimum_epoch
            || manifest.platform != std::env::consts::OS
            || manifest.architecture != std::env::consts::ARCH
            || !digest_valid(&manifest.source_revision, 40)
            || manifest.node_version != "26.11.1"
            || Some(manifest.postgres_version.as_str()) != pins["postgresVersion"].as_str()
            || Some(manifest.vector_version.as_str()) != pins["pgvectorVersion"].as_str()
            || Some(manifest.certified) != pins["certified"].as_bool()
            || manifest.files.is_empty()
            || manifest.files.len() > 100_000
        {
            return Err("host_manifest_incompatible".into());
        }
        for name in manifest.entry_points.paths().into_iter().chain([
            "build/geodata/geodata-date.txt",
            "build/geodata/cities500.txt",
            "build/geodata/admin1CodesASCII.txt",
            "build/geodata/admin2Codes.txt",
            "build/geodata/countryInfo.txt",
            "build/geodata/ne_10m_admin_0_countries.geojson",
            "build/geodata/landmarks.ndjson.gz",
        ]) {
            relative(name)?;
            if !manifest.files.contains_key(name) {
                return Err("host_component_missing".into());
            }
        }
        verify_files(root, &manifest.files)?;
        Ok(Self {
            root: root.into(),
            manifest,
            manifest_sha256: format!("{:x}", Sha256::digest(raw)),
        })
    }
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
    pub fn source_revision(&self) -> &str {
        &self.manifest.source_revision
    }
    pub fn certified(&self) -> bool {
        self.manifest.certified
    }
    pub fn check_files(&self) -> Result<(), String> {
        verify_files(&self.root, &self.manifest.files)
    }
}

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{
        mpsc::{self, Receiver},
        Arc, Mutex,
    },
    time::Duration,
};
use zeroize::Zeroizing;

const AGENT: &str = include_str!("../../runtime/host-agent.mjs");

fn private_file(path: &Path, append: bool) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .append(append);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options.open(path).map_err(|_| "host_state_file_invalid")?;
    let meta = file.metadata().map_err(|_| "host_state_file_invalid")?;
    if !meta.is_file() {
        return Err("host_state_file_invalid".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err("host_state_file_invalid".into());
        }
    }
    Ok(file)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostStart<'a> {
    state: &'a Path,
    runtime: &'a Path,
    manifest_sha256: &'a str,
    source_revision: &'a str,
    postgres_major: &'a str,
    password: &'a str,
    database_port: u16,
    api_port: u16,
    entry_points: &'a EntryPoints,
}

struct HostOwner {
    tree: crate::process_tree::ProcessTree,
    terminated: Mutex<bool>,
}
impl HostOwner {
    fn terminate(&self) {
        let mut terminated = self
            .terminated
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !*terminated {
            self.tree.terminate();
            *terminated = true;
        }
    }
}
#[cfg(unix)]
fn owned_exit(child: &mut Child, owner: &HostOwner) -> Result<Option<ExitStatus>, String> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            return Ok(None);
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            *owner
                .terminated
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = true;
        }
        return Err("host_process_state_failed".into());
    }
    if unsafe { info.assume_init().si_pid() } == 0 {
        return Ok(None);
    }
    // Keep the owned leader unreaped until its group is terminated: the PID cannot be reused here.
    owner.terminate();
    child
        .wait()
        .map(Some)
        .map_err(|_| "host_process_state_failed".into())
}
#[cfg(windows)]
fn owned_exit(child: &mut Child, _owner: &HostOwner) -> Result<Option<ExitStatus>, String> {
    child
        .try_wait()
        .map_err(|_| "host_process_state_failed".into())
}
pub struct HostProcess {
    owner: Arc<HostOwner>,
    pid: u32,
    input: Option<ChildStdin>,
    ready: Receiver<Result<(), String>>,
    exited: Receiver<Result<(), String>>,
    stopped: Option<Result<(), String>>,
}
impl VerifiedHostRuntime {
    /// Credentials are native-only; callers persist them in the OS credential store before first start.
    pub fn start(
        &self,
        state: &Path,
        password: &Zeroizing<String>,
        database_port: u16,
        api_port: u16,
    ) -> Result<HostProcess, String> {
        self.check_files()?;
        if password.len() < 24
            || password.len() > 512
            || password.contains(['\r', '\n', '\0'])
            || database_port == 0
            || api_port == 0
            || database_port == api_port
        {
            return Err("host_config_invalid".into());
        }
        crate::runtime_store::private_directory(state)?;
        crate::host_storage::check(state)?;
        let database = state.join("database");
        match std::fs::symlink_metadata(&database) {
            Ok(_) => crate::host_storage::check(&database)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("host_storage_unavailable".into()),
        }
        if state.starts_with(&self.root) || self.root.starts_with(state) {
            return Err("host_state_overlaps_runtime".into());
        }
        let lease = private_file(&state.join("lease.lock"), false)?;
        lease.try_lock().map_err(|_| "host_already_owned")?;
        let message = Zeroizing::new(
            serde_json::to_vec(&HostStart {
                state,
                runtime: &self.root,
                manifest_sha256: &self.manifest_sha256,
                source_revision: &self.manifest.source_revision,
                postgres_major: "19",
                password,
                database_port,
                api_port,
                entry_points: &self.manifest.entry_points,
            })
            .map_err(|_| "host_config_invalid")?,
        );
        let mut command = Command::new(self.root.join(relative(&self.manifest.entry_points.node)?));
        command
            .args(["--input-type=module", "--eval", AGENT])
            .env_clear()
            .env("FRAMELEAF_HOST_AGENT", "1")
            .current_dir(state)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(private_file(&state.join("agent.log"), true)?);
        #[cfg(windows)]
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
        crate::process_tree::configure(&mut command);
        let mut child = command.spawn().map_err(|_| "host_agent_start_failed")?;
        let tree = match crate::process_tree::ProcessTree::attach(&child) {
            Ok(tree) => tree,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let input = child.stdin.take();
        let output = child.stdout.take();
        let (sender, ready) = mpsc::channel();
        let owner = Arc::new(HostOwner {
            tree,
            terminated: Mutex::new(false),
        });
        let pid = child.id();
        let monitor_owner = owner.clone();
        let (exit_sender, exited) = mpsc::channel();
        std::thread::spawn(move || {
            let _lease = lease;
            let result = loop {
                match owned_exit(&mut child, &monitor_owner) {
                    Ok(Some(status)) => {
                        break if status.success() {
                            Ok(())
                        } else {
                            Err("host_process_exited".into())
                        }
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                    Err(_) => {
                        monitor_owner.terminate();
                        let _ = child.wait();
                        break Err("host_process_state_failed".into());
                    }
                }
            };
            monitor_owner.terminate();
            drop(_lease);
            let _ = exit_sender.send(result);
        });
        let mut process = HostProcess {
            owner,
            pid,
            input,
            ready,
            exited,
            stopped: None,
        };
        let Some(output) = output else {
            return Err("host_agent_pipe_failed".into());
        };
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let mut reader = BufReader::new(output);
            let result = Read::by_ref(&mut reader)
                .take(8193)
                .read_until(b'\n', &mut bytes)
                .map_err(|_| "host_readiness_failed".to_string())
                .and_then(|_| {
                    if bytes.len() > 8192
                        || serde_json::from_slice::<serde_json::Value>(&bytes).ok()
                            != Some(serde_json::json!({"state":"running"}))
                    {
                        Err("host_readiness_failed".into())
                    } else {
                        Ok(())
                    }
                });
            let _ = sender.send(result);
            let _ = std::io::copy(&mut reader, &mut std::io::sink());
        });
        process
            .input
            .as_mut()
            .ok_or("host_agent_pipe_failed")?
            .write_all(&message)
            .and_then(|_| process.input.as_mut().unwrap().write_all(b"\n"))
            .map_err(|_| "host_agent_pipe_failed")?;
        Ok(process)
    }
}
impl HostProcess {
    pub fn process_id(&self) -> u32 {
        self.pid
    }
    pub fn wait_ready(&mut self, timeout: Duration) -> Result<(), String> {
        let result = self
            .ready
            .recv_timeout(timeout)
            .map_err(|_| "host_readiness_timeout".to_string())
            .and_then(|result| result);
        if let Err(error) = result {
            self.input.take();
            self.owner.terminate();
            let _ = self.exited.recv_timeout(Duration::from_secs(10));
            self.stopped = Some(Err(error.clone()));
            return Err(error);
        }
        if let Ok(result) = self.exited.try_recv() {
            self.stopped = Some(result);
            return Err("host_process_exited".into());
        }
        Ok(())
    }
    pub fn stop(&mut self) -> Result<(), String> {
        if let Some(result) = &self.stopped {
            return result.clone();
        }
        if let Some(mut input) = self.input.take() {
            let _ = input.write_all(b"stop\n");
        }
        let result = match self.exited.recv_timeout(Duration::from_secs(90)) {
            Ok(result) => result,
            Err(_) => {
                self.owner.terminate();
                let _ = self.exited.recv_timeout(Duration::from_secs(10));
                Err("host_shutdown_failed".into())
            }
        };
        self.stopped = Some(result.clone());
        result
    }
}
impl Drop for HostProcess {
    fn drop(&mut self) {
        self.input.take();
        if self.stopped.is_none() {
            self.owner.terminate();
            let _ = self.exited.recv_timeout(Duration::from_secs(10));
        }
    }
}
