//! Signed private runtimes; no shell, ambient Python or server-selected executable.
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Artifact {
    sha256: String,
    bytes: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    protocol_version: u32,
    epoch: u64,
    platform: String,
    architecture: String,
    provider: String,
    python: String,
    source_revision: String,
    files: BTreeMap<String, Artifact>,
}

fn digest_valid(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn relative(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() || value.len() > 4096 || value.contains(['\\', ':']) {
        return Err("runtime_path_invalid".into());
    }
    for part in value.split('/') {
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if part.is_empty()
            || matches!(part, "." | "..")
            || part.ends_with(['.', ' '])
            || part.chars().any(char::is_control)
            || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        {
            return Err("runtime_path_invalid".into());
        }
    }
    Ok(PathBuf::from(value))
}
fn no_link(path: &Path) -> Result<fs::Metadata, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "runtime_file_unavailable")?;
    if meta.file_type().is_symlink() {
        return Err("runtime_link_forbidden".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err("runtime_link_forbidden".into());
        }
    }
    Ok(meta)
}
fn absolute_directory(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("runtime_root_invalid".into());
    }
    for ancestor in path.ancestors() {
        if !no_link(ancestor)?.is_dir() {
            return Err("runtime_root_invalid".into());
        }
    }
    Ok(())
}
fn inventory(root: &Path) -> Result<BTreeSet<String>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeSet::new();
    let mut count = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(|_| "runtime_inventory_failed")? {
            count += 1;
            if count > 100_000 {
                return Err("runtime_inventory_limit".into());
            }
            let path = entry.map_err(|_| "runtime_inventory_failed")?.path();
            let meta = no_link(&path)?;
            if meta.is_dir() {
                pending.push(path);
            } else if meta.is_file() {
                let name = path
                    .strip_prefix(root)
                    .map_err(|_| "runtime_path_invalid")?
                    .to_str()
                    .ok_or("runtime_path_invalid")?
                    .replace('\\', "/");
                relative(&name)?;
                files.insert(name);
            } else {
                return Err("runtime_special_file_forbidden".into());
            }
        }
    }
    Ok(files)
}

pub struct VerifiedRuntime {
    root: PathBuf,
    manifest: Manifest,
    manifest_sha256: String,
}
impl VerifiedRuntime {
    /// Trusted keys and rollback floor come from the app/release authority, never the NAS or pack itself.
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
            return Err("runtime_signature_invalid".into());
        }
        let manifest: Manifest =
            serde_json::from_slice(raw).map_err(|_| "runtime_manifest_invalid")?;
        if manifest.schema_version != 1
            || manifest.protocol_version != 1
            || manifest.epoch < minimum_epoch
            || manifest.epoch == 0
            || manifest.platform != std::env::consts::OS
            || manifest.architecture != std::env::consts::ARCH
            || !matches!(
                manifest.provider.as_str(),
                "CPUExecutionProvider"
                    | "CUDAExecutionProvider"
                    | "CoreMLExecutionProvider"
                    | "OpenVINOExecutionProvider"
                    | "MIGraphXExecutionProvider"
            )
            || !digest_valid(&manifest.source_revision, 40)
            || manifest.files.is_empty()
            || manifest.files.len() > 100_000
        {
            return Err("runtime_manifest_incompatible".into());
        }
        relative(&manifest.python)?;
        if !manifest.files.contains_key(&manifest.python) {
            return Err("runtime_interpreter_unapproved".into());
        }
        let verified = Self {
            root: root.to_path_buf(),
            manifest,
            manifest_sha256: format!("{:x}", Sha256::digest(raw)),
        };
        verified.check_files()?;
        Ok(verified)
    }
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
    pub fn provider(&self) -> &str {
        &self.manifest.provider
    }
    fn check_files(&self) -> Result<(), String> {
        absolute_directory(&self.root)?;
        let mut folded = BTreeSet::new();
        let mut total = 0u64;
        for (name, artifact) in &self.manifest.files {
            relative(name)?;
            total = total
                .checked_add(artifact.bytes)
                .ok_or("runtime_size_invalid")?;
            if !folded.insert(name.to_lowercase())
                || !digest_valid(&artifact.sha256, 64)
                || artifact.bytes > 16 * 1024 * 1024 * 1024
                || total > 64 * 1024 * 1024 * 1024
            {
                return Err("runtime_artifact_invalid".into());
            }
        }
        if inventory(&self.root)? != self.manifest.files.keys().cloned().collect() {
            return Err("runtime_inventory_mismatch".into());
        }
        for (name, artifact) in &self.manifest.files {
            let path = self.root.join(relative(name)?);
            let meta = no_link(&path)?;
            if !meta.is_file() || meta.len() != artifact.bytes {
                return Err("runtime_artifact_changed".into());
            }
            let mut file = File::open(path).map_err(|_| "runtime_file_unavailable")?;
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 65536];
            let mut read = 0;
            loop {
                let count = file.read(&mut buffer).map_err(|_| "runtime_read_failed")?;
                if count == 0 {
                    break;
                }
                read += count as u64;
                if read > artifact.bytes {
                    return Err("runtime_artifact_changed".into());
                }
                hasher.update(&buffer[..count]);
            }
            if read != artifact.bytes || format!("{:x}", hasher.finalize()) != artifact.sha256 {
                return Err("runtime_artifact_changed".into());
            }
        }
        Ok(())
    }
}

const START: &[u8] = b"frameleaf-native-start\n";
const GATE: &str = r#"import os,sys,runpy,threading,signal
expected=b'frameleaf-native-start\n'
assert sys.stdin.buffer.read(len(expected))==expected
def lost_parent():
    os.read(sys.stdin.fileno(),1)
    if os.name=='posix':
        os.killpg(os.getpgrp(),signal.SIGKILL)
    os._exit(125)
threading.Thread(target=lost_parent,daemon=True).start()
sys.argv=sys.argv[1:]
runpy.run_module(sys.argv[0],run_name='__main__')
"#;

pub struct NativeSidecar {
    child: std::process::Child,
    tree: crate::process_tree::ProcessTree,
    scratch: PathBuf,
    token: zeroize::Zeroizing<String>,
    stopped: bool,
    exit_status: Option<std::process::ExitStatus>,
}
impl NativeSidecar {
    pub fn working_dir(&self) -> &Path {
        &self.scratch
    }
    pub fn authorization(&self) -> &str {
        self.token.as_str()
    }
    pub fn is_running(&mut self) -> Result<bool, String> {
        if self.stopped {
            return Ok(false);
        }
        if let Some(status) = self
            .child
            .try_wait()
            .map_err(|_| "runtime_process_status_failed")?
        {
            self.tree.terminate();
            self.exit_status = Some(status);
            self.stopped = true;
            return Ok(false);
        }
        Ok(true)
    }
    pub fn stop(&mut self) -> Result<(), String> {
        if !self.stopped {
            self.tree.terminate();
            let _ = self.child.kill();
            self.child
                .wait()
                .map_err(|_| "runtime_process_stop_failed")?;
            self.stopped = true;
        }
        Ok(())
    }
}
impl Drop for NativeSidecar {
    fn drop(&mut self) {
        let _ = self.stop();
        let _ = fs::remove_dir_all(&self.scratch);
    }
}
impl VerifiedRuntime {
    pub fn start_sidecar(
        &self,
        cache: &Path,
        private_root: &Path,
        port: u16,
    ) -> Result<NativeSidecar, String> {
        if port < 1024 {
            return Err("runtime_port_invalid".into());
        }
        self.launch(cache, private_root, Invocation::Serve(port))
    }
    fn launch(
        &self,
        cache: &Path,
        private_root: &Path,
        invocation: Invocation<'_>,
    ) -> Result<NativeSidecar, String> {
        use rand::RngCore;
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        self.check_files()?;
        absolute_directory(cache)?;
        absolute_directory(private_root)?;
        let scratch = private_root.join(format!("inference-{}", uuid::Uuid::new_v4()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&scratch)
            .map_err(|_| "runtime_scratch_failed")?;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let token = zeroize::Zeroizing::new(
            secret
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        zeroize::Zeroize::zeroize(&mut secret);
        let module = match &invocation {
            Invocation::Serve(_) => "immich_ml.native_runtime",
            Invocation::Qualify {
                spec,
                fixture,
                name,
            } => {
                let write = || -> Result<(), String> {
                    write_private(&scratch.join("qualification.json"), spec)?;
                    write_private(&scratch.join(name), fixture)
                };
                if let Err(error) = write() {
                    let _ = fs::remove_dir_all(&scratch);
                    return Err(error);
                }
                "immich_ml.native_qualification"
            }
        };
        let mut command = Command::new(self.root.join(relative(&self.manifest.python)?));
        command
            .env_clear()
            .arg("-I")
            .arg("-B")
            .arg("-c")
            .arg(GATE)
            .arg(module)
            .arg("--cache-dir")
            .arg(cache)
            .current_dir(&scratch)
            .env("FRAMELEAF_ML_AUTH_TOKEN", token.as_str())
            .env("TMPDIR", &scratch)
            .env("TMP", &scratch)
            .env("TEMP", &scratch)
            .env("XDG_CACHE_HOME", scratch.join("cache"))
            .env("HF_HOME", scratch.join("huggingface"))
            .env("TORCH_HOME", scratch.join("torch"))
            .env("HF_HUB_OFFLINE", "1")
            .env("TRANSFORMERS_OFFLINE", "1")
            .env("OMP_NUM_THREADS", "1")
            .env("OPENBLAS_NUM_THREADS", "1")
            .env("MKL_NUM_THREADS", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match invocation {
            Invocation::Serve(port) => {
                command
                    .arg("--port")
                    .arg(port.to_string())
                    .arg("--provider")
                    .arg(self.provider());
            }
            Invocation::Qualify { .. } => {
                command
                    .arg("--spec")
                    .arg(scratch.join("qualification.json"))
                    .arg("--output")
                    .arg(scratch.join("report.json"));
            }
        }
        #[cfg(unix)]
        command.env("PATH", "/usr/bin:/bin");
        #[cfg(windows)]
        {
            // Windows needs its OS directory for platform DLL discovery, never an inherited PATH.
            if let Some(root) = std::env::var_os("SystemRoot") {
                command.env("PATH", Path::new(&root).join("System32"));
                command.env("SystemRoot", root);
            }
        }
        crate::process_tree::configure(&mut command);
        let child = match command.spawn() {
            Ok(value) => value,
            Err(_) => {
                let _ = fs::remove_dir_all(&scratch);
                return Err("runtime_start_failed".into());
            }
        };
        let mut child = child;
        let tree = match crate::process_tree::ProcessTree::attach(&child) {
            Ok(value) => value,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_dir_all(&scratch);
                return Err(error);
            }
        };
        let mut owner = NativeSidecar {
            child,
            tree,
            scratch,
            token,
            stopped: false,
            exit_status: None,
        };
        owner
            .child
            .stdin
            .as_mut()
            .ok_or("runtime_gate_failed")?
            .write_all(START)
            .map_err(|_| "runtime_gate_failed")?;
        Ok(owner)
    }
}

enum Invocation<'a> {
    Serve(u16),
    Qualify {
        spec: &'a [u8],
        fixture: &'a [u8],
        name: &'a str,
    },
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|_| "runtime_fixture_write_failed".into())
}

pub struct QualifiedRuntime {
    report: serde_json::Value,
    manifest_sha256: String,
}
impl QualifiedRuntime {
    pub fn report(&self) -> &serde_json::Value {
        &self.report
    }
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
}
impl VerifiedRuntime {
    /// Blocking operation: worker orchestration runs this outside the UI executor.
    pub fn qualify(
        &self,
        cache: &Path,
        private_root: &Path,
        spec: &[u8],
        fixture: &[u8],
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<QualifiedRuntime, String> {
        use std::{
            sync::atomic::Ordering,
            time::{Duration, Instant},
        };
        if cancel.load(Ordering::Acquire) {
            return Err("runtime_cancelled".into());
        }
        if spec.is_empty()
            || spec.len() > 4 * 1024 * 1024
            || fixture.is_empty()
            || fixture.len() > 16 * 1024 * 1024
        {
            return Err("runtime_qualification_input_invalid".into());
        }
        let value: serde_json::Value =
            serde_json::from_slice(spec).map_err(|_| "runtime_qualification_input_invalid")?;
        let name = value["fixtureFile"]
            .as_str()
            .ok_or("runtime_qualification_input_invalid")?;
        let deadline = value
            .get("deadlineSeconds")
            .map(|v| v.as_u64().unwrap_or(0))
            .unwrap_or(120);
        relative(name)?;
        if name.contains('/')
            || matches!(name, "qualification.json" | "report.json")
            || value["protocolVersion"] != 1
            || value["provider"] != self.provider()
            || value["modelKey"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 256)
                .is_none()
            || value["preprocessingSha256"]
                .as_str()
                .filter(|s| digest_valid(s, 64))
                .is_none()
            || value["fixtureSha256"] != format!("{:x}", Sha256::digest(fixture))
            || !(1..=600).contains(&deadline)
        {
            return Err("runtime_qualification_input_invalid".into());
        }
        let mut child = self.launch(
            cache,
            private_root,
            Invocation::Qualify {
                spec,
                fixture,
                name,
            },
        )?;
        let ends = Instant::now() + Duration::from_secs(deadline);
        while child.is_running()? {
            if cancel.load(Ordering::Acquire) {
                return Err("runtime_cancelled".into());
            }
            if Instant::now() >= ends {
                return Err("runtime_qualification_timeout".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if cancel.load(Ordering::Acquire) {
            return Err("runtime_cancelled".into());
        }
        if !child.exit_status.is_some_and(|status| status.success()) {
            return Err("runtime_qualification_failed".into());
        }
        let path = child.scratch.join("report.json");
        let meta = no_link(&path)?;
        if !meta.is_file() || meta.len() > 4 * 1024 * 1024 {
            return Err("runtime_qualification_report_invalid".into());
        }
        let mut bytes = Vec::new();
        File::open(path)
            .and_then(|file| file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes))
            .map_err(|_| "runtime_qualification_report_invalid")?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("runtime_qualification_report_invalid".into());
        }
        let report: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "runtime_qualification_report_invalid")?;
        validate_report(&report, &value, &format!("{:x}", Sha256::digest(spec)))?;
        self.check_files()?;
        Ok(QualifiedRuntime {
            report,
            manifest_sha256: self.manifest_sha256.clone(),
        })
    }
}
fn validate_report(
    report: &serde_json::Value,
    spec: &serde_json::Value,
    binding: &str,
) -> Result<(), String> {
    let invalid = || String::from("runtime_qualification_report_invalid");
    for field in [
        "modelKey",
        "provider",
        "preprocessingSha256",
        "fixtureSha256",
    ] {
        if report[field] != spec[field] {
            return Err(invalid());
        }
    }
    if report["protocolVersion"] != 1
        || report["bindingSha256"] != binding
        || !report["reason"].is_null()
        || report["runtimeFingerprint"]
            .as_str()
            .filter(|s| digest_valid(s, 64))
            .is_none()
        || !["coldMilliseconds", "warmMilliseconds"].iter().all(|key| {
            report[*key]
                .as_f64()
                .is_some_and(|v| v.is_finite() && (0.0..=600_000.0).contains(&v))
        })
    {
        return Err(invalid());
    }
    let provider = spec["provider"].as_str().ok_or_else(invalid)?;
    if !matches!(provider, "CPUExecutionProvider" | "CUDAExecutionProvider") {
        return Err(invalid());
    }
    let execution = report["execution"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 64)
        .ok_or_else(invalid)?;
    let mut mixed = false;
    for item in execution {
        let nodes = item["nodes"].as_object().ok_or_else(invalid)?;
        if !item["reason"].is_null()
            || nodes
                .get(provider)
                .and_then(|v| v.as_u64())
                .is_none_or(|n| n == 0)
            || nodes.iter().any(|(key, v)| {
                (key != provider && key != "CPUExecutionProvider")
                    || !v.as_u64().is_some_and(|n| n > 0 && n <= 200_000)
            })
        {
            return Err(invalid());
        }
        let state = if provider == "CPUExecutionProvider" {
            "ready-cpu"
        } else if nodes.contains_key("CPUExecutionProvider") {
            mixed = true;
            "ready-mixed"
        } else {
            "ready-accelerator"
        };
        if item["state"] != state {
            return Err(invalid());
        }
    }
    let state = if provider == "CPUExecutionProvider" {
        "ready-cpu"
    } else if mixed {
        "ready-mixed"
    } else {
        "ready-accelerator"
    };
    if report["state"] != state {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn python_gate_allows_normal_qualification_process_exit() {
        use std::{
            io::Write,
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let mut command = Command::new(if cfg!(windows) { "python" } else { "python3" });
        command
            .args(["-I", "-B", "-c", GATE, "this"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        crate::process_tree::configure(&mut command);
        let mut child = command.spawn().unwrap();
        let tree = crate::process_tree::ProcessTree::attach(&child).unwrap();
        child.stdin.as_mut().unwrap().write_all(START).unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if Instant::now() >= end {
                tree.terminate();
                let _ = child.wait();
                panic!("normal Python exit hung");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    fn python_gate_terminates_when_parent_pipe_closes() {
        use std::{
            io::Write,
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let mut command = Command::new(if cfg!(windows) { "python" } else { "python3" });
        command
            .args([
                "-I",
                "-B",
                "-c",
                GATE,
                "http.server",
                "--bind",
                "127.0.0.1",
                "0",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        crate::process_tree::configure(&mut command);
        let mut child = command.spawn().expect("CI Python required for gate test");
        let tree = crate::process_tree::ProcessTree::attach(&child).unwrap();
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(START).unwrap();
        drop(pipe);
        let end = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= end {
                tree.terminate();
                let _ = child.wait();
                panic!("parent pipe guardian failed");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(!status.success());
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(libc::SIGKILL));
        }
        #[cfg(windows)]
        assert_eq!(status.code(), Some(125));
    }
}
