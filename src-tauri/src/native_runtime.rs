//! Signed private runtimes; no shell, ambient Python or server-selected executable.
mod metal;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Artifact {
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
}
#[derive(Clone, Copy, Default, Deserialize)]
enum ModuleNamespace {
    #[default]
    #[serde(rename = "immich_ml")]
    Immich,
    #[serde(rename = "frameleaf_ml")]
    Frameleaf,
}
impl ModuleNamespace {
    fn prefix(self) -> &'static str {
        match self {
            Self::Immich => "immich_ml",
            Self::Frameleaf => "frameleaf_ml",
        }
    }
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
    #[serde(default)]
    module_namespace: ModuleNamespace,
    #[serde(default)]
    device_observer: Option<metal::Descriptor>,
    files: BTreeMap<String, Artifact>,
}

pub(crate) fn digest_valid(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn relative(value: &str) -> Result<PathBuf, String> {
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
pub(crate) fn absolute_directory(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("runtime_root_invalid".into());
    }
    #[cfg(windows)]
    if let Some(parts) = path
        .to_str()
        .and_then(crate::windows_protection::filesystem_components)
    {
        for part in parts {
            if !no_link(Path::new(part))?.is_dir() {
                return Err("runtime_root_invalid".into());
            }
        }
        return Ok(());
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
        metal::validate(&manifest)?;
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
    pub(crate) fn epoch(&self) -> u64 {
        self.manifest.epoch
    }
    /// `share` is the payload of an installed release with the same files (the processor and
    /// accelerated manifests of one pack): its files are linked instead of copied again. The
    /// caller verifies every byte of the result against this manifest either way.
    pub(crate) fn copy_payload(
        &self,
        destination: &Path,
        share: Option<&Path>,
    ) -> Result<(), String> {
        self.check_files()?;
        for (name, artifact) in &self.manifest.files {
            let source = self.root.join(relative(name)?);
            let target = destination.join(relative(name)?);
            fs::create_dir_all(target.parent().ok_or("runtime_path_invalid")?)
                .map_err(|_| "runtime_copy_failed")?;
            if let Some(share) = share {
                let shared = share.join(relative(name)?);
                if no_link(&shared).is_ok_and(|meta| meta.is_file() && meta.len() == artifact.bytes)
                    && fs::hard_link(&shared, &target).is_ok()
                {
                    continue;
                }
            }
            let metadata = no_link(&source)?;
            let input = File::open(source).map_err(|_| "runtime_copy_failed")?;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut output = options.open(&target).map_err(|_| "runtime_copy_failed")?;
            let copied = std::io::copy(&mut input.take(artifact.bytes + 1), &mut output)
                .map_err(|_| "runtime_copy_failed")?;
            if copied != artifact.bytes {
                return Err("runtime_artifact_changed".into());
            }
            output.sync_all().map_err(|_| "runtime_copy_failed")?;
            fs::set_permissions(target, metadata.permissions())
                .map_err(|_| "runtime_copy_failed")?;
        }
        self.check_files()
    }
    pub fn provider(&self) -> &str {
        &self.manifest.provider
    }
    pub fn source_revision(&self) -> &str {
        &self.manifest.source_revision
    }
    /// FL-1760: this pack's FFmpeg, when its signed list has one. Packs released before it don't.
    pub(crate) fn ffmpeg(&self) -> Option<PackFfmpeg> {
        PackFfmpeg::from_files(&self.root, &self.manifest.files)
    }
    /// Every byte once per launch; after that, a file whose metadata changed is hashed again.
    fn check_files(&self) -> Result<(), String> {
        check_files_remembered(
            &VERIFIED_RUNTIMES,
            &self.root,
            &self.manifest_sha256,
            &self.manifest.files,
            std::time::SystemTime::now(),
        )
        .map(|_| ())
    }
}

const FFMPEG_FOLDER: &str = "media-tools";
/// The encoder of a verified pack. The manifest gains no field for it, so apps already released
/// still accept a pack that carries it.
pub(crate) struct PackFfmpeg {
    root: PathBuf,
    executable: String,
    files: BTreeMap<String, Artifact>,
    /// Keeps the release from being replaced while this is in use.
    lease: Option<std::sync::Arc<File>>,
}
impl PackFfmpeg {
    fn from_files(root: &Path, files: &BTreeMap<String, Artifact>) -> Option<Self> {
        let name = if cfg!(windows) {
            "ffmpeg.exe"
        } else {
            "ffmpeg"
        };
        let executable = format!("{FFMPEG_FOLDER}/{name}");
        files.contains_key(&executable).then(|| Self {
            root: root.to_path_buf(),
            executable,
            files: files
                .iter()
                .filter(|(name, _)| Path::new(name).starts_with(FFMPEG_FOLDER))
                .map(|(name, artifact)| (name.clone(), artifact.clone()))
                .collect(),
            lease: None,
        })
    }
    pub(crate) fn holding(mut self, lease: std::sync::Arc<File>) -> Self {
        self.lease = Some(lease);
        self
    }
    /// The program to run, with its folder read again against the signed list.
    pub(crate) fn check(&self) -> Result<PathBuf, String> {
        for (name, artifact) in &self.files {
            verify_file(&self.root, name, artifact)?;
        }
        Ok(self.root.join(relative(&self.executable)?))
    }
}

/// A file newer than this when its hash began may still change within one timestamp tick, so it
/// is not remembered as verified. Two seconds also covers the coarsest common filesystem clock.
const STAMP_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);

/// What the filesystem says about a file. A different stamp means it must be hashed again.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct FileStamp {
    bytes: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    changed: (i64, i64),
    #[cfg(unix)]
    identity: (u64, u64),
    #[cfg(windows)]
    created: u64,
    #[cfg(windows)]
    attributes: u32,
}
impl FileStamp {
    /// `None` for anything but a plain file: a link or reparse point is never remembered.
    pub(crate) fn read(path: &Path) -> Option<Self> {
        let meta = no_link(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        #[cfg(windows)]
        use std::os::windows::fs::MetadataExt;
        Some(Self {
            bytes: meta.len(),
            modified: meta.modified().ok()?,
            #[cfg(unix)]
            changed: (meta.ctime(), meta.ctime_nsec()),
            #[cfg(unix)]
            identity: (meta.dev(), meta.ino()),
            #[cfg(windows)]
            created: meta.creation_time(),
            #[cfg(windows)]
            attributes: meta.file_attributes(),
        })
    }
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }
    /// Whether the file was already at rest when a hash that began at `started` read it.
    pub(crate) fn settled(&self, started: std::time::SystemTime) -> bool {
        #[cfg(unix)]
        let latest = match u64::try_from(self.changed.0) {
            Ok(seconds) => self.modified.max(
                std::time::UNIX_EPOCH
                    + std::time::Duration::new(
                        seconds,
                        self.changed.1.clamp(0, 999_999_999) as u32,
                    ),
            ),
            Err(_) => return false,
        };
        #[cfg(not(unix))]
        let latest = self.modified;
        started
            .duration_since(latest)
            .is_ok_and(|age| age >= STAMP_SETTLE)
    }
}

type RememberedRuntimes =
    std::sync::Mutex<std::collections::HashMap<(PathBuf, String), Vec<FileStamp>>>;
/// Kept in memory only, so each launch of the app hashes every runtime file at least once.
static VERIFIED_RUNTIMES: std::sync::LazyLock<RememberedRuntimes> =
    std::sync::LazyLock::new(Default::default);

/// The stamps of exactly the manifest's files, or `None` when the folder no longer matches it.
fn runtime_stamps(root: &Path, files: &BTreeMap<String, Artifact>) -> Option<Vec<FileStamp>> {
    absolute_directory(root).ok()?;
    if inventory(root).ok()? != files.keys().cloned().collect::<BTreeSet<_>>() {
        return None;
    }
    files
        .iter()
        .map(|(name, artifact)| {
            let stamp = FileStamp::read(&root.join(relative(name).ok()?))?;
            (stamp.bytes() == artifact.bytes).then_some(stamp)
        })
        .collect()
}

/// Returns whether the files were hashed. Anything unexpected takes the full check, which also
/// names what is wrong. `now` is read before hashing, so a change during the hash is not trusted.
fn check_files_remembered(
    remembered: &RememberedRuntimes,
    root: &Path,
    manifest_sha256: &str,
    files: &BTreeMap<String, Artifact>,
    now: std::time::SystemTime,
) -> Result<bool, String> {
    let key = (root.to_path_buf(), manifest_sha256.to_owned());
    let before = runtime_stamps(root, files);
    {
        let mut known = remembered.lock().unwrap_or_else(|error| error.into_inner());
        if before.is_some() && known.get(&key) == before.as_ref() {
            return Ok(false);
        }
        known.remove(&key);
    }
    verify_files(root, files)?;
    if let Some(before) = before {
        if before.iter().all(|stamp| stamp.settled(now))
            && runtime_stamps(root, files).as_ref() == Some(&before)
        {
            remembered
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(key, before);
        }
    }
    Ok(true)
}

pub(crate) fn verify_files(root: &Path, files: &BTreeMap<String, Artifact>) -> Result<(), String> {
    absolute_directory(root)?;
    let mut folded = BTreeSet::new();
    let mut total = 0u64;
    for (name, artifact) in files {
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
    if inventory(root)? != files.keys().cloned().collect() {
        return Err("runtime_inventory_mismatch".into());
    }
    for (name, artifact) in files {
        verify_file(root, name, artifact)?;
    }
    Ok(())
}
/// One listed file, read again: no link, the listed size and the listed digest.
pub(crate) fn verify_file(root: &Path, name: &str, artifact: &Artifact) -> Result<(), String> {
    let path = root.join(relative(name)?);
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
    Ok(())
}

const START: &[u8] = b"frameleaf-native-start\n";
/// FD-71: on Windows the watch for a lost parent must never sit in a read of the pipe. The C
/// runtime holds its lock on descriptor 0 for as long as a read of it is pending, and every other
/// use of that descriptor in the process (`lseek`, `fstat`, a library setting up its standard
/// streams as it loads) then waits for a read that never ends. onnxruntime's native module did
/// exactly that while loading, under the loader lock, so the runtime could not even exit: every
/// Windows runtime start hung importing onnxruntime and qualification timed out. There the pipe
/// is looked at instead, which returns at once, until the parent's end closes or writes.
const GATE: &str = r#"import os,sys,runpy,threading,signal,time
expected=b'frameleaf-native-start\n'
assert sys.stdin.buffer.read(len(expected))==expected
def lost_parent():
    if os.name=='nt':
        import msvcrt,_winapi
        pipe=msvcrt.get_osfhandle(sys.stdin.fileno())
        while True:
            try:
                if _winapi.PeekNamedPipe(pipe,0)[0]:
                    break
            except OSError:
                break
            time.sleep(0.2)
    else:
        os.read(sys.stdin.fileno(),1)
    if os.name=='posix':
        os.killpg(os.getpgrp(),signal.SIGKILL)
    os._exit(125)
threading.Thread(target=lost_parent,daemon=True).start()
sys.argv=sys.argv[1:]
if sys.argv[0]=='frameleaf-desktop-metal-v1':
    parent,expected_hash,mode=sys.argv[1:4]
    sys.argv=[mode]+sys.argv[4:]
    sys.path.insert(0,parent)
    from frameleaf_desktop_ml.entry import run
    run(mode,expected_hash)
else:
    runpy.run_module(sys.argv[0],run_name='__main__',alter_sys=True)
"#;

/// Held under an exclusive lock for as long as a process owns an inference scratch, so pruning
/// can tell an abandoned scratch from one in use (also by another instance of the app).
pub(crate) const SCRATCH_OWNER: &str = ".owner";
const SCRATCH_OWNER_PENDING: &str = ".owner-pending";
fn own_scratch(scratch: &Path) -> Result<File, String> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // The owner record appears under its name only once its lock is held: pruning in another
    // instance of the app must never see an unlocked owner of a scratch that is in use. Until the
    // rename the scratch has no owner record, which pruning keeps for a week.
    let pending = scratch.join(SCRATCH_OWNER_PENDING);
    // A scratch is created for one sidecar; an owner record already there is never replaced.
    if fs::symlink_metadata(scratch.join(SCRATCH_OWNER)).is_ok() {
        return Err("runtime_scratch_failed".into());
    }
    let owner = options
        .open(&pending)
        .map_err(|_| "runtime_scratch_failed")?;
    owner.try_lock().map_err(|_| "runtime_scratch_failed")?;
    fs::rename(&pending, scratch.join(SCRATCH_OWNER)).map_err(|_| "runtime_scratch_failed")?;
    Ok(owner)
}

pub struct NativeSidecar {
    child: std::process::Child,
    tree: crate::process_tree::ProcessTree,
    scratch: PathBuf,
    token: zeroize::Zeroizing<String>,
    stopped: bool,
    exit_status: Option<std::process::ExitStatus>,
    lease: Option<std::sync::Arc<File>>,
    /// Released before the scratch is removed.
    owner: Option<File>,
    /// The last lines the process wrote to its error stream.
    stderr: StderrTail,
}
/// The kept lines, and whether the stream has been read to its end.
type StderrTail = (
    std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
);
const STDERR_LINES: usize = 12;
const STDERR_LINE_LENGTH: usize = 240;
/// Keep the tail of a process's error stream, so a crash can say why. The thread ends when the
/// process closes the stream, which it does by exiting.
fn keep_stderr_tail(mut stream: impl std::io::Read + Send + 'static) -> StderrTail {
    let tail = std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
    let drained = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (kept, done) = (tail.clone(), drained.clone());
    std::thread::spawn(move || {
        let keep = |line: &[u8]| {
            let text = String::from_utf8_lossy(line);
            let text: String = text
                .trim_end()
                .chars()
                .filter(|c| !c.is_control())
                .take(STDERR_LINE_LENGTH)
                .collect();
            if text.is_empty() {
                return;
            }
            let mut kept = kept.lock().unwrap();
            if kept.len() == STDERR_LINES {
                kept.pop_front();
            }
            kept.push_back(text);
        };
        // Read in small pieces and keep only the start of each line: a line of any length
        // (a diagnostic with no newline) costs no more memory than a short one.
        let (mut piece, mut line) = ([0u8; 4096], Vec::with_capacity(STDERR_LINE_LENGTH * 4));
        loop {
            let count = match stream.read(&mut piece) {
                Ok(0) => break,
                Ok(count) => count,
                // Interrupted by a signal, not ended: read again.
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            for &byte in &piece[..count] {
                if byte == b'\n' {
                    keep(&line);
                    line.clear();
                } else if line.len() < STDERR_LINE_LENGTH * 4 {
                    line.push(byte);
                }
            }
        }
        keep(&line);
        done.store(true, std::sync::atomic::Ordering::Release);
    });
    (tail, drained)
}
impl NativeSidecar {
    /// Why the process ended by itself: its exit status and the last lines of its error stream.
    /// `None` while it runs, and when this app stopped it.
    pub(crate) fn exit_report(&mut self) -> Option<String> {
        let _ = self.is_running();
        let status = self.exit_status?;
        // The process is gone; its last lines may still be on their way through the pipe.
        // Briefly, and no longer: something it started may still hold the pipe open.
        for _ in 0..20 {
            if self.stderr.1.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let lines = self.stderr.0.lock().unwrap();
        let tail: Vec<&str> = lines.iter().map(String::as_str).collect();
        Some(if tail.is_empty() {
            status.to_string()
        } else {
            format!("{status}: {}", tail.join(" | "))
        })
    }
    pub(crate) fn hold_lease(&mut self, lease: std::sync::Arc<File>) {
        self.lease = Some(lease);
    }
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
            // A process that had already ended by itself keeps its own exit status.
            if let Ok(Some(status)) = self.child.try_wait() {
                self.exit_status = Some(status);
            }
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
        drop(self.owner.take());
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
        self.launch(
            cache,
            private_root,
            Invocation::Serve {
                port,
                qualified: &[],
                threads: 1,
            },
        )
    }
    pub fn start_qualified_sidecar(
        &self,
        qualified: &QualifiedRuntime,
        cache: &Path,
        private_root: &Path,
        port: u16,
    ) -> Result<NativeSidecar, String> {
        self.start_bound_sidecar(&[qualified], cache, private_root, port)
    }
    pub fn start_bound_sidecar(
        &self,
        qualified: &[&QualifiedRuntime],
        cache: &Path,
        private_root: &Path,
        port: u16,
    ) -> Result<NativeSidecar, String> {
        self.start_bound_sidecar_threads(qualified, cache, private_root, port, 1)
    }
    /// As `start_bound_sidecar`, serving up to `threads` requests at once (one, when the
    /// worker runs one task at a time).
    pub(crate) fn start_bound_sidecar_threads(
        &self,
        qualified: &[&QualifiedRuntime],
        cache: &Path,
        private_root: &Path,
        port: u16,
        threads: u32,
    ) -> Result<NativeSidecar, String> {
        if !(1..=64).contains(&qualified.len())
            || port < 1024
            || qualified
                .iter()
                .any(|item| item.manifest_sha256 != self.manifest_sha256)
        {
            return Err("runtime_qualification_binding_invalid".into());
        }
        let threads = threads.clamp(1, 64);
        self.launch(
            cache,
            private_root,
            Invocation::Serve {
                port,
                qualified,
                threads,
            },
        )
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
        crate::runtime_store::create_private_directory(&scratch)?;
        let owner = match own_scratch(&scratch) {
            Ok(owner) => owner,
            Err(error) => {
                let _ = fs::remove_dir_all(&scratch);
                return Err(error);
            }
        };
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
            Invocation::Serve { qualified, .. } => {
                let write = || -> Result<(), String> {
                    for (index, item) in qualified.iter().enumerate() {
                        write_private(
                            &scratch.join(format!("qualification-{index}.json")),
                            &item.spec,
                        )?;
                        let report = serde_json::to_vec(&item.report)
                            .map_err(|_| "runtime_qualification_report_invalid")?;
                        write_private(&scratch.join(format!("report-{index}.json")), &report)?;
                    }
                    Ok(())
                };
                if let Err(error) = write() {
                    let _ = fs::remove_dir_all(&scratch);
                    return Err(error);
                }
                "native_runtime"
            }
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
                "native_qualification"
            }
        };
        let mut command = Command::new(self.root.join(relative(&self.manifest.python)?));
        command
            .env_clear()
            .arg("-I")
            .arg("-B")
            .arg("-c")
            .arg(GATE)
            .args(metal::arguments(&self.manifest, &self.root, module)?)
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
            .env("MACHINE_LEARNING_MODEL_INTRA_OP_THREADS", "4")
            .env("MACHINE_LEARNING_MODEL_INTER_OP_THREADS", "1")
            .env(
                "MACHINE_LEARNING_REQUEST_THREADS",
                match &invocation {
                    // As many requests at once as the worker runs tasks at once.
                    Invocation::Serve { threads, .. } => threads.to_string(),
                    Invocation::Qualify { .. } => "1".into(),
                },
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        match invocation {
            Invocation::Serve {
                port, qualified, ..
            } => {
                if qualified.len() > 1 {
                    // Older signed runtimes must reject this invocation rather than use only the last pair.
                    command.arg("--binding-set");
                }
                for index in 0..qualified.len() {
                    command
                        .arg("--spec")
                        .arg(scratch.join(format!("qualification-{index}.json")))
                        .arg("--qualification-report")
                        .arg(scratch.join(format!("report-{index}.json")));
                }
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
                let mut folders = Vec::new();
                for folder in device_library_folders(
                    self.provider(),
                    self.manifest.files.keys().map(String::as_str),
                ) {
                    folders.push(self.root.join(relative(&folder)?));
                }
                let program_files = crate::host_install::windows_program_files()?;
                command.envs(windows_environment(
                    &root,
                    &scratch,
                    &folders,
                    program_files.as_os_str(),
                )?);
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
        let stderr = child
            .stderr
            .take()
            .map(keep_stderr_tail)
            .unwrap_or_default();
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
            lease: None,
            owner: Some(owner),
            stderr,
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

/// FD-63: the folders of a CUDA pack that hold the NVIDIA wheels' Windows libraries
/// (`.../site-packages/nvidia/<component>/bin`), relative to the payload.
///
/// onnxruntime opens a fixed list of them by full path before a session is created. The rest are
/// opened later by name, by NVIDIA's own libraries: cuDNN's convolution library, the run-time
/// compiler cuDNN and cuFFT use, cuFFT's linker. Windows looks for a library named that way in
/// the program's folder, the OS directory and `PATH`, none of which is inside the pack.
#[cfg(any(windows, test))]
fn device_library_folders<'a>(
    provider: &str,
    files: impl Iterator<Item = &'a str>,
) -> BTreeSet<String> {
    let mut folders = BTreeSet::new();
    if provider != "CUDAExecutionProvider" {
        return folders;
    }
    for name in files {
        let parts: Vec<&str> = name.split('/').collect();
        let count = parts.len();
        if count >= 5
            && parts[count - 1].to_ascii_lowercase().ends_with(".dll")
            && parts[count - 2] == "bin"
            && parts[count - 4] == "nvidia"
            && parts[count - 5] == "site-packages"
        {
            folders.insert(parts[..count - 1].join("/"));
        }
    }
    folders
}

/// What a runtime process gets on Windows besides the variables every platform sets.
///
/// `PATH`: the OS directory, then (FD-63) the pack's own NVIDIA library folders, signed and
/// verified before this point; never an inherited `PATH`. `USERPROFILE` (FD-63): the runtime's
/// settings name a default folder under the home directory when they are imported, and Python on
/// Windows has no home directory without this variable, so the import failed and nothing
/// qualified. The process's own scratch stands in; the user's profile stays out of reach.
/// `ProgramFiles` and `ProgramW6432`: NVML, which `nvidia-smi` uses and through which
/// the runtime learns there is a card, finds itself through them. Without them `nvidia-smi`
/// ends with "Failed to initialize NVML: Unknown Error", the runtime reports no card, and every
/// CUDA qualification is refused (`native_device_execution_evidence_required`) on a computer
/// whose CUDA works. The OS's registered folder is given, never an inherited value.
#[cfg(any(windows, test))]
fn windows_environment(
    system_root: &std::ffi::OsStr,
    scratch: &Path,
    library_folders: &[PathBuf],
    program_files: &std::ffi::OsStr,
) -> Result<[(&'static str, std::ffi::OsString); 5], String> {
    let mut search = vec![Path::new(system_root).join("System32")];
    search.extend(library_folders.iter().cloned());
    Ok([
        (
            "PATH",
            std::env::join_paths(search).map_err(|_| "runtime_path_invalid")?,
        ),
        ("SystemRoot", system_root.to_owned()),
        ("USERPROFILE", scratch.as_os_str().to_owned()),
        ("ProgramFiles", program_files.to_owned()),
        ("ProgramW6432", program_files.to_owned()),
    ])
}

enum Invocation<'a> {
    Serve {
        port: u16,
        qualified: &'a [&'a QualifiedRuntime],
        /// How many requests the process serves at once.
        threads: u32,
    },
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
    spec: Vec<u8>,
    report: serde_json::Value,
    manifest_sha256: String,
}
impl QualifiedRuntime {
    pub(crate) fn specification(&self) -> &[u8] {
        &self.spec
    }
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
        let mut refused = None;
        self.qualify_explained(cache, private_root, spec, fixture, cancel, &mut refused)
            .map_err(|code| qualification_failure(code, refused.as_deref()))
    }
    /// `qualify`, also handing back what a refusing process wrote as its reason (`refusal`), so
    /// FD-63's hardware evidence can tell the runtime's own refusal from a process that crashed
    /// or wrote nothing: both are `runtime_qualification_failed` to the caller.
    pub(crate) fn qualify_explained(
        &self,
        cache: &Path,
        private_root: &Path,
        spec: &[u8],
        fixture: &[u8],
        cancel: &std::sync::atomic::AtomicBool,
        refused: &mut Option<String>,
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
        let qwen_binary = if value["engine"] == "qwen-gguf" {
            let mut candidates = self.manifest.files.iter().filter(|(path, _)| {
                match self.manifest.platform.as_str() {
                    "windows" => {
                        path.as_str()
                            == "python/Lib/site-packages/frameleaf_ml/native-bin/llama-server.exe"
                    }
                    "macos" | "linux" => {
                        path.starts_with("python/lib/python")
                            && path.ends_with("/site-packages/frameleaf_ml/native-bin/llama-server")
                    }
                    _ => false,
                }
            });
            let (_, artifact) = candidates.next().ok_or("runtime_qwen_binary_unavailable")?;
            if candidates.next().is_some() {
                return Err("runtime_qwen_binary_unavailable".into());
            }
            Some(artifact.sha256.as_str())
        } else {
            None
        };
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
            // FD-56: the process leaves its reason in the report it could not pass. Say it, so
            // a refusal is never silent; the code the caller acts on stays the same.
            *refused = refusal(&child.scratch.join("report.json"));
            if let Some(why) = refused {
                eprintln!("runtime qualification refused: {why}");
            }
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
        validate_report(
            &report,
            &value,
            &format!("{:x}", Sha256::digest(spec)),
            self.provider(),
            metal::collector_hash(&self.manifest),
            qwen_binary,
        )?;
        self.check_files()?;
        Ok(QualifiedRuntime {
            spec: spec.to_vec(),
            report,
            manifest_sha256: self.manifest_sha256.clone(),
        })
    }
}
/// The specific reason for a failed known-answer check, from the reason the runtime wrote, so the
/// person sees "wrong answer" or "out of memory" instead of a general failure. Anything else stays
/// `runtime_qualification_failed`.
pub(crate) fn qualification_failure(code: String, refused: Option<&str>) -> String {
    if code != "runtime_qualification_failed" {
        return code;
    }
    let Some(refused) = refused else {
        return code;
    };
    let (reason, detail) = refused.split_once(' ').unwrap_or((refused, ""));
    match reason {
        "native_output_value_mismatch"
        | "native_output_shape_mismatch"
        | "native_output_schema_mismatch" => "runtime_output_mismatch",
        "native_memory_insufficient" => "runtime_out_of_memory",
        "native_staged_model_unavailable" | "native_staged_hash_mismatch" => {
            "runtime_model_missing"
        }
        "native_provider_unavailable"
        | "native_provider_execution_unproven"
        | "native_device_execution_evidence_required" => "runtime_provider_unavailable",
        // ONNX Runtime and Python name an allocation failure only in the detail.
        _ if [
            "MemoryError",
            "Failed to allocate",
            "out of memory",
            "bad_alloc",
        ]
        .iter()
        .any(|text| detail.contains(text)) =>
        {
            "runtime_out_of_memory"
        }
        _ => return code,
    }
    .into()
}

/// Why a qualification process refused: the code, and the short detail, in the report it left.
/// For a person reading the log only: never trusted, never sent anywhere.
fn refusal(report: &Path) -> Option<String> {
    let raw = crate::runtime_store::read_bounded(report, 64 * 1024).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let reason = value["reason"].as_str().filter(|reason| {
        !reason.is_empty()
            && reason.len() <= 128
            && reason.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    })?;
    let detail: String = value["detail"]
        .as_str()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(500)
        .collect();
    Some(format!("{reason} {detail}").trim_end().to_owned())
}

/// `runtime_provider` is the one provider the installed runtime's signed manifest declares, and
/// `expected_collector` the device collector that manifest carries (CoreML only).
fn validate_report(
    report: &serde_json::Value,
    spec: &serde_json::Value,
    binding: &str,
    runtime_provider: &str,
    expected_collector: Option<&str>,
    qwen_binary: Option<&str>,
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
    {
        return Err(invalid());
    }
    if spec["engine"] == "qwen-gguf" {
        let binary = qwen_binary
            .filter(|hash| digest_valid(hash, 64))
            .ok_or_else(invalid)?;
        let execution = report["qwenExecution"].as_object().ok_or_else(invalid)?;
        let build = execution
            .get("build")
            .and_then(|item| item.as_str())
            .ok_or_else(invalid)?;
        let (number, revision) = build
            .strip_prefix('b')
            .and_then(|item| item.split_once('-'))
            .ok_or_else(invalid)?;
        if report["engine"] != "qwen-gguf"
            || spec["provider"] != "CPUExecutionProvider"
            || runtime_provider != "CPUExecutionProvider"
            || expected_collector.is_some()
            || report["state"] != "ready-cpu"
            || execution.len() != 3
            || execution.get("binarySha256").and_then(|item| item.as_str()) != Some(binary)
            || number.is_empty()
            || !number.bytes().all(|byte| byte.is_ascii_digit())
            || !revision.starts_with("7fe450e19")
            || revision.len() > 40
            || !digest_valid(revision, revision.len())
            || !execution
                .get("coldMilliseconds")
                .and_then(|item| item.as_array())
                .is_some_and(|samples| {
                    samples.len() == 2
                        && samples.iter().all(|sample| {
                            sample
                                .as_f64()
                                .is_some_and(|value| (0.0..=600_000.0).contains(&value))
                        })
                })
        {
            return Err(invalid());
        }
        return Ok(());
    }
    if spec.get("engine").is_some_and(|engine| engine != "onnx")
        || report.get("engine").is_some_and(|engine| engine != "onnx")
        || !["coldMilliseconds", "warmMilliseconds"].iter().all(|key| {
            report[*key]
                .as_f64()
                .is_some_and(|v| v.is_finite() && (0.0..=600_000.0).contains(&v))
        })
    {
        return Err(invalid());
    }
    let provider = spec["provider"].as_str().ok_or_else(invalid)?;
    // The providers a runtime profile can declare (server `runtime-profiles.json`), and only the
    // one this runtime was signed for.
    if provider != runtime_provider
        || !matches!(
            provider,
            "CPUExecutionProvider"
                | "CUDAExecutionProvider"
                | "CoreMLExecutionProvider"
                | "OpenVINOExecutionProvider"
        )
    {
        return Err(invalid());
    }
    // CoreML can keep work on the processor inside its own nodes, so it never reports
    // accelerator-only execution (the runtime and the server use the same rule).
    let always_mixed = provider == "CoreMLExecutionProvider";
    // The server refuses a CoreML report without the signed collector's device proof, and any
    // other report that carries one; refuse the same here instead of submitting it.
    if always_mixed {
        metal::validate_report(report, spec, expected_collector.ok_or_else(invalid)?)?;
    } else if expected_collector.is_some() || !report["deviceExecution"].is_null() {
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
        } else if always_mixed || nodes.contains_key("CPUExecutionProvider") {
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
mod remembered_file_tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> (Fixture, BTreeMap<String, Artifact>) {
        let root = std::env::temp_dir().join(format!("frameleaf-stamps-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(&root).unwrap_or(root);
        // `canonicalize` gives a `\\?\` path on Windows, which every check here accepts.
        fs::write(root.join("a.bin"), b"hello").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(root.join("a.bin"))
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        let files = BTreeMap::from([(
            "a.bin".to_owned(),
            Artifact {
                sha256: format!("{:x}", Sha256::digest(b"hello")),
                bytes: 5,
            },
        )]);
        (Fixture(root), files)
    }
    /// Far enough ahead that even a just-written file's change time has settled.
    fn later() -> SystemTime {
        SystemTime::now() + Duration::from_secs(60)
    }

    #[test]
    fn a_runtime_is_hashed_once_until_a_file_changes() {
        let (root, files) = fixture();
        let known = RememberedRuntimes::default();
        let check = |now| check_files_remembered(&known, &root.0, "manifest", &files, now);
        assert_eq!(check(later()), Ok(true));
        assert_eq!(check(later()), Ok(false));
        // The same length, so only the metadata can give it away before hashing.
        fs::write(root.0.join("a.bin"), b"jello").unwrap();
        assert_eq!(check(later()), Err("runtime_artifact_changed".to_owned()));
        assert_eq!(check(later()), Err("runtime_artifact_changed".to_owned()));
    }

    #[test]
    fn a_file_added_to_a_remembered_runtime_is_refused() {
        let (root, files) = fixture();
        let known = RememberedRuntimes::default();
        let check = || check_files_remembered(&known, &root.0, "manifest", &files, later());
        assert_eq!(check(), Ok(true));
        fs::write(root.0.join("extra.bin"), b"x").unwrap();
        assert_eq!(check(), Err("runtime_inventory_mismatch".to_owned()));
    }

    #[test]
    fn another_manifest_over_the_same_folder_is_hashed_for_itself() {
        let (root, files) = fixture();
        let known = RememberedRuntimes::default();
        assert_eq!(
            check_files_remembered(&known, &root.0, "first", &files, later()),
            Ok(true)
        );
        assert_eq!(
            check_files_remembered(&known, &root.0, "second", &files, later()),
            Ok(true)
        );
    }

    #[test]
    fn a_file_written_moments_before_its_hash_is_not_remembered() {
        let (root, files) = fixture();
        fs::write(root.0.join("a.bin"), b"hello").unwrap();
        let known = RememberedRuntimes::default();
        let now = SystemTime::now();
        assert_eq!(
            check_files_remembered(&known, &root.0, "manifest", &files, now),
            Ok(true)
        );
        assert_eq!(
            check_files_remembered(&known, &root.0, "manifest", &files, now),
            Ok(true)
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_pack_without_ffmpeg_has_none_and_one_with_it_is_read_against_its_signed_list() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("frameleaf-pack-ffmpeg-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("media-tools")).unwrap();
        let name = if cfg!(windows) {
            "media-tools/ffmpeg.exe"
        } else {
            "media-tools/ffmpeg"
        };
        let listed = |bytes: &[u8]| Artifact {
            sha256: format!("{:x}", Sha256::digest(bytes)),
            bytes: bytes.len() as u64,
        };
        fs::write(root.join(name), b"encoder").unwrap();
        fs::write(root.join("media-tools/FFMPEG-LICENSE.txt"), b"licence").unwrap();
        fs::write(root.join("python"), b"interpreter").unwrap();

        // Every pack released so far: a stray file the manifest does not list counts for nothing.
        let released = BTreeMap::from([("python".to_string(), listed(b"interpreter"))]);
        assert!(PackFfmpeg::from_files(&root, &released).is_none());

        let mut files = released;
        files.insert(name.to_string(), listed(b"encoder"));
        files.insert(
            "media-tools/FFMPEG-LICENSE.txt".to_string(),
            listed(b"licence"),
        );
        let ffmpeg = PackFfmpeg::from_files(&root, &files).unwrap();
        assert_eq!(ffmpeg.files.len(), 2);
        assert_eq!(ffmpeg.check().unwrap(), root.join(name));

        fs::write(root.join("media-tools/FFMPEG-LICENSE.txt"), b"licencf").unwrap();
        assert_eq!(ffmpeg.check().unwrap_err(), "runtime_artifact_changed");
        fs::write(root.join("media-tools/FFMPEG-LICENSE.txt"), b"licence").unwrap();
        fs::write(root.join(name), b"encodes").unwrap();
        assert_eq!(ffmpeg.check().unwrap_err(), "runtime_artifact_changed");
        fs::remove_file(root.join(name)).unwrap();
        assert!(ffmpeg.check().is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("python"), root.join(name)).unwrap();
            assert!(ffmpeg.check().is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn names_the_known_answer_failure() {
        let failed = || String::from("runtime_qualification_failed");
        for (refused, expected) in [
            (
                Some("native_output_value_mismatch ValueError: x"),
                "runtime_output_mismatch",
            ),
            (Some("native_memory_insufficient"), "runtime_out_of_memory"),
            (
                Some("native_qualification_failed RuntimeException: Failed to allocate memory"),
                "runtime_out_of_memory",
            ),
            (Some("native_staged_hash_mismatch"), "runtime_model_missing"),
            (
                Some("native_device_execution_evidence_required"),
                "runtime_provider_unavailable",
            ),
            (
                Some("native_qualification_failed TypeError: x"),
                "runtime_qualification_failed",
            ),
            (None, "runtime_qualification_failed"),
        ] {
            assert_eq!(super::qualification_failure(failed(), refused), expected);
        }
        // Only a refused run is renamed: a timeout stays a timeout.
        assert_eq!(
            super::qualification_failure(
                "runtime_qualification_timeout".into(),
                Some("native_memory_insufficient")
            ),
            "runtime_qualification_timeout"
        );
    }
    use super::*;
    #[test]
    fn qwen_report_requires_signed_binary_and_exact_cpu_candidate_evidence() {
        const CPU: &str = "CPUExecutionProvider";
        let spec = serde_json::json!({"engine":"qwen-gguf","provider":"CPUExecutionProvider","modelKey":"candidate",
            "fixtureSha256":"a".repeat(64),"preprocessingSha256":"b".repeat(64)});
        let mut report = spec.clone();
        report["protocolVersion"] = serde_json::json!(1);
        report["bindingSha256"] = serde_json::json!("binding");
        report["runtimeFingerprint"] = serde_json::json!("c".repeat(64));
        report["state"] = serde_json::json!("ready-cpu");
        let binary = "d".repeat(64);
        report["qwenExecution"] = serde_json::json!({"build":"b11146-7fe450e19","binarySha256":binary,"coldMilliseconds":[100.0,120.0]});
        assert!(validate_report(&report, &spec, "binding", CPU, None, Some(&binary)).is_ok());
        assert!(validate_report(&report, &spec, "binding", CPU, None, None).is_err());
        assert!(
            validate_report(&report, &spec, "binding", CPU, None, Some(&"e".repeat(64))).is_err()
        );
        let mut invalid = report.clone();
        invalid["qwenExecution"]["build"] = serde_json::json!("b11146-000000000");
        assert!(validate_report(&invalid, &spec, "binding", CPU, None, Some(&binary)).is_err());
        // A Qwen candidate is CPU-only: never under an accelerated runtime's manifest.
        assert!(validate_report(
            &report,
            &spec,
            "binding",
            "CoreMLExecutionProvider",
            None,
            Some(&binary)
        )
        .is_err());
        report["qwenExecution"]["coldMilliseconds"] = serde_json::json!([100.0]);
        assert!(validate_report(&report, &spec, "binding", CPU, None, Some(&binary)).is_err());
    }
    #[test]
    fn a_refused_qualification_names_its_reason_from_the_report_it_left() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-refusal-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let report = root.join("report.json");
        assert_eq!(refusal(&report), None);
        std::fs::write(
            &report,
            r#"{"protocolVersion":1,"modelKey":"m","state":"incompatible","reason":"native_output_value_mismatch"}"#,
        )
        .unwrap();
        assert_eq!(
            refusal(&report).as_deref(),
            Some("native_output_value_mismatch")
        );
        std::fs::write(
            &report,
            "{\"state\":\"incompatible\",\"reason\":\"native_qualification_failed\",\"detail\":\"RuntimeError: CUDA failure\\n2\"}",
        )
        .unwrap();
        assert_eq!(
            refusal(&report).as_deref(),
            Some("native_qualification_failed RuntimeError: CUDA failure2")
        );
        // Anything that is not a plain code is not repeated.
        for bad in [
            r#"{"reason":"Not A Code"}"#,
            r#"{"reason":""}"#,
            r#"{"reason":7}"#,
            "not json",
        ] {
            std::fs::write(&report, bad).unwrap();
            assert_eq!(refusal(&report), None, "{bad}");
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn a_cuda_pack_puts_the_folders_of_its_nvidia_libraries_on_the_search_path() {
        let files = [
            "python/python.exe",
            "python/Lib/site-packages/onnxruntime/capi/onnxruntime_providers_cuda.dll",
            "python/Lib/site-packages/nvidia/cudnn/bin/cudnn64_9.dll",
            "python/Lib/site-packages/nvidia/cudnn/bin/cudnn_cnn64_9.DLL",
            "python/Lib/site-packages/nvidia/cuda_nvrtc/bin/nvrtc64_120_0.dll",
            "python/Lib/site-packages/nvidia/cudnn/include/cudnn.h",
            "python/Lib/site-packages/other/nvidia/x/bin/planted.dll",
            "nvidia/cudnn/bin/outside.dll",
        ];
        let folders = |provider| {
            device_library_folders(provider, files.iter().copied())
                .into_iter()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            folders("CUDAExecutionProvider"),
            [
                "python/Lib/site-packages/nvidia/cuda_nvrtc/bin",
                "python/Lib/site-packages/nvidia/cudnn/bin"
            ]
        );
        // The processor manifest of the same pack, and every other provider, keep the OS directory alone.
        for provider in ["CPUExecutionProvider", "OpenVINOExecutionProvider"] {
            assert!(folders(provider).is_empty(), "{provider}");
        }
    }
    #[test]
    fn a_windows_runtime_searches_the_os_directory_then_the_pack_and_has_a_home() {
        let scratch = Path::new("scratch folder");
        let folders = [PathBuf::from("pack").join("cudnn"), PathBuf::from("nvrtc")];
        let environment = windows_environment(
            std::ffi::OsStr::new("root"),
            scratch,
            &folders,
            std::ffi::OsStr::new("programs"),
        )
        .unwrap();
        let search: Vec<PathBuf> = std::env::split_paths(&environment[0].1).collect();
        assert_eq!(environment[0].0, "PATH");
        assert_eq!(
            search,
            [
                Path::new("root").join("System32"),
                folders[0].clone(),
                folders[1].clone()
            ]
        );
        assert_eq!(environment[1], ("SystemRoot", "root".into()));
        assert_eq!(environment[2], ("USERPROFILE", scratch.into()));
        assert_eq!(environment[3], ("ProgramFiles", "programs".into()));
        assert_eq!(environment[4], ("ProgramW6432", "programs".into()));
    }
    /// NVML (and so `nvidia-smi`, through which the runtime learns there is a card) does not
    /// initialize without the Program Files variables: with the environment before them, a
    /// computer whose CUDA works reported no card and refused every CUDA qualification.
    #[cfg(windows)]
    #[test]
    fn a_windows_runtime_process_can_see_the_nvidia_card() {
        use std::process::Command;
        let root = std::env::var_os("SystemRoot").unwrap();
        let smi = Path::new(&root).join("System32").join("nvidia-smi.exe");
        if !smi.is_file() {
            eprintln!("no NVIDIA driver here; nothing to check");
            return;
        }
        let scratch = std::env::temp_dir().canonicalize().unwrap();
        let program_files = crate::host_install::windows_program_files().unwrap();
        let sees = |with: bool| {
            let mut command = Command::new(&smi);
            command
                .env_clear()
                .args(["--query-gpu=index", "--format=csv,noheader"]);
            for (name, value) in
                windows_environment(&root, &scratch, &[], program_files.as_os_str()).unwrap()
            {
                if with || !name.starts_with("Program") {
                    command.env(name, value);
                }
            }
            command.output().unwrap().status.success()
        };
        if !sees(true) {
            eprintln!(
                "nvidia-smi reports no card even with the full environment; nothing to check"
            );
            return;
        }
        assert!(
            !sees(false),
            "NVML initialized without the Program Files variables"
        );
    }
    /// Python on Windows finds no home directory in an emptied environment; the runtime's
    /// settings ask for one when they are imported.
    #[cfg(windows)]
    #[test]
    fn a_windows_runtime_process_can_name_its_home_directory() {
        use std::process::Command;
        let root = std::env::var_os("SystemRoot").unwrap();
        let scratch = std::env::temp_dir().canonicalize().unwrap();
        let home = |with: bool| {
            let mut command = Command::new("python");
            command
                .env_clear()
                .args(["-I", "-B", "-c"])
                .arg("from pathlib import Path; Path.home()");
            let programs = std::ffi::OsStr::new(r"C:\Program Files");
            for (name, value) in windows_environment(&root, &scratch, &[], programs).unwrap() {
                if with || name != "USERPROFILE" {
                    command.env(name, value);
                }
            }
            // The hosted Python is found through the inherited PATH, which a pack never needs.
            let python = std::env::var_os("PATH").unwrap();
            command.env("PATH", python);
            command.output().unwrap().status.success()
        };
        assert!(!home(false), "the environment before FD-63 had a home");
        assert!(home(true));
    }
    fn report_for(provider: &str, state: &str, cpu_nodes: bool) -> [serde_json::Value; 2] {
        let mut nodes = serde_json::json!({ provider: 12 });
        if cpu_nodes {
            nodes["CPUExecutionProvider"] = 3.into();
        }
        let spec = serde_json::json!({"modelKey":"clip:model","provider":provider,
            "preprocessingSha256":"a".repeat(64),"fixtureSha256":"b".repeat(64)});
        let report = serde_json::json!({"protocolVersion":1,"modelKey":"clip:model","provider":provider,
            "preprocessingSha256":"a".repeat(64),"fixtureSha256":"b".repeat(64),
            "bindingSha256":"c".repeat(64),"reason":null,"runtimeFingerprint":"d".repeat(64),
            "coldMilliseconds":120.0,"warmMilliseconds":8.5,"state":state,
            "execution":[{"state":state,"reason":null,"nodes":nodes}]});
        [report, spec]
    }
    fn check(provider: &str, state: &str, cpu_nodes: bool, runtime: &str) -> Result<(), String> {
        let [report, spec] = report_for(provider, state, cpu_nodes);
        validate_report(&report, &spec, &"c".repeat(64), runtime, None, None)
    }
    #[test]
    fn report_is_accepted_only_for_the_provider_the_runtime_declares() {
        const CPU: &str = "CPUExecutionProvider";
        const COREML: &str = "CoreMLExecutionProvider";
        const OPENVINO: &str = "OpenVINOExecutionProvider";
        const CUDA: &str = "CUDAExecutionProvider";
        assert!(check(CPU, "ready-cpu", false, CPU).is_ok());
        // CoreML is accepted only with its collector's device proof (see `metal`).
        assert!(check(COREML, "ready-mixed", false, COREML).is_err());
        assert!(check(COREML, "ready-mixed", true, COREML).is_err());
        for provider in [OPENVINO, CUDA] {
            assert!(check(provider, "ready-accelerator", false, provider).is_ok());
            assert!(check(provider, "ready-mixed", true, provider).is_ok());
            assert!(check(provider, "ready-accelerator", true, provider).is_err());
        }
        // CoreML never counts as accelerator-only, and a CPU runtime cannot pass as accelerated.
        assert!(check(COREML, "ready-accelerator", false, COREML).is_err());
        assert!(check(COREML, "ready-cpu", false, COREML).is_err());
        // A report for another provider than the installed runtime's is refused, either way round.
        for (provider, state, runtime) in [
            (COREML, "ready-mixed", CPU),
            (OPENVINO, "ready-accelerator", CPU),
            (CUDA, "ready-accelerator", OPENVINO),
            (CPU, "ready-cpu", COREML),
        ] {
            assert_eq!(
                check(provider, state, false, runtime).unwrap_err(),
                "runtime_qualification_report_invalid",
                "{provider} under {runtime}"
            );
        }
        // Providers no runtime profile declares are refused even when the runtime names them.
        for provider in ["MIGraphXExecutionProvider", "TensorrtExecutionProvider", ""] {
            assert!(check(provider, "ready-accelerator", false, provider).is_err());
        }
    }
    #[test]
    fn scratch_owner_is_published_only_with_its_lock_held() {
        let scratch = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("inference-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&scratch).unwrap();
        let owner = own_scratch(&scratch).unwrap();
        assert!(!scratch.join(SCRATCH_OWNER_PENDING).exists());
        // The published record is the locked handle itself (also after the rename on Windows).
        let published = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(scratch.join(SCRATCH_OWNER))
            .unwrap();
        assert!(published.try_lock().is_err());
        // A second owner of the same scratch is refused and leaves the first one's record alone.
        assert!(own_scratch(&scratch).is_err());
        assert!(published.try_lock().is_err());
        drop(owner);
        assert!(published.try_lock().is_ok());
        drop(published);
        fs::remove_dir_all(scratch).unwrap();
    }
    #[test]
    fn qualification_cannot_start_a_different_runtime_manifest() {
        let runtime = VerifiedRuntime {
            root: PathBuf::new(),
            manifest: serde_json::from_value(serde_json::json!({
                "schemaVersion":1,"protocolVersion":1,"epoch":1,
                "platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,
                "provider":"CPUExecutionProvider","python":"python", "sourceRevision":"a".repeat(40),"files":{}
            })).unwrap(),
            manifest_sha256: "a".repeat(64),
        };
        let qualified = QualifiedRuntime {
            spec: vec![],
            report: serde_json::Value::Null,
            manifest_sha256: "b".repeat(64),
        };
        assert_eq!(
            runtime
                .start_qualified_sidecar(
                    &qualified,
                    Path::new("missing"),
                    Path::new("missing"),
                    19999
                )
                .err()
                .unwrap(),
            "runtime_qualification_binding_invalid"
        );
        for bindings in [vec![], vec![&qualified], vec![&qualified; 65]] {
            assert_eq!(
                runtime
                    .start_bound_sidecar(
                        &bindings,
                        Path::new("missing"),
                        Path::new("missing"),
                        19999
                    )
                    .err()
                    .unwrap(),
                "runtime_qualification_binding_invalid"
            );
        }
    }
    #[test]
    fn python_gate_registers_the_executed_main_module() {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-gate-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("test_identity.py"),"import sys,unittest\nclass Identity(unittest.TestCase):\n def test_main(self):\n  self.assertEqual(sys.modules['__main__'].__spec__.name,'unittest.__main__')\n").unwrap();
        let mut command = Command::new(if cfg!(windows) { "python" } else { "python3" });
        command
            .args(["-I", "-B", "-c", GATE, "unittest", "discover", "-s"])
            .arg(&root)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        crate::process_tree::configure(&mut command);
        let mut child = command.spawn().unwrap();
        let tree = crate::process_tree::ProcessTree::attach(&child).unwrap();
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(START).unwrap();
        let status = child.wait().unwrap();
        drop(pipe);
        let mut errors = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .take(4096)
            .read_to_string(&mut errors)
            .unwrap();
        tree.terminate();
        fs::remove_dir_all(root).unwrap();
        assert!(
            status.success(),
            "executed module was not registered as __main__: {errors}"
        );
    }
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
    /// FD-71: with the pipe held open, as the app holds it for as long as the runtime runs, the
    /// runtime may still use its standard input: `lseek` and `fstat` on it (as onnxruntime's
    /// native module does when it loads) and hand it to a child process. On Windows these waited
    /// forever behind the gate's own read of the pipe.
    #[test]
    fn python_gate_leaves_the_standard_input_usable_while_the_parent_holds_the_pipe() {
        use std::{
            io::Write,
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let python = if cfg!(windows) { "python" } else { "python3" };
        let mut command = Command::new(python);
        command
            .args(["-I", "-B", "-c", GATE, "timeit", "-n", "1", "-r", "1"])
            // The gate's watch is started before this runs; give it time to be waiting.
            // `lseek` takes the C runtime's lock on the descriptor, which a pending read held.
            .arg("import os, subprocess, sys, time\ntime.sleep(1)\ntry: os.lseek(0, 0, 1)\nexcept OSError: pass\nos.fstat(0)\nsubprocess.run([sys.executable, '-I', '-B', '-c', 'pass'], check=True)")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        crate::process_tree::configure(&mut command);
        let mut child = command.spawn().unwrap();
        let tree = crate::process_tree::ProcessTree::attach(&child).unwrap();
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(START).unwrap();
        let end = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= end {
                tree.terminate();
                let _ = child.wait();
                panic!("the runtime hung using its standard input while the parent held the pipe");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        drop(pipe);
        tree.terminate();
        assert!(status.success());
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
            // macOS can complete the explicit exit before delivering this process's group SIGKILL.
            assert!(status.signal() == Some(libc::SIGKILL) || status.code() == Some(125));
        }
        #[cfg(windows)]
        assert_eq!(status.code(), Some(125));
    }
}

#[cfg(test)]
mod accepted_qualification_tests {
    use super::*;
    use crate::{
        ml_transport::AcceptedQualification, model_catalogue::approved_profile, worker::SavedWorker,
    };
    use serde_json::{json, Value};
    const AT: i64 = 1_792_094_400_000;
    fn fixture() -> (
        crate::model_catalogue::ApprovedProfile,
        QualifiedRuntime,
        Value,
        SavedWorker,
    ) {
        let catalogue: Value =
            serde_json::from_str(include_str!("../../runtime/model-catalogue.json")).unwrap();
        let data: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/accepted-qualification.json"
        ))
        .unwrap();
        let p = catalogue["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["spec"]["modelKey"] == data["response"]["modelKey"])
            .unwrap();
        let profile = approved_profile(
            p["modelName"].as_str().unwrap(),
            &p["spec"]["entries"],
            p["runtimeSourceRevision"].as_str().unwrap(),
            p["spec"]["provider"].as_str().unwrap(),
        )
        .unwrap()
        .unwrap();
        let response = data["response"].clone();
        let mut report = data["report"].clone();
        report["coldMilliseconds"] = json!(120.0);
        let qualified = QualifiedRuntime {
            spec: profile
                .challenge(response["id"].as_str().unwrap())
                .unwrap()
                .0,
            report,
            manifest_sha256: "a".repeat(64),
        };
        let worker: SavedWorker = serde_json::from_value(json!({"serverId":"server","accountId":"account","deviceId":"445bc2b6-f4cd-439e-b8bb-7e84d7ee0550","sessionId":"1117c1ca-0495-46e9-b579-f321520c2b1a","authorizationEpoch":2,"workerToken":"a".repeat(64),"expiresAt":"2026-10-15T22:00:00Z","nextSequence":1})).unwrap();
        (profile, qualified, response, worker)
    }
    #[test]
    fn accepted_evidence_binds_local_runtime_and_survives_only_ordinary_token_renewal() {
        let (profile, qualified, response, mut worker) = fixture();
        let grant = AcceptedQualification::bind(
            &worker,
            &profile,
            &qualified,
            &serde_json::to_vec(&response).unwrap(),
            AT,
        )
        .unwrap();
        assert_eq!(grant.id(), response["id"].as_str().unwrap());
        worker.worker_token = "b".repeat(64);
        worker.next_sequence = 9;
        assert!(grant.validate_authority(&worker, AT).is_ok());
        for (field, value) in [
            ("serverId", json!("other")),
            ("accountId", json!("other")),
            ("deviceId", json!("other")),
            ("sessionId", json!("other")),
            ("authorizationEpoch", json!(3)),
        ] {
            let mut changed = serde_json::to_value(&worker).unwrap();
            changed[field] = value;
            assert!(grant
                .validate_authority(&serde_json::from_value(changed).unwrap(), AT)
                .is_err());
        }
        assert!(grant.validate_authority(&worker, AT + 3_600_000).is_err());
        assert!(grant.validate_runtime(&qualified, AT).is_ok());
        let config: Value = serde_json::from_slice(qualified.specification()).unwrap();
        let task_wire = json!({"id":"ff8f1290-3c1d-4695-8696-af493be01fe0","taskId":"c39d4385-84f8-4c37-a643-1b98fc12df93",
            "deviceId":worker.device_id,"sessionId":worker.session_id,"authorizationEpoch":2,"generation":1,
            "qualificationId":response["id"],"qualificationExpiresAt":response["expiresAt"],"modelKey":response["modelKey"],
            "configJson":serde_json::to_string(&config["entries"]).unwrap(),"configSha256":response["configSha256"],
            "inputSha256":"b".repeat(64),"inputKind":"text","maxInputBytes":1024,"expiresAt":"2026-10-15T20:01:00Z","executionDeadline":"2026-10-15T20:03:00Z"});
        let task = serde_json::from_value(task_wire.clone()).unwrap();
        assert!(grant.validate_task(&worker, &task, AT).is_ok());
        for (field, value) in [
            (
                "qualificationId",
                json!("c39d4385-84f8-4c37-a643-1b98fc12df93"),
            ),
            ("qualificationExpiresAt", json!("2026-10-15T21:00:01Z")),
            ("inputKind", json!("image")),
            ("configSha256", json!("c".repeat(64))),
        ] {
            let mut changed = task_wire.clone();
            changed[field] = value;
            assert!(grant
                .validate_task(&worker, &serde_json::from_value(changed).unwrap(), AT)
                .is_err());
        }
    }
    #[test]
    fn accepted_evidence_rejects_altered_runtime_report_model_association_and_lifetime() {
        let (profile, qualified, response, worker) = fixture();
        for (field, value) in [
            ("id", json!("ff8f1290-3c1d-4695-8696-af493be01fe0")),
            ("modelKey", json!("other")),
            ("configSha256", json!("b".repeat(64))),
            ("bindingSha256", json!("b".repeat(64))),
            ("manifestSha256", json!("b".repeat(64))),
            ("runtimeFingerprint", json!("b".repeat(64))),
            ("reportSha256", json!("b".repeat(64))),
            ("inputKind", json!("image")),
            ("deviceId", json!("other")),
            ("sessionId", json!("other")),
            ("authorizationEpoch", json!(3)),
            ("qualifiedAt", json!("2026-10-15T20:05:00Z")),
            ("expiresAt", json!("2026-10-15T21:00:01Z")),
            ("expiresAt", json!("2026-10-15T19:00:00Z")),
        ] {
            let mut changed = response.clone();
            changed[field] = value;
            assert!(
                AcceptedQualification::bind(
                    &worker,
                    &profile,
                    &qualified,
                    &serde_json::to_vec(&changed).unwrap(),
                    AT
                )
                .is_err(),
                "{field}"
            );
        }
        // A field a newer server adds is not evidence of anything: every known field is still
        // checked and the reply is accepted.
        let mut newer = response.clone();
        newer["somethingNew"] = json!(true);
        let raw = serde_json::to_vec(&newer).unwrap();
        assert!(AcceptedQualification::bind(&worker, &profile, &qualified, &raw, AT).is_ok());
    }
}
