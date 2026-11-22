//! FL-1760: converts one video at a time for the server, beside the AI worker. The server decides
//! which computers get work: one it has not enabled is answered with no task.
//! A job that cannot finish here is handed back and starts from zero wherever it runs next.
use crate::{
    host_runtime::VerifiedHostRuntime,
    ml_transport::WorkerTransport,
    package_lease::CodeLease,
    process_tree::ProcessTree,
    transcode_args::{self, Pass},
};
use reqwest::{
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    Method,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime},
};
use uuid::Uuid;

const FOLDER: &str = "transcodes";
const INPUT: &str = "input";
const OUTPUT: &str = "output.mp4";
const PASS_LOG: &str = "pass";
const PROCESS_RECORD: &str = "process.json";

/// Asking is also how the server learns this desktop can convert: it forgets after 150 seconds.
const CLAIM_EVERY: Duration = Duration::from_secs(30);
const AFTER_ERROR: Duration = Duration::from_secs(60);
const OLD_SERVER_RECHECK: Duration = Duration::from_secs(15 * 60);
const NO_FFMPEG_RECHECK: Duration = Duration::from_secs(10 * 60);
const LEASE: Duration = Duration::from_secs(120);
const HEARTBEAT_EVERY: Duration = Duration::from_secs(30);
const HEARTBEAT_RETRY: Duration = Duration::from_secs(5);
const HEARTBEAT_LIMIT: Duration = Duration::from_secs(25);
const HAND_BACK_LIMIT: Duration = Duration::from_secs(5);
/// How long the body of one download or upload may take in all, and without a byte arriving.
const TRANSFER_LIMIT: Duration = Duration::from_secs(12 * 60 * 60);
const STALL_LIMIT: Duration = Duration::from_secs(60);
/// Encoders need room beyond the AI models already loaded.
const START_MEMORY: u64 = 2 * 1024 * 1024 * 1024;
const KEEP_MEMORY: u64 = 512 * 1024 * 1024;
const MIN_OUTPUT_ALLOWANCE: u64 = 1024 * 1024 * 1024;

/// The worker's own flags: Stop or sign-out, Pause, and its setup ending.
#[derive(Clone, Copy)]
pub(crate) struct Signals<'a> {
    pub cancelled: &'a AtomicBool,
    pub paused: &'a AtomicBool,
    pub ended: &'a AtomicBool,
}
impl Signals<'_> {
    fn over(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || self.ended.load(Ordering::Acquire)
    }
    fn stop_work(&self) -> bool {
        self.over() || self.paused.load(Ordering::Acquire)
    }
}

#[derive(Deserialize)]
struct Claim {
    task: Option<Task>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Task {
    id: String,
    claim_token: String,
    input_options: Vec<String>,
    output_options: Vec<String>,
    two_pass: bool,
    frame_count: u64,
    source_bytes: u64,
    max_output_bytes: u64,
}
#[derive(Deserialize)]
struct Ack {
    accepted: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Grant {
    upload_token: String,
}

struct Job {
    id: String,
    claim_token: String,
    options: Vec<String>,
    two_pass: bool,
    frame_count: u64,
    source_bytes: u64,
    max_output_bytes: u64,
}
fn heartbeat_payload(claim_token: &str, progress: Option<u8>) -> String {
    match progress {
        Some(progress) => {
            serde_json::json!({ "claimToken": claim_token, "progress": progress }).to_string()
        }
        None => serde_json::json!({ "claimToken": claim_token }).to_string(),
    }
}

const PROGRESS_UNKNOWN: u8 = u8::MAX;
/// How far the encode is, 0 to 100 across all its passes. It only rises until it is cleared.
struct EncodeProgress(AtomicU8);
impl EncodeProgress {
    fn new() -> Self {
        Self(AtomicU8::new(PROGRESS_UNKNOWN))
    }
    fn get(&self) -> Option<u8> {
        Some(self.0.load(Ordering::Acquire)).filter(|value| *value != PROGRESS_UNKNOWN)
    }
    fn rise(&self, percent: u8) {
        let _ = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current == PROGRESS_UNKNOWN || percent > current).then_some(percent)
            });
    }
    fn clear(&self) {
        self.0.store(PROGRESS_UNKNOWN, Ordering::Release);
    }
}
/// The first of two passes is the lower half and the second the upper, so it never goes back.
fn overall_percent(pass: Pass, frames: u64, frame_count: u64) -> Option<u8> {
    if frame_count == 0 {
        return None;
    }
    let done = u128::from(frames.min(frame_count));
    let total = u128::from(frame_count);
    Some(match pass {
        Pass::Only => done * 100 / total,
        Pass::First => done * 50 / total,
        Pass::Second => 50 + done * 50 / total,
    } as u8)
}
/// Reads FFmpeg's `-progress` lines until it closes them.
fn read_progress(reader: impl BufRead, pass: Pass, frame_count: u64, progress: &EncodeProgress) {
    for line in reader.lines() {
        let Ok(line) = line else { return };
        let frames = line.strip_prefix("frame=").map(str::trim);
        if let Some(percent) = frames
            .and_then(|frames| frames.parse().ok())
            .and_then(|frames| overall_percent(pass, frames, frame_count))
        {
            progress.rise(percent);
        }
    }
}
/// How a job ended, and so what the server is told.
#[derive(Debug, PartialEq, Eq)]
enum End {
    Uploaded,
    /// The server no longer gives this desktop the job: nothing to hand back.
    LeaseLost,
    HandBack(&'static str),
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}
/// The ids go into URLs and a folder name, so they are checked before anything else.
fn admit(task: Task) -> Result<Job, (String, String, &'static str)> {
    let refuse = |task: &Task, code| Err((task.id.clone(), task.claim_token.clone(), code));
    let allowance = task
        .source_bytes
        .saturating_mul(2)
        .max(MIN_OUTPUT_ALLOWANCE);
    if task.source_bytes == 0 || task.max_output_bytes == 0 || task.max_output_bytes > allowance {
        return refuse(&task, "input-invalid");
    }
    let options = match transcode_args::validate(&task.input_options, &task.output_options) {
        Ok(options) => options,
        Err(_) => return refuse(&task, "encode-failed"),
    };
    Ok(Job {
        id: task.id,
        claim_token: task.claim_token,
        options,
        two_pass: task.two_pass,
        frame_count: task.frame_count,
        source_bytes: task.source_bytes,
        max_output_bytes: task.max_output_bytes,
    })
}

/// The one folder of a job, gone when this is dropped, however the job ended.
struct Workspace(PathBuf);
impl Workspace {
    fn create(root: &Path, id: &str) -> Result<Self, String> {
        crate::runtime_store::private_directory(root)?;
        let path = root.join(id);
        let _ = fs::remove_dir_all(&path);
        crate::runtime_store::private_directory(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

static CLEANED: Mutex<bool> = Mutex::new(false);
/// What a crash left behind, once per launch and before any new job: an encoder still running
/// and every temp file.
pub(crate) fn clean_after_crash(data: &Path) {
    let mut cleaned = CLEANED.lock().unwrap_or_else(|poison| poison.into_inner());
    if std::mem::replace(&mut *cleaned, true) {
        return;
    }
    clear(&data.join(FOLDER), "ffmpeg");
}
fn clear(root: &Path, program: &str) {
    #[cfg(unix)]
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            stop_recorded(&entry.path().join(PROCESS_RECORD), program);
        }
    }
    #[cfg(not(unix))]
    let _ = program; // A job object ends its processes when this app does.
    let _ = fs::remove_dir_all(root);
}
/// Only the very process that was recorded: a PID in use by anything else is left alone.
#[cfg(unix)]
fn stop_recorded(record: &Path, program: &str) {
    use crate::process_tree::{Presence, ProcessIdentity};
    let Ok(raw) = crate::runtime_store::read_bounded(record, 8192) else {
        return;
    };
    let Ok(recorded) = serde_json::from_slice::<ProcessIdentity>(&raw) else {
        return;
    };
    let named = recorded
        .program
        .file_name()
        .is_some_and(|name| name == program);
    if named && ProcessIdentity::lookup(recorded.pid) == Presence::Present(recorded.clone()) {
        // Started as the leader of its own group.
        unsafe { libc::kill(-(recorded.pid as i32), libc::SIGKILL) };
    }
}

/// The signed package's FFmpeg. Helper-only installs have no package, and so no conversions: a
/// program found on PATH is never used.
struct Encoder {
    package: PathBuf,
    runtime: VerifiedHostRuntime,
}
impl Encoder {
    fn locate() -> Option<Self> {
        let mut records = crate::host_install::installed().ok()?;
        let library = crate::host_setup::library_package(&records);
        records.sort_by_key(|record| Some(&record.manifest_sha256) != library.as_ref());
        records.into_iter().find_map(|record| {
            let layout = record.layout().ok()?;
            let _lease = CodeLease::acquire_existing(&layout.runtime).ok()?;
            let (layout, runtime) = crate::host_setup::verified(&record).ok()?;
            runtime.ffmpeg().ok()?;
            Some(Self {
                package: layout.runtime,
                runtime,
            })
        })
    }
    /// Holds the package still for the job and reads its FFmpeg again.
    fn ready(&self) -> Result<(CodeLease, PathBuf), String> {
        let lease = CodeLease::acquire_existing(&self.package)?;
        Ok((lease, self.runtime.ffmpeg()?))
    }
}

/// Checking a whole package is slow, so it is done once for as long as the package stays good.
static LOCATED: Mutex<Option<Arc<Encoder>>> = Mutex::new(None);
fn located() -> Option<Arc<Encoder>> {
    let mut known = LOCATED.lock().unwrap_or_else(|poison| poison.into_inner());
    if known.is_none() {
        *known = Encoder::locate().map(Arc::new);
    }
    known.clone()
}
fn forget_encoder() {
    *LOCATED.lock().unwrap_or_else(|poison| poison.into_inner()) = None;
}

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tauri::async_runtime::spawn_blocking(work).await.ok()
}
async fn wait(period: Duration, signals: Signals<'_>) {
    let until = tokio::time::Instant::now() + period;
    while !signals.over() && tokio::time::Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub(crate) async fn run(worker: &WorkerTransport, data: &Path, signals: Signals<'_>) {
    let cleanup = data.to_path_buf();
    let _ = blocking(move || clean_after_crash(&cleanup)).await;
    let root = data.join(FOLDER);
    while !signals.over() {
        let pause = turn(worker, &root, signals).await;
        wait(pause, signals).await;
    }
}

async fn turn(worker: &WorkerTransport, root: &Path, signals: Signals<'_>) -> Duration {
    if signals.stop_work() {
        return CLAIM_EVERY;
    }
    let Some(ready) = blocking(located).await.flatten() else {
        return NO_FFMPEG_RECHECK;
    };
    let admitted = blocking(crate::resource_policy::sample)
        .await
        .is_some_and(|status| status.refusal(START_MEMORY).is_none());
    if !admitted || signals.stop_work() {
        return CLAIM_EVERY;
    }
    let claim = worker
        .transcode_json::<Claim>("api/desktop/transcodes/claim", "transcode-claim", "")
        .await;
    let task = match claim {
        Ok(Claim { task: Some(task) }) => task,
        Ok(Claim { task: None }) => return CLAIM_EVERY,
        // An older server has no conversions to offer.
        Err(code) if code == "server_http_404" => return OLD_SERVER_RECHECK,
        Err(_) => return AFTER_ERROR,
    };
    // Not safe to put in a URL: the lease runs out on the server by itself.
    if !canonical_uuid(&task.id) || !canonical_uuid(&task.claim_token) {
        return AFTER_ERROR;
    }
    let job = match admit(task) {
        Ok(job) => job,
        Err((id, claim_token, code)) => {
            hand_back(worker, &id, &claim_token, code).await;
            return AFTER_ERROR;
        }
    };
    let package = ready.clone();
    let Some(Ok((lease, ffmpeg))) = blocking(move || package.ready()).await else {
        forget_encoder();
        hand_back(worker, &job.id, &job.claim_token, "cancelled").await;
        return AFTER_ERROR;
    };
    convert(worker, root, &job, &ffmpeg, signals).await;
    drop(lease);
    Duration::ZERO
}

async fn convert(
    worker: &WorkerTransport,
    root: &Path,
    job: &Job,
    ffmpeg: &Path,
    signals: Signals<'_>,
) {
    let (folder, id) = (root.to_path_buf(), job.id.clone());
    let Some(Ok(workspace)) = blocking(move || Workspace::create(&folder, &id)).await else {
        hand_back(worker, &job.id, &job.claim_token, "cancelled").await;
        return;
    };
    // The side that loses is dropped here: that ends a transfer and kills the encoder.
    let progress = Arc::new(EncodeProgress::new());
    let end = tokio::select! {
        end = work(worker, job, &workspace.0, ffmpeg, &progress) => end,
        end = watch(worker, job, &progress, signals) => end,
    };
    if let End::HandBack(code) = end {
        hand_back(worker, &job.id, &job.claim_token, code).await;
    }
    let _ = blocking(move || drop(workspace)).await;
}

async fn hand_back(worker: &WorkerTransport, id: &str, claim_token: &str, code: &str) {
    let payload = serde_json::json!({ "claimToken": claim_token, "code": code }).to_string();
    let _ = tokio::time::timeout(
        HAND_BACK_LIMIT,
        worker.transcode_json::<Ack>(
            &format!("api/desktop/transcodes/{id}/fail"),
            &format!("transcode-fail:{id}"),
            &payload,
        ),
    )
    .await;
}

#[derive(Debug, PartialEq, Eq)]
enum Beat {
    Renewed,
    Lost,
    Retry,
}
/// A server that says no ended the job. One that cannot be reached gets until the lease is out.
fn judge_heartbeat(answer: &Result<bool, String>, since_renewed: Duration) -> Beat {
    match answer {
        Ok(true) => Beat::Renewed,
        Ok(false) => Beat::Lost,
        Err(code) if code == "worker_lease_refused" => Beat::Lost,
        Err(_) if since_renewed >= LEASE => Beat::Lost,
        Err(_) => Beat::Retry,
    }
}

/// Runs for as long as the job may: returns only when it has to stop.
async fn watch(
    worker: &WorkerTransport,
    job: &Job,
    progress: &EncodeProgress,
    signals: Signals<'_>,
) -> End {
    const GIVE_BACK: End = End::HandBack("cancelled");
    let (path, operation) = (
        format!("api/desktop/transcodes/{}/heartbeat", job.id),
        format!("transcode-heartbeat:{}", job.id),
    );
    // A server from before progress refuses the field: the lease matters more, so it is dropped.
    let mut send_progress = true;
    let mut renewed = Instant::now();
    let mut beat_due = renewed + HEARTBEAT_EVERY;
    let mut wall = SystemTime::now();
    let mut seconds = 0u32;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if signals.stop_work() {
            return GIVE_BACK;
        }
        let now = SystemTime::now();
        // The computer slept.
        if crate::worker_setup::wake_gap(wall, now) {
            return GIVE_BACK;
        }
        wall = now;
        seconds = seconds.wrapping_add(1);
        if seconds % 5 == 0 {
            let status = blocking(crate::resource_policy::sample).await;
            if status.is_none_or(|status| status.refusal(KEEP_MEMORY).is_some()) {
                return GIVE_BACK;
            }
        }
        if Instant::now() < beat_due {
            continue;
        }
        let percent = progress.get().filter(|_| send_progress);
        let payload = heartbeat_payload(&job.claim_token, percent);
        let answer = tokio::time::timeout(
            HEARTBEAT_LIMIT,
            worker.transcode_json::<Ack>(&path, &operation, &payload),
        )
        .await
        .unwrap_or_else(|_| Err("worker_request_interrupted".into()))
        .map(|ack| ack.accepted);
        if percent.is_some() && matches!(&answer, Err(code) if code == "server_http_400") {
            send_progress = false;
            beat_due = Instant::now();
            continue;
        }
        match judge_heartbeat(&answer, renewed.elapsed()) {
            Beat::Renewed => {
                renewed = Instant::now();
                beat_due = renewed + HEARTBEAT_EVERY;
            }
            Beat::Lost => return End::LeaseLost,
            Beat::Retry => beat_due = Instant::now() + HEARTBEAT_RETRY,
        }
    }
}

async fn work(
    worker: &WorkerTransport,
    job: &Job,
    folder: &Path,
    ffmpeg: &Path,
    progress: &Arc<EncodeProgress>,
) -> End {
    let steps = async {
        check_disk(folder, job).await?;
        download(worker, job, &folder.join(INPUT)).await?;
        for pass in passes(job.two_pass) {
            encode(job, folder, ffmpeg, *pass, progress).await?;
        }
        progress.clear();
        upload(worker, job, &folder.join(OUTPUT)).await
    };
    match steps.await {
        Ok(()) => End::Uploaded,
        Err(end) => end,
    }
}

fn passes(two_pass: bool) -> &'static [Pass] {
    if two_pass {
        &[Pass::First, Pass::Second]
    } else {
        &[Pass::Only]
    }
}

fn enough_room(available: u64, source: u64, max_output: u64) -> bool {
    source
        .checked_add(max_output)
        .is_some_and(|needed| available >= needed)
}
async fn check_disk(folder: &Path, job: &Job) -> Result<(), End> {
    let path = folder.to_path_buf();
    let available = blocking(move || crate::host_storage::available_bytes(&path)).await;
    match available {
        Some(Ok(bytes)) if enough_room(bytes, job.source_bytes, job.max_output_bytes) => Ok(()),
        _ => Err(End::HandBack("insufficient-disk")),
    }
}

/// What a refused request means for the job.
fn refusal(code: &str) -> End {
    match code {
        "worker_lease_refused" => End::LeaseLost,
        _ => End::HandBack("cancelled"),
    }
}

async fn download(worker: &WorkerTransport, job: &Job, path: &Path) -> Result<(), End> {
    const INVALID: End = End::HandBack("input-invalid");
    let id = &job.id;
    let token = &job.claim_token;
    // The signed request goes in its turn; the body is read without holding the line.
    let mut response = worker
        .transcode_request(
            Method::GET,
            &format!("api/desktop/transcodes/{id}/input?claimToken={token}"),
            &format!("transcode-input:{id}:{token}"),
            "",
            Some(TRANSFER_LIMIT),
        )
        .await
        .map_err(|code| refusal(&code))?;
    if !response.status().is_success() {
        let (status, message) = crate::transport::refused(response).await;
        return Err(match status {
            404 => INVALID,
            _ => refusal(&crate::ml_transport::worker_refusal(status, &message)),
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length != job.source_bytes)
    {
        return Err(INVALID);
    }
    let target = path.to_path_buf();
    let mut file = blocking(move || create_private(&target))
        .await
        .and_then(Result::ok)
        .ok_or(End::HandBack("cancelled"))?;
    let mut received = 0u64;
    loop {
        let chunk = tokio::time::timeout(STALL_LIMIT, response.chunk())
            .await
            .map_err(|_| End::HandBack("cancelled"))?
            .map_err(|_| End::HandBack("cancelled"))?;
        let Some(chunk) = chunk else { break };
        received = received.saturating_add(chunk.len() as u64);
        if received > job.source_bytes {
            return Err(INVALID);
        }
        file = blocking(move || file.write_all(&chunk).map(|()| file))
            .await
            .and_then(Result::ok)
            .ok_or(End::HandBack("insufficient-disk"))?;
    }
    if received != job.source_bytes {
        return Err(INVALID);
    }
    blocking(move || file.sync_all())
        .await
        .and_then(Result::ok)
        .ok_or(End::HandBack("insufficient-disk"))
}

fn create_private(path: &Path) -> std::io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Kills the encoder and everything it started, unless it already ended by itself.
struct RunningEncoder {
    child: Child,
    tree: ProcessTree,
    ended: bool,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl Drop for RunningEncoder {
    fn drop(&mut self) {
        if !self.ended {
            self.tree.terminate();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Whether the job's own files have grown past what it may write: the output itself, and the
/// output with its two-pass logs.
fn over_limit(folder: &Path, limit: u64) -> bool {
    let Ok(entries) = fs::read_dir(folder) else {
        return false;
    };
    let mut total = 0u64;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name == INPUT || name == PROCESS_RECORD {
            continue;
        }
        let bytes = entry.metadata().map_or(0, |meta| meta.len());
        if name == OUTPUT && bytes > limit {
            return true;
        }
        total = total.saturating_add(bytes);
    }
    total > limit.saturating_mul(2)
}

fn start_encoder(
    options: &[String],
    folder: &Path,
    ffmpeg: &Path,
    pass: Pass,
    frame_count: u64,
    progress: Arc<EncodeProgress>,
) -> Result<RunningEncoder, ()> {
    let args = transcode_args::ffmpeg_args(
        &folder.join(INPUT),
        &folder.join(OUTPUT),
        &folder.join(PASS_LOG),
        options,
        pass,
    );
    let mut command = Command::new(ffmpeg);
    command
        .args(args)
        .current_dir(folder)
        .env_clear()
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(tools) = ffmpeg.parent() {
        command.env("PATH", tools);
    }
    #[cfg(windows)]
    command.env(
        "SystemRoot",
        crate::windows_protection::system_root().map_err(|_| ())?,
    );
    crate::process_tree::configure(&mut command);
    let mut child = command.spawn().map_err(|_| ())?;
    let tree = match ProcessTree::attach(&child) {
        Ok(tree) => tree,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(());
        }
    };
    #[cfg(unix)]
    if let Some(identity) = crate::process_tree::ProcessIdentity::of(child.id()) {
        if let Ok(raw) = serde_json::to_vec(&identity) {
            let _ = fs::write(folder.join(PROCESS_RECORD), raw);
        }
    }
    let reader = child.stdout.take().map(|stdout| {
        std::thread::spawn(move || {
            read_progress(BufReader::new(stdout), pass, frame_count, &progress);
        })
    });
    Ok(RunningEncoder {
        child,
        tree,
        ended: false,
        reader,
    })
}

async fn encode(
    job: &Job,
    folder: &Path,
    ffmpeg: &Path,
    pass: Pass,
    progress: &Arc<EncodeProgress>,
) -> Result<(), End> {
    const FAILED: End = End::HandBack("encode-failed");
    let (options, target, program) = (
        job.options.clone(),
        folder.to_path_buf(),
        ffmpeg.to_path_buf(),
    );
    // Starting a process and writing its record touch the disk.
    let (frame_count, shared) = (job.frame_count, progress.clone());
    let mut running =
        blocking(move || start_encoder(&options, &target, &program, pass, frame_count, shared))
            .await
            .and_then(Result::ok)
            .ok_or(FAILED)?;
    let limit = job.max_output_bytes;
    let mut ticks = 0u32;
    let status = loop {
        match running.child.try_wait() {
            Ok(Some(status)) => {
                running.ended = true;
                break status;
            }
            Ok(None) => {}
            Err(_) => return Err(FAILED),
        }
        ticks = ticks.wrapping_add(1);
        if ticks % 4 == 0 {
            let target = folder.to_path_buf();
            if blocking(move || over_limit(&target, limit))
                .await
                .unwrap_or(true)
            {
                return Err(FAILED);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    // Its last lines are in before the next pass, or the upload, moves the figure on.
    if let Some(reader) = running.reader.take() {
        let _ = blocking(move || reader.join()).await;
    }
    let target = folder.to_path_buf();
    if !status.success()
        || blocking(move || over_limit(&target, limit))
            .await
            .unwrap_or(true)
    {
        return Err(FAILED);
    }
    Ok(())
}

fn digest(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok((format!("{:x}", hasher.finalize()), total));
        }
        hasher.update(&buffer[..count]);
        total += count as u64;
    }
}

async fn upload(worker: &WorkerTransport, job: &Job, path: &Path) -> Result<(), End> {
    const FAILED: End = End::HandBack("encode-failed");
    let target = path.to_path_buf();
    let (checksum, size) = blocking(move || digest(&target))
        .await
        .and_then(Result::ok)
        .ok_or(FAILED)?;
    if size == 0 || size > job.max_output_bytes {
        return Err(FAILED);
    }
    let id = &job.id;
    let payload = serde_json::json!({
        "claimToken": job.claim_token,
        "checksum": checksum,
        "sizeInBytes": size.to_string(),
    })
    .to_string();
    let grant: Grant = worker
        .transcode_json(
            &format!("api/desktop/transcodes/{id}/upload-grant"),
            &format!("transcode-upload-grant:{id}"),
            &payload,
        )
        .await
        .map_err(|code| refusal(&code))?;
    let (client, url) = worker
        .transcode_upload_target(&format!("api/desktop/transcodes/{id}/output"))
        .await
        .map_err(|code| refusal(&code))?;
    let target = path.to_path_buf();
    let file = blocking(move || File::open(target))
        .await
        .and_then(Result::ok)
        .ok_or(FAILED)?;
    let body =
        crate::copy_upload::part_body(Arc::new(file), 0, size, Arc::new(AtomicBool::new(false)));
    // Not signed, and no lock is held: heartbeats keep going while this runs.
    let response = client
        .put(url)
        .timeout(TRANSFER_LIMIT)
        .header("x-frameleaf-transcode-upload", grant.upload_token)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, size)
        .body(body)
        .send()
        .await
        .map_err(|_| End::HandBack("cancelled"))?;
    if !response.status().is_success() {
        let (status, message) = crate::transport::refused(response).await;
        return Err(refusal(&crate::ml_transport::worker_refusal(
            status, &message,
        )));
    }
    let ack: Ack = crate::transport::json_limit(response, 65_536)
        .await
        .map_err(|_| End::HandBack("cancelled"))?;
    if ack.accepted {
        Ok(())
    } else {
        Err(End::LeaseLost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-transcode-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }
    fn task() -> Task {
        Task {
            id: Uuid::new_v4().to_string(),
            claim_token: Uuid::new_v4().to_string(),
            input_options: vec![],
            output_options: ["-c:v", "libx264", "-c:a", "aac", "-map", "0:0"]
                .map(String::from)
                .into(),
            two_pass: false,
            frame_count: 100,
            source_bytes: 2048,
            max_output_bytes: MIN_OUTPUT_ALLOWANCE,
        }
    }

    #[test]
    fn a_job_folder_is_removed_after_success_failure_and_cancel() {
        let root = scratch();
        for _ in 0..3 {
            let workspace = Workspace::create(&root.join("jobs"), &Uuid::new_v4().to_string());
            let workspace = workspace.unwrap();
            let folder = workspace.0.clone();
            fs::write(folder.join(INPUT), b"source").unwrap();
            fs::write(folder.join(OUTPUT), b"output").unwrap();
            fs::write(folder.join("pass-0.log"), b"log").unwrap();
            drop(workspace);
            assert!(!folder.exists());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_crash_leaves_nothing_after_the_next_launch() {
        let data = scratch();
        let folder = data.join(FOLDER).join(Uuid::new_v4().to_string());
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join(INPUT), b"source").unwrap();
        clear(&data.join(FOLDER), "ffmpeg");
        assert!(!data.join(FOLDER).exists());
        // Nothing to clean is not a fault.
        clear(&data.join(FOLDER), "ffmpeg");
        fs::remove_dir_all(data).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_next_launch_stops_only_the_encoder_it_recorded() {
        use crate::process_tree::ProcessIdentity;
        use std::os::unix::process::CommandExt;
        let start = || {
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
                .unwrap()
        };
        let identity = |child: &Child| {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match ProcessIdentity::of(child.id()) {
                    Some(found) if found.program.ends_with("sleep") => return found,
                    _ if Instant::now() > deadline => panic!("no identity"),
                    _ => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        };
        let data = scratch();
        let root = data.join(FOLDER);
        let folder = root.join(Uuid::new_v4().to_string());
        fs::create_dir_all(&folder).unwrap();

        // A record of another program's name leaves a live process alone.
        let mut other = start();
        fs::write(
            folder.join(PROCESS_RECORD),
            serde_json::to_vec(&identity(&other)).unwrap(),
        )
        .unwrap();
        stop_recorded(&folder.join(PROCESS_RECORD), "ffmpeg");
        std::thread::sleep(Duration::from_millis(100));
        assert!(other.try_wait().unwrap().is_none());
        other.kill().unwrap();
        other.wait().unwrap();

        let mut left = start();
        fs::write(
            folder.join(PROCESS_RECORD),
            serde_json::to_vec(&identity(&left)).unwrap(),
        )
        .unwrap();
        clear(&root, "sleep");
        let status = left.wait().unwrap();
        assert!(!status.success());
        assert!(!root.exists());
        fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn a_task_outside_its_limits_or_with_a_refused_command_is_not_run() {
        assert!(admit(task()).is_ok());
        let mut large = task();
        large.max_output_bytes = MIN_OUTPUT_ALLOWANCE + 1;
        assert_eq!(admit(large).err().unwrap().2, "input-invalid");
        let mut doubled = task();
        doubled.source_bytes = MIN_OUTPUT_ALLOWANCE;
        doubled.max_output_bytes = MIN_OUTPUT_ALLOWANCE * 2;
        assert!(admit(doubled).is_ok());
        let mut empty = task();
        empty.source_bytes = 0;
        assert_eq!(admit(empty).err().unwrap().2, "input-invalid");
        let mut attack = task();
        attack
            .output_options
            .extend(["-vf".to_string(), "movie=/etc/passwd".to_string()]);
        assert_eq!(admit(attack).err().unwrap().2, "encode-failed");
        let mut input = task();
        input.input_options = vec!["-i".into(), "/etc/passwd".into()];
        assert_eq!(admit(input).err().unwrap().2, "encode-failed");
        assert!(canonical_uuid(&Uuid::new_v4().to_string()));
        for value in ["../../etc", "", "ABC", "00000000000000000000000000000000"] {
            assert!(!canonical_uuid(value));
        }
    }

    #[test]
    fn a_lost_lease_stops_the_job_and_an_unreachable_server_gets_until_it_runs_out() {
        let early = Duration::from_secs(40);
        assert_eq!(judge_heartbeat(&Ok(true), early), Beat::Renewed);
        assert_eq!(judge_heartbeat(&Ok(false), early), Beat::Lost);
        let refused = Err("worker_lease_refused".to_string());
        assert_eq!(judge_heartbeat(&refused, early), Beat::Lost);
        let down = Err("worker_request_interrupted".to_string());
        assert_eq!(judge_heartbeat(&down, early), Beat::Retry);
        assert_eq!(judge_heartbeat(&down, LEASE), Beat::Lost);
        assert_eq!(refusal("worker_lease_refused"), End::LeaseLost);
        assert_eq!(refusal("server_http_500"), End::HandBack("cancelled"));
    }

    #[test]
    fn progress_rises_across_two_passes_and_is_left_out_when_unknown() {
        assert_eq!(overall_percent(Pass::Only, 25, 100), Some(25));
        assert_eq!(overall_percent(Pass::Only, 500, 100), Some(100));
        assert_eq!(overall_percent(Pass::First, 100, 100), Some(50));
        assert_eq!(overall_percent(Pass::Second, 0, 100), Some(50));
        assert_eq!(overall_percent(Pass::Second, 100, 100), Some(100));
        assert_eq!(overall_percent(Pass::Only, u64::MAX, u64::MAX), Some(100));
        assert_eq!(overall_percent(Pass::Only, 10, 0), None);

        let progress = EncodeProgress::new();
        assert_eq!(progress.get(), None);
        let first = "frame=40\nfps=1\nprogress=continue\nframe=N/A\nframe=100\n";
        read_progress(first.as_bytes(), Pass::First, 100, &progress);
        assert_eq!(progress.get(), Some(50));
        read_progress("frame=0\n".as_bytes(), Pass::Second, 100, &progress);
        assert_eq!(progress.get(), Some(50));
        read_progress("frame=60\n".as_bytes(), Pass::Second, 100, &progress);
        assert_eq!(progress.get(), Some(80));
        read_progress("frame=10\n".as_bytes(), Pass::Second, 100, &progress);
        assert_eq!(progress.get(), Some(80));
        progress.clear();
        assert_eq!(progress.get(), None);
        read_progress("frame=10\n".as_bytes(), Pass::Only, 0, &progress);
        assert_eq!(progress.get(), None);
    }

    #[test]
    fn a_heartbeat_names_progress_only_when_it_is_known() {
        let with: serde_json::Value =
            serde_json::from_str(&heartbeat_payload("token", Some(42))).unwrap();
        assert_eq!(
            with,
            serde_json::json!({"claimToken":"token","progress":42})
        );
        let without: serde_json::Value =
            serde_json::from_str(&heartbeat_payload("token", None)).unwrap();
        assert_eq!(without, serde_json::json!({"claimToken":"token"}));
    }

    #[test]
    fn disk_room_covers_the_source_and_the_largest_output() {
        assert!(enough_room(30, 10, 20));
        assert!(!enough_room(29, 10, 20));
        assert!(!enough_room(u64::MAX, u64::MAX, 1));
    }

    #[test]
    fn output_past_its_limit_is_caught_but_the_source_does_not_count() {
        let folder = scratch();
        fs::write(folder.join(INPUT), vec![0; 64]).unwrap();
        fs::write(folder.join(OUTPUT), vec![0; 10]).unwrap();
        assert!(!over_limit(&folder, 10));
        assert!(over_limit(&folder, 9));
        fs::write(folder.join("pass-0.log"), vec![0; 11]).unwrap();
        assert!(over_limit(&folder, 10));
        fs::remove_dir_all(folder).unwrap();
    }
}
