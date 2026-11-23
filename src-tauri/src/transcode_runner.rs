//! FL-1760: converts one video at a time for the server, beside the AI worker. The server decides
//! which computers get work: one it has not enabled is answered with no task.
//! A job that cannot finish here is handed back and starts from zero wherever it runs next.
use crate::{
    host_runtime::VerifiedHostRuntime,
    ml_transport::WorkerTransport,
    package_lease::CodeLease,
    process_tree::ProcessTree,
    runtime_store::InstalledFfmpeg,
    transcode_args::{self, Pass},
};
use futures_util::StreamExt;
use reqwest::{
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    Method,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    future::Future,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
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
const STOP_POLL: Duration = Duration::from_millis(100);
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
/// `work`'s answer, or `None` as soon as a stop is asked for, whatever `work` is waiting on.
async fn unless_stopped<T>(signals: Signals<'_>, work: impl Future<Output = T>) -> Option<T> {
    let stopped = async {
        while !signals.stop_work() {
            tokio::time::sleep(STOP_POLL).await;
        }
    };
    tokio::select! {
        biased;
        () = stopped => None,
        answer = work => Some(answer),
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
        // Renamed try_update in Rust 1.95; this crate still supports 1.90.
        #[allow(deprecated)]
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

/// A verified FFmpeg: the host package's, or else the installed AI runtime pack's. A program
/// found on PATH is never used, and with neither of these there are no conversions.
enum Encoder {
    Host {
        package: PathBuf,
        runtime: Box<VerifiedHostRuntime>,
    },
    Pack(Arc<InstalledFfmpeg>),
}
/// The program of one job. A pack's goes through its release's epoch check at every launch.
#[derive(Clone)]
struct Ffmpeg {
    path: PathBuf,
    pack: Option<Arc<InstalledFfmpeg>>,
}
impl Ffmpeg {
    fn launch<T>(&self, start: impl FnOnce(&Path) -> Result<T, ()>) -> Result<T, ()> {
        match &self.pack {
            Some(pack) => pack
                .launch(|| start(&self.path).map_err(|()| "transcode_launch_failed".to_string()))
                .map_err(|_| ()),
            None => start(&self.path),
        }
    }
}
impl Encoder {
    fn locate_host() -> Option<Self> {
        let mut records = crate::host_install::installed().ok()?;
        let library = crate::host_setup::library_package(&records);
        records.sort_by_key(|record| Some(&record.manifest_sha256) != library.as_ref());
        records.into_iter().find_map(|record| {
            let layout = record.layout().ok()?;
            let _lease = CodeLease::acquire_existing(&layout.runtime).ok()?;
            let (layout, runtime) = crate::host_setup::verified(&record).ok()?;
            runtime.ffmpeg().ok()?;
            Some(Self::Host {
                package: layout.runtime,
                runtime: Box::new(runtime),
            })
        })
    }
    /// Holds its package still for the job and reads its FFmpeg again. A pack's release is
    /// already held for as long as the worker's setup runs.
    fn ready(&self) -> Result<(Option<CodeLease>, Ffmpeg), String> {
        match self {
            Self::Host { package, runtime } => {
                let lease = CodeLease::acquire_existing(package)?;
                let path = runtime.ffmpeg()?;
                Ok((Some(lease), Ffmpeg { path, pack: None }))
            }
            Self::Pack(pack) => {
                let path = pack.check()?;
                let pack = Some(pack.clone());
                Ok((None, Ffmpeg { path, pack }))
            }
        }
    }
}

/// Checking a whole package is slow: done once while it stays good, and not again for a while
/// when there is none, which is the usual answer on a helper-only install.
static HOST: Mutex<(Option<Arc<Encoder>>, Option<Instant>)> = Mutex::new((None, None));
fn located_host() -> Option<Arc<Encoder>> {
    let mut known = HOST.lock().unwrap_or_else(|poison| poison.into_inner());
    let due = known
        .1
        .is_none_or(|checked| checked.elapsed() >= NO_FFMPEG_RECHECK);
    if known.0.is_none() && due {
        *known = (Encoder::locate_host().map(Arc::new), Some(Instant::now()));
    }
    known.0.clone()
}
fn forget_host() {
    *HOST.lock().unwrap_or_else(|poison| poison.into_inner()) = (None, Some(Instant::now()));
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

pub(crate) async fn run(
    worker: &WorkerTransport,
    data: &Path,
    pack: Option<InstalledFfmpeg>,
    signals: Signals<'_>,
) {
    let mut pack = pack.map(|ffmpeg| Arc::new(Encoder::Pack(Arc::new(ffmpeg))));
    let cleanup = data.to_path_buf();
    let _ = blocking(move || clean_after_crash(&cleanup)).await;
    let root = data.join(FOLDER);
    while !signals.over() {
        let pause = turn(worker, &root, &mut pack, signals).await;
        wait(pause, signals).await;
    }
}

async fn turn(
    worker: &WorkerTransport,
    root: &Path,
    pack: &mut Option<Arc<Encoder>>,
    signals: Signals<'_>,
) -> Duration {
    if signals.stop_work() {
        return CLAIM_EVERY;
    }
    let host = blocking(located_host).await.flatten();
    let Some(ready) = host.or_else(|| pack.clone()) else {
        return NO_FFMPEG_RECHECK;
    };
    let admitted = blocking(crate::resource_policy::sample)
        .await
        .is_some_and(|status| status.refusal(START_MEMORY).is_none());
    if !admitted || signals.stop_work() {
        return CLAIM_EVERY;
    }
    // Seen through here, because the requests of a job can be dropped part way.
    if worker.maintain_session().await.is_err() {
        return AFTER_ERROR;
    }
    // The lease is counted from before it was asked for, so never later than the server's.
    let asked = Instant::now();
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
        // Whichever it was is not offered again: asking for work it cannot do helps nobody.
        match *ready {
            Encoder::Host { .. } => forget_host(),
            Encoder::Pack(_) => *pack = None,
        }
        hand_back(worker, &job.id, &job.claim_token, "cancelled").await;
        return AFTER_ERROR;
    };
    convert(worker, root, &job, &ffmpeg, asked + LEASE, signals).await;
    drop(lease);
    Duration::ZERO
}

async fn convert(
    worker: &WorkerTransport,
    root: &Path,
    job: &Job,
    ffmpeg: &Ffmpeg,
    lease_ends: Instant,
    signals: Signals<'_>,
) {
    let (folder, id) = (root.to_path_buf(), job.id.clone());
    let Some(Ok(workspace)) = blocking(move || Workspace::create(&folder, &id)).await else {
        hand_back(worker, &job.id, &job.claim_token, "cancelled").await;
        return;
    };
    // The side that loses is dropped here: that ends a transfer and kills the encoder.
    let progress = Arc::new(EncodeProgress::new());
    let launches = Arc::new(LaunchGate::new());
    let end = tokio::select! {
        end = work(worker, job, &workspace.0, ffmpeg, &progress, &launches) => end,
        end = watch(worker, job, &progress, lease_ends, signals) => end,
    };
    // A launch still under way finishes and is killed before the folder or package is let go.
    let _ = blocking(move || launches.close()).await;
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
fn judge_heartbeat(answer: &Result<bool, String>, lease_left: Duration) -> Beat {
    match answer {
        Ok(true) => Beat::Renewed,
        Ok(false) => Beat::Lost,
        Err(code) if code == "worker_lease_refused" => Beat::Lost,
        Err(_) if lease_left.is_zero() => Beat::Lost,
        Err(_) => Beat::Retry,
    }
}
/// How long one heartbeat may take: never past the lease, and none at all once it is out.
fn heartbeat_limit(lease_left: Duration) -> Option<Duration> {
    (!lease_left.is_zero()).then(|| lease_left.min(HEARTBEAT_LIMIT))
}

/// Runs for as long as the job may: returns only when it has to stop.
async fn watch(
    worker: &WorkerTransport,
    job: &Job,
    progress: &EncodeProgress,
    mut lease_ends: Instant,
    signals: Signals<'_>,
) -> End {
    const GIVE_BACK: End = End::HandBack("cancelled");
    let (path, operation) = (
        format!("api/desktop/transcodes/{}/heartbeat", job.id),
        format!("transcode-heartbeat:{}", job.id),
    );
    // A server from before progress refuses the field: the lease matters more, so it is dropped.
    let mut send_progress = true;
    let mut beat_due = (lease_ends - LEASE) + HEARTBEAT_EVERY;
    let mut wall = SystemTime::now();
    let mut seconds = 0u32;
    let left = |ends: Instant| ends.saturating_duration_since(Instant::now());
    loop {
        let Some(tick) = heartbeat_limit(left(lease_ends)) else {
            return End::LeaseLost;
        };
        let pause = tokio::time::sleep(tick.min(Duration::from_secs(1)));
        if unless_stopped(signals, pause).await.is_none() {
            return GIVE_BACK;
        }
        let now = SystemTime::now();
        // The computer slept.
        if crate::worker_setup::wake_gap(wall, now) {
            return GIVE_BACK;
        }
        wall = now;
        seconds = seconds.wrapping_add(1);
        if seconds.is_multiple_of(5) {
            let Some(status) =
                unless_stopped(signals, blocking(crate::resource_policy::sample)).await
            else {
                return GIVE_BACK;
            };
            if status.is_none_or(|status| status.refusal(KEEP_MEMORY).is_some()) {
                return GIVE_BACK;
            }
        }
        if Instant::now() < beat_due {
            continue;
        }
        let Some(limit) = heartbeat_limit(left(lease_ends)) else {
            return End::LeaseLost;
        };
        let percent = progress.get().filter(|_| send_progress);
        let payload = heartbeat_payload(&job.claim_token, percent);
        let sent = Instant::now();
        let attempt = tokio::time::timeout(
            limit,
            worker.transcode_json::<Ack>(&path, &operation, &payload),
        );
        let Some(answer) = unless_stopped(signals, attempt).await else {
            return GIVE_BACK;
        };
        let answer = answer
            .unwrap_or_else(|_| Err("worker_request_interrupted".into()))
            .map(|ack| ack.accepted);
        if percent.is_some() && matches!(&answer, Err(code) if code == "server_http_400") {
            send_progress = false;
            beat_due = Instant::now();
            continue;
        }
        let lease_left = left(lease_ends);
        match judge_heartbeat(&answer, lease_left) {
            Beat::Renewed => {
                lease_ends = sent + LEASE;
                beat_due = sent + HEARTBEAT_EVERY;
            }
            Beat::Lost => return End::LeaseLost,
            Beat::Retry => beat_due = Instant::now() + HEARTBEAT_RETRY.min(lease_left),
        }
    }
}

async fn work(
    worker: &WorkerTransport,
    job: &Job,
    folder: &Path,
    ffmpeg: &Ffmpeg,
    progress: &Arc<EncodeProgress>,
    launches: &Arc<LaunchGate<RunningEncoder>>,
) -> End {
    let steps = async {
        check_disk(folder, job).await?;
        download(worker, job, &folder.join(INPUT)).await?;
        for pass in passes(job.two_pass) {
            encode(job, folder, ffmpeg, *pass, progress, launches).await?;
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

/// What a job may write besides its source: the output, and for two passes as much again for
/// their logs. The disk check reserves this and `over_limit` enforces it.
fn working_room(max_output: u64, two_pass: bool) -> Option<u64> {
    max_output.checked_mul(if two_pass { 2 } else { 1 })
}
fn enough_room(available: u64, source: u64, max_output: u64, two_pass: bool) -> bool {
    working_room(max_output, two_pass)
        .and_then(|room| source.checked_add(room))
        .is_some_and(|needed| available >= needed)
}
async fn check_disk(folder: &Path, job: &Job) -> Result<(), End> {
    let path = folder.to_path_buf();
    let available = blocking(move || crate::host_storage::available_bytes(&path)).await;
    match available {
        Some(Ok(bytes))
            if enough_room(bytes, job.source_bytes, job.max_output_bytes, job.two_pass) =>
        {
            Ok(())
        }
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

/// Whether the job's own files have grown past what it may write: the output past its limit,
/// or everything but the source past the room the disk check reserved.
fn over_limit(folder: &Path, max_output: u64, room: u64) -> bool {
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
        if name == OUTPUT && bytes > max_output {
            return true;
        }
        total = total.saturating_add(bytes);
    }
    total > room
}

/// Where a launch on the blocking pool leaves what it started. Dropping the job's future does not
/// stop that launch, so `close` waits for it and ends whatever nobody came back for.
struct LaunchGate<T>(Mutex<(bool, Option<T>)>);
impl<T> LaunchGate<T> {
    fn new() -> Self {
        Self(Mutex::new((false, None)))
    }
    fn state(&self) -> std::sync::MutexGuard<'_, (bool, Option<T>)> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }
    /// Starts it unless the gate has closed, holding the gate shut against `close` meanwhile.
    fn launch(&self, start: impl FnOnce() -> Result<T, ()>) -> bool {
        let mut state = self.state();
        if state.0 {
            return false;
        }
        match start() {
            Ok(started) => {
                state.1 = Some(started);
                true
            }
            Err(()) => false,
        }
    }
    fn take(&self) -> Option<T> {
        self.state().1.take()
    }
    fn close(&self) {
        let mut state = self.state();
        state.0 = true;
        drop(state.1.take());
    }
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
    ffmpeg: &Ffmpeg,
    pass: Pass,
    progress: &Arc<EncodeProgress>,
    launches: &Arc<LaunchGate<RunningEncoder>>,
) -> Result<(), End> {
    const FAILED: End = End::HandBack("encode-failed");
    let (options, target, program) = (job.options.clone(), folder.to_path_buf(), ffmpeg.clone());
    // Starting a process and writing its record touch the disk.
    let (frame_count, shared, gate) = (job.frame_count, progress.clone(), launches.clone());
    let launched = blocking(move || {
        gate.launch(|| {
            program.launch(|path| start_encoder(&options, &target, path, pass, frame_count, shared))
        })
    })
    .await
    .unwrap_or(false);
    if !launched {
        return Err(FAILED);
    }
    let mut running = launches.take().ok_or(FAILED)?;
    let limit = job.max_output_bytes;
    let room = working_room(limit, job.two_pass).ok_or(FAILED)?;
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
        if ticks.is_multiple_of(4) {
            let target = folder.to_path_buf();
            if blocking(move || over_limit(&target, limit, room))
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
        || blocking(move || over_limit(&target, limit, room))
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

/// When an upload's body last moved. The next chunk is asked for once the last has been written.
struct UploadActivity {
    last: Mutex<tokio::time::Instant>,
    sent: AtomicU64,
    size: u64,
}
impl UploadActivity {
    fn new(size: u64) -> Self {
        Self {
            last: Mutex::new(tokio::time::Instant::now()),
            sent: AtomicU64::new(0),
            size,
        }
    }
    fn wrote(&self, bytes: u64) {
        self.sent.fetch_add(bytes, Ordering::AcqRel);
        *self
            .last
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = tokio::time::Instant::now();
    }
    /// Ends when the body has not moved for `limit`. Once all of it is out the server may take
    /// its time checking the file, so only the total limit applies.
    async fn stalled(&self, limit: Duration) {
        loop {
            let last = *self
                .last
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let due = last + limit;
            let body_left = self.sent.load(Ordering::Acquire) < self.size;
            if body_left && tokio::time::Instant::now() >= due {
                return;
            }
            let wake = if body_left {
                due
            } else {
                tokio::time::Instant::now() + limit
            };
            tokio::time::sleep_until(wake).await;
        }
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
    let activity = Arc::new(UploadActivity::new(size));
    let moved = activity.clone();
    let chunks =
        crate::copy_upload::part_stream(Arc::new(file), 0, size, Arc::new(AtomicBool::new(false)))
            .inspect(move |chunk| {
                if let Ok(chunk) = chunk {
                    moved.wrote(chunk.len() as u64);
                }
            });
    let body = reqwest::Body::wrap_stream(chunks);
    // Not signed, and no lock is held: heartbeats keep going while this runs.
    let sending = client
        .put(url)
        .timeout(TRANSFER_LIMIT)
        .header("x-frameleaf-transcode-upload", grant.upload_token)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, size)
        .body(body)
        .send();
    let response = tokio::select! {
        response = sending => response.map_err(|_| End::HandBack("cancelled"))?,
        () = activity.stalled(STALL_LIMIT) => return Err(End::HandBack("cancelled")),
    };
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

    /// Needs the pinned FFmpeg: `FRAMELEAF_PINNED_MEDIA` is a folder holding its `ffmpeg` and
    /// `ffprobe`, and `commands.json` with the commands `server/src/utils/media.ts` emits.
    #[tokio::test]
    #[ignore = "needs the pinned FFmpeg in FRAMELEAF_PINNED_MEDIA"]
    async fn the_pinned_ffmpeg_runs_the_servers_commands_and_keeps_to_its_whitelists() {
        let media = PathBuf::from(std::env::var("FRAMELEAF_PINNED_MEDIA").unwrap());
        let suffix = std::env::consts::EXE_SUFFIX;
        let (ffmpeg, ffprobe) = (
            media.join(format!("ffmpeg{suffix}")),
            media.join(format!("ffprobe{suffix}")),
        );
        let commands: serde_json::Value =
            serde_json::from_slice(&fs::read(media.join("commands.json")).unwrap()).unwrap();
        let strings = |value: &serde_json::Value| -> Vec<String> {
            serde_json::from_value(value.clone()).unwrap()
        };
        for (name, command) in commands.as_object().unwrap() {
            transcode_args::validate(
                &strings(&command["inputOptions"]),
                &strings(&command["outputOptions"]),
            )
            .unwrap_or_else(|_| panic!("{name} refused"));
        }
        let root = scratch();
        let make = |args: &[&str], output: &Path| {
            let status = Command::new(&ffmpeg)
                .args(["-hide_banner", "-v", "error", "-nostdin", "-y"])
                .args(args)
                .arg(output)
                .status()
                .unwrap();
            assert!(status.success());
        };
        let (sdr, hdr) = (root.join("sdr.mp4"), root.join("hdr.mp4"));
        let sources = [
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=1920x1080:rate=24:duration=2",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=1000:sample_rate=48000:duration=2",
            "-c:a",
            "aac",
            "-ac",
            "2",
        ];
        make(
            &[
                &sources[..],
                &[
                    "-c:v",
                    "libx264",
                    "-preset",
                    "ultrafast",
                    "-pix_fmt",
                    "yuv420p",
                ],
            ]
            .concat(),
            &sdr,
        );
        make(
            &[
                &sources[..],
                &[
                    "-c:v",
                    "libx265",
                    "-preset",
                    "ultrafast",
                    "-x265-params",
                    "log-level=error",
                    "-pix_fmt",
                    "yuv420p10le",
                    "-color_primaries",
                    "bt2020",
                    "-color_trc",
                    "smpte2084",
                    "-colorspace",
                    "bt2020nc",
                ],
            ]
            .concat(),
            &hdr,
        );
        // A job path with a space and a non-ASCII letter. On Windows it stays as the OS spells it,
        // not canonical; elsewhere the temp folder can sit behind a link (`/var` on macOS), which
        // job folders refuse, as they would for an app data folder.
        let temp = std::env::temp_dir();
        let temp = if cfg!(windows) {
            temp
        } else {
            temp.canonicalize().unwrap()
        };
        let plain = temp.join(format!("frameleaf job é {}", Uuid::new_v4()));
        fs::create_dir_all(&plain).unwrap();
        for (name, source, jobs) in [
            ("onePass", &sdr, &root),
            ("onePass", &sdr, &plain),
            ("onePassCapped", &sdr, &root),
            ("twoPass", &sdr, &root),
            ("twoPass", &sdr, &plain),
            ("tonemap", &hdr, &root),
        ] {
            let command = &commands[name];
            let two_pass = command["twoPass"].as_bool().unwrap();
            assert_eq!(two_pass, name == "twoPass");
            let job = Job {
                id: Uuid::new_v4().to_string(),
                claim_token: Uuid::new_v4().to_string(),
                options: transcode_args::validate(&[], &strings(&command["outputOptions"]))
                    .unwrap(),
                two_pass,
                frame_count: 48,
                source_bytes: fs::metadata(source).unwrap().len(),
                max_output_bytes: MIN_OUTPUT_ALLOWANCE,
            };
            let workspace = Workspace::create(&jobs.join("jobs"), &job.id).unwrap();
            fs::copy(source, workspace.0.join(INPUT)).unwrap();
            let progress = Arc::new(EncodeProgress::new());
            let launches = Arc::new(LaunchGate::new());
            for pass in passes(two_pass) {
                let program = Ffmpeg {
                    path: ffmpeg.clone(),
                    pack: None,
                };
                encode(&job, &workspace.0, &program, *pass, &progress, &launches)
                    .await
                    .unwrap_or_else(|end| panic!("{name}: {end:?}"));
                let expected = if *pass == Pass::First { 50 } else { 100 };
                assert_eq!(progress.get(), Some(expected), "{name}");
            }
            let probed = Command::new(&ffprobe)
                .args([
                    "-v",
                    "error",
                    "-show_streams",
                    "-show_format",
                    "-of",
                    "json",
                ])
                .arg(workspace.0.join(OUTPUT))
                .output()
                .unwrap();
            assert!(probed.status.success(), "{name}");
            let facts: serde_json::Value = serde_json::from_slice(&probed.stdout).unwrap();
            let stream = |kind: &str| {
                facts["streams"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|stream| stream["codec_type"] == kind)
                    .unwrap_or_else(|| panic!("{name}: no {kind}"))
                    .clone()
            };
            let (video, audio) = (stream("video"), stream("audio"));
            assert_eq!(video["codec_name"], "h264", "{name}");
            assert_eq!(
                (&video["width"], &video["height"]),
                (&1280.into(), &720.into())
            );
            // The server's tone map asks for full range (`r=pc`), which H.264 reports as yuvj420p.
            let picture = if name == "tonemap" {
                "yuvj420p"
            } else {
                "yuv420p"
            };
            assert_eq!(video["pix_fmt"], picture, "{name}");
            assert_eq!(audio["codec_name"], "aac", "{name}");
            assert_eq!(audio["channels"], 2, "{name}");
            let duration: f64 = facts["format"]["duration"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            assert!((1.9..=2.2).contains(&duration), "{name}: {duration}");
            if name == "tonemap" {
                assert_eq!(video["color_transfer"], "bt709", "tone mapped");
                assert_eq!(video["color_primaries"], "bt709", "tone mapped");
            }
        }

        // The builder's own command line, on inputs that try to reach outside the job.
        let options =
            transcode_args::validate(&[], &strings(&commands["onePass"]["outputOptions"])).unwrap();
        let output = plain.join("refused.mp4");
        let run = |args: Vec<std::ffi::OsString>| {
            Command::new(&ffmpeg)
                .args(args)
                .stdin(Stdio::null())
                .output()
                .unwrap()
        };
        let built = |input: &Path| {
            transcode_args::ffmpeg_args(input, &output, &plain.join("log"), &options, Pass::Only)
        };
        let segment = plain.join("segment.ts");
        make(
            &["-i", sdr.to_str().unwrap(), "-c", "copy", "-f", "mpegts"],
            &segment,
        );
        let playlist = plain.join("reads-a-file.m3u8");
        fs::write(
            &playlist,
            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\nsegment.ts\n#EXT-X-ENDLIST\n",
        )
        .unwrap();
        // Proves the playlist is a real attack: with the format list taken out, it opens.
        let control = run(built(&playlist)
            .into_iter()
            .collect::<Vec<_>>()
            .chunks(1)
            .map(|arg| arg[0].clone())
            .scan(false, |skip, arg| {
                let drop = *skip || arg == "-format_whitelist";
                *skip = arg == "-format_whitelist";
                Some((!drop).then_some(arg))
            })
            .flatten()
            .flat_map(|arg| {
                if arg == "-i" {
                    vec!["-allowed_extensions".into(), "ALL".into(), arg]
                } else {
                    vec![arg]
                }
            })
            .collect());
        assert!(
            control.status.success() && fs::metadata(&output).is_ok_and(|meta| meta.len() > 0),
            "the playlist should read its segment without the list"
        );
        fs::remove_file(&output).unwrap();
        let concat = plain.join("reads-a-file.ffconcat");
        fs::write(&concat, "ffconcat version 1.0\nfile 'segment.ts'\n").unwrap();
        for input in [&playlist, &concat] {
            let refused = run(built(input));
            assert!(!refused.status.success(), "{input:?}");
            assert!(!output.exists(), "{input:?}");
        }
        for url in [
            "http://127.0.0.1:9/video.mp4",
            "https://127.0.0.1:9/video.mp4",
            "tcp://127.0.0.1:9",
            "data:text/plain;base64,AAAA",
        ] {
            let refused = run(built(Path::new(url)));
            let said = String::from_utf8_lossy(&refused.stderr);
            assert!(!refused.status.success(), "{url}");
            assert!(said.contains("not on whitelist"), "{url}: {said}");
        }
        fs::remove_dir_all(plain).unwrap();
        fs::remove_dir_all(root).unwrap();
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
        let early = Duration::from_secs(80);
        assert_eq!(judge_heartbeat(&Ok(true), early), Beat::Renewed);
        assert_eq!(judge_heartbeat(&Ok(false), early), Beat::Lost);
        let refused = Err("worker_lease_refused".to_string());
        assert_eq!(judge_heartbeat(&refused, early), Beat::Lost);
        let down = Err("worker_request_interrupted".to_string());
        assert_eq!(judge_heartbeat(&down, early), Beat::Retry);
        assert_eq!(judge_heartbeat(&down, Duration::ZERO), Beat::Lost);
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
    fn a_heartbeat_never_runs_past_the_lease() {
        assert_eq!(heartbeat_limit(LEASE), Some(HEARTBEAT_LIMIT));
        assert_eq!(
            heartbeat_limit(Duration::from_secs(3)),
            Some(Duration::from_secs(3))
        );
        assert_eq!(heartbeat_limit(Duration::ZERO), None);
    }

    #[tokio::test]
    async fn a_stop_is_seen_while_a_request_is_still_waiting() {
        let (cancelled, paused, ended) = (
            AtomicBool::new(false),
            AtomicBool::new(false),
            AtomicBool::new(false),
        );
        let signals = Signals {
            cancelled: &cancelled,
            paused: &paused,
            ended: &ended,
        };
        assert_eq!(unless_stopped(signals, async { 7 }).await, Some(7));
        let pause = async {
            tokio::time::sleep(STOP_POLL).await;
            paused.store(true, Ordering::Release);
        };
        let (answer, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(unless_stopped(signals, std::future::pending::<u8>()), pause)
        })
        .await
        .unwrap();
        assert_eq!(answer, None);
    }

    #[tokio::test(start_paused = true)]
    async fn an_upload_stalls_only_while_body_is_left_and_each_write_resets_it() {
        let limit = Duration::from_secs(60);
        let activity = UploadActivity::new(10);
        tokio::time::advance(Duration::from_secs(59)).await;
        activity.wrote(4);
        let waited = tokio::time::Instant::now();
        activity.stalled(limit).await;
        assert_eq!(waited.elapsed(), limit);

        // All of it written: the server may take as long as the total limit allows.
        activity.wrote(6);
        assert!(tokio::time::timeout(limit * 10, activity.stalled(limit))
            .await
            .is_err());
    }

    #[test]
    fn closing_the_gate_waits_for_a_launch_and_ends_what_it_started() {
        struct Started(Arc<AtomicBool>);
        impl Drop for Started {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let ended = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(LaunchGate::new());
        let (entered, inside) = std::sync::mpsc::channel();
        let (launching, flag) = (gate.clone(), ended.clone());
        let launch = std::thread::spawn(move || {
            launching.launch(|| {
                entered.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(100));
                Ok(Started(flag))
            })
        });
        inside.recv().unwrap();
        gate.close();
        // Back from `close` only once the launch finished and its result was ended.
        assert!(ended.load(Ordering::Acquire));
        assert!(launch.join().unwrap());
        assert!(gate.take().is_none());
        let mut ran = false;
        assert!(!gate.launch(|| {
            ran = true;
            Err(())
        }));
        assert!(!ran);
    }

    #[cfg(unix)]
    #[test]
    fn closing_the_gate_kills_and_reaps_an_encoder_nobody_came_back_for() {
        use crate::process_tree::{Presence, ProcessIdentity};
        let gate = LaunchGate::new();
        let mut pid = 0;
        assert!(gate.launch(|| {
            let mut command = Command::new("/bin/sleep");
            command.arg("30");
            crate::process_tree::configure(&mut command);
            let child = command.spawn().map_err(|_| ())?;
            pid = child.id();
            let tree = ProcessTree::attach(&child).map_err(|_| ())?;
            Ok(RunningEncoder {
                child,
                tree,
                ended: false,
                reader: None,
            })
        }));
        gate.close();
        assert_eq!(ProcessIdentity::lookup(pid), Presence::Absent);
    }

    #[test]
    fn disk_room_covers_everything_the_job_may_write() {
        assert!(enough_room(30, 10, 20, false));
        assert!(!enough_room(29, 10, 20, false));
        // Two passes may write their logs as well as the output.
        assert!(enough_room(50, 10, 20, true));
        assert!(!enough_room(49, 10, 20, true));
        assert!(!enough_room(u64::MAX, u64::MAX, 1, false));
        assert!(!enough_room(u64::MAX, 0, u64::MAX, true));
        assert_eq!(working_room(u64::MAX, true), None);
    }

    #[test]
    fn output_past_its_limit_is_caught_but_the_source_does_not_count() {
        let folder = scratch();
        fs::write(folder.join(INPUT), vec![0; 64]).unwrap();
        fs::write(folder.join(OUTPUT), vec![0; 10]).unwrap();
        assert!(!over_limit(&folder, 10, 10));
        assert!(over_limit(&folder, 9, 18));
        fs::write(folder.join("pass-0.log"), vec![0; 10]).unwrap();
        // One pass has no room for a log; two have exactly what the disk check reserved.
        assert!(over_limit(&folder, 10, working_room(10, false).unwrap()));
        assert!(!over_limit(&folder, 10, working_room(10, true).unwrap()));
        fs::write(folder.join("pass-0.log"), vec![0; 11]).unwrap();
        assert!(over_limit(&folder, 10, working_room(10, true).unwrap()));
        fs::remove_dir_all(folder).unwrap();
    }
}
