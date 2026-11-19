//! FD-77: Computer backup. This computer's own folders (Documents, Desktop and Downloads by default; the
//! photo library is left out because Cloud Backup already has it) go to Frameleaf Cloud through the backup
//! engine (`frameleaf-backup-core`, FD-75) as a `frameleaf-repository/1` repository in the computer's own
//! bucket (FC-288). The repository key is the recovery key: made here, kept in the OS credential store,
//! never sent to Cloud (except locked with a passphrase, when the person asks).
//!
//! Every backup runs in the background agent (`frameleaf-desktop --computer-backup`), which the OS starts
//! every 15 minutes whether or not the app is open; Back Up Now starts the same agent at once. The agent
//! writes its progress to `state.json` and stops when `stop` appears, so the window only reads and asks.

use crate::computer_backup_cloud::{self as cloud, Cloud, Grant, Link, Refusal};
use frameleaf_backup_core::{
    self as engine,
    s3::{S3Credentials, S3Options, S3Store},
    snapshot_record::{sign_snapshot_descriptor, Manifest, SnapshotDescriptor},
    BackupOptions, Repository, RetentionPolicy, Source, Store,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const LINK_CREDENTIAL: &str = "computer-backup-link";
pub(crate) const KEY_CREDENTIAL: &str = "computer-backup-key";
pub const AGENT_FLAG: &str = "--computer-backup";

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn iso_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

// ---------------------------------------------------------------- where things are kept

/// `<app local data>/computer-backup`, found without Tauri so the agent can use it. A development build
/// may put it elsewhere (`FRAMELEAF_COMPUTER_BACKUP_DIR`), as the end-to-end test does.
pub(crate) fn data_dir() -> PathBuf {
    if let Some(dir) =
        std::env::var_os("FRAMELEAF_COMPUTER_BACKUP_DIR").filter(|_| cfg!(debug_assertions))
    {
        return PathBuf::from(dir);
    }
    let base = if cfg!(target_os = "macos") {
        home().join("Library/Application Support")
    } else if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(home)
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".local/share"))
    };
    base.join("app.frameleaf.desktop").join("computer-backup")
}

pub(crate) fn home() -> PathBuf {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn read_json<T: for<'a> Deserialize<'a> + Default>(path: &Path) -> T {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Written whole to a temporary file first, so a reader never sees half of it.
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))
        .map_err(|_| "computer_backup_storage_failed")?;
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(value).expect("JSON"))
        .and_then(|_| fs::rename(&temporary, path))
        .map_err(|_| "computer_backup_storage_failed".into())
}

// ---------------------------------------------------------------- settings (the person's choices)

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Folder {
    pub id: String,
    /// The folder's name at the top of every backup. Unique.
    pub name: String,
    pub path: String,
    pub on: bool,
    #[serde(default)]
    pub photos: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Schedule {
    /// `hour` or `day`.
    pub every: String,
    /// Minutes after local midnight, for `day`.
    pub at: u32,
    /// Minutes after local midnight a running backup stops by, or None.
    pub stop_by: Option<u32>,
    /// Mbit/s, or None for no limit.
    pub limit_mbps: Option<u32>,
    pub wait_on_battery: bool,
    /// `recommended`, `30d`, `1y` or `forever`.
    pub keep: String,
}

impl Default for Schedule {
    fn default() -> Self {
        Schedule {
            every: "day".into(),
            at: 120,
            stop_by: Some(420),
            limit_mbps: None,
            wait_on_battery: true,
            keep: "recommended".into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Settings {
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub schedule: Schedule,
    /// Set-up finished and backups are on.
    #[serde(default)]
    pub enabled: bool,
    pub key_saved_at: Option<String>,
    #[serde(default)]
    pub locked_copy: bool,
    /// Whether the account has a Cloud plan, once Cloud said so.
    pub plan: Option<bool>,
    /// Every name a backup ever used, and where it came from, so a restore can put it back.
    #[serde(default)]
    pub places: Vec<(String, String)>,
}

pub(crate) fn settings_path() -> PathBuf {
    data_dir().join("settings.json")
}

pub(crate) fn load_settings() -> Settings {
    let mut settings: Settings = read_json(&settings_path());
    if settings.folders.is_empty() {
        settings.folders = default_folders();
    }
    settings
}

pub(crate) fn save_settings(settings: &Settings) -> Result<(), String> {
    write_json(&settings_path(), settings)
}

/// Documents, Desktop and Downloads on; the photo library found and left out.
pub(crate) fn default_folders() -> Vec<Folder> {
    let home = home();
    let mut folders: Vec<Folder> = ["Documents", "Desktop", "Downloads"]
        .into_iter()
        .map(|name| Folder {
            id: name.to_lowercase(),
            name: name.into(),
            path: home.join(name).to_string_lossy().into_owned(),
            on: true,
            photos: false,
        })
        .collect();
    let (name, photos) = if cfg!(target_os = "macos") {
        (
            "Photos Library",
            home.join("Pictures/Photos Library.photoslibrary"),
        )
    } else {
        ("Pictures", home.join("Pictures"))
    };
    if photos.exists() {
        folders.push(Folder {
            id: "pictures".into(),
            name: name.into(),
            path: photos.to_string_lossy().into_owned(),
            on: false,
            photos: true,
        });
    }
    folders
}

/// Another folder the person chose. Its name is unique among the folders backed up.
pub(crate) fn add_folder(settings: &mut Settings, path: &Path) -> Result<(), String> {
    let base = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "Folder".into());
    let path_text = path.to_string_lossy().into_owned();
    if let Some(existing) = settings
        .folders
        .iter_mut()
        .find(|folder| folder.path == path_text)
    {
        existing.on = true;
        return Ok(());
    }
    let mut name = base.clone();
    let mut n = 2;
    while settings.folders.iter().any(|folder| folder.name == name) {
        name = format!("{base} {n}");
        n += 1;
    }
    settings.folders.push(Folder {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        path: path_text,
        on: true,
        photos: false,
    });
    Ok(())
}

// ---------------------------------------------------------------- state (what the agent did)

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Running {
    pub started_at: i64,
    pub files: u64,
    pub bytes: u64,
    pub total_files: u64,
    pub total_bytes: u64,
    pub stored_bytes: u64,
    pub heartbeat: i64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunRecord {
    pub at: i64,
    /// `backup`, `restore` or `failed`.
    pub kind: String,
    pub ok: bool,
    pub files: u64,
    pub bytes: u64,
    pub took_ms: i64,
    pub problem: Option<String>,
    /// For a restore: the backup's time, and whether it went back where it was.
    pub from: Option<String>,
    pub original: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Sizes {
    pub files: u64,
    pub bytes: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct State {
    pub running: Option<Running>,
    #[serde(default)]
    pub runs: Vec<RunRecord>,
    pub last_attempt: Option<i64>,
    pub last_success: Option<i64>,
    pub last_prune: Option<i64>,
    pub problem: Option<String>,
    #[serde(default)]
    pub offline: bool,
    /// Bytes: this computer's bucket, the account's total and the plan's allowance.
    pub usage: Option<(u64, u64, u64)>,
    /// `holdUntil` of a held purge.
    pub purge: Option<String>,
    /// By folder name, from the newest backup.
    #[serde(default)]
    pub sizes: std::collections::BTreeMap<String, Sizes>,
    /// The run lease of a run that stopped without giving it back, resumed by the next run.
    pub lease: Option<String>,
    #[serde(default)]
    pub skipped: u64,
}

pub(crate) fn state_path() -> PathBuf {
    data_dir().join("state.json")
}

static STATE_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn load_state() -> State {
    read_json(&state_path())
}

pub(crate) fn update_state(change: impl FnOnce(&mut State)) -> State {
    let _guard = STATE_LOCK.lock();
    let mut state = load_state();
    change(&mut state);
    let _ = write_json(&state_path(), &state);
    state
}

pub(crate) fn record(state: &mut State, run: RunRecord) {
    state.runs.insert(0, run);
    state.runs.truncate(20);
}

fn stop_path() -> PathBuf {
    data_dir().join("stop")
}

pub(crate) fn ask_stop() {
    let _ = fs::create_dir_all(data_dir());
    let _ = fs::write(stop_path(), b"");
}

/// A run is going if its heartbeat is under two minutes old (a crashed agent's is not).
pub(crate) fn is_running(state: &State) -> bool {
    state
        .running
        .as_ref()
        .is_some_and(|run| now_ms() - run.heartbeat < 120_000)
}

// ---------------------------------------------------------------- keys

#[derive(Serialize, Deserialize)]
pub(crate) struct SavedKey {
    pub code: String,
}

pub(crate) fn recovery_key() -> Result<Option<[u8; 32]>, String> {
    Ok(crate::credentials::load::<SavedKey>(KEY_CREDENTIAL)?
        .and_then(|saved| engine::parse_recovery_code(&saved.code)))
}

/// The recovery key, made the first time it is asked for.
pub(crate) fn ensure_recovery_key() -> Result<String, String> {
    if let Some(saved) = crate::credentials::load::<SavedKey>(KEY_CREDENTIAL)? {
        return Ok(saved.code);
    }
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    let code = engine::recovery_code(&key);
    crate::credentials::save(KEY_CREDENTIAL, &SavedKey { code: code.clone() })?;
    Ok(code)
}

pub(crate) fn link() -> Result<Option<Link>, String> {
    crate::credentials::load::<Link>(LINK_CREDENTIAL)
}

// ---------------------------------------------------------------- storage through Cloud

/// Where this computer's repository lives in its bucket: its vault is its instance id.
pub(crate) fn prefix(link: &Link) -> String {
    format!("r/v1/{}/", link.instance_id)
}

/// A store whose credentials come from Cloud and are renewed before `refreshAfterSec`, or when the
/// provider says they expired.
pub(crate) fn store(
    cloud: Arc<Cloud>,
    operation: &'static str,
    lease: Option<String>,
    limit: Option<u64>,
) -> Result<(S3Store, bool), Refusal> {
    let first = cloud.grant(operation, lease.as_deref())?;
    let at = prefix(&cloud.link);
    let read_only = first.read_only;
    let held: Arc<Mutex<(Grant, Instant)>> = Arc::new(Mutex::new((first.clone(), Instant::now())));
    let credentials = Box::new(move |expired: bool| {
        let mut held = held
            .lock()
            .map_err(|_| engine::Error::Invalid("lock".into()))?;
        if expired || held.1.elapsed() >= held.0.refresh_after {
            let next = cloud
                .rotate(operation, lease.as_deref())
                .map_err(|refusal| engine::Error::S3 {
                    message: refusal.code(),
                    status: Some(refusal.status),
                    code: Some(refusal.code()),
                })?;
            *held = (next, Instant::now());
        }
        Ok(S3Credentials {
            access_key_id: held.0.access_key_id.clone(),
            secret_access_key: held.0.secret_access_key.clone(),
            session_token: Some(held.0.session_token.clone()),
        })
    });
    let mut options = S3Options::new(&first.endpoint, &first.region, &first.bucket, credentials);
    options.prefix = at;
    if let Some(limit) = limit {
        options.upload_limit = Some(Arc::new(move || Some(limit)));
    }
    let store = S3Store::new(options).map_err(|_| Refusal {
        status: 0,
        code: "computer_backup_storage_failed".into(),
    })?;
    Ok((store, read_only))
}

fn engine_code(error: &engine::Error) -> String {
    match error {
        engine::Error::Stopped => "computer_backup_stopped".into(),
        engine::Error::Unseal => "computer_backup_key_wrong".into(),
        engine::Error::S3 { status: None, .. } => cloud::UNREACHABLE.into(),
        engine::Error::S3 {
            code: Some(code), ..
        } if code.starts_with("computer_backup") || code.contains('-') => code.clone(),
        engine::Error::S3 { .. } => "computer_backup_storage_failed".into(),
        _ => "computer_backup_failed".into(),
    }
}

pub(crate) fn open_repository(
    store: impl Store + 'static,
    key: &[u8; 32],
    create: bool,
) -> Result<Repository, String> {
    let store: Arc<dyn Store> = Arc::new(store);
    let empty = store
        .list("config")
        .map_err(|e| engine_code(&e))?
        .is_empty();
    if empty && create {
        Repository::init(store, key, Some("1"), None).map_err(|e| engine_code(&e))
    } else if empty {
        Err("computer_backup_nothing_yet".into())
    } else {
        Repository::open(store, key).map_err(|e| engine_code(&e))
    }
}

// ---------------------------------------------------------------- when to run

/// Whether a scheduled backup is due at `now_local` (minutes after local midnight, and the local day number).
pub(crate) fn due(
    schedule: &Schedule,
    last_attempt_ms: Option<i64>,
    now_ms: i64,
    offset_ms: i64,
) -> bool {
    let Some(last) = last_attempt_ms else {
        return true;
    };
    if schedule.every == "hour" {
        return now_ms - last >= 3_600_000;
    }
    let local = now_ms + offset_ms;
    let today_at = local - local.rem_euclid(86_400_000) + i64::from(schedule.at) * 60_000;
    let slot = if local >= today_at {
        today_at
    } else {
        today_at - 86_400_000
    };
    last + offset_ms < slot
}

/// Whether `stop_by` has come for a run that started at `started_ms`.
pub(crate) fn past_stop_by(
    schedule: &Schedule,
    started_ms: i64,
    now_ms: i64,
    offset_ms: i64,
) -> bool {
    let Some(stop) = schedule.stop_by else {
        return false;
    };
    let started = started_ms + offset_ms;
    let mut stop_at = started - started.rem_euclid(86_400_000) + i64::from(stop) * 60_000;
    if stop_at <= started {
        stop_at += 86_400_000;
    }
    now_ms + offset_ms >= stop_at
}

fn retention(keep: &str) -> Option<RetentionPolicy> {
    match keep {
        "forever" => None,
        "30d" => Some(RetentionPolicy {
            keep_last: 3,
            keep_days: 30,
            keep_monthly: 0,
        }),
        "1y" => Some(RetentionPolicy {
            keep_last: 3,
            keep_days: 365,
            keep_monthly: 0,
        }),
        _ => Some(engine::maintenance::DEFAULT_RETENTION),
    }
}

const SKIPPED_FOLDERS: [&str; 3] = ["Caches", "node_modules", ".cache"];

/// Names never worth keeping: caches, the trash and system clutter.
fn skipped(path: &[String], entry: &engine::SourceEntry) -> bool {
    let name = entry.name.as_str();
    matches!(
        name,
        ".DS_Store"
            | ".Trash"
            | ".Trashes"
            | "Thumbs.db"
            | "desktop.ini"
            | "$RECYCLE.BIN"
            | ".fseventsd"
            | ".Spotlight-V100"
    ) || (entry.kind == engine::EntryType::Dir && SKIPPED_FOLDERS.contains(&name) && path.len() > 1)
}

// ---------------------------------------------------------------- one backup

pub(crate) struct RunOptions {
    /// Back Up Now: run even when not due or on battery.
    pub now: bool,
    pub offset_ms: i64,
}

/// Runs one backup if one is due. Returns false when nothing was due.
pub(crate) fn run(options: &RunOptions) -> Result<bool, String> {
    let settings = load_settings();
    if !settings.enabled {
        return Ok(false);
    }
    let state = load_state();
    if is_running(&state) {
        return Ok(false);
    }
    if !options.now {
        if !due(
            &settings.schedule,
            state.last_attempt,
            now_ms(),
            options.offset_ms,
        ) {
            return Ok(false);
        }
        if settings.schedule.wait_on_battery && crate::computer_backup_platform::on_battery() {
            return Ok(false);
        }
    }
    let _ = fs::remove_file(stop_path());
    let started = now_ms();
    update_state(|state| {
        state.last_attempt = Some(started);
        state.running = Some(Running {
            started_at: started,
            heartbeat: started,
            ..Default::default()
        });
    });
    let outcome = backup_once(&settings, options, started);
    let took = now_ms() - started;
    update_state(|state| {
        state.running = None;
        match &outcome {
            Ok((stats, problems)) => {
                state.last_success = Some(now_ms());
                state.offline = false;
                state.problem = None;
                state.skipped = *problems;
                record(
                    state,
                    RunRecord {
                        at: now_ms(),
                        kind: "backup".into(),
                        ok: true,
                        files: stats.files,
                        bytes: stats.stored_bytes,
                        took_ms: took,
                        problem: None,
                        from: None,
                        original: None,
                    },
                );
            }
            Err(code) => {
                state.offline = code == cloud::UNREACHABLE;
                state.problem = Some(code.clone());
                record(
                    state,
                    RunRecord {
                        at: now_ms(),
                        kind: "backup".into(),
                        ok: false,
                        files: 0,
                        bytes: 0,
                        took_ms: took,
                        problem: Some(code.clone()),
                        from: None,
                        original: None,
                    },
                );
            }
        }
    });
    let _ = fs::remove_file(stop_path());
    outcome.map(|_| true)
}

fn backup_once(
    settings: &Settings,
    options: &RunOptions,
    started: i64,
) -> Result<(engine::Stats, u64), String> {
    let link = link()?.ok_or("computer_backup_not_connected")?;
    let key = recovery_key()?.ok_or("computer_backup_key_missing")?;
    let cloud = Arc::new(Cloud::new(link.clone()));
    let lease = load_state()
        .lease
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    cloud.take_lease(&lease, "backup").map_err(|r| r.code())?;
    update_state(|state| state.lease = Some(lease.clone()));
    let run_id = uuid::Uuid::now_v7().to_string();
    let report = |status: &str,
                  stats: Option<&engine::Stats>,
                  manifest: Option<&str>,
                  error: Option<&str>| {
        let _ = cloud.post("/v1/backup/runs", json!({
            "runId": run_id, "status": status,
            "startedAt": time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(started) * 1_000_000).ok()
                .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok()),
            "finishedAt": (status != "running").then(iso_now),
            "bytesUploaded": stats.map_or(0, |s| s.stored_bytes), "objectsUploaded": stats.map_or(0, |s| s.files),
            "objectsSkipped": 0, "manifestKey": manifest, "errorCode": error,
        }));
    };
    report("running", None, None, None);

    // The lease is renewed every minute, and the run stops when asked, or at the schedule's stop-by time.
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let keeper = {
        let (cloud, lease, stop, done) = (cloud.clone(), lease.clone(), stop.clone(), done.clone());
        let (schedule, offset, now) = (settings.schedule.clone(), options.offset_ms, options.now);
        std::thread::spawn(move || {
            let mut renewed = Instant::now();
            while !done.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(500));
                if stop_path().exists()
                    || (!now && past_stop_by(&schedule, started, now_ms(), offset))
                {
                    stop.store(true, Ordering::SeqCst);
                }
                if renewed.elapsed() >= Duration::from_secs(60) {
                    renewed = Instant::now();
                    if let Err(refusal) = cloud.renew_lease(&lease) {
                        if refusal.code == "lease-lost" {
                            stop.store(true, Ordering::SeqCst);
                        }
                    }
                }
                update_state(|state| {
                    if let Some(running) = state.running.as_mut() {
                        running.heartbeat = now_ms();
                    }
                });
            }
        })
    };
    let result = backup_with_lease(settings, &cloud, &lease, &key, &stop);
    done.store(true, Ordering::SeqCst);
    let _ = keeper.join();
    match &result {
        Ok((stats, manifest, _)) => report("succeeded", Some(stats), Some(manifest), None),
        Err(code) => report(
            if code == "computer_backup_stopped" {
                "cancelled"
            } else {
                "failed"
            },
            None,
            None,
            Some(
                &code
                    .replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "_")
                    .chars()
                    .take(64)
                    .collect::<String>(),
            ),
        ),
    }
    cloud.release_lease(&lease);
    update_state(|state| state.lease = None);
    let _ = cloud.call(
        reqwest::Method::PUT,
        "/v1/backup/settings",
        Some(json!({"keyMode": "server", "scheduleEnabled": settings.enabled})),
    );
    let (stats, _, problems) = result?;
    // At most one clean-up a day, after a backup that finished.
    let prune_due = load_state()
        .last_prune
        .is_none_or(|last| now_ms() - last > 86_400_000);
    if let Some(policy) = retention(&settings.schedule.keep).filter(|_| prune_due) {
        if prune(&cloud, &key, policy).is_ok() {
            update_state(|state| state.last_prune = Some(now_ms()));
        }
    }
    refresh_cloud(&cloud);
    Ok((stats, problems))
}

fn backup_with_lease(
    settings: &Settings,
    cloud: &Arc<Cloud>,
    lease: &str,
    key: &[u8; 32],
    stop: &AtomicBool,
) -> Result<(engine::Stats, String, u64), String> {
    let limit = settings
        .schedule
        .limit_mbps
        .map(|mbps| u64::from(mbps) * 125_000);
    let (store, read_only) =
        store(cloud.clone(), "upload", Some(lease.to_string()), limit).map_err(|r| r.code())?;
    if read_only {
        return Err("computer_backup_read_only".into());
    }
    let mut repository = open_repository(store, key, true)?;

    // The signed history Cloud keeps decides the number of this backup.
    let vault = cloud.link.instance_id.clone();
    let history = cloud
        .get(&format!("/v2/backup/snapshots?vaultId={vault}&limit=1"))
        .map_err(|r| r.code())?;
    let (sequence, previous) = match history["head"].as_object() {
        Some(head) => (
            head["sequence"].as_u64().unwrap_or(0) + 1,
            head["digest"].as_str().map(str::to_string),
        ),
        None => (1, None),
    };
    let snapshot_id = uuid::Uuid::now_v7();

    let chosen: Vec<&Folder> = settings
        .folders
        .iter()
        .filter(|folder| folder.on && Path::new(&folder.path).is_dir())
        .collect();
    if chosen.is_empty() {
        return Err("computer_backup_no_folders".into());
    }
    let snapshot = crate::computer_backup_platform::OpenFiles::take(
        chosen
            .iter()
            .map(|folder| PathBuf::from(&folder.path))
            .collect(),
    );
    let disks: Vec<Box<dyn Source>> = chosen
        .iter()
        .map(|folder| {
            Box::new(engine::fs_source(
                snapshot.read_path(Path::new(&folder.path)),
            )) as Box<dyn Source>
        })
        .collect();
    let filtered: Vec<Box<dyn Source + '_>> = disks
        .iter()
        .map(|disk| Box::new(engine::filter_source(disk.as_ref(), skipped)) as Box<dyn Source>)
        .collect();
    let mounts = chosen
        .iter()
        .zip(&filtered)
        .map(|(folder, source)| (vec![folder.name.clone()], source.as_ref()))
        .collect();
    let source = engine::mount_source(mounts).map_err(|e| engine_code(&e))?;
    let (total_files, total_bytes) = engine::measure_source(&source, &[]);
    update_state(|state| {
        if let Some(running) = state.running.as_mut() {
            running.total_files = total_files;
            running.total_bytes = total_bytes;
        }
    });
    let last_write = Mutex::new(Instant::now() - Duration::from_secs(5));
    let progress = |progress: engine::Progress| {
        if let Ok(mut last) = last_write.lock() {
            if last.elapsed() >= Duration::from_millis(700) {
                *last = Instant::now();
                update_state(|state| {
                    if let Some(running) = state.running.as_mut() {
                        running.files = progress.files;
                        running.bytes = progress.bytes;
                        running.stored_bytes = progress.stored_bytes;
                    }
                });
            }
        }
    };
    let result = engine::backup(
        &mut repository,
        &source,
        &BackupOptions {
            sequence: Some(sequence),
            snapshot_id: Some(snapshot_id.simple().to_string()),
            stop: Some(stop),
            on_progress: Some(&progress),
            ..Default::default()
        },
    )
    .map_err(|e| engine_code(&e))?;
    drop(snapshot);

    // The receipt Cloud keeps: signed by this computer's key, chained to the one before.
    let jwk = cloud.jwk();
    let descriptor = SnapshotDescriptor {
        version: 2,
        instance_id: cloud.link.instance_id.clone(),
        vault_id: vault,
        snapshot_id: snapshot_id.to_string(),
        sequence,
        previous_digest: previous,
        created_at: result.snapshot.time.clone(),
        manifest: Manifest {
            format: "frameleaf-repository".into(),
            format_version: 1,
            key_version: 1,
            object_key: format!("{}{}", prefix(&cloud.link), result.key),
            version_id: result
                .version_id
                .clone()
                .ok_or("computer_backup_storage_unversioned")?,
            ciphertext_sha256: result.ciphertext_sha256.clone(),
        },
        signer_kid: jwk.kid,
    };
    let signature =
        sign_snapshot_descriptor(&descriptor, cloud.signing_key()).map_err(|e| engine_code(&e))?;
    cloud
        .post(
            "/v2/backup/snapshots",
            json!({"descriptor": descriptor, "signature": signature.signature}),
        )
        .map_err(|r| r.code())?;

    // What each folder holds, for the page.
    let top = engine::list_folder(&repository, &result.snapshot, &[]).unwrap_or_default();
    let mut places = settings.places.clone();
    update_state(|state| {
        state.sizes = top
            .iter()
            .map(|entry| {
                (
                    entry.name.clone(),
                    Sizes {
                        files: entry.files.unwrap_or(0),
                        bytes: entry.size,
                    },
                )
            })
            .collect();
    });
    for folder in &chosen {
        if !places
            .iter()
            .any(|(name, path)| name == &folder.name && path == &folder.path)
        {
            places.push((folder.name.clone(), folder.path.clone()));
        }
    }
    if places != settings.places {
        let mut current = load_settings();
        current.places = places;
        let _ = save_settings(&current);
    }
    let manifest = descriptor.manifest.object_key;
    Ok((
        result.snapshot.stats,
        manifest,
        result.problems.len() as u64,
    ))
}

/// A prune holds two credentials under one lease (FC-284): `prune` deletes and reads, `upload` writes
/// the packs and index that replace what it removes.
struct PruneStore {
    upload: S3Store,
    prune: S3Store,
}

impl Store for PruneStore {
    fn put(&self, key: &str, body: &[u8]) -> engine::Result<Option<String>> {
        self.upload.put(key, body)
    }
    fn get(&self, key: &str, range: Option<engine::ByteRange>) -> engine::Result<Vec<u8>> {
        self.prune.get(key, range)
    }
    fn list(&self, prefix: &str) -> engine::Result<Vec<engine::StoredObject>> {
        self.prune.list(prefix)
    }
    fn delete(&self, key: &str) -> engine::Result<()> {
        self.prune.delete(key)
    }
}

fn prune(cloud: &Arc<Cloud>, key: &[u8; 32], policy: RetentionPolicy) -> Result<(), String> {
    let lease = uuid::Uuid::new_v4().to_string();
    cloud.take_lease(&lease, "prune").map_err(|r| r.code())?;
    let result = (|| {
        let (upload, _) =
            store(cloud.clone(), "upload", Some(lease.clone()), None).map_err(|r| r.code())?;
        let (prune, _) =
            store(cloud.clone(), "prune", Some(lease.clone()), None).map_err(|r| r.code())?;
        let store: Arc<dyn Store> = Arc::new(PruneStore { upload, prune });
        let mut repository = Repository::open(store, key).map_err(|e| engine_code(&e))?;
        engine::prune(
            &mut repository,
            &engine::PruneOptions {
                policy,
                ..Default::default()
            },
        )
        .map_err(|e| engine_code(&e))
    })();
    cloud.release_lease(&lease);
    result.map(drop)
}

/// Usage, the plan and any purge, as Cloud sees them now.
pub(crate) fn refresh_cloud(cloud: &Cloud) {
    let usage = cloud.get("/v1/backup/usage").ok();
    let purge = cloud.get("/v1/backup/purge");
    update_state(|state| {
        if let Some(usage) = &usage {
            let n = |field: &str| usage[field].as_u64().unwrap_or(0);
            state.usage = Some((
                n("bytesCurrent"),
                n("accountBytesCurrent"),
                n("allowanceBytes"),
            ));
        }
        match &purge {
            Ok(purge) if purge["status"] == "held" => {
                state.purge = purge["holdUntil"].as_str().map(str::to_string)
            }
            Ok(_) => state.purge = None,
            Err(refusal) if refusal.status == 404 => state.purge = None,
            Err(_) => {}
        }
    });
}

// ---------------------------------------------------------------- restore

/// An opened repository for browsing, with restore credentials only.
pub(crate) struct Browser {
    pub repository: Repository,
    pub snapshots: Vec<(String, engine::Snapshot)>,
}

pub(crate) fn open_browser() -> Result<Browser, String> {
    let link = link()?.ok_or("computer_backup_not_connected")?;
    let key = recovery_key()?.ok_or("computer_backup_key_missing")?;
    let cloud = Arc::new(Cloud::new(link));
    let (store, _) = store(cloud, "restore", None, None).map_err(|r| r.code())?;
    let mut repository = open_repository(store, &key, false)?;
    repository.load_index().map_err(|e| engine_code(&e))?;
    let mut snapshots = Vec::new();
    for (key, _) in repository
        .list_snapshots()
        .map_err(|e| engine_code(&e))?
        .into_iter()
        .rev()
    {
        snapshots.push((
            key.clone(),
            repository
                .read_snapshot(&key)
                .map_err(|e| engine_code(&e))?,
        ));
    }
    Ok(Browser {
        repository,
        snapshots,
    })
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Item {
    pub name: String,
    pub folder: bool,
    pub size: u64,
    pub changed: i64,
    pub files: Option<u64>,
}

impl Browser {
    fn snapshot(&self, key: &str) -> Result<&engine::Snapshot, String> {
        self.snapshots
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, s)| s)
            .ok_or_else(|| "computer_backup_no_such_backup".into())
    }

    pub(crate) fn list(&self, key: &str, path: &[String]) -> Result<Vec<Item>, String> {
        let mut items: Vec<Item> = engine::list_folder(&self.repository, self.snapshot(key)?, path)
            .map_err(|e| engine_code(&e))?
            .into_iter()
            .filter(|entry| entry.kind != engine::EntryType::Symlink)
            .map(|entry| Item {
                folder: entry.kind == engine::EntryType::Dir,
                size: entry.size,
                changed: entry.mtime,
                files: entry.files,
                name: entry.name,
            })
            .collect();
        items.sort_by(|a, b| {
            b.folder
                .cmp(&a.folder)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(items)
    }

    /// Puts each item back where it was (`target` None) or into `target`. Nothing is deleted: what is in
    /// the way is renamed with the restore's date first.
    pub(crate) fn restore(
        &self,
        key: &str,
        items: &[Vec<String>],
        target: Option<&Path>,
        places: &[(String, String)],
        folders: &[Folder],
    ) -> Result<engine::RestoreResult, String> {
        let snapshot = self.snapshot(key)?;
        let mut total = engine::RestoreResult::default();
        let origin = |top: &String| -> Result<PathBuf, String> {
            folders
                .iter()
                .find(|f| &f.name == top)
                .map(|f| PathBuf::from(&f.path))
                .or_else(|| {
                    places
                        .iter()
                        .rev()
                        .find(|(name, _)| name == top)
                        .map(|(_, p)| PathBuf::from(p))
                })
                .ok_or_else(|| "computer_backup_place_unknown".into())
        };
        let aside = |existing: &Path| {
            let date = time::OffsetDateTime::now_utc().date();
            let stem = existing
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let extension = existing
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy()))
                .unwrap_or_default();
            (1..)
                .map(|n| {
                    let suffix = if n == 1 {
                        String::new()
                    } else {
                        format!(" {n}")
                    };
                    existing.with_file_name(format!(
                        "{stem} (before restore {date}{suffix}){extension}"
                    ))
                })
                .find(|candidate| !candidate.exists())
                .expect("a free name")
        };
        for item in items {
            let Some(top) = item.first() else { continue };
            // `restore` puts an item inside the folder it is given, under its own name.
            let result = match target {
                Some(target) => {
                    engine::restore(&self.repository, snapshot, item, target, Some(&aside))
                        .map_err(|e| engine_code(&e))?
                }
                // A whole top folder goes back into its own place, whatever that folder is called on disk.
                None if item.len() == 1 => restore_folder_contents(
                    &self.repository,
                    snapshot,
                    item,
                    &origin(top)?,
                    &aside,
                )?,
                None => {
                    let parent = item[1..item.len() - 1]
                        .iter()
                        .fold(origin(top)?, |at, name| at.join(name));
                    engine::restore(&self.repository, snapshot, item, &parent, Some(&aside))
                        .map_err(|e| engine_code(&e))?
                }
            };
            total.files += result.files;
            total.bytes += result.bytes;
            total.moved_aside.extend(result.moved_aside);
        }
        Ok(total)
    }
}

/// A top folder back in its own place: each thing it held is restored into that place.
fn restore_folder_contents(
    repository: &Repository,
    snapshot: &engine::Snapshot,
    path: &[String],
    place: &Path,
    aside: &dyn Fn(&Path) -> PathBuf,
) -> Result<engine::RestoreResult, String> {
    fs::create_dir_all(place).map_err(|_| "computer_backup_restore_failed")?;
    let mut total = engine::RestoreResult::default();
    for entry in engine::list_folder(repository, snapshot, path).map_err(|e| engine_code(&e))? {
        let mut child = path.to_vec();
        child.push(entry.name);
        let result = engine::restore(repository, snapshot, &child, place, Some(aside))
            .map_err(|e| engine_code(&e))?;
        total.files += result.files;
        total.bytes += result.bytes;
        total.moved_aside.extend(result.moved_aside);
    }
    Ok(total)
}

// ---------------------------------------------------------------- the agent

/// `frameleaf-desktop --computer-backup [--now]`: started by launchd or the Task Scheduler every 15 minutes,
/// and by Back Up Now. Runs one backup if one is due, then exits.
pub fn agent_main(now: bool) -> i32 {
    // Read before any thread starts: the local offset can't be read safely afterwards on Unix.
    let offset_ms = time::UtcOffset::current_local_offset()
        .map(|o| i64::from(o.whole_seconds()) * 1000)
        .unwrap_or(0);
    let _ = fs::create_dir_all(data_dir());
    let Ok(lock) = crate::computer_backup_platform::RunLock::take(&data_dir().join("run.lock"))
    else {
        return 0;
    };
    let result = run(&RunOptions { now, offset_ms });
    drop(lock);
    match result {
        Ok(_) => 0,
        Err(code) => {
            eprintln!("computer backup: {code}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(every: &str, at: u32, stop_by: Option<u32>) -> Schedule {
        Schedule {
            every: every.into(),
            at,
            stop_by,
            ..Default::default()
        }
    }
    const DAY: i64 = 86_400_000;
    const MIN: i64 = 60_000;

    #[test]
    fn a_daily_backup_is_due_once_its_time_has_come_each_day() {
        let daily = schedule("day", 120, None);
        let midnight = 20_000 * DAY;
        assert!(
            due(&daily, None, midnight, 0),
            "the first backup is always due"
        );
        assert!(
            !due(&daily, Some(midnight + 130 * MIN), midnight + 300 * MIN, 0),
            "already ran today after 2:00"
        );
        assert!(
            due(&daily, Some(midnight - 600 * MIN), midnight + 121 * MIN, 0),
            "ran yesterday; 2:00 has come"
        );
        assert!(
            !due(&daily, Some(midnight - 600 * MIN), midnight + 119 * MIN, 0),
            "ran yesterday at 14:00; 2:00 not yet"
        );
        assert!(
            due(&daily, Some(midnight - 2 * DAY), midnight + 30 * MIN, 0),
            "missed yesterday's slot"
        );
        // UTC-6: 2:00 local is 8:00 UTC.
        assert!(!due(
            &daily,
            Some(midnight + 9 * 60 * MIN),
            midnight + 10 * 60 * MIN,
            -6 * 60 * MIN
        ));
        assert!(due(
            &daily,
            Some(midnight + 7 * 60 * MIN),
            midnight + 9 * 60 * MIN,
            -6 * 60 * MIN
        ));
    }

    #[test]
    fn an_hourly_backup_waits_an_hour_and_a_run_stops_by_its_time() {
        let hourly = schedule("hour", 0, Some(420));
        assert!(!due(&hourly, Some(0), 59 * MIN, 0));
        assert!(due(&hourly, Some(0), 60 * MIN, 0));
        let night = 20_000 * DAY + 120 * MIN;
        assert!(!past_stop_by(&hourly, night, night + 299 * MIN, 0));
        assert!(past_stop_by(&hourly, night, night + 300 * MIN, 0));
        // Started after the stop-by time: it may run until the next day's.
        assert!(!past_stop_by(
            &hourly,
            night + 400 * MIN,
            night + 600 * MIN,
            0
        ));
        assert!(!past_stop_by(
            &schedule("day", 0, None),
            night,
            night + 10 * DAY,
            0
        ));
    }

    #[test]
    fn added_folders_get_unique_names_and_the_photo_library_starts_left_out() {
        let mut settings = Settings {
            folders: default_folders(),
            ..Default::default()
        };
        assert!(settings.folders.iter().filter(|f| !f.photos).all(|f| f.on));
        assert!(settings.folders.iter().filter(|f| f.photos).all(|f| !f.on));
        add_folder(&mut settings, Path::new("/Volumes/Work/Documents")).unwrap();
        add_folder(&mut settings, Path::new("/Volumes/Work/Documents")).unwrap();
        let added: Vec<_> = settings
            .folders
            .iter()
            .filter(|f| f.path == "/Volumes/Work/Documents")
            .collect();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].name, "Documents 2");
    }

    /// The whole journey against tools/computer_backup_stand_in.mjs (Cloud and versioned S3, both local):
    /// link in the browser, back up twice, browse, restore back where they were and into another folder,
    /// keep a locked copy of the key, delete with the 30-day hold, keep the backups, disconnect.
    /// `node tools/test_computer_backup_e2e.mjs` starts the stand-in and runs this.
    #[test]
    #[ignore = "needs the local Cloud stand-in; run by tools/test_computer_backup_e2e.mjs"]
    fn end_to_end_against_local_cloud_and_s3_stand_ins() {
        use crate::computer_backup_cloud::Poll;
        assert!(
            std::env::var("FRAMELEAF_CLOUD_URL")
                .is_ok_and(|url| url.starts_with("http://127.0.0.1:")),
            "only a local stand-in"
        );
        let _store = crate::credentials::use_test_store();
        let root = std::env::temp_dir().join(format!("fd77-e2e-{}", uuid::Uuid::new_v4()));
        let home = root.join("home");
        std::env::set_var("HOME", &home);
        std::env::set_var("USERPROFILE", &home);
        std::env::set_var("FRAMELEAF_COMPUTER_BACKUP_DIR", root.join("data"));
        let write = |path: &str, body: &[u8]| {
            let path = home.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        };
        let big: Vec<u8> = (0..3_000_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        write("Documents/Tax 2025.xlsx", b"version one");
        write("Documents/Receipts/March.pdf", b"receipt");
        write("Documents/.DS_Store", b"clutter");
        write("Desktop/note.txt", b"a note");
        write("Downloads/big.bin", &big);
        write(
            if cfg!(target_os = "macos") {
                "Pictures/Photos Library.photoslibrary/database"
            } else {
                "Pictures/photo.jpg"
            },
            b"photos",
        );

        // Connect Cloud: the device flow, approved in the browser, then the link.
        let cloud_url = cloud::cloud_url().unwrap();
        let (issuer, api) = cloud::discover(&cloud_url);
        let key = cloud::new_key();
        let start =
            cloud::device_start(&issuer, "Pat’s MacBook Pro", &key, "desktop/macos").unwrap();
        assert!(matches!(
            cloud::device_poll(&issuer, &start.device_code).unwrap(),
            Poll::Pending
        ));
        reqwest::blocking::get(&start.verification_uri_complete)
            .unwrap()
            .error_for_status()
            .unwrap();
        let Poll::Approved(token) = cloud::device_poll(&issuer, &start.device_code).unwrap() else {
            panic!("approved")
        };
        let instance_id = uuid::Uuid::now_v7().to_string();
        let link = cloud::register(
            &issuer,
            &api,
            &cloud_url,
            &token,
            &key,
            &instance_id,
            "Pat’s MacBook Pro",
            "desktop/macos",
        )
        .unwrap();
        assert_eq!(link.instance_id, instance_id);
        crate::credentials::save(LINK_CREDENTIAL, &link).unwrap();
        let cloud = Cloud::new(link.clone());
        if let Err(refusal) = cloud.grant("restore", None) {
            panic!("the plan covers this computer: {refusal:?}");
        }

        // Choose folders: Documents, Desktop and Downloads on, the photo library left out. Save the key. Schedule.
        let mut settings = load_settings();
        let names: Vec<(&str, bool)> = settings
            .folders
            .iter()
            .map(|f| (f.name.as_str(), f.on))
            .collect();
        assert_eq!(
            &names[..3],
            &[("Documents", true), ("Desktop", true), ("Downloads", true)]
        );
        assert!(settings.folders[3].photos && !settings.folders[3].on);
        settings.enabled = true;
        save_settings(&settings).unwrap();
        let code = ensure_recovery_key().unwrap();
        assert!(code.starts_with("FLRK-"));
        assert_eq!(ensure_recovery_key().unwrap(), code, "made once");

        // First backup.
        let now = RunOptions {
            now: true,
            offset_ms: 0,
        };
        assert!(run(&now).unwrap());
        let state = load_state();
        assert!(state.runs[0].ok, "{:?}", state.runs[0]);
        assert_eq!(
            state.runs[0].files, 4,
            "clutter and the photo library are left out"
        );
        assert_eq!(state.sizes["Documents"].files, 2);
        assert!(
            state
                .usage
                .is_some_and(|(mine, _, plan)| mine > 0 && plan == 1_000_000_000_000),
            "{:?}",
            state.usage
        );
        assert!(state.lease.is_none() && state.running.is_none());

        // Changes, and a second backup.
        write("Documents/Tax 2025.xlsx", b"version two");
        fs::remove_file(home.join("Desktop/note.txt")).unwrap();
        assert!(run(&now).unwrap());
        let history = cloud
            .get(&format!("/v2/backup/snapshots?vaultId={instance_id}"))
            .unwrap();
        assert_eq!(
            history["head"]["sequence"], 2,
            "two signed, chained receipts"
        );

        // Restore: date → browse → tick.
        let browser = open_browser().unwrap();
        assert_eq!(browser.snapshots.len(), 2);
        let (newest, oldest) = (
            browser.snapshots[0].0.clone(),
            browser.snapshots[1].0.clone(),
        );
        let names = |items: Vec<Item>| {
            items
                .into_iter()
                .map(|i| (i.name, i.folder))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(browser.list(&newest, &[]).unwrap()),
            [
                ("Desktop".into(), true),
                ("Documents".into(), true),
                ("Downloads".into(), true)
            ]
        );
        assert_eq!(
            names(browser.list(&oldest, &["Documents".into()]).unwrap()),
            [("Receipts".into(), true), ("Tax 2025.xlsx".into(), false)]
        );
        assert!(browser
            .list(&newest, &["Desktop".into()])
            .unwrap()
            .is_empty());

        // Back where they were: what is there now is kept and renamed.
        let settings = load_settings();
        let tick = |path: &[&str]| path.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let result = browser
            .restore(
                &oldest,
                &[
                    tick(&["Documents", "Tax 2025.xlsx"]),
                    tick(&["Desktop", "note.txt"]),
                ],
                None,
                &settings.places,
                &settings.folders,
            )
            .unwrap();
        assert_eq!(result.files, 2);
        assert_eq!(
            fs::read(home.join("Documents/Tax 2025.xlsx")).unwrap(),
            b"version one"
        );
        assert_eq!(fs::read(home.join("Desktop/note.txt")).unwrap(), b"a note");
        assert_eq!(result.moved_aside.len(), 1);
        let (_, aside) = &result.moved_aside[0];
        assert!(
            aside
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("Tax 2025 (before restore "),
            "{aside:?}"
        );
        assert_eq!(fs::read(aside).unwrap(), b"version two");

        // Into another folder; and a whole folder back in its own place.
        let other = root.join("Restored");
        browser
            .restore(
                &newest,
                &[tick(&["Downloads"])],
                Some(&other),
                &settings.places,
                &settings.folders,
            )
            .unwrap();
        assert_eq!(fs::read(other.join("Downloads/big.bin")).unwrap(), big);
        fs::remove_dir_all(home.join("Downloads")).unwrap();
        browser
            .restore(
                &newest,
                &[tick(&["Downloads"])],
                None,
                &settings.places,
                &settings.folders,
            )
            .unwrap();
        assert_eq!(fs::read(home.join("Downloads/big.bin")).unwrap(), big);

        // A locked copy of the key in Cloud opens only with its passphrase.
        let recovery = recovery_key().unwrap().unwrap();
        let blob =
            engine::escrow::wrap_bucket_key(&recovery, "correct horse battery", None).unwrap();
        cloud
            .call(
                reqwest::Method::PUT,
                "/v1/backup/escrow",
                Some(serde_json::to_value(&blob).unwrap()),
            )
            .unwrap();
        let back: engine::escrow::KeyEscrowBlob =
            serde_json::from_value(cloud.get("/v1/backup/escrow").unwrap()).unwrap();
        assert_eq!(
            engine::escrow::unwrap_bucket_key(&back, "correct horse battery").unwrap(),
            recovery
        );

        // Delete with the 30-day hold: backups can't write, restores still work; Keep My Backups undoes it.
        cloud.post("/v1/backup/purge", json!({})).unwrap();
        refresh_cloud(&cloud);
        assert!(load_state().purge.is_some());
        write("Documents/later.txt", b"later");
        let refused = run(&now).unwrap_err();
        assert!(
            refused == "backup-read-only" || refused == "computer_backup_read_only",
            "{refused}"
        );
        assert_eq!(
            open_browser().unwrap().snapshots.len(),
            2,
            "restores keep working during the hold"
        );
        cloud
            .call(reqwest::Method::DELETE, "/v1/backup/purge", None)
            .unwrap();
        refresh_cloud(&cloud);
        assert!(load_state().purge.is_none());
        assert!(run(&now).unwrap());
        assert_eq!(open_browser().unwrap().snapshots.len(), 3);

        // Disconnect: Cloud no longer accepts this computer.
        cloud
            .call(reqwest::Method::DELETE, "/v1/instance", None)
            .unwrap();
        assert!(Cloud::new(link).get("/v1/backup/usage").is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
