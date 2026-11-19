//! FD-77: the Computer backup page's commands. Each answers quickly: Cloud and the engine run on a
//! blocking thread, and backups themselves run in the agent process (see `computer_backup`).

use crate::computer_backup::{self as backup, Browser, Folder, Item, RunRecord, Schedule, Sizes};
use crate::computer_backup_cloud::{self as cloud, Cloud, DeviceStart, Poll};
use crate::computer_backup_platform as platform;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;
use tauri::{State, WebviewWindow};

#[derive(Default)]
pub struct ComputerBackup {
    pending: Mutex<Option<Pending>>,
    browser: Mutex<Option<Browser>>,
    measured: Mutex<HashMap<String, Option<Sizes>>>,
}

struct Pending {
    start: DeviceStart,
    key: ed25519_dalek::SigningKey,
    instance_id: String,
    cloud: url::Url,
    issuer: url::Url,
    api: url::Url,
    asked: std::time::Instant,
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|_| "computer_backup_failed".to_string())?
}

fn lock<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, String> {
    mutex.lock().map_err(|_| "computer_backup_failed".into())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderView {
    #[serde(flatten)]
    folder: Folder,
    size: Option<u64>,
    files: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    os: &'static str,
    computer: String,
    connected: bool,
    connecting: Option<String>,
    plan: Option<bool>,
    enabled: bool,
    folders: Vec<FolderView>,
    schedule: Schedule,
    running: Option<backup::Running>,
    runs: Vec<RunRecord>,
    last_success: Option<i64>,
    problem: Option<String>,
    offline: bool,
    skipped: u64,
    usage: Option<(u64, u64, u64)>,
    full_disk_access: bool,
    key_saved_at: Option<String>,
    locked_copy: bool,
    purge: Option<String>,
}

/// Sizes come from the newest backup; before the first one, each folder is measured once in the background.
fn sizes(
    state: &ComputerBackup,
    folder: &Folder,
    from_backup: &std::collections::BTreeMap<String, Sizes>,
) -> (Option<u64>, Option<u64>) {
    if let Some(sizes) = from_backup.get(&folder.name) {
        return (Some(sizes.bytes), Some(sizes.files));
    }
    let Ok(mut measured) = state.measured.lock() else {
        return (None, None);
    };
    match measured.get(&folder.path) {
        Some(Some(sizes)) => (Some(sizes.bytes), Some(sizes.files)),
        Some(None) => (None, None),
        None => {
            measured.insert(folder.path.clone(), None);
            let path = folder.path.clone();
            std::thread::spawn(move || {
                let source = frameleaf_backup_core::fs_source(path.clone());
                let (files, bytes) = frameleaf_backup_core::measure_source(&source, &[]);
                MEASURED
                    .lock()
                    .map(|mut done| done.push((path, Sizes { files, bytes })))
                    .ok();
            });
            (None, None)
        }
    }
}

static MEASURED: Mutex<Vec<(String, Sizes)>> = Mutex::new(Vec::new());

fn view(state: &ComputerBackup) -> Result<View, String> {
    if let (Ok(mut done), Ok(mut measured)) = (MEASURED.lock(), state.measured.lock()) {
        for (path, sizes) in done.drain(..) {
            measured.insert(path, Some(sizes));
        }
    }
    let settings = backup::load_settings();
    let current = backup::load_state();
    let connected = backup::link()?.is_some();
    let connecting = lock(&state.pending)?
        .as_ref()
        .map(|pending| pending.start.user_code.clone());
    let folders = settings
        .folders
        .iter()
        .map(|folder| {
            let (size, files) = sizes(state, folder, &current.sizes);
            FolderView {
                folder: folder.clone(),
                size,
                files,
            }
        })
        .collect();
    Ok(View {
        os: platform::os(),
        computer: platform::computer_name(),
        connected,
        connecting,
        plan: settings.plan,
        enabled: settings.enabled,
        folders,
        schedule: settings.schedule,
        running: current
            .running
            .clone()
            .filter(|_| backup::is_running(&current)),
        runs: current.runs,
        last_success: current.last_success,
        problem: current.problem,
        offline: current.offline,
        skipped: current.skipped,
        usage: current.usage,
        full_disk_access: platform::full_disk_access(),
        key_saved_at: settings.key_saved_at,
        locked_copy: settings.locked_copy,
        purge: current.purge,
    })
}

#[tauri::command]
pub async fn computer_backup_status(
    window: WebviewWindow,
    state: State<'_, ComputerBackup>,
) -> Result<View, String> {
    crate::require_local(&window)?;
    view(&state)
}

/// Usage, plan storage and any deletion hold, asked of Cloud when the page opens.
#[tauri::command]
pub async fn computer_backup_refresh(window: WebviewWindow) -> Result<(), String> {
    crate::require_local(&window)?;
    blocking(|| {
        if let Some(link) = backup::link()? {
            backup::refresh_cloud(&Cloud::new(link));
        }
        Ok(())
    })
    .await
}

fn open(app: &tauri::AppHandle, url: &str) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|_| "computer_backup_browser_unavailable".into())
}

/// Set-up step 1: asks Cloud for a device code and opens the approval page in the browser.
#[tauri::command]
pub async fn computer_backup_connect(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, ComputerBackup>,
) -> Result<String, String> {
    crate::require_local(&window)?;
    let pending = blocking(|| {
        let cloud = cloud::cloud_url()?;
        let (issuer, api) = cloud::discover(&cloud);
        let key = cloud::new_key();
        let start = cloud::device_start(
            &issuer,
            &platform::computer_name(),
            &key,
            &platform::platform(),
        )
        .map_err(|r| r.code())?;
        Ok(Pending {
            start,
            key,
            instance_id: uuid::Uuid::now_v7().to_string(),
            cloud,
            issuer,
            api,
            asked: std::time::Instant::now(),
        })
    })
    .await?;
    let code = pending.start.user_code.clone();
    open(&app, &pending.start.verification_uri_complete)?;
    *lock(&state.pending)? = Some(pending);
    Ok(code)
}

#[tauri::command]
pub async fn computer_backup_connect_again(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, ComputerBackup>,
) -> Result<(), String> {
    crate::require_local(&window)?;
    let url = lock(&state.pending)?
        .as_ref()
        .map(|p| p.start.verification_uri_complete.clone())
        .ok_or("computer_backup_not_connecting")?;
    open(&app, &url)
}

#[tauri::command]
pub async fn computer_backup_cancel_connect(
    window: WebviewWindow,
    state: State<'_, ComputerBackup>,
) -> Result<(), String> {
    crate::require_local(&window)?;
    *lock(&state.pending)? = None;
    Ok(())
}

/// Asks once whether the person approved in the browser (the page polls at Cloud's interval). Once they
/// have, links the computer and learns whether the account has a Cloud plan.
#[tauri::command]
pub async fn computer_backup_connect_poll(
    window: WebviewWindow,
    state: State<'_, ComputerBackup>,
) -> Result<String, String> {
    crate::require_local(&window)?;
    let (issuer, api, cloud_url, code, key, instance_id, expired) = {
        let pending = lock(&state.pending)?;
        let p = pending.as_ref().ok_or("computer_backup_not_connecting")?;
        (
            p.issuer.clone(),
            p.api.clone(),
            p.cloud.clone(),
            p.start.device_code.clone(),
            p.key.clone(),
            p.instance_id.clone(),
            p.asked.elapsed().as_secs() > p.start.expires_in,
        )
    };
    if expired {
        *lock(&state.pending)? = None;
        return Err("expired_token".into());
    }
    let outcome = blocking(move || {
        match cloud::device_poll(&issuer, &code).map_err(|r| r.code())? {
            Poll::Pending | Poll::SlowDown => Ok(None),
            Poll::Approved(token) => {
                let link = cloud::register(
                    &issuer,
                    &api,
                    &cloud_url,
                    &token,
                    &key,
                    &instance_id,
                    &platform::computer_name(),
                    &platform::platform(),
                )?;
                crate::credentials::save(backup::LINK_CREDENTIAL, &link)?;
                // A restore grant provisions the bucket, and says whether the plan covers backups.
                let plan = match Cloud::new(link).grant("restore", None) {
                    Ok(_) => Some(true),
                    Err(refusal) if refusal.code == "entitlement-missing" => Some(false),
                    Err(_) => None,
                };
                let mut settings = backup::load_settings();
                settings.plan = plan;
                backup::save_settings(&settings)?;
                Ok(Some(if plan == Some(false) {
                    "noplan"
                } else {
                    "linked"
                }))
            }
        }
    })
    .await;
    match outcome {
        Ok(None) => Ok("pending".into()),
        Ok(Some(done)) => {
            *lock(&state.pending)? = None;
            Ok(done.into())
        }
        Err(code) => {
            if code != cloud::UNREACHABLE {
                *lock(&state.pending)? = None;
            }
            Err(code)
        }
    }
}

#[derive(Deserialize)]
pub struct Choice {
    id: String,
    on: bool,
}

#[tauri::command]
pub async fn computer_backup_set_folders(
    window: WebviewWindow,
    folders: Vec<Choice>,
) -> Result<(), String> {
    crate::require_local(&window)?;
    let mut settings = backup::load_settings();
    for folder in &mut settings.folders {
        if let Some(choice) = folders.iter().find(|choice| choice.id == folder.id) {
            folder.on = choice.on;
        }
    }
    backup::save_settings(&settings)
}

/// Another folder, chosen in the system's folder picker.
#[tauri::command]
pub async fn computer_backup_add_folder(
    window: WebviewWindow,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    use tauri_plugin_dialog::DialogExt;
    crate::require_local(&window)?;
    blocking(move || {
        let Some(folder) = app
            .dialog()
            .file()
            .set_title("Choose a folder to back up")
            .blocking_pick_folder()
        else {
            return Ok(false);
        };
        let path = folder
            .into_path()
            .map_err(|_| "computer_backup_folder_invalid")?;
        let mut settings = backup::load_settings();
        backup::add_folder(&mut settings, &path)?;
        backup::save_settings(&settings).map(|_| true)
    })
    .await
}

/// The recovery key, shown openly only during set-up, before the person confirms saving it.
#[tauri::command]
pub async fn computer_backup_setup_key(window: WebviewWindow) -> Result<String, String> {
    crate::require_local(&window)?;
    if backup::load_settings().key_saved_at.is_some() {
        return Err("computer_backup_confirm_required".into());
    }
    blocking(backup::ensure_recovery_key).await
}

#[tauri::command]
pub async fn computer_backup_key_saved(window: WebviewWindow) -> Result<(), String> {
    crate::require_local(&window)?;
    let mut settings = backup::load_settings();
    settings.key_saved_at.get_or_insert_with(|| {
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default()
    });
    backup::save_settings(&settings)
}

fn confirmed_key() -> Result<String, String> {
    if backup::load_settings().key_saved_at.is_some()
        && !platform::confirm_owner("show your Computer backup recovery key")
    {
        return Err("computer_backup_not_confirmed".into());
    }
    backup::ensure_recovery_key()
}

/// After set-up: Touch ID or Windows Hello first.
#[tauri::command]
pub async fn computer_backup_show_key(window: WebviewWindow) -> Result<String, String> {
    crate::require_local(&window)?;
    blocking(confirmed_key).await
}

/// A printable page with the key and how to restore.
pub(crate) fn recovery_kit(code: &str, computer: &str) -> String {
    let escape = |text: &str| {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    format!(
        "<!doctype html><meta charset=utf-8><title>Frameleaf recovery kit</title>\
<style>body{{font:15px/1.5 -apple-system,Segoe UI,sans-serif;max-width:640px;margin:48px auto;color:#111}}code{{font:600 20px ui-monospace,monospace;word-break:break-all}}</style>\
<h1>Frameleaf Computer backup: recovery kit</h1>\
<p>Computer: <b>{}</b></p><p>Recovery key:</p><p><code>{}</code></p>\
<h2>To restore on another computer</h2><ol><li>Install Frameleaf.</li><li>Choose Computer backup › Restore from a backup you already have.</li>\
<li>Sign in to your Frameleaf account and enter this recovery key.</li></ol>\
<p>Keep this page away from the computer it protects: printed, or in a password manager. Without the key nobody, including Frameleaf, can open these backups.</p>",
        escape(computer),
        escape(code)
    )
}

#[tauri::command]
pub async fn computer_backup_download_kit(
    window: WebviewWindow,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    use tauri_plugin_dialog::DialogExt;
    crate::require_local(&window)?;
    blocking(move || {
        let code = confirmed_key()?;
        let Some(file) = app
            .dialog()
            .file()
            .set_title("Save your recovery kit")
            .set_file_name("Frameleaf recovery kit.html")
            .blocking_save_file()
        else {
            return Ok(false);
        };
        let path = file
            .into_path()
            .map_err(|_| "computer_backup_folder_invalid")?;
        std::fs::write(path, recovery_kit(&code, &platform::computer_name()))
            .map_err(|_| "computer_backup_storage_failed")?;
        Ok(true)
    })
    .await
}

#[tauri::command]
pub async fn computer_backup_set_schedule(
    window: WebviewWindow,
    schedule: Schedule,
) -> Result<(), String> {
    crate::require_local(&window)?;
    if !matches!(schedule.every.as_str(), "hour" | "day")
        || schedule.at >= 1440
        || schedule.stop_by.is_some_and(|m| m >= 1440)
        || !matches!(
            schedule.keep.as_str(),
            "recommended" | "30d" | "1y" | "forever"
        )
        || schedule.limit_mbps.is_some_and(|m| m == 0 || m > 10_000)
    {
        return Err("computer_backup_schedule_invalid".into());
    }
    let mut settings = backup::load_settings();
    settings.schedule = schedule;
    backup::save_settings(&settings)
}

/// The end of set-up: backups on, the agent installed, and the first backup started.
#[tauri::command]
pub async fn computer_backup_finish(window: WebviewWindow) -> Result<(), String> {
    crate::require_local(&window)?;
    blocking(|| {
        if backup::link()?.is_none() || backup::recovery_key()?.is_none() {
            return Err("computer_backup_not_connected".into());
        }
        let mut settings = backup::load_settings();
        settings.enabled = true;
        backup::save_settings(&settings)?;
        platform::install_agent()?;
        platform::start_agent_now()
    })
    .await
}

#[tauri::command]
pub async fn computer_backup_run_now(window: WebviewWindow) -> Result<(), String> {
    crate::require_local(&window)?;
    platform::start_agent_now()
}

#[tauri::command]
pub async fn computer_backup_stop(window: WebviewWindow) -> Result<(), String> {
    crate::require_local(&window)?;
    backup::ask_stop();
    Ok(())
}

#[tauri::command]
pub async fn computer_backup_open_full_disk_access(window: WebviewWindow) -> Result<(), String> {
    crate::require_local(&window)?;
    platform::open_full_disk_access_settings()
}

#[tauri::command]
pub async fn computer_backup_open_plans(
    window: WebviewWindow,
    app: tauri::AppHandle,
) -> Result<(), String> {
    crate::require_local(&window)?;
    open(&app, "https://frameleaf.cloud/store")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupDate {
    key: String,
    time: String,
    files: u64,
    bytes: u64,
}

/// Every backup, newest first. Opens the repository with restore credentials and keeps it for browsing.
#[tauri::command]
pub async fn computer_backup_backups(
    window: WebviewWindow,
    state: State<'_, ComputerBackup>,
) -> Result<Vec<BackupDate>, String> {
    crate::require_local(&window)?;
    let browser = blocking(backup::open_browser).await?;
    let dates = browser
        .snapshots
        .iter()
        .map(|(key, snapshot)| BackupDate {
            key: key.clone(),
            time: snapshot.time.clone(),
            files: snapshot.stats.files,
            bytes: snapshot.stats.bytes,
        })
        .collect();
    *lock(&state.browser)? = Some(browser);
    Ok(dates)
}

#[tauri::command]
pub async fn computer_backup_browse(
    window: WebviewWindow,
    state: State<'_, ComputerBackup>,
    backup: String,
    path: Vec<String>,
) -> Result<Vec<Item>, String> {
    crate::require_local(&window)?;
    lock(&state.browser)?
        .as_ref()
        .ok_or("computer_backup_not_open")?
        .list(&backup, &path)
}

#[tauri::command]
pub async fn computer_backup_choose_target(
    window: WebviewWindow,
    app: tauri::AppHandle,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    crate::require_local(&window)?;
    blocking(move || {
        Ok(app
            .dialog()
            .file()
            .set_title("Restore into this folder")
            .blocking_pick_folder()
            .and_then(|folder| folder.into_path().ok())
            .map(|path| path.to_string_lossy().into_owned()))
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Restored {
    files: u64,
    bytes: u64,
    renamed: usize,
}

#[tauri::command]
pub async fn computer_backup_restore(
    window: WebviewWindow,
    state: State<'_, ComputerBackup>,
    backup: String,
    items: Vec<Vec<String>>,
    target: Option<String>,
) -> Result<Restored, String> {
    crate::require_local(&window)?;
    let settings = backup::load_settings();
    let started = backup::now_ms();
    let (result, time) = {
        let browser = lock(&state.browser)?;
        let browser = browser.as_ref().ok_or("computer_backup_not_open")?;
        let time = browser
            .snapshots
            .iter()
            .find(|(k, _)| k == &backup)
            .map(|(_, s)| s.time.clone());
        (
            browser.restore(
                &backup,
                &items,
                target.as_deref().map(std::path::Path::new),
                &settings.places,
                &settings.folders,
            ),
            time,
        )
    };
    let result = result?;
    backup::update_state(|current| {
        backup::record(
            current,
            RunRecord {
                at: backup::now_ms(),
                kind: "restore".into(),
                ok: true,
                files: result.files,
                bytes: result.bytes,
                took_ms: backup::now_ms() - started,
                problem: None,
                from: time,
                original: Some(target.is_none()),
            },
        )
    });
    Ok(Restored {
        files: result.files,
        bytes: result.bytes,
        renamed: result.moved_aside.len(),
    })
}

/// A copy of the recovery key in Cloud, locked with a passphrase first (or removed, with None).
#[tauri::command]
pub async fn computer_backup_locked_copy(
    window: WebviewWindow,
    passphrase: Option<String>,
) -> Result<(), String> {
    crate::require_local(&window)?;
    let on = passphrase.is_some();
    blocking(move || {
        let cloud = Cloud::new(backup::link()?.ok_or("computer_backup_not_connected")?);
        match passphrase {
            Some(passphrase) => {
                if frameleaf_backup_core::escrow::escrow_passphrase_problem(&passphrase).is_some() {
                    return Err("computer_backup_passphrase_short".into());
                }
                let key = backup::recovery_key()?.ok_or("computer_backup_key_missing")?;
                let blob = frameleaf_backup_core::escrow::wrap_bucket_key(&key, &passphrase, None)
                    .map_err(|_| "computer_backup_failed")?;
                cloud
                    .call(
                        reqwest::Method::PUT,
                        "/v1/backup/escrow",
                        Some(serde_json::to_value(blob).expect("JSON")),
                    )
                    .map_err(|r| r.code())?;
            }
            None => {
                if let Err(refusal) = cloud.call(reqwest::Method::DELETE, "/v1/backup/escrow", None)
                {
                    if refusal.status != 404 {
                        return Err(refusal.code());
                    }
                }
            }
        }
        Ok(())
    })
    .await?;
    let mut settings = backup::load_settings();
    settings.locked_copy = on;
    backup::save_settings(&settings)
}

/// Stops backups and removes this computer from the account; Cloud keeps what's stored, read-only, for 30 days.
#[tauri::command]
pub async fn computer_backup_disconnect(
    window: WebviewWindow,
    state: State<'_, ComputerBackup>,
) -> Result<(), String> {
    crate::require_local(&window)?;
    blocking(|| {
        if let Some(link) = backup::link()? {
            match Cloud::new(link).call(reqwest::Method::DELETE, "/v1/instance", None) {
                Ok(_) => {}
                Err(refusal) if refusal.status == 401 || refusal.status == 404 => {}
                Err(refusal) => return Err(refusal.code()),
            }
        }
        backup::ask_stop();
        platform::remove_agent();
        crate::credentials::delete(backup::LINK_CREDENTIAL)?;
        let mut settings = backup::load_settings();
        settings.enabled = false;
        settings.plan = None;
        backup::save_settings(&settings)?;
        backup::update_state(|current| *current = backup::State::default());
        Ok(())
    })
    .await?;
    *lock(&state.browser)? = None;
    Ok(())
}

/// Deletes this computer's backups after the 30-day hold, once the owner confirms it's them.
#[tauri::command]
pub async fn computer_backup_delete(window: WebviewWindow) -> Result<(), String> {
    crate::require_local(&window)?;
    blocking(|| {
        if !platform::confirm_owner("delete this computer’s backups") {
            return Err("computer_backup_not_confirmed".into());
        }
        let cloud = Cloud::new(backup::link()?.ok_or("computer_backup_not_connected")?);
        cloud
            .post("/v1/backup/purge", json!({}))
            .map_err(|r| r.code())?;
        backup::ask_stop();
        let mut settings = backup::load_settings();
        settings.enabled = false;
        backup::save_settings(&settings)?;
        backup::refresh_cloud(&cloud);
        Ok(())
    })
    .await
}

/// Keep My Backups: calls off a held deletion and turns backups back on.
#[tauri::command]
pub async fn computer_backup_keep(window: WebviewWindow) -> Result<(), String> {
    crate::require_local(&window)?;
    blocking(|| {
        let cloud = Cloud::new(backup::link()?.ok_or("computer_backup_not_connected")?);
        cloud
            .call(reqwest::Method::DELETE, "/v1/backup/purge", None)
            .map_err(|r| r.code())?;
        let mut settings = backup::load_settings();
        settings.enabled = true;
        backup::save_settings(&settings)?;
        backup::refresh_cloud(&cloud);
        Ok(())
    })
    .await
}
