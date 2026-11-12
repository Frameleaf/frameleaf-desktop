use crate::{
    connection::SavedConnection,
    model_cache::{check_cancel, CacheProgress},
};
use serde::Serialize;
use std::{
    future::Future,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[derive(Clone, Default, Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SetupStatus {
    pub state: String,
    pub code: Option<String>,
    pub control: crate::worker_control::WorkerControl,
    pub workloads: Vec<WorkloadStatus>,
    pub active_workload: Option<String>,
    pub models: Option<ModelProgress>,
    /// Tasks finished since the worker last started; read-only, for the status display.
    pub completed_tasks: u64,
    /// FD-52: the provider each workload runs on, and why when the processor stands in.
    pub providers: Vec<crate::provider_selection::WorkloadProvider>,
}
#[derive(Clone, Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ModelProgress {
    total_bytes: u64,
    verified_bytes: u64,
    download: Option<ModelDownload>,
}
#[derive(Clone, Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ModelDownload {
    received_bytes: u64,
    total_bytes: u64,
}
#[derive(Clone, Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkloadStatus {
    pub workload: String,
    pub state: String,
    pub model_names: Vec<String>,
    pub code: Option<String>,
}
#[derive(Clone)]
struct Progress {
    user_paused: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    status: Arc<Mutex<SetupStatus>>,
    notify: Arc<dyn Fn(SetupStatus) + Send + Sync>,
}
impl Progress {
    fn set(&self, state: &str, code: Option<String>) {
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        let mut current = self.status.lock().unwrap();
        let status = SetupStatus {
            state: state.into(),
            code,
            control: if self.user_paused.load(Ordering::Acquire) {
                crate::worker_control::WorkerControl::Paused
            } else {
                crate::worker_control::WorkerControl::Running
            },
            workloads: current.workloads.clone(),
            active_workload: None,
            models: current.models.clone().map(|mut models| {
                models.download = None;
                models
            }),
            completed_tasks: current.completed_tasks,
            providers: current.providers.clone(),
        };
        if *current == status {
            return;
        }
        *current = status.clone();
        drop(current);
        (self.notify)(status);
    }
    fn update(&self, update: impl FnOnce(&mut SetupStatus)) {
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        let mut status = self.status.lock().unwrap();
        let previous = status.clone();
        update(&mut status);
        if *status != previous {
            let snapshot = status.clone();
            drop(status);
            (self.notify)(snapshot);
        }
    }
    fn completed(&self) {
        self.update(|status| status.completed_tasks += 1);
    }
    fn active(&self, workload: Option<&str>) {
        self.update(|status| status.active_workload = workload.map(str::to_owned));
    }
    fn cache_progress(&self, event: CacheProgress) {
        self.update(|status| {
            let Some(models) = &mut status.models else {
                return;
            };
            match event {
                CacheProgress::Verified(bytes) => {
                    models.verified_bytes += bytes;
                    models.download = None;
                }
                CacheProgress::Download { received, total } => {
                    models.download = Some(ModelDownload {
                        received_bytes: received,
                        total_bytes: total,
                    });
                }
            }
        });
    }
    fn workloads(&self, workloads: Vec<WorkloadStatus>) {
        self.update(|status| status.workloads = workloads);
    }
    fn workload(&self, workload: &str, state: &str, code: Option<String>) {
        let mut statuses = self.status.lock().unwrap().workloads.clone();
        if let Some(item) = statuses.iter_mut().find(|item| item.workload == workload) {
            item.state = state.into();
            item.code = code;
        }
        self.workloads(statuses);
    }
}
struct Running {
    cancel: Arc<AtomicBool>,
    task: tauri::async_runtime::JoinHandle<()>,
}
#[derive(Default)]
pub(crate) struct WorkerSetup {
    user_paused: Arc<AtomicBool>,
    running: tokio::sync::Mutex<Option<Running>>,
    status: Arc<Mutex<SetupStatus>>,
}
impl WorkerSetup {
    pub fn status(&self) -> SetupStatus {
        self.status.lock().unwrap().clone()
    }
    /// The worker gave up and waits for Retry Setup. The saved session may be one the server has
    /// fenced since, so a retry starts from a newly issued session instead of replaying it.
    fn parked(&self) -> bool {
        self.status.lock().unwrap().state == "setup-needs-attention"
    }
    pub fn pause(&self) -> SetupStatus {
        self.user_paused.store(true, Ordering::Release);
        let mut status = self.status.lock().unwrap();
        status.control = crate::worker_control::WorkerControl::Paused;
        status.state = if matches!(
            status.state.as_str(),
            "working" | "preparing-runtime" | "preparing-models" | "qualifying" | "starting-worker"
        ) {
            "pausing".into()
        } else {
            "paused".into()
        };
        status.code = Some("user_paused".into());
        status.clone()
    }
    pub async fn hold(&self, control: crate::worker_control::WorkerControl) -> SetupStatus {
        self.stop().await;
        self.user_paused.store(
            control == crate::worker_control::WorkerControl::Paused,
            Ordering::Release,
        );
        let status = SetupStatus {
            state: if control == crate::worker_control::WorkerControl::Paused {
                "paused"
            } else {
                "stopped"
            }
            .into(),
            code: None,
            control,
            ..SetupStatus::default()
        };
        *self.status.lock().unwrap() = status.clone();
        status
    }
    async fn start_work<F, Fut>(&self, notify: Arc<dyn Fn(SetupStatus) + Send + Sync>, work: F)
    where
        F: FnOnce(Progress) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let mut running = self.running.lock().await;
        if let Some(previous) = running.take() {
            previous.cancel.store(true, Ordering::Release);
            let _ = previous.task.await;
        }
        self.user_paused.store(false, Ordering::Release);
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Progress {
            user_paused: self.user_paused.clone(),
            cancelled: cancel.clone(),
            status: self.status.clone(),
            notify,
        };
        let task = tauri::async_runtime::spawn(async move {
            match work(progress.clone()).await {
                Ok(()) => progress.set("qualified", None),
                Err(code) => {
                    let state = match code.as_str() {
                        "model_download_permission_required" => "model-download-required",
                        // Server configuration, not a fault here: retrying cannot change it.
                        "worker_no_eligible_workloads" => "no-eligible-work",
                        _ => "setup-needs-attention",
                    };
                    let safe = if code.len() <= 128
                        && code
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    {
                        code
                    } else {
                        "worker_setup_failed".into()
                    };
                    progress.set(state, Some(safe));
                }
            }
        });
        *running = Some(Running { cancel, task });
    }
    pub async fn stop(&self) {
        let mut running = self.running.lock().await;
        if let Some(previous) = running.take() {
            previous.cancel.store(true, Ordering::Release);
            let _ = previous.task.await;
        }
        *self.status.lock().unwrap() = SetupStatus::default();
    }
    pub async fn start(
        &self,
        saved: SavedConnection,
        paths: SetupPaths,
        allow_download: bool,
        notify: Arc<dyn Fn(SetupStatus) + Send + Sync>,
    ) {
        let fresh = self.parked();
        self.start_work(notify, move |progress| async move {
            let server = saved.server.clone();
            supervise(
                &progress,
                fresh,
                |refresh| {
                    let saved = saved.clone();
                    let paths = paths.clone();
                    let progress = progress.clone();
                    async move {
                        if refresh {
                            refresh_session(&saved).await?;
                            check_cancel(&progress.cancelled)?;
                        }
                        prepare(saved, paths, allow_download, progress).await
                    }
                },
                || {
                    let server = server.clone();
                    async move {
                        tauri::async_runtime::spawn_blocking(move || network_route(&server))
                            .await
                            .ok()
                            .flatten()
                    }
                },
                ROUTE_POLL,
            )
            .await
        })
        .await;
    }
}

const NO_WORK_RECHECK: Duration = Duration::from_secs(5 * 60);
const POLICY_RECHECK: Duration = Duration::from_secs(5 * 60);
const ROUTE_POLL: Duration = Duration::from_secs(5);

/// Keep the worker going across everything the server may change under it: lost connections and
/// fenced sessions reconnect, and refusals an administrator or the network can lift are waited out.
async fn supervise<F, Fut, R, RFut>(
    progress: &Progress,
    mut fresh: bool,
    mut attempt: F,
    mut route: R,
    route_poll: Duration,
) -> Result<(), String>
where
    F: FnMut(bool) -> Fut,
    Fut: Future<Output = Result<(), String>>,
    R: FnMut() -> RFut,
    RFut: Future<Output = Option<std::net::IpAddr>>,
{
    loop {
        let result = reconnect(progress, fresh, &mut attempt).await;
        fresh = false;
        match result {
            // An administrator can assign work at any time: ask the server again later.
            Err(code) if code == "worker_no_eligible_workloads" => {
                progress.set("no-eligible-work", Some(code));
                recheck_after(progress, NO_WORK_RECHECK).await?;
            }
            // The server will not use this computer for now: its owner turned helping off, or
            // this computer left the home network. Either can change without anyone opening the app.
            Err(code)
                if matches!(
                    code.as_str(),
                    "worker_policy_required" | "worker_lan_required"
                ) =>
            {
                progress.set("paused", Some(code));
                recheck_after_or_route_change(progress, POLICY_RECHECK, &mut route, route_poll)
                    .await?;
            }
            result => return result,
        }
    }
}

/// Wait out the period, and any user pause beyond it; Stop or a new start cancels the wait.
async fn recheck_after(progress: &Progress, period: Duration) -> Result<(), String> {
    recheck_after_or_route_change(progress, period, &mut || async { None }, Duration::MAX).await
}

/// As `recheck_after`, ended early when the route to the server changes (another network, a VPN).
async fn recheck_after_or_route_change<R, RFut>(
    progress: &Progress,
    period: Duration,
    route: &mut R,
    poll: Duration,
) -> Result<(), String>
where
    R: FnMut() -> RFut,
    RFut: Future<Output = Option<std::net::IpAddr>>,
{
    let started = std::time::Instant::now();
    let initial = route().await;
    let mut polled = std::time::Instant::now();
    while started.elapsed() < period || progress.user_paused.load(Ordering::Acquire) {
        check_cancel(&progress.cancelled)?;
        tokio::time::sleep(Duration::from_millis(250).min(poll)).await;
        if polled.elapsed() >= poll && !progress.user_paused.load(Ordering::Acquire) {
            polled = std::time::Instant::now();
            if route().await != initial {
                break;
            }
        }
    }
    check_cancel(&progress.cancelled)
}

/// The local address this computer would use to reach the server. It changes when the network
/// does; nothing is sent to find it.
fn network_route(server: &str) -> Option<std::net::IpAddr> {
    let target = crate::connection::normalize_server(server)
        .ok()?
        .socket_addrs(|| None)
        .ok()?
        .into_iter()
        .next()?;
    let socket = std::net::UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .ok()?;
    socket.connect(target).ok()?;
    socket.local_addr().ok().map(|address| address.ip())
}

pub(crate) fn bundled_runtime(resources: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    if let Some(prefix) = resources
        .parent()
        .filter(|parent| parent.file_name() == Some(std::ffi::OsStr::new("lib")))
        .and_then(Path::parent)
    {
        let shared = prefix.join("share/Frameleaf/native-runtime");
        if shared.exists() {
            return shared;
        }
    }
    resources.join("native-runtime")
}

#[derive(Clone)]
pub(crate) struct SetupPaths {
    pub data: PathBuf,
    pub bundle: PathBuf,
}
async fn cancellable<T>(
    future: impl Future<Output = Result<T, String>>,
    cancel: &AtomicBool,
) -> Result<T, String> {
    check_cancel(cancel)?;
    tokio::select! {
        result = future => result,
        _ = async { loop { if cancel.load(Ordering::Acquire) { break; } tokio::time::sleep(Duration::from_millis(50)).await; } } => Err("worker_setup_cancelled".into())
    }
}
async fn wait_for_user<F: Future<Output = Result<(), String>>>(
    progress: &Progress,
    mut maintain: impl FnMut() -> F,
) -> Result<(), String> {
    while progress.user_paused.load(Ordering::Acquire) {
        check_cancel(&progress.cancelled)?;
        progress.set("paused", Some("user_paused".into()));
        maintain().await?;
        cancellable(
            async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            },
            &progress.cancelled,
        )
        .await?;
    }
    check_cancel(&progress.cancelled)
}
async fn wait_for_capacity<F: Future<Output = Result<(), String>>>(
    required_memory: u64,
    progress: &Progress,
    mut maintain: impl FnMut() -> F,
) -> Result<(), String> {
    loop {
        wait_for_user(progress, &mut maintain).await?;
        check_cancel(&progress.cancelled)?;
        maintain().await?;
        let status = tauri::async_runtime::spawn_blocking(crate::resource_policy::sample)
            .await
            .map_err(|_| "resource_status_unavailable")?;
        check_cancel(&progress.cancelled)?;
        let Some(reason) = status.refusal(required_memory) else {
            return Ok(());
        };
        progress.set("paused", Some(reason.into()));
        cancellable(
            async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            },
            &progress.cancelled,
        )
        .await?;
    }
}
fn wake_gap(previous: std::time::SystemTime, current: std::time::SystemTime) -> bool {
    current
        .duration_since(previous)
        .map_or(true, |gap| gap > Duration::from_secs(30))
}
#[derive(Clone)]
struct WakeClock(Arc<Mutex<std::time::SystemTime>>);
impl WakeClock {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(std::time::SystemTime::now())))
    }
    fn observe(&self, current: std::time::SystemTime) -> bool {
        let mut previous = self.0.lock().unwrap();
        let resumed = wake_gap(*previous, current);
        *previous = current;
        resumed
    }
}
const TASK_FAILURE_LIMIT: u32 = 5;
/// One bad task is dropped and the next is claimed; an unbroken run of them parks the worker.
#[derive(Default)]
struct TaskFailures(u32);
impl TaskFailures {
    fn completed(&mut self) {
        self.0 = 0;
    }
    /// The pause before the next claim, or the code to park with once the run reaches the limit.
    fn dropped(&mut self, code: String) -> Result<Duration, String> {
        self.0 += 1;
        if self.0 >= TASK_FAILURE_LIMIT {
            return Err(code);
        }
        Ok(reconnect_delay(self.0, rand::random()))
    }
}
fn reconnect_delay(attempt: u32, entropy: u64) -> Duration {
    let base = (1u64 << attempt.min(5)).min(30) * 1000;
    Duration::from_millis(base + entropy % (base + 1))
}
fn retryable(error: &str) -> bool {
    matches!(
        error,
        "worker_request_interrupted"
            | "server_response_interrupted"
            | "server_unreachable_or_certificate_invalid"
            | "worker_session_setup_interrupted"
            | "model_download_unavailable"
            | "model_download_interrupted"
            | "worker_session_renewal_required"
            // The server ended this worker session (a household change fences the device) or the
            // policy the work ran under: a newly issued session and qualification carry on. If the
            // device itself is refused, issuing that session fails and the worker stops there.
            | "worker_session_rejected"
            | "worker_policy_changed"
            | "worker_lease_expired"
            | "worker_lease_lost"
            | "worker_execution_deadline"
            | "runtime_process_stopped"
            | "runtime_not_ready"
            | "runtime_prediction_interrupted"
            | "server_http_408"
            | "server_http_429"
            | "server_http_502"
            | "server_http_503"
            | "server_http_504"
    )
}
async fn reconnect<F: FnMut(bool) -> Fut, Fut: Future<Output = Result<(), String>>>(
    progress: &Progress,
    mut refresh: bool,
    mut attempt: F,
) -> Result<(), String> {
    let mut retries = 0u32;
    loop {
        wait_for_user(progress, || async { Ok(()) }).await?;
        let error = match attempt(refresh).await {
            Ok(()) => return Ok(()),
            Err(error) if retryable(&error) => error,
            Err(error) => return Err(error),
        };
        check_cancel(&progress.cancelled)?;
        if matches!(
            progress.status.lock().unwrap().state.as_str(),
            "working" | "waiting-for-work"
        ) {
            retries = 0;
        }
        progress.set("reconnecting", Some(error));
        let delay = reconnect_delay(retries, rand::random());
        retries = retries.saturating_add(1);
        refresh = true;
        cancellable(
            async {
                tokio::time::sleep(delay).await;
                Ok(())
            },
            &progress.cancelled,
        )
        .await?;
    }
}
async fn refresh_session(saved: &SavedConnection) -> Result<(), String> {
    let client = crate::transport::client()?;
    let capabilities = crate::transport::capabilities(&client, saved)
        .await?
        .ok_or("desktop_protocol_unsupported")?;
    if !capabilities.features.worker_session {
        return Err("desktop_worker_session_unavailable".into());
    }
    // Issue rechecks the existing device and photo session; recovery must never re-enroll a revoked device.
    let worker = crate::transport::issue_worker_session(&client, saved).await?;
    crate::credentials::save("worker-session", &worker)
}
/// Watches work whose models are already loaded: the memory floor was applied when it was admitted.
async fn resource_loss(clock: &WakeClock) -> String {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        if clock.observe(std::time::SystemTime::now()) {
            return "system_resumed".into();
        }
        match tauri::async_runtime::spawn_blocking(crate::resource_policy::sample).await {
            Ok(status) => {
                if let Some(reason) = status.refusal_while_loaded() {
                    return reason.into();
                }
            }
            Err(_) => return "status_unavailable".into(),
        }
    }
}
async fn maintained<T, F: Future<Output = Result<(), String>>>(
    work: impl Future<Output = Result<T, String>>,
    interrupt: impl Future<Output = String>,
    mut maintain: impl FnMut() -> F,
    cancelled: &AtomicBool,
) -> Result<T, String> {
    tokio::pin!(work, interrupt);
    loop {
        check_cancel(cancelled)?;
        // A renewal can rotate the server token; finish saving it even if work or sign-out completes.
        maintain().await?;
        check_cancel(cancelled)?;
        let completed = cancellable(
            async {
                Ok(tokio::select! {
                    biased;
                    result = &mut work => Some(result),
                    reason = &mut interrupt => Some(Err(reason)),
                    _ = tokio::time::sleep(Duration::from_secs(30)) => None,
                })
            },
            cancelled,
        )
        .await?;
        if let Some(result) = completed {
            return result;
        }
    }
}
async fn download_network_loss<F: Future<Output = Option<bool>>>(mut sample: impl FnMut() -> F) {
    loop {
        if sample().await != Some(true) {
            return;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
async fn acquisition<T, F: Future<Output = Result<(), String>>>(
    work: impl Future<Output = Result<T, String>>,
    explicit_permission: bool,
    maintain: impl FnMut() -> F,
    network_loss: impl Future<Output = ()>,
    cancelled: &AtomicBool,
) -> Result<T, String> {
    maintained(
        work,
        async {
            if explicit_permission {
                std::future::pending::<()>().await;
            }
            network_loss.await;
            "model_download_permission_required".into()
        },
        maintain,
        cancelled,
    )
    .await
}
async fn monitored_preparation<T: Send + 'static, F: Future<Output = Result<(), String>>>(
    work: impl FnOnce(Arc<AtomicBool>) -> T + Send + 'static,
    interrupt: impl Future<Output = String>,
    maintain: impl FnMut() -> F,
    cancelled: &AtomicBool,
) -> Result<(T, Option<String>), String> {
    check_cancel(cancelled)?;
    let stop = Arc::new(AtomicBool::new(false));
    let request = stop.clone();
    let mut task = tauri::async_runtime::spawn_blocking(move || work(request));
    let reason = match maintained(
        async { Ok((&mut task).await) },
        interrupt,
        maintain,
        cancelled,
    )
    .await
    {
        Ok(result) => {
            return result
                .map(|value| (value, None))
                .map_err(|_| "runtime_qualification_failed".into())
        }
        Err(reason) => Some(reason),
    };
    stop.store(true, Ordering::Release);
    // Dropping a blocking task leaves it running; join before resuming or signing out.
    let value = task.await.map_err(|_| "runtime_qualification_failed")?;
    Ok((value, reason))
}
pub(crate) fn inventory_profiles(
    value: &serde_json::Value,
    source: &str,
    provider: &str,
) -> Result<
    (
        Vec<Vec<crate::model_catalogue::ApprovedProfile>>,
        Vec<WorkloadStatus>,
    ),
    String,
> {
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Inventory {
        protocol_version: u32,
        provider: String,
        runtime_source_revision: String,
        workloads: Vec<Entry>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Entry {
        workload: String,
        state: String,
        model_names: Vec<String>,
        model_keys: Vec<String>,
    }
    let invalid = || "worker_model_inventory_invalid".to_string();
    let inventory: Inventory = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    if inventory.protocol_version != 1
        || inventory.provider != provider
        || inventory.runtime_source_revision != source
        || inventory.workloads.len() != 4
    {
        return Err(invalid());
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut groups = Vec::new();
    let mut statuses = Vec::new();
    for entry in inventory.workloads {
        if !["clip", "ocr", "face", "enrichment"].contains(&entry.workload.as_str())
            || !seen.insert(entry.workload.clone())
            || ![
                "eligible",
                "disabled",
                "pinned",
                "legacy",
                "unavailable",
                "unsupported",
            ]
            .contains(&entry.state.as_str())
            || entry.model_names.len() > 8
            || entry
                .model_names
                .iter()
                .any(|name| name.is_empty() || name.len() > 2048)
        {
            return Err(invalid());
        }
        let mut state = entry.state;
        if state == "eligible" {
            let expected = match entry.workload.as_str() {
                "clip" => 3,
                "ocr" | "face" => 1,
                _ => return Err(invalid()),
            };
            if entry.model_keys.len() != expected
                || entry
                    .model_keys
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != expected
                || entry.model_keys.iter().any(|key| {
                    !key.starts_with(&(entry.workload.clone() + ":"))
                        || key.len() != entry.workload.len() + 65
                        || !key[entry.workload.len() + 1..]
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            {
                return Err(invalid());
            }
            let profiles = crate::model_catalogue::inventory_group(
                &entry.workload,
                &entry.model_keys,
                source,
                provider,
            )?;
            if profiles.is_empty() {
                state = "unsupported".into();
            } else {
                groups.push(profiles);
            }
        } else if !entry.model_keys.is_empty() {
            return Err(invalid());
        }
        statuses.push(WorkloadStatus {
            workload: entry.workload,
            state,
            model_names: entry.model_names,
            code: None,
        });
    }
    Ok((groups, statuses))
}

/// Whether the app's bundled runtime should replace the active one. The bundle is only read here,
/// not trusted: activation verifies its signature and refuses a reused or rolled-back epoch, so a
/// rebuilt runtime that kept its epoch fails visibly instead of leaving the old runtime running.
pub(crate) fn bundle_supersedes(active_sha256: &str, active_epoch: u64, manifest: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    if format!("{:x}", Sha256::digest(manifest)) == active_sha256 {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(manifest)
        .ok()
        .and_then(|value| value.get("epoch")?.as_u64())
        .is_none_or(|epoch| epoch >= active_epoch)
}

async fn prepare(
    saved: SavedConnection,
    paths: SetupPaths,
    allow_download: bool,
    progress: Progress,
) -> Result<(), String> {
    use crate::{
        ml_transport::WorkerTransport,
        native_predictor::Step,
        release_policy::open_runtime_store,
        runtime_store::{private_directory, read_bounded},
        transport,
    };
    progress.update(|status| status.models = None);
    progress.set("preparing-runtime", None);
    let cancelled = progress.cancelled.clone();
    let (data, bundle) = (paths.data.clone(), paths.bundle.clone());
    let (installed, attestation) = tauri::async_runtime::spawn_blocking(move || {
        check_cancel(&cancelled)?;
        let mut missing = Vec::new();
        let mut parent = data.as_path();
        while std::fs::symlink_metadata(parent).is_err() {
            missing.push(parent.to_path_buf());
            parent = parent.parent().ok_or("app_data_directory_unavailable")?;
        }
        crate::native_runtime::absolute_directory(parent)?;
        for directory in missing.iter().rev() {
            private_directory(directory)?;
        }
        private_directory(&data)?;
        private_directory(&data.join("models"))?;
        private_directory(&data.join("scratch"))?;
        if !bundle.exists()
            && matches!(std::fs::symlink_metadata(data.join("runtimes/active.json")), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            return Err("runtime_pack_unavailable".into());
        }
        let store = open_runtime_store(&data.join("runtimes"))?;
        let active = store.load_active()?;
        let bundled = if bundle.exists() {
            Some(read_bounded(&bundle.join("manifest.json"), 8 * 1024 * 1024)?)
        } else {
            None
        };
        // An app update ships a new runtime: activate it, or the old runtime keeps running forever.
        // An older bundle (the app was downgraded) leaves the newer active runtime in place.
        let install = match (&active, &bundled) {
            (None, Some(_)) => true,
            (Some(active), Some(manifest)) => bundle_supersedes(active.manifest_sha256(), active.epoch(), manifest),
            _ => false,
        };
        let installed = match (active, bundled) {
            (Some(value), _) if !install => value,
            (active, Some(manifest)) => {
                // Release the shared lease first: activation takes the store's exclusive lock.
                drop(active);
                let signature: [u8; 64] = read_bounded(&bundle.join("manifest.sig"), 64)?
                    .try_into()
                    .map_err(|_| "runtime_signature_invalid")?;
                store.install_and_activate(&bundle.join("payload"), &manifest, &signature)?;
                store.load_active()?.ok_or("runtime_activation_failed")?
            }
            (_, None) => return Err("runtime_pack_unavailable".into()),
        };
        check_cancel(&cancelled)?;
        let attestation = store.attestation(&installed)?;
        Ok::<_, String>((installed, attestation))
    })
    .await
    .map_err(|_| "runtime_preparation_failed")??;
    let client = transport::client()?;
    let caps = cancellable(
        transport::capabilities(&client, &saved),
        &progress.cancelled,
    )
    .await?
    .ok_or("desktop_protocol_unsupported")?;
    if !caps.features.worker_session {
        return Err("desktop_worker_session_unavailable".into());
    }
    let worker = WorkerTransport::load(&saved)?;
    let inventory = cancellable(
        worker.model_inventory(installed.source_revision(), installed.provider()),
        &progress.cancelled,
    )
    .await?;
    let (groups, statuses) = inventory_profiles(
        &inventory,
        installed.source_revision(),
        installed.provider(),
    )?;
    progress.workloads(statuses);
    if groups.is_empty() {
        return Err("worker_no_eligible_workloads".into());
    }
    // FD-52: an accelerated runtime beside the processor one, where the app ships one this
    // computer can use. Any fault on that side leaves every workload on the processor.
    let (accelerated, mut plan) =
        crate::provider_selection::open(&paths, &installed, &worker, groups.clone()).await;
    let mut installed =
        crate::provider_selection::Runtimes::new(installed, attestation, accelerated);
    let profiles: Vec<_> = groups.iter().flatten().cloned().collect();
    let network = tauri::async_runtime::spawn_blocking(crate::resource_policy::sample)
        .await
        .map_err(|_| "resource_status_unavailable")?;
    let explicit_permission = allow_download;
    let allow_download = explicit_permission || network.unmetered == Some(true);
    let mut counted = std::collections::BTreeSet::new();
    let total_bytes = profiles
        .iter()
        .filter(|profile| counted.insert(profile.cache_identity()))
        .map(|profile| profile.cache_bytes())
        .sum();
    counted.clear();
    progress.update(|status| {
        status.models = Some(ModelProgress {
            total_bytes,
            verified_bytes: 0,
            download: None,
        })
    });
    progress.set("preparing-models", None);
    // Complete acquisition before requesting short-lived nonces.
    let mut caches = Vec::new();
    for profile in &profiles {
        let count = counted.insert(profile.cache_identity());
        wait_for_user(&progress, || worker.maintain_session()).await?;
        let cache = acquisition(
            profile.prepare_cache(
                &paths.data.join("models"),
                &client,
                &progress.cancelled,
                allow_download,
                |event| {
                    if count {
                        progress.cache_progress(event);
                    }
                },
            ),
            explicit_permission,
            || worker.maintain_session(),
            download_network_loss(|| async {
                tauri::async_runtime::spawn_blocking(crate::resource_policy::sample)
                    .await
                    .ok()
                    .and_then(|status| status.unmetered)
            }),
            &progress.cancelled,
        )
        .await?;
        caches.push(cache);
    }
    let mut failures = TaskFailures::default();
    'qualification: loop {
        // The provider chosen for each workload; a failed provider is demoted and this restarts.
        let groups = plan.groups();
        progress.update(|status| status.providers = plan.providers());
        let mut prepared = Vec::new();
        let mut accepted_profiles = Vec::new();
        let mut accepted_caches = Vec::new();
        'workload: for group in &groups {
            let workload = group[0]
                .model_key()
                .split(':')
                .next()
                .ok_or("worker_model_inventory_invalid")?;
            progress.workload(workload, "qualifying", None);
            let mut group_prepared = Vec::new();
            let mut group_caches = Vec::new();
            for profile in group {
                let index = profiles
                    .iter()
                    .position(|item| item.model_key() == profile.model_key())
                    .ok_or("worker_model_binding_invalid")?;
                let cache = caches[index].clone();
                group_caches.push(cache.clone());
                check_cancel(&progress.cancelled)?;
                wait_for_capacity(profile.minimum_memory(), &progress, || {
                    worker.maintain_session()
                })
                .await?;
                progress.set("qualifying", None);
                let challenge = match cancellable(
                    worker.request_qualification(
                        profile,
                        installed.attestation(profile.provider())?,
                        &uuid::Uuid::new_v4().to_string(),
                    ),
                    &progress.cancelled,
                )
                .await
                {
                    Ok(value) => value,
                    Err(code) if code.starts_with("workload_desktop_") => {
                        if plan.demote(workload, &code, false) {
                            continue 'qualification;
                        }
                        progress.workload(workload, "unavailable", Some(code));
                        continue 'workload;
                    }
                    Err(code) => return Err(code),
                };
                let spec = challenge.specification().to_vec();
                let fixture = challenge.fixture().to_vec();
                let scratch = paths.data.join("scratch");
                let provider = profile.provider().to_owned();
                let clock = WakeClock::new();
                let ((runtime, qualified), interrupted) = monitored_preparation(
                    move |cancel| {
                        let qualified = installed
                            .qualify(&provider, &cache, &scratch, &spec, &fixture, &cancel);
                        (installed, qualified)
                    },
                    async { format!("resource_{}", resource_loss(&clock).await) },
                    || worker.maintain_session(),
                    &progress.cancelled,
                )
                .await?;
                installed = runtime;
                check_cancel(&progress.cancelled)?;
                if clock.observe(std::time::SystemTime::now()) {
                    progress.set("paused", Some("system_resumed".into()));
                    continue 'qualification;
                }
                if let Some(reason) = interrupted {
                    if let Some(reason) = reason.strip_prefix("resource_") {
                        progress.set("paused", Some(reason.into()));
                        continue 'qualification;
                    }
                    return Err(reason);
                }
                let qualified = match qualified {
                    Ok(value) => value,
                    Err(code)
                        if matches!(
                            code.as_str(),
                            "runtime_qualification_failed"
                                | "runtime_qualification_timeout"
                                | "runtime_qualification_report_invalid"
                        ) =>
                    {
                        if plan.demote(workload, &code, true) {
                            continue 'qualification;
                        }
                        progress.workload(workload, "unavailable", Some(code));
                        continue 'workload;
                    }
                    Err(code) => return Err(code),
                };
                match cancellable(
                    worker.submit_qualification(&challenge, &qualified),
                    &progress.cancelled,
                )
                .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        if plan.demote(workload, "worker_qualification_refused", false) {
                            continue 'qualification;
                        }
                        progress.workload(
                            workload,
                            "unavailable",
                            Some("worker_qualification_refused".into()),
                        );
                        continue 'workload;
                    }
                    Err(code) if code.starts_with("workload_desktop_") => {
                        if plan.demote(workload, &code, false) {
                            continue 'qualification;
                        }
                        progress.workload(workload, "unavailable", Some(code));
                        continue 'workload;
                    }
                    Err(code) => return Err(code),
                }
                let accepted = match cancellable(
                    worker.read_accepted_qualification(profile, &qualified, challenge.id()),
                    &progress.cancelled,
                )
                .await
                {
                    Ok(value) => value,
                    Err(code) if code.starts_with("workload_desktop_") => {
                        if plan.demote(workload, &code, false) {
                            continue 'qualification;
                        }
                        progress.workload(workload, "unavailable", Some(code));
                        continue 'workload;
                    }
                    Err(code) => return Err(code),
                };
                group_prepared.push((qualified, accepted));
            }
            prepared.extend(group_prepared);
            accepted_profiles.extend(group.iter().cloned());
            accepted_caches.extend(group_caches);
            progress.workload(workload, "ready", None);
        }
        if prepared.is_empty() {
            // The server offered work but none qualified here (timeout, refusal): a local fault
            // that Retry Setup can clear, not the server-configuration state.
            return Err("worker_no_qualified_workloads".into());
        }
        let mut memory_by_cache = std::collections::BTreeMap::new();
        for (profile, cache) in accepted_profiles.iter().zip(&accepted_caches) {
            let memory = memory_by_cache.entry(cache).or_insert(0u64);
            *memory = (*memory).max(profile.minimum_memory());
        }
        let required_memory = memory_by_cache.values().sum();
        let combined = paths.data.join("model-sets");
        let cancelled = progress.cancelled.clone();
        let cache = tauri::async_runtime::spawn_blocking(move || {
            crate::model_catalogue::shared_cache(
                &accepted_profiles,
                &accepted_caches,
                &combined,
                &cancelled,
            )
        })
        .await
        .map_err(|_| "worker_cache_publish_failed")??;
        // Best effort: reclaim superseded model revisions and abandoned staging.
        let models = paths.data.join("models");
        let referenced = profiles
            .iter()
            .map(|profile| profile.cache_identity().2.to_owned())
            .collect();
        // FD-52: and runtime packs, combined model sets and scratch nothing can use any more.
        let (data, bundle, set) = (paths.data.clone(), paths.bundle.clone(), cache.clone());
        let active_runtime = installed.cpu().manifest_sha256().to_owned();
        let accelerated_runtime = installed
            .accelerated()
            .map(|runtime| runtime.manifest_sha256().to_owned());
        let _ = tauri::async_runtime::spawn_blocking(move || {
            let now = std::time::SystemTime::now();
            let _ = crate::model_cache::prune(&models, &referenced, now);
            if let Some(active) = accelerated_runtime {
                crate::provider_selection::reclaim_superseded(&data, &bundle, &active);
            }
            crate::release_policy::reclaim_superseded(&data, &bundle, &active_runtime, &set, now)
        })
        .await;
        loop {
            wait_for_capacity(required_memory, &progress, || worker.maintain_session()).await?;
            let now = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
            if prepared
                .iter()
                .any(|(proof, accepted)| accepted.validate_runtime(proof, now + 60_000).is_err())
            {
                continue 'qualification;
            }
            progress.set("starting-worker", None);
            let scratch = paths.data.join("scratch");
            let cache = cache.clone();
            let (runtime, proofs, mut predictor) =
                tauri::async_runtime::spawn_blocking(move || {
                    let reservation =
                        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                            .map_err(|_| "runtime_port_unavailable")?;
                    let port = reservation
                        .local_addr()
                        .map_err(|_| "runtime_port_unavailable")?
                        .port();
                    drop(reservation);
                    let bindings: Vec<_> = prepared
                        .iter()
                        .map(|(proof, accepted)| (proof, accepted))
                        .collect();
                    let predictor = installed.start(&bindings, &cache, &scratch, port)?;
                    Ok::<_, String>((installed, prepared, predictor))
                })
                .await
                .map_err(|_| "runtime_start_failed")??;
            installed = runtime;
            prepared = proofs;
            check_cancel(&progress.cancelled)?;
            let (_sender, mut cancel) = tokio::sync::watch::channel(false);
            let clock = WakeClock::new();
            loop {
                worker.maintain_session().await?;
                let resources =
                    tauri::async_runtime::spawn_blocking(crate::resource_policy::sample)
                        .await
                        .map_err(|_| "resource_status_unavailable")?;
                check_cancel(&progress.cancelled)?;
                if clock.observe(std::time::SystemTime::now()) {
                    predictor.stop()?;
                    progress.set("paused", Some("system_resumed".into()));
                    continue 'qualification;
                }
                if progress.user_paused.load(Ordering::Acquire) {
                    predictor.stop()?;
                    progress.set("paused", Some("user_paused".into()));
                    break;
                }
                // The models are loaded: only power and network can refuse now. Memory was checked
                // at admission, and this process's own models must not count against its floor.
                if let Some(reason) = resources.refusal_while_loaded() {
                    // Release model memory before waiting, otherwise the warm process can prevent recovery.
                    predictor.stop()?;
                    progress.set("paused", Some(reason.into()));
                    break;
                }
                let now =
                    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
                if prepared.iter().any(|(proof, accepted)| {
                    accepted.validate_runtime(proof, now + 60_000).is_err()
                }) {
                    continue 'qualification;
                }
                progress.set("working", None);
                let accepted: Vec<_> = prepared.iter().map(|(_, accepted)| accepted).collect();
                let completed = cancellable(async {
                    tokio::select! {
                        biased;
                        reason = resource_loss(&clock) => Err(format!("resource_{reason}")),
                        result = predictor.execute_next_with_activity(&worker, &accepted, &mut cancel, |workload| progress.active(Some(workload))) => result,
                    }
                }, &progress.cancelled).await;
                progress.active(None);
                match completed {
                    Ok(Step::Completed) => {
                        failures.completed();
                        progress.completed();
                    }
                    Ok(Step::Dropped(code)) => {
                        let delay = match failures.dropped(code) {
                            Ok(delay) => delay,
                            Err(code) => {
                                predictor.stop()?;
                                return Err(code);
                            }
                        };
                        cancellable(
                            async {
                                tokio::time::sleep(delay).await;
                                Ok(())
                            },
                            &progress.cancelled,
                        )
                        .await?;
                        if !predictor.is_running()? {
                            // Inference was cut short: load the models again before the next claim.
                            break;
                        }
                    }
                    Ok(Step::Idle) => {
                        progress.set("waiting-for-work", None);
                        cancellable(
                            async {
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                Ok(())
                            },
                            &progress.cancelled,
                        )
                        .await?;
                    }
                    Err(reason) if reason.starts_with("resource_") => {
                        predictor.stop()?;
                        progress.set("paused", Some(reason[9..].into()));
                        if reason == "resource_system_resumed" {
                            continue 'qualification;
                        }
                        break;
                    }
                    Err(reason) => {
                        // FD-52: the accelerated runtime's process did not serve: use the
                        // processor for its workloads instead of failing the worker.
                        let lane = predictor.failed_lane().map(str::to_owned);
                        if lane.is_some_and(|lane| plan.demote_runtime(&lane, &reason)) {
                            predictor.stop()?;
                            continue 'qualification;
                        }
                        return Err(reason);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn bundled_runtime_keeps_legacy_and_development_resource_locations() {
        let resources = std::env::temp_dir().join("frameleaf-synthetic-resources");
        assert_eq!(
            bundled_runtime(&resources),
            resources.join("native-runtime")
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_bundled_runtime_uses_the_immutable_shared_payload_and_legacy_fallback() {
        let root =
            std::env::temp_dir().join(format!("frameleaf-resources-{}", uuid::Uuid::new_v4()));
        let resources = root.join("usr/lib/Frameleaf");
        let shared = root.join("usr/share/Frameleaf/native-runtime");
        std::fs::create_dir_all(&resources).unwrap();
        assert_eq!(
            bundled_runtime(&resources),
            resources.join("native-runtime")
        );
        std::fs::create_dir_all(&shared).unwrap();
        assert_eq!(bundled_runtime(&resources), shared);
        assert_eq!(
            bundled_runtime(&root.join("debug")),
            root.join("debug/native-runtime")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn finished_tasks_are_counted_and_survive_state_changes() {
        let progress = Progress {
            user_paused: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(SetupStatus::default())),
            notify: Arc::new(|_| {}),
        };
        progress.set("working", None);
        progress.completed();
        progress.completed();
        progress.set("waiting-for-work", None);
        progress.set("paused", Some("memory_low".into()));
        let status = progress.status.lock().unwrap().clone();
        assert_eq!(status.completed_tasks, 2);
        assert_eq!(
            serde_json::to_value(&status).unwrap()["completedTasks"],
            serde_json::json!(2)
        );
    }
    #[test]
    fn global_progress_preserves_independent_workload_results() {
        let progress = Progress {
            user_paused: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(SetupStatus::default())),
            notify: Arc::new(|_| {}),
        };
        progress.workloads(vec![
            WorkloadStatus {
                workload: "ocr".into(),
                state: "ready".into(),
                model_names: vec!["PP-OCRv5_mobile".into()],
                code: None,
            },
            WorkloadStatus {
                workload: "face".into(),
                state: "eligible".into(),
                model_names: vec!["buffalo_l".into()],
                code: None,
            },
        ]);
        progress.workload(
            "face",
            "unavailable",
            Some("workload_desktop_nas_face_producer_unavailable".into()),
        );
        progress.set("working", None);
        let status = progress.status.lock().unwrap().clone();
        assert_eq!(status.workloads[0].state, "ready");
        assert_eq!(status.workloads[1].state, "unavailable");
        progress.cancelled.store(true, Ordering::Release);
        progress.workload("face", "ready", None);
        assert_eq!(*progress.status.lock().unwrap(), status);
    }
    fn inventory_fixture() -> serde_json::Value {
        inventory_fixture_with("ViT-B-16-SigLIP-384__webli")
    }
    fn inventory_fixture_with(clip_model: &str) -> serde_json::Value {
        let catalogue: serde_json::Value =
            serde_json::from_str(include_str!("../../runtime/model-catalogue.json")).unwrap();
        let workloads = ["clip", "ocr", "face", "enrichment"].map(|workload| {
            let profiles: Vec<_> = catalogue["profiles"].as_array().unwrap().iter().filter(|p|
                p["workload"] == workload && p["spec"]["provider"] == "CPUExecutionProvider" &&
                p["runtimeSourceRevision"] == "25b22c16e47a27a2eb50017d838497abce850d11").collect();
            // one model per workload, as one server config selects one: the release default, or `clip_model`
            let default = if workload == "clip" {
                Some(serde_json::json!(clip_model))
            } else {
                profiles.first().map(|p| p["modelName"].clone())
            };
            let profiles: Vec<_> = profiles.into_iter().filter(|p| Some(&p["modelName"]) == default.as_ref()).collect();
            serde_json::json!({"workload":workload,"state":if workload == "enrichment" {"unsupported"} else {"eligible"},
                "modelNames":profiles.first().map(|p| vec![p["modelName"].clone()]).unwrap_or_default(),
                "modelKeys":profiles.iter().map(|p|p["modelKey"].clone()).collect::<Vec<_>>()})
        });
        serde_json::json!({"protocolVersion":1,"provider":"CPUExecutionProvider",
            "runtimeSourceRevision":"25b22c16e47a27a2eb50017d838497abce850d11","workloads":workloads})
    }
    #[test]
    fn inventory_keeps_eligible_workloads_when_another_is_pinned_or_unknown() {
        let source = "25b22c16e47a27a2eb50017d838497abce850d11";
        let mut value = inventory_fixture();
        value["workloads"][2]["state"] = serde_json::json!("pinned");
        value["workloads"][2]["modelKeys"] = serde_json::json!([]);
        let (groups, statuses) =
            inventory_profiles(&value, source, "CPUExecutionProvider").unwrap();
        assert_eq!(groups.iter().map(Vec::len).collect::<Vec<_>>(), vec![3, 1]);
        assert_eq!(statuses[2].state, "pinned");
        value["workloads"][1]["modelKeys"][0] =
            serde_json::json!(format!("ocr:{}", "0".repeat(64)));
        let (groups, statuses) =
            inventory_profiles(&value, source, "CPUExecutionProvider").unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(statuses[1].state, "unsupported");
        assert!(inventory_profiles(&value, source, "CUDAExecutionProvider").is_err());
    }
    #[test]
    fn inventory_selects_each_new_clip_model_and_rejects_mixed_model_groups() {
        let source = "25b22c16e47a27a2eb50017d838497abce850d11";
        let models = ["ViT-B-32__openai", "ViT-SO400M-16-SigLIP2-384__webli"];
        for model in models {
            let value = inventory_fixture_with(model);
            let keys = value["workloads"][0]["modelKeys"].clone();
            assert_eq!(keys.as_array().unwrap().len(), 3);
            let (groups, _) = inventory_profiles(&value, source, "CPUExecutionProvider").unwrap();
            let mut selected: Vec<_> = groups[0].iter().map(|p| p.model_key().to_owned()).collect();
            let mut expected: Vec<_> = keys
                .as_array()
                .unwrap()
                .iter()
                .map(|k| k.as_str().unwrap().to_owned())
                .collect();
            selected.sort();
            expected.sort();
            assert_eq!(selected, expected);
        }
        // one key from the other model leaves no complete group: search is unsupported, the rest stay
        let mut value = inventory_fixture_with(models[0]);
        value["workloads"][0]["modelKeys"][0] =
            inventory_fixture_with(models[1])["workloads"][0]["modelKeys"][0].clone();
        let (groups, statuses) =
            inventory_profiles(&value, source, "CPUExecutionProvider").unwrap();
        assert_eq!(statuses[0].state, "unsupported");
        assert_eq!(groups.iter().map(Vec::len).collect::<Vec<_>>(), vec![1, 1]);
    }
    #[test]
    fn inventory_rejects_partial_clip_groups_and_invalid_authority_shapes() {
        let source = "25b22c16e47a27a2eb50017d838497abce850d11";
        let mut value = inventory_fixture();
        value["workloads"][0]["modelKeys"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(inventory_profiles(&value, source, "CPUExecutionProvider").is_err());
        let mut value = inventory_fixture();
        value["workloads"][0]["url"] = serde_json::json!("https://untrusted");
        assert!(inventory_profiles(&value, source, "CPUExecutionProvider").is_err());
        let mut value = inventory_fixture();
        value["workloads"][2] = value["workloads"][1].clone();
        assert!(inventory_profiles(&value, source, "CPUExecutionProvider").is_err());
    }
    #[tokio::test]
    async fn reconnect_retries_a_dropped_http_connection_and_requires_reauthorization() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).unwrap() > 0);
                if attempt == 1 {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                }
            }
        });
        let progress = Progress {
            user_paused: Arc::default(),
            cancelled: Arc::default(),
            status: Arc::default(),
            notify: Arc::new(|_| {}),
        };
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let client = crate::transport::client().unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            reconnect(&progress, false, |refresh| {
                let number = attempts.fetch_add(1, Ordering::AcqRel);
                assert_eq!(refresh, number != 0);
                let request = client.get(&url);
                async move {
                    request
                        .send()
                        .await
                        .map(|_| ())
                        .map_err(|_| "worker_request_interrupted".into())
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        server.join().unwrap();
        assert_eq!(attempts.load(Ordering::Acquire), 2);
    }
    #[tokio::test]
    async fn a_fenced_worker_session_is_reissued_but_a_refused_device_or_identity_is_not_retried() {
        let progress = Progress {
            user_paused: Arc::default(),
            cancelled: Arc::default(),
            status: Arc::default(),
            notify: Arc::new(|_| {}),
        };
        // The server ended the session or the policy mid-loop: issue a new session and carry on.
        for error in ["worker_session_rejected", "worker_policy_changed"] {
            let refreshes = std::sync::Mutex::new(Vec::new());
            tokio::time::timeout(
                Duration::from_secs(5),
                reconnect(&progress, false, |refresh| {
                    refreshes.lock().unwrap().push(refresh);
                    async move {
                        if refresh {
                            Ok(())
                        } else {
                            Err(error.into())
                        }
                    }
                }),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(*refreshes.lock().unwrap(), [false, true], "{error}");
        }
        // Issuing the session is what proves the device: when that is refused, nothing is retried.
        for error in [
            "server_http_401",
            "server_http_403",
            "server_identity_changed",
            "account_identity_changed",
            "worker_association_changed",
            "worker_qualification_refused",
            "runtime_signature_invalid",
            "server_model_not_supported",
        ] {
            let attempts = std::sync::atomic::AtomicUsize::new(0);
            let result = reconnect(&progress, false, |_| {
                attempts.fetch_add(1, Ordering::AcqRel);
                async { Err(error.into()) }
            })
            .await;
            assert_eq!(result.unwrap_err(), error);
            assert_eq!(attempts.load(Ordering::Acquire), 1);
        }
    }
    #[tokio::test]
    async fn stopping_reconnect_backoff_prevents_late_attempts() {
        let setup = WorkerSetup::default();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let attempts = count.clone();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        setup
            .start_work(
                Arc::new(move |value| {
                    let _ = tx.send(value);
                }),
                move |progress| async move {
                    reconnect(&progress, false, |_| {
                        attempts.fetch_add(1, Ordering::AcqRel);
                        async { Err("worker_request_interrupted".into()) }
                    })
                    .await
                },
            )
            .await;
        assert_eq!(rx.recv().await.unwrap().state, "reconnecting");
        setup.stop().await;
        assert_eq!(count.load(Ordering::Acquire), 1);
    }
    #[tokio::test]
    async fn pausing_reconnect_prevents_reauthorization_after_backoff() {
        let setup = WorkerSetup::default();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let attempts = count.clone();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        setup
            .start_work(
                Arc::new(move |value| {
                    let _ = tx.send(value);
                }),
                move |progress| async move {
                    reconnect(&progress, false, |_| {
                        attempts.fetch_add(1, Ordering::AcqRel);
                        async { Err("worker_request_interrupted".into()) }
                    })
                    .await
                },
            )
            .await;
        assert_eq!(rx.recv().await.unwrap().state, "reconnecting");
        setup.pause();
        tokio::time::sleep(Duration::from_millis(2100)).await;
        setup.stop().await;
        assert_eq!(count.load(Ordering::Acquire), 1);
    }
    #[test]
    fn wake_observation_survives_completed_futures_and_is_shared_with_the_claim_gate() {
        let clock = WakeClock::new();
        let gate = clock.clone();
        let before = *clock.0.lock().unwrap();
        assert!(!clock.observe(before + Duration::from_secs(5)));
        assert!(!gate.observe(before + Duration::from_secs(10)));
        assert!(gate.observe(before + Duration::from_secs(41)));
        assert!(!clock.observe(before + Duration::from_secs(46)));
    }
    #[test]
    fn reconnect_backoff_is_jittered_bounded_and_wake_gaps_invalidate_work() {
        for attempt in [0, 1, 4, 5, 20, u32::MAX] {
            let a = reconnect_delay(attempt, 0);
            let b = reconnect_delay(attempt, u64::MAX);
            assert!(a >= Duration::from_secs(1) && b >= Duration::from_secs(1));
            assert!(a <= Duration::from_secs(60) && b <= Duration::from_secs(60));
            assert_ne!(a, b);
        }
        let now = std::time::UNIX_EPOCH + Duration::from_secs(1000);
        assert!(!wake_gap(now, now + Duration::from_secs(5)));
        assert!(wake_gap(now, now + Duration::from_secs(31)));
        assert!(wake_gap(now, now - Duration::from_secs(1)));
    }
    #[tokio::test]
    async fn user_pause_drains_current_work_and_prevents_the_next_task() {
        let setup = WorkerSetup::default();
        let jobs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = jobs.clone();
        let (started_tx, started) = tokio::sync::oneshot::channel();
        let (finish_tx, finish) = tokio::sync::oneshot::channel();
        let (status_tx, mut status) = tokio::sync::mpsc::unbounded_channel();
        setup
            .start_work(
                Arc::new(move |value| {
                    let _ = status_tx.send(value);
                }),
                move |progress| async move {
                    progress.set("working", None);
                    started_tx.send(()).unwrap();
                    finish.await.unwrap();
                    assert!(
                        !progress.cancelled.load(Ordering::Acquire),
                        "pause must drain rather than cancel"
                    );
                    count.fetch_add(1, Ordering::AcqRel);
                    wait_for_user(&progress, || async { Ok(()) }).await?;
                    count.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
            )
            .await;
        started.await.unwrap();
        assert_eq!(status.recv().await.unwrap().state, "working");
        assert_eq!(
            setup.pause().control,
            crate::worker_control::WorkerControl::Paused
        );
        finish_tx.send(()).unwrap();
        let paused = tokio::time::timeout(Duration::from_secs(2), status.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(paused.state, "paused");
        assert_eq!(jobs.load(Ordering::Acquire), 1);
        setup
            .hold(crate::worker_control::WorkerControl::Stopped)
            .await;
        assert_eq!(setup.status().state, "stopped");
        assert_eq!(jobs.load(Ordering::Acquire), 1);
        let (resumed_tx, resumed) = tokio::sync::oneshot::channel();
        setup
            .start_work(Arc::new(|_| {}), move |progress| async move {
                wait_for_user(&progress, || async { Ok(()) }).await?;
                resumed_tx.send(()).unwrap();
                Ok(())
            })
            .await;
        tokio::time::timeout(Duration::from_secs(2), resumed)
            .await
            .unwrap()
            .unwrap();
        setup.stop().await;
    }
    #[tokio::test]
    async fn completed_acquisition_waits_for_inflight_token_rotation_checkpoint() {
        for sign_out in [false, true] {
            let cancelled = Arc::new(AtomicBool::new(false));
            let request = cancelled.clone();
            let (entered_tx, entered) = tokio::sync::oneshot::channel();
            let (work_tx, work) = tokio::sync::oneshot::channel();
            let (release_tx, release) = tokio::sync::oneshot::channel();
            let saved = Arc::new(AtomicBool::new(false));
            let checkpoint = saved.clone();
            let task = tokio::spawn(async move {
                let mut entered_tx = Some(entered_tx);
                let mut release = Some(release);
                acquisition(
                    async {
                        work.await.unwrap();
                        Ok(42)
                    },
                    false,
                    || {
                        let entered_tx = entered_tx.take().unwrap();
                        let release = release.take().unwrap();
                        let checkpoint = checkpoint.clone();
                        async move {
                            entered_tx.send(()).unwrap();
                            release.await.unwrap();
                            checkpoint.store(true, Ordering::Release);
                            Ok(())
                        }
                    },
                    std::future::pending(),
                    &cancelled,
                )
                .await
            });
            entered.await.unwrap();
            work_tx.send(()).unwrap();
            if sign_out {
                request.store(true, Ordering::Release);
            }
            tokio::task::yield_now().await;
            assert!(
                !task.is_finished(),
                "finishing a download must not discard an in-flight token rotation"
            );
            release_tx.send(()).unwrap();
            let result = task.await.unwrap();
            if sign_out {
                assert_eq!(result.unwrap_err(), "worker_setup_cancelled");
            } else {
                assert_eq!(result.unwrap(), 42);
            }
            assert!(saved.load(Ordering::Acquire));
        }
    }
    #[tokio::test]
    async fn interrupted_http_acquisition_never_publishes_partial_weights() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-acquire-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("model.onnx");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/model", listener.local_addr().unwrap());
        let (started_tx, started) = tokio::sync::oneshot::channel();
        let (stop_tx, stop) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nwei")
                .unwrap();
            started_tx.send(()).unwrap();
            let _ = stop.recv_timeout(Duration::from_secs(10));
        });
        let client = crate::transport::client().unwrap();
        let cancel = AtomicBool::new(false);
        let result = acquisition(
            crate::model_cache::acquire_file(
                &client,
                &url,
                &path,
                7,
                "0000000000000000000000000000000000000000000000000000000000000000",
                &cancel,
            ),
            false,
            || async { Ok(()) },
            async {
                started.await.unwrap();
                let samples = std::sync::atomic::AtomicUsize::new(0);
                download_network_loss(|| {
                    let unmetered = samples.fetch_add(1, Ordering::AcqRel) == 0;
                    async move { Some(unmetered) }
                })
                .await;
                assert_eq!(samples.load(Ordering::Acquire), 2);
            },
            &cancel,
        )
        .await;
        let _ = stop_tx.send(());
        server.join().unwrap();
        let files: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        std::fs::remove_dir_all(root).unwrap();
        assert_eq!(result.unwrap_err(), "model_download_permission_required");
        // FD-39: the partial is kept for a Range resume; it is never published unverified.
        assert_eq!(
            files,
            [format!(".download-{}", "0".repeat(64)).as_str()],
            "interrupted model must leave only its resumable partial"
        );
    }
    #[tokio::test]
    async fn explicit_download_permission_does_not_bypass_worker_revocation() {
        let result: Result<(), String> = acquisition(
            std::future::pending(),
            true,
            || async { Err("worker_session_revoked".into()) },
            async {},
            &AtomicBool::new(false),
        )
        .await;
        assert_eq!(result.unwrap_err(), "worker_session_revoked");
        assert_eq!(
            acquisition(
                async { Ok(42) },
                true,
                || async { Ok(()) },
                async {},
                &AtomicBool::new(false)
            )
            .await
            .unwrap(),
            42
        );
    }
    #[tokio::test]
    async fn verified_cached_weights_do_not_require_network_permission() {
        use sha2::{Digest, Sha256};
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-offline-cache-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("model.onnx");
        std::fs::write(&path, b"weights").unwrap();
        let hash = format!("{:x}", Sha256::digest(b"weights"));
        let cancel = AtomicBool::new(false);
        let client = crate::transport::client().unwrap();
        let result = acquisition(
            crate::model_cache::acquire_file(
                &client,
                "http://127.0.0.1:1",
                &path,
                7,
                &hash,
                &cancel,
            ),
            false,
            || async { Ok(()) },
            async {},
            &cancel,
        )
        .await;
        std::fs::remove_dir_all(root).unwrap();
        result.unwrap();
    }
    #[tokio::test]
    async fn automatic_download_waits_for_permission_on_unknown_or_metered_network() {
        for state in [None, Some(false)] {
            tokio::time::timeout(
                Duration::from_secs(1),
                download_network_loss(|| async { state }),
            )
            .await
            .unwrap();
        }
    }
    #[tokio::test]
    async fn interrupted_preparation_is_joined_before_returning_owned_runtime() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let cleaned = Arc::new(AtomicBool::new(false));
        let proof = cleaned.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (owned, reason) = monitored_preparation(
            move |stop| {
                tx.send(()).unwrap();
                while !stop.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                proof.store(true, Ordering::Release);
                42
            },
            async {
                rx.await.unwrap();
                "resource_on_battery".into()
            },
            || async { Ok(()) },
            &cancelled,
        )
        .await
        .unwrap();
        assert_eq!(owned, 42);
        assert_eq!(reason.as_deref(), Some("resource_on_battery"));
        assert!(cleaned.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn sign_out_joins_preparation_even_when_the_monitor_is_waiting() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let request = cancelled.clone();
        let cleaned = Arc::new(AtomicBool::new(false));
        let proof = cleaned.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let trigger = tokio::spawn(async move {
            rx.await.unwrap();
            request.store(true, Ordering::Release);
        });
        let (_, reason) = monitored_preparation(
            move |stop| {
                tx.send(()).unwrap();
                while !stop.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                proof.store(true, Ordering::Release);
            },
            std::future::pending(),
            || async { Ok(()) },
            &cancelled,
        )
        .await
        .unwrap();
        trigger.await.unwrap();
        assert_eq!(reason.as_deref(), Some("worker_setup_cancelled"));
        assert!(cleaned.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn preparation_maintenance_failure_interrupts_work() {
        assert_eq!(
            maintained::<(), _>(
                std::future::pending(),
                std::future::pending(),
                || async { Err("worker_session_revoked".into()) },
                &AtomicBool::new(false)
            )
            .await
            .unwrap_err(),
            "worker_session_revoked"
        );
    }
    #[tokio::test]
    async fn resource_refusal_prevents_work_and_remains_cancellable() {
        let setup = WorkerSetup::default();
        let touched = Arc::new(AtomicBool::new(false));
        let proof = touched.clone();
        let renewals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let renewed = renewals.clone();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        setup
            .start_work(
                Arc::new(move |status| {
                    let _ = tx.send(status);
                }),
                move |progress| async move {
                    wait_for_capacity(u64::MAX, &progress, || async {
                        renewed.fetch_add(1, Ordering::AcqRel);
                        Ok(())
                    })
                    .await?;
                    proof.store(true, Ordering::Release);
                    Ok(())
                },
            )
            .await;
        let status = tokio::time::timeout(Duration::from_secs(7), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, "paused");
        setup.stop().await;
        assert!(!touched.load(Ordering::Acquire));
        assert!(renewals.load(Ordering::Acquire) > 0);
        assert_eq!(setup.status(), SetupStatus::default());
    }
    #[tokio::test]
    async fn fresh_nested_app_directory_reports_missing_pack_without_touching_server_credentials() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-setup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let data = root.join("new-parent/app");
        let progress = Progress {
            user_paused: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(SetupStatus::default())),
            notify: Arc::new(|_| {}),
        };
        let saved = SavedConnection {
            server: "https://127.0.0.1:1".into(),
            server_id: "test".into(),
            account_id: uuid::Uuid::new_v4().to_string(),
            name: "Test".into(),
            token: "synthetic".into(),
            device_name: "Test".into(),
            mode: "client-worker".into(),
            device_id: Some(uuid::Uuid::new_v4().to_string()),
        };
        let result = prepare(
            saved,
            SetupPaths {
                data: data.clone(),
                bundle: root.join("absent"),
            },
            false,
            progress,
        )
        .await;
        let active = data.join("runtimes/active.json").exists();
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(result.unwrap_err(), "runtime_pack_unavailable");
        assert!(!active);
    }
    #[tokio::test]
    async fn sign_out_waits_for_preparation_cleanup_and_prevents_late_status() {
        let setup = WorkerSetup::default();
        let (started_tx, started) = tokio::sync::oneshot::channel();
        let cleaned = Arc::new(AtomicBool::new(false));
        let proof = cleaned.clone();
        setup
            .start_work(Arc::new(|_| {}), move |progress| async move {
                progress.set("downloading-models", None);
                started_tx.send(()).unwrap();
                while !progress.cancelled.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                proof.store(true, Ordering::Release);
                progress.set("qualified", None);
                Ok(())
            })
            .await;
        tokio::time::timeout(Duration::from_secs(2), started)
            .await
            .expect("setup did not start")
            .unwrap();
        assert_eq!(setup.status().state, "downloading-models");
        setup.stop().await;
        assert!(cleaned.load(Ordering::Acquire));
        assert_eq!(setup.status(), SetupStatus::default());
    }
    #[tokio::test]
    async fn failed_preparation_is_visible_without_claiming_processing() {
        let setup = WorkerSetup::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        setup
            .start_work(
                Arc::new(move |status| {
                    let _ = tx.send(status);
                }),
                |_| async { Err("runtime_pack_unavailable".into()) },
            )
            .await;
        let status = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, "setup-needs-attention");
        assert_eq!(status.code.as_deref(), Some("runtime_pack_unavailable"));
        setup.stop().await;
    }
    #[tokio::test]
    async fn the_no_work_recheck_waits_out_pauses_and_stops_on_cancel() {
        let progress = Progress {
            user_paused: Arc::new(AtomicBool::new(true)),
            cancelled: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(SetupStatus::default())),
            notify: Arc::new(|_| {}),
        };
        // Paused: the recheck holds past its period until resumed.
        let held = tokio::time::timeout(
            Duration::from_millis(600),
            recheck_after(&progress, Duration::ZERO),
        )
        .await;
        assert!(held.is_err());
        progress.user_paused.store(false, Ordering::Release);
        assert!(recheck_after(&progress, Duration::ZERO).await.is_ok());
        progress.cancelled.store(true, Ordering::Release);
        assert_eq!(
            recheck_after(&progress, Duration::from_secs(60)).await,
            Err("worker_setup_cancelled".into())
        );
    }
    #[test]
    fn an_updated_app_replaces_the_active_runtime_but_a_downgrade_does_not() {
        use sha2::{Digest, Sha256};
        let active = br#"{"epoch":6,"sourceRevision":"old"}"#;
        let active_sha = format!("{:x}", Sha256::digest(active));
        assert!(!bundle_supersedes(&active_sha, 6, active));
        assert!(bundle_supersedes(&active_sha, 6, br#"{"epoch":7}"#));
        // Same epoch, new bytes: activation must run so the store reports runtime_epoch_reused.
        assert!(bundle_supersedes(
            &active_sha,
            6,
            br#"{"epoch":6,"sourceRevision":"new"}"#
        ));
        assert!(!bundle_supersedes(&active_sha, 6, br#"{"epoch":5}"#));
        assert!(bundle_supersedes(&active_sha, 6, b"not json"));
    }
    #[tokio::test]
    async fn no_eligible_workloads_is_reported_as_server_configuration() {
        let setup = WorkerSetup::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        setup
            .start_work(
                Arc::new(move |status| {
                    let _ = tx.send(status);
                }),
                |_| async { Err("worker_no_eligible_workloads".into()) },
            )
            .await;
        let status = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, "no-eligible-work");
        setup.stop().await;

        // Offered work that failed to qualify here stays a retryable setup fault.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        setup
            .start_work(
                Arc::new(move |status| {
                    let _ = tx.send(status);
                }),
                |_| async { Err("worker_no_qualified_workloads".into()) },
            )
            .await;
        let status = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, "setup-needs-attention");
        setup.stop().await;
    }

    // ---- FD-38: the worker against a server that fences sessions, changes policy and refuses tasks.
    use crate::ml_transport::{
        household_tests::{Device, FakeServer},
        WorkerTransport,
    };
    use crate::native_predictor::{step_with, Step};
    use std::sync::atomic::AtomicUsize;
    type SavedSession = tokio::sync::Mutex<Option<WorkerTransport>>;

    fn quiet() -> Progress {
        Progress {
            user_paused: Arc::default(),
            cancelled: Arc::default(),
            status: Arc::default(),
            notify: Arc::new(|_| {}),
        }
    }
    /// What `prepare` does once the runtime is ready, with the local model replaced: use the saved
    /// session or issue a new one, qualify under it, then claim and work until `done`.
    async fn work(
        server: &FakeServer,
        device: &Device,
        saved: &SavedSession,
        refresh: bool,
        predicting: &dyn Fn(),
        done: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        let mut saved = saved.lock().await;
        if refresh || saved.is_none() {
            *saved = Some(server.session(device).await?);
        }
        let worker = saved.as_ref().unwrap();
        let qualification = server.qualification(worker).await;
        let (_sender, mut cancel) = tokio::sync::watch::channel(false);
        let mut failures = TaskFailures::default();
        while !done() {
            let step = step_with(worker, &[&qualification], &mut cancel, |_| async {
                predicting();
                Ok(serde_json::json!({}))
            })
            .await?;
            match step {
                Step::Completed => failures.completed(),
                Step::Dropped(code) => drop(failures.dropped(code)?),
                Step::Idle => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        Ok(())
    }
    /// The supervised worker for one device; returns its outcome and each attempt's `refresh`.
    async fn run(
        server: &FakeServer,
        device: &Device,
        saved: &SavedSession,
        fresh: bool,
        predicting: &dyn Fn(),
        done: &dyn Fn() -> bool,
    ) -> (Result<(), String>, Vec<bool>) {
        let refreshes = Mutex::new(Vec::new());
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            supervise(
                &quiet(),
                fresh,
                |refresh| {
                    refreshes.lock().unwrap().push(refresh);
                    work(server, device, saved, refresh, predicting, done)
                },
                || async { None },
                ROUTE_POLL,
            ),
        )
        .await
        .expect("the worker stalled");
        (result, refreshes.into_inner().unwrap())
    }

    #[tokio::test]
    async fn a_session_fenced_in_the_middle_of_a_task_is_reissued_and_work_continues() {
        let server = FakeServer::start();
        let device = server.enrol();
        let saved = SavedSession::default();
        server.queue(&device, 3);
        let predictions = AtomicUsize::new(0);
        let (result, refreshes) = run(
            &server,
            &device,
            &saved,
            false,
            // The administrator changes this computer's household setting during its second task.
            &|| {
                if predictions.fetch_add(1, Ordering::AcqRel) == 1 {
                    server.toggle_household(&device);
                }
            },
            &|| server.completed(&device) == 2,
        )
        .await;
        assert_eq!(result, Ok(()));
        assert_eq!(refreshes, [false, true]);
        assert_eq!(server.sessions_issued(&device), 2);
        // The fenced task's result never passed the door and no failure was reported for it.
        assert_eq!(server.reports(&device), ["result", "result"]);
    }

    #[tokio::test]
    async fn a_household_change_on_one_computer_does_not_stop_another() {
        let server = FakeServer::start();
        let (a, b) = (server.enrol(), server.enrol());
        let (saved_a, saved_b) = (SavedSession::default(), SavedSession::default());
        for (device, saved) in [(&a, &saved_a), (&b, &saved_b)] {
            server.queue(device, 1);
            let done = || server.completed(device) == 1;
            let (result, refreshes) = run(&server, device, saved, false, &|| {}, &done).await;
            assert_eq!((result, refreshes), (Ok(()), vec![false]));
        }

        // The administrator toggles A while B is in the middle of a task.
        server.queue(&b, 2);
        let predictions = AtomicUsize::new(0);
        let (result, refreshes) = run(
            &server,
            &b,
            &saved_b,
            false,
            &|| {
                if predictions.fetch_add(1, Ordering::AcqRel) == 0 {
                    server.toggle_household(&a);
                }
            },
            &|| server.completed(&b) == 2,
        )
        .await;
        // B's task lost the policy revision it ran under: the server refused that result, B
        // reported no failure for it, refreshed its authority and finished the next task.
        assert_eq!(result, Ok(()));
        assert_eq!(refreshes, [false, true]);
        assert_eq!(server.reports(&b), ["result", "result", "result"]);

        // A itself was fenced: its saved session is refused, a new one is issued and it carries on.
        server.queue(&a, 1);
        let done = || server.completed(&a) == 2;
        let (result, refreshes) = run(&server, &a, &saved_a, false, &|| {}, &done).await;
        assert_eq!((result, refreshes), (Ok(()), vec![false, true]));
        assert_eq!(server.sessions_issued(&a), 2);
    }

    #[tokio::test]
    async fn a_failed_or_refused_task_is_dropped_and_the_next_one_is_claimed() {
        let server = FakeServer::start();
        let device = server.enrol();
        let saved = SavedSession::default();
        server.queue(&device, 3);
        // The first task's input fails on the server; the second's result is refused (cancelled job).
        server.respond_next(&device, "/input", 500, serde_json::json!({}));
        server.respond_next(
            &device,
            "/result",
            200,
            serde_json::json!({"accepted":false}),
        );
        let done = || server.completed(&device) == 1;
        let (result, refreshes) = run(&server, &device, &saved, false, &|| {}, &done).await;
        assert_eq!(result, Ok(()));
        // No reconnect and no new session: the same association claimed the third task.
        assert_eq!(refreshes, [false]);
        assert_eq!(server.sessions_issued(&device), 1);
        // The held lease was failed back to the server; the refused one heard nothing more.
        assert_eq!(server.reports(&device), ["fail", "result"]);
    }

    #[tokio::test]
    async fn five_failed_tasks_in_a_row_park_the_worker_and_fewer_do_not() {
        let mut failures = TaskFailures::default();
        for _ in 0..3 {
            for _ in 0..TASK_FAILURE_LIMIT - 1 {
                let delay = failures.dropped("worker_result_refused".into()).unwrap();
                assert!(delay >= Duration::from_secs(1) && delay <= Duration::from_secs(64));
            }
            failures.completed();
        }

        let server = FakeServer::start();
        let device = server.enrol();
        let saved = SavedSession::default();
        server.queue(&device, 6);
        for _ in 0..5 {
            server.respond_next(
                &device,
                "/result",
                200,
                serde_json::json!({"accepted":false}),
            );
        }
        let (result, refreshes) = run(&server, &device, &saved, false, &|| {}, &|| false).await;
        assert_eq!(result, Err("worker_result_refused".into()));
        assert_eq!(refreshes, [false]);
        assert_eq!(server.completed(&device), 0);

        // Parked is the state Retry Setup is offered in.
        let setup = WorkerSetup::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        setup
            .start_work(
                Arc::new(move |status| {
                    let _ = tx.send(status);
                }),
                move |_| async move { result },
            )
            .await;
        let status = rx.recv().await.unwrap();
        assert_eq!(status.state, "setup-needs-attention");
        assert_eq!(status.code.as_deref(), Some("worker_result_refused"));
        setup.stop().await;
    }

    #[tokio::test]
    async fn retry_setup_after_a_fenced_session_starts_from_a_new_one() {
        let server = FakeServer::start();
        let device = server.enrol();
        let saved = SavedSession::default();
        server.queue(&device, 1);
        let done = || server.completed(&device) == 1;
        let (result, _) = run(&server, &device, &saved, false, &|| {}, &done).await;
        assert_eq!(result, Ok(()));

        // The worker parks, and the server fences its saved session while it sits there.
        let setup = WorkerSetup::default();
        assert!(!setup.parked());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        setup
            .start_work(
                Arc::new(move |status| {
                    let _ = tx.send(status);
                }),
                |_| async { Err("runtime_start_failed".into()) },
            )
            .await;
        assert_eq!(rx.recv().await.unwrap().state, "setup-needs-attention");
        assert!(setup.parked());
        server.toggle_household(&device);

        // Retry Setup, in the same process: the first attempt already asks for a new session.
        server.queue(&device, 1);
        let done = || server.completed(&device) == 2;
        let (result, refreshes) =
            run(&server, &device, &saved, setup.parked(), &|| {}, &done).await;
        assert_eq!((result, refreshes), (Ok(()), vec![true]));
        assert_eq!(server.sessions_issued(&device), 2);

        setup.stop().await;
        assert!(!setup.parked());
    }

    #[tokio::test]
    async fn a_policy_or_lan_refusal_waits_and_resumes_when_the_network_changes() {
        for (message, code) in [
            ("desktop_pool_policy_required", "worker_policy_required"),
            ("desktop_worker_lan_required", "worker_lan_required"),
        ] {
            let server = FakeServer::start();
            let device = server.enrol();
            let saved = SavedSession::default();
            server.queue(&device, 1);
            server.respond_next(
                &device,
                "/claim",
                403,
                serde_json::json!({"message":message}),
            );
            let statuses = Arc::new(Mutex::new(Vec::new()));
            let seen = statuses.clone();
            let progress = Progress {
                notify: Arc::new(move |status: SetupStatus| {
                    seen.lock().unwrap().push((status.state, status.code))
                }),
                ..quiet()
            };
            let attempts = AtomicUsize::new(0);
            let routes = AtomicUsize::new(0);
            let done = || server.completed(&device) == 1;
            // Far sooner than the five-minute timer: the route to the server changed.
            tokio::time::timeout(
                Duration::from_secs(10),
                supervise(
                    &progress,
                    false,
                    |refresh| {
                        attempts.fetch_add(1, Ordering::AcqRel);
                        work(&server, &device, &saved, refresh, &|| {}, &done)
                    },
                    || {
                        let moved = routes.fetch_add(1, Ordering::AcqRel) > 0;
                        async move { Some(std::net::IpAddr::from([192, 168, 1, 2 + moved as u8])) }
                    },
                    Duration::from_millis(20),
                ),
            )
            .await
            .expect("the worker stayed parked")
            .unwrap();
            assert_eq!(attempts.load(Ordering::Acquire), 2);
            assert_eq!(server.sessions_issued(&device), 1);
            assert_eq!(
                *statuses.lock().unwrap(),
                [("paused".to_owned(), Some(code.to_owned()))]
            );
        }
    }

    #[tokio::test]
    async fn the_refusal_wait_also_ends_on_its_timer_and_on_stop() {
        let progress = quiet();
        let home = || async { Some(std::net::IpAddr::from([192, 168, 1, 2])) };
        let poll = Duration::from_millis(20);
        let started = std::time::Instant::now();
        let period = Duration::from_millis(400);
        recheck_after_or_route_change(&progress, period, &mut { home }, poll)
            .await
            .unwrap();
        assert!(started.elapsed() >= period);
        progress.cancelled.store(true, Ordering::Release);
        assert_eq!(
            recheck_after_or_route_change(&progress, Duration::from_secs(60), &mut { home }, poll)
                .await,
            Err("worker_setup_cancelled".into())
        );
    }

    #[test]
    fn the_route_to_a_server_is_read_without_sending_anything() {
        assert_eq!(
            network_route("http://127.0.0.1:2283"),
            Some(std::net::IpAddr::from([127, 0, 0, 1]))
        );
        assert_eq!(network_route("not a server"), None);
    }
}
