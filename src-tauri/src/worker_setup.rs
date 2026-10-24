use crate::{connection::SavedConnection, model_cache::check_cancel};
use serde::Serialize;
use std::{
    future::Future,
    path::PathBuf,
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
        };
        if *current == status {
            return;
        }
        *current = status.clone();
        drop(current);
        (self.notify)(status);
    }
    fn workloads(&self, workloads: Vec<WorkloadStatus>) {
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        let mut status = self.status.lock().unwrap();
        status.workloads = workloads;
        let snapshot = status.clone();
        drop(status);
        (self.notify)(snapshot);
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
    notify: Arc<dyn Fn(SetupStatus) + Send + Sync>,
    task: tauri::async_runtime::JoinHandle<Result<(), String>>,
}
#[derive(Default)]
pub(crate) struct WorkerSetup {
    failed: Arc<AtomicBool>,
    user_paused: Arc<AtomicBool>,
    running: tokio::sync::Mutex<Option<Running>>,
    status: Arc<Mutex<SetupStatus>>,
}
impl WorkerSetup {
    pub fn check_available(&self) -> Result<(), String> {
        let _ = self.status();
        if self.failed.load(Ordering::Acquire) {
            return Err("worker_shutdown_unconfirmed".into());
        }
        Ok(())
    }
    pub fn is_active(&self) -> bool {
        self.failed.load(Ordering::Acquire)
            || self
                .running
                .try_lock()
                .map_or(true, |running| running.is_some())
    }
    pub fn status(&self) -> SetupStatus {
        if self.failed.load(Ordering::Acquire) {
            return shutdown_status();
        }
        self.status
            .lock()
            .map(|status| status.clone())
            .unwrap_or_else(|_| {
                self.failed.store(true, Ordering::Release);
                shutdown_status()
            })
    }
    pub fn pause(&self) -> Result<SetupStatus, String> {
        self.check_available()?;
        self.user_paused.store(true, Ordering::Release);
        let mut status = self.status.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            "worker_shutdown_unconfirmed"
        })?;
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
        Ok(status.clone())
    }
    pub async fn hold(
        &self,
        control: crate::worker_control::WorkerControl,
    ) -> Result<SetupStatus, String> {
        self.stop().await?;
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
            workloads: Vec::new(),
        };
        *self.status.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            "worker_shutdown_unconfirmed"
        })? = status.clone();
        Ok(status)
    }
    async fn drain(&self, running: &mut Option<Running>) -> Result<(), String> {
        if let Some(previous) = running.as_mut() {
            previous.cancel.store(true, Ordering::Release);
            let notify = previous.notify.clone();
            let result = (&mut previous.task).await;
            running.take();
            if !matches!(&result, Ok(Ok(())))
                && !matches!(&result, Ok(Err(code)) if !shutdown_uncertain(code))
                && !self.failed.swap(true, Ordering::AcqRel)
            {
                notify(shutdown_status());
            }
        }
        self.check_available()
    }
    async fn start_work<F, Fut>(
        &self,
        notify: Arc<dyn Fn(SetupStatus) + Send + Sync>,
        work: F,
    ) -> Result<(), String>
    where
        F: FnOnce(Progress) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let mut running = self.running.lock().await;
        self.drain(&mut running).await?;
        self.user_paused.store(false, Ordering::Release);
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Progress {
            user_paused: self.user_paused.clone(),
            cancelled: cancel.clone(),
            status: self.status.clone(),
            notify: notify.clone(),
        };
        let failed = self.failed.clone();
        let task = tauri::async_runtime::spawn(async move {
            let result = work(progress.clone()).await;
            if result
                .as_ref()
                .err()
                .is_some_and(|code| shutdown_uncertain(code))
            {
                failed.store(true, Ordering::Release);
                (progress.notify)(shutdown_status());
                return result;
            }
            match &result {
                Ok(()) => progress.set("qualified", None),
                Err(code) => {
                    let state = if code == "model_download_permission_required" {
                        "model-download-required"
                    } else {
                        "setup-needs-attention"
                    };
                    let safe = if code.len() <= 128
                        && code
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    {
                        code.clone()
                    } else {
                        "worker_setup_failed".into()
                    };
                    progress.set(state, Some(safe));
                }
            }
            result
        });
        *running = Some(Running {
            cancel,
            task,
            notify,
        });
        Ok(())
    }
    pub async fn stop(&self) -> Result<(), String> {
        let mut running = self.running.lock().await;
        self.drain(&mut running).await?;
        *self.status.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            "worker_shutdown_unconfirmed"
        })? = SetupStatus::default();
        Ok(())
    }
    pub async fn start(
        &self,
        saved: SavedConnection,
        paths: SetupPaths,
        allow_download: bool,
        notify: Arc<dyn Fn(SetupStatus) + Send + Sync>,
    ) -> Result<(), String> {
        self.start_work(notify, move |progress| async move {
            reconnect(&progress, |refresh| {
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
            })
            .await
        })
        .await
    }
}
fn shutdown_uncertain(code: &str) -> bool {
    matches!(
        code,
        "worker_shutdown_unconfirmed"
            | "runtime_process_shutdown_unconfirmed"
            | "runtime_process_status_failed"
            | "runtime_process_stop_failed"
    )
}
fn shutdown_status() -> SetupStatus {
    SetupStatus {
        state: "setup-needs-attention".into(),
        code: Some("worker_shutdown_unconfirmed".into()),
        ..SetupStatus::default()
    }
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
    mut attempt: F,
) -> Result<(), String> {
    let mut retries = 0u32;
    let mut refresh = false;
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
async fn resource_loss(required_memory: u64, clock: &WakeClock) -> String {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        if clock.observe(std::time::SystemTime::now()) {
            return "system_resumed".into();
        }
        match tauri::async_runtime::spawn_blocking(crate::resource_policy::sample).await {
            Ok(status) => {
                if let Some(reason) = status.refusal(required_memory) {
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
                .map_err(|_| "worker_shutdown_unconfirmed".into())
        }
        Err(reason) => Some(reason),
    };
    stop.store(true, Ordering::Release);
    // Dropping a blocking task leaves it running; join before resuming or signing out.
    let value = task.await.map_err(|_| "worker_shutdown_unconfirmed")?;
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

async fn prepare(
    saved: SavedConnection,
    paths: SetupPaths,
    allow_download: bool,
    progress: Progress,
) -> Result<(), String> {
    use crate::{
        ml_transport::WorkerTransport,
        release_policy::open_runtime_store,
        runtime_store::{private_directory, read_bounded},
        transport,
    };
    progress.set("preparing-runtime", None);
    let cancelled = progress.cancelled.clone();
    let data = paths.data.clone();
    let (mut installed, attestation) = tauri::async_runtime::spawn_blocking(move || {
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
        if !paths.bundle.exists()
            && matches!(std::fs::symlink_metadata(data.join("runtimes/active.json")), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            return Err("runtime_pack_unavailable".into());
        }
        let store = open_runtime_store(&data.join("runtimes"))?;
        let installed = match store.load_active()? {
            Some(value) => value,
            None => {
                if !paths.bundle.exists() {
                    return Err("runtime_pack_unavailable".into());
                }
                let manifest = read_bounded(&paths.bundle.join("manifest.json"), 8 * 1024 * 1024)?;
                let signature: [u8; 64] = read_bounded(&paths.bundle.join("manifest.sig"), 64)?
                    .try_into()
                    .map_err(|_| "runtime_signature_invalid")?;
                store.install_and_activate(&paths.bundle.join("payload"), &manifest, &signature)?;
                store.load_active()?.ok_or("runtime_activation_failed")?
            }
        };
        check_cancel(&cancelled)?;
        let attestation = store.attestation(&installed)?;
        Ok::<_, String>((installed, attestation))
    })
    .await
    .map_err(|_| "worker_shutdown_unconfirmed")??;
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
    let profiles: Vec<_> = groups.iter().flatten().cloned().collect();
    if paths.data.file_name().and_then(|name| name.to_str()) != Some("worker") {
        return Err("source_input_budget_invalid".into());
    }
    let input_base = paths
        .data
        .parent()
        .ok_or("source_input_budget_invalid")?
        .to_path_buf();
    let input_identity = crate::credentials::identity()?;
    let input_bindings = profiles.len();
    let inputs = tauri::async_runtime::spawn_blocking(move || {
        crate::private_inputs::WorkerInputs::acquire(&input_base, input_identity, input_bindings)
    })
    .await
    .map_err(|_| "worker_shutdown_unconfirmed")??;
    let outcome = async {
    let network = tauri::async_runtime::spawn_blocking(crate::resource_policy::sample)
        .await
        .map_err(|_| "resource_status_unavailable")?;
    let explicit_permission = allow_download;
    let allow_download = explicit_permission || network.unmetered == Some(true);
    progress.set("preparing-models", None);
    // Complete acquisition before requesting short-lived nonces.
    let mut caches = Vec::new();
    for profile in &profiles {
        wait_for_user(&progress, || worker.maintain_session()).await?;
        let cache = acquisition(
            profile.prepare_cache(
                &paths.data.join("models"),
                &client,
                &progress.cancelled,
                allow_download,
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
    'qualification: loop {
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
                inputs.check()?;
                let challenge = match cancellable(
                    worker.request_qualification(
                        profile,
                        &attestation,
                        &uuid::Uuid::new_v4().to_string(),
                    ),
                    &progress.cancelled,
                )
                .await
                {
                    Ok(value) => value,
                    Err(code) if code.starts_with("workload_desktop_") => {
                        progress.workload(workload, "unavailable", Some(code));
                        continue 'workload;
                    }
                    Err(code) => return Err(code),
                };
                let spec = challenge.specification().to_vec();
                let fixture = challenge.fixture().to_vec();
                let scratch = paths.data.join("scratch");
                let clock = WakeClock::new();
                let ((runtime, qualified), interrupted) = monitored_preparation(
                    move |cancel| {
                        let qualified =
                            installed.qualify(&cache, &scratch, &spec, &fixture, &cancel);
                        (installed, qualified)
                    },
                    async {
                        format!(
                            "resource_{}",
                            resource_loss(profile.minimum_memory(), &clock).await
                        )
                    },
                    || worker.maintain_session(),
                    &progress.cancelled,
                )
                .await?;
                installed = runtime;
                if let Err(code) = &qualified {
                    if shutdown_uncertain(code) {
                        return Err(code.clone());
                    }
                }
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
                        progress.workload(
                            workload,
                            "unavailable",
                            Some("worker_qualification_refused".into()),
                        );
                        continue 'workload;
                    }
                    Err(code) if code.starts_with("workload_desktop_") => {
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
            return Err("worker_no_eligible_workloads".into());
        }
        let mut memory_by_cache = std::collections::BTreeMap::new();
        for (profile, cache) in accepted_profiles.iter().zip(&accepted_caches) {
            let memory = memory_by_cache.entry(cache).or_insert(0u64);
            *memory = (*memory).max(profile.minimum_memory());
        }
        let required_memory = memory_by_cache.values().sum();
        let reports: Vec<_> = prepared.iter().map(|(proof, _)| proof.report()).collect();
        let memory = crate::memory_admission::envelope(required_memory, &reports)?;
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
        .map_err(|_| "worker_shutdown_unconfirmed")??;
        loop {
            wait_for_capacity(memory.startup, &progress, || worker.maintain_session()).await?;
            let now = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
            if prepared
                .iter()
                .any(|(proof, accepted)| accepted.validate_runtime(proof, now + 60_000).is_err())
            {
                continue 'qualification;
            }
            progress.set("starting-worker", None);
            inputs.check()?;
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
                    let predictor = crate::native_predictor::NativePredictor::start_many(
                        &installed, &bindings, &cache, &scratch, port,
                    )?;
                    Ok::<_, String>((installed, prepared, predictor))
                })
                .await
                .map_err(|_| "worker_shutdown_unconfirmed")??;
            installed = runtime;
            prepared = proofs;
            let restart = async {
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
                    progress.set("paused", Some("system_resumed".into()));
                    return Ok::<bool, String>(true);
                }
                if progress.user_paused.load(Ordering::Acquire) {
                    progress.set("paused", Some("user_paused".into()));
                    return Ok(false);
                }
                if let Some(reason) = resources.refusal(memory.running) {
                    // Release model memory before waiting, otherwise the warm process can prevent recovery.
                    progress.set("paused", Some(reason.into()));
                    return Ok(false);
                }
                let now =
                    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
                if prepared.iter().any(|(proof, accepted)| {
                    accepted.validate_runtime(proof, now + 60_000).is_err()
                }) {
                    return Ok::<bool, String>(true);
                }
                let accepted: Vec<_> = prepared.iter().map(|(_, accepted)| accepted).collect();
                let completed = cancellable(async {
                    tokio::select! {
                        biased;
                        reason = resource_loss(memory.running, &clock) => Err(format!("resource_{reason}")),
                        result = async {
                            inputs.check()?;
                            predictor.prepare(&worker, &mut cancel).await?;
                            progress.set("working", None);
                            predictor.execute_next_many(&worker, &accepted, &mut cancel).await
                        } => result,
                    }
                }, &progress.cancelled).await;
                match completed {
                    Ok(true) => {}
                    Ok(false) => {
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
                            progress.set("paused", Some(reason[9..].into()));
                        if reason == "resource_system_resumed" {
                            return Ok::<bool, String>(true);
                        }
                        return Ok(false);
                    }
                    Err(reason) => return Err(reason),
                }
            }
            }.await;
            predictor.stop()?;
            if restart? {
                continue 'qualification;
            }
        }
    }
    }.await;
    if outcome
        .as_ref()
        .err()
        .is_some_and(|code| shutdown_uncertain(code))
    {
        return outcome;
    }
    tauri::async_runtime::spawn_blocking(move || inputs.finish())
        .await
        .map_err(|_| "worker_shutdown_unconfirmed")??;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
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
        let catalogue: serde_json::Value =
            serde_json::from_str(include_str!("../../runtime/model-catalogue.json")).unwrap();
        let workloads = ["clip", "ocr", "face", "enrichment"].map(|workload| {
            let profiles: Vec<_> = catalogue["profiles"].as_array().unwrap().iter().filter(|p|
                p["workload"] == workload && p["spec"]["provider"] == "CPUExecutionProvider" &&
                p["runtimeSourceRevision"] == "25b22c16e47a27a2eb50017d838497abce850d11").collect();
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
            reconnect(&progress, |refresh| {
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
    async fn authorization_identity_and_binding_failures_are_not_retried() {
        let progress = Progress {
            user_paused: Arc::default(),
            cancelled: Arc::default(),
            status: Arc::default(),
            notify: Arc::new(|_| {}),
        };
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
            let result = reconnect(&progress, |_| {
                attempts.fetch_add(1, Ordering::AcqRel);
                async { Err(error.into()) }
            })
            .await;
            assert_eq!(result.unwrap_err(), error);
            assert_eq!(attempts.load(Ordering::Acquire), 1);
        }
    }
    #[tokio::test]
    async fn uncertain_helper_shutdown_blocks_replacement_and_keeps_attention_status() {
        for code in [
            "runtime_process_shutdown_unconfirmed",
            "runtime_process_status_failed",
        ] {
            let setup = WorkerSetup::default();
            let _ = setup
                .start_work(Arc::new(|_| {}), move |_| async move { Err(code.into()) })
                .await;
            assert_eq!(
                setup.stop().await.unwrap_err(),
                "worker_shutdown_unconfirmed"
            );
            assert!(setup.is_active());
            assert!(setup.pause().is_err());
            assert_eq!(
                setup.status().code.as_deref(),
                Some("worker_shutdown_unconfirmed")
            );
            let started = Arc::new(AtomicBool::new(false));
            let seen = started.clone();
            let _ = setup
                .start_work(Arc::new(|_| {}), move |_| async move {
                    seen.store(true, Ordering::Release);
                    Ok(())
                })
                .await;
            tokio::task::yield_now().await;
            assert!(!started.load(Ordering::Acquire));
            let _ = setup
                .hold(crate::worker_control::WorkerControl::Paused)
                .await;
            assert_eq!(
                setup.status().code.as_deref(),
                Some("worker_shutdown_unconfirmed")
            );
        }
    }
    #[tokio::test]
    async fn panicked_helper_shutdown_is_not_reported_as_stopped() {
        let setup = WorkerSetup::default();
        let _ = setup
            .start_work(Arc::new(|_| {}), |_| async {
                panic!("synthetic helper failure")
            })
            .await;
        assert_eq!(
            setup.stop().await.unwrap_err(),
            "worker_shutdown_unconfirmed"
        );
        assert!(setup.is_active());
        assert_eq!(
            setup.status().code.as_deref(),
            Some("worker_shutdown_unconfirmed")
        );
    }
    #[tokio::test]
    async fn panicked_preparation_preserves_shutdown_uncertainty() {
        let result: Result<((), Option<String>), String> = monitored_preparation(
            |_| panic!("synthetic preparation failure"),
            std::future::pending(),
            || async { Ok(()) },
            &AtomicBool::new(false),
        )
        .await;
        assert_eq!(result.unwrap_err(), "worker_shutdown_unconfirmed");
    }
    #[tokio::test]
    async fn cancelled_helper_drain_keeps_ownership_for_stop_and_replacement() {
        for replacement in [false, true] {
            let setup = WorkerSetup::default();
            let (observed, stopping) = tokio::sync::oneshot::channel();
            let (finish, wait) = tokio::sync::oneshot::channel();
            setup
                .start_work(Arc::new(|_| {}), move |progress| async move {
                    while !progress.cancelled.load(Ordering::Acquire) {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    let _ = observed.send(());
                    let _ = wait.await;
                    Ok(())
                })
                .await
                .unwrap();
            let replaced = Arc::new(AtomicBool::new(false));
            let proof = replaced.clone();
            let mut drain: std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + '_>> =
                if replacement {
                    Box::pin(setup.start_work(Arc::new(|_| {}), move |_| async move {
                        proof.store(true, Ordering::Release);
                        Ok(())
                    }))
                } else {
                    Box::pin(setup.stop())
                };
            tokio::select! {
                _ = &mut drain => panic!("drain returned before the worker finished"),
                result = stopping => result.unwrap(),
            }
            drop(drain);
            assert!(setup.running.lock().await.is_some());
            assert!(!replaced.load(Ordering::Acquire));
            let mut stop = Box::pin(setup.stop());
            assert!(tokio::time::timeout(Duration::from_millis(10), &mut stop)
                .await
                .is_err());
            finish.send(()).unwrap();
            stop.await.unwrap();
            assert!(setup.running.lock().await.is_none());
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
                    reconnect(&progress, |_| {
                        attempts.fetch_add(1, Ordering::AcqRel);
                        async { Err("worker_request_interrupted".into()) }
                    })
                    .await
                },
            )
            .await
            .unwrap();
        assert_eq!(rx.recv().await.unwrap().state, "reconnecting");
        setup.stop().await.unwrap();
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
                    reconnect(&progress, |_| {
                        attempts.fetch_add(1, Ordering::AcqRel);
                        async { Err("worker_request_interrupted".into()) }
                    })
                    .await
                },
            )
            .await
            .unwrap();
        assert_eq!(rx.recv().await.unwrap().state, "reconnecting");
        setup.pause().unwrap();
        tokio::time::sleep(Duration::from_millis(2100)).await;
        setup.stop().await.unwrap();
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
            .await
            .unwrap();
        started.await.unwrap();
        assert_eq!(status.recv().await.unwrap().state, "working");
        assert_eq!(
            setup.pause().unwrap().control,
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
            .await
            .unwrap();
        assert_eq!(setup.status().state, "stopped");
        assert_eq!(jobs.load(Ordering::Acquire), 1);
        let (resumed_tx, resumed) = tokio::sync::oneshot::channel();
        setup
            .start_work(Arc::new(|_| {}), move |progress| async move {
                wait_for_user(&progress, || async { Ok(()) }).await?;
                resumed_tx.send(()).unwrap();
                Ok(())
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), resumed)
            .await
            .unwrap()
            .unwrap();
        setup.stop().await.unwrap();
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
    async fn interrupted_http_acquisition_removes_partial_weights() {
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
        let files = std::fs::read_dir(&root).unwrap().count();
        std::fs::remove_dir_all(root).unwrap();
        assert_eq!(result.unwrap_err(), "model_download_permission_required");
        assert_eq!(
            files, 0,
            "interrupted model must not leave partial or published weights"
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
            .await
            .unwrap();
        let status = tokio::time::timeout(Duration::from_secs(7), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, "paused");
        setup.stop().await.unwrap();
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
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), started)
            .await
            .expect("setup did not start")
            .unwrap();
        assert_eq!(setup.status().state, "downloading-models");
        setup.stop().await.unwrap();
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
            .await
            .unwrap();
        let status = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, "setup-needs-attention");
        assert_eq!(status.code.as_deref(), Some("runtime_pack_unavailable"));
        setup.stop().await.unwrap();
    }
}
