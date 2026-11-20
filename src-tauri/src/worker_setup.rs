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
    /// What the AI runtime process said when it last ended by itself: its exit status and the
    /// last lines of its error output. Shown under the stop reason; cleared by a finished task.
    pub detail: Option<String>,
    /// How many tasks this computer runs at once, when the server lets it hold several.
    pub concurrent_tasks: u32,
    /// The most this computer runs at once since it ran short of memory doing more. Kept for
    /// as long as AI processing runs, across restarts of its setup.
    #[serde(skip)]
    pub(crate) capacity_ceiling: Option<u32>,
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
            detail: current.detail.clone(),
            concurrent_tasks: current.concurrent_tasks,
            capacity_ceiling: current.capacity_ceiling,
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
        self.update(|status| {
            status.completed_tasks += 1;
            status.detail = None;
        });
    }
    /// Keep, and log, why the runtime process ended.
    fn crashed(&self, report: Option<String>) {
        let Some(report) = report else { return };
        eprintln!("worker_runtime_exited: {report}");
        self.update(|status| status.detail = Some(report));
    }
    fn capacity_ceiling(&self) -> Option<u32> {
        self.status.lock().unwrap().capacity_ceiling
    }
    /// Run no more than this many tasks at once from now on.
    fn lower_capacity(&self, ceiling: u32) {
        self.update(|status| {
            let ceiling = ceiling.max(1);
            status.capacity_ceiling =
                Some(status.capacity_ceiling.map_or(ceiling, |c| c.min(ceiling)));
            status.concurrent_tasks = status.concurrent_tasks.min(ceiling);
        });
    }
    /// One more at once than it last ran short at, after a long run of tasks without trouble.
    fn raise_capacity(&self) {
        self.update(|status| {
            status.capacity_ceiling = status.capacity_ceiling.map(|ceiling| ceiling + 1);
        });
    }
    fn running_at_once(&self, tasks: u32) {
        self.update(|status| status.concurrent_tasks = tasks);
    }
    fn completed_tasks(&self) -> u64 {
        self.status.lock().unwrap().completed_tasks
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
    /// A download that starts over reports its verified files again: take the first count back.
    fn uncredit(&self, bytes: u64) {
        self.update(|status| {
            if let Some(models) = &mut status.models {
                models.verified_bytes = models.verified_bytes.saturating_sub(bytes);
                models.download = None;
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
    /// A worker task is running and has not given up: it keeps its own session current.
    pub(crate) async fn running(&self) -> bool {
        !self.parked()
            && self
                .running
                .lock()
                .await
                .as_ref()
                .is_some_and(|running| !running.task.inner().is_finished())
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
                        "worker_no_eligible_workloads" | "server_update_required" => {
                            "no-eligible-work"
                        }
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
        if fresh {
            // FD-64: Retry Setup also tries a GPU provider that was remembered as failed.
            crate::provider_selection::forget(&paths.data);
        }
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
                        // No session saved: the connection check could not get one (AI
                        // processing off, away from home, server busy). Ask here, where a
                        // refusal is named, waited out and asked again.
                        if refresh || !session_saved(&saved) {
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

fn session_saved(saved: &SavedConnection) -> bool {
    matches!(
        crate::credentials::load::<crate::worker::SavedWorker>("worker-session"),
        Ok(Some(worker)) if worker.server_id == saved.server_id
            && worker.account_id == saved.account_id
            && Some(&worker.device_id) == saved.device_id.as_ref()
    )
}

const NO_WORK_RECHECK: Duration = Duration::from_secs(5 * 60);
/// How often a working computer asks the server which models its tasks use now.
const MODEL_RECHECK: Duration = Duration::from_secs(5 * 60);
/// How long until a task the server refused here (not the model: the library's index, say) is
/// offered again. While an administrator's change of the search model is still being applied
/// on the server the wait is short; a library built with another model is a long one.
fn refused_task_retry(code: &str) -> Duration {
    let code = code.strip_prefix("workload_").unwrap_or(code);
    if code == "desktop_qualification_hold" {
        // The server's hold lasts five minutes.
        return Duration::from_secs(5 * 60 + 30);
    }
    Duration::from_secs(
        if matches!(
            code,
            "desktop_clip_index_changed" | "desktop_clip_index_dimensions"
        ) {
            2 * 60
        } else {
            30 * 60
        },
    )
}
/// A refusal by the server of one task, as `first_failure` reports it when every task was
/// refused (the `workload_` taken off). This app's own `desktop_…` codes (an unsupported
/// protocol, a missing enrolment) are not among them and stop the worker with their own words.
fn server_task_refusal(code: &str) -> bool {
    code.starts_with("desktop_clip_")
        || code.starts_with("desktop_model_profile_")
        || matches!(
            code,
            "desktop_pool_model_unavailable"
                | "desktop_face_profile_unavailable"
                | "desktop_qualification_hold"
        )
}
/// A refusal the processor would meet just the same (the model is held back, the library's
/// index is another model's): the task waits where it is, on the provider it had.
fn provider_independent(code: &str) -> bool {
    let code = code.strip_prefix("workload_").unwrap_or(code);
    // Not a profile the server lacks for this provider: the processor's may exist.
    code == "desktop_qualification_hold"
        || code.starts_with("desktop_clip_index_")
        || code == "desktop_clip_space_unavailable"
}
/// How many tasks of each kind the server lets one computer run at once (`concurrency` in the
/// `/models` reply, from the administrator's Jobs setting). One where the reply does not say.
fn inventory_concurrency(inventory: &serde_json::Value) -> std::collections::BTreeMap<String, u32> {
    inventory["workloads"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let limit = entry["concurrency"].as_u64().unwrap_or(1).clamp(1, 64) as u32;
            Some((entry["workload"].as_str()?.to_owned(), limit))
        })
        .collect()
}
/// How many tasks this computer can work on at once, whatever the server would allow.
///
/// - Memory: beside the loaded models (`model_memory`), each task in hand needs working memory
///   of its own, taken as a quarter of the models' and at least 256 MB. What is free now, less
///   the models, says how many fit. Unknown free memory is one task.
/// - The device: a graphics card or neural engine works on several inputs at once, up to
///   eight here. The processor already gives each task four threads, so one task, or two on a
///   computer with eight cores or more.
///
/// It is a starting point, not a promise: a graphics card's own memory is not something this
/// app can read, so running short while working lowers it (`Progress::lower_capacity`).
fn local_capacity(
    accelerated: bool,
    cores: usize,
    available_memory: Option<u64>,
    model_memory: u64,
) -> u32 {
    let per_task = (model_memory / 4).max(256 * 1024 * 1024);
    let by_memory = available_memory.map_or(1, |free| free.saturating_sub(model_memory) / per_task);
    let by_device = if accelerated {
        8
    } else {
        (cores / 4).clamp(1, 2) as u64
    };
    by_memory.clamp(1, by_device) as u32
}
/// How many tasks to run at once: what the server allows for the tasks that are ready, what
/// this computer can take, and no more than it managed since it last ran short of memory.
fn concurrent_tasks(
    limits: &std::collections::BTreeMap<String, u32>,
    ready: &std::collections::BTreeSet<String>,
    local: u32,
    ceiling: Option<u32>,
) -> u32 {
    let allowed: u32 = ready
        .iter()
        .map(|workload| limits.get(workload).copied().unwrap_or(1))
        .sum();
    allowed.min(local).min(ceiling.unwrap_or(u32::MAX)).max(1)
}
/// What a runtime that ended or stopped answering means for how the work goes on.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum AfterCrash {
    /// Several tasks were in hand: most likely memory. This many at once, on the same runtime.
    Fewer(u32),
    /// One task in hand on a graphics card or neural engine: the same runtime again, after a
    /// wait that grows with each crash in a row.
    Again(u32),
    /// The runtime itself is failing: the processor takes its work, or the crash is counted.
    Failing,
}
/// A graphics card or neural engine keeps its work until its runtime has ended this many times
/// in a row with one task in hand and no task finished in between (owner decision: one crash
/// at a single task never moves the work to the processor).
const CRASHES_AT_ONE: u32 = 3;
/// This many tasks finished in a row, with none refused and no crash, lets one more run at
/// once again after a step down.
const CLEAN_RUN: u32 = 50;
/// The processor's own runtime, at one task at a time after stepping down, is started once
/// more before it is treated as failing (as it always was).
const PROCESSOR_CRASHES_AT_ONE: u32 = 2;
/// How the runtime has fared since AI processing started, for how many tasks to run at once
/// and whether a graphics card keeps the work.
#[derive(Default)]
struct RuntimeTrouble {
    at_one: u32,
    processor_at_one: u32,
    clean: u32,
    clean_accelerated: u32,
}
impl RuntimeTrouble {
    /// `in_hand`: the tasks the runtime was working on when it ended. `accelerated`: the
    /// runtime that ended is the graphics card's or neural engine's, and how it ended counts
    /// as a crash (with nothing in hand: its process was found gone, not merely slow to
    /// start). `stepped_down`: fewer tasks are already run at once than this computer was
    /// first taken to manage. The processor's own runtime has no other device to fall back
    /// to: beyond the one more go after a step down, its crashes are counted across restarts
    /// of the setup (`CRASH_LIMIT`), as they always were.
    fn crashed(&mut self, in_hand: u32, accelerated: bool, stepped_down: bool) -> AfterCrash {
        self.clean = 0;
        // The processor's runtime crashing says nothing about the graphics card's recovery.
        if accelerated {
            self.clean_accelerated = 0;
        }
        match in_hand {
            // With its one task, or found gone between tasks: the graphics card keeps the
            // work until the third in a row.
            0 | 1 if accelerated => {
                self.at_one += 1;
                match self.at_one < CRASHES_AT_ONE {
                    true => AfterCrash::Again(self.at_one),
                    false => {
                        self.at_one = 0;
                        AfterCrash::Failing
                    }
                }
            }
            // It did not start: never a matter of memory.
            0 => AfterCrash::Failing,
            1 if stepped_down => {
                self.processor_at_one += 1;
                match self.processor_at_one < PROCESSOR_CRASHES_AT_ONE {
                    true => AfterCrash::Again(self.processor_at_one),
                    false => AfterCrash::Failing,
                }
            }
            1 => AfterCrash::Failing,
            several => AfterCrash::Fewer(several / 2),
        }
    }
    /// A task was dropped; `accelerated`: on the graphics card's or neural engine's runtime.
    /// The run of finished tasks starts again.
    fn refused(&mut self, accelerated: bool) {
        self.clean = 0;
        if accelerated {
            self.clean_accelerated = 0;
        }
    }
    /// A task finished; `accelerated`: on the graphics card's or neural engine's runtime.
    /// First `true` after a long run of tasks without trouble: one more may run at once.
    /// Second `true` after as long a run on the accelerated runtime: it has recovered from
    /// its crashes. Only its own tasks say so, and only they end a row of its crashes: the
    /// processor finishing other work beside it says nothing about the graphics card.
    fn completed(&mut self, accelerated: bool) -> (bool, bool) {
        self.clean += 1;
        let raise = self.clean >= CLEAN_RUN;
        if raise {
            self.clean = 0;
        }
        match accelerated {
            true => {
                self.at_one = 0;
                self.clean_accelerated += 1;
            }
            false => self.processor_at_one = 0,
        }
        let recovered = self.clean_accelerated >= CLEAN_RUN;
        if recovered {
            self.clean_accelerated = 0;
        }
        (raise, recovered)
    }
}
/// The reason work leaves the accelerated runtime. Its process died under a task that was
/// dropped for a reason of its own (a deadline, say), for the third time in a row: that is
/// the runtime crashing out, so it rests and is tried again later, and the tray and the AI
/// page say so. A task handed back or short of memory keeps its own reason.
/// What follows a pool that ended by itself.
#[derive(Debug, PartialEq)]
pub(crate) enum AfterPool {
    /// The accelerated runtime crashed out: its work has moved to the processor and it rests.
    CrashedOut,
    /// The server may have withdrawn a model: qualify again.
    Requalify,
    Carry,
}
/// The crash-out is decided before qualifying again, which the same failures can ask for at
/// the same moment: otherwise the runtime would neither fall back nor rest. `lane`: the
/// runtime whose process ended.
pub(crate) fn after_pool(
    plan: &mut crate::provider_selection::Plan,
    crash: Option<AfterCrash>,
    dropped: Option<&str>,
    lane: Option<&str>,
    requalify: bool,
) -> AfterPool {
    if let (Some(AfterCrash::Failing), Some(code), Some(lane)) = (crash, dropped, lane) {
        if plan.demote_runtime(lane, &crashed_out(crash, code.to_owned())) {
            return AfterPool::CrashedOut;
        }
    }
    match requalify {
        true => AfterPool::Requalify,
        false => AfterPool::Carry,
    }
}
fn crashed_out(crash: Option<AfterCrash>, code: String) -> String {
    let own = code.ends_with("_cancelled")
        || code.starts_with("resource_")
        || crate::provider_selection::crashed(&code);
    match crash {
        Some(AfterCrash::Failing) if !own => "runtime_process_stopped".into(),
        _ => code,
    }
}
/// The tasks in hand, counted as the pool claims and settles them. A task that ends the pool
/// with its failure is never settled and stays counted: after a crash this is how many the
/// runtime was working on.
#[derive(Default)]
struct InHand(std::sync::atomic::AtomicU32);
impl InHand {
    fn claimed(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
    fn settled(&self, task: &crate::native_predictor::TaskStep) {
        if task.model.is_some() {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }
    fn count(&self) -> u32 {
        self.0.load(Ordering::Acquire)
    }
}
/// The pool ended because the runtime ended or stopped answering: what comes next, with the
/// number to run at once already lowered when it was a matter of memory.
fn after_crash(
    trouble: &mut RuntimeTrouble,
    progress: &Progress,
    in_hand: u32,
    accelerated: bool,
) -> AfterCrash {
    let stepped_down = progress.capacity_ceiling().is_some();
    let after = trouble.crashed(in_hand, accelerated, stepped_down);
    if let AfterCrash::Fewer(fewer) = after {
        progress.lower_capacity(fewer);
    }
    after
}
/// What a pool that has ended says about the runtime, if it was the runtime that ended.
/// `completed`: how the pool ended. `dropped`: the code of a task dropped in it. `in_hand`:
/// the tasks the runtime was working on. `lane`: the runtime whose process is gone
/// (`NativePredictor::failed_lane`).
fn judge(
    trouble: &mut RuntimeTrouble,
    progress: &Progress,
    plan: &crate::provider_selection::Plan,
    completed: &Result<(), String>,
    dropped: Option<&str>,
    in_hand: u32,
    lane: Option<&str>,
) -> Option<AfterCrash> {
    // The graphics card's or neural engine's own runtime is the one that ended.
    let accelerated = lane.is_some_and(|lane| plan.accelerates(lane));
    match completed {
        // With nothing in hand only a process found gone is its crash: one that did not
        // answer in time has not started, which is handled as it always was.
        Err(reason) if runtime_crash(reason) => {
            let counts = in_hand > 0 || crate::provider_selection::crashed(reason);
            Some(after_crash(
                trouble,
                progress,
                in_hand,
                accelerated && counts,
            ))
        }
        // Its process died under a task that was dropped for a reason of its own.
        Ok(()) if dropped.is_some() && accelerated => Some(after_crash(trouble, progress, 1, true)),
        _ => None,
    }
}
/// The server withdraws a model from this computer after this many failed tasks in a row
/// (`native_predictor::counts_against_grant`) and then leases it nothing for that model.
const GRANT_STRIKES: u32 = 3;
/// The server's count, kept the way the server keeps it: for each model, the failed tasks in a
/// row since that model's last result.
#[derive(Default)]
struct GrantStrikes(std::collections::BTreeMap<String, u32>);
impl GrantStrikes {
    fn completed(&mut self, model: Option<&str>) {
        if let Some(model) = model {
            self.0.remove(model);
        }
    }
    /// Whether the server has now withdrawn this model, so it must be qualified again.
    fn failed(&mut self, model: Option<&str>, code: &str) -> bool {
        let Some(model) = model else { return false };
        if !crate::native_predictor::counts_against_grant(code) {
            return false;
        }
        let strikes = self.0.entry(model.to_owned()).or_default();
        *strikes += 1;
        if *strikes < GRANT_STRIKES {
            return false;
        }
        self.0.remove(model);
        true
    }
}
/// How many times a challenge the server refuses the same way every time is asked for again.
const CHALLENGE_REJECTED_LIMIT: u32 = 3;
/// How long a stop waits for the held lease to be handed back to the server.
const LEASE_RETURN: Duration = Duration::from_secs(3);
/// How long quitting the app waits for the worker to stop and hand its lease back.
pub(crate) const QUIT_GRACE: Duration = Duration::from_secs(11);
/// The AI runtime ending by itself this many times in a row, with no task finished in between,
/// stops the worker with `runtime_crash_loop`.
const CRASH_LIMIT: u32 = 3;
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
            // The server refused every task for a reason of its own (`first_failure` took the
            // `workload_` off): nothing here is broken. Wait and offer again.
            Err(code) if server_task_refusal(&code) => {
                let wait = refused_task_retry(&code);
                progress.set("paused", Some(code));
                recheck_after(progress, wait).await?;
            }
            // The server refused this computer's timestamp. Each attempt reads the server's
            // clock again (`Capabilities::clock_skew_ms`), and the person may correct theirs.
            Err(code) if code == "clock_invalid" => {
                progress.set("paused", Some(code));
                recheck_after(progress, POLICY_RECHECK).await?;
            }
            // An administrator can assign work, or update the server, at any time: ask again later.
            Err(code)
                if matches!(
                    code.as_str(),
                    "worker_no_eligible_workloads" | "server_update_required"
                ) =>
            {
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
    let started = tokio::time::Instant::now();
    let initial = route().await;
    let mut polled = tokio::time::Instant::now();
    while started.elapsed() < period || progress.user_paused.load(Ordering::Acquire) {
        check_cancel(&progress.cancelled)?;
        tokio::time::sleep(Duration::from_millis(250).min(poll)).await;
        if polled.elapsed() >= poll && !progress.user_paused.load(Ordering::Acquire) {
            polled = tokio::time::Instant::now();
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
    pub app_version: String,
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
/// The wait before a runtime that crashed is started again on the same device: longer with
/// each crash in a row. A stop ends the wait.
async fn restart_wait(crashes: u32, cancel: &AtomicBool) -> Result<(), String> {
    let wait = reconnect_delay(crashes, rand::random());
    hold_off(Some(tokio::time::Instant::now() + wait), cancel).await
}
/// Wait out what is left of a pause before the next claim; a stop ends the wait.
async fn hold_off(until: Option<tokio::time::Instant>, cancel: &AtomicBool) -> Result<(), String> {
    let Some(until) = until else { return Ok(()) };
    cancellable(
        async {
            tokio::time::sleep_until(until).await;
            Ok(())
        },
        cancel,
    )
    .await
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
/// One bad task is dropped and the next is claimed. A run of them slows the claims down and,
/// from the limit on, shows why; it never stops the worker, because each is a different task or
/// a server that will recover.
#[derive(Default)]
struct TaskFailures(u32);
impl TaskFailures {
    fn completed(&mut self) {
        self.0 = 0;
    }
    /// The pause before the next claim, and whether the run is long enough to show its reason.
    fn dropped(&mut self) -> (Duration, bool) {
        self.0 = self.0.saturating_add(1);
        (
            reconnect_delay(self.0, rand::random()),
            self.0 >= TASK_FAILURE_LIMIT,
        )
    }
}
fn reconnect_delay(attempt: u32, entropy: u64) -> Duration {
    let base = (1u64 << attempt.min(5)).min(30) * 1000;
    Duration::from_millis(base + entropy % (base + 1))
}
pub(crate) fn retryable(error: &str) -> bool {
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
            // The server no longer holds the challenge or qualification: qualify again.
            | "worker_qualification_restart"
            | "worker_challenge_busy"
            | "server_http_408"
            | "server_http_429" // A failing or busy server, or a proxy in front of it, recovers by itself: 500 like 503.
    ) || error.starts_with("server_http_5")
}
/// The AI runtime process ended or stopped answering while it was serving.
fn runtime_crash(error: &str) -> bool {
    matches!(
        error,
        "runtime_process_stopped" | "runtime_prediction_interrupted" | "runtime_not_ready"
    )
}
async fn reconnect<F: FnMut(bool) -> Fut, Fut: Future<Output = Result<(), String>>>(
    progress: &Progress,
    mut refresh: bool,
    mut attempt: F,
) -> Result<(), String> {
    let mut retries = 0u32;
    // Kept here, across every restart of the setup: counted inside it, a runtime that dies
    // every time would be set up again for ever, a few seconds apart.
    let mut crashes = 0u32;
    loop {
        wait_for_user(progress, || async { Ok(()) }).await?;
        let finished = progress.completed_tasks();
        let error = match attempt(refresh).await {
            Ok(()) => return Ok(()),
            // The server changed which models its tasks use: set up again with them, now.
            Err(error) if error == "worker_models_changed" => {
                check_cancel(&progress.cancelled)?;
                (refresh, retries, crashes) = (false, 0, 0);
                continue;
            }
            Err(error) if retryable(&error) => error,
            Err(error) => return Err(error),
        };
        check_cancel(&progress.cancelled)?;
        let worked = progress.completed_tasks() > finished;
        if worked {
            // A task finished: the run of crashes ended, whatever stopped this attempt.
            crashes = 0;
        }
        let delay = if runtime_crash(&error) {
            crashes += 1;
            if crashes >= CRASH_LIMIT {
                return Err("runtime_crash_loop".into());
            }
            // Nor is a new session asked for: one issued for an earlier fault is saved.
            refresh = false;
            // The session is not at fault: the same one sets up again, after a longer wait.
            reconnect_delay(crashes, rand::random())
        } else {
            if worked
                // "working" is announced before the server has answered a claim; an answered
                // claim with no task leaves "waiting-for-work".
                || progress.status.lock().unwrap().state == "waiting-for-work"
            {
                retries = 0;
            }
            refresh = true;
            let delay = reconnect_delay(retries, rand::random());
            retries = retries.saturating_add(1);
            delay
        };
        progress.set("reconnecting", Some(error));
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
    let worker =
        crate::transport::issue_worker_session(&client, saved, capabilities.clock_skew_ms).await?;
    crate::credentials::save("worker-session", &worker)
}
/// FD-64: what stopped a qualification or a measurement, if anything. `Ok` is a pause for power,
/// memory or sleep, to wait out and qualify again; `Err` ends the preparation with that code.
fn interruption(resumed: bool, interrupted: Option<String>) -> Option<Result<String, String>> {
    if resumed {
        return Some(Ok("system_resumed".into()));
    }
    let reason = interrupted?;
    Some(match reason.strip_prefix("resource_") {
        Some(pause) => Ok(pause.into()),
        None => Err(reason),
    })
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
/// `paused` ends the download with `user_paused`: what was received stays on disk and the
/// download continues from there when the person resumes.
async fn acquisition<T, F: Future<Output = Result<(), String>>>(
    work: impl Future<Output = Result<T, String>>,
    explicit_permission: bool,
    maintain: impl FnMut() -> F,
    network_loss: impl Future<Output = ()>,
    paused: impl Future<Output = ()>,
    cancelled: &AtomicBool,
) -> Result<T, String> {
    maintained(
        work,
        async {
            tokio::select! {
                _ = paused => "user_paused".into(),
                _ = async {
                    if explicit_permission {
                        std::future::pending::<()>().await;
                    }
                    network_loss.await;
                } => "model_download_permission_required".into(),
            }
        },
        maintain,
        cancelled,
    )
    .await
}
async fn flag_set(flag: &AtomicBool) {
    while !flag.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
/// Why work that holds a lease must stop now: Stop, sign-out or quit; a pause for power or
/// network; the computer waking from sleep.
async fn lease_interruption(progress: &Progress, clock: &WakeClock) -> String {
    tokio::select! {
        reason = resource_loss(clock) => format!("resource_{reason}"),
        _ = flag_set(&progress.cancelled) => "worker_setup_cancelled".into(),
    }
}
/// Run one step of work (a claim and its task). When `interrupt` says to stop first, signal
/// `stop` and give the step `grace` to hand its lease back (`fail` with `cancelled`) before it
/// is dropped: the server gives the task to another computer at once instead of waiting for the
/// lease to run out.
async fn returning_lease<T>(
    step: impl Future<Output = Result<T, String>>,
    interrupt: impl Future<Output = String>,
    stop: &tokio::sync::watch::Sender<bool>,
    grace: Duration,
) -> Result<T, String> {
    tokio::pin!(step);
    tokio::select! {
        biased;
        result = &mut step => result,
        reason = interrupt => {
            let _ = stop.send(true);
            let _ = tokio::time::timeout(grace, &mut step).await;
            Err(reason)
        }
    }
}
/// What `/models` says each task runs: its state and model keys. Two replies with the same
/// signature need the same models on this computer.
fn inventory_signature(inventory: &serde_json::Value) -> Vec<(String, String, Vec<String>)> {
    let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_owned();
    let mut signature: Vec<_> = inventory["workloads"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| {
            let keys = entry["modelKeys"].as_array().into_iter().flatten();
            (
                text(&entry["workload"]),
                text(&entry["state"]),
                keys.map(text).collect(),
            )
        })
        .collect();
    signature.sort();
    signature
}
/// What to do about a refusal while qualifying one model.
#[derive(Debug, PartialEq)]
enum Refusal {
    /// The server's bookkeeping, or a challenge it no longer holds: ask for a new challenge for
    /// this model after a pause.
    Again,
    /// The task's model may have changed on the server: read `/models` again.
    Models,
    /// The server does not take this provider's result: use the processor.
    Processor,
    /// This task can't be done here now; the others carry on.
    Task,
    /// Nothing on this computer can change it.
    Stop,
}
fn refusal(code: &str, provider: &str) -> Refusal {
    if matches!(
        code,
        "worker_challenge_busy" | "worker_qualification_restart" | "worker_challenge_rejected"
    ) {
        return Refusal::Again;
    }
    if matches!(
        code,
        "workload_desktop_model_profile_unavailable"
            | "workload_desktop_model_profile_changed"
            | "workload_desktop_pool_model_unavailable"
            | "workload_desktop_clip_profile_unavailable"
            | "workload_desktop_face_profile_unavailable"
    ) {
        return Refusal::Models;
    }
    if code.starts_with("workload_") {
        return Refusal::Task;
    }
    // The server refused what a GPU runtime sent (its attestation, its report). The processor
    // runtime is a different signed runtime with its own report: try that before giving up.
    let about_the_runtime = matches!(
        code,
        "worker_runtime_unsigned"
            | "worker_qualification_report_refused"
            | "worker_qualification_refused"
            | "worker_challenge_invalid"
            | "worker_qualification_invalid"
    ) || code.starts_with("server_http_4");
    if about_the_runtime && provider != crate::provider_selection::CPU {
        return Refusal::Processor;
    }
    Refusal::Stop
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
/// A model file that could not be written, on a volume with less free space than the model
/// needs, is a full disk: say so instead of a general write failure.
fn disk_shortfall(code: String, models: &Path, needed: u64) -> String {
    let write_failed = matches!(
        code.as_str(),
        "model_file_create_failed"
            | "model_file_write_failed"
            | "model_file_publish_failed"
            | "model_cache_publish_failed"
    );
    if write_failed && crate::host_storage::available_bytes(models).is_ok_and(|free| free < needed)
    {
        return "model_disk_space_insufficient".into();
    }
    code
}

/// Why no workload qualified: the first one's reason, or the general code when none was given.
///
/// A refusal by the server that passes by itself comes before any other reason: the worker
/// then waits and offers that task again, instead of stopping over another task's fault and
/// never coming back for it.
fn first_failure(workloads: &[WorkloadStatus]) -> String {
    let codes: Vec<&str> = workloads
        .iter()
        .filter(|item| item.state == "unavailable")
        .filter_map(|item| item.code.as_deref())
        .map(|code| code.strip_prefix("workload_").unwrap_or(code))
        .collect();
    // Of several such refusals, the one offered again soonest: each task is tried when its own
    // wait is over, not when the longest one is.
    codes
        .iter()
        .filter(|code| server_task_refusal(code))
        .min_by_key(|code| refused_task_retry(code))
        .or(codes.first())
        .map_or_else(
            || "worker_no_qualified_workloads".into(),
            |code| (*code).into(),
        )
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
    // A newer server may add fields to the reply or to a task's entry: they are ignored. The
    // profiles themselves are hashed into their model keys and stay strict (`model_catalogue`).
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Inventory {
        protocol_version: u32,
        provider: String,
        runtime_source_revision: String,
        workloads: Vec<Entry>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Entry {
        workload: String,
        state: String,
        model_names: Vec<String>,
        model_keys: Vec<String>,
        /// The server's catalogue profile of each model key, in the same order.
        #[serde(default)]
        profiles: Vec<serde_json::Value>,
    }
    let invalid = || "worker_model_inventory_invalid".to_string();
    let inventory: Inventory = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    if inventory.protocol_version != 2
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
        let state = entry.state;
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
            groups.push(crate::model_catalogue::served_group(
                &entry.workload,
                &entry.model_keys,
                &entry.profiles,
                source,
                provider,
            )?);
        } else if !entry.model_keys.is_empty() || !entry.profiles.is_empty() {
            return Err(invalid());
        }
        // Routing states come only from servers older than desktop auto-setup, which decide desktop
        // work by their own routes: updating the server is what makes the task available here.
        let code = matches!(state.as_str(), "pinned" | "legacy" | "unavailable")
            .then(|| "server_update_required".to_string());
        statuses.push(WorkloadStatus {
            workload: entry.workload,
            state,
            model_names: entry.model_names,
            code,
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

/// The two macOS floors the release checks enforce (`tools/check_macos_minimum.py`), read at
/// build time so the app and the checks cannot disagree.
const MACOS_MINIMUMS: &str = include_str!("../../packaging/macos/minimum-versions.json");
fn os_version(text: &str) -> Option<(u64, u64)> {
    let mut parts = text.trim().split('.').map(|part| part.parse::<u64>().ok());
    Some((parts.next()??, parts.next().unwrap_or(Some(0))?))
}
/// The oldest macOS the AI runtime pack runs on. The app itself runs on older ones.
fn ai_runtime_macos_floor() -> Option<(u64, u64)> {
    serde_json::from_str::<serde_json::Value>(MACOS_MINIMUMS)
        .ok()?
        .get("aiRuntime")?
        .as_str()
        .and_then(os_version)
}
/// The macOS this app is running on; `None` on other systems or when it cannot be read.
fn running_macos() -> Option<(u64, u64)> {
    #[cfg(target_os = "macos")]
    {
        let mut text = [0u8; 32];
        let mut length = text.len();
        // SAFETY: the name is NUL-terminated and `length` is the size of `text`, which the
        // kernel fills with at most that many bytes and reports back in `length`.
        let read = unsafe {
            libc::sysctlbyname(
                c"kern.osproductversion".as_ptr(),
                text.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        } == 0;
        let text = text.get(..length).filter(|_| read)?;
        os_version(std::str::from_utf8(text).ok()?.trim_end_matches('\0'))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}
/// Refuse AI processing on a macOS older than the runtime pack needs, where the runtime would
/// only fail to load. FD-64: on macOS a version or a floor that cannot be read is not known to
/// be supported, so nothing is installed or downloaded; other systems have no such floor.
fn runtime_os_supported(
    os: &str,
    running: Option<(u64, u64)>,
    floor: Option<(u64, u64)>,
) -> Result<(), String> {
    if os != "macos" {
        return Ok(());
    }
    match (running, floor) {
        (Some(running), Some(floor)) if running >= floor => Ok(()),
        (Some(_), Some(_)) => Err("runtime_os_unsupported".into()),
        _ => Err("runtime_os_unknown".into()),
    }
}

async fn prepare(
    saved: SavedConnection,
    paths: SetupPaths,
    allow_download: bool,
    progress: Progress,
) -> Result<(), String> {
    let os_supported = runtime_os_supported(
        std::env::consts::OS,
        running_macos(),
        ai_runtime_macos_floor(),
    );
    prepare_on(os_supported, saved, paths, allow_download, progress).await
}
async fn prepare_on(
    os_supported: Result<(), String>,
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
    // Before anything is created, installed, downloaded or started.
    os_supported?;
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
        // An installed runtime that no longer verifies (a file changed or went missing) is
        // rebuilt from the app's signed bundle below, instead of failing the same way for ever.
        let active = match store.load_active() {
            Ok(active) => active,
            Err(_) if bundle.exists() => None,
            Err(code) => return Err(code),
        };
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
    // This computer runs only the server's catalogue, which servers before desktop auto-setup don't send.
    if !caps.features.worker_auto_setup {
        return Err("server_update_required".into());
    }
    let several_leases = caps.features.worker_concurrent_leases;
    let worker = WorkerTransport::load(&saved)?
        .with_clock_skew(caps.clock_skew_ms)
        .with_withdrawal_notice(caps.features.worker_withdrawal_notice)
        .with_concurrent_leases(several_leases);
    let (source, provider) = (
        installed.source_revision().to_owned(),
        installed.provider().to_owned(),
    );
    let inventory = cancellable(
        worker.model_inventory(&source, &provider),
        &progress.cancelled,
    )
    .await?;
    // The server decides which models run here, and may change its mind at any time: asked
    // again while working, a different answer sets this computer up again with the new models.
    let signature = inventory_signature(&inventory);
    // How many tasks of each kind the server lets this computer run at once.
    let mut limits = inventory_concurrency(&inventory);
    // A question that fails changes nothing; the claims report a server in trouble.
    let latest_inventory = || async { worker.model_inventory(&source, &provider).await.ok() };
    let models_changed = || async {
        latest_inventory()
            .await
            .is_some_and(|value| inventory_signature(&value) != signature)
    };
    let mut models_checked = std::time::Instant::now();
    let (groups, statuses) = inventory_profiles(
        &inventory,
        installed.source_revision(),
        installed.provider(),
    )?;
    progress.workloads(statuses);
    if groups.is_empty() {
        // The server offers every enabled task it can: none means none is turned on for computers.
        return Err("worker_no_eligible_workloads".into());
    }
    // FD-52: an accelerated runtime beside the processor one, where the app ships one this
    // computer can use. Any fault on that side leaves every workload on the processor.
    let (accelerated, mut plan) =
        crate::provider_selection::open(&paths, &installed, &worker, groups.clone()).await?;
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
    // The model mirror is Frameleaf's host, not the person's server: its own client.
    let mirror = transport::public_client_builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| "network_client_unavailable")?;
    // Complete acquisition before requesting short-lived nonces.
    let mut caches = Vec::new();
    for profile in &profiles {
        let count = counted.insert(profile.cache_identity());
        let cache = loop {
            wait_for_user(&progress, || worker.maintain_session()).await?;
            progress.set("preparing-models", None);
            let credited = std::sync::atomic::AtomicU64::new(0);
            let result = acquisition(
                profile.prepare_cache(
                    &paths.data.join("models"),
                    &mirror,
                    &progress.cancelled,
                    allow_download,
                    |event| {
                        if count {
                            if let CacheProgress::Verified(bytes) = &event {
                                credited.fetch_add(*bytes, Ordering::AcqRel);
                            }
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
                flag_set(&progress.user_paused),
                &progress.cancelled,
            )
            .await;
            match result {
                // Paused in the middle of a file: wait, then carry on from what was received.
                Err(code) if code == "user_paused" => {
                    progress.uncredit(credited.load(Ordering::Acquire));
                }
                result => break result,
            }
        }
        .map_err(|code| disk_shortfall(code, &paths.data.join("models"), profile.cache_bytes()))?;
        caches.push(cache);
    }
    let mut failures = TaskFailures::default();
    let mut refusals = 0u32;
    let mut strikes = GrantStrikes::default();
    // The graphics card's crashes in a row are kept with the plan's records, so a setup that
    // starts again in between (a lost session, say) does not start the count again.
    let mut trouble = RuntimeTrouble {
        at_one: plan.crash_streak(),
        ..Default::default()
    };
    // When the server refused each task, for offering it again that long after the refusal
    // (not that long after this setup began, which the downloads and checks may outlast).
    let mut refused_at = std::collections::BTreeMap::<String, tokio::time::Instant>::new();
    'qualification: loop {
        refused_at.clear();
        let pass_started = tokio::time::Instant::now();
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
                group_caches.push(caches[index].clone());
                // One model's qualification, from a new challenge to the accepted record. A
                // refusal the server clears by itself starts this model again, not the others.
                let mut rejected = 0u32;
                let (qualified, accepted) = 'attempt: loop {
                    let cache = caches[index].clone();
                    check_cancel(&progress.cancelled)?;
                    wait_for_capacity(profile.minimum_memory(), &progress, || {
                        worker.maintain_session()
                    })
                    .await?;
                    progress.set("qualifying", None);
                    // What a refusal from the server means for this model, task and provider.
                    macro_rules! refused {
                        ($code:expr) => {{
                            let code: String = $code;
                            if retryable(&code)
                                && code != "worker_qualification_restart"
                                && code != "worker_challenge_busy"
                            {
                                return Err(code);
                            }
                            if code == "worker_challenge_rejected" {
                                rejected += 1;
                            }
                            match refusal(&code, profile.provider()) {
                                Refusal::Again if rejected < CHALLENGE_REJECTED_LIMIT => {
                                    refusals = refusals.saturating_add(1);
                                    let delay = reconnect_delay(refusals, rand::random());
                                    // Say why this computer is waiting.
                                    progress.set("reconnecting", Some(code));
                                    cancellable(
                                        async {
                                            tokio::time::sleep(delay).await;
                                            Ok(())
                                        },
                                        &progress.cancelled,
                                    )
                                    .await?;
                                    continue 'attempt;
                                }
                                Refusal::Models if models_changed().await => {
                                    return Err("worker_models_changed".into());
                                }
                                Refusal::Again
                                | Refusal::Models
                                | Refusal::Task
                                | Refusal::Processor
                                    if !provider_independent(&code)
                                        && plan.demote(workload, &code, false) =>
                                {
                                    continue 'qualification;
                                }
                                Refusal::Again | Refusal::Models | Refusal::Task => {
                                    refused_at
                                        .insert(workload.to_owned(), tokio::time::Instant::now());
                                    progress.workload(workload, "unavailable", Some(code));
                                    continue 'workload;
                                }
                                Refusal::Processor | Refusal::Stop => return Err(code),
                            }
                        }};
                    }
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
                        Err(code) if code == "worker_setup_cancelled" => return Err(code),
                        Err(code) => refused!(code),
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
                                    | "runtime_output_mismatch"
                                    | "runtime_out_of_memory"
                                    | "runtime_model_missing"
                                    | "runtime_provider_unavailable"
                            ) =>
                        {
                            // Memory another program held, or a slow moment, is not remembered
                            // against the GPU for the whole runtime epoch.
                            let remember = !crate::provider_selection::passing(&code);
                            if plan.demote(workload, &code, remember) {
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
                        Err(code) if code == "worker_setup_cancelled" => return Err(code),
                        Err(code) => refused!(code),
                    }
                    let accepted = match cancellable(
                        worker.read_accepted_qualification(profile, &qualified, challenge.id()),
                        &progress.cancelled,
                    )
                    .await
                    {
                        Ok(value) => value,
                        Err(code) if code == "worker_setup_cancelled" => return Err(code),
                        Err(code) => refused!(code),
                    };
                    break (qualified, accepted);
                };
                check_cancel(&progress.cancelled)?;
                if let Err(code) = installed.runtime(profile.provider()).and_then(|runtime| {
                    accepted.write_evidence(
                        &paths.data.join("qualification-evidence"),
                        &paths.app_version,
                        profile,
                        runtime,
                        &qualified,
                        worker.now()?,
                    )
                }) {
                    eprintln!("worker_qualification_evidence_failed: {code}");
                }
                group_prepared.push((qualified, accepted));
            }
            // FD-56: an accelerated provider keeps a workload only where it measured faster than
            // the processor here. Measured once per runtime epoch, on the same fixtures, without
            // the server; anything that stops the measurement leaves the processor in charge.
            if plan.unmeasured(workload) {
                let accelerated_ms = crate::provider_selection::warm_milliseconds(
                    group_prepared
                        .iter()
                        .map(|(qualified, _)| qualified.report()),
                );
                let twins: Vec<_> = plan
                    .cpu_group(workload)
                    .into_iter()
                    .flatten()
                    .filter_map(|profile| {
                        let index = profiles
                            .iter()
                            .position(|item| item.model_key() == profile.model_key())?;
                        Some((profile.clone(), caches[index].clone()))
                    })
                    .collect();
                let scratch = paths.data.join("scratch");
                let clock = WakeClock::new();
                let ((runtime, cpu_ms), interrupted) = monitored_preparation(
                    move |cancel| {
                        let mut qualified = Vec::new();
                        for (profile, cache) in &twins {
                            let measured = profile
                                .challenge(&uuid::Uuid::new_v4().to_string())
                                .and_then(|(spec, fixture)| {
                                    installed.qualify(
                                        crate::provider_selection::CPU,
                                        cache,
                                        &scratch,
                                        &spec,
                                        &fixture,
                                        &cancel,
                                    )
                                });
                            match measured {
                                Ok(value) => qualified.push(value),
                                Err(_) => return (installed, None),
                            }
                        }
                        let total = crate::provider_selection::warm_milliseconds(
                            qualified.iter().map(|value| value.report()),
                        );
                        (installed, total)
                    },
                    async { format!("resource_{}", resource_loss(&clock).await) },
                    || worker.maintain_session(),
                    &progress.cancelled,
                )
                .await?;
                installed = runtime;
                check_cancel(&progress.cancelled)?;
                // FD-64: a pause for power, memory or sleep measured nothing. Wait it out and
                // qualify again, as above, instead of giving the workload to the processor.
                if let Some(stopped) =
                    interruption(clock.observe(std::time::SystemTime::now()), interrupted)
                {
                    progress.set("paused", Some(stopped?));
                    continue 'qualification;
                }
                if plan.measured(workload, accelerated_ms, cpu_ms) {
                    continue 'qualification;
                }
            }
            prepared.extend(group_prepared);
            accepted_profiles.extend(group.iter().cloned());
            accepted_caches.extend(group_caches);
            progress.workload(workload, "ready", None);
        }
        if prepared.is_empty() {
            // The server offered work but none qualified here: say why (wrong answer, out of
            // memory, server refusal…), a fault Retry Setup can clear, not a server setting.
            return Err(first_failure(&progress.status.lock().unwrap().workloads));
        }
        let mut memory_by_cache = std::collections::BTreeMap::new();
        for (profile, cache) in accepted_profiles.iter().zip(&accepted_caches) {
            let memory = memory_by_cache.entry(cache).or_insert(0u64);
            *memory = (*memory).max(profile.minimum_memory());
        }
        let required_memory = memory_by_cache.values().sum();
        // For choosing how many tasks to run at once: which tasks are ready, and whether any
        // runs on a graphics card or neural engine.
        let ready: std::collections::BTreeSet<String> = accepted_profiles
            .iter()
            .filter_map(|profile| profile.model_key().split(':').next().map(str::to_owned))
            .collect();
        let accelerated = accepted_profiles
            .iter()
            .any(|profile| profile.provider() != crate::provider_selection::CPU);
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
        // How long this pass took, from the first challenge to here.
        let pass_took = pass_started.elapsed();
        loop {
            wait_for_capacity(required_memory, &progress, || worker.maintain_session()).await?;
            let now = worker.now()?;
            if prepared
                .iter()
                .any(|(proof, accepted)| accepted.validate_runtime(proof, now + 60_000).is_err())
            {
                continue 'qualification;
            }
            progress.set("starting-worker", None);
            // One task at a time unless the server lets a desktop hold several leases. Then:
            // as many as the server's Jobs setting allows and this computer can take.
            let free_memory = tauri::async_runtime::spawn_blocking(crate::resource_policy::sample)
                .await
                .ok()
                .and_then(|status| status.available_memory);
            let cores = std::thread::available_parallelism().map_or(1, |cores| cores.get());
            let local = local_capacity(accelerated, cores, free_memory, required_memory);
            let mut at_once = match several_leases {
                true => concurrent_tasks(&limits, &ready, local, progress.capacity_ceiling()),
                false => 1,
            };
            progress.running_at_once(at_once);
            // The process is started able to serve as many requests at once as this computer
            // could ever take, so a higher Jobs setting takes effect with the next claim.
            let threads = match several_leases {
                true => local,
                false => 1,
            };
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
                    let predictor =
                        installed.start(&bindings, &cache, &scratch, port, now, threads)?;
                    Ok::<_, String>((installed, prepared, predictor))
                })
                .await
                .map_err(|_| "runtime_start_failed")??;
            installed = runtime;
            prepared = proofs;
            check_cancel(&progress.cancelled)?;
            // The tasks that are ready get at least as long to work as it took to get here,
            // before a refused task is offered again and everything is checked once more:
            // however long the checks take, work is never starved by retries.
            let work_due = tokio::time::Instant::now() + pass_took.max(Duration::from_secs(120));
            // Signalled to make the step in hand give its lease back before it is dropped.
            let (stop, mut cancel) = tokio::sync::watch::channel(false);
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
                let now = worker.now()?;
                if prepared.iter().any(|(proof, accepted)| {
                    accepted.validate_runtime(proof, now + 60_000).is_err()
                }) {
                    continue 'qualification;
                }
                // A task the server refused for a reason of its own is offered again in time.
                let offer_again = progress
                    .status
                    .lock()
                    .unwrap()
                    .workloads
                    .iter()
                    .filter(|item| item.state == "unavailable")
                    .filter_map(|item| {
                        Some((refused_at.get(&item.workload)?, item.code.as_deref()?))
                    })
                    .any(|(at, code)| {
                        code.starts_with("workload_") && at.elapsed() >= refused_task_retry(code)
                    });
                if offer_again && tokio::time::Instant::now() >= work_due {
                    predictor.stop()?;
                    return Err("worker_models_changed".into());
                }
                // A graphics card or neural engine that rested after crashes is tried again:
                // set up again, and the plan made then gives it its work back.
                if plan
                    .rest_ends()
                    .is_some_and(|due| std::time::Instant::now() >= due)
                {
                    predictor.stop()?;
                    return Err("worker_models_changed".into());
                }
                // The server may have changed a task's model, or turned a task on or off.
                if models_checked.elapsed() >= MODEL_RECHECK {
                    models_checked = std::time::Instant::now();
                    if let Some(latest) = latest_inventory().await {
                        if inventory_signature(&latest) != signature {
                            predictor.stop()?;
                            return Err("worker_models_changed".into());
                        }
                        // The administrator's Jobs setting is followed without setting up
                        // again: the next claim asks for what it allows now.
                        limits = inventory_concurrency(&latest);
                        if several_leases {
                            at_once = concurrent_tasks(
                                &limits,
                                &ready,
                                local,
                                progress.capacity_ceiling(),
                            );
                            progress.running_at_once(at_once);
                        }
                    }
                }
                progress.set("working", None);
                let accepted: Vec<_> = prepared.iter().map(|(_, accepted)| accepted).collect();
                // How many tasks to have in hand, which a memory shortfall lowers as it goes.
                let at_once_now = std::sync::atomic::AtomicU32::new(at_once);
                let slots = || several_leases.then(|| at_once_now.load(Ordering::Acquire));
                // The pool works on, refilling as tasks finish, until this loop is needed:
                // a pause, the next look at the server's models, a refused task due to be
                // offered again, or the qualifications nearing their end. It then finishes
                // what is in hand and hands back.
                let models_due = models_checked + MODEL_RECHECK;
                let offer_due = progress
                    .status
                    .lock()
                    .unwrap()
                    .workloads
                    .iter()
                    .filter(|item| item.state == "unavailable")
                    .filter_map(|item| {
                        Some((refused_at.get(&item.workload)?, item.code.as_deref()?))
                    })
                    .filter(|(_, code)| code.starts_with("workload_"))
                    .map(|(at, code)| (*at + refused_task_retry(code)).max(work_due))
                    .min();
                let rest_ends = plan.rest_ends();
                let keep_claiming = || {
                    !progress.user_paused.load(Ordering::Acquire)
                        && std::time::Instant::now() < models_due
                        && rest_ends.is_none_or(|due| std::time::Instant::now() < due)
                        && offer_due.is_none_or(|due| tokio::time::Instant::now() < due)
                        && worker.now().is_ok_and(|now| {
                            prepared.iter().all(|(proof, accepted)| {
                                accepted.validate_runtime(proof, now + 60_000).is_ok()
                            })
                        })
                };
                let pool = crate::native_predictor::Pool {
                    slots: &slots,
                    keep_claiming: &keep_claiming,
                    abandon: &|| {},
                };
                let mut requalify = false;
                let mut refused_in_a_row = 0u32;
                let mut dropped: Option<String> = None;
                // Until when the next claim is held off after a dropped task. The pool waits
                // it out itself, except where it ends first because the runtime was stopped.
                let mut held_off: Option<tokio::time::Instant> = None;
                let mut unclaimed: Option<Step> = None;
                // The tasks in hand. One that ends the pool with its failure stays counted:
                // after a crash this is how many the runtime was working on.
                let in_hand = InHand::default();
                let mut recovered = false;
                // The models the graphics card or neural engine is working on in this plan.
                let accelerated_models = plan.accelerated_models();
                let (limits_now, ready_now) = (&limits, &ready);
                let mut on_task = |task: crate::native_predictor::TaskStep| match task.step {
                    Step::Completed => {
                        failures.completed();
                        held_off = None;
                        strikes.completed(task.model.as_deref());
                        progress.completed();
                        refused_in_a_row = 0;
                        // A long run without trouble: one more at once than it last ran
                        // short at, up to what the server allows and this computer can take.
                        let on_accelerated = task
                            .model
                            .as_deref()
                            .is_some_and(|model| accelerated_models.contains(model));
                        let (clean, well) = trouble.completed(on_accelerated);
                        recovered |= well;
                        if clean && progress.capacity_ceiling().is_some() {
                            progress.raise_capacity();
                            let more = concurrent_tasks(
                                limits_now,
                                ready_now,
                                local,
                                progress.capacity_ceiling(),
                            );
                            at_once_now.store(more, Ordering::Release);
                            progress.running_at_once(more);
                        }
                        Some(Duration::ZERO)
                    }
                    Step::Dropped(code) => {
                        let on_accelerated = task
                            .model
                            .as_deref()
                            .is_some_and(|model| accelerated_models.contains(model));
                        trouble.refused(on_accelerated);
                        // The model refused two tasks running with others: most likely too
                        // many for this computer's memory. Half as many from here on.
                        let running = at_once_now.load(Ordering::Acquire);
                        refused_in_a_row = match code.as_str() {
                            "runtime_prediction_refused" => refused_in_a_row + 1,
                            _ => 0,
                        };
                        if refused_in_a_row >= 2 && running > 1 {
                            refused_in_a_row = 0;
                            let fewer = (running / 2).max(1);
                            at_once_now.store(fewer, Ordering::Release);
                            progress.lower_capacity(fewer);
                        }
                        // By now the server has withdrawn the model and will lease nothing
                        // for it: stop claiming and qualify again, which grants it again.
                        // Only a failure the server acknowledged was counted there.
                        requalify |= task.reported && strikes.failed(task.model.as_deref(), &code);
                        dropped = Some(code);
                        let pause = failures.dropped().0;
                        held_off = Some(tokio::time::Instant::now() + pause);
                        (!requalify).then_some(pause)
                    }
                    step @ (Step::Idle | Step::Busy(_)) => {
                        unclaimed = Some(step);
                        None
                    }
                };
                let on_step = |task: crate::native_predictor::TaskStep| {
                    in_hand.settled(&task);
                    on_task(task)
                };
                // A stop waits for every lease in hand to be handed back, one request each.
                let grace = LEASE_RETURN + Duration::from_secs(u64::from(at_once.min(8)) - 1);
                let completed = returning_lease(
                    predictor.work(
                        &worker,
                        &accepted,
                        &mut cancel,
                        &pool,
                        |workload| {
                            in_hand.claimed();
                            progress.active(Some(workload))
                        },
                        on_step,
                    ),
                    lease_interruption(&progress, &clock),
                    &stop,
                    grace,
                )
                .await;
                progress.active(None);
                let running = at_once_now.load(Ordering::Acquire);
                at_once = running;
                // A runtime that ended or stopped answering: what it means depends on how
                // many tasks it was working on, not on how many it was allowed.
                if recovered {
                    plan.recovered();
                }
                let crash = judge(
                    &mut trouble,
                    &progress,
                    &plan,
                    &completed,
                    dropped.as_deref(),
                    in_hand.count(),
                    predictor.failed_lane(),
                );
                plan.set_crash_streak(trouble.at_one);
                match completed {
                    Ok(()) => {
                        // The accelerated runtime crashed out. Decided before qualifying
                        // again, which the same failures can ask for: its work moves to the
                        // processor and it rests, and the setup that follows qualifies anew.
                        let lane = predictor.failed_lane().map(str::to_owned);
                        match after_pool(
                            &mut plan,
                            crash,
                            dropped.as_deref(),
                            lane.as_deref(),
                            requalify,
                        ) {
                            AfterPool::CrashedOut => {
                                progress.crashed(predictor.exit_report());
                                predictor.stop()?;
                                continue 'qualification;
                            }
                            AfterPool::Requalify => {
                                // Its process died as well: the wait before it is started
                                // again is kept.
                                if let Some(AfterCrash::Again(_)) = crash {
                                    progress.crashed(predictor.exit_report());
                                }
                                predictor.stop()?;
                                if let Some(AfterCrash::Again(crashes)) = crash {
                                    restart_wait(crashes, &progress.cancelled).await?;
                                }
                                continue 'qualification;
                            }
                            AfterPool::Carry => {}
                        }
                        if let Some(code) = dropped {
                            // FD-52: the accelerated runtime's process died while inferring: its
                            // workloads move to the processor instead of crashing on every restart.
                            let lane = predictor.failed_lane().map(str::to_owned);
                            let code = crashed_out(crash, code);
                            if let Some(AfterCrash::Again(crashes)) = crash {
                                // The graphics card keeps the work: its runtime is started
                                // again after a wait.
                                progress.crashed(predictor.exit_report());
                                predictor.stop()?;
                                restart_wait(crashes, &progress.cancelled).await?;
                                break;
                            }
                            if lane.is_some_and(|lane| plan.demote_runtime(&lane, &code)) {
                                progress.crashed(predictor.exit_report());
                                predictor.stop()?;
                                continue 'qualification;
                            }
                            if !predictor.is_running()? {
                                // Inference was cut short: load the models again before the
                                // next claim, which is still held off as after any dropped task.
                                hold_off(held_off, &progress.cancelled).await?;
                                break;
                            }
                        }
                        let pause = match unclaimed {
                            Some(Step::Busy(code)) => {
                                let (delay, show) = failures.dropped();
                                if show {
                                    // A long run of server errors: say why while waiting.
                                    progress.set("reconnecting", Some(code));
                                }
                                Some(delay)
                            }
                            Some(_) => {
                                progress.set("waiting-for-work", None);
                                Some(Duration::from_secs(1))
                            }
                            None => None,
                        };
                        if let Some(pause) = pause {
                            cancellable(
                                async {
                                    tokio::time::sleep(pause).await;
                                    Ok(())
                                },
                                &progress.cancelled,
                            )
                            .await?;
                        }
                    }
                    // With several tasks in hand the likeliest cause is memory, not the
                    // device: half as many on the same runtime, halved again each time down
                    // to one. With one task in hand a graphics card or neural engine keeps
                    // the work: its runtime is started again after a wait, and only the third
                    // crash in a row with no task finished in between is a failing runtime
                    // (FD-52 below). So is one that did not start.
                    Err(_)
                        if matches!(crash, Some(AfterCrash::Fewer(_) | AfterCrash::Again(_))) =>
                    {
                        check_cancel(&progress.cancelled)?;
                        progress.crashed(predictor.exit_report());
                        predictor.stop()?;
                        if let Some(AfterCrash::Again(crashes)) = crash {
                            restart_wait(crashes, &progress.cancelled).await?;
                        }
                        break;
                    }
                    Err(reason) if reason.starts_with("resource_") => {
                        predictor.stop()?;
                        progress.set("paused", Some(reason[9..].into()));
                        if reason == "resource_system_resumed" {
                            continue 'qualification;
                        }
                        break;
                    }
                    // The server withdrew a model from this computer (its count of failed
                    // tasks outlives this setup's). Qualify again: the withdrawn model is
                    // held back and set aside, the others go back to work.
                    Err(reason) if reason == "worker_model_withdrawn" => {
                        predictor.stop()?;
                        strikes = GrantStrikes::default();
                        continue 'qualification;
                    }
                    Err(reason) => {
                        // FD-52: the accelerated runtime's process did not serve: use the
                        // processor for its workloads instead of failing the worker. A stop
                        // or sign-out while it was starting is not a provider failure.
                        check_cancel(&progress.cancelled)?;
                        // Why the process ended, for the page and the log, before it is cleared.
                        progress.crashed(predictor.exit_report());
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
                "modelKeys":profiles.iter().map(|p|p["modelKey"].clone()).collect::<Vec<_>>(),
                // protocol 2: the server's own profile for each key
                "profiles":if workload == "enrichment" {vec![]} else {profiles.into_iter().cloned().collect::<Vec<_>>()}})
        });
        serde_json::json!({"protocolVersion":2,"provider":"CPUExecutionProvider",
            "runtimeSourceRevision":"25b22c16e47a27a2eb50017d838497abce850d11","workloads":workloads})
    }
    #[test]
    fn inventory_keeps_eligible_workloads_when_another_is_pinned_or_unknown() {
        let source = "25b22c16e47a27a2eb50017d838497abce850d11";
        let mut value = inventory_fixture();
        value["workloads"][2]["state"] = serde_json::json!("pinned");
        value["workloads"][2]["modelKeys"] = serde_json::json!([]);
        value["workloads"][2]["profiles"] = serde_json::json!([]);
        let (groups, statuses) =
            inventory_profiles(&value, source, "CPUExecutionProvider").unwrap();
        assert_eq!(groups.iter().map(Vec::len).collect::<Vec<_>>(), vec![3, 1]);
        assert_eq!(statuses[2].state, "pinned");
        // Only an older server sends a routing state: updating it is the fix.
        assert_eq!(statuses[2].code.as_deref(), Some("server_update_required"));
        assert_eq!(statuses[0].code, None);
        // A key the server's own profile does not carry, or a profile for another provider, is refused:
        // the desktop runs exactly what the server sent.
        assert!(inventory_profiles(&value, source, "CUDAExecutionProvider").is_err());
        value["workloads"][1]["modelKeys"][0] =
            serde_json::json!(format!("ocr:{}", "0".repeat(64)));
        assert!(inventory_profiles(&value, source, "CPUExecutionProvider").is_err());
        // Protocol 1 (no profiles) comes only from older servers.
        let mut old = inventory_fixture();
        old["protocolVersion"] = serde_json::json!(1);
        assert!(inventory_profiles(&old, source, "CPUExecutionProvider").is_err());
    }
    #[test]
    fn reports_the_first_specific_reason_nothing_qualified() {
        let status = |workload: &str, state: &str, code: Option<&str>| WorkloadStatus {
            workload: workload.into(),
            state: state.into(),
            model_names: vec![],
            code: code.map(Into::into),
        };
        assert_eq!(
            first_failure(&[
                status("clip", "disabled", None),
                status("ocr", "unavailable", Some("runtime_out_of_memory")),
                status("face", "unavailable", Some("runtime_output_mismatch")),
            ]),
            "runtime_out_of_memory"
        );
        assert_eq!(
            first_failure(&[status(
                "clip",
                "unavailable",
                Some("workload_server_update_required")
            )]),
            "server_update_required"
        );
        assert_eq!(
            first_failure(&[status("clip", "unavailable", None)]),
            "worker_no_qualified_workloads"
        );
    }
    #[test]
    fn names_a_full_disk_when_a_model_file_cannot_be_written() {
        let models = std::env::temp_dir().canonicalize().unwrap();
        for (code, needed, expected) in [
            (
                "model_file_write_failed",
                u64::MAX,
                "model_disk_space_insufficient",
            ),
            ("model_file_write_failed", 0, "model_file_write_failed"),
            (
                "model_download_interrupted",
                u64::MAX,
                "model_download_interrupted",
            ),
        ] {
            assert_eq!(disk_shortfall(code.into(), &models, needed), expected);
        }
    }
    #[test]
    fn inventory_runs_each_clip_model_the_server_selects_and_refuses_mismatched_keys() {
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
        // A key that does not match the profile the server sent beside it is refused, not guessed at.
        let mut value = inventory_fixture_with(models[0]);
        value["workloads"][0]["modelKeys"][0] =
            inventory_fixture_with(models[1])["workloads"][0]["modelKeys"][0].clone();
        assert!(inventory_profiles(&value, source, "CPUExecutionProvider").is_err());
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
        // A field this app does not know is never used, wherever it claims to point; the same
        // field inside a profile is refused (the profile is hashed into its key).
        let mut value = inventory_fixture();
        value["workloads"][0]["url"] = serde_json::json!("https://untrusted");
        assert!(inventory_profiles(&value, source, "CPUExecutionProvider").is_ok());
        value["workloads"][0]["profiles"][0]["url"] = serde_json::json!("https://untrusted");
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
            std::future::pending(),
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
            std::future::pending(),
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
                std::future::pending(),
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
            std::future::pending(),
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
    #[test]
    fn the_ai_runtime_floor_is_the_declared_one_and_only_an_older_macos_is_refused() {
        let declared: serde_json::Value = serde_json::from_str(MACOS_MINIMUMS).unwrap();
        let floor = ai_runtime_macos_floor().expect("aiRuntime is declared as major.minor");
        assert_eq!(
            format!("{}.{}", floor.0, floor.1),
            declared["aiRuntime"].as_str().unwrap()
        );
        assert!(floor > os_version(declared["app"].as_str().unwrap()).unwrap());
        assert_eq!(os_version("15.6.1"), Some((15, 6)));
        assert_eq!(os_version("26\n"), Some((26, 0)));
        assert_eq!(os_version("fifteen"), None);
        let refused = Err("runtime_os_unsupported".to_string());
        assert_eq!(
            runtime_os_supported("macos", Some((floor.0 - 1, 9)), Some(floor)),
            refused
        );
        assert_eq!(
            runtime_os_supported("macos", Some((11, 0)), Some(floor)),
            refused
        );
        assert_eq!(
            runtime_os_supported("macos", Some(floor), Some(floor)),
            Ok(())
        );
        assert_eq!(
            runtime_os_supported("macos", Some((floor.0 + 1, 0)), Some(floor)),
            Ok(())
        );
        // FD-64: on macOS a version or a floor that could not be read is not known to be
        // supported, so setup stops with its own code instead of installing on a guess.
        let unknown = Err("runtime_os_unknown".to_string());
        assert_eq!(runtime_os_supported("macos", None, Some(floor)), unknown);
        assert_eq!(runtime_os_supported("macos", Some((26, 0)), None), unknown);
        assert_eq!(runtime_os_supported("macos", None, None), unknown);
        // Other systems have no such floor, whatever is or is not read there.
        for os in ["windows", "linux"] {
            assert_eq!(runtime_os_supported(os, None, Some(floor)), Ok(()));
            assert_eq!(runtime_os_supported(os, None, None), Ok(()));
            assert_eq!(runtime_os_supported(os, Some((11, 0)), Some(floor)), Ok(()));
        }
        // The Mac this suite runs on is read and decided, never unknown.
        #[cfg(target_os = "macos")]
        assert_ne!(
            runtime_os_supported("macos", running_macos(), ai_runtime_macos_floor()),
            unknown
        );
        assert!(!retryable("runtime_os_unknown"));
        #[cfg(target_os = "macos")]
        assert!(running_macos().is_some_and(|version| version >= (11, 0)));
        #[cfg(not(target_os = "macos"))]
        assert_eq!(running_macos(), None);
        // It stops for the person: the worker never retries it by itself.
        assert!(!retryable("runtime_os_unsupported"));
    }
    #[tokio::test]
    async fn an_older_macos_stops_ai_setup_before_anything_is_created_or_started() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-setup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let data = root.join("app");
        let status = Arc::new(Mutex::new(SetupStatus::default()));
        let progress = Progress {
            user_paused: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            status: status.clone(),
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
        // An older macOS, and (FD-64) one whose version could not be read.
        for (running, code) in [
            (Some((11, 0)), "runtime_os_unsupported"),
            (None, "runtime_os_unknown"),
        ] {
            let result = prepare_on(
                runtime_os_supported("macos", running, ai_runtime_macos_floor()),
                saved.clone(),
                SetupPaths {
                    data: data.clone(),
                    bundle: root.join("absent"),
                    app_version: "test".into(),
                },
                true,
                progress.clone(),
            )
            .await;
            assert_eq!(result.unwrap_err(), code);
            assert!(!data.exists(), "nothing is prepared on such a macOS");
            assert_eq!(*status.lock().unwrap(), SetupStatus::default());
        }
        std::fs::remove_dir_all(&root).unwrap();
        // The worker reports it as a state that waits for the person, with its own code.
        let setup = WorkerSetup::default();
        setup
            .start_work(Arc::new(|_| {}), |_| async {
                Err("runtime_os_unsupported".into())
            })
            .await;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while setup.status().code.is_none() {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let status = setup.status();
        assert_eq!(status.state, "setup-needs-attention");
        assert_eq!(status.code.as_deref(), Some("runtime_os_unsupported"));
    }
    #[test]
    fn a_pause_during_qualification_or_timing_is_waited_out_and_never_decides_the_provider() {
        // Nothing stopped it: the measurement stands.
        assert_eq!(interruption(false, None), None);
        // Battery, memory or sleep: pause with that reason and qualify again.
        for reason in [
            "on_battery",
            "memory_low",
            "system_resumed",
            "status_unavailable",
        ] {
            assert_eq!(
                interruption(false, Some(format!("resource_{reason}"))),
                Some(Ok(reason.to_owned()))
            );
        }
        // The computer slept, whether or not the watcher saw it first.
        assert_eq!(interruption(true, None), Some(Ok("system_resumed".into())));
        assert_eq!(
            interruption(true, Some("resource_on_battery".into())),
            Some(Ok("system_resumed".into()))
        );
        // Anything else (the session could not be kept current) ends the preparation with its
        // own code, which the worker reconnects after where it can.
        assert_eq!(
            interruption(false, Some("worker_request_interrupted".into())),
            Some(Err("worker_request_interrupted".into()))
        );
        // The timing uses it: an interrupted measurement is no longer "speed unknown".
        let source = include_str!("worker_setup.rs");
        let production = &source[..source.find("mod tests {").unwrap()];
        let timing = &production[production.find("if plan.unmeasured(workload)").unwrap()..];
        let settled = timing.find("plan.measured(workload").unwrap();
        assert!(timing[..settled].contains("interruption("));
        assert!(timing[..settled].contains("continue 'qualification"));
    }
    #[tokio::test]
    async fn retry_setup_forgets_remembered_provider_failures_and_an_ordinary_start_keeps_them() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-setup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let record = root.join("provider-failures.json");
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
        let paths = SetupPaths {
            data: root.clone(),
            bundle: root.join("absent"),
            app_version: "test".into(),
        };
        let setup = WorkerSetup::default();
        // The worker starting by itself keeps what it remembered.
        std::fs::write(&record, b"{}").unwrap();
        setup
            .start(saved.clone(), paths.clone(), false, Arc::new(|_| {}))
            .await;
        setup.stop().await;
        assert!(record.exists());
        // Parked, waiting for the person: Retry Setup forgets it before anything else runs.
        setup.status.lock().unwrap().state = "setup-needs-attention".into();
        setup.start(saved, paths, false, Arc::new(|_| {})).await;
        let forgotten = !record.exists();
        setup.stop().await;
        std::fs::remove_dir_all(&root).unwrap();
        assert!(forgotten);
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
        // Not the macOS this suite happens to run on: an older one is refused before the pack.
        let result = prepare_on(
            Ok(()),
            saved,
            SetupPaths {
                data: data.clone(),
                bundle: root.join("absent"),
                app_version: "test".into(),
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
                Step::Dropped(_) | Step::Busy(_) => drop(failures.dropped()),
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
    async fn failed_tasks_in_a_row_slow_the_claims_down_and_never_stop_the_worker() {
        let mut failures = TaskFailures::default();
        for round in 1..=3 * TASK_FAILURE_LIMIT {
            let (delay, show) = failures.dropped();
            assert!(delay >= Duration::from_secs(1) && delay <= Duration::from_secs(64));
            // From the limit on, the reason is shown while waiting.
            assert_eq!(show, round >= TASK_FAILURE_LIMIT);
        }
        failures.completed();
        assert!(!failures.dropped().1);

        // Six refused results in a row: each is a different task, and the seventh is done.
        let server = FakeServer::start();
        let device = server.enrol();
        let saved = SavedSession::default();
        server.queue(&device, 7);
        for _ in 0..6 {
            server.respond_next(
                &device,
                "/result",
                200,
                serde_json::json!({"accepted":false}),
            );
        }
        let done = || server.completed(&device) == 1;
        let (result, refreshes) = run(&server, &device, &saved, false, &|| {}, &done).await;
        assert_eq!(result, Ok(()));
        assert_eq!(refreshes, [false]);
    }

    #[tokio::test]
    async fn a_failing_server_and_an_unknown_refusal_of_one_task_never_stop_the_worker() {
        // 500 is a server in trouble, like 503: retried, whatever it is asked.
        for code in ["server_http_500", "server_http_503", "server_http_520"] {
            assert!(retryable(code), "{code}");
        }
        for code in ["worker_challenge_busy", "worker_qualification_restart"] {
            assert!(retryable(code), "{code}");
        }
        assert!(!retryable("server_http_400"));

        let server = FakeServer::start();
        let device = server.enrol();
        let saved = SavedSession::default();
        server.queue(&device, 2);
        // The claim fails six times over, then a task's input is refused with a status this app
        // has never heard of, then the next task is done: same session throughout.
        for _ in 0..6 {
            server.respond_next(&device, "/claim", 500, serde_json::json!({}));
        }
        server.respond_next(
            &device,
            "/input",
            418,
            serde_json::json!({"message":"teapot"}),
        );
        let done = || server.completed(&device) == 1;
        let (result, refreshes) = run(&server, &device, &saved, false, &|| {}, &done).await;
        assert_eq!(result, Ok(()));
        assert_eq!(refreshes, [false]);
        assert_eq!(server.sessions_issued(&device), 1);
        // The refused task was handed back; the other was done.
        assert_eq!(server.reports(&device), ["fail", "result"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_runtime_that_keeps_dying_stops_the_worker_instead_of_being_set_up_for_ever() {
        for error in ["runtime_process_stopped", "runtime_prediction_interrupted"] {
            let progress = quiet();
            let attempts = AtomicUsize::new(0);
            let result = reconnect(&progress, false, |refresh| {
                attempts.fetch_add(1, Ordering::AcqRel);
                // The session is not at fault: no new one is asked for.
                assert!(!refresh);
                // As the real setup: "working" is announced before the runtime has served.
                progress.set("working", None);
                async move { Err(error.into()) }
            })
            .await;
            assert_eq!(result, Err("runtime_crash_loop".into()), "{error}");
            assert_eq!(attempts.load(Ordering::Acquire), CRASH_LIMIT as usize);
        }
        // A task finished since the last crash: the run of crashes starts again from one.
        let progress = quiet();
        let attempts = AtomicUsize::new(0);
        let result = reconnect(&progress, false, |_| {
            if attempts.fetch_add(1, Ordering::AcqRel) == 2 {
                progress.completed();
            }
            async { Err("runtime_process_stopped".into()) }
        })
        .await;
        assert_eq!(result, Err("runtime_crash_loop".into()));
        assert_eq!(attempts.load(Ordering::Acquire), 5);
    }

    #[tokio::test]
    async fn a_model_change_on_the_server_sets_up_again_at_once_with_the_same_session() {
        let progress = quiet();
        let refreshes = Mutex::new(Vec::new());
        let started = std::time::Instant::now();
        reconnect(&progress, false, |refresh| {
            let mut seen = refreshes.lock().unwrap();
            seen.push(refresh);
            let first = seen.len() == 1;
            async move {
                if first {
                    Err("worker_models_changed".into())
                } else {
                    Ok(())
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(*refreshes.lock().unwrap(), [false, false]);
        // No backoff, and nothing shown as a fault.
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(progress.status.lock().unwrap().state, "");
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_of_every_task_by_the_server_is_waited_out_and_offered_again() {
        // The search model is being changed on the server: minutes, not a stop.
        assert_eq!(
            refused_task_retry("workload_desktop_clip_index_changed"),
            Duration::from_secs(120)
        );
        assert_eq!(
            refused_task_retry("desktop_clip_index_dimensions"),
            Duration::from_secs(120)
        );
        assert_eq!(
            refused_task_retry("workload_desktop_clip_index_incompatible"),
            Duration::from_secs(1800)
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
        let started = tokio::time::Instant::now();
        let result = supervise(
            &progress,
            false,
            |_| {
                let first = attempts.fetch_add(1, Ordering::AcqRel) == 0;
                async move {
                    if first {
                        // What `first_failure` reports when the only task was refused.
                        Err("desktop_clip_index_changed".into())
                    } else {
                        Ok(())
                    }
                }
            },
            || async { None },
            ROUTE_POLL,
        )
        .await;
        assert_eq!(result, Ok(()));
        assert_eq!(attempts.load(Ordering::Acquire), 2);
        assert!(started.elapsed() >= Duration::from_secs(120));
        assert_eq!(
            *statuses.lock().unwrap(),
            [(
                "paused".to_owned(),
                Some("desktop_clip_index_changed".to_owned())
            )]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_runtime_that_never_answers_or_a_server_that_keeps_failing_is_backed_off() {
        // The runtime starts and never becomes healthy: counted like a crash, then stopped.
        let progress = quiet();
        let attempts = AtomicUsize::new(0);
        let result = reconnect(&progress, false, |refresh| {
            attempts.fetch_add(1, Ordering::AcqRel);
            assert!(!refresh);
            progress.set("working", None);
            async { Err("runtime_not_ready".into()) }
        })
        .await;
        assert_eq!(result, Err("runtime_crash_loop".into()));
        assert_eq!(attempts.load(Ordering::Acquire), CRASH_LIMIT as usize);

        // "working" is announced before the server has answered anything: it does not make the
        // next wait short again. Five failures in a row wait 1-2, 2-4, 4-8, 8-16 and 16-32 s.
        let progress = quiet();
        let attempts = AtomicUsize::new(0);
        let started = tokio::time::Instant::now();
        reconnect(&progress, false, |_| {
            let failing = attempts.fetch_add(1, Ordering::AcqRel) < 5;
            progress.set("working", None);
            async move {
                match failing {
                    true => Err("server_http_503".into()),
                    false => Ok(()),
                }
            }
        })
        .await
        .unwrap();
        assert!(started.elapsed() >= Duration::from_secs(31));
    }

    #[tokio::test(start_paused = true)]
    async fn a_finished_task_ends_the_run_of_crashes_and_a_crash_asks_for_no_new_session() {
        // Two crashes, then an attempt that finishes a task and loses the connection, then a
        // crash: that is one crash since the last finished task, not three.
        let progress = quiet();
        let attempts = AtomicUsize::new(0);
        let refreshes = Mutex::new(Vec::new());
        let result = reconnect(&progress, false, |refresh| {
            refreshes.lock().unwrap().push(refresh);
            let attempt = attempts.fetch_add(1, Ordering::AcqRel);
            if attempt == 2 {
                progress.completed();
            }
            async move {
                match attempt {
                    0 | 1 | 3 => Err("runtime_process_stopped".into()),
                    2 => Err("worker_request_interrupted".into()),
                    _ => Ok(()),
                }
            }
        })
        .await;
        assert_eq!(result, Ok(()));
        // The lost connection asks for a new session once; the crash after it does not ask again.
        assert_eq!(
            *refreshes.lock().unwrap(),
            [false, false, false, true, false]
        );
    }

    #[test]
    fn a_refusal_that_passes_by_itself_outranks_another_tasks_fault() {
        let status = |workload: &str, code: &str| WorkloadStatus {
            workload: workload.into(),
            state: "unavailable".into(),
            model_names: vec![],
            code: Some(code.into()),
        };
        // Smart search failed its check here; text recognition is only held back for five
        // minutes. Stopping over the first would never offer the second again.
        assert_eq!(
            first_failure(&[
                status("clip", "runtime_output_mismatch"),
                status("ocr", "workload_desktop_qualification_hold"),
            ]),
            "desktop_qualification_hold"
        );
        assert!(server_task_refusal("desktop_qualification_hold"));
        // Smart search is refused for 30 minutes and text recognition held for 5½: the wait
        // is the shorter one, whatever order the tasks come in.
        for order in [["clip", "ocr"], ["ocr", "clip"]] {
            let code = |task: &str| match task {
                "clip" => "workload_desktop_clip_index_incompatible",
                _ => "workload_desktop_qualification_hold",
            };
            assert_eq!(
                first_failure(&[
                    status(order[0], code(order[0])),
                    status(order[1], code(order[1]))
                ]),
                "desktop_qualification_hold"
            );
        }
    }

    #[tokio::test]
    async fn several_tasks_run_at_once_and_each_free_slot_is_refilled_at_once() {
        use crate::native_predictor::pool_with;
        let server = FakeServer::start();
        server.offer_concurrent_leases(3);
        let device = server.enrol();
        let worker = server.session(&device).await.unwrap();
        let qualification = server.qualification(&worker).await;
        server.queue(&device, 5);
        let (_keep, mut cancel) = tokio::sync::watch::channel(false);
        let (running, most, started) = (
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        );
        let (slow_running, refilled) = (AtomicBool::new(false), AtomicBool::new(false));
        // The first task is held until both replacements have started; the second and third
        // are held until all three are at work.
        let (slow, quick) = (
            tokio::sync::Semaphore::new(0),
            tokio::sync::Semaphore::new(0),
        );
        let quals = [&qualification];
        let work = pool_with(&worker, &quals, &mut cancel, Some(3), |_| async {
            let now = running.fetch_add(1, Ordering::AcqRel) + 1;
            most.fetch_max(now, Ordering::AcqRel);
            match started.fetch_add(1, Ordering::AcqRel) {
                0 => {
                    slow_running.store(true, Ordering::Release);
                    slow.acquire().await.unwrap().forget();
                    slow_running.store(false, Ordering::Release);
                }
                order @ 1..=2 => {
                    if order == 2 {
                        quick.add_permits(2);
                    }
                    quick.acquire().await.unwrap().forget();
                }
                // A fourth and fifth task started while the slow one was still at work.
                order => {
                    if slow_running.load(Ordering::Acquire) {
                        refilled.store(true, Ordering::Release);
                    }
                    if order == 4 {
                        slow.add_permits(1);
                    }
                }
            }
            running.fetch_sub(1, Ordering::AcqRel);
            Ok(serde_json::json!({}))
        });
        let steps = tokio::time::timeout(Duration::from_secs(20), work)
            .await
            .expect("a free place was not refilled")
            .unwrap();
        // Room for three: never more than three at once, and all five done.
        assert_eq!(steps, [const { Step::Completed }; 5]);
        assert_eq!(most.load(Ordering::Acquire), 3);
        assert_eq!(server.completed(&device), 5);
        // The slow task did not hold the other slots up: they were refilled as they emptied.
        assert!(refilled.load(Ordering::Acquire));
        // The first claim waits for work; the ones made with tasks in hand do not hold the
        // line, and every one says how much room there is.
        let (slots, waits) = server.claims();
        assert_eq!(slots[..3], [3, 2, 1]);
        assert_eq!(waits[..3], [20_000, 0, 0]);
        assert!(
            waits[3..waits.len() - 1].iter().all(|wait| *wait == 0),
            "{waits:?}"
        );

        // One task the model refuses is that task's outcome only: the others are done.
        server.queue(&device, 2);
        let turn = AtomicUsize::new(0);
        let steps = pool_with(&worker, &[&qualification], &mut cancel, Some(3), |_| {
            let refused = turn.fetch_add(1, Ordering::AcqRel) == 0;
            async move {
                match refused {
                    true => Err("runtime_prediction_refused".into()),
                    false => Ok(serde_json::json!({})),
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps
                .iter()
                .filter(|step| **step == Step::Completed)
                .count(),
            1
        );
        assert_eq!(server.failures(), ["input-invalid"]);
        assert_eq!(server.completed(&device), 6);
    }

    #[tokio::test]
    async fn a_refused_input_keeps_the_runtime_and_the_next_claim_waits_out_the_backoff() {
        use crate::native_predictor::{run_pool, Pool, TaskStep};
        let server = FakeServer::start();
        let device = server.enrol();
        let worker = server.session(&device).await.unwrap();
        let qualification = server.qualification(&worker).await;
        server.queue(&device, 2);
        let (_keep, mut cancel) = tokio::sync::watch::channel(false);
        let (stopped, predictions) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let dropped_at = std::sync::Mutex::new(None);
        let waited = std::sync::Mutex::new(None);
        let pool = Pool {
            slots: &|| None,
            keep_claiming: &|| true,
            abandon: &|| {
                stopped.fetch_add(1, Ordering::AcqRel);
            },
        };
        let mut reported = Vec::new();
        let on_step = |task: TaskStep| {
            if let Step::Dropped(_) = task.step {
                reported.push(task.reported);
                *dropped_at.lock().unwrap() = Some(std::time::Instant::now());
                return Some(Duration::from_millis(300));
            }
            Some(Duration::ZERO)
        };
        let predict = |_, _, _| async {
            if predictions.fetch_add(1, Ordering::AcqRel) == 0 {
                return Err("runtime_prediction_refused".to_string());
            }
            *waited.lock().unwrap() = dropped_at.lock().unwrap().map(|at| at.elapsed());
            Ok(serde_json::json!({}))
        };
        let quals = [&qualification];
        run_pool(
            &worker,
            &quals,
            &mut cancel,
            &pool,
            |_| {},
            on_step,
            predict,
        )
        .await
        .unwrap();
        // The model answered: its process is left serving, and the server acknowledged the report.
        assert_eq!(stopped.load(Ordering::Acquire), 0);
        assert_eq!(server.failures(), ["input-invalid"]);
        assert_eq!(reported, [true]);
        // The only task in hand was dropped: the pool held the next claim off itself.
        assert!(waited.lock().unwrap().unwrap() >= Duration::from_millis(300));
        assert_eq!(server.completed(&device), 1);
    }

    #[tokio::test]
    async fn a_claim_held_off_stays_held_off_when_the_runtime_must_be_loaded_again() {
        // The pool ended early (the runtime was stopped under the dropped task): what is left
        // of the pause is waited before the models are loaded and the next claim is made.
        let cancel = AtomicBool::new(false);
        let (start, pause) = (tokio::time::Instant::now(), Duration::from_millis(200));
        hold_off(Some(start + pause), &cancel).await.unwrap();
        assert!(start.elapsed() >= pause);
        // Nothing held off, or the pause already over: no wait.
        let again = tokio::time::Instant::now();
        hold_off(None, &cancel).await.unwrap();
        hold_off(Some(start), &cancel).await.unwrap();
        assert!(again.elapsed() < pause);
        // A stop ends the wait.
        cancel.store(true, Ordering::Release);
        let far = tokio::time::Instant::now() + Duration::from_secs(60);
        assert_eq!(
            hold_off(Some(far), &cancel).await,
            Err("worker_setup_cancelled".into())
        );
    }

    #[tokio::test]
    async fn a_lease_that_arrives_after_claiming_stopped_is_handed_straight_back() {
        use crate::native_predictor::{run_pool, Pool, TaskStep};
        let server = FakeServer::start();
        server.offer_concurrent_leases(2);
        // A slow link: a claim for more room is still on its way when the first task ends.
        server.slow_claims(Duration::from_millis(400));
        let device = server.enrol();
        let worker = server.session(&device).await.unwrap();
        let qualification = server.qualification(&worker).await;
        server.queue(&device, 1);
        let (_keep, mut cancel) = tokio::sync::watch::channel(false);
        let pool = Pool {
            slots: &|| Some(2),
            keep_claiming: &|| true,
            abandon: &|| {},
        };
        let predictions = AtomicUsize::new(0);
        let predict = |_, _, _| async {
            predictions.fetch_add(1, Ordering::AcqRel);
            // The claim that waited for work, a claim for more room (nothing there), and now
            // a second one: it has reached the server, which is about to lease it a new task.
            while server.claims_received() < 3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            server.queue(&device, 1);
            // Ends without a word to the server, as a lease the server took back does.
            Err("worker_lease_lost".to_string())
        };
        // As the owner that must qualify again: no more claims.
        let on_step = |task: TaskStep| match task.step {
            Step::Dropped(_) => None,
            _ => Some(Duration::ZERO),
        };
        let quals = [&qualification];
        let work = run_pool(
            &worker,
            &quals,
            &mut cancel,
            &pool,
            |_| {},
            on_step,
            predict,
        );
        tokio::time::timeout(Duration::from_secs(20), work)
            .await
            .expect("the pool did not end")
            .unwrap();
        // The second task was leased by the claim already sent, and went straight back.
        assert_eq!(predictions.load(Ordering::Acquire), 1);
        assert_eq!(server.failures(), ["cancelled"]);
    }

    #[tokio::test]
    async fn a_lease_that_arrives_after_a_pause_is_handed_straight_back() {
        use crate::native_predictor::{run_pool, Pool};
        let server = FakeServer::start();
        let device = server.enrol();
        let worker = server.session(&device).await.unwrap();
        let qualification = server.qualification(&worker).await;
        server.queue(&device, 1);
        let (_keep, mut cancel) = tokio::sync::watch::channel(false);
        // Wanted when the claim is sent, paused by the time it is answered.
        let asked = AtomicUsize::new(0);
        let pool = Pool {
            slots: &|| None,
            keep_claiming: &|| asked.fetch_add(1, Ordering::AcqRel) == 0,
            abandon: &|| {},
        };
        let predictions = AtomicUsize::new(0);
        let predict = |_, _, _| async {
            predictions.fetch_add(1, Ordering::AcqRel);
            Ok(serde_json::json!({}))
        };
        let quals = [&qualification];
        let on_step = |_| Some(Duration::ZERO);
        run_pool(
            &worker,
            &quals,
            &mut cancel,
            &pool,
            |_| {},
            on_step,
            predict,
        )
        .await
        .unwrap();
        assert_eq!(predictions.load(Ordering::Acquire), 0);
        assert_eq!(server.failures(), ["cancelled"]);
        assert!(!server.handled().contains(&"input".to_string()));
    }

    #[tokio::test]
    async fn a_runtime_that_ends_under_several_tasks_is_reported_as_one_failure() {
        use crate::native_predictor::pool_with;
        let server = FakeServer::start();
        server.offer_concurrent_leases(3);
        let device = server.enrol();
        let worker = server.session(&device).await.unwrap();
        let qualification = server.qualification(&worker).await;
        server.queue(&device, 3);
        let (_keep, mut cancel) = tokio::sync::watch::channel(false);
        let in_hand = AtomicUsize::new(0);
        let all_in_hand = tokio::sync::Notify::new();
        // The process ends with three tasks in hand: each prediction fails the same way.
        let result = pool_with(
            &worker,
            &[&qualification],
            &mut cancel,
            Some(3),
            |_| async {
                if in_hand.fetch_add(1, Ordering::AcqRel) == 2 {
                    all_in_hand.notify_waiters();
                } else {
                    all_in_hand.notified().await;
                }
                Err("runtime_process_stopped".into())
            },
        )
        .await;
        assert_eq!(result, Err("runtime_process_stopped".into()));
        // The server, which withdraws a model after three failed tasks in a row, hears of one
        // failure; the other two tasks go straight back in line.
        // The failure is told first: the server takes the hand-backs after it as part of it.
        assert_eq!(
            server.failures(),
            ["model-unavailable", "cancelled", "cancelled"]
        );
    }

    #[tokio::test]
    async fn a_stop_hands_back_every_lease_it_holds() {
        use crate::native_predictor::pool_with;
        let server = FakeServer::start();
        server.offer_concurrent_leases(3);
        let device = server.enrol();
        let worker = server.session(&device).await.unwrap();
        let qualification = server.qualification(&worker).await;
        server.queue(&device, 3);
        let (stop, mut cancel) = tokio::sync::watch::channel(false);
        let predicting = AtomicUsize::new(0);
        let all_running = tokio::sync::Notify::new();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            returning_lease(
                pool_with(
                    &worker,
                    &[&qualification],
                    &mut cancel,
                    Some(3),
                    |_| async {
                        if predicting.fetch_add(1, Ordering::AcqRel) == 2 {
                            all_running.notify_one();
                        }
                        std::future::pending::<Result<serde_json::Value, String>>().await
                    },
                ),
                async {
                    all_running.notified().await;
                    "worker_setup_cancelled".to_owned()
                },
                &stop,
                LEASE_RETURN,
            ),
        )
        .await
        .expect("the stop waited for the tasks");
        assert_eq!(result, Err("worker_setup_cancelled".into()));
        assert_eq!(server.failures(), ["cancelled", "cancelled", "cancelled"]);
    }

    #[test]
    fn the_number_of_tasks_at_once_follows_the_server_and_this_computers_limits() {
        const GB: u64 = 1024 * 1024 * 1024;
        // The processor: one task, or two with eight cores, memory allowing.
        assert_eq!(local_capacity(false, 4, Some(32 * GB), 2 * GB), 1);
        assert_eq!(local_capacity(false, 8, Some(32 * GB), 2 * GB), 2);
        assert_eq!(local_capacity(false, 16, Some(32 * GB), 2 * GB), 2);
        // A graphics card or neural engine: up to eight, by the memory that is free beside
        // the models (2 GB of models: half a gigabyte of working memory for each task).
        assert_eq!(local_capacity(true, 8, Some(32 * GB), 2 * GB), 8);
        assert_eq!(local_capacity(true, 8, Some(3 * GB), 2 * GB), 2);
        assert_eq!(local_capacity(true, 8, Some(GB), 2 * GB), 1);
        // Free memory that can't be read is one task.
        assert_eq!(local_capacity(true, 8, None, 2 * GB), 1);

        let inventory = serde_json::json!({"workloads":[
            {"workload":"clip","state":"eligible","concurrency":4},
            {"workload":"face","state":"eligible","concurrency":2},
            {"workload":"ocr","state":"eligible"},
            {"workload":"enrichment","state":"unsupported","concurrency":900},
        ]});
        let limits = inventory_concurrency(&inventory);
        assert_eq!(limits["clip"], 4);
        // A reply that does not say (an older server) is one; a nonsense number is capped.
        assert_eq!((limits["ocr"], limits["enrichment"]), (1, 64));
        let ready = |tasks: &[&str]| tasks.iter().map(|task| task.to_string()).collect();
        // What the server allows for the ready tasks, capped by this computer...
        assert_eq!(
            concurrent_tasks(&limits, &ready(&["clip", "face"]), 8, None),
            6
        );
        assert_eq!(
            concurrent_tasks(&limits, &ready(&["clip", "face"]), 3, None),
            3
        );
        assert_eq!(concurrent_tasks(&limits, &ready(&["ocr"]), 8, None), 1);
        // ...and by what it managed since it last ran short of memory.
        assert_eq!(
            concurrent_tasks(&limits, &ready(&["clip", "face"]), 8, Some(1)),
            1
        );

        // Running short lowers the number; it is not raised by being told a higher one.
        let progress = quiet();
        progress.running_at_once(6);
        progress.lower_capacity(3);
        progress.lower_capacity(5);
        assert_eq!(progress.capacity_ceiling(), Some(3));
        progress.set("working", None);
        assert_eq!(progress.capacity_ceiling(), Some(3));
        assert_eq!(progress.status.lock().unwrap().concurrent_tasks, 3);
    }

    #[test]
    fn a_runtime_that_ends_is_judged_by_the_tasks_it_had_in_hand() {
        // The processor's runtime did not start (nothing in hand): never a matter of memory,
        // whatever the allowance.
        let mut trouble = RuntimeTrouble::default();
        assert_eq!(trouble.crashed(0, false, false), AfterCrash::Failing);
        assert_eq!(trouble.crashed(0, false, true), AfterCrash::Failing);
        // Several in hand: half as many each time, on the same runtime, down to one.
        assert_eq!(trouble.crashed(8, false, false), AfterCrash::Fewer(4));
        assert_eq!(trouble.crashed(4, true, true), AfterCrash::Fewer(2));
        assert_eq!(trouble.crashed(3, true, true), AfterCrash::Fewer(1));
        assert_eq!(trouble.crashed(2, true, true), AfterCrash::Fewer(1));
        // One task in hand on a graphics card: it keeps the work. The same runtime again,
        // twice, and only the third crash in a row is a failing runtime.
        assert_eq!(trouble.crashed(1, true, true), AfterCrash::Again(1));
        assert_eq!(trouble.crashed(1, true, true), AfterCrash::Again(2));
        assert_eq!(trouble.crashed(1, true, true), AfterCrash::Failing);
        // After that the count starts again (the card is tried again later).
        assert_eq!(trouble.crashed(1, true, false), AfterCrash::Again(1));
        // Its process found gone between tasks is a crash like any other: one of the three.
        assert_eq!(trouble.crashed(0, true, false), AfterCrash::Again(2));
        assert_eq!(trouble.crashed(0, true, false), AfterCrash::Failing);
        // A task finished in between starts that count again too.
        let mut trouble = RuntimeTrouble::default();
        assert_eq!(trouble.crashed(1, true, false), AfterCrash::Again(1));
        assert_eq!(trouble.crashed(1, true, false), AfterCrash::Again(2));
        // The processor finishing other work in between does not end the row.
        assert_eq!(trouble.completed(false), (false, false));
        assert_eq!(trouble.crashed(1, true, false), AfterCrash::Failing);
        assert_eq!(trouble.crashed(1, true, false), AfterCrash::Again(1));
        assert_eq!(trouble.completed(true), (false, false));
        assert_eq!(trouble.crashed(1, true, false), AfterCrash::Again(1));
        // The processor's runtime crashing does not undo the graphics card's run of
        // finished tasks; a crash of its own does.
        let mut trouble = RuntimeTrouble::default();
        for _ in 1..CLEAN_RUN {
            assert!(!trouble.completed(true).1);
        }
        assert_eq!(trouble.crashed(2, false, false), AfterCrash::Fewer(1));
        assert!(trouble.completed(true).1);
        for _ in 1..CLEAN_RUN {
            assert!(!trouble.completed(true).1);
        }
        assert_eq!(trouble.crashed(2, true, false), AfterCrash::Fewer(1));
        assert!(!trouble.completed(true).1);
        // The third crash under a task dropped for its own reason is still the runtime
        // crashing out; a hand-back and a crash code are kept as they are.
        let out = |crash, code: &str| crashed_out(crash, code.to_owned());
        let failing = Some(AfterCrash::Failing);
        assert_eq!(
            out(failing, "worker_execution_deadline"),
            "runtime_process_stopped"
        );
        assert_eq!(out(failing, "worker_cancelled"), "worker_cancelled");
        assert_eq!(out(failing, "resource_memory"), "resource_memory");
        assert_eq!(
            out(failing, "runtime_prediction_interrupted"),
            "runtime_prediction_interrupted"
        );
        assert_eq!(
            out(None, "worker_execution_deadline"),
            "worker_execution_deadline"
        );
        // Three acknowledged deadline failures of one model ask to qualify again at the same
        // moment the third crash is judged: the crash-out is still what the work loop acts on
        // first (it checks `AfterCrash::Failing` before `requalify`).
        let (mut trouble, mut strikes) = (RuntimeTrouble::default(), GrantStrikes::default());
        let mut last = (None, false);
        for _ in 0..CRASHES_AT_ONE {
            let requalify = strikes.failed(Some("clip"), "worker_execution_deadline");
            last = (Some(trouble.crashed(1, true, false)), requalify);
        }
        assert_eq!(last, (failing, true));
        assert_eq!(
            out(last.0, "worker_execution_deadline"),
            "runtime_process_stopped"
        );
        // The processor's own runtime has nowhere to fall back to. One task at a time from
        // the start: failing at the first crash, counted by the restarts, as it always was.
        let mut trouble = RuntimeTrouble::default();
        assert_eq!(trouble.crashed(1, false, false), AfterCrash::Failing);
        // At one after stepping down: the same runtime once more, then it is failing; a
        // task finished in between starts that count again.
        assert_eq!(trouble.crashed(1, false, true), AfterCrash::Again(1));
        assert_eq!(trouble.completed(false), (false, false));
        assert_eq!(trouble.crashed(1, false, true), AfterCrash::Again(1));
        assert_eq!(trouble.crashed(1, false, true), AfterCrash::Failing);

        // A long run of finished tasks lets one more run at once; trouble starts the run again.
        let mut trouble = RuntimeTrouble::default();
        for _ in 1..CLEAN_RUN {
            assert_eq!(trouble.completed(false), (false, false));
        }
        trouble.refused(false);
        for _ in 1..CLEAN_RUN {
            assert_eq!(trouble.completed(false), (false, false));
        }
        // Only the processor's tasks: one more at once, and no word on the graphics card.
        assert_eq!(trouble.completed(false), (true, false));
        // The graphics card has recovered after as long a run of its own tasks.
        for _ in 1..CLEAN_RUN {
            assert!(!trouble.completed(true).1);
        }
        assert!(trouble.completed(true).1);
        // A task of its own dropped in between starts that run again; the processor's does not.
        for _ in 1..CLEAN_RUN {
            assert!(!trouble.completed(true).1);
        }
        trouble.refused(false);
        trouble.refused(true);
        assert!(!trouble.completed(true).1);
        let progress = quiet();
        progress.raise_capacity();
        assert_eq!(progress.capacity_ceiling(), None);
        progress.lower_capacity(2);
        progress.raise_capacity();
        assert_eq!(progress.capacity_ceiling(), Some(3));
    }

    #[tokio::test]
    async fn a_crash_under_the_pool_lowers_what_runs_at_once_by_the_tasks_in_hand() {
        use crate::native_predictor::{run_pool, Pool, TaskStep};
        // Wired as the work loop wires it: the pool's claims and settled tasks are counted,
        // and when the pool ends with the runtime's failure the count decides what follows.
        let crash = |slots: u32, tasks: u32, accelerated: bool| async move {
            let server = FakeServer::start();
            server.offer_concurrent_leases(slots.max(2));
            let device = server.enrol();
            let worker = server.session(&device).await.unwrap();
            let qualification = server.qualification(&worker).await;
            server.queue(&device, tasks);
            let (_keep, mut cancel) = tokio::sync::watch::channel(false);
            let (in_hand, started) = (InHand::default(), AtomicUsize::new(0));
            let all_in_hand = tokio::sync::Notify::new();
            let room = || Some(slots);
            let pool = Pool {
                slots: &room,
                keep_claiming: &|| true,
                abandon: &|| {},
            };
            // The process ends once every task is in hand: each prediction fails the same way.
            let predict = |_, _, _| async {
                if started.fetch_add(1, Ordering::AcqRel) as u32 + 1 == tasks {
                    all_in_hand.notify_waiters();
                } else {
                    all_in_hand.notified().await;
                }
                Err("runtime_process_stopped".to_string())
            };
            let on_step = |task: TaskStep| {
                in_hand.settled(&task);
                Some(Duration::ZERO)
            };
            let quals = [&qualification];
            let ended = run_pool(
                &worker,
                &quals,
                &mut cancel,
                &pool,
                |_| in_hand.claimed(),
                on_step,
                predict,
            )
            .await;
            assert_eq!(ended, Err("runtime_process_stopped".into()));
            assert!(runtime_crash("runtime_process_stopped"));
            let progress = quiet();
            progress.running_at_once(slots);
            let mut trouble = RuntimeTrouble::default();
            let after = after_crash(&mut trouble, &progress, in_hand.count(), accelerated);
            (in_hand.count(), after, progress.capacity_ceiling())
        };
        // Four allowed, three in hand when it ended: one at once from here on, same runtime.
        assert_eq!(crash(4, 3, true).await, (3, AfterCrash::Fewer(1), Some(1)));
        // One in hand on a graphics card: nothing lowered, the same runtime again.
        assert_eq!(crash(4, 1, true).await, (1, AfterCrash::Again(1), None));
        // One in hand on the processor: a failing runtime, nothing lowered.
        assert_eq!(crash(1, 1, false).await, (1, AfterCrash::Failing, None));
    }

    #[tokio::test]
    async fn a_graphics_card_whose_runtime_dies_under_one_task_keeps_the_work_until_the_third() {
        use crate::native_predictor::{testing::DyingRuntime, Pool, TaskStep};
        use crate::provider_selection::tests::{directory, end_rest, plan_on};
        // The real predictor over a real runtime process that ends by itself when its one
        // task reaches it, three times in a row, judged as the work loop judges it.
        let runtime = DyingRuntime::build();
        let manifest = runtime.manifest().to_owned();
        let data = directory();
        let mut plan = plan_on(&data, &manifest, "driver-1");
        assert!(plan.accelerates(&manifest));
        let server = FakeServer::start();
        let device = server.enrol();
        let worker = server.session(&device).await.unwrap();
        let qualification = server.qualification(&worker).await;
        let (progress, mut trouble) = (quiet(), RuntimeTrouble::default());
        let mut judged = Vec::new();
        for crash in 1..=CRASHES_AT_ONE {
            server.queue(&device, 1);
            let mut predictor = runtime.start("fixture-model", qualification.id());
            let (_keep, mut cancel) = tokio::sync::watch::channel(false);
            let claimed = AtomicUsize::new(0);
            let pool = Pool {
                slots: &|| None,
                keep_claiming: &|| claimed.load(Ordering::Acquire) == 0,
                abandon: &|| {},
            };
            let quals = [&qualification];
            let before = server.claims_received();
            let ended = predictor
                .work(
                    &worker,
                    &quals,
                    &mut cancel,
                    &pool,
                    |_| {},
                    |_: TaskStep| {
                        claimed.fetch_add(1, Ordering::AcqRel);
                        Some(Duration::ZERO)
                    },
                )
                .await;
            // Its one task was leased, the prediction broke off, and the predictor (which
            // then stops every process itself) still names the runtime that died.
            assert!(server.claims_received() > before);
            assert_eq!(ended, Err("runtime_prediction_interrupted".into()));
            assert_eq!(predictor.failed_lane(), Some(manifest.as_str()));
            assert!(!predictor.is_running().unwrap());
            // One task in hand (the fixture's model key names no workload, so the claim
            // is not announced to the caller here).
            let lane = predictor.failed_lane();
            judged.push(judge(&mut trouble, &progress, &plan, &ended, None, 1, lane));
            if crash < CRASHES_AT_ONE {
                // The graphics card keeps the work, and nothing rests.
                assert!(plan.accelerates(&manifest) && plan.rest_ends().is_none());
            }
        }
        assert_eq!(
            judged,
            [
                Some(AfterCrash::Again(1)),
                Some(AfterCrash::Again(2)),
                Some(AfterCrash::Failing)
            ]
        );
        assert_eq!(progress.capacity_ceiling(), None);
        // The third: the work loop moves that runtime's work to the processor, with the
        // reason, and it rests.
        assert!(plan.demote_runtime(&manifest, "runtime_prediction_interrupted"));
        assert!(!plan.accelerates(&manifest) && plan.rest_ends().is_some());
        let next = plan_on(&data, &manifest, "driver-1");
        assert!(next.rest_ends().is_some() && !next.accelerates(&manifest));
        assert!(next
            .providers()
            .iter()
            .any(|chosen| chosen.fallback.as_deref() == Some("runtime_prediction_interrupted")));
        // After the rest the plan made then tries the graphics card again.
        end_rest(&data);
        let again = plan_on(&data, &manifest, "driver-1");
        assert!(again.accelerates(&manifest) && again.rest_ends().is_none());
        crate::provider_selection::forget(&data);
        let _ = std::fs::remove_dir_all(data);
    }

    #[tokio::test]
    async fn claims_for_more_room_back_off_and_a_finished_task_asks_at_once() {
        use crate::native_predictor::pool_with;
        let server = FakeServer::start();
        server.offer_concurrent_leases(2);
        let device = server.enrol();
        let worker = server.session(&device).await.unwrap();
        let qualification = server.qualification(&worker).await;
        server.queue(&device, 1);
        let (_keep, mut cancel) = tokio::sync::watch::channel(false);
        let finished = std::sync::Mutex::new(None);
        let quals = [&qualification];
        // One task in hand for a little over three seconds, with room for a second and
        // nothing more to give: claims at once, then after 1 and 2 seconds (the next would
        // be 4 seconds on), and one more as soon as the task is done.
        let steps = pool_with(&worker, &quals, &mut cancel, Some(2), |_| async {
            tokio::time::sleep(Duration::from_millis(3600)).await;
            *finished.lock().unwrap() = Some(std::time::Instant::now());
            Ok(serde_json::json!({}))
        })
        .await
        .unwrap();
        assert_eq!(steps, [Step::Completed]);
        let finished = finished.lock().unwrap().unwrap();
        let times = server.claim_times();
        // The claim that waited for work, three for more room, the one after the task.
        assert!(times.len() >= 5, "{times:?}");
        let gap = |a: usize, b: usize| times[b].duration_since(times[a]).as_millis();
        assert!((900..1900).contains(&gap(1, 2)), "{}", gap(1, 2));
        assert!((1900..3400).contains(&gap(2, 3)), "{}", gap(2, 3));
        // Not four seconds after the last, as the back-off alone would have it.
        let after = times[4].saturating_duration_since(finished).as_millis();
        assert!(after < 900, "{after}");
        assert!(gap(3, 4) < 3900, "{}", gap(3, 4));
        // The waits the pool uses, in full: 1, 2, 4 and 8 seconds, and never more than 8.
        let waits: Vec<u64> = (0..7)
            .map(|empty| crate::native_predictor::refill_wait(empty).as_secs())
            .collect();
        assert_eq!(waits, [1, 2, 4, 8, 8, 8, 8]);
        assert_eq!(crate::native_predictor::refill_wait(u32::MAX).as_secs(), 8);
    }

    #[tokio::test]
    async fn the_one_report_of_a_crash_is_sent_again_when_it_does_not_arrive() {
        use crate::native_predictor::pool_with;
        let server = FakeServer::start();
        let device = server.enrol();
        let worker = server.session(&device).await.unwrap();
        let qualification = server.qualification(&worker).await;
        server.queue(&device, 1);
        server.respond_next(&device, "/fail", 503, serde_json::json!({}));
        let (_keep, mut cancel) = tokio::sync::watch::channel(false);
        let quals = [&qualification];
        let result = pool_with(&worker, &quals, &mut cancel, None, |_| async {
            Err("runtime_process_stopped".into())
        })
        .await;
        assert_eq!(result, Err("runtime_process_stopped".into()));
        assert_eq!(server.failures(), ["model-unavailable"]);
    }

    #[test]
    fn failed_tasks_are_counted_for_each_model_as_the_server_counts_them() {
        let (clip, face) = (Some("clip:a"), Some("face:b"));
        let mut strikes = GrantStrikes::default();
        // Two failures for one model, with results for another in between: the third still
        // means the server has withdrawn the first.
        assert!(!strikes.failed(clip, "worker_execution_deadline"));
        strikes.completed(face);
        assert!(!strikes.failed(clip, "server_http_400"));
        strikes.completed(face);
        assert!(strikes.failed(clip, "runtime_process_stopped"));
        // Counted from nothing again after qualifying, and reset by that model's own result.
        assert!(!strikes.failed(clip, "worker_execution_deadline"));
        assert!(!strikes.failed(clip, "worker_execution_deadline"));
        strikes.completed(clip);
        assert!(!strikes.failed(clip, "worker_execution_deadline"));
        // What the server does not count is not counted here, nor a step that claimed nothing.
        for _ in 0..5 {
            assert!(!strikes.failed(face, "worker_cancelled"));
            assert!(!strikes.failed(face, "worker_input_invalid"));
            assert!(!strikes.failed(None, "worker_execution_deadline"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn only_the_servers_task_refusals_are_waited_out_as_refused_tasks() {
        for code in [
            "desktop_clip_index_changed",
            "desktop_clip_index_incompatible",
            "desktop_clip_space_unavailable",
            "desktop_model_profile_unavailable",
            "desktop_pool_model_unavailable",
        ] {
            assert!(server_task_refusal(code), "{code}");
        }
        // This app's own codes stop the worker and say what they mean.
        for code in [
            "desktop_protocol_unsupported",
            "desktop_worker_session_unavailable",
            "desktop_enrollment_required",
        ] {
            assert!(!server_task_refusal(code), "{code}");
            let attempts = AtomicUsize::new(0);
            let result = supervise(
                &quiet(),
                false,
                |_| {
                    attempts.fetch_add(1, Ordering::AcqRel);
                    async move { Err(code.into()) }
                },
                || async { None },
                ROUTE_POLL,
            )
            .await;
            assert_eq!(result, Err(code.into()));
            assert_eq!(attempts.load(Ordering::Acquire), 1);
        }
        // A timestamp the server refused: waited out and tried again, with the reason shown.
        let statuses = Arc::new(Mutex::new(Vec::new()));
        let seen = statuses.clone();
        let progress = Progress {
            notify: Arc::new(move |status: SetupStatus| {
                seen.lock().unwrap().push((status.state, status.code))
            }),
            ..quiet()
        };
        let attempts = AtomicUsize::new(0);
        let result = supervise(
            &progress,
            false,
            |_| {
                let first = attempts.fetch_add(1, Ordering::AcqRel) == 0;
                async move {
                    match first {
                        true => Err("clock_invalid".into()),
                        false => Ok(()),
                    }
                }
            },
            || async { None },
            ROUTE_POLL,
        )
        .await;
        assert_eq!(result, Ok(()));
        assert_eq!(
            *statuses.lock().unwrap(),
            [("paused".to_owned(), Some("clock_invalid".to_owned()))]
        );
    }

    #[test]
    fn the_models_to_run_are_compared_by_task_state_and_model_keys() {
        let current = inventory_fixture();
        let signature = inventory_signature(&current);
        assert_eq!(signature.len(), 4);
        // The same answer, with something new a later server adds and in another order.
        let mut same = current.clone();
        same["workloads"].as_array_mut().unwrap().reverse();
        same["workloads"][0]["somethingNew"] = serde_json::json!(true);
        assert_eq!(inventory_signature(&same), signature);
        // Another model for a task.
        assert_ne!(
            inventory_signature(&inventory_fixture_with("ViT-B-32__openai")),
            signature
        );
        // A task turned off, and one turned on.
        let mut disabled = current.clone();
        disabled["workloads"][1]["state"] = serde_json::json!("disabled");
        disabled["workloads"][1]["modelKeys"] = serde_json::json!([]);
        assert_ne!(inventory_signature(&disabled), signature);
        assert_ne!(
            inventory_signature(&current),
            inventory_signature(&disabled)
        );
    }

    #[test]
    fn a_new_field_in_the_inventory_is_ignored_but_a_changed_profile_is_still_refused() {
        let source = "25b22c16e47a27a2eb50017d838497abce850d11";
        let mut value = inventory_fixture();
        value["somethingNew"] = serde_json::json!({"a":1});
        value["workloads"][0]["somethingNew"] = serde_json::json!("x");
        let (groups, _) = inventory_profiles(&value, source, "CPUExecutionProvider").unwrap();
        assert_eq!(groups.len(), 3);
        // The profile is hashed into its model key: nothing may be added to it.
        value["workloads"][0]["profiles"][0]["somethingNew"] = serde_json::json!(1);
        assert!(inventory_profiles(&value, source, "CPUExecutionProvider").is_err());
    }

    #[test]
    fn a_refusal_while_qualifying_is_retried_scoped_or_moved_to_the_processor() {
        use crate::provider_selection::CPU;
        const CUDA: &str = "CUDAExecutionProvider";
        for provider in [CPU, CUDA] {
            // Bookkeeping, and a challenge the server no longer holds: this model again.
            for code in [
                "worker_challenge_busy",
                "worker_qualification_restart",
                // The same answer every time: asked again a bounded number of times.
                "worker_challenge_rejected",
            ] {
                assert_eq!(refusal(code, provider), Refusal::Again, "{code}");
            }
            assert!(!retryable("worker_challenge_rejected"));
            // The model may have changed: ask the server what to run.
            for code in [
                "workload_desktop_model_profile_unavailable",
                "workload_desktop_model_profile_changed",
            ] {
                assert_eq!(refusal(code, provider), Refusal::Models, "{code}");
            }
            assert_eq!(
                refusal("workload_desktop_clip_index_incompatible", provider),
                Refusal::Task
            );
            // A model the server holds back after failed tasks: that task waits out the hold
            // (five minutes) while the others work, and is then qualified again.
            assert_eq!(
                refusal("workload_desktop_qualification_hold", provider),
                Refusal::Task
            );
            assert_eq!(
                refused_task_retry("workload_desktop_qualification_hold"),
                Duration::from_secs(330)
            );
            assert!(server_task_refusal("desktop_qualification_hold"));
            // Neither a hold nor another model's index is the provider's doing: the task is
            // not moved to the processor over it. A changed model still may be.
            assert!(provider_independent("workload_desktop_qualification_hold"));
            assert!(provider_independent(
                "workload_desktop_clip_index_incompatible"
            ));
            assert!(!provider_independent(
                "workload_desktop_model_profile_unavailable"
            ));
            assert!(!provider_independent("worker_runtime_unsigned"));
            assert!(provider_independent(
                "workload_desktop_clip_space_unavailable"
            ));
            assert!(!provider_independent(
                "workload_desktop_clip_profile_unavailable"
            ));
            // Nothing a different provider would change.
            for code in ["worker_policy_required", "worker_device_refused"] {
                assert_eq!(refusal(code, provider), Refusal::Stop, "{code}");
            }
        }
        // The server refused what the GPU runtime sent: the processor runtime is tried, and
        // only a refusal of that one stops the worker.
        for code in [
            "worker_runtime_unsigned",
            "worker_qualification_report_refused",
            "server_http_400",
            "server_http_413",
        ] {
            assert_eq!(refusal(code, CUDA), Refusal::Processor, "{code}");
            assert_eq!(refusal(code, CPU), Refusal::Stop, "{code}");
        }
        // Memory or a slow moment is not held against the GPU for the whole runtime epoch.
        for code in ["runtime_out_of_memory", "runtime_qualification_timeout"] {
            assert!(crate::provider_selection::passing(code), "{code}");
        }
        assert!(!crate::provider_selection::passing(
            "runtime_output_mismatch"
        ));
    }

    #[tokio::test]
    async fn a_stop_hands_the_held_lease_back_as_cancelled() {
        let server = FakeServer::start();
        let device = server.enrol();
        let worker = server.session(&device).await.unwrap();
        let qualification = server.qualification(&worker).await;
        server.queue(&device, 1);
        let (stop, mut cancel) = tokio::sync::watch::channel(false);
        let predicting = tokio::sync::Notify::new();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            returning_lease(
                // The model is in the middle of this task and would never finish.
                step_with(&worker, &[&qualification], &mut cancel, |_| async {
                    predicting.notify_one();
                    std::future::pending::<Result<serde_json::Value, String>>().await
                }),
                async {
                    predicting.notified().await;
                    "worker_setup_cancelled".to_owned()
                },
                &stop,
                LEASE_RETURN,
            ),
        )
        .await
        .expect("the stop waited for the task");
        assert_eq!(result, Err("worker_setup_cancelled".into()));
        // The server heard at once that the task is free, and why.
        assert_eq!(server.reports(&device), ["fail"]);
        assert_eq!(server.failures(), ["cancelled"]);
    }

    #[tokio::test]
    async fn a_pause_stops_a_model_download_and_keeps_what_was_received() {
        let paused = AtomicBool::new(false);
        let cancelled = AtomicBool::new(false);
        let download = acquisition(
            std::future::pending::<Result<(), String>>(),
            true,
            || async { Ok(()) },
            std::future::pending(),
            async {
                paused.store(true, Ordering::Release);
                flag_set(&paused).await
            },
            &cancelled,
        );
        let result = tokio::time::timeout(Duration::from_secs(5), download).await;
        // Ended by the pause, not cancelled: the caller waits and continues the same file.
        assert_eq!(
            result.expect("the download ignored the pause"),
            Err("user_paused".into())
        );
        assert!(!cancelled.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn a_refusal_to_issue_a_session_keeps_its_name_and_is_waited_out() {
        for (status, message, code) in [
            // Policy-off was a 401 here on older servers and is a 403 now.
            (
                401,
                "desktop_pool_policy_required",
                "worker_policy_required",
            ),
            (
                403,
                "desktop_pool_policy_required",
                "worker_policy_required",
            ),
            (403, "desktop_worker_lan_required", "worker_lan_required"),
        ] {
            let server = FakeServer::start();
            let device = server.enrol();
            let saved = SavedSession::default();
            server.queue(&device, 1);
            server.respond_next(
                &device,
                "/devices/session",
                status,
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
            let routes = AtomicUsize::new(0);
            let done = || server.completed(&device) == 1;
            tokio::time::timeout(
                Duration::from_secs(10),
                supervise(
                    &progress,
                    false,
                    |refresh| work(&server, &device, &saved, refresh, &|| {}, &done),
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
            // Waited with the reason shown, then set up and worked by itself.
            assert_eq!(
                *statuses.lock().unwrap(),
                [("paused".to_owned(), Some(code.to_owned()))],
                "{status} {message}"
            );
            assert_eq!(server.sessions_issued(&device), 1);
        }
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
