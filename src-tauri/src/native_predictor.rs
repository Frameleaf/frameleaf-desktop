//! One scoped NAS job at a time; the owned qualified process is stopped whenever a failure may
//! have left inference running, and on every failure that is not confined to one task.
use crate::{
    ml_transport::{AcceptedQualification, ClaimedTask, InputKind, WorkerFailure, WorkerTransport},
    native_runtime::{NativeSidecar, QualifiedRuntime},
    runtime_store::InstalledRuntime,
    transport,
};
use reqwest::{
    multipart::{Form, Part},
    Client,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{future::Future, path::Path, time::Duration};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::watch;
use zeroize::Zeroizing;

struct BoundClient {
    client: Client,
    base: String,
    token: Zeroizing<String>,
    model_key: String,
    entries: Value,
    kind: String,
}
/// `now_ms`: the server's time (`WorkerTransport::now`), which stamped every deadline here.
fn execution_duration(task: &ClaimedTask, now_ms: i64) -> Result<Duration, String> {
    let parse = |value: &str| -> Result<i128, String> {
        OffsetDateTime::parse(value, &Rfc3339)
            .map(|date| date.unix_timestamp_nanos())
            .map_err(|_| "worker_deadline_invalid".into())
    };
    let now = i128::from(now_ms) * 1_000_000;
    let deadline = parse(&task.execution_deadline)?.min(parse(&task.qualification_expires_at)?);
    let lease = parse(&task.expires_at)?;
    let remaining = deadline - now;
    if lease <= now || lease > deadline || remaining <= 0 || remaining > 600_000_000_000 {
        return Err("worker_execution_deadline".into());
    }
    Ok(Duration::from_nanos(remaining as u64))
}
impl BoundClient {
    fn new(port: u16, token: String, spec: &Value) -> Result<Self, String> {
        if port < 1024 || !spec["entries"].is_object() {
            return Err("worker_model_binding_invalid".into());
        }
        let model_key = spec["modelKey"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or("worker_model_binding_invalid")?;
        let kind = spec["fixtureKind"]
            .as_str()
            .filter(|s| matches!(*s, "text" | "image"))
            .ok_or("worker_model_binding_invalid")?;
        Ok(Self {
            client: Client::builder()
                .tls_built_in_native_certs(false)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .pool_max_idle_per_host(0)
                .build()
                .map_err(|_| "runtime_client_failed")?,
            base: format!("http://127.0.0.1:{port}"),
            token: Zeroizing::new(token),
            model_key: model_key.into(),
            entries: spec["entries"].clone(),
            kind: kind.into(),
        })
    }
    async fn health(&self) -> Result<bool, String> {
        let mut response = self
            .client
            .get(format!("{}/ping", self.base))
            .bearer_auth(self.token.as_str())
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .map_err(|_| "runtime_not_ready")?;
        let ready = response.status().is_success();
        let mut size = 0;
        while let Some(bytes) = response.chunk().await.map_err(|_| "runtime_not_ready")? {
            size += bytes.len();
            if size > 256 {
                return Err("runtime_health_invalid".into());
            }
        }
        Ok(ready)
    }
    async fn predict(
        &self,
        task: &ClaimedTask,
        input: &[u8],
        now_ms: i64,
    ) -> Result<Value, String> {
        let config: Value =
            serde_json::from_str(&task.config_json).map_err(|_| "worker_model_binding_invalid")?;
        if task.model_key != self.model_key
            || config != self.entries
            || task.config_json.len() > 65_536
            || format!("{:x}", Sha256::digest(task.config_json.as_bytes())) != task.config_sha256
            || !matches!(
                (&task.input_kind, self.kind.as_str()),
                (InputKind::Text, "text") | (InputKind::Image, "image")
            )
            || task.max_input_bytes > 16 * 1024 * 1024
        {
            return Err("worker_model_binding_invalid".into());
        }
        task.verify_input(input)?;
        let duration = execution_duration(task, now_ms)?;
        let form = Form::new().text("entries", task.config_json.clone());
        let form = match task.input_kind {
            InputKind::Text => form.text(
                "text",
                String::from_utf8(input.to_vec()).map_err(|_| "worker_text_invalid")?,
            ),
            InputKind::Image => form.part(
                "image",
                Part::bytes(input.to_vec())
                    .file_name("input")
                    .mime_str("application/octet-stream")
                    .map_err(|_| "worker_input_invalid")?,
            ),
        };
        let response = self
            .client
            .post(format!("{}/predict", self.base))
            .bearer_auth(self.token.as_str())
            // A backstop only: the task's own deadline (`race_prediction`) ends a slow
            // prediction first, so a healthy runtime that runs late is never taken for one
            // whose answer broke off.
            .timeout(duration + PREDICTION_TIMEOUT_SLACK)
            .multipart(form)
            .send()
            .await
            .map_err(|error| match error.is_timeout() {
                true => "worker_execution_deadline",
                false => "runtime_prediction_interrupted",
            })?;
        let value: Value = transport::json_limit(response, 4 * 1024 * 1024).await?;
        if !value.is_object() {
            return Err("runtime_prediction_invalid".into());
        }
        Ok(value)
    }
}
async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}
type WorkerStep<'a> = std::pin::Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>>;
async fn worker_jobs<T>(
    state: &mut T,
    mut execute: impl for<'a> FnMut(&'a mut T, watch::Receiver<bool>) -> WorkerStep<'a>,
    cancel: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    loop {
        let execution_cancel = cancel.clone();
        let completed = tokio::select! {
            biased;
            _ = cancelled(cancel) => return Err("worker_cancelled".into()),
            result = execute(state, execution_cancel) => result?,
        };
        if !completed {
            // A server may answer an empty long-poll immediately; do not spin against it.
            tokio::select! {
                biased;
                _ = cancelled(cancel) => return Err("worker_cancelled".into()),
                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
        }
    }
}
async fn race_prediction<T>(
    prediction: impl Future<Output = Result<T, String>>,
    lease: impl Future<Output = Result<(), String>>,
    cancel: &mut watch::Receiver<bool>,
    duration: Duration,
) -> Result<T, String> {
    tokio::pin!(prediction, lease);
    tokio::select! {
        biased;
        _ = cancelled(cancel) => Err("worker_cancelled".into()),
        _ = tokio::time::sleep(duration) => Err("worker_execution_deadline".into()),
        result = &mut lease => Err(result.err().unwrap_or_else(|| "worker_lease_lost".into())),
        result = &mut prediction => result,
    }
}

/// What one turn of the claim loop did.
#[derive(Debug, PartialEq)]
pub(crate) enum Step {
    Idle,
    Completed,
    /// One task was given up. The session and its qualifications stay good for the next claim.
    Dropped(String),
    /// Nothing was claimed: the server is failing or busy. Ask again after a pause.
    Busy(String),
}
/// The server counts this failed task against the model's grant: after three in a row for one
/// model from this computer (kept across sessions) it withdraws the model, and `claim` then
/// returns nothing for it. A handed-back lease, a refused input and a lease the server already ended
/// are not counted.
pub(crate) fn counts_against_grant(code: &str) -> bool {
    !lease_gone(code)
        && matches!(
            failure_report(code),
            WorkerFailure::InferenceFailed | WorkerFailure::ModelUnavailable
        )
}
struct TaskFailure {
    code: String,
    /// The local model may still be running this input.
    inferring: bool,
}
/// Failures that end one task only.
fn task_scoped(code: &str) -> bool {
    matches!(
        code,
        "worker_result_refused"
            | "worker_lease_refused"
            | "worker_lease_lost"
            | "worker_lease_expired"
            | "worker_execution_deadline"
            | "worker_input_interrupted"
            | "worker_input_invalid"
            | "worker_input_too_large"
            | "worker_text_invalid"
            | "runtime_prediction_refused" // A status with no name the worker knows (a 4xx this app has never heard of, a 5xx from a
                                           // busy server) while fetching, heartbeating or reporting one task says nothing about the
                                           // session or the next task. A bare 401 or 403 is about who is asking, not about one task.
    ) || (code.starts_with("server_http_")
        && !matches!(code, "server_http_401" | "server_http_403"))
}
/// The server (or something in front of it) is failing or busy: nothing was refused.
fn server_unavailable(code: &str) -> bool {
    code.starts_with("server_http_5") || matches!(code, "server_http_408" | "server_http_429")
}
/// What the server is told about a task given up (`fail`), as accurately as this side knows.
fn failure_report(code: &str) -> WorkerFailure {
    match code {
        // The lease is handed back unfinished: stop, pause, sign-out, quit, or a wait for power.
        "worker_cancelled" => WorkerFailure::Cancelled,
        "worker_input_invalid"
        | "worker_input_too_large"
        | "worker_text_invalid"
        | "runtime_prediction_refused" => WorkerFailure::InputInvalid,
        "runtime_process_stopped" | "runtime_prediction_interrupted" | "runtime_not_ready" => {
            WorkerFailure::ModelUnavailable
        }
        _ => WorkerFailure::InferenceFailed,
    }
}
/// The server no longer honours this lease, or the credential behind it: it hears nothing more
/// about the task, neither a result nor a failure.
fn lease_gone(code: &str) -> bool {
    matches!(
        code,
        "worker_result_refused"
            | "worker_lease_refused"
            | "worker_lease_lost"
            | "worker_lease_expired"
            | "worker_session_rejected"
            | "worker_policy_changed"
    )
}
fn heartbeat_undelivered(code: &str) -> bool {
    matches!(
        code,
        "worker_request_interrupted"
            | "server_response_interrupted"
            | "server_http_408"
            | "server_http_429"
    ) || code.starts_with("server_http_5")
}
fn lease_expired(task: &ClaimedTask, now_ms: Result<i64, String>) -> bool {
    let expires = OffsetDateTime::parse(&task.expires_at, &Rfc3339)
        .map(|expires| expires.unix_timestamp_nanos() / 1_000_000);
    match (expires, now_ms) {
        (Ok(expires), Ok(now)) => expires <= i128::from(now),
        _ => true,
    }
}
const HEARTBEAT: Duration = Duration::from_secs(20);
const HEARTBEAT_RETRY: Duration = Duration::from_secs(5);
/// Renew the lease until the prediction ends. A heartbeat that could not be delivered is retried
/// while the last expiry the server granted is still ahead; a refusal ends the task at once.
async fn hold_lease<F: Future<Output = Result<bool, String>>>(
    mut heartbeat: impl FnMut() -> F,
    expired: impl Fn() -> bool,
    every: Duration,
    retry: Duration,
) -> Result<(), String> {
    loop {
        tokio::time::sleep(every).await;
        loop {
            match heartbeat().await {
                Ok(true) => break,
                Ok(false) => return Err("worker_lease_lost".into()),
                Err(code) if heartbeat_undelivered(&code) && !expired() => {
                    tokio::time::sleep(retry).await;
                }
                Err(code) if heartbeat_undelivered(&code) => return Err("worker_lease_lost".into()),
                Err(code) => return Err(code),
            }
        }
    }
}
/// How long a claim already sent may still be answered after a stop is asked for. A task the
/// server leased in that moment is handed straight back instead of being left to expire.
const CLAIM_GRACE: Duration = Duration::from_secs(2);
async fn next_task(
    transport: &WorkerTransport,
    qualifications: &[&AcceptedQualification],
    cancel: &mut watch::Receiver<bool>,
    slots: Option<u32>,
) -> Result<Result<(usize, ClaimedTask), Step>, String> {
    let claim = transport.claim_with(qualifications, slots, 20_000);
    tokio::pin!(claim);
    let claimed = tokio::select! {
        biased;
        _ = cancelled(cancel) => {
            if let Ok(Ok(Some((index, task)))) = tokio::time::timeout(CLAIM_GRACE, &mut claim).await {
                let _ = transport
                    .fail(&task, WorkerFailure::Cancelled, qualifications[index])
                    .await;
            }
            return Err("worker_cancelled".into());
        }
        _ = tokio::time::sleep(Duration::from_secs(30)) => Err("worker_execution_deadline".into()),
        result = &mut claim => result,
    };
    match claimed {
        Ok(Some(claimed)) => Ok(Ok(claimed)),
        Ok(None) => Ok(Err(Step::Idle)),
        // Nothing was claimed and nothing is wrong with this session: ask again after a pause.
        Err(code) if server_unavailable(&code) => Ok(Err(Step::Busy(code))),
        Err(code) => Err(code),
    }
}
/// What became of one claimed task, and which model it was for.
#[derive(Debug, PartialEq)]
pub(crate) struct TaskStep {
    /// The model key of the task; `None` when nothing was claimed.
    pub model: Option<String>,
    pub step: Step,
    /// The server acknowledged the failure report of a dropped task: only then has it counted
    /// the failure toward withdrawing the model.
    pub reported: bool,
}
/// How the worker steers the pool of tasks in hand.
pub(crate) struct Pool<'a> {
    /// How many tasks may be in hand right now, where the server lets a desktop hold several
    /// leases. `None` is one task, claimed the way it always was.
    pub slots: &'a (dyn Fn() -> Option<u32> + Sync),
    /// Whether to go on claiming. When it says no, the tasks in hand are finished and the pool
    /// ends, so its owner can do what it must between tasks.
    pub keep_claiming: &'a (dyn Fn() -> bool + Sync),
    /// Stop the runtime process: the only task in hand was given up in the middle of its
    /// prediction, which is still running there.
    pub abandon: &'a (dyn Fn() + Sync),
}
/// Work on tasks side by side, each under its own lease with its own heartbeat, input, result
/// and failure, and ask for another as soon as one is done.
///
/// - With nothing in hand the claim waits for work, as one always did. With tasks in hand it
///   does not wait: signed requests go one at a time, and a held-open claim would keep their
///   heartbeats and results waiting. When the server has nothing more, it is asked again in a
///   second.
/// - `on_step` hears of each task as soon as it is settled, and answers how long to hold off
///   the next claim; `None` is "stop claiming".
/// - A failure that is not one task's alone ends the claiming; the other tasks in hand are
///   still settled, and the failure is returned when they are.
/// - The pool ends when nothing was there to claim, or nothing is in hand and claiming stopped.
pub(crate) async fn run_pool<F, P>(
    transport: &WorkerTransport,
    qualifications: &[&AcceptedQualification],
    cancel: &mut watch::Receiver<bool>,
    pool: &Pool<'_>,
    mut on_claim: impl FnMut(&ClaimedTask),
    mut on_step: impl FnMut(TaskStep) -> Option<Duration>,
    predict: F,
) -> Result<(), String>
where
    F: Fn(usize, ClaimedTask, Vec<u8>) -> P,
    P: Future<Output = Result<Value, String>>,
{
    use futures_util::{stream::FuturesUnordered, StreamExt};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let (in_hand, crash_reported) = (AtomicUsize::new(0), tokio::sync::Mutex::new(false));
    // The runtime was stopped under an abandoned prediction: nothing more is started on it.
    let stopped = AtomicBool::new(false);
    let (in_hand, crash_reported, stopped, predict) =
        (&in_hand, &crash_reported, &stopped, &predict);
    // One task in hand, from its input to the server hearing what became of it.
    let work = |index: usize, task: ClaimedTask, mut cancel: watch::Receiver<bool>| async move {
        let qualification = qualifications[index];
        let run = |held, input| predict(index, held, input);
        let outcome = run_claimed(transport, &task, qualification, &mut cancel, run).await;
        // A prediction given up on is still running in the process. With this the only task
        // in hand, the process is stopped before the server is told, as it always was; one
        // task's late deadline must not end the others' work.
        // A refusal is the model's answer: nothing is left running, and the process serves on.
        let abandoned = outcome.as_ref().is_err_and(|failure| {
            failure.inferring && failure.code != "runtime_prediction_refused"
        });
        if abandoned && in_hand.load(Ordering::Acquire) == 1 {
            stopped.store(true, Ordering::Release);
            (pool.abandon)();
        }
        let step = settle(transport, &task, qualification, outcome, crash_reported).await;
        in_hand.fetch_sub(1, Ordering::AcqRel);
        (task.model_key, step)
    };
    let mut running = FuturesUnordered::new();
    // A claim for more room, made while tasks are in hand. It is waited for alongside them:
    // it takes its turn among their requests, and they must go on being served meanwhile.
    let mut more = None;
    let mut claiming = true;
    let mut next_claim = tokio::time::Instant::now();
    // Claims for more room the server answered with nothing, in a row: each waits twice as
    // long as the one before, up to `REFILL_WAIT_MOST` seconds. A task that finishes asks
    // again at once, since that is when the server's answer is likeliest to change.
    let mut empty = 0u32;
    let mut fatal: Option<String> = None;
    loop {
        let slots = (pool.slots)();
        let room = slots.unwrap_or(1).saturating_sub(running.len() as u32);
        claiming &= fatal.is_none()
            && (pool.keep_claiming)()
            && !*cancel.borrow()
            && !stopped.load(Ordering::Acquire);
        let due = claiming && room > 0 && more.is_none();
        if due && tokio::time::Instant::now() >= next_claim {
            if running.is_empty() {
                // Nothing in hand: wait for work, as one always did.
                let room = slots.map(|_| room);
                match next_task(transport, qualifications, cancel, room).await? {
                    // The owner stopped wanting tasks while the claim waited (a pause).
                    Ok((index, task)) if !(pool.keep_claiming)() => {
                        let _ = transport
                            .fail(&task, WorkerFailure::Cancelled, qualifications[index])
                            .await;
                    }
                    Ok((index, task)) => {
                        on_claim(&task);
                        in_hand.fetch_add(1, Ordering::AcqRel);
                        running.push(work(index, task, cancel.clone()));
                    }
                    Err(step) => {
                        on_step(TaskStep {
                            model: None,
                            step,
                            reported: false,
                        });
                        return Ok(());
                    }
                }
                continue;
            }
            more = Some(Box::pin(transport.claim_with(
                qualifications,
                Some(room),
                0,
            )));
        }
        // Nothing in hand and nothing asked for: done, unless the next claim is only being
        // held off after a dropped task, which is waited out here.
        if running.is_empty() && more.is_none() && !due {
            return fatal.map_or(Ok(()), Err);
        }
        let asked = more.is_some();
        let answer = async {
            match more.as_mut() {
                Some(claim) => claim.await,
                None => std::future::pending().await,
            }
        };
        let wait = async {
            match due {
                // In steps of a second, so a pause or a stop is seen while holding off.
                true => {
                    let step = tokio::time::Instant::now() + Duration::from_secs(1);
                    tokio::time::sleep_until(next_claim.min(step)).await
                }
                false => std::future::pending().await,
            }
        };
        tokio::select! {
            claimed = answer, if asked => {
                more = None;
                // A refused or failed claim for more just waits a second: the tasks in hand
                // say soon enough if something is wrong.
                match claimed.ok().flatten() {
                    // No longer wanted (a stop, a pause, a failure, the runtime stopped):
                    // straight back to the server, its input never fetched.
                    Some((index, task))
                        if !claiming
                            || fatal.is_some()
                            || *cancel.borrow()
                            || stopped.load(Ordering::Acquire)
                            || !(pool.keep_claiming)() =>
                    {
                        let _ = transport
                            .fail(&task, WorkerFailure::Cancelled, qualifications[index])
                            .await;
                    }
                    Some((index, task)) => {
                        empty = 0;
                        on_claim(&task);
                        in_hand.fetch_add(1, Ordering::AcqRel);
                        running.push(work(index, task, cancel.clone()));
                    }
                    None => {
                        next_claim = tokio::time::Instant::now() + refill_wait(empty);
                        empty += 1;
                    }
                }
            }
            Some((model, step)) = running.next(), if !running.is_empty() => match step {
                Ok((step, reported)) => {
                    let done = step == Step::Completed;
                    let now = tokio::time::Instant::now();
                    match on_step(TaskStep { model: Some(model), step, reported }) {
                        // A place came free: ask for more now, whatever was being waited out.
                        Some(pause) if done => {
                            empty = 0;
                            next_claim = now + pause;
                        }
                        Some(pause) => next_claim = next_claim.max(now + pause),
                        None => claiming = false,
                    }
                }
                Err(code) => {
                    fatal.get_or_insert(code);
                }
            },
            _ = wait => {}
        }
    }
}
/// One claimed task, from its input to an acknowledged result.
async fn run_claimed<F, P>(
    transport: &WorkerTransport,
    task: &ClaimedTask,
    qualification: &AcceptedQualification,
    cancel: &mut watch::Receiver<bool>,
    predict: F,
) -> Result<(), TaskFailure>
where
    F: FnOnce(ClaimedTask, Vec<u8>) -> P,
    P: Future<Output = Result<Value, String>>,
{
    let idle = |code: String| TaskFailure {
        code,
        inferring: false,
    };
    let now = || transport.now();
    let duration = execution_duration(task, now().map_err(idle)?).map_err(idle)?;
    let lease = std::sync::Mutex::new(task.clone());
    // Whether the model has been given the input: only then is something still running in the
    // process when the task is given up.
    let predicting = std::sync::atomic::AtomicBool::new(false);
    // The lease is kept alive from the claim on, while the input is fetched as well: with
    // several tasks in hand on a slow link, an input can take longer than a lease lasts.
    let value = race_prediction(
        async {
            let held = lease.lock().unwrap().clone();
            let input = transport.input(&held, qualification).await?;
            predicting.store(true, std::sync::atomic::Ordering::Release);
            // Under the lease as the heartbeat last renewed it: a slow input can outlast
            // the expiry the claim came with.
            let held = lease.lock().unwrap().clone();
            predict(held, input).await
        },
        hold_lease(
            || async {
                let mut next = lease.lock().unwrap().clone();
                let accepted = transport.heartbeat(&mut next, qualification).await?;
                if accepted {
                    *lease.lock().unwrap() = next;
                }
                Ok(accepted)
            },
            || lease_expired(&lease.lock().unwrap(), now()),
            HEARTBEAT,
            HEARTBEAT_RETRY,
        ),
        cancel,
        duration,
    )
    .await
    .map_err(|code| TaskFailure {
        code,
        inferring: predicting.load(std::sync::atomic::Ordering::Acquire),
    })?;
    // Report under the last lease the server granted; `complete` refuses one that has run out.
    let held = lease.lock().unwrap().clone();
    let accepted = race_prediction(
        transport.complete(&held, &value, qualification),
        std::future::pending(),
        cancel,
        Duration::from_secs(30),
    )
    .await
    .map_err(idle)?;
    if !accepted {
        return Err(idle("worker_result_refused".into()));
    }
    Ok(())
}
const CRASH_REPORT_RETRY: Duration = Duration::from_secs(1);
/// How long a claim for more room is held off, at most, while the server has nothing to give.
const REFILL_WAIT_MOST: u64 = 8;
/// The wait before the next claim for more room, after `empty` of them in a row were
/// answered with nothing: 1, 2, 4 and then 8 seconds.
pub(crate) fn refill_wait(empty: u32) -> Duration {
    Duration::from_secs((1u64 << empty.min(3)).min(REFILL_WAIT_MOST))
}
/// `crash_reported`: shared by the tasks in hand together. When the runtime process ends
/// under several of them, one is reported as `model-unavailable` and the rest are handed back
/// as `cancelled`: it was one failure of the runtime, and the server, which withdraws a model
/// after three failed tasks in a row, must count it as one.
async fn settle(
    transport: &WorkerTransport,
    task: &ClaimedTask,
    qualification: &AcceptedQualification,
    outcome: Result<(), TaskFailure>,
    crash_reported: &tokio::sync::Mutex<bool>,
) -> Result<(Step, bool), String> {
    let Err(failure) = outcome else {
        return Ok((Step::Completed, false));
    };
    let mut reported = false;
    if !lease_gone(&failure.code) {
        let mut report = failure_report(&failure.code);
        // The one report that stands for the whole crash goes first: the server takes the
        // hand-backs that follow a `model-unavailable` as part of that failure, and would
        // count one that came before it as a hand-back of its own. The others wait here
        // until it has been sent.
        let mut first = None;
        if matches!(report, WorkerFailure::ModelUnavailable) {
            let mut told = crash_reported.lock().await;
            match *told {
                true => report = WorkerFailure::Cancelled,
                false => {
                    *told = true;
                    first = Some(told);
                }
            }
        }
        let mut sent = transport.fail(task, report, qualification).await;
        // It must arrive, or the server counts the crash as nothing: it is sent once more,
        // and if that fails too, the next task still in hand carries it instead.
        if let Some(mut told) = first {
            if sent.is_err() {
                tokio::time::sleep(CRASH_REPORT_RETRY).await;
                sent = transport.fail(task, report, qualification).await;
                if sent.is_err() {
                    *told = false;
                }
            }
        }
        reported = sent == Ok(true);
    }
    if task_scoped(&failure.code) {
        Ok((Step::Dropped(failure.code), reported))
    } else {
        Err(failure.code)
    }
}
/// The claim loop's own steps with the local model replaced, for tests without a signed runtime.
#[cfg(test)]
pub(crate) async fn step_with<F, P>(
    transport: &WorkerTransport,
    qualifications: &[&AcceptedQualification],
    cancel: &mut watch::Receiver<bool>,
    predict: F,
) -> Result<Step, String>
where
    F: FnOnce(Vec<u8>) -> P,
    P: Future<Output = Result<Value, String>>,
{
    let (index, task) = match next_task(transport, qualifications, cancel, None).await? {
        Ok(claimed) => claimed,
        Err(step) => return Ok(step),
    };
    let run = |_, input| predict(input);
    let outcome = run_claimed(transport, &task, qualifications[index], cancel, run).await;
    let alone = tokio::sync::Mutex::new(false);
    let settled = settle(transport, &task, qualifications[index], outcome, &alone).await;
    settled.map(|(step, _)| step)
}
/// As the worker with room for `slots` tasks at once, with the local model replaced: works
/// until the server has nothing more, and returns what became of each task in the order they
/// were settled.
#[cfg(test)]
pub(crate) async fn pool_with<F, P>(
    transport: &WorkerTransport,
    qualifications: &[&AcceptedQualification],
    cancel: &mut watch::Receiver<bool>,
    slots: Option<u32>,
    predict: F,
) -> Result<Vec<Step>, String>
where
    F: Fn(Vec<u8>) -> P,
    P: Future<Output = Result<Value, String>>,
{
    let mut steps = Vec::new();
    let pool = Pool {
        slots: &|| slots,
        keep_claiming: &|| true,
        abandon: &|| {},
    };
    let heard = |task: TaskStep| {
        if task.model.is_some() {
            steps.push(task.step);
        }
        Some(Duration::ZERO)
    };
    let run = |_, _, input| predict(input);
    run_pool(transport, qualifications, cancel, &pool, |_| {}, heard, run).await?;
    Ok(steps)
}

/// How much longer than the task's deadline a prediction request itself may run.
const PREDICTION_TIMEOUT_SLACK: Duration = Duration::from_secs(5);

/// How long every runtime process may take to answer its first health check.
const READY_DEADLINE: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 15 });

pub struct NativePredictor {
    /// One process per runtime in use (the processor runtime, an accelerated one, or both).
    children: Vec<Lane>,
    roles: Vec<BoundRole>,
    /// The process that was not serving when `ready` last failed.
    failed: Option<usize>,
}
struct Lane {
    child: NativeSidecar,
    manifest_sha256: String,
}
struct BoundRole {
    client: BoundClient,
    qualification_id: String,
    lane: usize,
}
struct ActiveExecution<'a> {
    predictor: &'a mut NativePredictor,
    retain: bool,
}
impl Drop for ActiveExecution<'_> {
    fn drop(&mut self) {
        if !self.retain {
            let _ = self.predictor.stop();
        }
    }
}
impl NativePredictor {
    /// Own the process for a serial, cancellable association; errors require fresh orchestration.
    pub async fn run(
        self,
        transport: WorkerTransport,
        qualification: AcceptedQualification,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<(), String> {
        let mut state = (self, transport, qualification);
        let outcome = worker_jobs(
            &mut state,
            |state, mut execution_cancel| {
                Box::pin(async move {
                    state
                        .0
                        .execute_next(&state.1, &state.2, &mut execution_cancel)
                        .await
                })
            },
            &mut cancel,
        )
        .await;
        state.0.stop()?;
        outcome
    }
    /// The sealed qualification and installed runtime must have the same signed manifest identity.
    pub fn start(
        installed: &InstalledRuntime,
        qualified: &QualifiedRuntime,
        qualification: &AcceptedQualification,
        cache: &Path,
        private_root: &Path,
        port: u16,
    ) -> Result<Self, String> {
        Self::start_many(
            installed,
            &[(qualified, qualification)],
            cache,
            private_root,
            port,
        )
    }
    pub fn start_many(
        installed: &InstalledRuntime,
        bindings: &[(&QualifiedRuntime, &AcceptedQualification)],
        cache: &Path,
        private_root: &Path,
        port: u16,
    ) -> Result<Self, String> {
        Self::start_lanes(&[(installed, port)], bindings, cache, private_root)
    }
    /// Start one process per runtime that has a binding; each binding runs on the runtime whose
    /// signed manifest it was qualified with. Roles keep the order of `bindings`.
    pub(crate) fn start_lanes(
        runtimes: &[(&InstalledRuntime, u16)],
        bindings: &[(&QualifiedRuntime, &AcceptedQualification)],
        cache: &Path,
        private_root: &Path,
    ) -> Result<Self, String> {
        let now = (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
        Self::start_lanes_at(runtimes, bindings, cache, private_root, now, 1)
    }
    /// `now_ms`: the server's time (`WorkerTransport::now`), which stamped the qualifications.
    pub(crate) fn start_lanes_at(
        runtimes: &[(&InstalledRuntime, u16)],
        bindings: &[(&QualifiedRuntime, &AcceptedQualification)],
        cache: &Path,
        private_root: &Path,
        now_ms: i64,
        // How many tasks the worker runs at once: each process serves that many requests.
        threads: u32,
    ) -> Result<Self, String> {
        if !(1..=64).contains(&bindings.len()) {
            return Err("worker_model_binding_invalid".into());
        }
        let mut keys = std::collections::BTreeSet::new();
        for (qualified, accepted) in bindings {
            accepted.validate_runtime(qualified, now_ms)?;
            let spec: Value = serde_json::from_slice(qualified.specification())
                .map_err(|_| "worker_model_binding_invalid")?;
            if !keys.insert(
                spec["modelKey"]
                    .as_str()
                    .ok_or("worker_model_binding_invalid")?
                    .to_owned(),
            ) {
                return Err("worker_model_binding_invalid".into());
            }
        }
        if bindings.iter().any(|(qualified, _)| {
            runtimes
                .iter()
                .filter(|(runtime, _)| runtime.manifest_sha256() == qualified.manifest_sha256())
                .count()
                != 1
        }) {
            return Err("runtime_qualification_binding_invalid".into());
        }
        let mut children: Vec<(Lane, u16)> = Vec::new();
        for (installed, port) in runtimes {
            let proofs: Vec<_> = bindings
                .iter()
                .map(|(qualified, _)| *qualified)
                .filter(|qualified| qualified.manifest_sha256() == installed.manifest_sha256())
                .collect();
            if proofs.is_empty() {
                continue;
            }
            // A failure here drops (and so stops) the processes already started.
            let child = installed.start_bound_sidecar_threads(
                &proofs,
                cache,
                private_root,
                *port,
                threads,
            )?;
            children.push((
                Lane {
                    child,
                    manifest_sha256: installed.manifest_sha256().into(),
                },
                *port,
            ));
        }
        let roles = bindings
            .iter()
            .map(|(qualified, accepted)| {
                let spec: Value = serde_json::from_slice(qualified.specification())
                    .map_err(|_| "worker_model_binding_invalid")?;
                let lane = children
                    .iter()
                    .position(|(lane, _)| lane.manifest_sha256 == qualified.manifest_sha256())
                    .ok_or("runtime_qualification_binding_invalid")?;
                let (owner, port) = &children[lane];
                Ok(BoundRole {
                    client: BoundClient::new(*port, owner.child.authorization().into(), &spec)?,
                    qualification_id: accepted.id().into(),
                    lane,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self {
            children: children.into_iter().map(|(lane, _)| lane).collect(),
            roles,
            failed: None,
        })
    }
    /// Stop every process; the first failure is reported after all were asked to stop.
    pub fn stop(&mut self) -> Result<(), String> {
        let mut result = Ok(());
        for lane in &mut self.children {
            let stopped = lane.child.stop();
            if result.is_ok() {
                result = stopped;
            }
        }
        result
    }
    pub(crate) fn is_running(&mut self) -> Result<bool, String> {
        for lane in &mut self.children {
            if !lane.child.is_running()? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Why a runtime process ended by itself, if one did (`NativeSidecar::exit_report`).
    pub(crate) fn exit_report(&mut self) -> Option<String> {
        self.children
            .iter_mut()
            .find_map(|lane| lane.child.exit_report())
    }
    /// The signed manifest of the runtime whose process was not serving when work last failed
    /// to start: a provider that did not initialise.
    pub(crate) fn failed_lane(&self) -> Option<&str> {
        self.failed
            .map(|index| self.children[index].manifest_sha256.as_str())
    }
    /// A lane is blamed (`failed_lane`) only when it is the reason this returned a startup
    /// failure: its process had stopped, or it was still not serving at the deadline. A wait
    /// that is cancelled or dropped while a lane is merely loading blames nothing.
    async fn ready(&mut self, cancel: &mut watch::Receiver<bool>) -> Result<(), String> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        const NONE: usize = usize::MAX;
        self.failed = None;
        let waiting = AtomicUsize::new(NONE);
        let (children, roles) = (&mut self.children, &self.roles);
        let wait = async {
            loop {
                let mut unready = NONE;
                for (index, lane) in children.iter_mut().enumerate() {
                    let role = roles.iter().find(|role| role.lane == index);
                    if !lane.child.is_running()? {
                        waiting.store(index, Ordering::Release);
                        return Err("runtime_process_stopped".into());
                    }
                    if let Some(role) = role {
                        // Named before the check: the deadline can fall while it is pending.
                        waiting.store(index, Ordering::Release);
                        if !role.client.health().await.unwrap_or(false) {
                            unready = index;
                            break;
                        }
                    }
                }
                waiting.store(unready, Ordering::Release);
                if unready == NONE {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        let result = race_prediction(wait, std::future::pending(), cancel, READY_DEADLINE).await;
        if matches!(
            result.as_ref().map_err(String::as_str),
            Err("runtime_process_stopped" | "worker_execution_deadline")
        ) {
            self.failed = Some(waiting.load(Ordering::Acquire)).filter(|index| *index != NONE);
        }
        // The process started and never answered its health check: that is the runtime not
        // being ready, which the worker counts and backs off from, not a task that ran late.
        result.map_err(|code| match code.as_str() {
            "worker_execution_deadline" => "runtime_not_ready".into(),
            _ => code,
        })
    }
    /// After a failed prediction: a lane whose process is gone crashed while inferring (a
    /// cancelled or refused prediction leaves it running), so the caller can stop using it.
    fn blame_exited(&mut self, lane: usize) {
        if !self.children[lane].child.is_running().unwrap_or(false) {
            self.failed = Some(lane);
        }
    }
    /// Execute one admitted job; empty NAS model grants cannot claim work.
    pub async fn execute_next(
        &mut self,
        transport: &WorkerTransport,
        qualification: &AcceptedQualification,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<bool, String> {
        self.execute_next_many(transport, &[qualification], cancel)
            .await
    }
    pub async fn execute_next_many(
        &mut self,
        transport: &WorkerTransport,
        qualifications: &[&AcceptedQualification],
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<bool, String> {
        // One task, then back to this owner.
        let claimed = std::sync::atomic::AtomicBool::new(false);
        let mut done = None;
        let pool = Pool {
            slots: &|| None,
            keep_claiming: &|| !claimed.load(std::sync::atomic::Ordering::Acquire),
            abandon: &|| {},
        };
        let on_claim = |_: &str| claimed.store(true, std::sync::atomic::Ordering::Release);
        let on_step = |task: TaskStep| {
            done = Some(task.step);
            None
        };
        self.work(transport, qualifications, cancel, &pool, on_claim, on_step)
            .await?;
        match done {
            Some(Step::Completed) => Ok(true),
            Some(Step::Idle) | None => Ok(false),
            // This owner has no way to carry on after a dropped task: it ends with the error.
            Some(Step::Dropped(code) | Step::Busy(code)) => {
                self.stop()?;
                Err(code)
            }
        }
    }
    /// Work on tasks until the pool ends (`run_pool`). An error stops the runtime processes.
    pub(crate) async fn work(
        &mut self,
        transport: &WorkerTransport,
        qualifications: &[&AcceptedQualification],
        cancel: &mut watch::Receiver<bool>,
        pool: &Pool<'_>,
        on_claim: impl FnMut(&str),
        on_step: impl FnMut(TaskStep) -> Option<Duration>,
    ) -> Result<(), String> {
        let mut active = ActiveExecution {
            predictor: self,
            retain: false,
        };
        let outcome = active
            .predictor
            .execute(transport, qualifications, cancel, pool, on_claim, on_step)
            .await;
        if outcome.is_err() {
            active.predictor.stop()?;
        }
        active.retain = true;
        outcome
    }
    async fn execute(
        &mut self,
        transport: &WorkerTransport,
        qualifications: &[&AcceptedQualification],
        cancel: &mut watch::Receiver<bool>,
        pool: &Pool<'_>,
        mut on_claim: impl FnMut(&str),
        on_step: impl FnMut(TaskStep) -> Option<Duration>,
    ) -> Result<(), String> {
        if self.roles.len() != qualifications.len()
            || self
                .roles
                .iter()
                .zip(qualifications)
                .any(|(role, accepted)| role.qualification_id != accepted.id())
        {
            return Err("worker_predictor_qualification_changed".into());
        }
        use std::sync::atomic::Ordering;
        self.ready(cancel).await?;
        let roles = &self.roles;
        // Shared by the tasks in hand: each checks its own process after its prediction.
        let children = std::sync::Mutex::new(&mut self.children);
        // Set when this owner stops the processes itself: that is not a process to blame.
        let stopped_here = std::sync::atomic::AtomicBool::new(false);
        // The lane whose process ended, or whose answer broke off, under a prediction. With
        // one task in hand this owner stops every process next (`abandon`), so it has to be
        // noted before.
        const NONE: usize = usize::MAX;
        let exited = std::sync::atomic::AtomicUsize::new(NONE);
        let exited = &exited;
        let abandon = || {
            stopped_here.store(true, Ordering::Release);
            for (index, lane) in children.lock().unwrap().iter_mut().enumerate() {
                // Already gone before this owner stops it (a deadline can win the race with
                // the broken connection, and then nothing else has looked): it ended by itself.
                if !lane.child.is_running().unwrap_or(true) {
                    let _ =
                        exited.compare_exchange(NONE, index, Ordering::AcqRel, Ordering::Acquire);
                }
                let _ = lane.child.stop();
            }
        };
        let pool = Pool {
            slots: pool.slots,
            keep_claiming: pool.keep_claiming,
            abandon: &abandon,
        };
        let outcome = run_pool(
            transport,
            qualifications,
            cancel,
            &pool,
            |task| {
                if let Some((workload, _)) = task.model_key.split_once(':') {
                    on_claim(workload);
                }
            },
            on_step,
            |index, task, input| {
                let (role, children) = (&roles[index], &children);
                async move {
                    let running = || children.lock().unwrap()[role.lane].child.is_running();
                    let answer = role.client.predict(&task, &input, transport.now()?).await;
                    let value = match answer {
                        Ok(value) => value,
                        // The local model refused this one input; the process itself is still serving.
                        Err(code) if code.starts_with("server_http_") => {
                            return Err("runtime_prediction_refused".into())
                        }
                        // Its answer broke off, before or after the first line: this runtime
                        // stopped answering, whether its process is already gone or still
                        // lingers. It is the one that failed, and it is reported as a crash.
                        Err(code)
                            if matches!(
                                code.as_str(),
                                "runtime_prediction_interrupted" | "server_response_interrupted"
                            ) =>
                        {
                            exited.store(role.lane, Ordering::Release);
                            return Err("runtime_prediction_interrupted".into());
                        }
                        Err(code) => return Err(code),
                    };
                    if !running()? {
                        exited.store(role.lane, Ordering::Release);
                        return Err("runtime_process_stopped".into());
                    }
                    Ok(value)
                }
            },
        )
        .await;
        // The runtime seen to fail under a prediction is blamed. Otherwise a process that is
        // gone without this owner having stopped it ended by itself.
        if let Some(lane) = Some(exited.load(Ordering::Acquire)).filter(|lane| *lane != NONE) {
            self.failed = Some(lane);
        } else if !stopped_here.load(Ordering::Acquire) {
            for lane in 0..self.children.len() {
                self.blame_exited(lane);
            }
        }
        outcome
    }
}

/// For tests of what follows a runtime that dies: a real, signed runtime pack whose process
/// ends by itself the moment it is asked to predict.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::native_runtime::VerifiedRuntime;
    use std::{
        fs,
        io::{Read, Write},
        net::TcpListener,
        path::PathBuf,
    };
    pub(crate) struct DyingRuntime {
        root: PathBuf,
        pack: VerifiedRuntime,
        port: u16,
        dies: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl DyingRuntime {
        pub(crate) fn build() -> Self {
            use ed25519_dalek::{Signer, SigningKey};
            use sha2::{Digest, Sha256};
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-dying-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            for name in ["pack", "cache", "work", "compiler"] {
                fs::create_dir(root.join(name)).unwrap();
            }
            // Passes the start gate, then lives until `<root>/die` appears.
            let source = root.join("compiler/main.rs");
            fs::write(&source, r#"use std::{io::{self,Read},thread,time::Duration};fn main(){let mut gate=[0;23];io::stdin().read_exact(&mut gate).unwrap();let flag=std::path::PathBuf::from(env!("DIE_FLAG"));loop{if flag.exists(){std::process::exit(3);}thread::sleep(Duration::from_millis(5));}}"#).unwrap();
            let name = if cfg!(windows) {
                "python.exe"
            } else {
                "python"
            };
            assert!(std::process::Command::new("rustc")
                .env("DIE_FLAG", root.join("die"))
                .arg(&source)
                .arg("-o")
                .arg(root.join("pack").join(name))
                .status()
                .unwrap()
                .success());
            let bytes = fs::read(root.join("pack").join(name)).unwrap();
            let raw = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"protocolVersion":1,"epoch":1,"platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,"provider":"CPUExecutionProvider","python":name,"sourceRevision":"a".repeat(40),"files":{name:{"sha256":format!("{:x}",Sha256::digest(&bytes)),"bytes":bytes.len()}}})).unwrap();
            let key = SigningKey::from_bytes(&[42; 32]);
            let pack = VerifiedRuntime::verify(
                &root.join("pack"),
                &raw,
                &key.sign(&raw).to_bytes(),
                &[key.verifying_key()],
                1,
            )
            .unwrap();
            // What the process would serve: healthy until a prediction arrives, which ends
            // the process and breaks the connection off without an answer.
            let serving = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = serving.local_addr().unwrap().port();
            let flag = root.join("die");
            let dies = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let dying = dies.clone();
            std::thread::spawn(move || {
                for socket in serving.incoming() {
                    let Ok(mut socket) = socket else { break };
                    let mut request = [0; 1024];
                    let read = socket.read(&mut request).unwrap_or(0);
                    if request[..read].starts_with(b"GET") {
                        let _ = socket.write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong",
                        );
                    } else if dying.load(std::sync::atomic::Ordering::Acquire) {
                        fs::write(&flag, b"").unwrap();
                    }
                }
            });
            Self {
                root,
                pack,
                port,
                dies,
            }
        }
        /// `true` (the start): its process ends when asked to predict. `false`: only its
        /// answer breaks off, and the process lives on until it is stopped.
        pub(crate) fn dies(&self, dies: bool) {
            self.dies.store(dies, std::sync::atomic::Ordering::Release);
        }
        pub(crate) fn manifest(&self) -> &str {
            self.pack.manifest_sha256()
        }
        /// Start its process anew, bound to this model and qualification.
        pub(crate) fn start(&self, model_key: &str, qualification_id: &str) -> NativePredictor {
            let _ = fs::remove_file(self.root.join("die"));
            let child = self
                .pack
                .start_sidecar(&self.root.join("cache"), &self.root.join("work"), 19990)
                .unwrap();
            let spec = serde_json::json!({"modelKey":model_key,"entries":{},"fixtureKind":"image"});
            NativePredictor {
                children: vec![Lane {
                    child,
                    manifest_sha256: self.manifest().into(),
                }],
                roles: vec![BoundRole {
                    client: BoundClient::new(self.port, "a".repeat(64), &spec).unwrap(),
                    qualification_id: qualification_id.into(),
                    lane: 0,
                }],
                failed: None,
            }
        }
    }
    impl Drop for DyingRuntime {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn now_ms() -> i64 {
        (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
    }
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    #[test]
    fn worker_loop_can_run_on_the_background_executor() {
        fn check(
            predictor: NativePredictor,
            transport: WorkerTransport,
            qualification: AcceptedQualification,
            cancel: watch::Receiver<bool>,
        ) {
            let future: std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + Send>> =
                Box::pin(predictor.run(transport, qualification, cancel));
            drop(future);
        }
        let _ = check;
    }

    #[tokio::test]
    async fn worker_loop_runs_serially_and_stops_on_first_failure() {
        let (_sender, mut cancel) = watch::channel(false);
        let mut calls = std::cell::Cell::new(0);
        let result = worker_jobs(
            &mut calls,
            |calls, _| {
                Box::pin(async move {
                    calls.set(calls.get() + 1);
                    if calls.get() == 3 {
                        Err("worker_lease_lost".into())
                    } else {
                        Ok(true)
                    }
                })
            },
            &mut cancel,
        )
        .await;
        assert_eq!(calls.get(), 3);
        assert_eq!(result, Err("worker_lease_lost".into()));
    }

    #[tokio::test]
    async fn worker_loop_cancels_a_pending_claim_and_drops_it() {
        struct Guard<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        let (sender, mut cancel) = watch::channel(false);
        let mut dropped = std::sync::atomic::AtomicBool::new(false);
        let run = worker_jobs(
            &mut dropped,
            |dropped, _| {
                let sender = sender.clone();
                Box::pin(async move {
                    let _guard = Guard(dropped);
                    sender.send(true).unwrap();
                    std::future::pending::<Result<bool, String>>().await
                })
            },
            &mut cancel,
        );
        assert_eq!(run.await, Err("worker_cancelled".into()));
        assert!(dropped.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test]
    async fn worker_loop_throttles_immediate_empty_responses() {
        let (sender, mut cancel) = watch::channel(false);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let mut state = &calls;
        let run = worker_jobs(
            &mut state,
            |calls, _| {
                Box::pin(async move {
                    calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(false)
                })
            },
            &mut cancel,
        );
        tokio::pin!(run);
        assert!(tokio::time::timeout(Duration::from_millis(30), &mut run)
            .await
            .is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        sender.send(true).unwrap();
        assert_eq!(run.await, Err("worker_cancelled".into()));
    }

    #[tokio::test]
    async fn worker_loop_never_claims_after_control_is_closed() {
        let (sender, mut cancel) = watch::channel(false);
        drop(sender);
        let result = worker_jobs(
            &mut (),
            |_, _| Box::pin(async { panic!("claim after owner disappeared") }),
            &mut cancel,
        )
        .await;
        assert_eq!(result, Err("worker_cancelled".into()));
    }

    fn stamp(offset: i64) -> String {
        let d = time::OffsetDateTime::now_utc() + time::Duration::seconds(offset);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            d.year(),
            u8::from(d.month()),
            d.day(),
            d.hour(),
            d.minute(),
            d.second()
        )
    }
    fn task() -> ClaimedTask {
        let config = json!({"clip":{"textual":{"modelName":"fixture"}}}).to_string();
        serde_json::from_value(json!({"id":"d621bd72-ad35-4199-95ab-76300756a38e","taskId":"c39d4385-84f8-4c37-a643-1b98fc12df93","deviceId":"445bc2b6-f4cd-439e-b8bb-7e84d7ee0550","sessionId":"1117c1ca-0495-46e9-b579-f321520c2b1a","authorizationEpoch":1,"generation":1,"modelKey":"fixture-key","configSha256":format!("{:x}",Sha256::digest(config.as_bytes())),"configJson":config,"inputSha256":format!("{:x}",Sha256::digest("été".as_bytes())),"inputKind":"text","maxInputBytes":1024,"expiresAt":stamp(30),"qualificationId":"ff8f1290-3c1d-4695-8696-af493be01fe0","qualificationExpiresAt":stamp(120),"executionDeadline":stamp(60)})).unwrap()
    }
    #[test]
    fn execution_stops_at_qualification_expiry_even_with_a_later_task_deadline() {
        let mut task = task();
        task.qualification_expires_at = stamp(5);
        task.expires_at = stamp(2);
        assert!(execution_duration(&task, now_ms()).unwrap() <= Duration::from_secs(5));
        task.qualification_expires_at = stamp(-1);
        assert!(execution_duration(&task, now_ms()).is_err());
    }

    #[tokio::test]
    async fn an_undelivered_heartbeat_is_retried_while_the_lease_is_held_and_a_refusal_ends_it() {
        let tick = Duration::from_millis(5);
        // Interrupted twice, then delivered: the task is still running afterwards.
        let replies = std::sync::Mutex::new(std::collections::VecDeque::from([
            Err("worker_request_interrupted".to_owned()),
            Err("server_http_503".to_owned()),
            Ok(true),
        ]));
        let lease = hold_lease(
            || {
                let next = replies.lock().unwrap().pop_front();
                async move {
                    match next {
                        Some(reply) => reply,
                        None => std::future::pending().await,
                    }
                }
            },
            || false,
            tick,
            tick,
        );
        assert!(tokio::time::timeout(Duration::from_millis(300), lease)
            .await
            .is_err());
        assert!(replies.lock().unwrap().is_empty());
        // Still undeliverable when the last granted expiry passes: the lease is treated as lost.
        let lost = hold_lease(
            || async { Err("worker_request_interrupted".into()) },
            || true,
            tick,
            tick,
        );
        assert_eq!(lost.await, Err("worker_lease_lost".into()));
        // The server answered and refused: no retry, whatever the local clock says.
        for (reply, expected) in [
            (Ok(false), "worker_lease_lost"),
            (
                Err("worker_session_rejected".to_owned()),
                "worker_session_rejected",
            ),
            (
                Err("worker_policy_changed".to_owned()),
                "worker_policy_changed",
            ),
        ] {
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let refused = hold_lease(
                || {
                    calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let reply = reply.clone();
                    async move { reply }
                },
                || false,
                tick,
                tick,
            );
            assert_eq!(refused.await, Err(expected.into()));
            assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn only_failures_confined_to_one_task_are_dropped_and_a_lost_lease_is_never_reported() {
        for code in [
            "worker_result_refused",
            "worker_lease_refused",
            "worker_lease_lost",
            "worker_input_interrupted",
            "runtime_prediction_refused",
            "server_http_500",
            "server_http_503",
            // A refusal of one task this app has no name for.
            "server_http_404",
            "server_http_410",
            "server_http_422",
        ] {
            assert!(task_scoped(code), "{code}");
        }
        // Three of these in a row and the server withdraws the model: the worker qualifies again.
        for code in [
            "worker_execution_deadline",
            "server_http_400",
            "runtime_process_stopped",
        ] {
            assert!(counts_against_grant(code), "{code}");
        }
        for code in [
            "worker_cancelled",
            "worker_input_invalid",
            "runtime_prediction_refused",
            "worker_lease_lost",
            "worker_result_refused",
        ] {
            assert!(!counts_against_grant(code), "{code}");
        }
        // What the server hears about a task given up.
        for (code, report) in [
            ("worker_cancelled", "cancelled"),
            ("worker_input_invalid", "input-invalid"),
            ("runtime_prediction_refused", "input-invalid"),
            ("runtime_process_stopped", "model-unavailable"),
            ("runtime_prediction_interrupted", "model-unavailable"),
            ("worker_execution_deadline", "inference-failed"),
            ("server_http_500", "inference-failed"),
        ] {
            let sent = serde_json::to_value(failure_report(code)).unwrap();
            assert_eq!(sent, json!(report), "{code}");
        }
        // These end the association or the process, not one task.
        for code in [
            "worker_session_rejected",
            "worker_policy_changed",
            "worker_cancelled",
            "worker_claim_invalid",
            "worker_task_qualification_changed",
            "runtime_process_stopped",
            "server_http_401",
        ] {
            assert!(!task_scoped(code), "{code}");
        }
        for code in [
            "worker_result_refused",
            "worker_lease_refused",
            "worker_lease_lost",
            "worker_lease_expired",
            "worker_session_rejected",
            "worker_policy_changed",
        ] {
            assert!(lease_gone(code), "{code}");
        }
        assert!(!lease_gone("worker_input_interrupted"));
        assert!(!lease_gone("runtime_prediction_refused"));
        let mut held = task();
        assert!(!lease_expired(&held, Ok(now_ms())));
        held.expires_at = stamp(-1);
        assert!(lease_expired(&held, Ok(now_ms())));
        held.expires_at = "invalid".into();
        assert!(lease_expired(&held, Ok(now_ms())));
    }

    fn client(port: u16) -> BoundClient {
        BoundClient::new(port, "a".repeat(64), &json!({"modelKey":"fixture-key","entries":{"clip":{"textual":{"modelName":"fixture"}}},"fixtureKind":"text"})).unwrap()
    }
    fn read_request(socket: &mut std::net::TcpStream) -> Vec<u8> {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut part = [0; 1024];
            let count = socket.read(&mut part).unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&part[..count]);
            assert!(bytes.len() <= 65536);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&bytes[..end]);
                let length: usize = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .unwrap()
                    .parse()
                    .unwrap();
                if bytes.len() >= end + 4 + length {
                    return bytes;
                }
            }
        }
    }
    #[test]
    fn refuses_changed_configuration_model_kind_hash_and_deadlines_before_network() {
        tauri::async_runtime::block_on(async {
            let client = client(19998);
            let mut task = task();
            task.model_key = "other".into();
            assert_eq!(
                client
                    .predict(&task, "été".as_bytes(), now_ms())
                    .await
                    .unwrap_err(),
                "worker_model_binding_invalid"
            );
            task = self::task();
            task.config_json = "{}".into();
            assert!(client
                .predict(&task, "été".as_bytes(), now_ms())
                .await
                .is_err());
            task = self::task();
            task.input_kind = InputKind::Image;
            assert!(client
                .predict(&task, "été".as_bytes(), now_ms())
                .await
                .is_err());
            task = self::task();
            assert!(client.predict(&task, b"changed", now_ms()).await.is_err());
            task.expires_at = stamp(-1);
            assert!(client
                .predict(&task, "été".as_bytes(), now_ms())
                .await
                .is_err());
            task = self::task();
            task.execution_deadline = stamp(800);
            assert!(client
                .predict(&task, "été".as_bytes(), now_ms())
                .await
                .is_err());
        });
    }
    #[test]
    fn loopback_prediction_preserves_utf8_configuration_and_private_authentication() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let bytes = read_request(&mut socket);
            let request = String::from_utf8(bytes).unwrap();
            assert!(request.starts_with("POST /predict "));
            assert!(request
                .to_ascii_lowercase()
                .contains(&format!("authorization: bearer {}", "a".repeat(64))));
            assert!(request.contains("été"));
            assert!(request.contains("fixture"));
            let body = r#"{"clip":"[1,2]"}"#;
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let value = tauri::async_runtime::block_on(client(port).predict(
            &task(),
            "été".as_bytes(),
            now_ms(),
        ))
        .unwrap();
        assert_eq!(value, json!({"clip":"[1,2]"}));
        server.join().unwrap();
    }
    #[test]
    fn cancellation_and_lease_loss_never_return_a_prediction() {
        tauri::async_runtime::block_on(async {
            let (_tx, mut cancel) = tokio::sync::watch::channel(true);
            let result = race_prediction(
                std::future::ready(Ok(1)),
                std::future::pending(),
                &mut cancel,
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(result.unwrap_err(), "worker_cancelled");
            let (_tx, mut cancel) = tokio::sync::watch::channel(false);
            let result: Result<u8, String> = race_prediction(
                std::future::pending(),
                std::future::ready(Err("worker_lease_lost".into())),
                &mut cancel,
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(result.unwrap_err(), "worker_lease_lost");
            let result: Result<u8, String> = race_prediction(
                std::future::pending(),
                std::future::pending(),
                &mut cancel,
                Duration::ZERO,
            )
            .await;
            assert_eq!(result.unwrap_err(), "worker_execution_deadline");
        });
    }
    #[test]
    fn response_redirects_and_nonobject_results_are_refused() {
        for (status, body, expected) in [
            ("302 Found", "{}".to_owned(), "server_http_302"),
            ("200 OK", "[]".to_owned(), "runtime_prediction_invalid"),
            (
                "200 OK",
                format!("{{\"data\":\"{}\"}}", "a".repeat(4 * 1024 * 1024)),
                "server_response_too_large",
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let _ = read_request(&mut socket);
                let _ = write!(socket, "HTTP/1.1 {status}\r\nLocation: http://127.0.0.1:1/private\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            });
            assert_eq!(
                tauri::async_runtime::block_on(client(port).predict(
                    &task(),
                    "été".as_bytes(),
                    now_ms()
                ))
                .unwrap_err(),
                expected
            );
            server.join().unwrap();
        }
    }
    #[test]
    fn cancellation_drops_an_inflight_http_prediction() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, mut cancel) = tokio::sync::watch::channel(false);
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let _ = read_request(&mut socket);
            tx.send(true).unwrap();
            assert_eq!(
                socket.read(&mut [0; 1]).unwrap(),
                0,
                "cancelled prediction connection remained open"
            );
        });
        tauri::async_runtime::block_on(async {
            let client = client(port);
            let task = task();
            let result = race_prediction(
                client.predict(&task, "été".as_bytes(), now_ms()),
                std::future::pending(),
                &mut cancel,
                Duration::from_secs(10),
            )
            .await;
            assert_eq!(result.unwrap_err(), "worker_cancelled");
        });
        server.join().unwrap();
    }
    #[test]
    fn description_prediction_preserves_bound_entries_and_binary_image() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let input = [0xff, 0, 0x80];
        let entries =
            json!({"image-description-tagging":{"visual":{"modelName":"Qwen3.5-4B","options":{}}}});
        let config = entries.to_string();
        let expected_config = config.clone();
        let result = json!({"image-description-tagging":{"description":"A red square.","people":[],"environment":"","objects":[],"visible_text":[],"context":"","tags":[]}});
        let response = result.to_string();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let bytes = read_request(&mut socket);
            assert!(bytes.windows(input.len()).any(|w| w == input));
            assert!(String::from_utf8_lossy(&bytes).contains("name=\"image\"; filename=\"input\""));
            let request = String::from_utf8_lossy(&bytes);
            assert!(request.contains(&expected_config));
            assert!(request.contains(&format!("authorization: Bearer {}", "a".repeat(64))));
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            )
            .unwrap();
        });
        let mut task = task();
        task.input_kind = InputKind::Image;
        task.input_sha256 = format!("{:x}", Sha256::digest(input));
        task.config_json = config;
        task.config_sha256 = format!("{:x}", Sha256::digest(task.config_json.as_bytes()));
        let client = BoundClient::new(
            port,
            "a".repeat(64),
            &json!({"modelKey":"fixture-key", "entries":entries, "fixtureKind":"image"}),
        )
        .unwrap();
        assert_eq!(
            tauri::async_runtime::block_on(client.predict(&task, &input, now_ms())).unwrap(),
            result
        );
        server.join().unwrap();
    }
    #[test]
    fn dropping_a_pending_execution_stops_its_owned_process() {
        use crate::native_runtime::VerifiedRuntime;
        use ed25519_dalek::{Signer, SigningKey};
        use std::{
            fs,
            process::Command,
            task::{Context, Poll, Waker},
        };
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-abort-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        for name in ["pack", "cache", "work", "compiler"] {
            fs::create_dir(root.join(name)).unwrap();
        }
        let source = root.join("compiler/main.rs");
        fs::write(&source,r#"use std::{io::{self,Read},thread,time::Duration};fn main(){let mut gate=[0;23];io::stdin().read_exact(&mut gate).unwrap();loop{thread::sleep(Duration::from_millis(10));}}"#).unwrap();
        let name = if cfg!(windows) {
            "python.exe"
        } else {
            "python"
        };
        assert!(Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(root.join("compiler").join(name))
            .status()
            .unwrap()
            .success());
        fs::copy(
            root.join("compiler").join(name),
            root.join("pack").join(name),
        )
        .unwrap();
        let bytes = fs::read(root.join("pack").join(name)).unwrap();
        let raw=serde_json::to_vec(&json!({"schemaVersion":1,"protocolVersion":1,"epoch":1,"platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,"provider":"CPUExecutionProvider","python":name,"sourceRevision":"a".repeat(40),"files":{name:{"sha256":format!("{:x}",Sha256::digest(&bytes)),"bytes":bytes.len()}}})).unwrap();
        let key = SigningKey::from_bytes(&[42; 32]);
        let pack = VerifiedRuntime::verify(
            &root.join("pack"),
            &raw,
            &key.sign(&raw).to_bytes(),
            &[key.verifying_key()],
            1,
        )
        .unwrap();
        let child = pack
            .start_sidecar(&root.join("cache"), &root.join("work"), 19998)
            .unwrap();
        let mut predictor = NativePredictor {
            children: vec![Lane {
                child,
                manifest_sha256: pack.manifest_sha256().into(),
            }],
            roles: vec![BoundRole {
                client: client(19998),
                qualification_id: "fixture".into(),
                lane: 0,
            }],
            failed: None,
        };
        assert!(predictor.is_running().unwrap());
        // FD-52: nothing listens on the port, so the lane is running but not serving yet.
        let lane = pack.manifest_sha256().to_owned();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            // Still not serving at the deadline: that lane failed to start.
            let (_keep, mut never) = watch::channel(false);
            // Named as the runtime's failure, which the worker counts and backs off from.
            assert_eq!(
                predictor.ready(&mut never).await.unwrap_err(),
                "runtime_not_ready"
            );
            assert_eq!(predictor.failed_lane(), Some(lane.as_str()));
            // Cancelled while it is still loading: nothing is blamed (and the old blame is gone).
            let (stop, mut stopping) = watch::channel(false);
            {
                let waiting = predictor.ready(&mut stopping);
                tokio::pin!(waiting);
                assert!(
                    tokio::time::timeout(Duration::from_millis(300), &mut waiting)
                        .await
                        .is_err()
                );
                stop.send(true).unwrap();
                assert_eq!(waiting.await.unwrap_err(), "worker_cancelled");
            }
            assert_eq!(predictor.failed_lane(), None);
            // The wait is dropped (sign-out drops the whole future): nothing is blamed either.
            assert!(
                tokio::time::timeout(Duration::from_millis(300), predictor.ready(&mut never))
                    .await
                    .is_err()
            );
            assert_eq!(predictor.failed_lane(), None);
        });
        // A failed prediction with the process still alive blames no lane.
        predictor.blame_exited(0);
        assert_eq!(predictor.failed_lane(), None);
        // Two lanes: the processor lane fails its first check and then serves; the accelerated
        // lane's check is still pending at the deadline. The accelerated lane is the one blamed.
        {
            let serving = TcpListener::bind("127.0.0.1:0").unwrap();
            let hanging = TcpListener::bind("127.0.0.1:0").unwrap();
            let processor_port = serving.local_addr().unwrap().port();
            let accelerated_port = hanging.local_addr().unwrap().port();
            thread::spawn(move || {
                let mut first = true;
                for socket in serving.incoming() {
                    let Ok(mut socket) = socket else { break };
                    if std::mem::take(&mut first) {
                        continue; // closed without an answer: not serving yet
                    }
                    let mut request = [0; 1024];
                    let _ = socket.read(&mut request);
                    let _ = socket.write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong",
                    );
                }
            });
            thread::spawn(move || {
                // Accepts and never answers.
                let held: Vec<_> = hanging.incoming().collect();
                drop(held);
            });
            let lane = |port: u16, name: &str| Lane {
                child: pack
                    .start_sidecar(&root.join("cache"), &root.join("work"), port)
                    .unwrap(),
                manifest_sha256: name.into(),
            };
            let role = |port: u16, lane: usize| BoundRole {
                client: client(port),
                qualification_id: format!("fixture-{lane}"),
                lane,
            };
            let mut pair = NativePredictor {
                children: vec![lane(19996, "processor"), lane(19997, "accelerated")],
                roles: vec![role(processor_port, 0), role(accelerated_port, 1)],
                failed: None,
            };
            runtime.block_on(async {
                let (_keep, mut never) = watch::channel(false);
                assert_eq!(
                    pair.ready(&mut never).await.unwrap_err(),
                    "runtime_not_ready"
                );
            });
            assert_eq!(pair.failed_lane(), Some("accelerated"));
        }
        let (_sender, mut cancel) = watch::channel(false);
        let mut future = Box::pin(worker_jobs(
            &mut predictor,
            |predictor, _| {
                Box::pin(async move {
                    let _active = ActiveExecution {
                        predictor,
                        retain: false,
                    };
                    std::future::pending::<Result<bool, String>>().await
                })
            },
            &mut cancel,
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        drop(future);
        assert!(!predictor.is_running().unwrap());
        // FD-52: a process that is gone after a failed prediction, or at the next start, is blamed.
        predictor.blame_exited(0);
        assert_eq!(predictor.failed_lane(), Some(lane.as_str()));
        runtime.block_on(async {
            let (_keep, mut never) = watch::channel(false);
            predictor.failed = None;
            assert_eq!(
                predictor.ready(&mut never).await.unwrap_err(),
                "runtime_process_stopped"
            );
        });
        assert_eq!(predictor.failed_lane(), Some(lane.as_str()));
        drop(predictor);
        fs::remove_dir_all(root).unwrap();
    }
}
