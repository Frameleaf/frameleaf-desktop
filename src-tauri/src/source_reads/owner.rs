//! The application owns one poller and drains its current read before changing authority.
mod preparation;
mod publication;
mod recovery;
use super::Job;
use crate::connection::{DeviceIdentity, SavedConnection};
use cap_std::{ambient_authority, fs::Dir};
pub use preparation::PreparationAction;
use serde::Serialize;
use std::{
    future::Future,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tokio::sync::watch;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub source_id: String,
    pub state: String,
    pub code: Option<String>,
}
impl Default for View {
    fn default() -> Self {
        Self {
            source_id: String::new(),
            state: "stopped".into(),
            code: None,
        }
    }
}
#[derive(Clone)]
struct Progress {
    source: String,
    status: Arc<Mutex<View>>,
    notify: Arc<dyn Fn(View) + Send + Sync>,
}
impl Progress {
    fn set(&self, state: &str, code: Option<String>) {
        let code = code.map(|code| {
            if code.len() <= 128
                && code
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                code
            } else {
                "source_read_failed".into()
            }
        });
        let view = View {
            source_id: self.source.clone(),
            state: state.into(),
            code,
        };
        if let Ok(mut value) = self.status.lock() {
            *value = view.clone();
        }
        (self.notify)(view);
    }
}
struct Signal {
    cancelled: Arc<AtomicBool>,
    changed: watch::Receiver<bool>,
}
impl Signal {
    async fn wait<T>(&mut self, work: impl Future<Output = T>) -> Option<T> {
        if self.cancelled.load(Ordering::Acquire) {
            return None;
        }
        tokio::select! { biased;
            _=self.changed.wait_for(|stopped|*stopped)=>None,
            result=work=>Some(result),
        }
    }
}
struct Stop {
    cancelled: Arc<AtomicBool>,
    changed: watch::Sender<bool>,
}
impl Stop {
    fn request(&self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.changed.send(true);
    }
}
impl Drop for Stop {
    fn drop(&mut self) {
        self.request();
    }
}
struct Running {
    stop: Stop,
    task: tauri::async_runtime::JoinHandle<Result<(), String>>,
}
#[derive(Default)]
struct Owner {
    running: Option<Running>,
    failed: bool,
}
#[derive(Default)]
pub struct Requests {
    owner: tokio::sync::Mutex<Owner>,
    active: AtomicBool,
    closing: AtomicBool,
    status: Arc<Mutex<View>>,
}
pub(super) fn unconfirmed(code: &str) -> bool {
    matches!(
        code,
        "source_read_shutdown_unconfirmed" | "source_copy_shutdown_unconfirmed"
    )
}
impl Requests {
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
    pub fn status(&self) -> View {
        self.status
            .lock()
            .map(|view| view.clone())
            .unwrap_or_else(|_| View {
                state: "needs-attention".into(),
                code: Some("source_status_unavailable".into()),
                ..View::default()
            })
    }
    pub(crate) fn request_shutdown(&self) -> bool {
        !self.closing.swap(true, Ordering::AcqRel)
    }
    async fn drain(&self, owner: &mut Owner) -> Result<(), String> {
        if owner.failed {
            return Err("source_read_shutdown_unconfirmed".into());
        }
        if let Some(previous) = owner.running.as_mut() {
            previous.stop.request();
            let result = (&mut previous.task).await;
            owner.running.take();
            match result {
                Ok(Ok(())) => {}
                Ok(Err(code)) if !unconfirmed(&code) => {}
                _ => {
                    owner.failed = true;
                    return Err("source_read_shutdown_unconfirmed".into());
                }
            }
        }
        self.active.store(false, Ordering::Release);
        Ok(())
    }
    pub(crate) async fn check_available(&self) -> Result<(), String> {
        let owner = self.owner.lock().await;
        if owner.failed || self.status().code.as_deref().is_some_and(unconfirmed) {
            return Err("source_read_shutdown_unconfirmed".into());
        }
        if self.closing.load(Ordering::Acquire) {
            return Err("source_read_shutting_down".into());
        }
        Ok(())
    }
    pub async fn stop(&self) -> Result<(), String> {
        let mut owner = self.owner.lock().await;
        self.drain(&mut owner).await?;
        *self
            .status
            .lock()
            .map_err(|_| "source_status_unavailable")? = View::default();
        Ok(())
    }
    pub async fn shutdown(&self) -> Result<(), String> {
        self.closing.store(true, Ordering::Release);
        self.stop().await
    }
    async fn install<F, Fut>(
        &self,
        source: String,
        notify: Arc<dyn Fn(View) + Send + Sync>,
        work: F,
    ) -> Result<View, String>
    where
        F: FnOnce(Progress, Signal) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        self.install_checked(source, notify, true, work).await
    }
    async fn install_checked<F, Fut>(
        &self,
        source: String,
        notify: Arc<dyn Fn(View) + Send + Sync>,
        replace: bool,
        work: F,
    ) -> Result<View, String>
    where
        F: FnOnce(Progress, Signal) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let mut owner = self.owner.lock().await;
        if !replace
            && self.active.load(Ordering::Acquire)
            && !matches!(self.status().state.as_str(), "stopped" | "needs-attention")
        {
            return Err("source_read_already_running".into());
        }
        self.drain(&mut owner).await?;
        if self.closing.load(Ordering::Acquire) {
            return Err("source_read_shutting_down".into());
        }
        let (send, receive) = watch::channel(false);
        let cancelled = Arc::new(AtomicBool::new(false));
        let progress = Progress {
            source,
            status: self.status.clone(),
            notify,
        };
        progress.set("starting", None);
        self.active.store(true, Ordering::Release);
        let signal = Signal {
            cancelled: cancelled.clone(),
            changed: receive,
        };
        let task_cancelled = cancelled.clone();
        let task = tauri::async_runtime::spawn(async move {
            let result = work(progress.clone(), signal).await;
            if result.as_ref().err().is_some_and(|code| unconfirmed(code)) {
                progress.set("needs-attention", result.as_ref().err().cloned());
            } else if task_cancelled.load(Ordering::Acquire) {
                progress.set("stopped", None);
            } else {
                match &result {
                    Ok(()) => progress.set("stopped", None),
                    Err(code) => progress.set("needs-attention", Some(code.clone())),
                }
            }
            result
        });
        owner.running = Some(Running {
            stop: Stop {
                cancelled,
                changed: send,
            },
            task,
        });
        Ok(self.status())
    }
    /// Called only after local reference approval and resource allowances exist; no UI activates it yet.
    pub async fn start(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        source: String,
        notify: Arc<dyn Fn(View) + Send + Sync>,
    ) -> Result<View, String> {
        if !super::canonical_uuid(&source) {
            return Err("source_read_request_invalid".into());
        }
        self.install(source.clone(), notify, move |progress, signal| {
            run(base, saved, source, progress, signal)
        })
        .await
    }
}

struct PollLease {
    root: PathBuf,
    identity: String,
    stamp: String,
    file: std::fs::File,
}
impl PollLease {
    fn acquire(base: &Path, source: &str) -> Result<Self, String> {
        if !super::canonical_uuid(source) {
            return Err("source_read_request_invalid".into());
        }
        let root = base.join("photo-reads").join(source);
        crate::native_runtime::absolute_directory(&root)?;
        crate::runtime_store::private_directory(&root)?;
        let mut records = 0;
        let mut entries = 0;
        for entry in std::fs::read_dir(&root).map_err(|_| "source_read_inventory_required")? {
            entries += 1;
            if entries > 10_002 {
                return Err("source_inventory_partial".into());
            }
            let entry = entry.map_err(|_| "source_journal_invalid")?;
            let name = entry.file_name();
            if !name
                .to_str()
                .is_some_and(|name| crate::native_runtime::digest_valid(name, 64))
            {
                continue;
            }
            if !entry
                .file_type()
                .map_err(|_| "source_journal_invalid")?
                .is_dir()
            {
                return Err("source_journal_invalid".into());
            }
            let meta = std::fs::symlink_metadata(entry.path().join("state.json"))
                .map_err(|_| "source_journal_invalid")?;
            if meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.len() > 0
                && meta.len() <= 4 * 1024 * 1024
            {
                records += 1;
            }
        }
        if records == 0 {
            return Err("source_read_inventory_required".into());
        }
        let dir = Dir::open_ambient_dir(&root, ambient_authority())
            .map_err(|_| "source_journal_invalid")?;
        let file = dir
            .open_with(".poll-owner.lock", &crate::host_state::options(true))
            .map_err(|_| "source_journal_invalid")?;
        let stamp = crate::copy_source::opened_stamp(&file)?;
        let file = file.into_std();
        crate::host_state::valid_file(&file)?;
        if file.metadata().map_err(|_| "source_journal_invalid")?.len() != 0 {
            return Err("source_journal_invalid".into());
        }
        file.try_lock().map_err(|_| "source_read_already_running")?;
        let identity = crate::copy_source::source_root_identity(&dir)?;
        let lease = Self {
            root,
            identity,
            stamp,
            file,
        };
        lease.check()?;
        Ok(lease)
    }
    fn check(&self) -> Result<(), String> {
        crate::native_runtime::absolute_directory(&self.root)?;
        let dir = Dir::open_ambient_dir(&self.root, ambient_authority())
            .map_err(|_| "source_journal_invalid")?;
        if crate::copy_source::source_root_identity(&dir)? != self.identity {
            return Err("source_journal_invalid".into());
        }
        crate::host_state::valid_file(&self.file)?;
        let named = dir
            .open_with(".poll-owner.lock", &crate::host_state::options(false))
            .map_err(|_| "source_journal_invalid")?;
        if crate::copy_source::opened_stamp(&named)? != self.stamp {
            return Err("source_journal_invalid".into());
        }
        Ok(())
    }
}
fn authority(base: &Path, saved: &SavedConnection, source: &str) -> Result<DeviceIdentity, String> {
    let identity = crate::credentials::identity()?;
    let consent = crate::source_import::current(saved, &identity, source)?;
    let approval = consent.reference_approval(saved, &identity)?;
    if !approval.is_photos()
        && (base.starts_with(approval.root()) || approval.root().starts_with(base))
    {
        return Err("source_staging_overlap".into());
    }
    Ok(identity)
}
async fn run(
    base: PathBuf,
    saved: SavedConnection,
    source: String,
    progress: Progress,
    mut signal: Signal,
) -> Result<(), String> {
    let initial_base = base.clone();
    let initial_saved = saved.clone();
    let initial_source = source.clone();
    let stop = signal.cancelled.clone();
    let lease = tauri::async_runtime::spawn_blocking(move || {
        if stop.load(Ordering::Acquire) {
            return Err("source_delivery_interrupted".into());
        }
        authority(&initial_base, &initial_saved, &initial_source)?;
        PollLease::acquire(&initial_base, &initial_source)
    })
    .await
    .map_err(|_| "source_read_shutdown_unconfirmed")??;
    let lease = Arc::new(lease);
    while !signal.cancelled.load(Ordering::Acquire) {
        let current_base = base.clone();
        let current_saved = saved.clone();
        let current_source = source.clone();
        let current_lease = lease.clone();
        let (identity, refusal) = tauri::async_runtime::spawn_blocking(move || {
            current_lease.check()?;
            let identity = authority(&current_base, &current_saved, &current_source)?;
            Ok::<_, String>((
                identity,
                crate::resource_policy::sample().refusal(64 * 1024 * 1024),
            ))
        })
        .await
        .map_err(|_| "source_read_shutdown_unconfirmed")??;
        if signal.cancelled.load(Ordering::Acquire) {
            break;
        }
        if let Some(code) = refusal {
            progress.set("paused", Some(code.into()));
        } else {
            progress.set("waiting", None);
            let Some(result) = signal
                .wait(crate::resource_bridge::poll(
                    &saved,
                    &identity,
                    &source,
                    2 * 1024 * 1024 * 1024,
                ))
                .await
            else {
                break;
            };
            if let Some(claim) = result? {
                let (request_source, key, version) = claim.resource_binding();
                if request_source != source {
                    return Err("source_read_request_invalid".into());
                }
                let key = key.to_owned();
                let version = version.to_owned();
                let current_base = base.clone();
                let current_saved = saved.clone();
                let current_source = source.clone();
                let current_lease = lease.clone();
                let stop = signal.cancelled.clone();
                let (job, identity) = tauri::async_runtime::spawn_blocking(move || {
                    current_lease.check()?;
                    if stop.load(Ordering::Acquire) {
                        return Err("source_delivery_interrupted".into());
                    }
                    let job = Job::resume(
                        &current_base,
                        &current_saved,
                        &identity,
                        &current_source,
                        &key,
                        &version,
                    )?;
                    Ok::<_, String>((Arc::new(job), identity))
                })
                .await
                .map_err(|_| "source_read_shutdown_unconfirmed")??;
                if signal.cancelled.load(Ordering::Acquire) {
                    break;
                }
                progress.set("serving", None);
                job.serve(saved.clone(), identity, claim, signal.cancelled.clone())
                    .await?;
            }
        }
        if signal
            .wait(tokio::time::sleep(std::time::Duration::from_secs(10)))
            .await
            .is_none()
        {
            break;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    fn notify() -> Arc<dyn Fn(View) + Send + Sync> {
        Arc::new(|_| {})
    }
    fn prepared() -> super::super::PreparationView {
        super::super::PreparationView {
            source_id: "source".into(),
            scan_id: "a".repeat(64),
            abandoned: false,
            maximum_bytes: 10,
            export: false,
            spent: 10,
            remaining: 0,
            prepared: true,
            resources: 1,
            completed: 1,
            staging_remaining: 2 * 1024 * 1024 * 1024 - 10,
        }
    }
    #[tokio::test]
    async fn cancelled_preparation_reply_cancels_but_retains_blocking_owner_until_drain() {
        let owner = Arc::new(Requests::default());
        let (ready, started) = tokio::sync::oneshot::channel();
        let (observed, stopping) = tokio::sync::oneshot::channel();
        let (finish, wait) = std::sync::mpsc::channel();
        let caller_owner = owner.clone();
        let caller = tokio::spawn(async move {
            caller_owner
                .prepare_owned("source".into(), notify(), move |_, check| {
                    ready.send(()).unwrap();
                    while check().is_ok() {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    observed.send(()).unwrap();
                    wait.recv().unwrap();
                    Ok(prepared())
                })
                .await
        });
        started.await.unwrap();
        caller.abort();
        assert!(caller.await.is_err_and(|error| error.is_cancelled()));
        tokio::time::timeout(std::time::Duration::from_secs(2), stopping)
            .await
            .unwrap()
            .unwrap();
        assert!(owner.is_active());
        let mut stop = Box::pin(owner.stop());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut stop)
                .await
                .is_err()
        );
        assert!(owner.is_active());
        finish.send(()).unwrap();
        stop.await.unwrap();
        assert!(!owner.is_active());
    }
    #[tokio::test]
    async fn stopping_preparation_drains_before_reply_and_preserves_unknown_failure() {
        for unknown in [false, true] {
            let owner = Arc::new(Requests::default());
            let (ready, started) = tokio::sync::oneshot::channel();
            let (observed, stopping) = tokio::sync::oneshot::channel();
            let (finish, wait) = std::sync::mpsc::channel();
            let caller_owner = owner.clone();
            let caller = tokio::spawn(async move {
                caller_owner
                    .prepare_owned("source".into(), notify(), move |_, check| {
                        ready.send(()).unwrap();
                        while check().is_ok() {
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                        observed.send(()).unwrap();
                        wait.recv().unwrap();
                        if unknown {
                            Err("source_copy_shutdown_unconfirmed".into())
                        } else {
                            Ok(prepared())
                        }
                    })
                    .await
            });
            started.await.unwrap();
            let stop_owner = owner.clone();
            let stop = tokio::spawn(async move { stop_owner.stop().await });
            tokio::time::timeout(std::time::Duration::from_secs(2), stopping)
                .await
                .unwrap()
                .unwrap();
            assert!(!caller.is_finished());
            assert!(!stop.is_finished());
            finish.send(()).unwrap();
            assert_eq!(
                caller.await.unwrap().err().as_deref(),
                Some(if unknown {
                    "source_copy_shutdown_unconfirmed"
                } else {
                    "source_delivery_interrupted"
                })
            );
            assert_eq!(
                stop.await.unwrap().err().as_deref(),
                if unknown {
                    Some("source_read_shutdown_unconfirmed")
                } else {
                    None
                }
            );
            assert_eq!(owner.is_active(), unknown);
        }
    }
    #[tokio::test]
    async fn metadata_inspection_cannot_replace_or_cancel_active_source_work() {
        let owner = Requests::default();
        let (finish, wait) = tokio::sync::oneshot::channel();
        owner
            .install("source".into(), notify(), move |_, _| async move {
                let _ = wait.await;
                Ok(())
            })
            .await
            .unwrap();
        let result = owner
            .install_checked("inspect".into(), notify(), false, |_, _| async move {
                panic!("inspection must not replace the active task")
            })
            .await;
        assert_eq!(result.err().as_deref(), Some("source_read_already_running"));
        assert!(owner.is_active());
        assert!(!owner
            .owner
            .lock()
            .await
            .running
            .as_ref()
            .unwrap()
            .stop
            .cancelled
            .load(Ordering::Acquire));
        let source = uuid::Uuid::new_v4().to_string();
        let saved = SavedConnection {
            server: "https://server.test/".into(),
            server_id: "server".into(),
            account_id: "owner".into(),
            name: "Synthetic".into(),
            token: "synthetic".into(),
            device_name: "Synthetic".into(),
            mode: "client-worker".into(),
            device_id: Some("device".into()),
        };
        for action in [
            PreparationAction::RescanSelected {
                expected_scan: "a".repeat(64),
            },
            PreparationAction::ApproveRead {
                expected_scan: "a".repeat(64),
                additional: 10,
            },
        ] {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                owner.prepare_reference(
                    PathBuf::new(),
                    saved.clone(),
                    source.clone(),
                    action,
                    notify(),
                ),
            )
            .await
            .unwrap();
            assert_eq!(result.err().as_deref(), Some("source_read_already_running"));
            assert!(!owner
                .owner
                .lock()
                .await
                .running
                .as_ref()
                .unwrap()
                .stop
                .cancelled
                .load(Ordering::Acquire));
        }
        finish.send(()).unwrap();
        owner.stop().await.unwrap();
    }
    #[tokio::test]
    async fn preparation_panic_reports_unknown_and_fences_replacement() {
        let owner = Requests::default();
        assert_eq!(
            owner
                .prepare_owned("source".into(), notify(), |_, _| {
                    panic!("synthetic blocking preparation panic")
                })
                .await
                .err()
                .as_deref(),
            Some("source_read_shutdown_unconfirmed")
        );
        assert_eq!(
            owner.stop().await.err().as_deref(),
            Some("source_read_shutdown_unconfirmed")
        );
        assert!(owner.is_active());
        assert!(owner
            .prepare_owned("next".into(), notify(), |_, _| Ok(prepared()))
            .await
            .is_err());
    }
    #[tokio::test]
    async fn preparation_result_is_returned_only_after_owned_work_finishes() {
        let owner = Requests::default();
        let view = owner
            .prepare_owned("source".into(), notify(), |_, check| {
                check()?;
                Ok(prepared())
            })
            .await
            .unwrap();
        assert!(view.prepared);
        assert_eq!(view.spent, 10);
        owner.stop().await.unwrap();
        assert!(!owner.is_active());
    }
    #[tokio::test]
    async fn cancelled_stop_retains_the_owned_task_until_a_later_drain() {
        let owner = Requests::default();
        let (observed, stopping) = tokio::sync::oneshot::channel();
        let (finish, wait) = tokio::sync::oneshot::channel();
        owner
            .install("source".into(), notify(), move |_, signal| async move {
                while !signal.cancelled.load(Ordering::Acquire) {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                let _ = observed.send(());
                let _ = wait.await;
                Ok(())
            })
            .await
            .unwrap();
        let mut stop = Box::pin(owner.stop());
        tokio::select! {
            result = &mut stop => panic!("stop returned before worker finished: {result:?}"),
            result = stopping => result.unwrap(),
        }
        drop(stop);
        assert!(owner.owner.lock().await.running.is_some());
        assert!(owner.is_active());
        let mut stop = Box::pin(owner.stop());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut stop)
                .await
                .is_err()
        );
        finish.send(()).unwrap();
        stop.await.unwrap();
        assert!(!owner.is_active());
    }
    #[tokio::test]
    async fn stop_waits_for_owned_blocking_work_and_excludes_replacement() {
        let owner = Arc::new(Requests::default());
        let (ready, started) = tokio::sync::oneshot::channel();
        let (observed, stopping) = tokio::sync::oneshot::channel();
        let (finish, wait) = std::sync::mpsc::channel();
        owner
            .install("source".into(), notify(), move |_, signal| async move {
                tokio::task::spawn_blocking(move || {
                    ready.send(()).unwrap();
                    while !signal.cancelled.load(Ordering::Acquire) {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    observed.send(()).unwrap();
                    wait.recv().unwrap();
                })
                .await
                .unwrap();
                Ok(())
            })
            .await
            .unwrap();
        started.await.unwrap();
        let stopper = owner.clone();
        let stopped = tokio::spawn(async move { stopper.stop().await });
        stopping.await.unwrap();
        assert!(owner.is_active());
        assert!(!stopped.is_finished());
        let replaced = Arc::new(AtomicBool::new(false));
        let seen = replaced.clone();
        let next_owner = owner.clone();
        let next = tokio::spawn(async move {
            next_owner
                .install("next".into(), notify(), move |_, mut signal| async move {
                    seen.store(true, Ordering::Release);
                    signal.wait(std::future::pending::<()>()).await;
                    Ok(())
                })
                .await
        });
        tokio::task::yield_now().await;
        assert!(!replaced.load(Ordering::Acquire));
        finish.send(()).unwrap();
        stopped.await.unwrap().unwrap();
        next.await.unwrap().unwrap();
        owner.stop().await.unwrap();
        assert!(!owner.is_active());
    }
    #[tokio::test]
    async fn panic_keeps_a_fence_instead_of_claiming_shutdown_or_starting_another_worker() {
        let owner = Requests::default();
        owner
            .install("source".into(), notify(), |_, _| async {
                panic!("synthetic owner failure");
            })
            .await
            .unwrap();
        assert_eq!(
            owner.stop().await.unwrap_err(),
            "source_read_shutdown_unconfirmed"
        );
        assert!(owner.is_active());
        assert!(owner
            .install("next".into(), notify(), |_, _| async { Ok(()) })
            .await
            .is_err());
    }
    #[tokio::test]
    async fn reported_unconfirmed_shutdown_fences_the_owner_even_if_its_outer_task_returns() {
        let owner = Requests::default();
        owner
            .install("source".into(), notify(), |_, _| async {
                Err("source_copy_shutdown_unconfirmed".into())
            })
            .await
            .unwrap();
        assert_eq!(
            owner.stop().await.unwrap_err(),
            "source_read_shutdown_unconfirmed"
        );
        assert!(owner.is_active());
    }
    #[tokio::test]
    async fn shutdown_wakes_idle_wait_and_refuses_later_starts() {
        let owner = Requests::default();
        owner
            .install("source".into(), notify(), |_, mut signal| async move {
                assert!(signal.wait(std::future::pending::<()>()).await.is_none());
                Ok(())
            })
            .await
            .unwrap();
        owner.shutdown().await.unwrap();
        assert!(!owner.is_active());
        assert!(owner
            .install("next".into(), notify(), |_, _| async { Ok(()) })
            .await
            .is_err());
    }
    #[test]
    fn polling_lease_requires_inventory_and_excludes_a_second_owner() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-poll-owner-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let source = uuid::Uuid::new_v4().to_string();
        assert!(PollLease::acquire(&root, &source).is_err());
        assert!(!root.join("photo-reads").exists());
        for path in [
            root.join("photo-reads"),
            root.join("photo-reads").join(&source),
        ] {
            crate::runtime_store::private_directory(&path).unwrap();
        }
        let record = root.join("photo-reads").join(&source).join("a".repeat(64));
        crate::runtime_store::private_directory(&record).unwrap();
        std::fs::write(
            record.join("state.json"),
            b"synthetic descriptor placeholder",
        )
        .unwrap();
        let lease = PollLease::acquire(&root, &source).unwrap();
        assert!(PollLease::acquire(&root, &source).is_err());
        lease.check().unwrap();
        drop(lease);
        PollLease::acquire(&root, &source).unwrap();
    }
}
