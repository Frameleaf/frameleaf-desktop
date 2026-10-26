use super::*;
use crate::source_reads::{Preparation, PreparationView};

/// Local user actions; a server claim never selects a path or grants an allowance.
pub enum PreparationAction {
    Plan {
        relative: String,
    },
    Selection {
        relatives: Vec<String>,
    },
    Read {
        additional: u64,
    },
    Reconcile,
    Rescan {
        relatives: Vec<String>,
        expected_scan: String,
    },
}
impl Requests {
    /// Uses the same application owner drained by source revocation, sign-out and quit.
    /// The reference controls remain hidden until publication and recovery are connected.
    pub async fn prepare_reference(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        source: String,
        action: PreparationAction,
        notify: Arc<dyn Fn(View) + Send + Sync>,
    ) -> Result<PreparationView, String> {
        if !super::super::canonical_uuid(&source) {
            return Err("source_read_request_invalid".into());
        }
        let selected_source = source.clone();
        self.prepare_owned(source, notify, move |cancelled, stop| {
            stop()?;
            let identity = authority(&base, &saved, &selected_source)?;
            match action {
                PreparationAction::Plan { relative } => {
                    Preparation::plan(&base, &saved, &identity, &selected_source, &relative)?
                        .view(&saved, &identity)
                }
                PreparationAction::Selection { relatives } => Preparation::plan_selection(
                    &base,
                    &saved,
                    &identity,
                    &selected_source,
                    &relatives,
                )?
                .view(&saved, &identity),
                PreparationAction::Rescan {
                    relatives,
                    expected_scan,
                } => Preparation::resume(&base, &saved, &identity, &selected_source)?.rescan(
                    &saved,
                    &identity,
                    &relatives,
                    &expected_scan,
                    stop,
                ),
                PreparationAction::Reconcile => {
                    Preparation::resume(&base, &saved, &identity, &selected_source)?
                        .reconcile_capacity(&saved, &identity, stop)
                }
                PreparationAction::Read { additional } => {
                    let mut preparation =
                        Preparation::resume(&base, &saved, &identity, &selected_source)?;
                    if additional > 0 {
                        stop()?;
                        preparation.approve(&saved, &identity, additional)?;
                    }
                    let policy = Mutex::new((
                        std::time::Instant::now(),
                        crate::resource_policy::sample().refusal(64 * 1024 * 1024),
                    ));
                    let gate = || {
                        stop()?;
                        let mut policy = policy.lock().map_err(|_| "network_unknown")?;
                        if policy.0.elapsed() >= std::time::Duration::from_secs(1) {
                            *policy = (
                                std::time::Instant::now(),
                                crate::resource_policy::sample().refusal(64 * 1024 * 1024),
                            );
                        }
                        if let Some(code) = policy.1 {
                            return Err(code.into());
                        }
                        stop()
                    };
                    preparation.stage_and_handoff(&saved, &identity, cancelled, &gate)
                }
            }
        })
        .await
    }
    pub(super) async fn prepare_owned<F>(
        &self,
        source: String,
        notify: Arc<dyn Fn(View) + Send + Sync>,
        work: F,
    ) -> Result<PreparationView, String>
    where
        F: FnOnce(
                &AtomicBool,
                &(dyn Fn() -> Result<(), String> + Sync),
            ) -> Result<PreparationView, String>
            + Send
            + 'static,
    {
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = super::super::Stop(cancelled.clone());
        let (send, receive) = tokio::sync::oneshot::channel();
        self.install(source, notify, move |progress, signal| async move {
            progress.set("preparing", None);
            let result = tauri::async_runtime::spawn_blocking(move || {
                let check = || {
                    if cancelled.load(Ordering::Acquire) || signal.cancelled.load(Ordering::Acquire)
                    {
                        return Err("source_delivery_interrupted".into());
                    }
                    Ok(())
                };
                check()?;
                let result = work(&cancelled, &check);
                if !result.as_ref().err().is_some_and(|code| unconfirmed(code)) {
                    check()?;
                }
                result
            })
            .await
            .map_err(|_| "source_read_shutdown_unconfirmed".to_string())
            .and_then(|result| result);
            let _ = send.send(result.clone());
            result.map(|_| ())
        })
        .await?;
        receive
            .await
            .map_err(|_| "source_read_shutdown_unconfirmed".to_string())?
    }
}
