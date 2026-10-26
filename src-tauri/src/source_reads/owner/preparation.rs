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
    RescanSelected {
        expected_scan: String,
    },
    ApproveRead {
        expected_scan: String,
        additional: u64,
    },
    Discard {
        expected_scan: String,
    },
    Abandon {
        expected_scan: String,
    },
    Rescan {
        relatives: Vec<String>,
        expected_scan: String,
    },
}
impl Requests {
    /// Uses the same application owner drained by source revocation, sign-out and quit.
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
        let replace = !matches!(
            &action,
            PreparationAction::RescanSelected { .. }
                | PreparationAction::ApproveRead { .. }
                | PreparationAction::Abandon { .. }
                | PreparationAction::Discard { .. }
        );
        self.prepare_owned_checked(source, notify, replace, move |cancelled, stop| {
            stop()?;
            let identity = if matches!(
                &action,
                PreparationAction::Abandon { .. } | PreparationAction::Discard { .. }
            ) {
                crate::credentials::identity()?
            } else {
                authority(&base, &saved, &selected_source)?
            };
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
                PreparationAction::RescanSelected { expected_scan } => {
                    Preparation::resume(&base, &saved, &identity, &selected_source)?
                        .rescan_selected(&saved, &identity, &expected_scan, stop)
                }
                PreparationAction::ApproveRead {
                    expected_scan,
                    additional,
                } => {
                    let mut preparation =
                        Preparation::resume(&base, &saved, &identity, &selected_source)?;
                    stop()?;
                    preparation.approve_scan(&saved, &identity, &expected_scan, additional)?;
                    preparation.view(&saved, &identity)
                }
                PreparationAction::Discard { expected_scan } => {
                    Preparation::resume_control(&base, &saved, &identity, &selected_source)?
                        .discard(&saved, &identity, &expected_scan, stop)
                }
                PreparationAction::Abandon { expected_scan } => {
                    Preparation::resume_control(&base, &saved, &identity, &selected_source)?
                        .abandon(&saved, &identity, &expected_scan, stop)
                }
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
                    prepare_one(
                        &mut preparation,
                        &saved,
                        &identity,
                        cancelled,
                        stop,
                        crate::resource_policy::sample,
                    )
                }
            }
        })
        .await
    }
    pub async fn reference_status(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        source: String,
    ) -> Result<Option<crate::source_reads::ReferenceStatus>, String> {
        if !super::super::canonical_uuid(&source) {
            return Err("source_read_request_invalid".into());
        }
        self.prepare_owned_checked(source.clone(), Arc::new(|_| {}), false, move |_, stop| {
            let identity = crate::credentials::identity()?;
            let scope = || {
                let consent = crate::credentials::load::<crate::source_consent::Consent>(
                    crate::source_consent::CREDENTIAL,
                )?
                .ok_or("source_approval_required")?;
                if consent.source_id() != source {
                    return Err("source_approval_changed".into());
                }
                consent.reference_metadata_scope(&saved, &identity)
            };
            let expected_scope = scope()?;
            let check = || {
                stop()?;
                if scope()? != expected_scope {
                    return Err("source_approval_changed".into());
                }
                Ok(())
            };
            let mut status =
                Preparation::reference_status(&base, &saved, &identity, &source, &check)?;
            let mut publications = super::super::publication::catalog(
                &base.join("photo-reads").join(&source).join("publications"),
                &saved,
                &identity,
                &source,
                &expected_scope,
                &check,
            )?;
            for publication in &mut publications {
                check()?;
                if publication.state == "recorded" {
                    if let Some(receipt) = &publication.receipt {
                        match Job::transfer_status(
                            &base,
                            &saved,
                            &identity,
                            &publication.resource_key,
                            receipt,
                            &expected_scope,
                        ) {
                            Ok(transfer) => publication.transfer = Some(transfer),
                            Err(code) => publication.transfer_error = Some(code),
                        }
                    }
                }
            }
            if status.is_none() && !publications.is_empty() {
                status = Some(crate::source_reads::ReferenceStatus {
                    source_id: source.clone(),
                    scans: Vec::new(),
                    publications: Vec::new(),
                });
            }
            if let Some(value) = &mut status {
                value.publications = publications;
            }
            check()?;
            Ok(status)
        })
        .await
    }
    pub async fn approve_reference_transfer(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        input: crate::source_reads::TransferApproval,
    ) -> Result<crate::source_reads::TransferStatus, String> {
        input.validate()?;
        self.prepare_owned_checked(
            input.source_id.clone(),
            Arc::new(|_| {}),
            false,
            move |_, stop| {
                let identity = crate::credentials::identity()?;
                let scope = || {
                    let consent = crate::credentials::load::<crate::source_consent::Consent>(
                        crate::source_consent::CREDENTIAL,
                    )?
                    .ok_or("source_approval_required")?;
                    if consent.source_id() != input.source_id {
                        return Err("source_approval_changed".into());
                    }
                    consent.reference_metadata_scope(&saved, &identity)
                };
                let expected_scope = scope()?;
                let check = || {
                    stop()?;
                    if scope()? != expected_scope {
                        return Err("source_approval_changed".into());
                    }
                    Ok(())
                };
                check()?;
                let _lease = PollLease::acquire(&base, &input.source_id)?;
                let publication = super::super::publication::Publication::recover(
                    &base,
                    &saved,
                    &identity,
                    &input.source_id,
                    expected_scope.clone(),
                    input.resource_key.clone(),
                )?;
                publication.require_record(&input.record_id)?;
                let receipt = publication.transfer_receipt()?;
                let job = Job::open_owned(
                    &base,
                    &saved,
                    &identity,
                    &input.source_id,
                    &input.resource_key,
                    &receipt.version,
                    super::super::OpenMode::Inspect,
                )?;
                job.approve_transfer_with(
                    &saved,
                    &identity,
                    receipt,
                    &expected_scope,
                    &input,
                    &check,
                )
            },
        )
        .await
    }
    #[cfg(test)]
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
        self.prepare_owned_checked(source, notify, true, work).await
    }
    async fn prepare_owned_checked<F, T>(
        &self,
        source: String,
        notify: Arc<dyn Fn(View) + Send + Sync>,
        replace: bool,
        work: F,
    ) -> Result<T, String>
    where
        T: Clone + Send + 'static,
        F: FnOnce(&AtomicBool, &(dyn Fn() -> Result<(), String> + Sync)) -> Result<T, String>
            + Send
            + 'static,
    {
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = super::super::Stop(cancelled.clone());
        let (send, receive) = tokio::sync::oneshot::channel();
        self.install_checked(
            source,
            notify,
            replace,
            None,
            move |progress, signal| async move {
                progress.set("preparing", None);
                let result = tauri::async_runtime::spawn_blocking(move || {
                    let check = || {
                        if cancelled.load(Ordering::Acquire)
                            || signal.cancelled.load(Ordering::Acquire)
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
            },
        )
        .await?;
        receive
            .await
            .map_err(|_| "source_read_shutdown_unconfirmed".to_string())?
    }
}

pub(super) fn prepare_one(
    preparation: &mut Preparation,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    cancelled: &AtomicBool,
    stop: &(dyn Fn() -> Result<(), String> + Sync),
    sample: fn() -> crate::resource_policy::Snapshot,
) -> Result<PreparationView, String> {
    let policy = Mutex::new((
        std::time::Instant::now(),
        sample().refusal(64 * 1024 * 1024),
    ));
    let gate = || {
        stop()?;
        let mut policy = policy.lock().map_err(|_| "network_unknown")?;
        if policy.0.elapsed() >= std::time::Duration::from_secs(1) {
            *policy = (
                std::time::Instant::now(),
                sample().refusal(64 * 1024 * 1024),
            );
        }
        if let Some(code) = policy.1 {
            return Err(code.into());
        }
        stop()
    };
    preparation.stage_and_handoff(saved, identity, cancelled, &gate)
}
