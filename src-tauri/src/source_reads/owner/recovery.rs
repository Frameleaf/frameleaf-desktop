//! Reconcile signed publication metadata without opening a Job or its original/provider.
use super::*;
use crate::{
    source_consent::{Consent, CREDENTIAL},
    source_reads::publication::Publication,
    transport,
};

fn authority(saved: &SavedConnection, source: &str) -> Result<(DeviceIdentity, String), String> {
    let identity = crate::credentials::identity()?;
    // Inactive reconnect records are intentionally never considered authority.
    let consent =
        crate::credentials::load::<Consent>(CREDENTIAL)?.ok_or("source_approval_required")?;
    if consent.source_id() != source {
        return Err("source_approval_changed".into());
    }
    let scope = consent.reference_metadata_scope(saved, &identity)?;
    Ok((identity, scope))
}
struct Recovery {
    publication: Publication,
    scope: String,
    lease: PollLease,
}
impl Recovery {
    fn check(
        &self,
        saved: &SavedConnection,
        source: &str,
        cancelled: &AtomicBool,
    ) -> Result<DeviceIdentity, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("source_delivery_interrupted".into());
        }
        self.lease.check()?;
        let (identity, scope) = authority(saved, source)?;
        if scope != self.scope {
            return Err("source_approval_changed".into());
        }
        Ok(identity)
    }
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryRequest {
    pub source_id: String,
    pub resource_key: String,
    pub record_id: String,
    pub request_id: String,
}
#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryWork {
    #[serde(flatten)]
    pub request: RecoveryRequest,
    pub state: String,
    pub code: Option<String>,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Key {
    pub(super) request: RecoveryRequest,
    session: String,
}
impl Key {
    pub(super) fn new(saved: &SavedConnection, request: RecoveryRequest) -> Result<Self, String> {
        if !super::super::canonical_uuid(&request.source_id)
            || !super::super::canonical_uuid(&request.request_id)
            || [&request.resource_key, &request.record_id]
                .iter()
                .any(|value| !crate::native_runtime::digest_valid(value, 64))
        {
            return Err("source_read_request_invalid".into());
        }
        Ok(Self {
            request,
            session: super::reading::session(saved),
        })
    }
    pub(super) fn matches(&self, saved: &SavedConnection, source: &str) -> bool {
        self.request.source_id == source && self.session == super::reading::session(saved)
    }
    pub(super) fn view(&self, view: View) -> RecoveryWork {
        RecoveryWork {
            request: self.request.clone(),
            state: view.state,
            code: view.code,
        }
    }
}
impl Requests {
    pub async fn start_reference_recovery(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        request: RecoveryRequest,
        notify: Arc<dyn Fn(RecoveryWork) + Send + Sync>,
    ) -> Result<RecoveryWork, String> {
        let key = Key::new(&saved, request)?;
        let event_key = key.clone();
        let requested = key.request.clone();
        let view = self
            .install_checked(
                requested.source_id.clone(),
                Arc::new(move |view| notify(event_key.view(view))),
                false,
                Some(OperationKey::Recovery(key.clone())),
                move |progress, signal| {
                    recover(
                        base,
                        saved,
                        requested.source_id,
                        requested.resource_key,
                        requested.record_id,
                        progress,
                        signal,
                    )
                },
            )
            .await?;
        Ok(key.view(view))
    }
    pub async fn pause_reference_recovery(
        &self,
        saved: &SavedConnection,
        request: RecoveryRequest,
    ) -> Result<RecoveryWork, String> {
        let key = Key::new(saved, request)?;
        let mut owner = self.owner.lock().await;
        if owner
            .running
            .as_ref()
            .and_then(|running| running.operation.as_ref())
            .and_then(OperationKey::recovery)
            != Some(&key)
        {
            return Err("source_read_operation_changed".into());
        }
        self.drain(&mut owner).await?;
        Ok(RecoveryWork {
            request: key.request,
            state: "paused".into(),
            code: None,
        })
    }
}

async fn recover(
    base: PathBuf,
    saved: SavedConnection,
    source: String,
    resource_key: String,
    record_id: String,
    progress: Progress,
    mut signal: Signal,
) -> Result<(), String> {
    let client = transport::client()?;
    let current_saved = saved.clone();
    let current_source = source.clone();
    let cancelled = signal.cancelled.clone();
    let mut recovery = tauri::async_runtime::spawn_blocking(move || {
        if cancelled.load(Ordering::Acquire) {
            return Err("source_delivery_interrupted".into());
        }
        let (identity, scope) = authority(&current_saved, &current_source)?;
        let lease = PollLease::acquire(&base, &current_source)?;
        let publication = Publication::recover(
            &base,
            &current_saved,
            &identity,
            &current_source,
            scope.clone(),
            resource_key,
        )?;
        publication.require_record(&record_id)?;
        let recovery = Recovery {
            publication,
            scope,
            lease,
        };
        recovery.check(&current_saved, &current_source, &cancelled)?;
        Ok::<_, String>(recovery)
    })
    .await
    .map_err(|_| "source_read_shutdown_unconfirmed")??;
    // Network waits belong to the installed owner and are drained by stop/sign-out.
    signal
        .wait(transport::reference_capabilities(&client, &saved))
        .await
        .ok_or("source_delivery_interrupted")??;
    progress.set("recovering", None);
    let mut completion = false;
    loop {
        let current_saved = saved.clone();
        let current_source = source.clone();
        let cancelled = signal.cancelled.clone();
        recovery = tauri::async_runtime::spawn_blocking(move || {
            recovery.check(&current_saved, &current_source, &cancelled)?;
            Ok::<_, String>(recovery)
        })
        .await
        .map_err(|_| "source_read_shutdown_unconfirmed")??;
        let (method, path, body) = if completion {
            match recovery.publication.recovery_completion() {
                Some((path, body)) => (reqwest::Method::PATCH, path, Some(body)),
                None => return Ok(()),
            }
        } else {
            (
                reqwest::Method::GET,
                recovery.publication.recovery_path()?,
                None,
            )
        };
        let mut request = client
            .request(
                method,
                crate::connection::normalize_server(&saved.server)?
                    .join(&format!("api/photo-sources/{source}/{path}"))
                    .map_err(|_| "source_publication_invalid")?,
            )
            .bearer_auth(&saved.token)
            .timeout(std::time::Duration::from_secs(30));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = signal
            .wait(async {
                transport::json::<serde_json::Value>(
                    request
                        .send()
                        .await
                        .map_err(|_| "source_publication_interrupted")?,
                )
                .await
            })
            .await
            .ok_or("source_delivery_interrupted")??;
        let current_saved = saved.clone();
        let current_source = source.clone();
        let cancelled = signal.cancelled.clone();
        recovery = tauri::async_runtime::spawn_blocking(move || {
            let identity = recovery.check(&current_saved, &current_source, &cancelled)?;
            if completion {
                recovery.publication.ack(response, &identity)?;
            } else {
                recovery.publication.recover_receipt(response, &identity)?;
            }
            Ok::<_, String>(recovery)
        })
        .await
        .map_err(|_| "source_read_shutdown_unconfirmed")??;
        if completion {
            return Ok(());
        }
        completion = true;
    }
}
