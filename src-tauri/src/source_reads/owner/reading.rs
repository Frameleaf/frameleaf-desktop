use super::*;
use crate::source_reads::{Preparation, PreparationView};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparationRequest {
    pub source_id: String,
    pub scan_id: String,
    pub request_id: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparationWork {
    #[serde(flatten)]
    pub request: PreparationRequest,
    pub state: String,
    pub code: Option<String>,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Key {
    pub(super) request: PreparationRequest,
    session: String,
}
fn session(saved: &SavedConnection) -> String {
    let mut hash = Sha256::new();
    hash.update(b"frameleaf/reference-preparation-session/v1");
    for value in [
        &saved.server,
        &saved.server_id,
        &saved.account_id,
        saved.device_id.as_deref().unwrap_or(""),
        &saved.token,
    ] {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    format!("{:x}", hash.finalize())
}
impl Key {
    pub(super) fn new(
        saved: &SavedConnection,
        request: PreparationRequest,
    ) -> Result<Self, String> {
        if !super::super::canonical_uuid(&request.source_id)
            || !super::super::canonical_uuid(&request.request_id)
            || !crate::native_runtime::digest_valid(&request.scan_id, 64)
        {
            return Err("source_read_request_invalid".into());
        }
        Ok(Self {
            request,
            session: session(saved),
        })
    }
    fn view(&self, view: View) -> PreparationWork {
        PreparationWork {
            request: self.request.clone(),
            state: view.state,
            code: view.code,
        }
    }
}
impl Requests {
    /// Installs one bounded read in the application owner, then returns without waiting for export.
    pub async fn start_reference_preparation(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        request: PreparationRequest,
        notify: Arc<dyn Fn(PreparationWork) + Send + Sync>,
    ) -> Result<PreparationWork, String> {
        self.start_preparation_with(base, saved, request, notify, crate::resource_policy::sample)
            .await
    }
    #[cfg(test)]
    pub(in crate::source_reads) async fn start_reference_preparation_for_test(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        request: PreparationRequest,
        notify: Arc<dyn Fn(PreparationWork) + Send + Sync>,
        sample: fn() -> crate::resource_policy::Snapshot,
    ) -> Result<PreparationWork, String> {
        self.start_preparation_with(base, saved, request, notify, sample)
            .await
    }
    async fn start_preparation_with(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        request: PreparationRequest,
        notify: Arc<dyn Fn(PreparationWork) + Send + Sync>,
        sample: fn() -> crate::resource_policy::Snapshot,
    ) -> Result<PreparationWork, String> {
        let key = Key::new(&saved, request)?;
        let event_key = key.clone();
        let requested = key.request.clone();
        let view = self
            .install_checked(
                key.request.source_id.clone(),
                Arc::new(move |view| notify(event_key.view(view))),
                false,
                Some(key.clone()),
                move |progress, signal| async move {
                    progress.set("preparing", None);
                    tauri::async_runtime::spawn_blocking(move || {
                        let check = || {
                            if signal.cancelled.load(Ordering::Acquire) {
                                Err("source_delivery_interrupted".into())
                            } else {
                                Ok(())
                            }
                        };
                        check()?;
                        let identity = authority(&base, &saved, &requested.source_id)?;
                        let mut prep =
                            Preparation::resume(&base, &saved, &identity, &requested.source_id)?;
                        prep.check_scan(&saved, &identity, &requested.scan_id)?;
                        let result = super::preparation::prepare_one(
                            &mut prep,
                            &saved,
                            &identity,
                            &signal.cancelled,
                            &check,
                            sample,
                        );
                        if !result.as_ref().err().is_some_and(|code| unconfirmed(code)) {
                            check()?;
                        }
                        result.map(|_: PreparationView| ())
                    })
                    .await
                    .map_err(|_| "source_read_shutdown_unconfirmed".to_string())?
                },
            )
            .await?;
        Ok(key.view(view))
    }
    pub async fn reference_preparation_status(
        &self,
        saved: &SavedConnection,
        source: &str,
    ) -> Result<Option<PreparationWork>, String> {
        if !super::super::canonical_uuid(source) {
            return Err("source_read_request_invalid".into());
        }
        let owner = self.owner.lock().await;
        if owner.failed || self.status().code.as_deref().is_some_and(unconfirmed) {
            return Err("source_read_shutdown_unconfirmed".into());
        }
        Ok(owner
            .running
            .as_ref()
            .and_then(|running| running.preparation.as_ref())
            .filter(|key| key.request.source_id == source && key.session == session(saved))
            .map(|key| key.view(self.status())))
    }
    /// A stale pause cannot cancel another operation, even after a new sign-in to the same source.
    pub async fn pause_reference_preparation(
        &self,
        saved: &SavedConnection,
        request: PreparationRequest,
    ) -> Result<PreparationWork, String> {
        let key = Key::new(saved, request)?;
        let mut owner = self.owner.lock().await;
        if owner
            .running
            .as_ref()
            .and_then(|running| running.preparation.as_ref())
            != Some(&key)
        {
            return Err("source_read_operation_changed".into());
        }
        self.drain(&mut owner).await?;
        Ok(PreparationWork {
            request: key.request,
            state: "paused".into(),
            code: None,
        })
    }
}
