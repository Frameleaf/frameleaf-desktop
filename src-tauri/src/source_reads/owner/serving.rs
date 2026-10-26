//! Request-bound serving uses only the displayed publication/allowance snapshot.
use super::*;
use crate::{resource_bridge::ReadResource, source_reads::publication::PublicationStatus};
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServingSelection {
    pub selection_id: String,
    pub resources: usize,
    pub max_transfer_bytes: u64,
}
pub(in crate::source_reads) struct Selection {
    pub(in crate::source_reads) summary: ServingSelection,
    resources: Vec<ReadResource>,
}
impl Selection {
    pub(in crate::source_reads) fn from_publications(
        source: &str,
        publications: &[PublicationStatus],
    ) -> Result<Option<Self>, String> {
        let mut entries: Vec<_> = publications
            .iter()
            .filter(|entry| {
                entry.state == "recorded"
                    && entry.receipt.is_some()
                    && entry.transfer_error.is_none()
                    && entry.transfer.as_ref().is_some_and(|transfer| {
                        transfer.upload_remaining >= transfer.bytes
                            && (transfer.cache_recorded
                                || transfer.read_remaining >= transfer.read_cost)
                    })
            })
            .collect();
        if entries.is_empty() {
            return Ok(None);
        }
        entries.sort_by(|a, b| a.resource_key.cmp(&b.resource_key));
        if entries
            .windows(2)
            .any(|pair| pair[0].resource_key == pair[1].resource_key)
        {
            return Err("source_serving_selection_changed".into());
        }
        let mut hash = Sha256::new();
        hash.update(b"frameleaf/reference-serving-selection/v1");
        hash.update(source.as_bytes());
        let mut resources = Vec::with_capacity(entries.len());
        let mut max_transfer_bytes = 0u64;
        for entry in entries {
            let transfer = entry
                .transfer
                .as_ref()
                .ok_or("source_serving_selection_changed")?;
            hash.update(
                serde_json::to_vec(&(&entry.resource_key, &entry.record_id, transfer))
                    .map_err(|_| "source_journal_invalid")?,
            );
            max_transfer_bytes = max_transfer_bytes
                .checked_add(transfer.upload_remaining)
                .ok_or("source_transfer_budget_invalid")?;
            resources.push(ReadResource {
                resource_key: entry.resource_key.clone(),
                version: transfer.version.clone(),
            });
        }
        Ok(Some(Self {
            summary: ServingSelection {
                selection_id: format!("{:x}", hash.finalize()),
                resources: resources.len(),
                max_transfer_bytes,
            },
            resources,
        }))
    }
    pub(in crate::source_reads) fn batch(&self, cursor: &mut usize) -> &[ReadResource] {
        let start = *cursor;
        let end = (start + 256).min(self.resources.len());
        *cursor = if end == self.resources.len() { 0 } else { end };
        &self.resources[start..end]
    }
}
pub(super) fn scope(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    source: &str,
) -> Result<String, String> {
    let consent = crate::credentials::load::<crate::source_consent::Consent>(
        crate::source_consent::CREDENTIAL,
    )?
    .ok_or("source_approval_required")?;
    if consent.source_id() != source {
        return Err("source_approval_changed".into());
    }
    consent.reference_metadata_scope(saved, identity)
}
impl Requests {
    pub async fn start_reference_serving(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        request: ServingRequest,
        notify: Arc<dyn Fn(ServingWork) + Send + Sync>,
    ) -> Result<ServingWork, String> {
        self.start_serving_with(base, saved, request, notify, crate::resource_policy::sample)
            .await
    }
    #[cfg(test)]
    pub(in crate::source_reads) async fn start_serving_for_test(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        request: ServingRequest,
        notify: Arc<dyn Fn(ServingWork) + Send + Sync>,
        sample: fn() -> crate::resource_policy::Snapshot,
    ) -> Result<ServingWork, String> {
        self.start_serving_with(base, saved, request, notify, sample)
            .await
    }
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServingRequest {
    pub source_id: String,
    pub selection_id: String,
    pub request_id: String,
}
#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServingWork {
    #[serde(flatten)]
    pub request: ServingRequest,
    pub state: String,
    pub code: Option<String>,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Key {
    pub(super) request: ServingRequest,
    session: String,
}
impl Key {
    pub(super) fn new(saved: &SavedConnection, request: ServingRequest) -> Result<Self, String> {
        if !super::super::canonical_uuid(&request.source_id)
            || !super::super::canonical_uuid(&request.request_id)
            || [&request.selection_id]
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
    pub(super) fn view(&self, view: View) -> ServingWork {
        ServingWork {
            request: self.request.clone(),
            state: view.state,
            code: view.code,
        }
    }
}
impl Requests {
    async fn start_serving_with(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        request: ServingRequest,
        notify: Arc<dyn Fn(ServingWork) + Send + Sync>,
        sample: fn() -> crate::resource_policy::Snapshot,
    ) -> Result<ServingWork, String> {
        let key = Key::new(&saved, request)?;
        let event_key = key.clone();
        let requested = key.request.clone();
        let view = self
            .install_checked(
                requested.source_id.clone(),
                Arc::new(move |view| notify(event_key.view(view))),
                false,
                Some(OperationKey::Serving(key.clone())),
                move |progress, signal| {
                    run(
                        base,
                        saved,
                        requested.source_id,
                        progress,
                        signal,
                        sample,
                        Some(requested.selection_id),
                    )
                },
            )
            .await?;
        Ok(key.view(view))
    }
    pub async fn pause_reference_serving(
        &self,
        saved: &SavedConnection,
        request: ServingRequest,
    ) -> Result<ServingWork, String> {
        let key = Key::new(saved, request)?;
        let mut owner = self.owner.lock().await;
        if owner
            .running
            .as_ref()
            .and_then(|running| running.operation.as_ref())
            .filter(|operation| **operation == OperationKey::Serving(key.clone()))
            .is_none()
        {
            return Err("source_read_operation_changed".into());
        }
        self.drain(&mut owner).await?;
        Ok(ServingWork {
            request: key.request,
            state: "paused".into(),
            code: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serving_requests_bind_source_selection_nonce_and_private_session() {
        let saved = SavedConnection {
            server: "https://photos.example.test/".into(),
            server_id: "server".into(),
            account_id: uuid::Uuid::new_v4().to_string(),
            device_id: Some(uuid::Uuid::new_v4().to_string()),
            token: "session".into(),
            name: "fixture".into(),
            device_name: "fixture".into(),
            mode: "client-worker".into(),
        };
        let request = ServingRequest {
            source_id: uuid::Uuid::new_v4().to_string(),
            selection_id: "a".repeat(64),
            request_id: uuid::Uuid::new_v4().to_string(),
        };
        let key = Key::new(&saved, request.clone()).unwrap();
        assert!(key.matches(&saved, &request.source_id));
        let mut other = saved.clone();
        other.token = "other".into();
        assert!(!key.matches(&other, &request.source_id));
        let mut invalid = request.clone();
        invalid.selection_id = "path".into();
        assert!(Key::new(&saved, invalid).is_err());
        let mut payload = serde_json::to_value(request).unwrap();
        payload["additional"] = serde_json::json!(100);
        assert!(serde_json::from_value::<ServingRequest>(payload).is_err());
    }
}
