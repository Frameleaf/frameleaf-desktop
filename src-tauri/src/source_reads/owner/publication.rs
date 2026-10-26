use super::*;
use crate::{
    source_reads::{publication::Publication, Preparation, PreparedResource},
    transport,
};

struct Resource {
    job: Job,
    publication: Publication,
    scan: String,
}
impl Resource {
    fn check(
        &self,
        base: &Path,
        saved: &SavedConnection,
        source: &str,
        lease: &PollLease,
        cancelled: &AtomicBool,
    ) -> Result<DeviceIdentity, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("source_delivery_interrupted".into());
        }
        lease.check()?;
        self.job.require_owner()?;
        let identity = authority(base, saved, source)?;
        Preparation::resume_control(base, saved, &identity, source)?
            .check_publication_scan(saved, &identity, &self.scan)?;
        self.job.resource.validate_current(saved, &identity)?;
        Ok(identity)
    }
}
impl Requests {
    /// Publishes metadata for the exact completed scan; original reads require a separate action.
    pub async fn start_reference_publication(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        request: PreparationRequest,
        notify: Arc<dyn Fn(PreparationWork) + Send + Sync>,
    ) -> Result<PreparationWork, String> {
        let key = super::reading::Key::new(&saved, request)?;
        let event_key = key.clone();
        let requested = key.request.clone();
        let view = self
            .install_checked(
                requested.source_id.clone(),
                Arc::new(move |view| notify(event_key.view(view))),
                false,
                Some(OperationKey::Publication(key.clone())),
                move |progress, signal| publish(base, saved, requested, progress, signal),
            )
            .await?;
        Ok(key.view(view))
    }
    pub async fn pause_reference_publication(
        &self,
        saved: &SavedConnection,
        request: PreparationRequest,
    ) -> Result<PreparationWork, String> {
        let key = super::reading::Key::new(saved, request)?;
        let mut owner = self.owner.lock().await;
        if owner
            .running
            .as_ref()
            .and_then(|running| running.operation.as_ref())
            .and_then(OperationKey::publication)
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

async fn inventory(
    base: PathBuf,
    saved: SavedConnection,
    source: String,
    scan: String,
    cancelled: Arc<AtomicBool>,
) -> Result<(PollLease, Vec<PreparedResource>), String> {
    tauri::async_runtime::spawn_blocking(move || {
        if cancelled.load(Ordering::Acquire) {
            return Err("source_delivery_interrupted".into());
        }
        let identity = authority(&base, &saved, &source)?;
        let lease = PollLease::acquire(&base, &source)?;
        let preparation = Preparation::resume_control(&base, &saved, &identity, &source)?;
        preparation.check_publication_scan(&saved, &identity, &scan)?;
        let resources = preparation.prepared_resources(&saved, &identity)?;
        if resources.is_empty() {
            return Err("source_preparation_required".into());
        }
        lease.check()?;
        Ok((lease, resources))
    })
    .await
    .map_err(|_| "source_read_shutdown_unconfirmed")?
}
async fn publish(
    base: PathBuf,
    saved: SavedConnection,
    request: PreparationRequest,
    progress: Progress,
    mut signal: Signal,
) -> Result<(), String> {
    let source = request.source_id;
    let scan = request.scan_id;
    let (lease, resources) = inventory(
        base.clone(),
        saved.clone(),
        source.clone(),
        scan.clone(),
        signal.cancelled.clone(),
    )
    .await?;
    let client = transport::client()?;
    // The wait belongs to the installed owner, so stop cannot be followed by a late worker start.
    signal
        .wait(transport::reference_capabilities(&client, &saved))
        .await
        .ok_or("source_delivery_interrupted")??;
    let lease = Arc::new(lease);
    for selected in resources {
        if signal.cancelled.load(Ordering::Acquire) {
            return Err("source_delivery_interrupted".into());
        }
        progress.set("publishing", None);
        let current_base = base.clone();
        let current_saved = saved.clone();
        let current_source = source.clone();
        let current_lease = lease.clone();
        let cancelled = signal.cancelled.clone();
        let current_scan = scan.clone();
        let mut resource = tauri::async_runtime::spawn_blocking(move || {
            if cancelled.load(Ordering::Acquire) {
                return Err("source_delivery_interrupted".into());
            }
            current_lease.check()?;
            let identity = authority(&current_base, &current_saved, &current_source)?;
            let preparation = Preparation::resume_control(
                &current_base,
                &current_saved,
                &identity,
                &current_source,
            )?;
            preparation.check_publication_scan(&current_saved, &identity, &current_scan)?;
            let job = Job::resume(
                &current_base,
                &current_saved,
                &identity,
                &current_source,
                &selected.resource_key,
                &selected.version,
            )?;
            if job.resource.id != selected.id
                || job.resource.sha256 != selected.sha256
                || job.resource.bytes != selected.bytes
            {
                return Err("source_item_changed".into());
            }
            let publication = job.publication(&current_saved, &identity)?;
            Ok::<_, String>(Resource {
                job,
                publication,
                scan: current_scan,
            })
        })
        .await
        .map_err(|_| "source_read_shutdown_unconfirmed")??;
        while let Some((method, path, body)) = resource.publication.next() {
            let current_base = base.clone();
            let current_saved = saved.clone();
            let current_source = source.clone();
            let current_lease = lease.clone();
            let cancelled = signal.cancelled.clone();
            resource = tauri::async_runtime::spawn_blocking(move || {
                resource.check(
                    &current_base,
                    &current_saved,
                    &current_source,
                    &current_lease,
                    &cancelled,
                )?;
                Ok::<_, String>(resource)
            })
            .await
            .map_err(|_| "source_read_shutdown_unconfirmed")??;
            let request = client
                .request(
                    method,
                    crate::connection::normalize_server(&saved.server)?
                        .join(&format!("api/photo-sources/{source}/{path}"))
                        .map_err(|_| "source_publication_invalid")?,
                )
                .bearer_auth(&saved.token)
                .timeout(std::time::Duration::from_secs(30))
                .json(&body);
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
            let current_base = base.clone();
            let current_saved = saved.clone();
            let current_source = source.clone();
            let current_lease = lease.clone();
            let cancelled = signal.cancelled.clone();
            resource = tauri::async_runtime::spawn_blocking(move || {
                let identity = resource.check(
                    &current_base,
                    &current_saved,
                    &current_source,
                    &current_lease,
                    &cancelled,
                )?;
                resource.publication.ack(response, &identity)?;
                Ok::<_, String>(resource)
            })
            .await
            .map_err(|_| "source_read_shutdown_unconfirmed")??;
        }
        if resource.publication.receipt().is_none() {
            return Err("source_reference_receipt_invalid".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stop_drains_owned_publication_capability_wait_without_late_requests() {
        {
            use tokio::io::AsyncReadExt;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let source = "44444444-4444-4444-8444-444444444444";
            let base = std::env::temp_dir().join(format!(
                "frameleaf-publication-stop-{}",
                uuid::Uuid::new_v4()
            ));
            let saved = SavedConnection {
                server: format!("https://{address}/"),
                server_id: "synthetic".into(),
                account_id: "11111111-1111-4111-8111-111111111111".into(),
                token: "synthetic-publication-session".into(),
                name: "Synthetic".into(),
                device_name: "Synthetic".into(),
                mode: "client-worker".into(),
                device_id: Some("22222222-2222-4222-8222-222222222222".into()),
            };
            let owner = Requests::default();
            let request = PreparationRequest {
                source_id: source.into(),
                scan_id: "a".repeat(64),
                request_id: uuid::Uuid::new_v4().to_string(),
            };
            let key = super::super::reading::Key::new(&saved, request).unwrap();
            owner
                .install_checked(
                    source.into(),
                    Arc::new(|_| {}),
                    false,
                    Some(OperationKey::Publication(key)),
                    move |_, mut signal| async move {
                        signal
                            .wait(transport::reference_capabilities(
                                &transport::client()?,
                                &saved,
                            ))
                            .await
                            .ok_or("source_delivery_interrupted")??;
                        Err("unexpected_late_publication".into())
                    },
                )
                .await
                .unwrap();
            let (mut stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            assert!(owner.is_active());
            tokio::time::timeout(std::time::Duration::from_secs(2), owner.stop())
                .await
                .unwrap()
                .unwrap();
            let mut hello = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                stream.read_to_end(&mut hello),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!owner.is_active());
            assert_eq!(owner.status().state, "stopped");
            assert!(!base.exists());
        }
    }
}
