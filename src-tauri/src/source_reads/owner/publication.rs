use super::*;
use crate::{
    source_reads::{publication::Publication, Preparation, PreparedResource},
    transport,
};

struct Resource {
    job: Job,
    publication: Publication,
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
        self.job.resource.validate_current(saved, &identity)?;
        Ok(identity)
    }
}
impl Requests {
    /// Publishes only already-prepared resource metadata; original reads remain separately approved.
    pub async fn publish_reference(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        source: String,
        notify: Arc<dyn Fn(View) + Send + Sync>,
    ) -> Result<View, String> {
        if !super::super::canonical_uuid(&source) {
            return Err("source_read_request_invalid".into());
        }
        self.install(source.clone(), notify, move |progress, signal| {
            publish(base, saved, source, progress, signal)
        })
        .await
    }
}
async fn inventory(
    base: PathBuf,
    saved: SavedConnection,
    source: String,
    cancelled: Arc<AtomicBool>,
) -> Result<(PollLease, Vec<PreparedResource>), String> {
    tauri::async_runtime::spawn_blocking(move || {
        if cancelled.load(Ordering::Acquire) {
            return Err("source_delivery_interrupted".into());
        }
        let identity = authority(&base, &saved, &source)?;
        let lease = PollLease::acquire(&base, &source)?;
        let preparation = Preparation::resume(&base, &saved, &identity, &source)?;
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
    source: String,
    progress: Progress,
    mut signal: Signal,
) -> Result<(), String> {
    let client = transport::client()?;
    // The wait belongs to the installed owner, so stop cannot be followed by a late worker start.
    signal
        .wait(transport::reference_capabilities(&client, &saved))
        .await
        .ok_or("source_delivery_interrupted")??;
    let (lease, resources) = inventory(
        base.clone(),
        saved.clone(),
        source.clone(),
        signal.cancelled.clone(),
    )
    .await?;
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
        let mut resource = tauri::async_runtime::spawn_blocking(move || {
            if cancelled.load(Ordering::Acquire) {
                return Err("source_delivery_interrupted".into());
            }
            current_lease.check()?;
            let identity = authority(&current_base, &current_saved, &current_source)?;
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
            Ok::<_, String>(Resource { job, publication })
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
    async fn stop_cancels_capability_wait_before_inventory_or_publication() {
        for recovery in [false, true] {
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
            if recovery {
                owner
                    .recover_reference(
                        base.clone(),
                        saved,
                        source.into(),
                        "a".repeat(64),
                        Arc::new(|_| {}),
                    )
                    .await
                    .unwrap();
            } else {
                owner
                    .publish_reference(base.clone(), saved, source.into(), Arc::new(|_| {}))
                    .await
                    .unwrap();
            }
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
