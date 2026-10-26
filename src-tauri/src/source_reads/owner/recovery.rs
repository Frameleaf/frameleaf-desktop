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
impl Requests {
    pub async fn recover_reference(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        source: String,
        resource_key: String,
        notify: Arc<dyn Fn(View) + Send + Sync>,
    ) -> Result<View, String> {
        if !super::super::canonical_uuid(&source)
            || !crate::native_runtime::digest_valid(&resource_key, 64)
        {
            return Err("source_read_request_invalid".into());
        }
        self.install(source.clone(), notify, move |progress, signal| {
            recover(base, saved, source, resource_key, progress, signal)
        })
        .await
    }
}
async fn recover(
    base: PathBuf,
    saved: SavedConnection,
    source: String,
    resource_key: String,
    progress: Progress,
    mut signal: Signal,
) -> Result<(), String> {
    let client = transport::client()?;
    // Network waits belong to the installed owner and are drained by stop/sign-out.
    signal
        .wait(transport::reference_capabilities(&client, &saved))
        .await
        .ok_or("source_delivery_interrupted")??;
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
