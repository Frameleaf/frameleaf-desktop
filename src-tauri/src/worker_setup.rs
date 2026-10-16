use crate::{connection::SavedConnection, model_cache::check_cancel};
use serde::Serialize;
use std::{
    future::Future,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[derive(Clone, Default, Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SetupStatus {
    pub state: String,
    pub code: Option<String>,
}
#[derive(Clone)]
struct Progress {
    cancelled: Arc<AtomicBool>,
    status: Arc<Mutex<SetupStatus>>,
    notify: Arc<dyn Fn(SetupStatus) + Send + Sync>,
}
impl Progress {
    fn set(&self, state: &str, code: Option<String>) {
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        let status = SetupStatus {
            state: state.into(),
            code,
        };
        let mut current = self.status.lock().unwrap();
        if *current == status {
            return;
        }
        *current = status.clone();
        drop(current);
        (self.notify)(status);
    }
}
struct Running {
    cancel: Arc<AtomicBool>,
    task: tauri::async_runtime::JoinHandle<()>,
}
#[derive(Default)]
pub(crate) struct WorkerSetup {
    running: tokio::sync::Mutex<Option<Running>>,
    status: Arc<Mutex<SetupStatus>>,
}
impl WorkerSetup {
    pub fn status(&self) -> SetupStatus {
        self.status.lock().unwrap().clone()
    }
    async fn start_work<F, Fut>(&self, notify: Arc<dyn Fn(SetupStatus) + Send + Sync>, work: F)
    where
        F: FnOnce(Progress) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let mut running = self.running.lock().await;
        if let Some(previous) = running.take() {
            previous.cancel.store(true, Ordering::Release);
            let _ = previous.task.await;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Progress {
            cancelled: cancel.clone(),
            status: self.status.clone(),
            notify,
        };
        let task = tauri::async_runtime::spawn(async move {
            match work(progress.clone()).await {
                Ok(()) => progress.set("qualified", None),
                Err(code) => {
                    let state = if code == "model_download_permission_required" {
                        "model-download-required"
                    } else {
                        "setup-needs-attention"
                    };
                    let safe = if code.len() <= 128
                        && code
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    {
                        code
                    } else {
                        "worker_setup_failed".into()
                    };
                    progress.set(state, Some(safe));
                }
            }
        });
        *running = Some(Running { cancel, task });
    }
    pub async fn stop(&self) {
        let mut running = self.running.lock().await;
        if let Some(previous) = running.take() {
            previous.cancel.store(true, Ordering::Release);
            let _ = previous.task.await;
        }
        *self.status.lock().unwrap() = SetupStatus::default();
    }
    pub async fn start(
        &self,
        saved: SavedConnection,
        paths: SetupPaths,
        allow_download: bool,
        notify: Arc<dyn Fn(SetupStatus) + Send + Sync>,
    ) {
        self.start_work(notify, move |progress| {
            prepare(saved, paths, allow_download, progress)
        })
        .await;
    }
}

pub(crate) struct SetupPaths {
    pub data: PathBuf,
    pub bundle: PathBuf,
}
async fn cancellable<T>(
    future: impl Future<Output = Result<T, String>>,
    cancel: &AtomicBool,
) -> Result<T, String> {
    check_cancel(cancel)?;
    tokio::select! {
        result = future => result,
        _ = async { loop { if cancel.load(Ordering::Acquire) { break; } tokio::time::sleep(Duration::from_millis(50)).await; } } => Err("worker_setup_cancelled".into())
    }
}
async fn wait_for_capacity<F: Future<Output = Result<(), String>>>(
    required_memory: u64,
    progress: &Progress,
    mut maintain: impl FnMut() -> F,
) -> Result<(), String> {
    loop {
        check_cancel(&progress.cancelled)?;
        cancellable(maintain(), &progress.cancelled).await?;
        let status = tauri::async_runtime::spawn_blocking(crate::resource_policy::sample)
            .await
            .map_err(|_| "resource_status_unavailable")?;
        check_cancel(&progress.cancelled)?;
        let Some(reason) = status.refusal(required_memory) else {
            return Ok(());
        };
        progress.set("paused", Some(reason.into()));
        cancellable(
            async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            },
            &progress.cancelled,
        )
        .await?;
    }
}
async fn prepare(
    saved: SavedConnection,
    paths: SetupPaths,
    allow_download: bool,
    progress: Progress,
) -> Result<(), String> {
    use crate::{
        ml_transport::WorkerTransport,
        model_catalogue::setup_profiles,
        release_policy::open_runtime_store,
        runtime_store::{private_directory, read_bounded},
        transport,
    };
    use serde::Deserialize;
    progress.set("preparing-runtime", None);
    let cancelled = progress.cancelled.clone();
    let data = paths.data.clone();
    let (mut installed, attestation) = tauri::async_runtime::spawn_blocking(move || {
        check_cancel(&cancelled)?;
        let mut missing = Vec::new();
        let mut parent = data.as_path();
        while std::fs::symlink_metadata(parent).is_err() {
            missing.push(parent.to_path_buf());
            parent = parent.parent().ok_or("app_data_directory_unavailable")?;
        }
        crate::native_runtime::absolute_directory(parent)?;
        for directory in missing.iter().rev() {
            private_directory(directory)?;
        }
        private_directory(&data)?;
        private_directory(&data.join("models"))?;
        private_directory(&data.join("scratch"))?;
        let store = open_runtime_store(&data.join("runtimes"))?;
        let installed = match store.load_active()? {
            Some(value) => value,
            None => {
                if !paths.bundle.exists() {
                    return Err("runtime_pack_unavailable".into());
                }
                let manifest = read_bounded(&paths.bundle.join("manifest.json"), 8 * 1024 * 1024)?;
                let signature: [u8; 64] = read_bounded(&paths.bundle.join("manifest.sig"), 64)?
                    .try_into()
                    .map_err(|_| "runtime_signature_invalid")?;
                store.install_and_activate(&paths.bundle.join("payload"), &manifest, &signature)?;
                store.load_active()?.ok_or("runtime_activation_failed")?
            }
        };
        check_cancel(&cancelled)?;
        let attestation = store.attestation(&installed)?;
        Ok::<_, String>((installed, attestation))
    })
    .await
    .map_err(|_| "runtime_preparation_failed")??;
    let client = transport::client()?;
    let caps = cancellable(
        transport::capabilities(&client, &saved),
        &progress.cancelled,
    )
    .await?
    .ok_or("desktop_protocol_unsupported")?;
    if !caps.features.worker_session {
        return Err("desktop_worker_session_unavailable".into());
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Config {
        machine_learning: Ml,
    }
    #[derive(Deserialize)]
    struct Ml {
        enabled: bool,
        clip: Clip,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Clip {
        enabled: bool,
        model_name: String,
    }
    let config: Config = cancellable(
        async {
            let base = crate::connection::normalize_server(&saved.server)?;
            let response = client
                .get(
                    base.join("api/system-config")
                        .map_err(|_| "server_address_invalid")?,
                )
                .bearer_auth(&saved.token)
                .send()
                .await
                .map_err(|_| "server_unreachable_or_certificate_invalid")?;
            transport::json_limit(response, 2 * 1024 * 1024).await
        },
        &progress.cancelled,
    )
    .await?;
    if !config.machine_learning.enabled || !config.machine_learning.clip.enabled {
        return Err("server_model_disabled".into());
    }
    let profiles = setup_profiles(
        &config.machine_learning.clip.model_name,
        installed.source_revision(),
        installed.provider(),
    )?;
    if profiles.is_empty() {
        return Err("server_model_not_supported".into());
    }
    let worker = WorkerTransport::load(&saved)?;
    let network = tauri::async_runtime::spawn_blocking(crate::resource_policy::sample)
        .await
        .map_err(|_| "resource_status_unavailable")?;
    let allow_download = allow_download || network.unmetered == Some(true);
    progress.set("preparing-models", None);
    // Complete acquisition before requesting short-lived nonces.
    let mut caches = Vec::new();
    for profile in &profiles {
        let cache = cancellable(
            profile.prepare_cache(
                &paths.data.join("models"),
                &client,
                &progress.cancelled,
                allow_download,
            ),
            &progress.cancelled,
        )
        .await?;
        caches.push(cache);
    }
    for (profile, cache) in profiles.iter().zip(caches) {
        check_cancel(&progress.cancelled)?;
        wait_for_capacity(profile.minimum_memory(), &progress, || {
            worker.maintain_session()
        })
        .await?;
        progress.set("qualifying", None);
        let challenge = cancellable(
            worker.request_qualification(profile, &attestation, &uuid::Uuid::new_v4().to_string()),
            &progress.cancelled,
        )
        .await?;
        let spec = challenge.specification().to_vec();
        let fixture = challenge.fixture().to_vec();
        let cancel = progress.cancelled.clone();
        let scratch = paths.data.join("scratch");
        let result = tauri::async_runtime::spawn_blocking(move || {
            let qualified = installed.qualify(&cache, &scratch, &spec, &fixture, &cancel)?;
            Ok::<_, String>((installed, qualified))
        })
        .await
        .map_err(|_| "runtime_qualification_failed")??;
        installed = result.0;
        check_cancel(&progress.cancelled)?;
        if !cancellable(
            worker.submit_qualification(&challenge, &result.1),
            &progress.cancelled,
        )
        .await?
        {
            return Err("worker_qualification_refused".into());
        }
        cancellable(
            worker.read_accepted_qualification(profile, &result.1, challenge.id()),
            &progress.cancelled,
        )
        .await?;
    }
    // shortcut: qualification is reported separately until resource-aware job scheduling is wired.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[tokio::test]
    async fn resource_refusal_prevents_work_and_remains_cancellable() {
        let setup = WorkerSetup::default();
        let touched = Arc::new(AtomicBool::new(false));
        let proof = touched.clone();
        let renewals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let renewed = renewals.clone();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        setup
            .start_work(
                Arc::new(move |status| {
                    let _ = tx.send(status);
                }),
                move |progress| async move {
                    wait_for_capacity(u64::MAX, &progress, || async {
                        renewed.fetch_add(1, Ordering::AcqRel);
                        Ok(())
                    })
                    .await?;
                    proof.store(true, Ordering::Release);
                    Ok(())
                },
            )
            .await;
        let status = tokio::time::timeout(Duration::from_secs(7), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, "paused");
        setup.stop().await;
        assert!(!touched.load(Ordering::Acquire));
        assert!(renewals.load(Ordering::Acquire) > 0);
        assert_eq!(setup.status(), SetupStatus::default());
    }
    #[tokio::test]
    async fn fresh_nested_app_directory_reports_missing_pack_without_touching_server_credentials() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-setup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let data = root.join("new-parent/app");
        let progress = Progress {
            cancelled: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(SetupStatus::default())),
            notify: Arc::new(|_| {}),
        };
        let saved = SavedConnection {
            server: "https://127.0.0.1:1".into(),
            server_id: "test".into(),
            account_id: uuid::Uuid::new_v4().to_string(),
            name: "Test".into(),
            token: "synthetic".into(),
            device_name: "Test".into(),
            mode: "client-worker".into(),
            device_id: Some(uuid::Uuid::new_v4().to_string()),
        };
        let result = prepare(
            saved,
            SetupPaths {
                data: data.clone(),
                bundle: root.join("absent"),
            },
            false,
            progress,
        )
        .await;
        let active = data.join("runtimes/active.json").exists();
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(result.unwrap_err(), "runtime_pack_unavailable");
        assert!(!active);
    }
    #[tokio::test]
    async fn sign_out_waits_for_preparation_cleanup_and_prevents_late_status() {
        let setup = WorkerSetup::default();
        let (started_tx, started) = tokio::sync::oneshot::channel();
        let cleaned = Arc::new(AtomicBool::new(false));
        let proof = cleaned.clone();
        setup
            .start_work(Arc::new(|_| {}), move |progress| async move {
                progress.set("downloading-models", None);
                started_tx.send(()).unwrap();
                while !progress.cancelled.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                proof.store(true, Ordering::Release);
                progress.set("qualified", None);
                Ok(())
            })
            .await;
        tokio::time::timeout(Duration::from_secs(2), started)
            .await
            .expect("setup did not start")
            .unwrap();
        assert_eq!(setup.status().state, "downloading-models");
        setup.stop().await;
        assert!(cleaned.load(Ordering::Acquire));
        assert_eq!(setup.status(), SetupStatus::default());
    }
    #[tokio::test]
    async fn failed_preparation_is_visible_without_claiming_processing() {
        let setup = WorkerSetup::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        setup
            .start_work(
                Arc::new(move |status| {
                    let _ = tx.send(status);
                }),
                |_| async { Err("runtime_pack_unavailable".into()) },
            )
            .await;
        let status = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, "setup-needs-attention");
        assert_eq!(status.code.as_deref(), Some("runtime_pack_unavailable"));
        setup.stop().await;
    }
}
