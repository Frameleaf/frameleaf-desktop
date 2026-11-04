//! Opt-in real NAS fixture; credentials live only in this test process.
use super::*;

#[test]
#[ignore = "changes the credential builder; run alone in its own test process"]
fn isolated_keyring_retains_real_worker_checkpoints_without_os_storage() {
    install_test_keyring();
    let worker: SavedWorker = serde_json::from_value(serde_json::json!({
        "serverId":"synthetic-server","accountId":"synthetic-account","deviceId":"synthetic-device",
        "sessionId":"1117c1ca-0495-46e9-b579-f321520c2b1a","authorizationEpoch":2,
        "workerToken":"a".repeat(64),"expiresAt":"2099-01-01T00:00:00Z","nextSequence":1
    }))
    .unwrap();
    credentials::save("worker-session", &worker).unwrap();
    let mut next = worker.clone();
    next.next_sequence = 2;
    credentials::save_worker_checkpoint(&worker, &next).unwrap();
    assert!(credentials::load::<SavedWorker>("worker-session")
        .unwrap()
        .is_some_and(|value| value == next));
    assert!(credentials::save_worker_checkpoint(&worker, &next).is_err());
    credentials::delete("worker-session").unwrap();
    assert!(credentials::load::<SavedWorker>("worker-session")
        .unwrap()
        .is_none());
}

type CredentialKey = (Option<String>, String, String);
type Secrets = std::sync::Arc<
    std::sync::Mutex<std::collections::BTreeMap<CredentialKey, zeroize::Zeroizing<Vec<u8>>>>,
>;
#[derive(Default)]
struct MemoryCredentials(Secrets);
struct MemoryEntry {
    values: Secrets,
    key: CredentialKey,
}
impl keyring::credential::CredentialApi for MemoryEntry {
    fn set_secret(&self, bytes: &[u8]) -> keyring::Result<()> {
        self.values
            .lock()
            .unwrap()
            .insert(self.key.clone(), zeroize::Zeroizing::new(bytes.to_vec()));
        Ok(())
    }
    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        self.values
            .lock()
            .unwrap()
            .get(&self.key)
            .map(|v| v.to_vec())
            .ok_or(keyring::Error::NoEntry)
    }
    fn delete_credential(&self) -> keyring::Result<()> {
        self.values
            .lock()
            .unwrap()
            .remove(&self.key)
            .map(|_| ())
            .ok_or(keyring::Error::NoEntry)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
impl keyring::credential::CredentialBuilderApi for MemoryCredentials {
    fn build(
        &self,
        target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring::Result<Box<keyring::credential::Credential>> {
        Ok(Box::new(MemoryEntry {
            values: self.0.clone(),
            key: (target.map(String::from), service.into(), user.into()),
        }))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn persistence(&self) -> keyring::credential::CredentialPersistence {
        keyring::credential::CredentialPersistence::ProcessOnly
    }
}
pub(crate) fn install_test_keyring() {
    keyring::set_default_credential_builder(Box::<MemoryCredentials>::default());
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureConnection {
    server: String,
    email: String,
    password: String,
    ca_pem: String,
    work_root: std::path::PathBuf,
}
struct OwnedRoot(std::path::PathBuf);
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
pub(crate) fn read_fixture_message(reader: &mut impl std::io::BufRead) -> serde_json::Value {
    use std::io::BufRead;
    let mut line = Vec::new();
    std::io::Read::take(reader, 65537)
        .read_until(b'\n', &mut line)
        .unwrap();
    assert!(
        !line.is_empty() && line.len() <= 65536,
        "fixture protocol length"
    );
    serde_json::from_slice(&line).expect("fixture protocol JSON")
}

#[test]
#[ignore = "requires the owned HTTPS/PostgreSQL fixture, factory CPU pack and approved model cache"]
fn actual_native_nas_library_jobs() {
    use crate::native_predictor::NativePredictor;
    use std::{
        fs,
        io::Write,
        path::PathBuf,
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };
    install_test_keyring();
    let identity = credentials::identity().unwrap();
    let enrollment = identity
        .enrollment("synthetic", "synthetic", "Native fixture", "client-worker")
        .unwrap();
    // Separate the protocol packet from libtest's test-name prefix.
    println!(
        "\nNATIVE_IDENTITY {}",
        serde_json::to_string(&enrollment).unwrap()
    );
    std::io::stdout().flush().unwrap();
    let mut input = std::io::BufReader::new(std::io::stdin());
    let configuration: FixtureConnection =
        serde_json::from_value(read_fixture_message(&mut input)).expect("fixture connection");
    assert!(credentials::load::<SavedConnection>("connection")
        .unwrap()
        .is_none());
    assert!(credentials::load::<SavedWorker>("worker-session")
        .unwrap()
        .is_none());
    let url = normalize_server(&configuration.server).unwrap();
    assert_eq!(url.host_str(), Some("tun.eu1.relays.frameleaf.test"));
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("FrameleafDesktop/", env!("CARGO_PKG_VERSION")))
        .add_root_certificate(
            reqwest::Certificate::from_pem(configuration.ca_pem.as_bytes()).unwrap(),
        )
        .resolve(
            url.host_str().unwrap(),
            ([127, 0, 0, 1], url.port().unwrap()).into(),
        )
        .build()
        .unwrap();
    let (saved, initial_worker) = tauri::async_runtime::block_on(async {
        let (mut saved, view) = crate::sign_in(
            &client,
            &configuration.server,
            &configuration.email,
            configuration.password,
            "Native sign-in fixture",
            |saved| {
                assert!(!saved.server_id.is_empty());
                assert_eq!(
                    credentials::load::<SavedConnection>("connection")?
                        .unwrap()
                        .server_id,
                    saved.server_id
                );
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(view.state, "preparing");
        let device = saved.device_id.clone().unwrap();
        let repeated = crate::prepare_with_client(&client, &mut saved).await;
        assert_eq!(repeated.state, "preparing");
        assert_eq!(saved.device_id.as_ref(), Some(&device));
        let worker: SavedWorker = credentials::load("worker-session").unwrap().unwrap();
        assert_eq!(worker.device_id, device);
        (saved, worker)
    });
    let worker = WorkerTransport::load(&saved).unwrap();
    tauri::async_runtime::block_on(async {
        worker.0.lock().await.client = client;
    });
    println!(
        "NATIVE_SIGNED_IN {}",
        serde_json::json!({
            "deviceId": saved.device_id, "sessionId": initial_worker.session_id,
            "accountId": saved.account_id,
        })
    );
    std::io::stdout().flush().unwrap();

    if std::env::var_os("FRAMELEAF_FACTORY_AUTOMATIC_SETUP").is_some() {
        crate::transport::FIXTURE_CLIENT
            .set(worker.0.blocking_lock().client.clone())
            .unwrap();
        automatic_setup_job(saved, configuration.work_root, &mut input);
        return;
    }

    crate::native_runtime::absolute_directory(configuration.work_root.parent().unwrap()).unwrap();
    fs::create_dir(&configuration.work_root).unwrap();
    let root = OwnedRoot(configuration.work_root.clone());
    let pack = PathBuf::from(std::env::var("FRAMELEAF_FACTORY_TEST_PACK").unwrap());
    let workload =
        std::env::var("FRAMELEAF_FACTORY_TEST_WORKLOAD").unwrap_or_else(|_| "clip".into());
    assert!(matches!(workload.as_str(), "clip" | "ocr" | "face"));
    let cache = PathBuf::from(std::env::var("FRAMELEAF_FACTORY_MODEL_CACHE").unwrap());
    let store = crate::release_policy::open_runtime_store(&root.0.join("store")).unwrap();
    let raw = fs::read(pack.join("manifest.json")).unwrap();
    let signature: [u8; 64] = fs::read(pack.join("manifest.sig"))
        .unwrap()
        .try_into()
        .unwrap();
    store
        .install_and_activate(&pack.join("payload"), &raw, &signature)
        .unwrap();
    let installed = store.load_active().unwrap().unwrap();
    let attestation = store.attestation(&installed).unwrap();
    tauri::async_runtime::block_on(async {
        let inventory = worker
            .model_inventory(installed.source_revision(), installed.provider())
            .await
            .unwrap();
        let (groups, statuses) = crate::worker_setup::inventory_profiles(
            &inventory,
            installed.source_revision(),
            installed.provider(),
        )
        .unwrap();
        assert_eq!(
            statuses
                .iter()
                .find(|item| item.workload == workload)
                .unwrap()
                .state,
            "eligible"
        );
        if workload == "ocr" {
            let face = groups
                .iter()
                .find(|group| group[0].model_key().starts_with("face:"))
                .expect("eligible Face inventory");
            let refusal = worker
                .request_qualification(&face[0], &attestation, &Uuid::new_v4().to_string())
                .await
                .err()
                .expect("unavailable NAS Face producer");
            assert!(refusal.starts_with("workload_desktop_"), "{refusal}");
        }
        let profiles = groups
            .into_iter()
            .find(|group| group[0].model_key().starts_with(&(workload.clone() + ":")))
            .unwrap();
        assert_eq!(profiles.len(), if workload == "clip" { 3 } else { 1 });
        let mut prepared = Vec::new();
        for profile in &profiles {
            let challenge = worker
                .request_qualification(profile, &attestation, &Uuid::new_v4().to_string())
                .await
                .unwrap();
            let proof = installed
                .qualify(
                    &cache,
                    &root.0,
                    challenge.specification(),
                    challenge.fixture(),
                    &AtomicBool::new(false),
                )
                .unwrap();
            assert!(worker
                .submit_qualification(&challenge, &proof)
                .await
                .unwrap());
            let accepted = worker
                .read_accepted_qualification(profile, &proof, challenge.id())
                .await
                .unwrap();
            prepared.push((proof, accepted));
        }
        let reservation = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let bindings: Vec<_> = prepared
            .iter()
            .map(|(proof, accepted)| (proof, accepted))
            .collect();
        let mut predictor =
            NativePredictor::start_many(&installed, &bindings, &cache, &root.0, port).unwrap();
        println!("NATIVE_QUALIFIED {{\"roles\":{}}}", profiles.len());
        std::io::stdout().flush().unwrap();
        let (_sender, mut cancel) = tokio::sync::watch::channel(false);
        let accepted: Vec<_> = prepared.iter().map(|(_, accepted)| accepted).collect();
        assert_eq!(read_fixture_message(&mut input)["command"], "execute");
        let deadline = Instant::now() + Duration::from_secs(120);
        while !predictor
            .execute_next_many(&worker, &accepted, &mut cancel)
            .await
            .unwrap()
        {
            assert!(Instant::now() < deadline, "fixture job did not arrive");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        println!("NATIVE_EXECUTED {{\"iteration\":1}}");
        std::io::stdout().flush().unwrap();
        predictor.stop().unwrap();
        let checkpoint: SavedWorker = credentials::load("worker-session").unwrap().unwrap();
        assert!(checkpoint.next_sequence > initial_worker.next_sequence);
        credentials::delete("worker-session").unwrap();
        credentials::delete("installation").unwrap();
        credentials::delete("connection").unwrap();
    });
}

#[test]
#[ignore = "changes the credential builder; run alone in its own test process"]
fn persisted_controls_survive_reload_and_do_not_cross_associations() {
    use crate::worker_control::{self, WorkerControl};
    install_test_keyring();
    let mut saved = SavedConnection {
        server: "https://synthetic.test/".into(),
        server_id: "server-a".into(),
        account_id: "account-a".into(),
        device_id: Some("device-a".into()),
        name: "Synthetic".into(),
        token: "synthetic".into(),
        device_name: "Synthetic".into(),
        mode: "client-worker".into(),
    };
    assert_eq!(
        worker_control::load(&saved).unwrap(),
        WorkerControl::Running
    );
    worker_control::save(&saved, WorkerControl::Paused).unwrap();
    assert_eq!(worker_control::load(&saved).unwrap(), WorkerControl::Paused);
    saved.account_id = "account-b".into();
    assert_eq!(
        worker_control::load(&saved).unwrap(),
        WorkerControl::Running
    );
    worker_control::save(&saved, WorkerControl::Stopped).unwrap();
    saved.account_id = "account-a".into();
    assert_eq!(worker_control::load(&saved).unwrap(), WorkerControl::Paused);
    worker_control::save(&saved, WorkerControl::Running).unwrap();
    saved.account_id = "account-b".into();
    assert_eq!(
        worker_control::load(&saved).unwrap(),
        WorkerControl::Stopped
    );
}

#[tokio::test]
async fn fresh_sign_in_rejects_invalid_details_before_credentials_or_network() {
    let client = crate::transport::client().unwrap();
    for (email, password) in [("", "fixture"), ("fixture@example.test", "")] {
        let result = crate::sign_in(
            &client,
            "https://unreachable.invalid/",
            email,
            password.into(),
            "Fixture",
            |_| panic!("invalid login must not request credential access"),
        )
        .await;
        assert_eq!(result.err().as_deref(), Some("login_details_invalid"));
    }
}

fn automatic_setup_job(
    saved: SavedConnection,
    root: std::path::PathBuf,
    input: &mut impl std::io::BufRead,
) {
    use std::{
        io::Write,
        time::{Duration, Instant},
    };
    std::fs::create_dir(&root).unwrap();
    let root = OwnedRoot(root);
    // Seed approved staged weights for this offline automatic-setup fixture.
    let pack = std::path::PathBuf::from(std::env::var("FRAMELEAF_FACTORY_TEST_PACK").unwrap());
    let cache = std::path::PathBuf::from(std::env::var("FRAMELEAF_FACTORY_MODEL_CACHE").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pack.join("manifest.json")).unwrap()).unwrap();
    let catalogue: serde_json::Value =
        serde_json::from_str(include_str!("../../../runtime/model-catalogue.json")).unwrap();
    let profile = catalogue["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|profile| {
            profile["workload"] == "ocr"
                && profile["runtimeSourceRevision"] == manifest["sourceRevision"]
                && profile["spec"]["provider"] == manifest["provider"]
        })
        .unwrap();
    let name = profile["modelName"].as_str().unwrap();
    let staged = root
        .0
        .join("worker/models")
        .join(format!(
            ".staging-{}",
            profile["modelSnapshotRevision"].as_str().unwrap()
        ))
        .join("ocr")
        .join(name);
    let mut directories = std::fs::DirBuilder::new();
    directories.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directories.mode(0o700);
    }
    for artifact in profile["artifactBytes"].as_object().unwrap().keys() {
        if artifact == &format!("models--frameleaf--{name}/refs/main") {
            continue;
        }
        let destination = staged.join(artifact);
        directories.create(destination.parent().unwrap()).unwrap();
        std::fs::copy(cache.join("ocr").join(name).join(artifact), destination).unwrap();
    }
    let setup = crate::worker_setup::WorkerSetup::default();
    tauri::async_runtime::block_on(async {
        setup
            .start(
                saved,
                crate::worker_setup::SetupPaths {
                    data: root.0.join("worker"),
                    bundle: std::env::var("FRAMELEAF_FACTORY_TEST_PACK").unwrap().into(),
                },
                false,
                std::sync::Arc::new(|status| {
                    eprintln!("automatic setup: {} {:?}", status.state, status.code);
                }),
            )
            .await;
        let deadline = Instant::now() + Duration::from_secs(900);
        loop {
            let status = setup.status();
            assert_ne!(status.state, "setup-needs-attention", "{status:?}");
            assert_ne!(status.state, "model-download-required", "{status:?}");
            assert_ne!(status.state, "paused", "{status:?}");
            if matches!(status.state.as_str(), "working" | "waiting-for-work") {
                assert!(status
                    .workloads
                    .iter()
                    .any(|item| item.workload == "ocr" && item.state == "ready"));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "automatic setup deadline: {status:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        println!("NATIVE_QUALIFIED {{\"roles\":1}}");
        std::io::stdout().flush().unwrap();
        assert_eq!(read_fixture_message(input)["command"], "execute");
        assert_eq!(read_fixture_message(input)["command"], "complete");
        setup.stop().await;
        println!("NATIVE_EXECUTED {{\"iteration\":1}}");
        std::io::stdout().flush().unwrap();
    });
}
