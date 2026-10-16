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
fn install_test_keyring() {
    keyring::set_default_credential_builder(Box::<MemoryCredentials>::default());
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureConnection {
    saved: SavedConnection,
    worker: SavedWorker,
    ca_pem: String,
    work_root: std::path::PathBuf,
}
struct OwnedRoot(std::path::PathBuf);
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn read_fixture_message(reader: &mut impl std::io::BufRead) -> serde_json::Value {
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
    use crate::{model_catalogue::approved_profile, native_predictor::NativePredictor};
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
    println!(
        "NATIVE_IDENTITY {}",
        serde_json::to_string(&enrollment).unwrap()
    );
    std::io::stdout().flush().unwrap();
    let mut input = std::io::BufReader::new(std::io::stdin());
    let configuration: FixtureConnection =
        serde_json::from_value(read_fixture_message(&mut input)).expect("fixture connection");
    credentials::save("worker-session", &configuration.worker).unwrap();
    let worker = WorkerTransport::load(&configuration.saved).unwrap();
    let url = normalize_server(&configuration.saved.server).unwrap();
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
    tauri::async_runtime::block_on(async {
        worker.0.lock().await.client = client;
    });

    crate::native_runtime::absolute_directory(configuration.work_root.parent().unwrap()).unwrap();
    fs::create_dir(&configuration.work_root).unwrap();
    let root = OwnedRoot(configuration.work_root.clone());
    let pack = PathBuf::from(std::env::var("FRAMELEAF_FACTORY_TEST_PACK").unwrap());
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
    let catalogue: serde_json::Value =
        serde_json::from_str(include_str!("../../../runtime/model-catalogue.json")).unwrap();
    let profiles: Vec<_> = catalogue["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["runtimeSourceRevision"] == installed.source_revision())
        .map(|p| {
            approved_profile(
                p["modelName"].as_str().unwrap(),
                &p["spec"]["entries"],
                installed.source_revision(),
                installed.provider(),
            )
            .unwrap()
            .unwrap()
        })
        .collect();
    assert_eq!(profiles.len(), 3);
    tauri::async_runtime::block_on(async {
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
        println!("NATIVE_QUALIFIED {{\"roles\":3}}");
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
        assert!(checkpoint.next_sequence > configuration.worker.next_sequence);
        credentials::delete("worker-session").unwrap();
        credentials::delete("installation").unwrap();
    });
}
