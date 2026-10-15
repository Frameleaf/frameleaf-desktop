use ed25519_dalek::{Signer, SigningKey};
use frameleaf_desktop::runtime_store::RuntimeStore;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use uuid::Uuid;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-store-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn manifest(epoch: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({"schemaVersion":1,"protocolVersion":1,"epoch":epoch,"platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,"provider":"CPUExecutionProvider","python":"python","sourceRevision":"a".repeat(40),"files":{"python":{"sha256":format!("{:x}",Sha256::digest(b"fixture")),"bytes":7}}})).unwrap()
}
#[test]
fn installs_independent_verified_bytes_and_refuses_rollback_or_active_leases() {
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let store = RuntimeStore::new(&fixture.0.join("store"), vec![key.verifying_key()], 1).unwrap();
    assert!(store.load_active().unwrap().is_none());
    let raw = manifest(2);
    let signature = key.sign(&raw).to_bytes();
    store
        .install_and_activate(&candidate, &raw, &signature)
        .unwrap();
    let installed = store.load_active().unwrap().unwrap();
    let first = installed.manifest_sha256().to_owned();
    assert_eq!(first, format!("{:x}", Sha256::digest(&raw)));
    let newer = manifest(3);
    assert!(store
        .install_and_activate(&candidate, &newer, &key.sign(&newer).to_bytes())
        .is_err());
    drop(installed);
    let old = manifest(1);
    assert!(store
        .install_and_activate(&candidate, &old, &key.sign(&old).to_bytes())
        .is_err());
    assert!(store
        .install_and_activate(&candidate, &newer, &[0; 64])
        .is_err());
    assert_eq!(
        store.load_active().unwrap().unwrap().manifest_sha256(),
        first
    );
    fs::write(candidate.join("python"), b"changed").unwrap();
    assert_eq!(
        store.load_active().unwrap().unwrap().manifest_sha256(),
        first
    );
    fs::write(candidate.join("python"), b"fixture").unwrap();
    store
        .install_and_activate(&candidate, &newer, &key.sign(&newer).to_bytes())
        .unwrap();
    assert_ne!(
        store.load_active().unwrap().unwrap().manifest_sha256(),
        first
    );
    assert!(fixture.0.join("store/releases").join(first).exists());
}
#[test]
fn incomplete_staging_and_tampered_installed_payload_are_never_adopted() {
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let store_root = fixture.0.join("store");
    let store = RuntimeStore::new(&store_root, vec![key.verifying_key()], 1).unwrap();
    fs::create_dir(store_root.join(".staging-incomplete")).unwrap();
    assert!(store.load_active().unwrap().is_none());
    let raw = manifest(1);
    store
        .install_and_activate(&candidate, &raw, &key.sign(&raw).to_bytes())
        .unwrap();
    let id = store
        .load_active()
        .unwrap()
        .unwrap()
        .manifest_sha256()
        .to_owned();
    fs::write(
        store_root.join("releases").join(id).join("payload/python"),
        b"tampered",
    )
    .unwrap();
    assert!(store.load_active().is_err());
}

#[test]
fn epoch_cannot_be_reused_for_different_runtime_bytes() {
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let store = RuntimeStore::new(&fixture.0.join("store"), vec![key.verifying_key()], 1).unwrap();
    let raw = manifest(2);
    store
        .install_and_activate(&candidate, &raw, &key.sign(&raw).to_bytes())
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    value["sourceRevision"] = json!("b".repeat(40));
    let changed = serde_json::to_vec(&value).unwrap();
    assert!(store
        .install_and_activate(&candidate, &changed, &key.sign(&changed).to_bytes())
        .is_err());
}

#[test]
#[ignore = "requires dedicated built runtime, mirrored model cache and synthetic qualification fixture"]
fn installed_private_cpu_pack_runs_production_qualification_and_inference() {
    use std::{
        net::TcpListener,
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };
    let pack = PathBuf::from(std::env::var("FRAMELEAF_NATIVE_TEST_PACK").unwrap());
    let cache = PathBuf::from(std::env::var("FRAMELEAF_NATIVE_TEST_CACHE").unwrap());
    let spec_path = PathBuf::from(std::env::var("FRAMELEAF_NATIVE_TEST_SPEC").unwrap());
    let raw = fs::read(pack.join("manifest.json")).unwrap();
    let workspace = Fixture::new();
    let key = SigningKey::from_bytes(&[42; 32]);
    // This fixture-only trust key never enters application release policy.
    let store =
        RuntimeStore::new(&workspace.0.join("store"), vec![key.verifying_key()], 1).unwrap();
    store
        .install_and_activate(&pack.join("payload"), &raw, &key.sign(&raw).to_bytes())
        .unwrap();
    let installed = store.load_active().unwrap().unwrap();
    let spec = fs::read(&spec_path).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&spec).unwrap();
    let name = value["fixtureFile"].as_str().unwrap();
    assert!(!name.contains(['/', '\\', ':']));
    let fixture = fs::read(spec_path.parent().unwrap().join(name)).unwrap();
    let qualified = installed
        .qualify(
            &cache,
            &workspace.0,
            &spec,
            &fixture,
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(qualified.report()["state"], "ready-cpu");
    assert_eq!(qualified.manifest_sha256(), installed.manifest_sha256());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut child = installed.start_sidecar(&cache, &workspace.0, port).unwrap();
    drop(installed);
    assert!(store
        .install_and_activate(&pack.join("payload"), &raw, &key.sign(&raw).to_bytes())
        .is_err());
    tauri::async_runtime::block_on(async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let base = format!("http://127.0.0.1:{port}");
        let end = Instant::now() + Duration::from_secs(15);
        loop {
            assert!(
                child.is_running().unwrap(),
                "native process exited before readiness"
            );
            if let Ok(response) = client
                .get(format!("{base}/ping"))
                .bearer_auth(child.authorization())
                .send()
                .await
            {
                let ready = response.status().is_success();
                response.bytes().await.unwrap();
                if ready {
                    break;
                }
            }
            assert!(Instant::now() < end, "native readiness timeout");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let response = client.get(format!("{base}/ping")).send().await.unwrap();
        let status = response.status();
        response.bytes().await.unwrap();
        assert_eq!(status, 401);
        let response = client
            .get(format!("{base}/hardware"))
            .bearer_auth(child.authorization())
            .send()
            .await
            .unwrap();
        let status = response.status();
        response.bytes().await.unwrap();
        assert_eq!(status, 404);
        let response = client
            .post(format!("{base}/predict"))
            .bearer_auth(child.authorization())
            .form(&[
                ("entries", value["entries"].to_string()),
                ("text", String::from_utf8(fixture).unwrap()),
            ])
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        let actual: serde_json::Value = response.json().await.unwrap();
        let left: Vec<f64> = serde_json::from_str(actual["clip"].as_str().unwrap()).unwrap();
        let right: Vec<f64> =
            serde_json::from_str(value["expectedOutput"]["clip"].as_str().unwrap()).unwrap();
        assert_eq!(left.len(), 512);
        assert_eq!(left.len(), right.len());
        for (a, b) in left.iter().zip(right) {
            assert!(a.is_finite() && (a - b).abs() <= 1e-4 + 1e-3 * b.abs());
        }
    });
    child.stop().unwrap();
    drop(child);
    store
        .install_and_activate(&pack.join("payload"), &raw, &key.sign(&raw).to_bytes())
        .unwrap();
    eprintln!("PASS: installed private runtime, production CPU qualification, scoped sidecar512 embedding and live update lease");
}
