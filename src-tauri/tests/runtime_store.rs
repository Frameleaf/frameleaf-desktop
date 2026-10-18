mod common;
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
    let store = RuntimeStore::new(
        &fixture.0.join("store"),
        vec![key.verifying_key()],
        1,
        common::authority(),
    )
    .unwrap();
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
fn restoring_an_old_active_pointer_cannot_lower_the_historical_epoch() {
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let root = fixture.0.join("store");
    let store =
        RuntimeStore::new(&root, vec![key.verifying_key()], 1, common::authority()).unwrap();
    let old = manifest(2);
    store
        .install_and_activate(&candidate, &old, &key.sign(&old).to_bytes())
        .unwrap();
    let old_pointer = fs::read(root.join("active.json")).unwrap();
    let newer = manifest(3);
    store
        .install_and_activate(&candidate, &newer, &key.sign(&newer).to_bytes())
        .unwrap();
    fs::write(root.join("active.json"), old_pointer).unwrap();
    assert!(
        store.load_active().is_err(),
        "restoring ordinary runtime metadata must not authorize a previously superseded runtime"
    );
}

#[test]
fn incomplete_staging_and_tampered_installed_payload_are_never_adopted() {
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let store_root = fixture.0.join("store");
    let store = RuntimeStore::new(
        &store_root,
        vec![key.verifying_key()],
        1,
        common::authority(),
    )
    .unwrap();
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
    let store = RuntimeStore::new(
        &fixture.0.join("store"),
        vec![key.verifying_key()],
        1,
        common::authority(),
    )
    .unwrap();
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
    let store = RuntimeStore::new(
        &workspace.0.join("store"),
        vec![key.verifying_key()],
        1,
        common::authority(),
    )
    .unwrap();
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
    let mut child = installed
        .start_qualified_sidecar(&qualified, &cache, &workspace.0, port)
        .unwrap();
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
            .form(&[("entries", "{}"), ("text", "unqualified configuration")])
            .send()
            .await
            .unwrap();
        let status = response.status();
        response.bytes().await.unwrap();
        assert_eq!(status, 409);
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

#[test]
fn attestation_preserves_signed_bytes_and_rechecks_installed_release() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::io::Read;
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let store_root = fixture.0.join("store");
    let store = RuntimeStore::new(
        &store_root,
        vec![key.verifying_key()],
        1,
        common::authority(),
    )
    .unwrap();
    let raw = manifest(2);
    let signature = key.sign(&raw).to_bytes();
    store
        .install_and_activate(&candidate, &raw, &signature)
        .unwrap();
    let installed = store.load_active().unwrap().unwrap();
    let attestation = serde_json::to_value(store.attestation(&installed).unwrap()).unwrap();
    let compressed = STANDARD
        .decode(attestation["manifestGzipBase64"].as_str().unwrap())
        .unwrap();
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(compressed.as_slice())
        .read_to_end(&mut decoded)
        .unwrap();
    assert_eq!(decoded, raw);
    assert_eq!(
        STANDARD
            .decode(attestation["signatureBase64"].as_str().unwrap())
            .unwrap(),
        signature
    );
    assert_eq!(attestation.as_object().unwrap().len(), 2);
    let release = store_root
        .join("releases")
        .join(installed.manifest_sha256());
    fs::write(release.join("manifest.sig"), [0; 64]).unwrap();
    assert!(store.attestation(&installed).is_err());
    fs::write(release.join("manifest.sig"), signature).unwrap();
    fs::write(release.join("payload/python"), b"changed").unwrap();
    assert!(store.attestation(&installed).is_err());
}

#[test]
#[ignore = "requires a private factory-signed pack; never release credentials in CI"]
fn factory_attestation_exports_exact_installed_release() {
    let fixture = Fixture::new();
    let root = PathBuf::from(std::env::var("FRAMELEAF_FACTORY_TEST_PACK").unwrap());
    let output = PathBuf::from(std::env::var("FRAMELEAF_FACTORY_ATTESTATION").unwrap());
    let store =
        frameleaf_desktop::release_policy::open_runtime_store(&fixture.0.join("store")).unwrap();
    let raw = fs::read(root.join("manifest.json")).unwrap();
    let signature: [u8; 64] = fs::read(root.join("manifest.sig"))
        .unwrap()
        .try_into()
        .unwrap();
    store
        .install_and_activate(&root.join("payload"), &raw, &signature)
        .unwrap();
    let installed = store.load_active().unwrap().unwrap();
    let envelope = serde_json::to_vec(&store.attestation(&installed).unwrap()).unwrap();
    assert!(envelope.len() < 4 * 1024 * 1024);
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .unwrap();
    file.write_all(&envelope).unwrap();
    file.sync_all().unwrap();
    eprintln!(
        "PASS: exact installed factory runtime attestation exported, {} bytes",
        envelope.len()
    );
}

#[test]
fn replaced_credential_identity_cannot_reauthorize_an_open_store() {
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let epochs = common::authority();
    let store = RuntimeStore::new(
        &fixture.0.join("store"),
        vec![key.verifying_key()],
        1,
        epochs.clone(),
    )
    .unwrap();
    let raw = manifest(2);
    store
        .install_and_activate(&candidate, &raw, &key.sign(&raw).to_bytes())
        .unwrap();
    *epochs.id.lock().unwrap() = Uuid::new_v4().to_string();
    assert!(
        store.load_active().is_err(),
        "a recreated credential must not adopt an already-open store"
    );
}

#[test]
fn historical_floor_survives_restart_deleted_pointer_and_another_root() {
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let epochs = common::authority();
    let root = fixture.0.join("store");
    let store = RuntimeStore::new(&root, vec![key.verifying_key()], 1, epochs.clone()).unwrap();
    let raw = manifest(3);
    store
        .install_and_activate(&candidate, &raw, &key.sign(&raw).to_bytes())
        .unwrap();
    fs::remove_file(root.join("active.json")).unwrap();
    drop(store);
    let restarted = RuntimeStore::new(&root, vec![key.verifying_key()], 1, epochs.clone()).unwrap();
    let other = RuntimeStore::new(
        &fixture.0.join("other"),
        vec![key.verifying_key()],
        1,
        epochs,
    )
    .unwrap();
    let old = manifest(2);
    for store in [&restarted, &other] {
        assert_eq!(
            store
                .install_and_activate(&candidate, &old, &key.sign(&old).to_bytes())
                .unwrap_err(),
            "runtime_epoch_rollback"
        );
        store
            .install_and_activate(&candidate, &raw, &key.sign(&raw).to_bytes())
            .unwrap();
    }
}
#[test]
fn failed_credential_write_retains_old_pointer_but_failed_publish_retains_new_floor() {
    use std::sync::atomic::Ordering;
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let epochs = common::authority();
    let root = fixture.0.join("store");
    let store = RuntimeStore::new(&root, vec![key.verifying_key()], 1, epochs.clone()).unwrap();
    let old = manifest(2);
    store
        .install_and_activate(&candidate, &old, &key.sign(&old).to_bytes())
        .unwrap();
    let pointer = fs::read(root.join("active.json")).unwrap();
    let newer = manifest(3);
    epochs.fail_persist.store(true, Ordering::Release);
    assert!(store
        .install_and_activate(&candidate, &newer, &key.sign(&newer).to_bytes())
        .is_err());
    assert_eq!(fs::read(root.join("active.json")).unwrap(), pointer);
    assert!(store.load_active().unwrap().is_some());
    epochs.fail_persist.store(false, Ordering::Release);
    epochs.fail_publish.store(true, Ordering::Release);
    assert!(store
        .install_and_activate(&candidate, &newer, &key.sign(&newer).to_bytes())
        .is_err());
    assert_eq!(fs::read(root.join("active.json")).unwrap(), pointer);
    assert!(store.load_active().is_err());
    epochs.fail_publish.store(false, Ordering::Release);
    store
        .install_and_activate(&candidate, &newer, &key.sign(&newer).to_bytes())
        .unwrap();
    assert!(store.load_active().unwrap().is_some());
    epochs.unavailable.store(true, Ordering::Release);
    assert!(store.load_active().is_err());
    assert!(RuntimeStore::new(&root, vec![key.verifying_key()], 1, epochs).is_err());
}
#[test]
fn missing_or_replaced_store_binding_requires_recovery_without_replacing_state() {
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let epochs = common::authority();
    let root = fixture.0.join("store");
    let store = RuntimeStore::new(&root, vec![key.verifying_key()], 1, epochs.clone()).unwrap();
    let raw = manifest(3);
    store
        .install_and_activate(&candidate, &raw, &key.sign(&raw).to_bytes())
        .unwrap();
    drop(store);
    let pointer = fs::read(root.join("active.json")).unwrap();
    let other_identity = common::authority();
    assert!(RuntimeStore::new(&root, vec![key.verifying_key()], 1, other_identity).is_err());
    fs::remove_file(root.join("epoch-authority.json")).unwrap();
    assert!(RuntimeStore::new(&root, vec![key.verifying_key()], 1, epochs).is_err());
    assert_eq!(fs::read(root.join("active.json")).unwrap(), pointer);
}
#[test]
fn provider_scopes_keep_manifest_identity_and_epochs_separate_across_roots() {
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let epochs = common::authority();
    let cpu = manifest(2);
    for (index, provider) in ["CPUExecutionProvider", "CUDAExecutionProvider"]
        .into_iter()
        .enumerate()
    {
        let store = RuntimeStore::new(
            &fixture.0.join(format!("store-{index}")),
            vec![key.verifying_key()],
            1,
            epochs.clone(),
        )
        .unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&cpu).unwrap();
        value["provider"] = json!(provider);
        let raw = serde_json::to_vec(&value).unwrap();
        store
            .install_and_activate(&candidate, &raw, &key.sign(&raw).to_bytes())
            .unwrap();
    }
    let other = RuntimeStore::new(
        &fixture.0.join("other"),
        vec![key.verifying_key()],
        1,
        epochs,
    )
    .unwrap();
    let mut changed: serde_json::Value = serde_json::from_slice(&cpu).unwrap();
    changed["sourceRevision"] = json!("b".repeat(40));
    let raw = serde_json::to_vec(&changed).unwrap();
    assert_eq!(
        other
            .install_and_activate(&candidate, &raw, &key.sign(&raw).to_bytes())
            .unwrap_err(),
        "runtime_epoch_reused"
    );
}

#[test]
fn newer_gpu_epoch_also_prevents_older_cpu_runtime_from_another_root() {
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let epochs = common::authority();
    let gpu = RuntimeStore::new(
        &fixture.0.join("gpu"),
        vec![key.verifying_key()],
        1,
        epochs.clone(),
    )
    .unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&manifest(3)).unwrap();
    value["provider"] = json!("CUDAExecutionProvider");
    let raw = serde_json::to_vec(&value).unwrap();
    gpu.install_and_activate(&candidate, &raw, &key.sign(&raw).to_bytes())
        .unwrap();
    let cpu =
        RuntimeStore::new(&fixture.0.join("cpu"), vec![key.verifying_key()], 1, epochs).unwrap();
    let old = manifest(2);
    assert_eq!(
        cpu.install_and_activate(&candidate, &old, &key.sign(&old).to_bytes())
            .err()
            .as_deref(),
        Some("runtime_epoch_rollback")
    );
}

#[test]
fn retained_runtime_cannot_start_or_qualify_after_another_root_advances() {
    let fixture = Fixture::new();
    let candidate = fixture.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let epochs = common::authority();
    let first = RuntimeStore::new(
        &fixture.0.join("first"),
        vec![key.verifying_key()],
        1,
        epochs.clone(),
    )
    .unwrap();
    let old = manifest(2);
    first
        .install_and_activate(&candidate, &old, &key.sign(&old).to_bytes())
        .unwrap();
    let retained = first.load_active().unwrap().unwrap();
    let second = RuntimeStore::new(
        &fixture.0.join("second"),
        vec![key.verifying_key()],
        1,
        epochs,
    )
    .unwrap();
    let newer = manifest(3);
    second
        .install_and_activate(&candidate, &newer, &key.sign(&newer).to_bytes())
        .unwrap();
    let cache = fixture.0.join("unused-cache");
    let work = fixture.0.join("unused-work");
    assert_eq!(
        retained
            .start_sidecar(&cache, &work, 19998)
            .err()
            .as_deref(),
        Some("runtime_epoch_rollback")
    );
    assert_eq!(
        retained
            .start_bound_sidecar(&[], &cache, &work, 19998)
            .err()
            .as_deref(),
        Some("runtime_epoch_rollback")
    );
    assert_eq!(
        retained
            .qualify(&cache, &work, b"", b"", &false.into())
            .err()
            .as_deref(),
        Some("runtime_epoch_rollback")
    );
    assert!(!cache.exists());
    assert!(!work.exists());
}
