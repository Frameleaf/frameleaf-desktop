//! Public release authority compiled into the app; a server response can never supply trust keys.
use crate::runtime_store::RuntimeStore;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use std::{collections::BTreeSet, path::Path};

const POLICY: &str = include_str!("../../runtime/release-trust.json");
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    schema_version: u32,
    minimum_runtime_epoch: u64,
    minimum_host_epoch: u64,
    keys: Vec<Key>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Key {
    id: String,
    public_key_hex: String,
}
fn parse_policy(raw: &str) -> Result<(u64, u64, Vec<VerifyingKey>), String> {
    let policy: Policy = serde_json::from_str(raw).map_err(|_| "release_policy_invalid")?;
    if policy.schema_version != 1
        || policy.minimum_runtime_epoch == 0
        || policy.minimum_host_epoch == 0
        || policy.keys.is_empty()
        || policy.keys.len() > 16
    {
        return Err("release_policy_invalid".into());
    }
    let mut ids = BTreeSet::new();
    let mut encoded = BTreeSet::new();
    let mut keys = Vec::new();
    for key in policy.keys {
        if key.id.is_empty()
            || key.id.len() > 64
            || !key
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !ids.insert(key.id)
            || key.public_key_hex.len() != 64
            || !key
                .public_key_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !encoded.insert(key.public_key_hex.clone())
        {
            return Err("release_policy_invalid".into());
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&key.public_key_hex[index * 2..index * 2 + 2], 16)
                .map_err(|_| "release_policy_invalid")?;
        }
        keys.push(VerifyingKey::from_bytes(&bytes).map_err(|_| "release_policy_invalid")?);
    }
    Ok((
        policy.minimum_runtime_epoch,
        policy.minimum_host_epoch,
        keys,
    ))
}
#[cfg(test)]
static COREML_FIXTURE_KEY: std::sync::OnceLock<VerifyingKey> = std::sync::OnceLock::new();
#[cfg(test)]
pub(crate) fn use_coreml_fixture_authority() {
    COREML_FIXTURE_KEY
        .get_or_init(|| ed25519_dalek::SigningKey::from_bytes(&[71; 32]).verifying_key());
}
pub fn open_runtime_store(root: &Path) -> Result<RuntimeStore, String> {
    #[cfg(test)]
    if let Some(key) = COREML_FIXTURE_KEY.get() {
        return RuntimeStore::new(
            root,
            vec![*key],
            1,
            std::sync::Arc::new(crate::credentials::CredentialEpochAuthority),
        );
    }

    let (floor, _, keys) = parse_policy(POLICY)?;
    RuntimeStore::new(
        root,
        keys,
        floor,
        std::sync::Arc::new(crate::credentials::CredentialEpochAuthority),
    )
}

pub fn verify_host_runtime(
    root: &Path,
    manifest: &[u8],
    signature: &[u8; 64],
) -> Result<crate::host_runtime::VerifiedHostRuntime, String> {
    let (_, floor, keys) = parse_policy(POLICY)?;
    crate::host_runtime::VerifiedHostRuntime::verify(root, manifest, signature, &keys, floor)
}
pub(crate) fn host_package_metadata(
    manifest: &[u8],
    signature: &[u8; 64],
    expected_manifest: &str,
    package: &[u8],
) -> Result<crate::host_runtime::PackageMetadata, String> {
    let (_, floor, keys) = parse_policy(POLICY)?;
    crate::host_runtime::package_metadata(
        manifest,
        signature,
        &keys,
        floor,
        expected_manifest,
        package,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_and_ml_minimums_are_explicit_and_independent() {
        let mut policy: serde_json::Value = serde_json::from_str(POLICY).unwrap();
        policy["minimumRuntimeEpoch"] = serde_json::json!(99);
        policy["minimumHostEpoch"] = serde_json::json!(2);
        let (ml, host, _) = parse_policy(&policy.to_string()).unwrap();
        assert_eq!((ml, host), (99, 2));
        for value in [
            serde_json::Value::Null,
            serde_json::json!(0),
            serde_json::json!(true),
            serde_json::json!("2"),
        ] {
            policy["minimumHostEpoch"] = value;
            assert!(parse_policy(&policy.to_string()).is_err());
        }
        policy.as_object_mut().unwrap().remove("minimumHostEpoch");
        assert!(parse_policy(&policy.to_string()).is_err());
    }
    #[test]
    fn public_policy_has_a_positive_floor_and_rejects_invalid_or_ambiguous_keys() {
        let (floor, host_floor, keys) = parse_policy(POLICY).unwrap();
        assert!(floor > 0);
        assert!(host_floor > 0);
        assert!(!keys.is_empty());
        let original: serde_json::Value = serde_json::from_str(POLICY).unwrap();
        let mut value = original.clone();
        value["minimumRuntimeEpoch"] = serde_json::json!(0);
        assert!(parse_policy(&value.to_string()).is_err());
        value = original.clone();
        value["keys"][0]["publicKeyHex"] = serde_json::json!("bad");
        assert!(parse_policy(&value.to_string()).is_err());
        value = original.clone();
        let duplicate = value["keys"][0].clone();
        value["keys"].as_array_mut().unwrap().push(duplicate);
        assert!(parse_policy(&value.to_string()).is_err());
        value = original;
        value["untrustedKeys"] = serde_json::json!([]);
        assert!(parse_policy(&value.to_string()).is_err());
    }
    #[test]
    #[ignore = "requires a factory-signed authoring candidate, never release credentials in CI"]
    fn factory_signed_candidate_verifies_against_compiled_authority() {
        let root = std::path::PathBuf::from(std::env::var("FRAMELEAF_FACTORY_TEST_PACK").unwrap());
        let raw = std::fs::read(root.join("manifest.json")).unwrap();
        let signature: [u8; 64] = std::fs::read(root.join("manifest.sig"))
            .unwrap()
            .try_into()
            .unwrap();
        let (floor, _, keys) = parse_policy(POLICY).unwrap();
        let verified = crate::native_runtime::VerifiedRuntime::verify(
            &root.join("payload"),
            &raw,
            &signature,
            &keys,
            floor,
        )
        .unwrap();
        assert!(verified.epoch() >= floor);
        eprintln!("PASS: factory-signed private runtime verified against the app's compiled release authority");
    }
    #[test]
    #[ignore = "requires a factory-signed runtime, owned OCR cache and real GPU preparation"]
    fn factory_signed_runtime_qualifies_with_observed_memory() {
        use std::{fs, path::PathBuf, sync::atomic::AtomicBool};
        let root = PathBuf::from(std::env::var_os("FRAMELEAF_FACTORY_TEST_PACK").unwrap());
        let cache = PathBuf::from(std::env::var_os("FRAMELEAF_FACTORY_TEST_CACHE").unwrap());
        let output = PathBuf::from(std::env::var_os("FRAMELEAF_FACTORY_TEST_WORK").unwrap());
        let signature: [u8; 64] = fs::read(root.join("manifest.sig"))
            .unwrap()
            .try_into()
            .unwrap();
        let (floor, _, keys) = parse_policy(POLICY).unwrap();
        let manifest_bytes = fs::read(root.join("manifest.json")).unwrap();
        let runtime = crate::native_runtime::VerifiedRuntime::verify(
            &root.join("payload"),
            &manifest_bytes,
            &signature,
            &keys,
            floor,
        )
        .unwrap();
        let profiles = crate::model_catalogue::setup_profiles(
            "PP-OCRv5_mobile",
            runtime.source_revision(),
            runtime.provider(),
        )
        .unwrap();
        assert_eq!(profiles.len(), 1);
        let profile = &profiles[0];
        let (spec, fixture) = profile
            .challenge(&uuid::Uuid::new_v4().to_string())
            .unwrap();
        let work = output.join(format!("qualification-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&work).unwrap();
        let qualified = runtime
            .qualify(&cache, &work, &spec, &fixture, &AtomicBool::new(false))
            .unwrap();
        let report = qualified.report();
        let envelope =
            crate::memory_admission::envelope(profile.minimum_memory(), &[report]).unwrap();
        assert!(envelope.startup > envelope.running);
        assert!(envelope.running >= profile.minimum_memory());
        let mut missing = report.clone();
        missing.as_object_mut().unwrap().remove("memory");
        assert_eq!(
            crate::memory_admission::envelope(profile.minimum_memory(), &[&missing]).unwrap_err(),
            "runtime_memory_measurement_required"
        );
        fs::write(output.join("native-memory-qualification.json"), serde_json::to_vec_pretty(&serde_json::json!({
            "sourceRevision": runtime.source_revision(), "manifestSha256": runtime.manifest_sha256(),
            "compiledReleaseAuthorityVerified": true, "freshNativeQualification": true,
            "report": report, "startupFreeMemoryBytes": envelope.startup,
            "runningFreeMemoryBytes": envelope.running, "missingMemoryRefused": true,
            "installedAcceptance": false, "nasLeaseExecuted": false,
        })).unwrap()).unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut sidecar = runtime
            .start_qualified_sidecar(&qualified, &cache, &work, port)
            .unwrap();
        let scratch = sidecar.working_dir().to_path_buf();
        let spec: serde_json::Value = serde_json::from_slice(&spec).unwrap();
        let engine = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let outputs = engine.block_on(async {
            let client = reqwest::Client::builder()
                .no_proxy()
                .pool_max_idle_per_host(0)
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap();
            let base = format!("http://127.0.0.1:{port}");
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_secs(spec["deadlineSeconds"].as_u64().unwrap() + 15);
            loop {
                if client
                    .get(format!("{base}/ping"))
                    .bearer_auth(sidecar.authorization())
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
                {
                    break;
                }
                assert!(
                    sidecar.is_running().unwrap(),
                    "owned sidecar exited during preload"
                );
                assert!(
                    std::time::Instant::now() < deadline,
                    "owned sidecar preload deadline"
                );
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            let form = |entries: &serde_json::Value, image: Vec<u8>| {
                reqwest::multipart::Form::new()
                    .text("entries", entries.to_string())
                    .part(
                        "image",
                        reqwest::multipart::Part::bytes(image)
                            .file_name("fixture.png")
                            .mime_str("image/png")
                            .unwrap(),
                    )
            };
            assert_eq!(
                client
                    .post(format!("{base}/predict"))
                    .multipart(form(&spec["entries"], fixture.clone()))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::UNAUTHORIZED
            );
            let mut changed = spec["entries"].clone();
            changed["ocr"]["detection"]["options"]["minScore"] = serde_json::json!(0.6);
            assert_eq!(
                client
                    .post(format!("{base}/predict"))
                    .bearer_auth(sidecar.authorization())
                    .multipart(form(&changed, fixture.clone()))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::CONFLICT
            );
            let mut oversized = fixture.clone();
            assert_eq!(&oversized[..8], b"\x89PNG\r\n\x1a\n");
            oversized[16..20].copy_from_slice(&8193_u32.to_be_bytes());
            assert_eq!(
                client
                    .post(format!("{base}/predict"))
                    .bearer_auth(sidecar.authorization())
                    .multipart(form(&spec["entries"], oversized))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::PAYLOAD_TOO_LARGE
            );
            let mut outputs = Vec::new();
            for _ in 0..2 {
                let response = client
                    .post(format!("{base}/predict"))
                    .bearer_auth(sidecar.authorization())
                    .multipart(form(&spec["entries"], fixture.clone()))
                    .send()
                    .await
                    .unwrap();
                assert!(
                    response.status().is_success(),
                    "bound OCR prediction refused"
                );
                let bytes = response.bytes().await.unwrap();
                assert!(bytes.len() <= 4 * 1024 * 1024);
                outputs.push(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap());
            }
            outputs
        });
        sidecar.stop().unwrap();
        drop(sidecar);
        assert!(!scratch.exists());
        // Use the packaged production comparator so this test cannot drift from its output contract.
        use std::process::{Child, Command, Stdio};
        struct Comparator(Child);
        impl Drop for Comparator {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let comparison = work.join("comparison.json");
        fs::write(
            &comparison,
            serde_json::to_vec(&serde_json::json!({
                "actual": outputs, "expected": spec["expectedOutput"],
            }))
            .unwrap(),
        )
        .unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        crate::native_runtime::VerifiedRuntime::verify(
            &root.join("payload"),
            &manifest_bytes,
            &signature,
            &keys,
            floor,
        )
        .unwrap();
        let mut comparator = Comparator(Command::new(root.join("payload").join(manifest["python"].as_str().unwrap()))
            .env_clear().args(["-I", "-B", "-c", "import json,sys;from frameleaf_ml.qualification import compare_output;v=json.load(open(sys.argv[1]));[compare_output(x,v['expected']) for x in v['actual']]"])
            .arg(&comparison).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = comparator.0.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "packaged comparator rejected native HTTP output"
                );
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "packaged comparator deadline"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        drop(comparator);
        fs::remove_file(comparison).unwrap();
        fs::write(output.join("native-bound-http.json"), serde_json::to_vec_pretty(&serde_json::json!({
            "sourceRevision": runtime.source_revision(), "manifestSha256": runtime.manifest_sha256(),
            "authenticatedCanonicalComparisons": 2, "unauthorizedRefused": true,
            "unboundConfigurationRefused": true, "oversizedImageRefused": true,
            "sidecarStopped": true, "scratchRemoved": true,
            "installedAcceptance": false, "nasLeaseExecuted": false,
        })).unwrap()).unwrap();
        assert!(fs::read_dir(&work).unwrap().next().is_none());
        fs::remove_dir(&work).unwrap();
    }
}
