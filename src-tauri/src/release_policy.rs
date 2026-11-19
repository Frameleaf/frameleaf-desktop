//! Public release authority compiled into the app; a NAS response can never supply trust keys.
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
    keys: Vec<Key>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Key {
    id: String,
    public_key_hex: String,
}
fn parse_policy(raw: &str) -> Result<(u64, Vec<VerifyingKey>), String> {
    let policy: Policy = serde_json::from_str(raw).map_err(|_| "release_policy_invalid")?;
    if policy.schema_version != 1
        || policy.minimum_runtime_epoch == 0
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
    Ok((policy.minimum_runtime_epoch, keys))
}
/// The release floor and keys every signed runtime artifact is checked against.
pub(crate) fn trust() -> Result<(u64, Vec<VerifyingKey>), String> {
    parse_policy(POLICY)
}
pub fn open_runtime_store(root: &Path) -> Result<RuntimeStore, String> {
    let (floor, keys) = parse_policy(POLICY)?;
    RuntimeStore::new(
        root,
        keys,
        floor,
        std::sync::Arc::new(crate::credentials::CredentialEpochAuthority),
    )
}

/// The release the app's own bundle would install: the rollback target pruning keeps.
pub(crate) fn bundled_release(bundle: &Path, manifest: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    crate::runtime_store::read_bounded(&bundle.join(manifest), 8 * 1024 * 1024)
        .ok()
        .map(|raw| format!("{:x}", Sha256::digest(raw)))
}

/// Best effort, once the current selection has qualified with the active runtime: reclaim
/// runtime packs that can never run again, combined model sets the selection no longer uses and
/// inference scratch no worker owns. Each rule keeps what it cannot identify.
pub(crate) fn reclaim_superseded(
    data: &Path,
    bundle: &Path,
    active_runtime: &str,
    active_set: &Path,
    now: std::time::SystemTime,
) {
    if let Ok(store) = open_runtime_store(&data.join("runtimes")) {
        let rollback = bundled_release(bundle, "manifest.json");
        let _ = store.prune(active_runtime, rollback.as_deref());
    }
    let _ = crate::model_cache::prune_model_sets(&data.join("model-sets"), active_set, now);
    let _ = crate::model_cache::prune_scratch(&data.join("scratch"), now);
}

pub fn verify_host_runtime(
    root: &Path,
    manifest: &[u8],
    signature: &[u8; 64],
) -> Result<crate::host_runtime::VerifiedHostRuntime, String> {
    let (floor, keys) = parse_policy(POLICY)?;
    crate::host_runtime::VerifiedHostRuntime::verify(root, manifest, signature, &keys, floor)
}
/// The package a library last ran with, admitted for its one export run and nothing else: the
/// same keys and release floor, and only the database builds this app declares it carries
/// libraries forward from.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
pub(crate) fn verify_host_carry_source(
    root: &Path,
    manifest: &[u8],
    signature: &[u8; 64],
) -> Result<crate::host_runtime::CarrySourceRuntime, String> {
    let (floor, keys) = parse_policy(POLICY)?;
    crate::host_runtime::VerifiedHostRuntime::verify_carry_source(
        root,
        manifest,
        signature,
        &keys,
        floor,
        &crate::host_runtime::declared_carry_sources(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_policy_has_a_positive_floor_and_rejects_invalid_or_ambiguous_keys() {
        let (floor, keys) = parse_policy(POLICY).unwrap();
        assert!(floor > 0);
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
        let (floor, keys) = parse_policy(POLICY).unwrap();
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

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an approved signed host/evidence pair on a disposable Windows runner"]
    fn factory_signed_host_candidate_verifies_against_compiled_authority() {
        use sha2::{Digest, Sha256};
        use std::io::Write;

        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(
            std::env::var("RUNNER_ENVIRONMENT").as_deref(),
            Ok("github-hosted")
        );
        let root =
            std::path::PathBuf::from(std::env::var("FRAMELEAF_FACTORY_HOST_TEST_PACK").unwrap());
        assert_eq!(
            root,
            std::path::PathBuf::from(std::env::var("RUNNER_TEMP").unwrap())
                .join("windows-compiled-host/candidate")
        );
        let expected = std::env::var("FRAMELEAF_FACTORY_HOST_EXPECTED_MANIFEST").unwrap();
        assert!(crate::native_runtime::digest_valid(&expected, 64));
        let raw = crate::runtime_store::read_bounded(&root.join("manifest.json"), 16 * 1024 * 1024)
            .unwrap();
        let signature: [u8; 64] =
            crate::runtime_store::read_bounded(&root.join("manifest.sig"), 64)
                .unwrap()
                .try_into()
                .unwrap();
        let host = verify_host_runtime(&root.join("payload"), &raw, &signature).unwrap();
        assert_eq!(host.manifest_sha256(), expected);
        assert_eq!(
            host.source_revision(),
            "9f22a57adb7a271d97ead305103c094fb3d25ad2"
        );
        assert!(!host.certified());
        let manifest: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(manifest["entryPoints"]["mlManifest"], "ml/manifest.json");
        let ml_root = root.join("payload/ml");
        let ml_raw =
            crate::runtime_store::read_bounded(&ml_root.join("manifest.json"), 8 * 1024 * 1024)
                .unwrap();
        let ml_signature: [u8; 64] =
            crate::runtime_store::read_bounded(&ml_root.join("manifest.sig"), 64)
                .unwrap()
                .try_into()
                .unwrap();
        let (floor, keys) = parse_policy(POLICY).unwrap();
        let ml = crate::native_runtime::VerifiedRuntime::verify(
            &ml_root.join("payload"),
            &ml_raw,
            &ml_signature,
            &keys,
            floor,
        )
        .unwrap();
        let unsigned: serde_json::Value = serde_json::from_slice(
            &crate::runtime_store::read_bounded(&root.join("qualification.json"), 16 * 1024 * 1024)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(unsigned["ml"]["manifestSha256"], ml.manifest_sha256());
        assert_eq!(unsigned["ml"]["sourceRevision"], ml.source_revision());
        assert_eq!(unsigned["ml"]["epoch"], ml.epoch());
        let mut altered = signature;
        altered[0] ^= 1;
        assert_eq!(
            verify_host_runtime(&root.join("payload"), &raw, &altered)
                .err()
                .as_deref(),
            Some("host_signature_invalid")
        );
        let mut altered_ml = ml_signature;
        altered_ml[0] ^= 1;
        assert_eq!(
            crate::native_runtime::VerifiedRuntime::verify(
                &ml_root.join("payload"),
                &ml_raw,
                &altered_ml,
                &keys,
                floor,
            )
            .err()
            .as_deref(),
            Some("runtime_signature_invalid")
        );

        let receipt = serde_json::json!({
            "schemaVersion":1,"qualification":"passed","platform":"windows","architecture":"x86_64",
            "manifestSha256":host.manifest_sha256(),"sourceRevision":host.source_revision(),
            "epoch":manifest["epoch"],"certified":host.certified(),
            "signatureSha256":format!("{:x}",Sha256::digest(signature)),
            "files":manifest["files"].as_object().unwrap().len(),
            "entryPoints":manifest["entryPoints"].as_object().unwrap().len(),
            "hostSignatureVerified":true,"nestedMLSignatureVerified":true,
            "changedHostSignatureRefused":true,"changedMLSignatureRefused":true,
            "ml":{"manifestSha256":ml.manifest_sha256(),"sourceRevision":ml.source_revision(),"epoch":ml.epoch()},
            "runtimeQualified":false,"redistributable":false,"installedPlatformQualified":false,
            "fullMediaConformance":false,"serverStarted":false,
            "scope":"Compiled host and nested ML signature/resource admission; protected installation remains separate"
        });
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.parent().unwrap().join("compiled-authority.json"))
            .unwrap();
        output
            .write_all(&serde_json::to_vec_pretty(&receipt).unwrap())
            .unwrap();
        output.sync_all().unwrap();
        eprintln!("PASS: complete host and nested ML resources verified against compiled release authority");
    }
}
