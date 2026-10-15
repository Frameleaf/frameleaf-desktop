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
// shortcut: the initial floor is compiled; add a monotonic OS-keystore floor before enabling runtime updates.
pub fn open_runtime_store(root: &Path) -> Result<RuntimeStore, String> {
    let (floor, keys) = parse_policy(POLICY)?;
    RuntimeStore::new(root, keys, floor)
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
}
