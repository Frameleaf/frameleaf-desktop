//! Approved model identities are compiled into the app; a NAS can request a profile but cannot replace it.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
const DATA: &str = include_str!("../../runtime/model-catalogue.json");
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Catalogue {
    schema_version: u32,
    epoch: u64,
    profiles: Vec<ProfileData>,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileData {
    model_key: String,
    model_name: String,
    workload: String,
    runtime_source_revision: String,
    model_snapshot_revision: String,
    embedding_dimensions: usize,
    spec: Value,
    fixture_base64: String,
    artifact_bytes: BTreeMap<String, u64>,
}
/// Only the compiled-catalogue selector can construct this authority-bearing type.
/// ```compile_fail
/// let _: frameleaf_desktop::model_catalogue::ApprovedProfile = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone)]
pub struct ApprovedProfile(ProfileData);
impl ApprovedProfile {
    pub fn model_key(&self) -> &str {
        self.0.model_key()
    }
    pub fn runtime_source_revision(&self) -> &str {
        &self.0.runtime_source_revision
    }
    pub fn provider(&self) -> &str {
        self.0.spec["provider"]
            .as_str()
            .expect("validated model provider")
    }
    pub fn embedding_dimensions(&self) -> usize {
        self.0.embedding_dimensions()
    }
    pub fn challenge(&self, id: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.0.challenge(id)
    }
}
fn invalid() -> String {
    "model_catalogue_invalid".into()
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn is_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn safe_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.contains(['\\', ':'])
        && !value.chars().any(char::is_control)
        && value.split('/').all(|part| {
            let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
            !part.is_empty()
                && !matches!(part, "." | "..")
                && !part.ends_with(['.', ' '])
                && !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        })
}
impl ProfileData {
    pub fn model_key(&self) -> &str {
        &self.model_key
    }
    pub fn embedding_dimensions(&self) -> usize {
        self.embedding_dimensions
    }
    fn fixture(&self) -> Result<Vec<u8>, String> {
        if self.fixture_base64.len() > 22_369_624 {
            return Err(invalid());
        }
        let bytes = STANDARD
            .decode(&self.fixture_base64)
            .map_err(|_| invalid())?;
        if bytes.is_empty()
            || bytes.len() > 16 * 1024 * 1024
            || STANDARD.encode(&bytes) != self.fixture_base64
            || self.spec["fixtureSha256"] != digest(&bytes)
        {
            return Err(invalid());
        }
        Ok(bytes)
    }
    /// A fresh NAS UUID changes the raw-spec digest without changing model/configuration or fixture bytes.
    pub fn challenge(&self, id: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
        let uuid = Uuid::parse_str(id).map_err(|_| "model_challenge_invalid")?;
        if uuid.get_version_num() != 4 || uuid.to_string() != id {
            return Err("model_challenge_invalid".into());
        }
        let mut spec = self.spec.clone();
        let extension = if spec["fixtureKind"] == "text" {
            "txt"
        } else {
            "png"
        };
        spec["fixtureFile"] = json!(format!("{id}.{extension}"));
        Ok((
            serde_json::to_vec(&spec).map_err(|_| invalid())?,
            self.fixture()?,
        ))
    }
    fn validate(&self) -> Result<(), String> {
        let object = self.spec.as_object().ok_or_else(invalid)?;
        let fields: BTreeSet<_> = [
            "protocolVersion",
            "modelKey",
            "provider",
            "models",
            "entries",
            "preprocessingSha256",
            "fixtureFile",
            "fixtureKind",
            "fixtureSha256",
            "expectedOutput",
            "minMemoryBytes",
            "deadlineSeconds",
        ]
        .into_iter()
        .collect();
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != fields
            || self.workload != "clip"
            || !is_digest(&self.runtime_source_revision, 40)
            || self.spec["protocolVersion"] != 1
            || self.spec["modelKey"] != self.model_key
            || !(1..=65536).contains(&self.embedding_dimensions)
            || !self.spec["entries"].is_object()
            || !matches!(
                self.spec["provider"].as_str(),
                Some(
                    "CPUExecutionProvider"
                        | "CUDAExecutionProvider"
                        | "CoreMLExecutionProvider"
                        | "OpenVINOExecutionProvider"
                        | "MIGraphXExecutionProvider"
                )
            )
            || !self.spec["preprocessingSha256"]
                .as_str()
                .is_some_and(|v| is_digest(v, 64))
            || !self.spec["minMemoryBytes"]
                .as_u64()
                .is_some_and(|v| v > 0 && v <= 9_007_199_254_740_991)
            || !self.spec["deadlineSeconds"]
                .as_u64()
                .is_some_and(|v| (1..=600).contains(&v))
        {
            return Err(invalid());
        }
        let name = self.spec["fixtureFile"].as_str().ok_or_else(invalid)?;
        if !safe_path(name)
            || name.contains('/')
            || matches!(name, "qualification.json" | "report.json")
        {
            return Err(invalid());
        }
        let models = self.spec["models"]
            .as_array()
            .filter(|v| v.len() == 1)
            .ok_or_else(invalid)?;
        let model = &models[0];
        let kind = self.spec["fixtureKind"].as_str().ok_or_else(invalid)?;
        let model_type = match kind {
            "text" => "textual",
            "image" => "visual",
            _ => return Err(invalid()),
        };
        if model["name"] != self.model_name
            || model["task"] != "clip"
            || model["type"] != model_type
        {
            return Err(invalid());
        }
        let entries = self.spec["entries"].as_object().ok_or_else(invalid)?;
        let clip = self.spec["entries"]["clip"]
            .as_object()
            .ok_or_else(invalid)?;
        if entries.len() != 1
            || clip.len() != 1
            || self.spec["entries"]["clip"][model_type]["modelName"] != self.model_name
        {
            return Err(invalid());
        }
        let artifacts = model["artifacts"]
            .as_object()
            .filter(|v| !v.is_empty() && v.len() <= 4096)
            .ok_or_else(invalid)?;
        if artifacts.keys().collect::<BTreeSet<_>>()
            != self.artifact_bytes.keys().collect::<BTreeSet<_>>()
        {
            return Err(invalid());
        }
        let ref_path = format!("models--frameleaf--{}/refs/main", self.model_name);
        if !is_digest(&self.model_snapshot_revision, 40)
            || artifacts.get(&ref_path)
                != Some(&json!(digest(self.model_snapshot_revision.as_bytes())))
            || self.artifact_bytes.get(&ref_path)
                != Some(&(self.model_snapshot_revision.len() as u64))
        {
            return Err(invalid());
        }
        let mut folded = BTreeSet::new();
        let mut total = 0u64;
        for (name, bytes) in &self.artifact_bytes {
            total = total.checked_add(*bytes).ok_or_else(invalid)?;
            if !safe_path(name)
                || !folded.insert(name.to_lowercase())
                || *bytes > 16 * 1024 * 1024 * 1024
                || total > 10 * 1024 * 1024 * 1024
                || !artifacts[name].as_str().is_some_and(|v| is_digest(v, 64))
            {
                return Err(invalid());
            }
        }
        let identity = json!({"protocolVersion":1,"entries":self.spec["entries"],"models":self.spec["models"],"preprocessingSha256":self.spec["preprocessingSha256"]});
        if self.model_key
            != format!(
                "clip:{}",
                digest(&serde_json::to_vec(&identity).map_err(|_| invalid())?)
            )
        {
            return Err(invalid());
        }
        let vector: Vec<f64> = serde_json::from_str(
            self.spec["expectedOutput"]["clip"]
                .as_str()
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        if vector.len() != self.embedding_dimensions || vector.iter().any(|v| !v.is_finite()) {
            return Err(invalid());
        }
        let fixture = self.fixture()?;
        let output = self.spec["expectedOutput"]
            .as_object()
            .ok_or_else(invalid)?;
        if kind == "text" {
            if output.len() != 1 || std::str::from_utf8(&fixture).is_err() {
                return Err(invalid());
            }
        } else if output.len() != 3
            || fixture.len() < 24
            || fixture[..8] != [137, 80, 78, 71, 13, 10, 26, 10]
            || self.spec["expectedOutput"]["imageWidth"]
                != u32::from_be_bytes(fixture[16..20].try_into().map_err(|_| invalid())?)
            || self.spec["expectedOutput"]["imageHeight"]
                != u32::from_be_bytes(fixture[20..24].try_into().map_err(|_| invalid())?)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
fn parse_catalogue(raw: &str) -> Result<Vec<ProfileData>, String> {
    let catalogue: Catalogue = serde_json::from_str(raw).map_err(|_| invalid())?;
    if catalogue.schema_version != 1
        || catalogue.epoch == 0
        || catalogue.profiles.is_empty()
        || catalogue.profiles.len() > 256
    {
        return Err(invalid());
    }
    let mut keys = BTreeSet::new();
    for profile in &catalogue.profiles {
        profile.validate()?;
        if !keys.insert((
            &profile.model_key,
            profile.spec["provider"].as_str(),
            &profile.runtime_source_revision,
        )) {
            return Err(invalid());
        }
    }
    Ok(catalogue.profiles)
}
pub fn approved_profile(
    model_name: &str,
    entries: &Value,
    runtime_source_revision: &str,
    provider: &str,
) -> Result<Option<ApprovedProfile>, String> {
    Ok(parse_catalogue(DATA)?
        .into_iter()
        .find(|profile| {
            profile.model_name == model_name
                && profile.spec["entries"] == *entries
                && profile.runtime_source_revision == runtime_source_revision
                && profile.spec["provider"] == provider
        })
        .map(ApprovedProfile))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    #[test]
    fn only_exact_built_in_model_configuration_runtime_and_provider_can_be_selected() {
        let catalogue: Value =
            serde_json::from_str(include_str!("../../runtime/model-catalogue.json")).unwrap();
        for raw in catalogue["profiles"].as_array().unwrap() {
            let name = raw["modelName"].as_str().unwrap();
            let entries = &raw["spec"]["entries"];
            let source = raw["runtimeSourceRevision"].as_str().unwrap();
            let selected = approved_profile(name, entries, source, "CPUExecutionProvider")
                .unwrap()
                .unwrap();
            assert_eq!(selected.model_key(), raw["modelKey"].as_str().unwrap());
            assert!(
                approved_profile("ViT-B-32__openai", entries, source, "CPUExecutionProvider")
                    .unwrap()
                    .is_none()
            );
            assert!(
                approved_profile(name, &json!({}), source, "CPUExecutionProvider")
                    .unwrap()
                    .is_none()
            );
            assert!(
                approved_profile(name, entries, &"0".repeat(40), "CPUExecutionProvider")
                    .unwrap()
                    .is_none()
            );
            assert!(
                approved_profile(name, entries, source, "CUDAExecutionProvider")
                    .unwrap()
                    .is_none()
            );
        }
    }
    #[test]
    fn challenge_nonce_changes_the_spec_binding_without_changing_model_or_fixture() {
        let catalogue: Value =
            serde_json::from_str(include_str!("../../runtime/model-catalogue.json")).unwrap();
        let raw = &catalogue["profiles"][0];
        let selected = approved_profile(
            raw["modelName"].as_str().unwrap(),
            &raw["spec"]["entries"],
            raw["runtimeSourceRevision"].as_str().unwrap(),
            "CPUExecutionProvider",
        )
        .unwrap()
        .unwrap();
        let (first, fixture) = selected
            .challenge("d621bd72-ad35-4199-95ab-76300756a38e")
            .unwrap();
        let (second, other) = selected
            .challenge("c39d4385-84f8-4c37-a643-1b98fc12df93")
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(fixture, other);
        let value: Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(value["modelKey"], raw["modelKey"]);
        assert_eq!(
            value["fixtureSha256"],
            format!("{:x}", Sha256::digest(&fixture))
        );
        assert_eq!(
            value["fixtureFile"],
            "d621bd72-ad35-4199-95ab-76300756a38e.txt"
        );
        assert!(selected.challenge("../untrusted").is_err());
    }
    #[test]
    fn rejects_tampered_built_in_identity_fixture_and_dimensions() {
        let original: Value = serde_json::from_str(DATA).unwrap();
        let mut value = original.clone();
        value["profiles"][0]["spec"]["models"][0]["artifacts"]["textual/model.onnx"] =
            json!("0".repeat(64));
        assert!(parse_catalogue(&value.to_string()).is_err());
        value = original.clone();
        value["profiles"][0]["embeddingDimensions"] = json!(512);
        assert!(parse_catalogue(&value.to_string()).is_err());
        value = original;
        value["profiles"][0]["fixtureBase64"] = json!(STANDARD.encode(b"changed"));
        assert!(parse_catalogue(&value.to_string()).is_err());
    }
    #[test]
    fn matches_nas_challenge_digest_for_every_approved_profile() {
        let expected = [
            "667244e2f6254b58c290a62f4b82cc5f82f5957f394813e015e1f8cf4454527a",
            "209293bc2f54fbcdc0524b1cec7eb81e5bfb4f045432885b037947288b42b03d",
            "839b7ff60758640ad3644dd7761bea5e8e26bfde32355c8371d9c50042ecc838",
            "c53ede795fb9a86ecba813f1e4f279ee4fa16e9109ed245db5ae8f1d144cd2c5",
            "a14a99cad4f9e208fd8729680a37211dd09ed13b9e34462559c13f9dd35826a3",
            "4756b97c88cdafaf134d234d96f49b64c9ec16294e6966c3eb9d94d4a60b66fa",
        ];
        let profiles = parse_catalogue(DATA).unwrap();
        assert_eq!(profiles.len(), expected.len());
        for (profile, expected) in profiles.iter().zip(expected) {
            let (spec, _) = profile
                .challenge("d621bd72-ad35-4199-95ab-76300756a38e")
                .unwrap();
            assert_eq!(digest(&spec), expected);
        }
    }
}
