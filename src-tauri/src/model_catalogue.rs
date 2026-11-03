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
    #[serde(default)]
    embedding_dimensions: Option<usize>,
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
    pub fn embedding_dimensions(&self) -> Option<usize> {
        self.0.embedding_dimensions()
    }
    pub(crate) fn minimum_memory(&self) -> u64 {
        self.0.spec["minMemoryBytes"]
            .as_u64()
            .expect("validated model memory envelope")
    }
    pub fn challenge(&self, id: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.0.challenge(id)
    }
    pub(crate) async fn prepare_cache(
        &self,
        root: &std::path::Path,
        client: &reqwest::Client,
        cancel: &std::sync::atomic::AtomicBool,
        allow_download: bool,
    ) -> Result<std::path::PathBuf, String> {
        crate::model_cache::prepare(
            crate::model_cache::CachePlan {
                task: self.0.spec["models"][0]["task"]
                    .as_str()
                    .ok_or_else(invalid)?,
                name: &self.0.model_name,
                revision: &self.0.model_snapshot_revision,
                hashes: self.0.spec["models"][0]["artifacts"]
                    .as_object()
                    .ok_or_else(invalid)?,
                sizes: &self.0.artifact_bytes,
            },
            root,
            client,
            cancel,
            allow_download,
        )
        .await
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
    pub fn embedding_dimensions(&self) -> Option<usize> {
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
            serde_json_canonicalizer::to_vec(&spec).map_err(|_| invalid())?,
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
            || !matches!(self.workload.as_str(), "clip" | "ocr" | "face")
            || !is_digest(&self.runtime_source_revision, 40)
            || self.spec["protocolVersion"] != 1
            || self.spec["modelKey"] != self.model_key
            || (self.workload == "clip"
                && !self
                    .embedding_dimensions
                    .is_some_and(|n| (1..=65536).contains(&n)))
            || (self.workload == "ocr" && self.embedding_dimensions.is_some())
            || (self.workload == "face" && self.embedding_dimensions != Some(512))
            || self.model_name.is_empty()
            || self.model_name.len() > 128
            || !self
                .model_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
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
            .filter(|v| v.len() == if self.workload == "clip" { 1 } else { 2 })
            .ok_or_else(invalid)?;
        let model = &models[0];
        let kind = self.spec["fixtureKind"].as_str().ok_or_else(invalid)?;
        let family = if self.workload == "face" {
            "facial-recognition"
        } else {
            &self.workload
        };
        if self.workload == "clip" {
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
        } else if self.workload == "face" {
            validate_face_entries(&self.spec["entries"], &self.model_name, kind)?;
        } else {
            validate_ocr_entries(models, &self.spec["entries"], &self.model_name, kind)?;
        }
        if self.workload == "face"
            && models
                .iter()
                .map(|model| model["type"].as_str().unwrap_or(""))
                .collect::<BTreeSet<_>>()
                != BTreeSet::from(["detection", "recognition"])
        {
            return Err(invalid());
        }
        if models.iter().any(|m| {
            m.as_object().is_none_or(|o| o.len() != 4)
                || m["name"] != self.model_name
                || m["task"] != family
                || m["artifacts"] != model["artifacts"]
        }) {
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
                "{}:{}",
                self.workload,
                digest(&serde_json::to_vec(&identity).map_err(|_| invalid())?)
            )
        {
            return Err(invalid());
        }
        if self.workload == "clip" {
            let vector: Vec<f64> = serde_json::from_str(
                self.spec["expectedOutput"]["clip"]
                    .as_str()
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?;
            if Some(vector.len()) != self.embedding_dimensions
                || vector.iter().any(|v| !v.is_finite())
            {
                return Err(invalid());
            }
        } else if self.workload == "face" {
            validate_face_output(&self.spec["expectedOutput"])?;
        } else {
            validate_ocr_output(&self.spec["expectedOutput"])?;
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
fn validate_face_entries(entries: &Value, name: &str, kind: &str) -> Result<(), String> {
    let group = entries["facial-recognition"]
        .as_object()
        .ok_or_else(invalid)?;
    if kind != "image"
        || entries.as_object().is_none_or(|value| value.len() != 1)
        || group.len() != 2
    {
        return Err(invalid());
    }
    let detection = group
        .get("detection")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    let recognition = group
        .get("recognition")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    let options = entries["facial-recognition"]["detection"]["options"]
        .as_object()
        .ok_or_else(invalid)?;
    if detection.len() != 2
        || detection.get("modelName") != Some(&json!(name))
        || recognition.len() != 1
        || recognition.get("modelName") != Some(&json!(name))
        || options.len() != 1
        || !options
            .get("minScore")
            .and_then(Value::as_f64)
            .is_some_and(|v| v.is_finite() && (0.1..=1.0).contains(&v))
    {
        return Err(invalid());
    }
    Ok(())
}
fn validate_face_output(output: &Value) -> Result<(), String> {
    let width = output["imageWidth"]
        .as_u64()
        .filter(|v| *v > 0 && *v <= 65536)
        .ok_or_else(invalid)? as f64;
    let height = output["imageHeight"]
        .as_u64()
        .filter(|v| *v > 0 && *v <= 65536)
        .ok_or_else(invalid)? as f64;
    let faces = output["facial-recognition"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 4096)
        .ok_or_else(invalid)?;
    if width * height > 16.0 * 1024.0 * 1024.0 {
        return Err(invalid());
    }
    for face in faces {
        let object = face
            .as_object()
            .filter(|v| v.len() == 3)
            .ok_or_else(invalid)?;
        let bbox = face["boundingBox"]
            .as_object()
            .filter(|v| v.len() == 4)
            .ok_or_else(invalid)?;
        let number = |key: &str| {
            bbox.get(key)
                .and_then(Value::as_f64)
                .filter(|v| v.is_finite())
                .ok_or_else(invalid)
        };
        let (x1, x2, y1, y2) = (number("x1")?, number("x2")?, number("y1")?, number("y2")?);
        if !(-width <= x1
            && x1 < x2
            && x2 <= width * 2.0
            && -height <= y1
            && y1 < y2
            && y2 <= height * 2.0
            && object
                .get("score")
                .and_then(Value::as_f64)
                .is_some_and(|v| v.is_finite() && (0.0..=1.0).contains(&v)))
        {
            return Err(invalid());
        }
        let encoded = object
            .get("embedding")
            .and_then(Value::as_str)
            .filter(|v| v.len() <= 65536)
            .ok_or_else(invalid)?;
        let vector: Vec<f64> = serde_json::from_str(encoded).map_err(|_| invalid())?;
        if vector.len() != 512 || vector.iter().any(|v| !v.is_finite()) {
            return Err(invalid());
        }
    }
    Ok(())
}

fn validate_ocr_entries(
    models: &[Value],
    entries: &Value,
    name: &str,
    kind: &str,
) -> Result<(), String> {
    let ocr = entries["ocr"].as_object().ok_or_else(invalid)?;
    if kind != "image"
        || entries.as_object().is_none_or(|v| v.len() != 1)
        || ocr.len() != 2
        || models
            .iter()
            .map(|m| m["type"].as_str().unwrap_or(""))
            .collect::<BTreeSet<_>>()
            != BTreeSet::from(["detection", "recognition"])
    {
        return Err(invalid());
    }
    for role in ["detection", "recognition"] {
        let entry = ocr
            .get(role)
            .and_then(Value::as_object)
            .ok_or_else(invalid)?;
        let options = entry
            .get("options")
            .and_then(Value::as_object)
            .ok_or_else(invalid)?;
        if entry.len() != 2
            || entry.get("modelName") != Some(&json!(name))
            || options.len() != if role == "detection" { 2 } else { 1 }
            || !options
                .get("minScore")
                .and_then(Value::as_f64)
                .is_some_and(|v| v.is_finite() && (0.1..=1.0).contains(&v))
            || (role == "detection"
                && !options
                    .get("maxResolution")
                    .and_then(Value::as_u64)
                    .is_some_and(|n| n > 0 && n <= 9_007_199_254_740_991))
        {
            return Err(invalid());
        }
    }
    Ok(())
}
fn validate_ocr_output(output: &Value) -> Result<(), String> {
    let width = output["imageWidth"]
        .as_u64()
        .filter(|v| (1..=65_536).contains(v))
        .ok_or_else(invalid)?;
    let height = output["imageHeight"]
        .as_u64()
        .filter(|v| (1..=65_536).contains(v))
        .ok_or_else(invalid)?;
    if width * height > 16 * 1024 * 1024 {
        return Err(invalid());
    }
    let ocr = output["ocr"]
        .as_object()
        .filter(|v| v.len() == 4)
        .ok_or_else(invalid)?;
    let text = ocr
        .get("text")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty() && v.len() <= 4096)
        .ok_or_else(invalid)?;
    if text.iter().any(|s| {
        !s.as_str()
            .is_some_and(|s| !s.is_empty() && s.encode_utf16().count() <= 16_384)
    }) {
        return Err(invalid());
    }
    for (name, count) in [
        ("box", text.len() * 8),
        ("boxScore", text.len()),
        ("textScore", text.len()),
    ] {
        let values = ocr
            .get(name)
            .and_then(Value::as_array)
            .filter(|v| v.len() == count)
            .ok_or_else(invalid)?;
        if values.iter().any(|v| {
            !v.as_f64()
                .is_some_and(|n| n.is_finite() && (0.0..=1.0).contains(&n))
        }) {
            return Err(invalid());
        }
    }
    Ok(())
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

pub(crate) fn setup_profiles(
    name: &str,
    source: &str,
    provider: &str,
) -> Result<Vec<ApprovedProfile>, String> {
    Ok(parse_catalogue(DATA)?
        .into_iter()
        .filter(|profile| {
            profile.model_name == name
                && profile.runtime_source_revision == source
                && profile.spec["provider"] == provider
        })
        .map(ApprovedProfile)
        .collect())
}

pub(crate) fn inventory_group(
    workload: &str,
    keys: &[String],
    source: &str,
    provider: &str,
) -> Result<Vec<ApprovedProfile>, String> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let profiles: Vec<_> = parse_catalogue(DATA)?
        .into_iter()
        .filter(|profile| {
            profile.workload == workload
                && keys.contains(&profile.model_key)
                && profile.runtime_source_revision == source
                && profile.spec["provider"] == provider
        })
        .map(ApprovedProfile)
        .collect();
    if profiles.len() != keys.len() {
        return Ok(Vec::new());
    }
    if workload == "clip" {
        let expected = setup_profiles(&profiles[0].0.model_name, source, provider)?;
        if expected.len() != 3
            || expected
                .iter()
                .any(|profile| !keys.iter().any(|key| key == profile.model_key()))
        {
            return Ok(Vec::new());
        }
    }
    Ok(profiles)
}

pub(crate) fn shared_cache(
    profiles: &[ApprovedProfile],
    caches: &[std::path::PathBuf],
    root: &std::path::Path,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<std::path::PathBuf, String> {
    use crate::{
        model_cache::{check_cancel, verify_file},
        runtime_store::{private_directory, Staging},
    };
    use std::{fs, path::PathBuf};
    if profiles.is_empty() || profiles.len() != caches.len() {
        return Err("worker_model_binding_invalid".into());
    }
    if caches.iter().all(|cache| cache == &caches[0]) {
        return Ok(caches[0].clone());
    }
    let mut files: BTreeMap<PathBuf, (PathBuf, u64, String)> = BTreeMap::new();
    for (profile, cache) in profiles.iter().zip(caches) {
        let profile = &profile.0;
        profile.validate()?;
        let prefix = PathBuf::from(
            profile.spec["models"][0]["task"]
                .as_str()
                .ok_or_else(invalid)?,
        )
        .join(&profile.model_name);
        let hashes = profile.spec["models"][0]["artifacts"]
            .as_object()
            .ok_or_else(invalid)?;
        let receipt = serde_json::to_vec(hashes).map_err(|_| invalid())?;
        let mut add = |name: &str, bytes: u64, hash: String| -> Result<(), String> {
            let relative = prefix.join(name);
            if let Some((_, old_bytes, old_hash)) = files.get(&relative) {
                if *old_bytes != bytes || *old_hash != hash {
                    return Err("worker_cache_conflict".into());
                }
            } else {
                files.insert(relative.clone(), (cache.join(relative), bytes, hash));
            }
            Ok(())
        };
        for (name, bytes) in &profile.artifact_bytes {
            add(
                name,
                *bytes,
                hashes[name].as_str().ok_or_else(invalid)?.into(),
            )?;
        }
        add(
            ".frameleaf-staged.json",
            receipt.len() as u64,
            digest(&receipt),
        )?;
    }
    let identity: Vec<_> = files
        .iter()
        .map(|(path, (_, bytes, hash))| (path, bytes, hash))
        .collect();
    let scope = digest(&serde_json::to_vec(&identity).map_err(|_| invalid())?);
    let active = root.join(scope);
    private_directory(root)?;
    if active.exists() {
        for (relative, (_, bytes, hash)) in &files {
            verify_file(&active.join(relative), *bytes, hash, cancel)?;
        }
        return Ok(active);
    }
    let staging = Staging::create(root.join(format!(".composition-{}", Uuid::new_v4())))?;
    for (relative, (source, bytes, hash)) in &files {
        check_cancel(cancel)?;
        verify_file(source, *bytes, hash, cancel)?;
        let mut parent = staging.path().to_path_buf();
        for part in relative.parent().ok_or_else(invalid)?.components() {
            parent.push(part);
            private_directory(&parent)?;
        }
        let target = staging.path().join(relative);
        // App-owned immutable weights share disk blocks; verify the published inode again before use.
        fs::hard_link(source, &target).map_err(|_| "worker_cache_publish_failed")?;
        verify_file(&target, *bytes, hash, cancel)?;
    }
    check_cancel(cancel)?;
    fs::rename(staging.path(), &active).map_err(|_| "worker_cache_publish_failed")?;
    Ok(active)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admits_the_qualified_face_detector_and_512_value_recognizer() {
        let profile: ProfileData =
            serde_json::from_str(include_str!("../tests/fixtures/face-profile.json")).unwrap();
        profile.validate().unwrap();
        assert_eq!(profile.embedding_dimensions(), Some(512));
        let (spec, fixture) = profile
            .challenge("d621bd72-ad35-4199-95ab-76300756a38e")
            .unwrap();
        assert_eq!(fixture.len(), 791555);
        assert_eq!(
            serde_json::from_slice::<Value>(&spec).unwrap()["models"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
    #[test]
    fn composes_distinct_revision_caches_without_replacing_weights_and_detects_tampering() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-cache-set-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let mut profiles = Vec::new();
        let mut caches = Vec::new();
        for (index, (workload, family, name, fixture)) in [
            (
                "ocr",
                "ocr",
                "PP-OCRv5_mobile",
                include_str!("../tests/fixtures/ocr-profile.json"),
            ),
            (
                "face",
                "facial-recognition",
                "buffalo_l",
                include_str!("../tests/fixtures/face-profile.json"),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let mut raw: Value = serde_json::from_str(fixture).unwrap();
            let bytes = format!("fixture weights {index}");
            let revision = raw["modelSnapshotRevision"].as_str().unwrap().to_owned();
            let reference = format!("models--frameleaf--{name}/refs/main");
            let hashes = json!({"detection/model.onnx":digest(bytes.as_bytes()),"recognition/model.onnx":digest(bytes.as_bytes()),reference.clone():digest(revision.as_bytes())});
            raw["modelName"] = json!(name);
            raw["artifactBytes"] = json!({"detection/model.onnx":bytes.len(),"recognition/model.onnx":bytes.len(),reference.clone():revision.len()});
            for model in raw["spec"]["models"].as_array_mut().unwrap() {
                model["name"] = json!(name);
                model["artifacts"] = hashes.clone();
            }
            for role in ["detection", "recognition"] {
                raw["spec"]["entries"][family][role]["modelName"] = json!(name);
            }
            let identity = json!({"protocolVersion":1,"entries":raw["spec"]["entries"],"models":raw["spec"]["models"],"preprocessingSha256":raw["spec"]["preprocessingSha256"]});
            let key = format!(
                "{workload}:{}",
                digest(&serde_json::to_vec(&identity).unwrap())
            );
            raw["modelKey"] = json!(key);
            raw["spec"]["modelKey"] = json!(key);
            let profile: ProfileData = serde_json::from_value(raw).unwrap();
            profile.validate().unwrap();
            let cache = root.join(format!("source-{index}"));
            let model = cache.join(family).join(name);
            for path in [&cache, &cache.join(family), &model] {
                crate::runtime_store::private_directory(path).unwrap();
            }
            for role in ["detection", "recognition"] {
                crate::runtime_store::private_directory(&model.join(role)).unwrap();
                std::fs::write(model.join(role).join("model.onnx"), &bytes).unwrap();
            }
            let mut parent = model.clone();
            for part in std::path::Path::new(&reference)
                .parent()
                .unwrap()
                .components()
            {
                parent.push(part);
                crate::runtime_store::private_directory(&parent).unwrap();
            }
            std::fs::write(model.join(&reference), revision).unwrap();
            std::fs::write(
                model.join(".frameleaf-staged.json"),
                serde_json::to_vec(&hashes).unwrap(),
            )
            .unwrap();
            profiles.push(ApprovedProfile(profile));
            caches.push(cache);
        }
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let active = shared_cache(&profiles, &caches, &root.join("sets"), &cancelled).unwrap();
        for (family, name) in [
            ("ocr", "PP-OCRv5_mobile"),
            ("facial-recognition", "buffalo_l"),
        ] {
            assert!(active
                .join(family)
                .join(name)
                .join("detection/model.onnx")
                .is_file());
        }
        assert_eq!(
            shared_cache(&profiles, &caches, &root.join("sets"), &cancelled).unwrap(),
            active
        );
        std::fs::write(
            active.join("facial-recognition/buffalo_l/detection/model.onnx"),
            b"changed",
        )
        .unwrap();
        assert_eq!(
            shared_cache(&profiles, &caches, &root.join("sets"), &cancelled).unwrap_err(),
            "model_file_changed"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn restores_a_verified_ocr_cache_from_its_own_family() {
        for (workload, family, name, fixture) in [
            (
                "ocr",
                "ocr",
                "PP-OCRv5_mobile",
                include_str!("../tests/fixtures/ocr-profile.json"),
            ),
            (
                "face",
                "facial-recognition",
                "buffalo_l",
                include_str!("../tests/fixtures/face-profile.json"),
            ),
        ] {
            let mut profile: Value = serde_json::from_str(fixture).unwrap();
            let weights = b"fixture weights";
            let reference = profile["modelSnapshotRevision"]
                .as_str()
                .unwrap()
                .to_owned();
            let ref_path = format!("models--frameleaf--{name}/refs/main");
            let hashes = json!({"detection/model.onnx":digest(weights),"recognition/model.onnx":digest(weights),ref_path.clone():digest(reference.as_bytes())});
            profile["artifactBytes"] = json!({"detection/model.onnx":weights.len(),"recognition/model.onnx":weights.len(),ref_path.clone():reference.len()});
            for model in profile["spec"]["models"].as_array_mut().unwrap() {
                model["artifacts"] = hashes.clone();
            }
            let identity = json!({"protocolVersion":1,"entries":profile["spec"]["entries"],"models":profile["spec"]["models"],"preprocessingSha256":profile["spec"]["preprocessingSha256"]});
            let key = format!(
                "{workload}:{}",
                digest(&serde_json::to_vec(&identity).unwrap())
            );
            profile["modelKey"] = json!(key);
            profile["spec"]["modelKey"] = json!(key);
            let profile: ProfileData = serde_json::from_value(profile).unwrap();
            profile.validate().unwrap();
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-ocr-cache-{}", Uuid::new_v4()));
            let model = root.join(&reference).join(family).join(name);
            std::fs::create_dir_all(model.join("detection")).unwrap();
            std::fs::create_dir_all(model.join("recognition")).unwrap();
            std::fs::create_dir_all(model.join(&ref_path).parent().unwrap()).unwrap();
            std::fs::write(model.join("detection/model.onnx"), weights).unwrap();
            std::fs::write(model.join("recognition/model.onnx"), weights).unwrap();
            std::fs::write(model.join(&ref_path), reference.as_bytes()).unwrap();
            std::fs::write(
                model.join(".frameleaf-staged.json"),
                serde_json::to_vec(&hashes).unwrap(),
            )
            .unwrap();
            let result = ApprovedProfile(profile)
                .prepare_cache(
                    &root,
                    &crate::transport::client().unwrap(),
                    &std::sync::atomic::AtomicBool::new(false),
                    false,
                )
                .await;
            std::fs::remove_dir_all(&root).unwrap();
            assert_eq!(result.unwrap(), root.join(reference));
        }
    }
    #[test]
    fn refuses_face_engine_vector_and_output_changes_with_a_recomputed_identity() {
        let original: Value =
            serde_json::from_str(include_str!("../tests/fixtures/face-profile.json")).unwrap();
        let changes: [fn(&mut Value); 11] = [
            |v| {
                v["spec"]["models"].as_array_mut().unwrap().pop();
            },
            |v| v["spec"]["models"][1]["task"] = json!("ocr"),
            |v| v["spec"]["models"][1]["type"] = json!("detection"),
            |v| {
                v["spec"]["models"][1]["artifacts"]["recognition/model.onnx"] =
                    json!("0".repeat(64))
            },
            |v| v["embeddingDimensions"] = json!(768),
            |v| {
                v["spec"]["entries"]["facial-recognition"]["detection"]["options"]["extra"] =
                    json!(true)
            },
            |v| {
                v["spec"]["expectedOutput"]["facial-recognition"][0]["embedding"] = json!("[1,2,3]")
            },
            |v| v["spec"]["expectedOutput"]["facial-recognition"][0]["embedding"] = json!("[NaN]"),
            |v| {
                v["spec"]["expectedOutput"]["facial-recognition"][0]["boundingBox"]["x2"] =
                    json!(-1024)
            },
            |v| v["spec"]["expectedOutput"]["facial-recognition"][0]["score"] = json!(1.1),
            |v| v["spec"]["expectedOutput"]["facial-recognition"] = json!([]),
        ];
        for change in changes {
            let mut value = original.clone();
            change(&mut value);
            let identity = json!({"protocolVersion":1,"entries":value["spec"]["entries"],"models":value["spec"]["models"],"preprocessingSha256":value["spec"]["preprocessingSha256"]});
            let key = format!("face:{}", digest(&serde_json::to_vec(&identity).unwrap()));
            value["modelKey"] = json!(key);
            value["spec"]["modelKey"] = json!(key);
            let profile: ProfileData = serde_json::from_value(value).unwrap();
            assert!(profile.validate().is_err());
        }
    }
    #[test]
    fn refuses_ocr_engine_and_output_changes_even_with_a_recomputed_identity() {
        let original: Value =
            serde_json::from_str(include_str!("../tests/fixtures/ocr-profile.json")).unwrap();
        let changes: [fn(&mut Value); 7] = [
            |v| {
                v["spec"]["models"].as_array_mut().unwrap().pop();
            },
            |v| v["spec"]["models"][1]["task"] = json!("clip"),
            |v| v["spec"]["models"][1]["type"] = json!("detection"),
            |v| {
                v["spec"]["models"][1]["artifacts"]["recognition/model.onnx"] =
                    json!("0".repeat(64))
            },
            |v| v["embeddingDimensions"] = json!(768),
            |v| v["spec"]["expectedOutput"]["ocr"]["box"][0] = json!(1.1),
            |v| v["spec"]["expectedOutput"]["ocr"]["textScore"] = json!([]),
        ];
        for change in changes {
            let mut value = original.clone();
            change(&mut value);
            let identity = json!({"protocolVersion":1,"entries":value["spec"]["entries"],"models":value["spec"]["models"],"preprocessingSha256":value["spec"]["preprocessingSha256"]});
            let key = format!("ocr:{}", digest(&serde_json::to_vec(&identity).unwrap()));
            value["modelKey"] = json!(key);
            value["spec"]["modelKey"] = json!(key);
            let profile: ProfileData = serde_json::from_value(value).unwrap();
            assert!(profile.validate().is_err());
        }
    }
    #[test]
    fn accepts_an_ocr_pair_without_embedding_dimensions() {
        let profile: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/ocr-profile.json")).unwrap();
        let catalogue = serde_json::json!({"schemaVersion":1,"epoch":4,"profiles":[profile]});
        let parsed = parse_catalogue(&catalogue.to_string()).unwrap();
        assert_eq!(parsed[0].workload, "ocr");
        assert_eq!(parsed[0].spec["models"].as_array().unwrap().len(), 2);
    }

    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    #[tokio::test]
    #[ignore = "requires explicit test-network model download and an owned preparation directory"]
    async fn fresh_preparation_acquires_the_released_default_snapshot() {
        let root =
            std::path::PathBuf::from(std::env::var("FRAMELEAF_PREPARATION_TEST_ROOT").unwrap());
        let profiles = setup_profiles(
            "ViT-B-16-SigLIP-384__webli",
            "f60b8f30da46d2750ac2eb811d36cd290c411a3e",
            "CPUExecutionProvider",
        )
        .unwrap();
        assert_eq!(profiles.len(), 3);
        let client = crate::transport::client().unwrap();
        for profile in profiles {
            let path = profile
                .prepare_cache(
                    &root,
                    &client,
                    &std::sync::atomic::AtomicBool::new(false),
                    true,
                )
                .await
                .unwrap();
            assert_eq!(
                path.file_name().unwrap(),
                "77dda0dfc7afd494b918ec174cddca24854a73d1"
            );
            assert!(path
                .join("clip/ViT-B-16-SigLIP-384__webli/.frameleaf-staged.json")
                .is_file());
        }
    }
    #[test]
    fn setup_selects_every_paired_role_only_for_the_current_model_runtime_and_provider() {
        let source = "f60b8f30da46d2750ac2eb811d36cd290c411a3e";
        let profiles =
            setup_profiles("ViT-B-16-SigLIP-384__webli", source, "CPUExecutionProvider").unwrap();
        assert_eq!(profiles.len(), 3);
        let roles: Vec<_> = profiles
            .iter()
            .map(|p| p.0.spec["fixtureKind"].as_str().unwrap())
            .collect();
        assert_eq!(roles.iter().filter(|role| **role == "image").count(), 1);
        assert_eq!(roles.iter().filter(|role| **role == "text").count(), 2);
        assert!(
            setup_profiles("ViT-B-32__openai", source, "CPUExecutionProvider")
                .unwrap()
                .is_empty()
        );
        assert!(setup_profiles(
            "ViT-B-16-SigLIP-384__webli",
            &"0".repeat(40),
            "CPUExecutionProvider"
        )
        .unwrap()
        .is_empty());
        assert!(setup_profiles(
            "ViT-B-16-SigLIP-384__webli",
            source,
            "CUDAExecutionProvider"
        )
        .unwrap()
        .is_empty());
    }
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
    fn pr274_profiles_preserve_every_legacy_profile_and_use_distinct_new_identities() {
        let catalogue: Value = serde_json::from_str(DATA).unwrap();
        let profiles = catalogue["profiles"].as_array().unwrap();
        assert_eq!(profiles.len(), 21);
        let legacy = Value::Array(profiles[..11].to_vec());
        assert_eq!(
            digest(&serde_json_canonicalizer::to_vec(&legacy).unwrap()),
            "f09d6ae3ddf26a5c6cc0b92b9b0db056d567092c709b8aeb807161aefed870b5"
        );
        let source = "1ca4d52e2b8158d89d8de8b17e1e6535e17691f4";
        let old_keys: BTreeSet<_> = profiles[..11]
            .iter()
            .map(|p| p["modelKey"].as_str().unwrap())
            .collect();
        for profile in &profiles[11..16] {
            assert_eq!(profile["runtimeSourceRevision"], source);
            assert!(!old_keys.contains(profile["modelKey"].as_str().unwrap()));
        }
        assert_eq!(
            setup_profiles("ViT-B-16-SigLIP-384__webli", source, "CPUExecutionProvider")
                .unwrap()
                .len(),
            3
        );
    }
    #[test]
    fn matches_nas_challenge_digest_for_every_approved_profile() {
        let expected = [
            "667244e2f6254b58c290a62f4b82cc5f82f5957f394813e015e1f8cf4454527a",
            "209293bc2f54fbcdc0524b1cec7eb81e5bfb4f045432885b037947288b42b03d",
            "839b7ff60758640ad3644dd7761bea5e8e26bfde32355c8371d9c50042ecc838",
            "667244e2f6254b58c290a62f4b82cc5f82f5957f394813e015e1f8cf4454527a",
            "209293bc2f54fbcdc0524b1cec7eb81e5bfb4f045432885b037947288b42b03d",
            "839b7ff60758640ad3644dd7761bea5e8e26bfde32355c8371d9c50042ecc838",
            "c53ede795fb9a86ecba813f1e4f279ee4fa16e9109ed245db5ae8f1d144cd2c5",
            "a14a99cad4f9e208fd8729680a37211dd09ed13b9e34462559c13f9dd35826a3",
            "4756b97c88cdafaf134d234d96f49b64c9ec16294e6966c3eb9d94d4a60b66fa",
            "314c297749e23952b8541b47000e191dbccbac1556c5710b8f23a03d5d21391f",
            "10a83ae85fa830c3097abaa4117a6adf6542b7ac3fbddb998599f3ef6382cc9d",
            "8259538dd53d4729b01115092f4709964592011cd2b5c819385b9ba9ebbc295a",
            "3642a6d2195bb7cdb3205bb65b9416462079150ab73c53c7d0bb71a48bd19a20",
            "24f6500b8b91a7203c4b91f56fbbdfe3b51666e653d7c576fe065f9fe6709d2e",
            "fb3d5c5410ea666f34496fd324fc4c88678f3685d4a145c38811a7609355a5ab",
            "b9f58507b2f76a79c90a4cdc49155f162a086c502966a1280d0cb3a02bb86510",
            "b435382d9f7d19b49cb227cdcbca97f258845c7df41f4dc7ec86fe4f6d944570",
            "9c8818340b94b0f37cdd35509e038a86db8d1ced793aa7a742e74754215bc779",
            "31337c0063a85bdf957d27ef7ec581b34e65ee4a73f53215c238ff2c9342d40c",
            "75d39bab3c7ce04a0b3864ae8eb420664970faa66ab2f55a82c043a8d4c9ebc1",
            "eae6ee5d7291fec288026e79094c294de27187f769310e373625e80a18bab1c2",
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
    #[test]
    fn current_profiles_preserve_all_released_bindings_and_select_only_the_qualified_source() {
        let catalogue: Value = serde_json::from_str(DATA).unwrap();
        let profiles = catalogue["profiles"].as_array().unwrap();
        assert_eq!(
            digest(
                &serde_json_canonicalizer::to_vec(&Value::Array(profiles[..16].to_vec())).unwrap()
            ),
            "2e8b52cf4107668d2df47eb0564398028cb75502d766a3403b4201a41c7b03a1"
        );
        let source = "f93c34d196955da3e2760c095c08b27ccbf53315";
        assert_eq!(profiles[16..].len(), 5);
        for profile in &profiles[16..] {
            assert_eq!(profile["runtimeSourceRevision"], source);
            assert_eq!(profile["spec"]["provider"], "CPUExecutionProvider");
            assert_eq!(
                profile["spec"]["preprocessingSha256"],
                "06c8c5cc89891f53ae06675c3a4f32113c45215e705a9b2da0051143a8e13639"
            );
        }
        assert_eq!(
            setup_profiles("ViT-B-16-SigLIP-384__webli", source, "CPUExecutionProvider")
                .unwrap()
                .len(),
            3
        );
        assert!(setup_profiles(
            "ViT-B-16-SigLIP-384__webli",
            source,
            "CUDAExecutionProvider"
        )
        .unwrap()
        .is_empty());
    }
}
