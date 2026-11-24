//! Model profiles come from the server's catalogue, the only one: the server sends the profile of each model
//! it selected, and this computer validates, downloads (from Frameleaf's model mirror, hash-checked) and runs
//! exactly that profile in its factory-signed runtime. `runtime/model-catalogue.json` is a copy of the server's
//! catalogue for tests and release tools only; the app never reads it.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
#[cfg(test)]
const DATA: &str = include_str!("../../runtime/model-catalogue.json");
#[cfg(test)]
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
/// Built only from a validated profile the server served (`from_served`), never deserialized directly.
/// ```compile_fail
/// let _: frameleaf_desktop::model_catalogue::ApprovedProfile = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone)]
pub struct ApprovedProfile(ProfileData);
impl ApprovedProfile {
    /// A profile exactly as the server's catalogue ships it, after the same checks every profile gets.
    pub fn from_served(value: &Value) -> Result<Self, String> {
        let profile: ProfileData = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        profile.validate()?;
        Ok(Self(profile))
    }
    pub fn model_key(&self) -> &str {
        self.0.model_key()
    }
    pub(crate) fn model_name(&self) -> &str {
        &self.0.model_name
    }
    pub(crate) fn model_snapshot_revision(&self) -> &str {
        &self.0.model_snapshot_revision
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
    pub(crate) fn cache_identity(&self) -> (&str, &str, &str) {
        (
            self.0.spec["models"][0]["task"]
                .as_str()
                .expect("validated model task"),
            &self.0.model_name,
            &self.0.model_snapshot_revision,
        )
    }
    pub(crate) fn cache_bytes(&self) -> u64 {
        self.0.artifact_bytes.values().copied().sum()
    }
    pub(crate) async fn prepare_cache(
        &self,
        root: &std::path::Path,
        client: &reqwest::Client,
        cancel: &std::sync::atomic::AtomicBool,
        allow_download: bool,
        progress: impl Fn(crate::model_cache::CacheProgress),
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
            progress,
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
/// A relative file name that is safe on every system this app runs on, and that is the same
/// path inside a download address: letters, digits, `.`, `_`, `-` and `/` only, so nothing in it
/// can be read as an escape (`%2e%2e`), a query (`?`), a fragment (`#`) or another host.
fn safe_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
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
        // FD-31: a description runs in the runtime's own llama.cpp process; every other profile is ONNX.
        let description = self.workload == "description";
        let mut fields = fields;
        if description {
            fields.insert("engine");
        }
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != fields
            || !matches!(
                self.workload.as_str(),
                "clip" | "ocr" | "face" | "description"
            )
            || (description
                && (self.spec["engine"] != "qwen-gguf"
                    || self.spec["provider"] != "CPUExecutionProvider"
                    || self.embedding_dimensions.is_some()))
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
            .filter(|v| {
                v.len()
                    == if self.workload == "clip" || description {
                        1
                    } else {
                        2
                    }
            })
            .ok_or_else(invalid)?;
        let model = &models[0];
        let kind = self.spec["fixtureKind"].as_str().ok_or_else(invalid)?;
        let family = match self.workload.as_str() {
            "face" => "facial-recognition",
            "description" => DESCRIPTION_TASK,
            other => other,
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
        } else if description {
            let artifacts = model["artifacts"].as_object().ok_or_else(invalid)?;
            if kind != "image"
                || model["type"] != "visual"
                || self.spec["entries"]
                    != json!({ DESCRIPTION_TASK: { "visual": { "modelName": self.model_name, "options": {} } } })
                || !["visual/model.gguf", "visual/mmproj.gguf"]
                    .iter()
                    .all(|name| artifacts.contains_key(*name))
            {
                return Err(invalid());
            }
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
        } else if description {
            validate_description_output(&self.spec["expectedOutput"])?;
        } else {
            validate_ocr_output(&self.spec["expectedOutput"])?;
        }
        let fixture = self.fixture()?;
        let output = self.spec["expectedOutput"]
            .as_object()
            .ok_or_else(invalid)?;
        if description {
            // One sentence, no image size: the binding reports none.
            if fixture.len() < 24 || fixture[..8] != [137, 80, 78, 71, 13, 10, 26, 10] {
                return Err(invalid());
            }
        } else if kind == "text" {
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
/// The native Qwen binding's request and result task (FD-31).
pub(crate) const DESCRIPTION_TASK: &str = "image-description-tagging";
/// A description: one bounded factual sentence, every other field empty, as the binding returns it.
pub(crate) fn validate_description_output(output: &Value) -> Result<(), String> {
    let empty = json!([]);
    let result = output[DESCRIPTION_TASK].as_object().ok_or_else(invalid)?;
    let text = result
        .get("description")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if output.as_object().is_none_or(|v| v.len() != 1)
        || result.len() != 7
        || text.is_empty()
        || text.chars().count() > 240
        || text.trim() != text
        || text.chars().any(char::is_control)
        || text.to_lowercase().contains("<think")
        || text.to_lowercase().contains("</think")
        || ["people", "objects", "visible_text", "tags"]
            .iter()
            .any(|key| result.get(*key) != Some(&empty))
        || ["environment", "context"]
            .iter()
            .any(|key| result.get(*key) != Some(&json!("")))
    {
        return Err(invalid());
    }
    Ok(())
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
#[cfg(test)]
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
#[cfg(test)]
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

/// The profiles the server sent for one task. Each is a valid profile of that workload for this runtime and
/// provider, carrying exactly the key the server named in the same place.
pub(crate) fn served_group(
    workload: &str,
    keys: &[String],
    served: &[Value],
    source: &str,
    provider: &str,
) -> Result<Vec<ApprovedProfile>, String> {
    if served.len() != keys.len() {
        return Err(invalid());
    }
    keys.iter()
        .zip(served)
        .map(|(key, value)| {
            let profile = ApprovedProfile::from_served(value)?;
            if profile.0.model_key != *key
                || profile.0.workload != workload
                || profile.0.runtime_source_revision != source
                || profile.0.spec["provider"] != provider
            {
                return Err(invalid());
            }
            Ok(profile)
        })
        .collect()
}

pub(crate) fn shared_cache(
    profiles: &[ApprovedProfile],
    caches: &[std::path::PathBuf],
    root: &std::path::Path,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<std::path::PathBuf, String> {
    use crate::{
        model_cache::{check_cancel, check_file},
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
    let active = root.join(&scope);
    private_directory(root)?;
    if active.exists() {
        let verified = files
            .iter()
            .try_for_each(|(relative, (_, bytes, _))| check_file(&active.join(relative), *bytes));
        match verified {
            Ok(()) => return Ok(active),
            // FD-64: the set links each model file, so a file its cache has since repaired
            // (replaced) leaves the set holding the old bytes, and one removed from the set is
            // simply missing. Discard the set and compose it again from the caches, which are
            // verified below before anything is linked.
            Err(code)
                if matches!(
                    code.as_str(),
                    "model_file_changed" | "model_file_unavailable" | "runtime_file_unavailable"
                ) =>
            {
                crate::model_cache::remove_contained(root, &scope)?;
            }
            Err(code) => return Err(code),
        }
    }
    let staging = Staging::create(root.join(format!(".composition-{}", Uuid::new_v4())))?;
    // Each source was hashed when it was downloaded: the set links those files, checked by size.
    for (relative, (source, bytes, _)) in &files {
        check_cancel(cancel)?;
        check_file(source, *bytes)?;
        let mut parent = staging.path().to_path_buf();
        for part in relative.parent().ok_or_else(invalid)?.components() {
            parent.push(part);
            private_directory(&parent)?;
        }
        let target = staging.path().join(relative);
        // App-owned immutable weights share disk blocks; verify the published inode again before use.
        fs::hard_link(source, &target).map_err(|_| "worker_cache_publish_failed")?;
        check_file(&target, *bytes)?;
    }
    check_cancel(cancel)?;
    fs::rename(staging.path(), &active).map_err(|_| "worker_cache_publish_failed")?;
    Ok(active)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_artifact_name_cannot_change_the_address_it_is_downloaded_from() {
        for name in [
            "visual/model.onnx",
            "models--frameleaf--ViT-B-32__openai/refs/main",
            "detection/model.onnx",
            "config.json",
        ] {
            assert!(safe_path(name), "{name}");
        }
        for name in [
            "%2e%2e/secret",
            "visual/model.onnx?download=1",
            "visual/model.onnx#fragment",
            "visual/%2fmodel.onnx",
            "a b/model.onnx",
            "visual;x/model.onnx",
            "user@host/model.onnx",
            "../model.onnx",
            "visual//model.onnx",
            "C:/model.onnx",
            "visual\\model.onnx",
            "",
        ] {
            assert!(!safe_path(name), "{name}");
        }
    }
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
        // FD-64: the cache repairs a changed file by replacing it (the right bytes, in a new
        // file). The set, which still links the changed one, is composed again from the caches
        // instead of failing for ever.
        let repaired = caches[1].join("facial-recognition/buffalo_l/detection/model.onnx");
        let linked = active.join("facial-recognition/buffalo_l/detection/model.onnx");
        for _ in 0..2 {
            std::fs::remove_file(&repaired).unwrap();
            std::fs::write(&repaired, b"fixture weights 1").unwrap();
            let again = shared_cache(&profiles, &caches, &root.join("sets"), &cancelled).unwrap();
            assert_eq!(again, active);
            assert_eq!(std::fs::read(&linked).unwrap(), b"fixture weights 1");
            // Changed again, through the set this time: the cache's file is the same one.
            std::fs::write(&linked, b"changed").unwrap();
            assert_eq!(std::fs::read(&repaired).unwrap(), b"changed");
        }
        std::fs::remove_file(&repaired).unwrap();
        std::fs::write(&repaired, b"fixture weights 1").unwrap();
        assert_eq!(std::fs::read(&linked).unwrap(), b"changed");
        shared_cache(&profiles, &caches, &root.join("sets"), &cancelled).unwrap();
        assert_eq!(std::fs::read(&linked).unwrap(), b"fixture weights 1");
        // A file or a folder missing from the set is composed again the same way.
        std::fs::remove_file(&linked).unwrap();
        shared_cache(&profiles, &caches, &root.join("sets"), &cancelled).unwrap();
        assert_eq!(std::fs::read(&linked).unwrap(), b"fixture weights 1");
        std::fs::remove_dir_all(active.join("ocr/PP-OCRv5_mobile/detection")).unwrap();
        shared_cache(&profiles, &caches, &root.join("sets"), &cancelled).unwrap();
        assert!(active
            .join("ocr/PP-OCRv5_mobile/detection/model.onnx")
            .is_file());
        // Nothing but the one set is left behind.
        assert_eq!(std::fs::read_dir(root.join("sets")).unwrap().count(), 1);
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
                    |_| {},
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
                    |_| {},
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
        let mut runtimes = BTreeSet::new();
        for raw in catalogue["profiles"].as_array().unwrap() {
            let name = raw["modelName"].as_str().unwrap();
            let entries = &raw["spec"]["entries"];
            let source = raw["runtimeSourceRevision"].as_str().unwrap();
            let provider = raw["spec"]["provider"].as_str().unwrap();
            let selected = approved_profile(name, entries, source, provider)
                .unwrap()
                .unwrap();
            assert_eq!(selected.model_key(), raw["modelKey"].as_str().unwrap());
            assert_eq!(selected.provider(), provider);
            // The whole catalogue is parsed per lookup; refuse near misses once per runtime.
            if !runtimes.insert((source, provider)) {
                continue;
            }
            // a selectable model the catalogue has no profile for
            assert!(
                approved_profile("ViT-B-16-SigLIP2__webli", entries, source, provider)
                    .unwrap()
                    .is_none()
            );
            assert!(approved_profile(name, &json!({}), source, provider)
                .unwrap()
                .is_none());
            assert!(approved_profile(name, entries, &"0".repeat(40), provider)
                .unwrap()
                .is_none());
            assert!(
                approved_profile(name, entries, source, "MIGraphXExecutionProvider")
                    .unwrap()
                    .is_none()
            );
        }
        assert!(runtimes.len() > 1);
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
            "e60c7be1967dfa9f38df396ed3b3f2bcf4e309ba3e02290933a4f6d4e7419165",
            "b218ecbe1dceac1f7dbe68f3ffd3558ae452964b42a46154c965e474e36a836f",
            "c89f6440a4462fb75aaab690b76552b817ff7abd8d481df87e5662524eafaab8",
            "546549421b4d0dc3f4a8601db9207befd4d82e3ecb9e0ad52849ed3199441be4",
            "b2af0f4cba01a87d6b656a69f4aa7ab3cddba1bfb0bda4d4340c8ce484e16ef0",
            "7b744d6547e885abcfdd845f914fe858bd5e13321783af9c3b26f679fdf95f76",
            "05fc08742b2b05cebd5bf54302f1c78f8ba16902a502e4815a8a750ecba02a66",
            "46fc1b58fd122980ee5de68b62d7c431f8f115bb84e2d19933aa55ba08a89cb1",
            "fc631cdf02d40fb5a491e6fb0991bf0e5399918b86657e1b9e1ba483d5f02841",
            "f66eb524b80589047de44409de6a19ffa9ca2de18b7b6d8669a692700a625da6",
            "4db2580d36114fce59cea7fafb125c4f82ab93f78e82772bd50d888d14c358fe",
            "6f146c1d05e93818586ed9fcf70e3ae6de1ff195dbfcf15e96cec4f8a93975c4",
            "a6d03f7df8104794200ac2c6f7734c77634dd0dd4a119fc24a85015730be0fa7",
            "2d8945f2b72d68508c39e87b2cbc123cf51723d8b302d67a678d4bd00720b582",
            "0832de93d79c15053749f2f17dddaae95e2a18b00fa0e86d104b6e0d2d14e438",
            "1f104316fb10128ad1444d40b1de21b968b52459a9096b7f4163b2613f2ec25e",
            "4f3f460977c87e1155cca9ad4b47e57cc8c3de3832984bcb5c212a4aaf71f7fb",
            "354abc377aa6c89a573b2c14468eb2fb94e1030ba1ebeae384dde01612adeb00",
            "d9eecddc9dbbc61ff126beb62ce35b1e45af0b289f568c3a9b6ca219eb75f93c",
            "40115f6689e12d4b40e2e456dd4f20b527a29795a17d76c1b79b881b6b3b0f34",
            "420f5d93f9189e42fad015eec0ff2cb19571e1e5f127e68b6e2770b697f15557",
            "7480057b35520ea85d2bff0fa0fa026df115eabdd51ab87a9ba3ba2211d97b6d",
            "37a25a170947f424cc0231e279ff5ea5de7dfc0c1a40b056bb60f3c807ef176b",
            "f4a861ae2fb52c45577f1ab08aa0bdf794628dc11c4e4a2de75909bac6bf68b6",
            "2a43cd5fb87f155cb03c1d528dad7d560f390654ce7849b4ffa4da45eab5daf2",
            "bb60ac6ef80bdf0bcc77295364cece4173adad781cd945a7250b47fa2e19ad88",
            "82bc3cb4ec3204c5f06e0b43e1c3e65666d82bda63381d655c7eb92ab1d56551",
            "f3dabc2a4bdda94ec954ed297ef9da4ea2ea2b7875d328c508d5ca3d31227e0e",
            "c07473e7f48fc116ede101ba012f266a7c84c1a79485f8be4f6f80df49153d82",
            "eb5990f3895a30726bf70f19dca270e14c09325364d0c71085c4334a54912cff",
            "84a5a8662aab5eac9415ca46b9c25318ba0bd989f4711853c75776614e919f8c",
            "f27d2e6a303cff1789e855e0f1561a3a04b030639d4ff789800394a6ead51b94",
            "064de008feb79e0ce67642f2613a17a33479e9238ef0ccc58db3eb5571bd8a77",
            "a40b7628bbc61c2dbab819e83fae6bc738e4e5d0fba06eed749bede91c1dba70",
            "207621ca4431e3358137b8ce4a742887b0db1e003b78548ea8fc36209a25512e",
            "b3c98ec6de5f9e761a62044b8a261dc66d6273eff91f4a40fe7a9f97ea7f1016",
            "25c77459eda63cc99a54f72320de3d0ef2029ce9a0c7d239eea62e24c499ad24",
            "5b33ebee9460aa445513f196cc73597daa3f874ea2b527801f18bc67121f0759",
            "6a1a473fc90069f0b222e697272cb1a78f8fadd4a1c52af7e42ed3d6eb8bb37e",
            "194ab4b05a9b81e28466bc4341bd26d3c80349f3508f701ae63c9569a11a4d58",
            "efa3e6033ea6b6c6aa769444ef5e3ba2432f1ed236ed37d919083edf255c5452",
            "9e8cc701380276c1af1036c3493460904e91b6dc3c49193100f2733b244fed1f",
            "994248b4729d33ae1dfc09365b7fd56f4949f80f15e1a6d4608b256b5308e54c",
            "003981e4139fad9a251f21c59a89824c06a109640a358a8367683bd6b865cd4c",
            "439a10ed09c75b25a0a4e39df0928e4636f6cc71eb73fecffa3eda028cbf4738",
            "c7d74c2feef0e1abd8ab48c519338f7d2bbebd7b5785544d21729dadb7231742",
            "8ae4a97bd0e176b44e519bf6c850310979364b986bd0f113913d3fe4df43fcf7",
            "9c3beed723095dbca064cc7b8af523d703fe249740367b9cb6d1ebc034ae2ab6",
            "c6af78be57ce709d21297e95b4be5030212ecd52d140899983dbd9f56fef9873",
            "9b285e797d131b12e0a583a467d11ab107610d4b81c196e6b438f274296d3657",
            "933b0789ec4350b99e64b3cb3b6d6bccaa850c54868131116a331a751ee60836",
            "b6a672e4e27b03b749c4a93801f79803ae1faf92eaab9694539c9b1361a0160b",
            "11ef055a3ba652e3231037eda669596ae0c141d79a19ec5bb255e3f719fc3309",
            "fdbf9b5a1e0573f59dd0842d2e543e9d71e4a2ce4fcc1ce36082302dcca2a263",
            "f651de490bf0ca761c0f475a2f4cf72cfa74bf1498cda30e2e12b7c25fbfd615",
            "b60e9e5b4a848a98ff3732ff961bcde2516d7b915b99299426d9631f36c34d1b",
            "d1ffb882c8508f0e4d37d03b84ece09a3311ebce7c53324a63b972e17dcf81cf",
            "69e9528ebf2333b497346eb8a786cbc1e029902a360f66d093396b1d93298105",
            "9037f282ae92ec3906fd5fd543de5f50954790b80a73a65168bde38633532895",
            "44138e82b6571ef566be87863442e5496e84dc294107aadf38608db00289d4da",
            "5c79f0a79976a2febed2381b0ff57e1fe6698947857327ff2d356fe925f736fc",
            "7131c1c5d18fe4d38ebf2654012e8f224a85e5dfd55aebd276579ee1554a3d5f",
            "4a42dc6f14a18a1aad75221992118a78aa96259ac0ba2cc686e29c02d684f7b1",
            "0429e7033b3ff53bf003e5f41514f3e22cdb2a372382f3e54cd8430474d5ff70",
            "c41e72990bd1faa690e43735707f2ed5191a367cea165c8188c2347243d9a3ce",
            "88430bcfd76c9853b392e5e99efc6c85bfff348e95e9ddba2ce2fcd5e205bbc8",
            "f3cec2f18b98eb7b266f19fcbfbf2e768205786813ab32c1877552ea7f8ed969",
            "f7ec69608f3bbd197f2095305ae237fbb92adefefcbb81427e6f16b7fc07aba4",
            "e816bfa65037eb5cf31c9f15235a5e62e28afeef93f55cfe067fac0b1f9e69a4",
            "79f6a6828171d0ac79d0a1b7b46e5bc495707ca354eee47685c0e3990d1a78f3",
            "3f3a667881b789ee7910f66d642ccb2f2988e31356845bfdaabebee2cca0f475",
            "988bea3533a79c9092e4ddd093041311fdc94dadcc7929c5418a538b940817e3",
            "f4fd2d89d61c68add788954f3eaa46e72446e709dee68a67653f54b56ff69c7f",
            "abc7407292f1b815c9f3694275e3a8bb130adafb0b48d2ad3396580c05f3e552",
            "b7d1e04824d89660c67265de02b9702c28df5364181318ce9ba6afc9813b75da",
            "e3a49032696ca9abb0369f90ecc530e3bbc36a371834a20a1250f1b96ec14052",
            "1904b558975efc5e39f122b7e2203bf750f9b704ac4f1e2136db1b52d474383e",
            "cdad3bb06fd2d2d90b508cd873dee95956d4da36d9c74b64841e7c502d0dd966",
            "4b8b16bf798bb5aec952a42b251ef33150e429ef04851f3031fe052a1e5a4996",
            "02bc91e1c3f4081ad6d1e5e1dc992616ba1c142e5b04c1f9f3f2e78f3e352b5e",
            "2ce10598215ef4ab45f4fcc38c3ae39c7bea261e742a21d10f7c67f7579f4095",
        ];
        let profiles = parse_catalogue(DATA).unwrap();
        // FD-56: an epoch 14 twin has its original's specification, so its digest: only the
        // runtime source differs.
        let twins: Vec<&str> = profiles
            .iter()
            .zip(expected)
            .filter(|(profile, _)| {
                profile.runtime_source_revision == "f2c451a6bf71ca3f3aec986e07f0852937268e2f"
            })
            .map(|(_, digest)| digest)
            .collect();
        assert_eq!(twins.len(), 60);
        let expected: Vec<&str> = expected.into_iter().chain(twins).collect();
        // Epochs 17 and 18 each append the server's own AI build as nine smart-search profiles,
        // so that build is a catalogue identity. No desktop runtime is built from those sources
        // and no desktop is offered them; they parse and build a challenge like any other
        // profile, and their digests are the server's to pin.
        const SERVER_AI_SOURCES: [&str; 2] = [
            "95593fc6887c74a705c85b0ab8c9685c79afb0e4",
            "24ea593e19ce160b2e1dd8cdafb0c15ff34240d0",
        ];
        let (desktop, rest) = profiles.split_at(expected.len());
        let (server_ai, epoch19) = rest.split_at(18);
        for (index, profile) in server_ai.iter().enumerate() {
            assert_eq!(
                profile.runtime_source_revision,
                SERVER_AI_SOURCES[index / 9]
            );
            assert_eq!(profile.workload, "clip");
            assert!(profile
                .challenge("d621bd72-ad35-4199-95ab-76300756a38e")
                .is_ok());
        }
        assert!(desktop
            .iter()
            .all(|profile| !SERVER_AI_SOURCES.contains(&profile.runtime_source_revision.as_str())));
        let challenge = |profile: &ProfileData| {
            digest(
                &profile
                    .challenge("d621bd72-ad35-4199-95ab-76300756a38e")
                    .unwrap()
                    .0,
            )
        };
        for (profile, expected) in desktop.iter().zip(&expected) {
            assert_eq!(challenge(profile), *expected);
        }
        // Epoch 19 (FD-31): the processor twins of b3905b4a under the desktop runtime source that adds
        // photo descriptions, each with its original's specification and digest, then Qwen3.5-4B's
        // description profile, whose digest is the server's (desktop-model-catalogue.spec.ts).
        const RUNTIME_SOURCE: &str = "35ba35dda671b99eb9c027e9168e185c31ebabf1";
        let originals: Vec<&str> = desktop
            .iter()
            .zip(&expected)
            .filter(|(profile, _)| {
                profile.runtime_source_revision == "b3905b4aebd22e48a1a3843c2831efcef543336e"
                    && profile.spec["provider"] == "CPUExecutionProvider"
            })
            .map(|(_, digest)| *digest)
            .collect();
        assert_eq!(epoch19.len(), originals.len() + 1);
        for (profile, original) in epoch19.iter().zip(&originals) {
            assert_eq!(profile.runtime_source_revision, RUNTIME_SOURCE);
            assert_eq!(challenge(profile), *original);
        }
        let description = epoch19.last().unwrap();
        assert_eq!(
            (
                description.workload.as_str(),
                description.model_name.as_str()
            ),
            ("description", "Qwen3.5-4B")
        );
        assert_eq!(
            challenge(description),
            "41abae7572292327a31bf47a4f9262eadd170b91646c95b7220c3e9c64b472d6"
        );
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
        // The other selectable models for the first factory runtime (server order since epoch 13).
        assert_eq!(profiles[52..62].len(), 10);
        for profile in &profiles[52..62] {
            assert_eq!(
                profile["runtimeSourceRevision"],
                "25b22c16e47a27a2eb50017d838497abce850d11"
            );
            assert_eq!(profile["spec"]["provider"], "CPUExecutionProvider");
            assert_eq!(
                profile["spec"]["preprocessingSha256"],
                profiles[0]["spec"]["preprocessingSha256"]
            );
        }
        for profile in &profiles[16..21] {
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
    fn runtime_profiles() -> Value {
        serde_json::from_str(include_str!("../../runtime/profiles.json")).unwrap()
    }
    #[test]
    fn factory_source_selects_every_released_group() {
        let runtime = runtime_profiles();
        let source = runtime["profiles"]["cpu-ort"]["sourceRevision"]
            .as_str()
            .unwrap();
        for (name, roles) in [
            ("ViT-B-16-SigLIP-384__webli", 3),
            ("ViT-B-32__openai", 3),
            ("ViT-SO400M-16-SigLIP2-384__webli", 3),
            ("PP-OCRv5_mobile", 1),
            ("PP-OCRv5_server", 1),
            ("buffalo_l", 1),
            ("antelopev2", 1),
            ("buffalo_s", 1),
            ("buffalo_m", 1),
        ] {
            assert_eq!(
                setup_profiles(name, source, "CPUExecutionProvider")
                    .unwrap()
                    .len(),
                roles,
                "{name}"
            );
        }
    }
    #[test]
    fn every_selectable_runtime_source_and_provider_has_a_catalogue_profile() {
        let runtime = runtime_profiles();
        let catalogue = parse_catalogue(DATA).unwrap();
        let mut pairs = 0;
        for (name, profile) in runtime["profiles"].as_object().unwrap() {
            let provider = profile["provider"].as_str().unwrap();
            let additional = profile["additionalSources"]
                .as_object()
                .into_iter()
                .flat_map(|targets| targets.values())
                .flat_map(|sources| sources.as_array().unwrap());
            for source in std::iter::once(&profile["sourceRevision"]).chain(additional) {
                pairs += 1;
                assert!(
                    catalogue.iter().any(|item| {
                        item.runtime_source_revision == source.as_str().unwrap()
                            && item.spec["provider"] == provider
                    }),
                    "{name} {source} {provider}"
                );
            }
        }
        assert!(pairs > 0);
    }
    #[test]
    fn a_served_profile_is_used_only_for_the_task_runtime_and_key_the_server_named() {
        let source = "f2c451a6bf71ca3f3aec986e07f0852937268e2f";
        let catalogue: Value = serde_json::from_str(DATA).unwrap();
        let served = |provider: &str| {
            catalogue["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| {
                    p["modelName"] == "buffalo_l"
                        && p["runtimeSourceRevision"] == source
                        && p["spec"]["provider"] == provider
                })
                .unwrap()
                .clone()
        };
        let cpu = served("CPUExecutionProvider");
        let keys = [cpu["modelKey"].as_str().unwrap().to_string()];
        for provider in [
            "CPUExecutionProvider",
            "CoreMLExecutionProvider",
            "CUDAExecutionProvider",
            "OpenVINOExecutionProvider",
        ] {
            let group = served_group("face", &keys, &[served(provider)], source, provider).unwrap();
            assert_eq!(group[0].provider(), provider);
        }
        let other_source = "94d52a8244da0edfa9f680a3b357fdccbc0ad7e8";
        for (workload, key, value, source, provider) in [
            (
                "face",
                &keys[0],
                cpu.clone(),
                source,
                "CUDAExecutionProvider",
            ),
            (
                "face",
                &keys[0],
                cpu.clone(),
                other_source,
                "CPUExecutionProvider",
            ),
            ("ocr", &keys[0], cpu.clone(), source, "CPUExecutionProvider"),
            (
                "face",
                &format!("face:{}", "0".repeat(64)),
                cpu.clone(),
                source,
                "CPUExecutionProvider",
            ),
        ] {
            assert!(served_group(
                workload,
                std::slice::from_ref(key),
                &[value],
                source,
                provider
            )
            .is_err());
        }
        // One missing, a changed field, or a profile that fails validation is refused too.
        assert!(served_group("face", &keys, &[], source, "CPUExecutionProvider").is_err());
        let mut changed = cpu.clone();
        changed["spec"]["fixtureSha256"] = json!("0".repeat(64));
        assert!(ApprovedProfile::from_served(&changed)
            .and_then(|p| p.challenge(&Uuid::new_v4().to_string()))
            .is_err());
        changed = cpu;
        changed["unexpected"] = json!(true);
        assert!(ApprovedProfile::from_served(&changed).is_err());
    }
    #[test]
    fn challenge_digest_does_not_depend_on_how_a_whole_number_is_written() {
        // FD-40: Desktop's copy once had 181.0 where the server has 181 in this profile.
        let source = "f93c34d196955da3e2760c095c08b27ccbf53315";
        let id = "d621bd72-ad35-4199-95ab-76300756a38e";
        let mut value: Value = serde_json::from_str(DATA).unwrap();
        let index = value["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .position(|p| p["modelName"] == "buffalo_l" && p["runtimeSourceRevision"] == source)
            .unwrap();
        let expected = parse_catalogue(DATA).unwrap()[index].challenge(id).unwrap();
        let bounds = &mut value["profiles"][index]["spec"]["expectedOutput"]["facial-recognition"]
            [0]["boundingBox"];
        for key in ["x1", "x2", "y1", "y2"] {
            assert!(bounds[key].is_u64());
            bounds[key] = json!(bounds[key].as_f64().unwrap());
        }
        let raw = value.to_string();
        assert!(raw.contains("\"x1\":181.0"));
        assert_eq!(
            parse_catalogue(&raw).unwrap()[index].challenge(id).unwrap(),
            expected
        );
    }

    #[test]
    fn fd31_a_description_profile_is_exactly_the_qwen_binding_library_serves() {
        let raw: Value =
            serde_json::from_str(include_str!("../tests/fixtures/description-profile.json"))
                .unwrap();
        let parse = |value: &Value| {
            serde_json::from_value::<ProfileData>(value.clone())
                .map_err(|_| invalid())
                .and_then(|profile| profile.validate())
        };
        parse(&raw).unwrap();
        let served = ApprovedProfile::from_served(&raw).unwrap();
        assert!(served
            .challenge("d621bd72-ad35-4199-95ab-76300756a38e")
            .is_ok());
        let changes: [fn(&mut Value); 8] = [
            |v| {
                v["spec"].as_object_mut().unwrap().remove("engine");
            },
            |v| v["spec"]["engine"] = json!("onnx"),
            |v| v["spec"]["provider"] = json!("CoreMLExecutionProvider"),
            |v| {
                v["spec"]["entries"][DESCRIPTION_TASK]["visual"]["options"] =
                    json!({"external_prompt": "other"})
            },
            |v| v["spec"]["models"][0]["task"] = json!("clip"),
            |v| v["embeddingDimensions"] = json!(512),
            |v| v["spec"]["expectedOutput"][DESCRIPTION_TASK]["tags"] = json!(["red"]),
            |v| v["spec"]["expectedOutput"][DESCRIPTION_TASK]["description"] = json!(""),
        ];
        for change in changes {
            let mut value = raw.clone();
            change(&mut value);
            assert!(parse(&value).is_err(), "{value}");
        }
        // An ONNX profile never names the Qwen engine.
        let mut ocr: Value =
            serde_json::from_str(include_str!("../tests/fixtures/ocr-profile.json")).unwrap();
        ocr["spec"]["engine"] = json!("qwen-gguf");
        assert!(parse(&ocr).is_err());
    }
}
