//! One bounded approved-folder copy, with immutable inventory and a small signed progress checkpoint.
pub(crate) mod history;
mod watch;

use crate::{
    connection::{DeviceIdentity, SavedConnection},
    copy_source::StagedCopy,
    copy_upload::UploadSession,
    import_album::{self, Destination},
    photo_sources::SourceFile,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    id: String,
    source_id: String,
    scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination: Option<Destination>,
    files: Vec<SourceFile>,
    total_bytes: u64,
    skipped: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    availability: Option<crate::source_metadata::AvailabilitySummary>,
    /// Why files counted in `skipped` were left out, where the reason is known.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    skipped_reasons: BTreeMap<String, u64>,
    /// The folder held more files than one batch; the next batch follows this run.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    more: bool,
    /// The digest of the completed batch this manifest follows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    continues: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Active {
    stage_id: String,
    item_id: String,
    copy: Option<StagedCopy>,
    upload: Option<UploadSession>,
    receipt: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    album_attached: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadBudget {
    used: u64,
    limit: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Cursor {
    manifest_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upload_budget: Option<UploadBudget>,
    position: usize,
    active: Option<Active>,
    /// Files left out of this run because they changed or went away before they were staged.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    watch_skipped: BTreeSet<usize>,
    /// The reason code for each skipped file, counted. Never a filename.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    skipped_reasons: BTreeMap<String, u64>,
    /// A later scan found no further batch after this completed one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    exhausted: bool,
    state: String,
}
/// Automatic allowance renewals stop here; beyond it the person approves more upload data.
const AUTOMATIC_ALLOWANCE_FACTOR: u64 = 4;
impl UploadBudget {
    /// Charges `bytes`. An exhausted allowance is renewed for the files still to copy, as an
    /// explicit approval would, until the run has been granted `ceiling` bytes in total.
    fn admit(&mut self, bytes: u64, renewal: u64, ceiling: u64) -> Result<(), String> {
        let used = match crate::upload_budget::reserve(self.used, bytes, self.limit) {
            Err(code) if self.limit < ceiling => {
                let limit = self.limit.saturating_add(renewal).min(ceiling);
                let used =
                    crate::upload_budget::reserve(self.used, bytes, limit).map_err(|_| code)?;
                self.limit = limit;
                used
            }
            other => other?,
        };
        self.used = used;
        Ok(())
    }
}
fn digest(value: &impl Serialize) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(
            serde_json_canonicalizer::to_vec(value).map_err(|_| "source_journal_invalid")?
        )
    ))
}
fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}
impl Cursor {
    fn new(manifest: &Manifest) -> Result<Self, String> {
        Ok(Self {
            manifest_hash: digest(manifest)?,
            upload_budget: Some(UploadBudget {
                used: 0,
                limit: manifest
                    .total_bytes
                    .checked_mul(2)
                    .ok_or("source_copy_budget_exceeded")?,
            }),
            position: 0,
            active: None,
            watch_skipped: BTreeSet::new(),
            skipped_reasons: BTreeMap::new(),
            exhausted: false,
            state: "ready".into(),
        })
    }
    fn approve_upload(&mut self, manifest: &Manifest) -> Result<(), String> {
        if matches!(self.state.as_str(), "complete" | "cancelled") {
            return Err("source_run_terminal".into());
        }
        let additional = view(manifest, self, "paused", None).additional_upload_allowance;
        let used = self.upload_budget.as_ref().map_or(0, |budget| budget.used);
        let limit = self
            .upload_budget
            .as_ref()
            .map_or(0, |budget| budget.limit)
            .checked_add(additional)
            .ok_or("source_upload_budget_exhausted")?;
        self.upload_budget = Some(UploadBudget { used, limit });
        self.state = "paused".into();
        Ok(())
    }
    fn validate(&self, manifest: &Manifest) -> Result<(), String> {
        if self
            .upload_budget
            .as_ref()
            .is_some_and(|budget| budget.used > budget.limit)
            || self.manifest_hash != digest(manifest)?
            || self.position > manifest.files.len()
            || self
                .watch_skipped
                .iter()
                .any(|&index| index >= self.position)
            || self.skipped_reasons.values().sum::<u64>() > self.watch_skipped.len() as u64
            || (self.exhausted && self.state != "complete")
            || !matches!(
                self.state.as_str(),
                "ready" | "open" | "paused" | "cancelled" | "complete"
            )
            || (self.active.is_some() && self.position >= manifest.files.len())
            || self.active.as_ref().is_some_and(|a| {
                !uuid(&a.stage_id)
                    || !uuid(&a.item_id)
                    || (a.album_attached && (manifest.destination.is_none() || a.receipt.is_none()))
            })
            || (self.state == "complete"
                && (self.position != manifest.files.len() || self.active.is_some()))
        {
            return Err("source_journal_invalid".into());
        }
        Ok(())
    }
}
const CAMERA_LOCATION: &str = "camera-location.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CameraLocation {
    manifest_hash: String,
    path: PathBuf,
}

struct Journal {
    root: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed<T> {
    value: T,
    signature: String,
}
impl Journal {
    fn new(base: &Path, source: &str) -> Result<Self, String> {
        if !uuid(source) {
            return Err("source_journal_invalid".into());
        }
        crate::runtime_store::private_directory(&base.join("photo-imports"))?;
        let root = base.join("photo-imports").join(source);
        crate::runtime_store::private_directory(&root)?;
        crate::runtime_store::private_directory(&root.join("stage"))?;
        Ok(Self { root })
    }
    fn signature(
        name: &str,
        value: &impl Serialize,
        identity: &DeviceIdentity,
    ) -> Result<String, String> {
        Ok(identity.sign(&format!(
            "frameleaf-desktop/source-run/v1\n{name}\n{}",
            digest(value)?
        )))
    }
    fn write(
        &self,
        name: &str,
        value: &impl Serialize,
        identity: &DeviceIdentity,
    ) -> Result<(), String> {
        let record = Signed {
            value,
            signature: Self::signature(name, value, identity)?,
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| "source_journal_invalid")?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("source_journal_too_large".into());
        }
        crate::native_runtime::absolute_directory(&self.root)?;
        let temporary = self
            .root
            .join(format!(".checkpoint-{}", uuid::Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            let mut file = options
                .open(&temporary)
                .map_err(|_| "source_journal_write_failed")?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "source_journal_write_failed")?;
            fs::rename(&temporary, self.root.join(name))
                .map_err(|_| "source_journal_write_failed")?;
            #[cfg(unix)]
            std::fs::File::open(&self.root)
                .and_then(|file| file.sync_all())
                .map_err(|_| "source_journal_write_failed")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
    fn read<T: DeserializeOwned + Serialize>(
        &self,
        name: &str,
        identity: &DeviceIdentity,
    ) -> Result<T, String> {
        crate::native_runtime::absolute_directory(&self.root)?;
        let bytes = crate::runtime_store::read_bounded(&self.root.join(name), 4 * 1024 * 1024)?;
        let record: Signed<T> =
            serde_json::from_slice(&bytes).map_err(|_| "source_journal_invalid")?;
        if record.signature != Self::signature(name, &record.value, identity)? {
            return Err("source_journal_invalid".into());
        }
        Ok(record.value)
    }
}

use crate::{
    copy_upload::{self, FolderUploadBinding, UploadOutcome},
    credentials,
    source_consent::{Consent, CREDENTIAL},
    transport,
};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tauri::{Emitter, Manager};
#[derive(Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImportView {
    pub state: String,
    pub source_id: String,
    pub total: usize,
    pub completed: usize,
    pub logical_bytes: u64,
    pub upload_remaining: Option<u64>,
    pub additional_upload_allowance: u64,
    pub skipped: u64,
    pub code: Option<String>,
    pub album_pending: bool,
    pub availability: Option<crate::source_metadata::AvailabilitySummary>,
}
/// The allowance one approval adds: twice the bytes of the files still to copy.
fn remaining_allowance(manifest: &Manifest, cursor: &Cursor) -> u64 {
    manifest.files[cursor.position..]
        .iter()
        .map(|file| file.bytes)
        .sum::<u64>()
        .saturating_mul(2)
}
fn view(manifest: &Manifest, cursor: &Cursor, state: &str, code: Option<String>) -> ImportView {
    ImportView {
        state: state.into(),
        source_id: manifest.source_id.clone(),
        total: manifest.files.len(),
        completed: cursor.position - cursor.watch_skipped.len(),
        logical_bytes: manifest.total_bytes,
        upload_remaining: cursor
            .upload_budget
            .as_ref()
            .map(|budget| budget.limit - budget.used),
        additional_upload_allowance: remaining_allowance(manifest, cursor),
        skipped: manifest.skipped + cursor.watch_skipped.len() as u64,
        album_pending: manifest.destination.is_some()
            && cursor
                .active
                .as_ref()
                .is_some_and(|active| active.receipt.is_some() && !active.album_attached),
        availability: manifest.availability.clone(),
        code,
    }
}
/// Another batch of the same folder follows this completed one.
fn continues(manifest: &Manifest, cursor: &Cursor) -> bool {
    cursor.state == "complete" && manifest.more && !cursor.exhausted
}
/// The state a stored run is shown in while no job is working on it.
fn resting<'a>(manifest: &Manifest, cursor: &'a Cursor) -> &'a str {
    if cursor.state == "open" || continues(manifest, cursor) {
        "paused"
    } else {
        &cursor.state
    }
}
fn skipped_reasons(manifest: &Manifest, cursor: &Cursor) -> BTreeMap<String, u64> {
    let mut reasons = manifest.skipped_reasons.clone();
    for (reason, count) in &cursor.skipped_reasons {
        *reasons.entry(reason.clone()).or_default() += count;
    }
    reasons
}
fn current(
    credential: &'static str,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    source: &str,
) -> Result<Consent, String> {
    let consent = credentials::load::<Consent>(credential)?.ok_or("source_approval_required")?;
    consent.approval(saved, identity)?;
    if consent.source_id() != source {
        return Err("source_approval_changed".into());
    }
    Ok(consent)
}
fn manifest_for(
    consent: &Consent,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    base: &Path,
) -> Result<Manifest, String> {
    let approval = consent.approval(saved, identity)?;
    batch_manifest(consent, saved, identity, base, approval.root(), None)?
        .ok_or("source_no_media".into())
}
/// One batch of the approved folder: the first, or the one after `previous`. `None` when a later
/// batch has nothing left to copy.
fn batch_manifest(
    consent: &Consent,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    base: &Path,
    root: &Path,
    previous: Option<&Manifest>,
) -> Result<Option<Manifest>, String> {
    use crate::photo_sources::Pin;
    let approval = consent.approval(saved, identity)?;
    if base.starts_with(root) || root.starts_with(base) {
        return Err("source_staging_overlap".into());
    }
    let pin = if let Some(media) = approval.media() {
        Pin::Camera(media)
    } else if previous.is_some_and(|run| run.files.iter().any(|file| file.watch_version.is_some()))
    {
        // A dropped folder stays bound to the folder that was previewed.
        Pin::Dropped(approval.root_identity())
    } else {
        Pin::Unpinned
    };
    let after = previous
        .and_then(|run| run.files.last())
        .map(|file| file.relative.as_str());
    let scan = crate::photo_sources::scan_batch(root, pin, after)?;
    if scan.inventory.truncated {
        return Err("source_inventory_partial".into());
    }
    if scan.unreadable > 0 {
        return Err("source_inventory_unreadable".into());
    }
    if previous.is_some() && scan.files.is_empty() {
        return Ok(None);
    }
    let mut manifest = make_manifest(consent, approval, scan, previous)?;
    approval.bind_camera_fingerprints(root, &mut manifest.files)?;
    Ok(Some(manifest))
}
fn make_manifest(
    consent: &Consent,
    approval: &crate::copy_source::CopyApproval,
    scan: crate::photo_sources::FolderScan,
    previous: Option<&Manifest>,
) -> Result<Manifest, String> {
    if scan.files.is_empty() {
        return Err("source_no_media".into());
    }
    let mut total_bytes = 0u64;
    for file in &scan.files {
        // FL-1268: no per-file ceiling; the server's free-space limit and the run budget still apply.
        // The scan leaves empty files out and counts them as skipped.
        if file.bytes == 0 {
            return Err("source_item_invalid".into());
        }
        total_bytes = total_bytes
            .checked_add(file.bytes)
            .filter(|n| *n <= (1u64 << 41))
            .ok_or("source_copy_budget_exceeded")?;
    }
    Ok(Manifest {
        id: uuid::Uuid::new_v4().to_string(),
        source_id: consent.source_id().into(),
        scope: approval.fingerprint(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|value| u64::try_from(value.as_millis()).ok()),
        destination: consent.destination.clone(),
        files: scan.files,
        total_bytes,
        // The folder-wide skips are reported once, with the first batch.
        skipped: if previous.is_none() {
            scan.inventory.skipped
        } else {
            0
        },
        availability: Some(scan.inventory.availability),
        skipped_reasons: if previous.is_none() && scan.inventory.empty > 0 {
            BTreeMap::from([("source_item_empty".to_string(), scan.inventory.empty)])
        } else {
            BTreeMap::new()
        },
        more: scan.more,
        continues: previous.map(digest).transpose()?,
    })
}
fn load_manifest(
    journal: &Journal,
    identity: &DeviceIdentity,
    consent: &Consent,
    saved: &SavedConnection,
) -> Result<Manifest, String> {
    let manifest: Manifest = journal.read("manifest.json", identity)?;
    if !uuid(&manifest.id)
        || manifest.source_id != consent.source_id()
        || manifest.scope != consent.approval(saved, identity)?.fingerprint()
        || manifest.destination != consent.destination
    {
        return Err("source_journal_invalid".into());
    }
    Ok(manifest)
}
fn load(
    journal: &Journal,
    identity: &DeviceIdentity,
    consent: &Consent,
    saved: &SavedConnection,
) -> Result<(Manifest, Cursor), String> {
    let manifest = load_manifest(journal, identity, consent, saved)?;
    let cursor: Cursor = match fs::symlink_metadata(journal.root.join("cursor.json")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Empty staging cannot prove that no earlier uploads occurred; recovery needs a new allowance.
            if fs::read_dir(journal.root.join("stage"))
                .map_err(|_| "source_journal_invalid")?
                .next()
                .is_some()
            {
                return Err("source_journal_invalid".into());
            }
            let mut cursor = Cursor::new(&manifest)?;
            cursor.upload_budget = None;
            journal.write("cursor.json", &cursor, identity)?;
            cursor
        }
        _ => journal.read("cursor.json", identity)?,
    };
    // The next batch's manifest is written before its cursor. A stop between the two leaves the
    // completed cursor of the batch this manifest names; nothing of the new batch was sent yet.
    let cursor = if manifest.continues.as_deref() == Some(cursor.manifest_hash.as_str())
        && cursor.state == "complete"
        && cursor.active.is_none()
    {
        let cursor = Cursor::new(&manifest)?;
        journal.write("cursor.json", &cursor, identity)?;
        cursor
    } else {
        cursor
    };
    cursor.validate(&manifest)?;
    Ok((manifest, cursor))
}
fn camera_location(
    journal: &Journal,
    manifest: &Manifest,
    identity: &DeviceIdentity,
    approval: &crate::copy_source::CopyApproval,
) -> Result<Option<PathBuf>, String> {
    match fs::symlink_metadata(journal.root.join(CAMERA_LOCATION)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => {}
    }
    let location: CameraLocation = journal.read(CAMERA_LOCATION, identity)?;
    // A reconnected camera stays reconnected for the batch that directly follows.
    if approval.media().is_none()
        || (location.manifest_hash != digest(manifest)?
            && manifest.continues.as_deref() != Some(location.manifest_hash.as_str()))
        || !location.path.is_absolute()
    {
        return Err("source_journal_invalid".into());
    }
    Ok(Some(location.path))
}

fn reconnect_camera_at(
    journal: &Journal,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    consent: &Consent,
    root: PathBuf,
) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let _no_materialization = crate::photo_sources::metadata_only::Guard::new()?;
    let approval = consent.approval(saved, identity)?;
    if !consent.camera() || approval.media().is_none() {
        return Err("source_camera_identity_unavailable".into());
    }
    let (manifest, cursor) = load(journal, identity, consent, saved)?;
    if matches!(cursor.state.as_str(), "complete" | "cancelled") && !continues(&manifest, &cursor) {
        return Err("source_run_terminal".into());
    }
    if root.starts_with(&journal.root) || journal.root.starts_with(&root) {
        return Err("source_staging_overlap".into());
    }
    let directory = approval.open_source(&root)?;
    let mounted = crate::copy_source::root_identity(&directory)?;
    let (volume, _) = mounted
        .split_once(':')
        .ok_or("source_camera_identity_unavailable")?;
    // Verified originals and any verified receipt awaiting its album already have durable proof.
    let first = cursor.position
        + usize::from(
            cursor
                .active
                .as_ref()
                .is_some_and(|active| active.receipt.is_some()),
        );
    for entry in &manifest.files[first..] {
        approval.require_camera_file(&directory, volume, entry)?;
    }
    journal.write(
        CAMERA_LOCATION,
        &CameraLocation {
            manifest_hash: digest(&manifest)?,
            path: root,
        },
        identity,
    )
}

struct SourceApi<'a> {
    client: &'a Client,
    base: &'a url::Url,
    saved: &'a SavedConnection,
    source: &'a str,
    cancel: &'a AtomicBool,
    gate: &'a (dyn Fn() -> Result<(), String> + Sync),
}
fn source_request_timeout(path: &str) -> std::time::Duration {
    std::time::Duration::from_secs(if path.ends_with("/verify") { 610 } else { 30 })
}
impl SourceApi<'_> {
    async fn call(&self, method: Method, path: &str, body: Value) -> Result<Value, String> {
        (self.gate)()?;
        let request = self
            .client
            .request(
                method,
                self.base
                    .join(&format!("api/photo-sources/{}/{path}", self.source))
                    .map_err(|_| "source_journal_invalid")?,
            )
            .bearer_auth(&self.saved.token)
            .timeout(source_request_timeout(path))
            .json(&body);
        transport::json(copy_upload::send(request, self.cancel).await?).await
    }
    async fn run(&self, m: &Manifest) -> Result<Value, String> {
        let value = self
            .call(
                Method::POST,
                "runs",
                json!({"id":m.id,"maxItems":m.files.len(),"maxBytes":m.total_bytes}),
            )
            .await?;
        if value["id"] != m.id
            || value["sourceId"] != m.source_id
            || value["maxItems"] != m.files.len()
            || value["maxBytes"] != m.total_bytes
            || !matches!(
                value["state"].as_str(),
                Some("open" | "paused" | "complete" | "cancelled")
            )
        {
            return Err("source_run_changed".into());
        }
        Ok(value)
    }
    async fn state(&self, m: &Manifest, state: &str) -> Result<(), String> {
        let value = self
            .call(
                Method::PATCH,
                &format!("runs/{}", m.id),
                json!({"state":state,"inventoryComplete":state=="complete"}),
            )
            .await?;
        if value["id"] != m.id || value["sourceId"] != m.source_id || value["state"] != state {
            return Err("source_run_changed".into());
        }
        Ok(())
    }
    async fn plan(&self, m: &Manifest, active: &Active, copy: &StagedCopy) -> Result<bool, String> {
        let request = json!({"id":active.item_id,"resourceKey":copy.resource_key(),"version":copy.version(),"sha256":copy.sha256,"bytes":copy.bytes});
        let value = self
            .call(
                Method::POST,
                &format!("runs/{}/items", m.id),
                request.clone(),
            )
            .await?;
        if request
            .as_object()
            .unwrap()
            .iter()
            .any(|(key, v)| value.get(key) != Some(v))
            || value["runId"] != m.id
            || !matches!(value["state"].as_str(), Some("planned" | "verified"))
        {
            return Err("source_item_changed".into());
        }
        Ok(value["state"] == "verified")
    }
}
fn check_receipt(
    value: &Value,
    saved: &SavedConnection,
    m: &Manifest,
    active: &Active,
    copy: &StagedCopy,
    asset: Option<&str>,
) -> Result<(), String> {
    let upload = active.upload.as_ref().ok_or("source_receipt_invalid")?;
    let expected = json!({"serverId":saved.server_id,"ownerId":saved.account_id,"sourceId":m.source_id,"runId":m.id,"itemId":active.item_id,"uploadResourceId":upload.resource_id(),"sha256":copy.sha256,"bytes":copy.bytes,"storage":"managed"});
    if expected
        .as_object()
        .unwrap()
        .iter()
        .any(|(k, v)| value.get(k) != Some(v))
        || !value["assetId"].as_str().is_some_and(uuid)
        || asset.is_some_and(|id| value["assetId"] != id)
        || value["verifiedAt"].as_str().is_none_or(|date| {
            time::OffsetDateTime::parse(date, &time::format_description::well_known::Rfc3339)
                .is_err()
        })
    {
        return Err("source_receipt_invalid".into());
    }
    Ok(())
}
async fn attach_verified(
    api: &SourceApi<'_>,
    manifest: &Manifest,
    cursor: &mut Cursor,
    copy: &StagedCopy,
    journal: &Journal,
    identity: &DeviceIdentity,
) -> Result<(), String> {
    let Some(destination) = manifest.destination.as_ref() else {
        return Ok(());
    };
    let active = cursor.active.as_ref().ok_or("source_journal_invalid")?;
    let Some(receipt) = active.receipt.as_ref().filter(|_| !active.album_attached) else {
        return Ok(());
    };
    check_receipt(receipt, api.saved, manifest, active, copy, None)?;
    let asset = receipt["assetId"]
        .as_str()
        .ok_or("source_receipt_invalid")?;
    (api.gate)()?;
    import_album::attach(
        api.client,
        api.base,
        api.saved,
        destination,
        asset,
        api.cancel,
    )
    .await?;
    cursor.active.as_mut().unwrap().album_attached = true;
    journal.write("cursor.json", cursor, identity)
}

#[allow(clippy::too_many_arguments)]
async fn execute(
    client: &Client,
    base: &url::Url,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    consent: &Consent,
    journal: &Journal,
    cancel: &AtomicBool,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
    notify: &(dyn Fn(ImportView) + Sync),
) -> Result<(), String> {
    let (manifest, mut cursor) = load(journal, identity, consent, saved)?;
    let approval = consent.approval(saved, identity)?;
    let reconnected = if approval.media().is_some() {
        camera_location(journal, &manifest, identity, approval)?
    } else {
        None
    };
    if matches!(cursor.state.as_str(), "cancelled" | "complete") {
        return Err("source_run_terminal".into());
    }
    let api = SourceApi {
        client,
        base,
        saved,
        source: &manifest.source_id,
        cancel,
        gate,
    };
    let result: Result<(), String> = async {
        gate()?;
        let caps: crate::connection::Capabilities = transport::json(
            copy_upload::send(
                client
                    .get(base.join("api/desktop/capabilities").unwrap())
                    .bearer_auth(&saved.token),
                cancel,
            )
            .await?,
        )
        .await?;
        if caps.protocol_version != 1 || caps.server_id != saved.server_id {
            return Err("server_identity_changed".into());
        }
        if let Some(destination) = &manifest.destination {
            gate()?;
            import_album::require_writable(client, base, saved, destination, cancel).await?;
        }
        let state = api.run(&manifest).await?;
        if state["state"] == "cancelled" {
            cursor.state = "cancelled".into();
            journal.write("cursor.json", &cursor, identity)?;
            // A cancelled run never resumes, so its staged copies are no longer needed.
            crate::copy_source::release_stages(&journal.root.join("stage"));
            notify(view(&manifest, &cursor, "cancelled", None));
            return Ok(());
        }
        if state["state"] == "complete" {
            if cursor.position != manifest.files.len() || cursor.active.is_some() {
                return Err("source_receipt_invalid".into());
            }
            cursor.state = "complete".into();
            journal.write("cursor.json", &cursor, identity)?;
            crate::copy_source::release_stages(&journal.root.join("stage"));
            if !manifest.more {
                notify(view(&manifest, &cursor, "complete", None));
            }
            return Ok(());
        }
        api.state(&manifest, "open").await?;
        cursor.state = "open".into();
        journal.write("cursor.json", &cursor, identity)?;
        while cursor.position < manifest.files.len() {
            gate()?;
            if cancel.load(Ordering::Acquire) {
                return Err("source_copy_cancelled".into());
            }
            if cursor
                .active
                .as_ref()
                .is_none_or(|active| active.copy.is_none())
            {
                let current = api.run(&manifest).await?;
                if current["state"] != "open" {
                    return Err("source_run_paused".into());
                }
            }
            let entry = &manifest.files[cursor.position];
            if cursor.active.is_none() {
                cursor.active = Some(Active {
                    stage_id: uuid::Uuid::new_v4().to_string(),
                    item_id: uuid::Uuid::new_v4().to_string(),
                    copy: None,
                    upload: None,
                    receipt: None,
                    album_attached: false,
                });
                journal.write("cursor.json", &cursor, identity)?;
            }
            if cursor.active.as_ref().unwrap().copy.is_none() {
                let id = &cursor.active.as_ref().unwrap().stage_id;
                let stage = journal.root.join("stage");
                let copy = if stage.join(id).join("receipt.json").exists() {
                    StagedCopy::restore(saved, identity, &stage, id)?
                } else {
                    // The signed intent owns this attempt; never remove an existing signed receipt as an incomplete copy.
                    crate::copy_source::release_stage(&stage, id)?;
                    let staged = consent.approval(saved, identity)?.stage_to(
                        saved,
                        identity,
                        &entry.relative,
                        &stage,
                        id,
                        Some(entry.bytes),
                        entry.watch_version.as_deref(),
                        reconnected.as_deref(),
                        cancel,
                        gate,
                    );
                    match staged {
                        Err(code)
                            if matches!(
                                code.as_str(),
                                "source_item_changed"
                                    | "source_item_unavailable"
                                    | "source_item_excluded"
                                    | "source_item_invalid"
                            ) =>
                        {
                            // No item was planned or uploaded, and the original is untouched. The
                            // rest of the run continues; a watched folder reconsiders this path on
                            // a later scan, and any other import records why it was left out.
                            cursor.watch_skipped.insert(cursor.position);
                            *cursor.skipped_reasons.entry(code).or_default() += 1;
                            cursor.position += 1;
                            cursor.active = None;
                            journal.write("cursor.json", &cursor, identity)?;
                            continue;
                        }
                        other => other?,
                    }
                };
                if !copy.matches_entry(&entry.relative, entry.bytes)
                    || entry
                        .watch_version
                        .as_ref()
                        .is_some_and(|version| version != &copy.version())
                    || copy.source_id() != manifest.source_id
                {
                    return Err("source_item_changed".into());
                }
                cursor.active.as_mut().unwrap().copy = Some(copy);
                journal.write("cursor.json", &cursor, identity)?;
            }
            let copy = cursor
                .active
                .as_ref()
                .unwrap()
                .copy
                .as_ref()
                .unwrap()
                .clone();
            if !copy.matches_entry(&entry.relative, entry.bytes)
                || entry
                    .watch_version
                    .as_ref()
                    .is_some_and(|version| version != &copy.version())
                || copy.source_id() != manifest.source_id
            {
                return Err("source_item_changed".into());
            }
            // Resume album work from the signed verification receipt without entering upload.
            attach_verified(&api, &manifest, &mut cursor, &copy, journal, identity).await?;
            let mut asset = cursor
                .active
                .as_ref()
                .unwrap()
                .receipt
                .as_ref()
                .and_then(|receipt| receipt["assetId"].as_str())
                .map(String::from);
            if cursor.active.as_ref().unwrap().receipt.is_none() {
                let verified = api
                    .plan(&manifest, cursor.active.as_ref().unwrap(), &copy)
                    .await?;
                if !verified {
                    let binding = FolderUploadBinding::new(
                        &copy,
                        &manifest.id,
                        &cursor.active.as_ref().unwrap().item_id,
                    )?;
                    let mut upload = cursor.active.as_ref().unwrap().upload.clone();
                    let (mut renewed, mut waits) = (false, 0);
                    let asset_id = loop {
                        let outcome = copy_upload::transfer(
                            client,
                            base,
                            saved,
                            identity,
                            &copy,
                            &binding,
                            &journal.root.join("stage"),
                            &mut upload,
                            |session, bytes| {
                                let renewal = remaining_allowance(&manifest, &cursor);
                                cursor
                                    .upload_budget
                                    .as_mut()
                                    .ok_or("source_upload_budget_required")?
                                    .admit(
                                        bytes,
                                        renewal,
                                        manifest
                                            .total_bytes
                                            .saturating_mul(AUTOMATIC_ALLOWANCE_FACTOR),
                                    )?;
                                cursor.active.as_mut().unwrap().upload = Some(session.clone());
                                journal.write("cursor.json", &cursor, identity)?;
                                notify(view(&manifest, &cursor, "copying", None));
                                Ok(())
                            },
                            cancel,
                            gate,
                        )
                        .await;
                        match outcome {
                            Ok(UploadOutcome::Ingested { asset_id, .. }) => break asset_id,
                            // The server is still processing the bytes it has; ask again shortly.
                            Ok(UploadOutcome::Pending) if waits < PROCESSING_WAITS => {
                                waits += 1;
                                wait(PROCESSING_WAIT * waits.min(6), cancel).await?;
                            }
                            Ok(UploadOutcome::Pending) => {
                                return Err("source_server_processing".into())
                            }
                            // The server no longer has the saved upload session (it expired or
                            // was removed). Forget it and send this original in one new session;
                            // the server still verifies the hash before anything is recorded.
                            Err(code)
                                if !renewed
                                    && upload.is_some()
                                    && matches!(
                                        code.as_str(),
                                        "source_upload_http_404" | "source_upload_http_410"
                                    ) =>
                            {
                                renewed = true;
                                upload = None;
                                cursor.active.as_mut().unwrap().upload = None;
                                journal.write("cursor.json", &cursor, identity)?;
                            }
                            Err(code) => return Err(code),
                        }
                    };
                    cursor.active.as_mut().unwrap().upload = upload;
                    asset = Some(asset_id);
                }
            }
            // A stored receipt is evidence of an earlier acknowledgement, not current NAS file health.
            let active = cursor.active.as_ref().unwrap();
            let upload = active.upload.as_ref().ok_or("source_receipt_invalid")?;
            let receipt = api
                .call(
                    Method::POST,
                    &format!("runs/{}/items/{}/verify", manifest.id, active.item_id),
                    json!({"uploadResourceId":upload.resource_id()}),
                )
                .await?;
            check_receipt(&receipt, saved, &manifest, active, &copy, asset.as_deref())?;
            cursor.active.as_mut().unwrap().receipt = Some(receipt);
            journal.write("cursor.json", &cursor, identity)?;
            attach_verified(&api, &manifest, &mut cursor, &copy, journal, identity).await?;
            let active = cursor.active.as_ref().unwrap();
            check_receipt(
                active.receipt.as_ref().unwrap(),
                saved,
                &manifest,
                active,
                &copy,
                None,
            )?;
            gate()?;
            copy.release(saved, identity, &journal.root.join("stage"))?;
            cursor.position += 1;
            cursor.active = None;
            journal.write("cursor.json", &cursor, identity)?;
            notify(view(&manifest, &cursor, "copying", None));
        }
        api.state(&manifest, "complete").await?;
        cursor.state = "complete".into();
        journal.write("cursor.json", &cursor, identity)?;
        // Every original of this run is verified or skipped; nothing staged is still needed.
        crate::copy_source::release_stages(&journal.root.join("stage"));
        // The next batch of a large folder follows without announcing a finished import.
        if !manifest.more {
            notify(view(&manifest, &cursor, "complete", None));
        }
        Ok(())
    }
    .await;
    if let Err(error) = &result {
        if cursor.state != "complete" {
            cursor.state = "paused".into();
            journal.write("cursor.json", &cursor, identity)?;
        }
        notify(view(
            &manifest,
            &cursor,
            if error == "source_copy_cancelled" {
                "paused"
            } else {
                "needs-attention"
            },
            Some(error.clone()),
        ));
    }
    result
}
/// How long a file the server is still processing is waited for before the run reports it.
const PROCESSING_WAIT: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_millis(5)
} else {
    std::time::Duration::from_secs(10)
};
const PROCESSING_WAITS: u32 = 12;
async fn wait(delay: std::time::Duration, cancel: &AtomicBool) -> Result<(), String> {
    let until = tokio::time::Instant::now() + delay;
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err("source_copy_cancelled".into());
        }
        let left = until.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Ok(());
        }
        tokio::time::sleep(left.min(std::time::Duration::from_millis(100))).await;
    }
}

/// Runs the stored batch and then each following batch of the same approved folder, so a folder
/// larger than one manifest is copied to its end without holding its whole file list.
#[allow(clippy::too_many_arguments)]
async fn execute_all(
    client: &Client,
    origin: &url::Url,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    consent: &Consent,
    journal: &Journal,
    base: &Path,
    kind: history::Kind,
    cancel: &AtomicBool,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
    notify: &(dyn Fn(ImportView) + Sync),
) -> Result<(), String> {
    loop {
        let (manifest, mut cursor) = load(journal, identity, consent, saved)?;
        if !continues(&manifest, &cursor) {
            execute(
                client, origin, saved, identity, consent, journal, cancel, gate, notify,
            )
            .await?;
            let (manifest, cursor) = load(journal, identity, consent, saved)?;
            if !continues(&manifest, &cursor) {
                return Ok(());
            }
            continue;
        }
        gate()?;
        history::completed(base, saved, identity, kind, &manifest, &cursor);
        let approval = consent.approval(saved, identity)?;
        let location = if approval.media().is_some() {
            camera_location(journal, &manifest, identity, approval)?
        } else {
            None
        };
        let root = location.as_deref().unwrap_or(approval.root());
        // This job already runs on a blocking thread; the scan holds no application lock.
        match batch_manifest(consent, saved, identity, base, root, Some(&manifest))? {
            Some(next) => {
                let first = Cursor::new(&next)?;
                journal.write("manifest.json", &next, identity)?;
                journal.write("cursor.json", &first, identity)?;
                if let Some(path) = location {
                    journal.write(
                        CAMERA_LOCATION,
                        &CameraLocation {
                            manifest_hash: digest(&next)?,
                            path,
                        },
                        identity,
                    )?;
                }
                notify(view(&next, &first, "copying", None));
            }
            None => {
                cursor.exhausted = true;
                journal.write("cursor.json", &cursor, identity)?;
                notify(view(&manifest, &cursor, "complete", None));
                return Ok(());
            }
        }
    }
}
struct Running {
    cancel: Arc<AtomicBool>,
    task: tauri::async_runtime::JoinHandle<()>,
    wake: Arc<tokio::sync::Notify>,
}
#[derive(Default)]
pub(crate) struct ImportTransfer(tokio::sync::Mutex<()>);
impl ImportTransfer {
    async fn acquire(
        &self,
        cancelled: &AtomicBool,
        wake: &tokio::sync::Notify,
    ) -> Result<tokio::sync::MutexGuard<'_, ()>, String> {
        tokio::select! {
            biased;
            _ = wake.notified() => Err("source_copy_cancelled".into()),
            guard = self.0.lock() => {
                if cancelled.load(Ordering::Acquire) {
                    Err("source_copy_cancelled".into())
                } else {
                    Ok(guard)
                }
            }
        }
    }
}

/// Imports pause only on a connection the platform reports as metered. A platform that cannot
/// classify the connection (Linux without NetworkManager, for one) does not block every import.
fn network_admission(unmetered: Option<bool>) -> Result<(), String> {
    match unmetered {
        Some(false) => Err("metered_network".into()),
        Some(true) | None => Ok(()),
    }
}

/// Staged copies of sources whose approval is gone can never be used again. This removes only
/// the app's staged copies under its own data folder; journals and every source file are kept.
fn sweep_abandoned(base: &Path, current: &[String]) {
    let Ok(entries) = fs::read_dir(base.join("photo-imports")) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(source) = name.to_str().filter(|name| uuid(name)) else {
            continue;
        };
        if current.iter().any(|id| id == source) {
            continue;
        }
        let root = entry.path();
        crate::copy_source::release_stages(&root.join("stage"));
        crate::copy_source::release_stages(&root.join("watch-batch").join("stage"));
    }
}
fn sweep_abandoned_sources(base: &Path) {
    let mut current = Vec::new();
    for credential in [CREDENTIAL, crate::drop_import::CREDENTIAL] {
        match credentials::load::<Consent>(credential) {
            Ok(Some(consent)) => current.push(consent.source_id().to_string()),
            Ok(None) => {}
            // Without a certain answer about every approval, nothing is removed.
            Err(_) => return,
        }
    }
    sweep_abandoned(base, &current);
}

pub(crate) struct SourceJobs {
    credential: &'static str,
    running: tokio::sync::Mutex<Option<Running>>,
    status: Arc<Mutex<ImportView>>,
    watching: Arc<AtomicBool>,
}
impl Default for SourceJobs {
    fn default() -> Self {
        Self::with_credential(CREDENTIAL)
    }
}
impl SourceJobs {
    pub(crate) fn with_credential(credential: &'static str) -> Self {
        Self {
            credential,
            running: Default::default(),
            status: Default::default(),
            watching: Default::default(),
        }
    }

    pub(crate) fn prepare_drop(
        &self,
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        consent: &Consent,
        scan: crate::photo_sources::FolderScan,
    ) -> Result<(), String> {
        let approval = consent.approved_scope(saved, identity)?;
        if base.starts_with(approval.root()) || approval.root().starts_with(base) {
            return Err("source_staging_overlap".into());
        }
        let manifest = make_manifest(consent, approval, scan, None)?;
        let journal = Journal::new(base, consent.source_id())?;
        journal.write("manifest.json", &manifest, identity)?;
        journal.write("cursor.json", &Cursor::new(&manifest)?, identity)
    }

    pub fn watching(&self) -> bool {
        self.watching.load(Ordering::Acquire)
    }
    pub async fn stop(&self) {
        if let Some(running) = self.running.lock().await.take() {
            running.cancel.store(true, Ordering::Release);
            running.wake.notify_one();
            let _ = running.task.await;
        }
    }
    pub fn status(
        &self,
        base: &Path,
        saved: &SavedConnection,
    ) -> Result<Option<ImportView>, String> {
        let identity = credentials::identity()?;
        let consent =
            credentials::load::<Consent>(self.credential)?.ok_or("source_approval_required")?;
        consent.require(saved, &identity)?;
        let live = self
            .status
            .lock()
            .map_err(|_| "source_status_unavailable")?
            .clone();
        if live.source_id == consent.source_id() && !live.state.is_empty() {
            return Ok(Some(live));
        }
        if consent.watch {
            return watch::status(base, saved, &consent, &identity).map(Some);
        }
        if !base
            .join("photo-imports")
            .join(consent.source_id())
            .join("manifest.json")
            .exists()
        {
            return Ok(None);
        }
        let journal = Journal::new(base, consent.source_id())?;
        let (manifest, cursor) = load(&journal, &identity, &consent, saved)?;
        Ok(Some(view(
            &manifest,
            &cursor,
            resting(&manifest, &cursor),
            None,
        )))
    }
    pub async fn prepare(
        &self,
        base: &Path,
        saved: &SavedConnection,
    ) -> Result<ImportView, String> {
        let identity = credentials::identity()?;
        let consent =
            credentials::load::<Consent>(self.credential)?.ok_or("source_approval_required")?;
        let approval = consent.approval(saved, &identity)?;
        if consent.watch {
            return Err("source_control_invalid".into());
        }
        self.stop().await;
        if base.starts_with(approval.root()) || approval.root().starts_with(base) {
            return Err("source_staging_overlap".into());
        }
        sweep_abandoned_sources(base);
        let journal = Journal::new(base, consent.source_id())?;
        let (manifest, cursor) = if journal.root.join("manifest.json").exists()
            || journal.root.join("cursor.json").exists()
        {
            load(&journal, &identity, &consent, saved)?
        } else {
            let saved = saved.clone();
            let base = base.to_path_buf();
            let (manifest, identity) = tauri::async_runtime::spawn_blocking(move || {
                let manifest = manifest_for(&consent, &saved, &identity, &base);
                (manifest, identity)
            })
            .await
            .map_err(|_| "source_inventory_failed")?;
            let manifest = manifest?;
            let cursor = Cursor::new(&manifest)?;
            journal.write("manifest.json", &manifest, &identity)?;
            journal.write("cursor.json", &cursor, &identity)?;
            (manifest, cursor)
        };
        let value = view(&manifest, &cursor, resting(&manifest, &cursor), None);
        *self
            .status
            .lock()
            .map_err(|_| "source_status_unavailable")? = value.clone();
        Ok(value)
    }
    pub async fn start(
        &self,
        app: tauri::AppHandle,
        base: PathBuf,
        saved: SavedConnection,
    ) -> Result<ImportView, String> {
        self.stop().await;
        let identity = credentials::identity()?;
        let consent =
            credentials::load::<Consent>(self.credential)?.ok_or("source_approval_required")?;
        consent.approval(&saved, &identity)?;
        let watch = consent.watch && !consent.watch_paused;
        if consent.watch_paused {
            return Err("source_control_invalid".into());
        }
        let value = self
            .status(&base, &saved)?
            .ok_or("source_manifest_required")?;
        if !watch && matches!(value.state.as_str(), "complete" | "cancelled") {
            return Err("source_run_terminal".into());
        }
        sweep_abandoned_sources(&base);
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let status = self.status.clone();
        let wake = Arc::new(tokio::sync::Notify::new());
        let wake_task = wake.clone();
        let watching = self.watching.clone();
        let credential = self.credential;
        let ordinary = credential == CREDENTIAL;
        let mut value = value;
        value.state = if watch {
            "watching"
        } else if ordinary {
            "copying"
        } else {
            "queued"
        }
        .into();
        value.code = None;
        *status.lock().map_err(|_| "source_status_unavailable")? = value.clone();
        watching.store(watch, Ordering::Release);
        let _ = app.emit_to("main", "photo-import-history", ());
        if ordinary {
            crate::tray::set_import_status(&app, Some(&value));
        } else {
            crate::tray::set_drop_status(&app, Some(&value));
        }
        // Network probes and journal I/O must not occupy an async worker.
        let task = tauri::async_runtime::spawn_blocking(move || {
            tauri::async_runtime::block_on(async move {
                let notify = |value: ImportView| {
                    if let Ok(mut current) = status.lock() {
                        *current = value.clone();
                    }
                    if ordinary {
                        crate::tray::set_import_status(&app, Some(&value));
                    } else {
                        crate::tray::set_drop_status(&app, Some(&value));
                    }
                    let _ = app.emit_to(
                        "main",
                        if ordinary {
                            "photo-import"
                        } else {
                            "photo-drop-import"
                        },
                        value,
                    );
                };
                let result = async {
                    let identity = credentials::identity()?;
                    let source = credentials::load::<Consent>(credential)?
                        .ok_or("source_approval_required")?;
                    let journal = Journal::new(&base, source.source_id())?;
                    let network = Mutex::new((
                        std::time::Instant::now() - std::time::Duration::from_secs(2),
                        None,
                    ));
                    let gate = || {
                        if stop.load(Ordering::Acquire) {
                            return Err("source_copy_cancelled".into());
                        }
                        let permission =
                            current(credential, &saved, &identity, source.source_id())?;
                        if watch && (!permission.watch || permission.watch_paused) {
                            return Err("source_copy_cancelled".into());
                        }
                        let mut snapshot = network.lock().map_err(|_| "network_unknown")?;
                        if snapshot.0.elapsed() >= std::time::Duration::from_secs(1) {
                            *snapshot = (
                                std::time::Instant::now(),
                                crate::resource_policy::sample().unmetered,
                            );
                        }
                        network_admission(snapshot.1)
                    };
                    let client = transport::client()?;
                    let origin = crate::connection::normalize_server(&saved.server)?;
                    let transfer = app.state::<ImportTransfer>();
                    if watch {
                        watch::run(
                            &client, &origin, &saved, &identity, &source, &journal, &base, &stop,
                            &wake_task, &gate, &notify, &transfer,
                        )
                        .await
                    } else {
                        let _permit = transfer.acquire(&stop, &wake_task).await?;
                        if !ordinary {
                            let mut queued = status
                                .lock()
                                .map_err(|_| "source_status_unavailable")?
                                .clone();
                            queued.state = "copying".into();
                            notify(queued);
                        }
                        execute_all(
                            &client,
                            &origin,
                            &saved,
                            &identity,
                            &source,
                            &journal,
                            &base,
                            history::Kind::for_consent(credential, &source),
                            &stop,
                            &gate,
                            &notify,
                        )
                        .await
                    }
                }
                .await;
                if let Err(code) = result {
                    let failed = status.lock().ok().and_then(|current| {
                        if current.state == "queued" && code == "source_copy_cancelled" {
                            return Some(ImportView {
                                state: "paused".into(),
                                code: None,
                                ..current.clone()
                            });
                        }
                        ((watch && !stop.load(Ordering::Acquire))
                            || matches!(current.state.as_str(), "copying" | "queued"))
                        .then(|| ImportView {
                            state: "needs-attention".into(),
                            code: Some(code),
                            ..current.clone()
                        })
                    });
                    if let Some(failed) = failed {
                        notify(failed);
                    }
                }
                watching.store(false, Ordering::Release);
            });
        });
        *self.running.lock().await = Some(Running { cancel, task, wake });
        Ok(value)
    }
    pub(crate) async fn reconnect_camera(
        &self,
        base: PathBuf,
        saved: SavedConnection,
        source_id: String,
        path: PathBuf,
    ) -> Result<(), String> {
        self.stop().await;
        let credential = self.credential;
        tauri::async_runtime::spawn_blocking(move || {
            let identity = credentials::identity()?;
            let consent = current(credential, &saved, &identity, &source_id)?;
            let journal = Journal::new(&base, consent.source_id())?;
            reconnect_camera_at(&journal, &saved, &identity, &consent, path)
        })
        .await
        .map_err(|_| "source_inventory_failed")?
    }

    pub async fn pause_watch(
        &self,
        base: &Path,
        saved: &SavedConnection,
    ) -> Result<ImportView, String> {
        let identity = credentials::identity()?;
        let mut consent =
            credentials::load::<Consent>(self.credential)?.ok_or("source_approval_required")?;
        consent.approval(saved, &identity)?;
        if !consent.watch {
            return Err("source_control_invalid".into());
        }
        consent.watch_paused = true;
        let persisted = credentials::save(self.credential, &consent);
        self.stop().await;
        persisted?;
        let value = watch::status(base, saved, &consent, &identity)?;
        *self
            .status
            .lock()
            .map_err(|_| "source_status_unavailable")? = value.clone();
        Ok(value)
    }
    pub async fn resume_watch(
        &self,
        app: tauri::AppHandle,
        base: PathBuf,
        saved: SavedConnection,
    ) -> Result<ImportView, String> {
        let identity = credentials::identity()?;
        let mut consent =
            credentials::load::<Consent>(self.credential)?.ok_or("source_approval_required")?;
        consent.approval(&saved, &identity)?;
        if !consent.watch {
            return Err("source_control_invalid".into());
        }
        if consent.watch_paused {
            consent.watch_paused = false;
            credentials::save(self.credential, &consent)?;
        }
        self.start(app, base, saved).await
    }
    pub async fn approve_upload(
        &self,
        base: &Path,
        saved: &SavedConnection,
    ) -> Result<ImportView, String> {
        self.stop().await;
        let identity = credentials::identity()?;
        let consent =
            credentials::load::<Consent>(self.credential)?.ok_or("source_approval_required")?;
        let journal = Journal::new(base, consent.source_id())?;
        let journal = if consent.watch {
            watch::batch(&journal)?
        } else {
            journal
        };
        let (manifest, mut cursor) = load(&journal, &identity, &consent, saved)?;
        cursor.approve_upload(&manifest)?;
        journal.write("cursor.json", &cursor, &identity)?;
        let value = view(&manifest, &cursor, "paused", None);
        *self
            .status
            .lock()
            .map_err(|_| "source_status_unavailable")? = value.clone();
        Ok(value)
    }
    pub async fn control(
        &self,
        base: &Path,
        saved: &SavedConnection,
        cancel: bool,
    ) -> Result<ImportView, String> {
        let identity = credentials::identity()?;
        let consent =
            credentials::load::<Consent>(self.credential)?.ok_or("source_approval_required")?;
        if consent.watch {
            return Err("source_control_invalid".into());
        }
        self.stop().await;
        let journal = Journal::new(base, consent.source_id())?;
        let (manifest, mut cursor) = load(&journal, &identity, &consent, saved)?;
        if !matches!(cursor.state.as_str(), "complete" | "cancelled") {
            cursor.state = if cancel { "cancelled" } else { "paused" }.into();
            journal.write("cursor.json", &cursor, &identity)?;
            if cancel {
                // A cancelled run never resumes, so its staged copies are no longer needed.
                crate::copy_source::release_stages(&journal.root.join("stage"));
            }
        } else if cancel && continues(&manifest, &cursor) {
            // Between batches there is no open run to cancel; the remaining batches are dropped.
            cursor.exhausted = true;
            journal.write("cursor.json", &cursor, &identity)?;
        }
        let client = transport::client()?;
        let base = crate::connection::normalize_server(&saved.server)?;
        let pending = AtomicBool::new(false);
        let control_gate =
            || current(self.credential, saved, &identity, consent.source_id()).map(|_| ());
        let api = SourceApi {
            client: &client,
            base: &base,
            saved,
            source: consent.source_id(),
            cancel: &pending,
            gate: &control_gate,
        };
        let confirmed = if cursor.state == "complete" {
            true
        } else {
            api.state(&manifest, &cursor.state).await.is_ok()
        };
        let value = view(
            &manifest,
            &cursor,
            &cursor.state,
            if confirmed {
                None
            } else {
                Some("source_stop_confirmation_pending".into())
            },
        );
        *self
            .status
            .lock()
            .map_err(|_| "source_status_unavailable")? = value.clone();
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn payload_allowance_survives_restart_and_refuses_sends_before_http() {
        tauri::async_runtime::block_on(async {
            for acknowledged in [true, false] {
                let f = Fixture::new();
                let mut cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
                // 36 of the 40 bytes this run may be granted automatically are already spent.
                cursor.upload_budget = Some(UploadBudget {
                    used: 36,
                    limit: 40,
                });
                f.journal
                    .write("cursor.json", &cursor, &f.identity)
                    .unwrap();
                let mut replies = f.replies(f.receipt(), false, false);
                replies.truncate(10);
                if !acknowledged {
                    replies[9] = protocol(503, "", "{}");
                }
                let server = Server::new(replies);
                let error = f.run(&server, &|| Ok(())).await.unwrap_err();
                assert_eq!(
                    error,
                    if acknowledged {
                        "source_upload_budget_exhausted"
                    } else {
                        "source_upload_http_503"
                    }
                );
                let patches: Vec<_> = server
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(headers, _)| headers.starts_with("PATCH /api/assets/uploads/"))
                    .cloned()
                    .collect();
                assert_eq!(patches.len(), 1);
                assert_eq!(patches[0].1, b"abcd");
                let cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
                assert_eq!(cursor.upload_budget.as_ref().unwrap().used, 40);
                assert_eq!(cursor.upload_budget.as_ref().unwrap().limit, 40);
                assert_eq!(cursor.position, 0);
                assert!(cursor.active.as_ref().unwrap().copy.is_some());
                let mut replies = vec![
                    preflight()[0].clone(),
                    f.run_ack("open"),
                    f.state_ack("open"),
                    f.plan_ack("planned"),
                ];
                replies.extend(preflight());
                replies.push(protocol(
                    204,
                    &format!(
                        "Upload-Offset: {}\r\nUpload-Complete: ?0\r\n",
                        if acknowledged { 4 } else { 0 }
                    ),
                    "",
                ));
                let restarted = Server::new(replies);
                assert_eq!(
                    f.run(&restarted, &|| Ok(())).await.unwrap_err(),
                    "source_upload_budget_exhausted"
                );
                assert!(!restarted
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(headers, _)| headers.starts_with("PATCH /api/assets/uploads/")));
                let mut cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
                assert_eq!(cursor.upload_budget.as_ref().unwrap().used, 40);
                cursor.approve_upload(&f.manifest).unwrap();
                assert_eq!(cursor.upload_budget.as_ref().unwrap().used, 40);
                assert_eq!(cursor.upload_budget.as_ref().unwrap().limit, 60);
                f.journal
                    .write("cursor.json", &cursor, &f.identity)
                    .unwrap();
                let restored: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
                assert_eq!(
                    view(&f.manifest, &restored, "paused", None).upload_remaining,
                    Some(20)
                );
                assert_eq!(
                    fs::read(f.base.join("source/photo.jpg")).unwrap(),
                    b"abcdefghij"
                );
                let mut replies = vec![
                    preflight()[0].clone(),
                    f.run_ack("open"),
                    f.state_ack("open"),
                    f.plan_ack("planned"),
                ];
                replies.extend(preflight());
                replies.push(protocol(
                    204,
                    &format!(
                        "Upload-Offset: {}\r\nUpload-Complete: ?0\r\n",
                        if acknowledged { 4 } else { 0 }
                    ),
                    "",
                ));
                for offset in if acknowledged {
                    vec![8, 10]
                } else {
                    vec![4, 8, 10]
                } {
                    replies.push(protocol(
                        204,
                        &format!("Upload-Offset: {offset}\r\nUpload-Complete: ?0\r\n"),
                        "",
                    ));
                }
                replies.push(protocol(
                    200,
                    "",
                    &json!({"id":ASSET,"status":"created","sha256":f.probe.sha256}).to_string(),
                ));
                replies.push(protocol(200, "", &f.receipt().to_string()));
                replies.push(f.state_ack("complete"));
                let renewed = Server::new(replies);
                f.run(&renewed, &|| Ok(())).await.unwrap();
                let final_cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
                assert_eq!(final_cursor.state, "complete");
                assert_eq!(
                    final_cursor.upload_budget.unwrap().used,
                    if acknowledged { 46 } else { 50 }
                );
                assert!(!f.journal.root.join("stage").join(&f.stage).exists());
            }
        });
    }
    #[test]
    fn legacy_cursor_needs_explicit_allowance_without_changing_its_signed_shape() {
        let f = Fixture::new();
        let mut legacy = serde_json::to_value(Cursor::new(&f.manifest).unwrap()).unwrap();
        legacy.as_object_mut().unwrap().remove("uploadBudget");
        let mut cursor: Cursor = serde_json::from_value(legacy.clone()).unwrap();
        cursor.validate(&f.manifest).unwrap();
        assert_eq!(digest(&cursor).unwrap(), digest(&legacy).unwrap());
        assert_eq!(
            view(&f.manifest, &cursor, "paused", None).upload_remaining,
            None
        );
        cursor.approve_upload(&f.manifest).unwrap();
        assert_eq!(
            view(&f.manifest, &cursor, "paused", None).upload_remaining,
            Some(20)
        );
        cursor.upload_budget.as_mut().unwrap().used = 21;
        assert!(cursor.validate(&f.manifest).is_err());
        cursor.state = "cancelled".into();
        assert_eq!(
            cursor.approve_upload(&f.manifest).unwrap_err(),
            "source_run_terminal"
        );
    }
    #[test]
    fn durable_import_journals_reject_tampering_other_installations_and_unacknowledged_progress() {
        let base = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("frameleaf-run-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&base).unwrap();
        let identity = DeviceIdentity::generate();
        let manifest = Manifest {
            id: uuid::Uuid::new_v4().to_string(),
            source_id: uuid::Uuid::new_v4().to_string(),
            scope: "a".repeat(64),
            created_at: None,
            destination: None,
            files: vec![SourceFile {
                relative: "nested/photo.jpg".into(),
                bytes: 8,
                watch_version: None,
            }],
            total_bytes: 8,
            skipped: 0,
            availability: None,
            skipped_reasons: BTreeMap::new(),
            more: false,
            continues: None,
        };
        let journal = Journal::new(&base, &manifest.source_id).unwrap();
        journal
            .write("manifest.json", &manifest, &identity)
            .unwrap();
        let restored: Manifest = journal.read("manifest.json", &identity).unwrap();
        assert_eq!(restored.files[0].relative, "nested/photo.jpg");
        let mut cursor = Cursor::new(&manifest).unwrap();
        journal.write("cursor.json", &cursor, &identity).unwrap();
        assert!(journal
            .read::<Cursor>("cursor.json", &DeviceIdentity::generate())
            .is_err());
        cursor.position = 2;
        assert!(cursor.validate(&manifest).is_err());
        let path = journal.root.join("cursor.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["value"]["position"] = serde_json::json!(1);
        std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(journal.read::<Cursor>("cursor.json", &identity).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }
    use crate::copy_upload::tests::{preflight, protocol, Server};
    const RESOURCE: &str = "11111111-1111-4111-8111-111111111111";
    const ASSET: &str = "44444444-4444-4444-8444-444444444444";
    struct Fixture {
        base: PathBuf,
        saved: SavedConnection,
        identity: DeviceIdentity,
        consent: Consent,
        journal: Journal,
        manifest: Manifest,
        probe: StagedCopy,
        item: String,
        stage: String,
    }
    impl Fixture {
        fn new() -> Self {
            Self::with_destination(None)
        }
        fn with_destination(destination: Option<Destination>) -> Self {
            let base = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("frameleaf-copy-job-{}", uuid::Uuid::new_v4()));
            crate::runtime_store::private_directory(&base).unwrap();
            for name in ["source", "data"] {
                crate::runtime_store::private_directory(&base.join(name)).unwrap();
            }
            fs::write(base.join("source/photo.jpg"), b"abcdefghij").unwrap();
            let saved = SavedConnection {
                server: "https://nas.test/".into(),
                server_id: "nas".into(),
                account_id: "owner".into(),
                name: "Fixture".into(),
                token: "synthetic-token".into(),
                device_name: "Fixture".into(),
                mode: "client-worker".into(),
                device_id: Some("device".into()),
            };
            let identity = DeviceIdentity::generate();
            let state = crate::source_consent::SourceConsent::default();
            let selected = state
                .select(state.generation().unwrap(), base.join("source"))
                .unwrap();
            let mut consent = state
                .approve(
                    &saved,
                    &identity,
                    &selected.selection_id,
                    true,
                    false,
                    destination,
                    |_| Ok(()),
                )
                .unwrap();
            consent.registered = true;
            let manifest = manifest_for(&consent, &saved, &identity, &base.join("data")).unwrap();
            let journal = Journal::new(&base.join("data"), consent.source_id()).unwrap();
            let probe = consent
                .approval(&saved, &identity)
                .unwrap()
                .stage(
                    &saved,
                    &identity,
                    "photo.jpg",
                    &journal.root.join("stage"),
                    &AtomicBool::new(false),
                )
                .unwrap();
            let item = uuid::Uuid::new_v4().to_string();
            let stage = uuid::Uuid::new_v4().to_string();
            let mut cursor = Cursor::new(&manifest).unwrap();
            cursor.active = Some(Active {
                item_id: item.clone(),
                stage_id: stage.clone(),
                copy: None,
                upload: None,
                receipt: None,
                album_attached: false,
            });
            journal
                .write("manifest.json", &manifest, &identity)
                .unwrap();
            journal.write("cursor.json", &cursor, &identity).unwrap();
            Self {
                base,
                saved,
                identity,
                consent,
                journal,
                manifest,
                probe,
                item,
                stage,
            }
        }
        fn run_ack(&self, state: &str) -> String {
            protocol(201,"",&json!({"id":self.manifest.id,"sourceId":self.manifest.source_id,"maxItems":1,"maxBytes":10,"state":state}).to_string())
        }
        fn state_ack(&self, state: &str) -> String {
            protocol(
                200,
                "",
                &json!({"id":self.manifest.id,"sourceId":self.manifest.source_id,"state":state})
                    .to_string(),
            )
        }
        fn plan_ack(&self, state: &str) -> String {
            protocol(201,"",&json!({"id":self.item,"runId":self.manifest.id,"resourceKey":self.probe.resource_key(),"version":self.probe.version(),"sha256":self.probe.sha256,"bytes":10,"state":state}).to_string())
        }
        fn receipt(&self) -> Value {
            json!({"serverId":self.saved.server_id,"ownerId":self.saved.account_id,"sourceId":self.manifest.source_id,"runId":self.manifest.id,"itemId":self.item,"uploadResourceId":RESOURCE,"assetId":ASSET,"sha256":self.probe.sha256,"bytes":10,"storage":"managed","verifiedAt":"2026-10-16T19:00:00Z"})
        }
        fn replies(&self, receipt: Value, verified: bool, lose_ack: bool) -> Vec<String> {
            let mut values = vec![
                preflight()[0].clone(),
                self.run_ack("open"),
                self.state_ack("open"),
                self.run_ack("open"),
                self.plan_ack(if verified { "verified" } else { "planned" }),
            ];
            if verified {
                values.remove(3);
            }
            if !verified {
                values.extend(preflight());
                values.push(protocol(201,&format!("Location: /api/assets/uploads/{RESOURCE}\r\nUpload-Offset: 0\r\nUpload-Complete: ?0\r\n"),""));
                for n in [4, 8, 10] {
                    values.push(protocol(
                        204,
                        &format!("Upload-Offset: {n}\r\nUpload-Complete: ?0\r\n"),
                        "",
                    ));
                }
                values.push(protocol(
                    200,
                    "",
                    &json!({"id":ASSET,"status":"created","sha256":self.probe.sha256}).to_string(),
                ));
            }
            values.push(if lose_ack {
                protocol(503, "", "{}")
            } else {
                protocol(200, "", &receipt.to_string())
            });
            if !lose_ack {
                values.push(self.state_ack("complete"));
            }
            values
        }
        async fn run(
            &self,
            server: &Server,
            gate: &(dyn Fn() -> Result<(), String> + Sync),
        ) -> Result<(), String> {
            execute(
                &transport::client().unwrap(),
                &server.base,
                &self.saved,
                &self.identity,
                &self.consent,
                &self.journal,
                &AtomicBool::new(false),
                gate,
                &|_| {},
            )
            .await
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn reconnect_binds_the_remounted_folder_to_the_same_signed_run_and_preserves_progress() {
        let f = Fixture::new();
        let original = f.base.join("source");
        fs::write(original.join("already-verified.jpg"), b"verified").unwrap();
        let selector = crate::source_consent::SourceConsent::default();
        let chosen = selector
            .select_camera(selector.generation().unwrap(), original.clone())
            .unwrap();
        let album = Destination {
            id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            name: "Trip".into(),
            shared: false,
        };
        let mut consent = selector
            .approve(
                &f.saved,
                &f.identity,
                &chosen.selection_id,
                true,
                false,
                Some(album.clone()),
                |_| Ok(()),
            )
            .unwrap();
        consent.registered = true;
        let approval = consent.approval(&f.saved, &f.identity).unwrap();
        assert!(
            approval.media().is_some(),
            "fixture volume must provide a durable identity"
        );
        let manifest = manifest_for(&consent, &f.saved, &f.identity, &f.base.join("data")).unwrap();
        assert_eq!(manifest.files.len(), 2);
        let journal = Journal::new(&f.base.join("data"), consent.source_id()).unwrap();
        let mut cursor = Cursor::new(&manifest).unwrap();
        cursor.position = 1;
        cursor.state = "paused".into();
        journal
            .write("manifest.json", &manifest, &f.identity)
            .unwrap();
        journal.write("cursor.json", &cursor, &f.identity).unwrap();
        let saved_cursor = fs::read(journal.root.join("cursor.json")).unwrap();

        fs::remove_file(original.join("already-verified.jpg")).unwrap();
        let remount = f.base.join("remounted");
        fs::rename(&original, &remount).unwrap();
        reconnect_camera_at(&journal, &f.saved, &f.identity, &consent, remount.clone()).unwrap();
        let (after, current) = load(&journal, &f.identity, &consent, &f.saved).unwrap();
        assert_eq!(after.id, manifest.id);
        assert_eq!(after.destination, Some(album));
        assert_eq!(current.position, 1);
        assert_eq!(
            fs::read(journal.root.join("cursor.json")).unwrap(),
            saved_cursor
        );
        let location = camera_location(&journal, &after, &f.identity, approval).unwrap();
        assert_eq!(location.as_deref(), Some(remount.as_path()));

        let entry = &after.files[current.position];
        let staged = approval
            .stage_to(
                &f.saved,
                &f.identity,
                &entry.relative,
                &journal.root.join("stage"),
                &uuid::Uuid::new_v4().to_string(),
                Some(entry.bytes),
                entry.watch_version.as_deref(),
                location.as_deref(),
                &AtomicBool::new(false),
                &|| Ok(()),
            )
            .unwrap();
        assert_eq!(staged.version(), entry.watch_version.clone().unwrap());

        let checkpoint = fs::read(journal.root.join(CAMERA_LOCATION)).unwrap();
        fs::rename(&remount, f.base.join("retained-original")).unwrap();
        fs::create_dir(&remount).unwrap();
        fs::write(remount.join("photo.jpg"), b"abcdefghij").unwrap();
        assert_eq!(
            reconnect_camera_at(&journal, &f.saved, &f.identity, &consent, remount.clone())
                .unwrap_err(),
            "source_camera_changed"
        );
        assert_eq!(
            fs::read(journal.root.join(CAMERA_LOCATION)).unwrap(),
            checkpoint
        );
        assert_eq!(
            approval.open_source(&remount).err().as_deref(),
            Some("source_camera_changed")
        );

        fs::remove_dir_all(&remount).unwrap();
        fs::rename(f.base.join("retained-original"), &remount).unwrap();
        fs::write(remount.join(&entry.relative), b"changed123").unwrap();
        assert_eq!(
            reconnect_camera_at(&journal, &f.saved, &f.identity, &consent, remount).unwrap_err(),
            "source_camera_changed"
        );
        assert_eq!(
            fs::read(journal.root.join(CAMERA_LOCATION)).unwrap(),
            checkpoint
        );

        let mut other_run = after;
        other_run.id = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            camera_location(&journal, &other_run, &f.identity, approval).unwrap_err(),
            "source_journal_invalid"
        );
    }

    #[test]
    fn pending_album_attachment_restarts_from_the_verified_receipt_without_uploading_again() {
        tauri::async_runtime::block_on(async {
            let album = Destination {
                id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                name: "Vacation".into(),
                shared: false,
            };
            let f = Fixture::with_destination(Some(album.clone()));
            let album_reply = protocol(
                200,
                "",
                &json!({
                    "id": album.id, "albumName": album.name, "kind": "album", "shared": false,
                    "albumUsers": [{"user": {"id": "owner"}, "role": "owner"}]
                })
                .to_string(),
            );

            let refused = Server::new(vec![preflight()[0].clone(), protocol(400, "", "{}")]);
            assert_eq!(
                f.run(&refused, &|| Ok(())).await.unwrap_err(),
                "source_album_unavailable_for_write"
            );
            assert!(!f.journal.root.join("stage").join(&f.stage).exists());

            let mut first = f.replies(f.receipt(), false, false);
            first.insert(1, album_reply.clone());
            first.pop();
            first.push(protocol(503, "", "{}"));
            let interrupted = Server::new(first);
            assert_eq!(
                f.run(&interrupted, &|| Ok(())).await.unwrap_err(),
                "server_http_503"
            );
            let pending: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            assert_eq!(pending.position, 0);
            assert!(view(&f.manifest, &pending, "paused", None).album_pending);
            assert_eq!(
                pending.active.as_ref().unwrap().receipt.as_ref().unwrap()["assetId"],
                ASSET
            );
            assert!(f.journal.root.join("stage").join(&f.stage).exists());

            let restarted = Server::new(vec![
                preflight()[0].clone(),
                album_reply,
                f.run_ack("open"),
                f.state_ack("open"),
                protocol(
                    200,
                    "",
                    &json!([{"id": ASSET, "success": false, "error": "duplicate"}]).to_string(),
                ),
                protocol(200, "", &f.receipt().to_string()),
                f.state_ack("complete"),
            ]);
            f.run(&restarted, &|| Ok(())).await.unwrap();
            let requests = restarted.requests.lock().unwrap();
            let attach = requests
                .iter()
                .position(|(header, _)| {
                    header.starts_with(&format!("PUT /api/albums/{}/assets ", album.id))
                })
                .unwrap();
            let verify = requests
                .iter()
                .position(|(header, _)| header.starts_with("POST ") && header.contains("/verify "))
                .unwrap();
            assert!(attach < verify);
            assert_eq!(
                serde_json::from_slice::<Value>(&requests[attach].1).unwrap(),
                json!({"ids": [ASSET]})
            );
            assert!(requests
                .iter()
                .all(|(header, _)| !header.contains("/api/assets/uploads")));
            let finished: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            assert_eq!(finished.state, "complete");
            assert_eq!(finished.position, 1);
            assert!(!f.journal.root.join("stage").join(&f.stage).exists());
        });
    }

    #[test]
    fn a_dropped_manifest_resumes_after_a_lost_ack_and_refuses_file_replacement() {
        tauri::async_runtime::block_on(async {
            let mut f = Fixture::new();
            f.manifest.files[0].watch_version = Some(f.probe.version());
            f.journal
                .write("manifest.json", &f.manifest, &f.identity)
                .unwrap();
            f.journal
                .write(
                    "cursor.json",
                    &Cursor::new(&f.manifest).unwrap(),
                    &f.identity,
                )
                .unwrap();
            let original = f.base.join("source/photo.jpg");
            fs::rename(&original, f.base.join("saved.jpg")).unwrap();
            fs::write(&original, b"0123456789").unwrap();
            let refused = Server::new(vec![
                preflight()[0].clone(),
                f.run_ack("open"),
                f.state_ack("open"),
                f.run_ack("open"),
                f.state_ack("complete"),
            ]);
            f.run(&refused, &|| Ok(())).await.unwrap();
            let cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            assert_eq!(cursor.state, "complete");
            assert_eq!(
                cursor.skipped_reasons,
                BTreeMap::from([("source_item_changed".to_string(), 1)])
            );
            assert_eq!(view(&f.manifest, &cursor, "complete", None).completed, 0);
            assert!(
                !refused.requests.lock().unwrap().iter().any(|(headers, _)| {
                    headers.contains("/api/assets/uploads") || headers.contains("/items")
                })
            );
            assert_eq!(fs::read(&original).unwrap(), b"0123456789");

            // A fresh drop can be completed by reloading the same signed journal after interruption.
            let mut f = Fixture::new();
            f.manifest.files[0].watch_version = Some(f.probe.version());
            f.journal
                .write("manifest.json", &f.manifest, &f.identity)
                .unwrap();
            let mut checkpoint = Cursor::new(&f.manifest).unwrap();
            checkpoint.active = Some(Active {
                stage_id: f.stage.clone(),
                item_id: f.item.clone(),
                copy: None,
                upload: None,
                receipt: None,
                album_attached: false,
            });
            f.journal
                .write("cursor.json", &checkpoint, &f.identity)
                .unwrap();
            let interrupted = Server::new(f.replies(f.receipt(), false, true));
            assert!(f.run(&interrupted, &|| Ok(())).await.is_err());
            let before: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            assert_eq!(before.position, 0);
            assert!(before.active.unwrap().copy.is_some());
            let resumed = Server::new(f.replies(f.receipt(), true, false));
            f.run(&resumed, &|| Ok(())).await.unwrap();
            let after: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            assert_eq!(after.position, 1);
            assert_eq!(after.state, "complete");
            assert_eq!(
                fs::read(f.base.join("source/photo.jpg")).unwrap(),
                b"abcdefghij"
            );
        });
    }

    #[test]
    fn cancel_while_waiting_for_the_shared_transfer_does_not_claim_a_turn() {
        tauri::async_runtime::block_on(async {
            let shared = ImportTransfer::default();
            let wake = tokio::sync::Notify::new();
            let stop = AtomicBool::new(false);
            let held = shared.acquire(&stop, &wake).await.unwrap();
            let cancelled = AtomicBool::new(false);
            let dropped = tokio::sync::Notify::new();
            let result = tokio::select! {
                result = shared.acquire(&cancelled, &dropped) => result,
                _ = async {
                    tokio::task::yield_now().await;
                    cancelled.store(true, Ordering::Release);
                    dropped.notify_one();
                    std::future::pending::<()>().await;
                } => unreachable!(),
            };
            assert_eq!(result.err().as_deref(), Some("source_copy_cancelled"));
            drop(held);
            assert!(shared.acquire(&stop, &wake).await.is_ok());
        });
    }

    #[test]
    fn a_changed_watch_file_is_reconsidered_without_uploading_under_its_old_version() {
        tauri::async_runtime::block_on(async {
            let mut f = Fixture::new();
            f.consent.watch = true;
            f.manifest.files[0].watch_version = Some(f.probe.version());
            f.journal
                .write("manifest.json", &f.manifest, &f.identity)
                .unwrap();
            f.journal
                .write(
                    "cursor.json",
                    &Cursor::new(&f.manifest).unwrap(),
                    &f.identity,
                )
                .unwrap();
            let path = f.base.join("source/photo.jpg");
            fs::rename(&path, f.base.join("previous.jpg")).unwrap();
            fs::write(&path, b"0123456789").unwrap();
            let server = Server::new(vec![
                preflight()[0].clone(),
                f.run_ack("open"),
                f.state_ack("open"),
                f.run_ack("open"),
                f.state_ack("complete"),
            ]);
            f.run(&server, &|| Ok(())).await.unwrap();
            let cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            assert_eq!(cursor.watch_skipped, BTreeSet::from([0]));
            assert_eq!(view(&f.manifest, &cursor, "complete", None).completed, 0);
            assert!(!server
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(
                    |(headers, _)| headers.starts_with("POST /api/assets/uploads/")
                        || headers.contains("/items")
                ));
            assert_eq!(fs::read(&path).unwrap(), b"0123456789");
        });
    }

    #[test]
    fn real_copy_job_keeps_its_stage_until_a_bound_nas_receipt_and_then_finishes_without_touching_source(
    ) {
        tauri::async_runtime::block_on(async {
            let f = Fixture::new();
            let server = Server::new(f.replies(f.receipt(), false, false));
            f.run(&server, &|| Ok(())).await.unwrap();
            let cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            assert_eq!(cursor.state, "complete");
            assert_eq!(cursor.position, 1);
            assert!(cursor.active.is_none());
            assert!(!f.journal.root.join("stage").join(&f.stage).exists());
            assert_eq!(
                fs::read(f.base.join("source/photo.jpg")).unwrap(),
                b"abcdefghij"
            );
            let requests = server.requests.lock().unwrap();
            assert_eq!(
                requests
                    .iter()
                    .filter(|(h, _)| h.starts_with("POST /api/assets/uploads "))
                    .count(),
                1
            );
            let sent: Vec<_> = requests
                .iter()
                .filter(|(h, _)| h.starts_with("PATCH /api/assets/uploads/"))
                .flat_map(|(_, bytes)| bytes.clone())
                .collect();
            assert_eq!(sent, b"abcdefghij");
        });
    }
    #[test]
    fn lost_verification_reply_reconciles_the_existing_item_without_head_or_new_upload() {
        tauri::async_runtime::block_on(async {
            let f = Fixture::new();
            let first = Server::new(f.replies(f.receipt(), false, true));
            assert!(f.run(&first, &|| Ok(())).await.is_err());
            let cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            assert_eq!(cursor.position, 0);
            assert!(cursor.active.unwrap().receipt.is_none());
            assert!(f
                .journal
                .root
                .join("stage")
                .join(&f.stage)
                .join("original")
                .exists());
            let retry = Server::new(f.replies(f.receipt(), true, false));
            f.run(&retry, &|| Ok(())).await.unwrap();
            assert!(!retry
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|(h, _)| h.contains("/api/assets/uploads")));
            assert_eq!(
                f.journal
                    .read::<Cursor>("cursor.json", &f.identity)
                    .unwrap()
                    .state,
                "complete"
            );
        });
    }
    #[test]
    fn foreign_receipt_and_failed_receipt_checkpoint_never_release_the_independent_original() {
        tauri::async_runtime::block_on(async {
            for corrupt_store in [false, true] {
                let f = Fixture::new();
                let mut receipt = f.receipt();
                if !corrupt_store {
                    receipt["ownerId"] = json!("foreign");
                }
                let server = Server::new(f.replies(receipt, false, false));
                let requests = server.requests.clone();
                let corrupted = AtomicBool::new(false);
                let gate = || {
                    if corrupt_store
                        && requests.lock().unwrap().iter().any(|(h, _)| {
                            h.starts_with(&format!("GET /api/assets/uploads/{RESOURCE}/result"))
                        })
                        && !corrupted.swap(true, Ordering::AcqRel)
                    {
                        fs::rename(
                            f.journal.root.join("cursor.json"),
                            f.journal.root.join("cursor.backup"),
                        )
                        .unwrap();
                        fs::create_dir(f.journal.root.join("cursor.json")).unwrap();
                    }
                    Ok(())
                };
                assert!(f.run(&server, &gate).await.is_err());
                assert_eq!(
                    fs::read(f.journal.root.join("stage").join(&f.stage).join("original")).unwrap(),
                    b"abcdefghij"
                );
                assert!(!server
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(h, b)| h.starts_with("PATCH /api/photo-sources/")
                        && String::from_utf8_lossy(b).contains("complete")));
            }
        });
    }
    #[test]
    fn a_policy_change_during_staging_discards_only_the_partial_cache_attempt() {
        let f = Fixture::new();
        let data = vec![5; 2 * 1024 * 1024];
        fs::write(f.base.join("source/photo.jpg"), &data).unwrap();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let gate = || {
            if calls.fetch_add(1, Ordering::AcqRel) >= 2 {
                Err("metered_network".into())
            } else {
                Ok(())
            }
        };
        let attempt = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            f.consent
                .approval(&f.saved, &f.identity)
                .unwrap()
                .stage_to(
                    &f.saved,
                    &f.identity,
                    "photo.jpg",
                    &f.journal.root.join("stage"),
                    &attempt,
                    Some(data.len() as u64),
                    None,
                    None,
                    &AtomicBool::new(false),
                    &gate
                )
                .err()
                .as_deref(),
            Some("metered_network")
        );
        assert!(!f.journal.root.join("stage").join(attempt).exists());
        assert_eq!(fs::read(f.base.join("source/photo.jpg")).unwrap(), data);
    }

    #[test]
    fn a_server_cancel_is_terminal_and_a_paused_run_is_checked_before_staging_an_original() {
        tauri::async_runtime::block_on(async {
            let f = Fixture::new();
            let server = Server::new(vec![preflight()[0].clone(), f.run_ack("cancelled")]);
            f.run(&server, &|| Ok(())).await.unwrap();
            assert_eq!(
                f.journal
                    .read::<Cursor>("cursor.json", &f.identity)
                    .unwrap()
                    .state,
                "cancelled"
            );
            assert!(!f.journal.root.join("stage").join(&f.stage).exists());
            let g = Fixture::new();
            let paused = Server::new(vec![
                preflight()[0].clone(),
                g.run_ack("open"),
                g.state_ack("open"),
                g.run_ack("paused"),
            ]);
            assert!(g.run(&paused, &|| Ok(())).await.is_err());
            assert!(!g.journal.root.join("stage").join(&g.stage).exists());
        });
    }
    #[test]
    fn initial_manifest_recovers_only_a_missing_cursor_and_never_replaces_corruption() {
        let f = Fixture::new();
        fs::remove_file(f.journal.root.join("cursor.json")).unwrap();
        assert!(load(&f.journal, &f.identity, &f.consent, &f.saved).is_err());
        f.probe
            .release(&f.saved, &f.identity, &f.journal.root.join("stage"))
            .unwrap();
        let (_, cursor) = load(&f.journal, &f.identity, &f.consent, &f.saved).unwrap();
        assert_eq!(cursor.position, 0);
        assert_eq!(cursor.state, "ready");
        assert!(cursor.active.is_none());
        assert!(
            cursor.upload_budget.is_none(),
            "missing accounting must not mint an allowance"
        );
        fs::write(f.journal.root.join("cursor.json"), b"corrupt").unwrap();
        assert!(load(&f.journal, &f.identity, &f.consent, &f.saved).is_err());
        assert_eq!(
            fs::read(f.journal.root.join("cursor.json")).unwrap(),
            b"corrupt"
        );
    }
    #[test]
    fn nas_original_verification_outlives_the_servers_ten_minute_hash_limit() {
        assert!(source_request_timeout("runs/id/items/id/verify").as_secs() > 600);
        assert_eq!(source_request_timeout("runs").as_secs(), 30);
    }
    #[test]
    fn legacy_manifests_keep_their_signed_representation_and_resume_cursor() {
        let mut f = Fixture::new();
        f.manifest.availability = None;
        f.manifest.created_at = None;
        let legacy = json!({"id":f.manifest.id,"sourceId":f.manifest.source_id,"scope":f.manifest.scope,
            "files":f.manifest.files,"totalBytes":f.manifest.total_bytes,"skipped":f.manifest.skipped});
        assert_eq!(digest(&f.manifest).unwrap(), digest(&legacy).unwrap());
        f.journal
            .write("manifest.json", &legacy, &f.identity)
            .unwrap();
        f.journal
            .write(
                "cursor.json",
                &Cursor::new(&f.manifest).unwrap(),
                &f.identity,
            )
            .unwrap();
        let (manifest, cursor) = load(&f.journal, &f.identity, &f.consent, &f.saved).unwrap();
        assert!(manifest.availability.is_none());
        assert!(manifest.created_at.is_none());
        assert_eq!(cursor.position, 0);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn a_file_hidden_after_approval_is_refused_before_new_staging() {
        use std::os::unix::ffi::OsStrExt;
        tauri::async_runtime::block_on(async {
            let f = Fixture::new();
            let path =
                std::ffi::CString::new(f.base.join("source/photo.jpg").as_os_str().as_bytes())
                    .unwrap();
            assert_eq!(unsafe { libc::chflags(path.as_ptr(), 0x8000) }, 0);
            let server = Server::new(vec![
                preflight()[0].clone(),
                f.run_ack("open"),
                f.state_ack("open"),
                f.run_ack("open"),
                f.state_ack("complete"),
            ]);
            f.run(&server, &|| Ok(())).await.unwrap();
            let cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            assert_eq!(
                cursor.skipped_reasons,
                BTreeMap::from([("source_item_excluded".to_string(), 1)])
            );
            assert!(!server
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|(headers, _)| headers.contains("/api/assets/uploads")));
            assert!(!f.journal.root.join("stage").join(&f.stage).exists());
        });
    }
    #[test]
    fn a_persisted_receipt_is_revalidated_before_releasing_a_stage_after_restart() {
        tauri::async_runtime::block_on(async {
            let f = Fixture::new();
            let first = Server::new(f.replies(f.receipt(), false, false));
            let pause_after_checkpoint = || {
                let cursor: Cursor = f.journal.read("cursor.json", &f.identity)?;
                if cursor
                    .active
                    .as_ref()
                    .is_some_and(|item| item.receipt.is_some())
                {
                    Err("source_copy_cancelled".into())
                } else {
                    Ok(())
                }
            };
            assert!(f.run(&first, &pause_after_checkpoint).await.is_err());
            let original = f.journal.root.join("stage").join(&f.stage).join("original");
            assert!(original.exists());
            let unhealthy = Server::new(vec![
                preflight()[0].clone(),
                f.run_ack("open"),
                f.state_ack("open"),
                protocol(409, "", "{}"),
            ]);
            assert!(f.run(&unhealthy, &|| Ok(())).await.is_err());
            assert_eq!(fs::read(&original).unwrap(), b"abcdefghij");
            let healthy = Server::new(vec![
                preflight()[0].clone(),
                f.run_ack("open"),
                f.state_ack("open"),
                protocol(200, "", &f.receipt().to_string()),
                f.state_ack("complete"),
            ]);
            f.run(&healthy, &|| Ok(())).await.unwrap();
            assert!(!healthy
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|(h, _)| h.contains("/api/assets/uploads")));
            assert!(!original.exists());
        });
    }

    const RENEWED: &str = "22222222-2222-4222-8222-222222222222";
    fn staged(f: &Fixture) -> Vec<String> {
        fs::read_dir(f.journal.root.join("stage"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn an_exhausted_allowance_renews_itself_up_to_a_ceiling_without_a_manual_approval() {
        tauri::async_runtime::block_on(async {
            let f = Fixture::new();
            let mut cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            cursor.upload_budget = Some(UploadBudget { used: 0, limit: 4 });
            f.journal
                .write("cursor.json", &cursor, &f.identity)
                .unwrap();
            let server = Server::new(f.replies(f.receipt(), false, false));
            f.run(&server, &|| Ok(())).await.unwrap();
            let cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            assert_eq!(cursor.state, "complete");
            let budget = cursor.upload_budget.unwrap();
            // One renewal of twice the remaining bytes, as an approval would grant.
            assert_eq!((budget.used, budget.limit), (10, 24));
        });
        let mut budget = UploadBudget { used: 0, limit: 4 };
        budget.admit(4, 20, 40).unwrap();
        assert_eq!((budget.used, budget.limit), (4, 4));
        budget.admit(30, 20, 40).unwrap_err();
        assert_eq!((budget.used, budget.limit), (4, 4));
        budget.admit(20, 20, 40).unwrap();
        assert_eq!((budget.used, budget.limit), (24, 24));
        budget.admit(16, 20, 40).unwrap();
        assert_eq!((budget.used, budget.limit), (40, 40));
        assert_eq!(
            budget.admit(1, 20, 40).unwrap_err(),
            "source_upload_budget_exhausted"
        );
    }

    #[test]
    fn a_file_the_server_is_still_processing_is_waited_for_within_a_bound() {
        tauri::async_runtime::block_on(async {
            let f = Fixture::new();
            // The first result poll answers 202; the retry finds the upload complete.
            let mut replies = f.replies(f.receipt(), false, false);
            let result = replies.len() - 3;
            let finished = replies.split_off(result);
            replies.push(protocol(202, "", ""));
            replies.extend(preflight());
            replies.push(protocol(
                204,
                "Upload-Offset: 10\r\nUpload-Complete: ?1\r\n",
                "",
            ));
            replies.extend(finished);
            let server = Server::new(replies);
            f.run(&server, &|| Ok(())).await.unwrap();
            let cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            assert_eq!(cursor.state, "complete");
            assert_eq!(
                server
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(headers, _)| headers.starts_with("POST /api/assets/uploads "))
                    .count(),
                1
            );

            let g = Fixture::new();
            let mut replies = g.replies(g.receipt(), false, false);
            replies.truncate(result);
            for _ in 0..=PROCESSING_WAITS {
                replies.push(protocol(202, "", ""));
                replies.extend(preflight());
                replies.push(protocol(
                    204,
                    "Upload-Offset: 10\r\nUpload-Complete: ?1\r\n",
                    "",
                ));
            }
            let stuck = Server::new(replies);
            assert_eq!(
                g.run(&stuck, &|| Ok(())).await.unwrap_err(),
                "source_server_processing"
            );
        });
    }

    #[test]
    fn a_saved_upload_session_the_server_no_longer_has_is_replaced_once() {
        tauri::async_runtime::block_on(async {
            for gone_again in [false, true] {
                let f = Fixture::new();
                let mut replies = f.replies(f.receipt(), false, false);
                replies.truncate(9);
                replies.push(protocol(503, "", "{}"));
                let interrupted = Server::new(replies);
                assert_eq!(
                    f.run(&interrupted, &|| Ok(())).await.unwrap_err(),
                    "source_upload_http_503"
                );
                let saved: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
                assert_eq!(
                    saved.active.unwrap().upload.unwrap().resource_id(),
                    RESOURCE
                );

                let mut replies = vec![
                    preflight()[0].clone(),
                    f.run_ack("open"),
                    f.state_ack("open"),
                    f.plan_ack("planned"),
                ];
                replies.extend(preflight());
                // The saved session expired on the server.
                replies.push(protocol(404, "", "{}"));
                replies.extend(preflight());
                replies.push(protocol(
                    201,
                    &format!("Location: /api/assets/uploads/{RENEWED}\r\nUpload-Offset: 0\r\nUpload-Complete: ?0\r\n"),
                    "",
                ));
                if gone_again {
                    replies.push(protocol(404, "", "{}"));
                } else {
                    for offset in [4, 8, 10] {
                        replies.push(protocol(
                            204,
                            &format!("Upload-Offset: {offset}\r\nUpload-Complete: ?0\r\n"),
                            "",
                        ));
                    }
                    replies.push(protocol(
                        200,
                        "",
                        &json!({"id":ASSET,"status":"created","sha256":f.probe.sha256}).to_string(),
                    ));
                    let mut receipt = f.receipt();
                    receipt["uploadResourceId"] = json!(RENEWED);
                    replies.push(protocol(200, "", &receipt.to_string()));
                    replies.push(f.state_ack("complete"));
                }
                let server = Server::new(replies);
                let result = f.run(&server, &|| Ok(())).await;
                let requests = server.requests.lock().unwrap();
                assert_eq!(
                    requests
                        .iter()
                        .filter(|(headers, _)| headers
                            .starts_with(&format!("HEAD /api/assets/uploads/{RESOURCE} ")))
                        .count(),
                    1
                );
                // Exactly one new session: a second missing session is reported, not retried.
                assert_eq!(
                    requests
                        .iter()
                        .filter(|(headers, _)| headers.starts_with("POST /api/assets/uploads "))
                        .count(),
                    1
                );
                let cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
                if gone_again {
                    assert_eq!(result.unwrap_err(), "source_upload_http_404");
                    assert_eq!(cursor.state, "paused");
                } else {
                    result.unwrap();
                    assert_eq!(cursor.state, "complete");
                    let verify = requests
                        .iter()
                        .find(|(headers, _)| headers.contains("/verify "))
                        .unwrap();
                    assert_eq!(
                        serde_json::from_slice::<Value>(&verify.1).unwrap(),
                        json!({"uploadResourceId": RENEWED})
                    );
                }
                assert_eq!(
                    fs::read(f.base.join("source/photo.jpg")).unwrap(),
                    b"abcdefghij"
                );
            }
        });
    }

    #[test]
    fn a_file_changed_during_the_import_is_skipped_with_its_reason_and_the_rest_complete() {
        tauri::async_runtime::block_on(async {
            let mut f = Fixture::new();
            let later = f.base.join("source/zz-later.jpg");
            fs::write(&later, b"0123456789").unwrap();
            f.manifest =
                manifest_for(&f.consent, &f.saved, &f.identity, &f.base.join("data")).unwrap();
            assert_eq!(f.manifest.files.len(), 2);
            let mut cursor = Cursor::new(&f.manifest).unwrap();
            cursor.active = Some(Active {
                item_id: f.item.clone(),
                stage_id: f.stage.clone(),
                copy: None,
                upload: None,
                receipt: None,
                album_attached: false,
            });
            f.journal
                .write("manifest.json", &f.manifest, &f.identity)
                .unwrap();
            f.journal
                .write("cursor.json", &cursor, &f.identity)
                .unwrap();
            let run = protocol(201,"",&json!({"id":f.manifest.id,"sourceId":f.manifest.source_id,"maxItems":2,"maxBytes":20,"state":"open"}).to_string());
            let mut replies = f.replies(f.receipt(), false, false);
            replies[1] = run.clone();
            replies[3] = run.clone();
            replies.insert(replies.len() - 1, run);
            let server = Server::new(replies);
            let requests = server.requests.clone();
            let changed = AtomicBool::new(false);
            // The second file is rewritten while the first is being uploaded.
            let gate = || {
                if requests
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(headers, _)| headers.starts_with("PATCH /api/assets/uploads/"))
                    && !changed.swap(true, Ordering::AcqRel)
                {
                    fs::write(&later, b"edited while importing").unwrap();
                }
                Ok(())
            };
            f.run(&server, &gate).await.unwrap();
            assert!(changed.load(Ordering::Acquire));
            let cursor: Cursor = f.journal.read("cursor.json", &f.identity).unwrap();
            assert_eq!((cursor.state.as_str(), cursor.position), ("complete", 2));
            assert_eq!(cursor.watch_skipped, BTreeSet::from([1]));
            let shown = view(&f.manifest, &cursor, "complete", None);
            assert_eq!((shown.completed, shown.skipped), (1, 1));
            let entry = serde_json::to_value(history::Entry::from_run(
                history::Kind::Folder,
                &f.manifest,
                &cursor,
                false,
            ))
            .unwrap();
            assert_eq!(entry["status"], "complete");
            assert_eq!(
                (&entry["verified"], &entry["total"]),
                (&json!(1), &json!(2))
            );
            assert_eq!(entry["skipped"], 1);
            assert_eq!(entry["skippedReasons"], json!({"source_item_changed": 1}));
            assert!(!entry.to_string().contains("zz-later"));
            // Neither original was modified, moved or deleted, and nothing stays staged.
            assert_eq!(fs::read(&later).unwrap(), b"edited while importing");
            assert_eq!(
                fs::read(f.base.join("source/photo.jpg")).unwrap(),
                b"abcdefghij"
            );
            assert!(staged(&f).is_empty());
        });
    }

    #[test]
    fn an_empty_file_is_left_out_with_its_reason_instead_of_failing_the_inventory() {
        let f = Fixture::new();
        fs::write(f.base.join("source/empty.jpg"), b"").unwrap();
        let manifest =
            manifest_for(&f.consent, &f.saved, &f.identity, &f.base.join("data")).unwrap();
        assert_eq!(
            manifest
                .files
                .iter()
                .map(|file| file.relative.as_str())
                .collect::<Vec<_>>(),
            ["photo.jpg"]
        );
        assert_eq!(manifest.skipped, 1);
        assert_eq!(
            manifest.skipped_reasons,
            BTreeMap::from([("source_item_empty".to_string(), 1)])
        );
        let cursor = Cursor::new(&manifest).unwrap();
        cursor.validate(&manifest).unwrap();
        assert_eq!(
            skipped_reasons(&manifest, &cursor),
            BTreeMap::from([("source_item_empty".to_string(), 1)])
        );
        fs::remove_file(f.base.join("source/photo.jpg")).unwrap();
        assert_eq!(
            manifest_for(&f.consent, &f.saved, &f.identity, &f.base.join("data"))
                .err()
                .as_deref(),
            Some("source_no_media")
        );
    }

    #[test]
    fn an_unclassified_network_does_not_block_imports_but_a_metered_one_pauses_them() {
        assert_eq!(network_admission(None), Ok(()));
        assert_eq!(network_admission(Some(true)), Ok(()));
        assert_eq!(
            network_admission(Some(false)).unwrap_err(),
            "metered_network"
        );
    }

    #[test]
    fn staged_copies_are_removed_when_a_run_completes_is_cancelled_or_loses_its_approval() {
        tauri::async_runtime::block_on(async {
            // The fixture's probe copy stands in for a staged original an earlier attempt left.
            let f = Fixture::new();
            assert_eq!(staged(&f), std::slice::from_ref(&f.probe.id));
            let server = Server::new(f.replies(f.receipt(), false, false));
            f.run(&server, &|| Ok(())).await.unwrap();
            assert!(staged(&f).is_empty());

            let f = Fixture::new();
            let cancelled = Server::new(vec![preflight()[0].clone(), f.run_ack("cancelled")]);
            f.run(&cancelled, &|| Ok(())).await.unwrap();
            assert!(staged(&f).is_empty());

            // A paused run with a current approval keeps its staged copy for the resume.
            let f = Fixture::new();
            let data = f.base.join("data");
            fs::write(f.journal.root.join("stage").join("notes.txt"), b"kept").unwrap();
            sweep_abandoned(&data, &[f.consent.source_id().to_string()]);
            assert_eq!(staged(&f).len(), 2);
            sweep_abandoned(&data, &[]);
            assert_eq!(staged(&f), ["notes.txt"]);
            assert!(f.journal.root.join("manifest.json").exists());
            assert_eq!(
                fs::read(f.base.join("source/photo.jpg")).unwrap(),
                b"abcdefghij"
            );
        });
    }

    #[test]
    fn a_folder_larger_than_one_batch_continues_with_the_next_batch_after_a_restart() {
        tauri::async_runtime::block_on(async {
            let f = Fixture::new();
            let bulk = f.base.join("source/bulk");
            fs::create_dir(&bulk).unwrap();
            for index in 0..crate::photo_sources::BATCH_FILES {
                fs::write(bulk.join(format!("{index:05}.jpg")), b"x").unwrap();
            }
            let data = f.base.join("data");
            let first = manifest_for(&f.consent, &f.saved, &f.identity, &data).unwrap();
            assert_eq!(first.files.len(), crate::photo_sources::BATCH_FILES);
            assert!(first.more && first.continues.is_none());
            let mut cursor = Cursor::new(&first).unwrap();
            cursor.position = first.files.len();
            cursor.state = "complete".into();
            f.journal
                .write("manifest.json", &first, &f.identity)
                .unwrap();
            f.journal
                .write("cursor.json", &cursor, &f.identity)
                .unwrap();
            // A completed batch with more to copy is resumable, not a finished import.
            assert!(continues(&first, &cursor));
            assert_eq!(resting(&first, &cursor), "paused");

            // The connection becomes metered right after the next batch is recorded.
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let gate = || {
                if calls.fetch_add(1, Ordering::AcqRel) == 0 {
                    Ok(())
                } else {
                    Err("metered_network".into())
                }
            };
            let offline = url::Url::parse("http://127.0.0.1:9/").unwrap();
            let result = execute_all(
                &transport::client().unwrap(),
                &offline,
                &f.saved,
                &f.identity,
                &f.consent,
                &f.journal,
                &data,
                history::Kind::Folder,
                &AtomicBool::new(false),
                &gate,
                &|_| {},
            )
            .await;
            assert_eq!(result.unwrap_err(), "metered_network");
            let (next, cursor) = load(&f.journal, &f.identity, &f.consent, &f.saved).unwrap();
            assert_eq!(
                next.files
                    .iter()
                    .map(|file| file.relative.as_str())
                    .collect::<Vec<_>>(),
                ["photo.jpg"]
            );
            assert_eq!(next.continues, Some(digest(&first).unwrap()));
            assert!(!next.more);
            assert_eq!((cursor.position, cursor.state.as_str()), (0, "paused"));
            assert!(cursor.upload_budget.is_some());

            // A stop between writing the next manifest and its cursor leaves the finished cursor.
            let mut finished = Cursor::new(&first).unwrap();
            finished.position = first.files.len();
            finished.state = "complete".into();
            f.journal
                .write("cursor.json", &finished, &f.identity)
                .unwrap();
            let (_, recovered) = load(&f.journal, &f.identity, &f.consent, &f.saved).unwrap();
            assert_eq!((recovered.position, recovered.state.as_str()), (0, "ready"));
            // An unrelated cursor is still refused.
            let mut foreign = Cursor::new(&first).unwrap();
            foreign.manifest_hash = "0".repeat(64);
            foreign.position = 0;
            f.journal
                .write("cursor.json", &foreign, &f.identity)
                .unwrap();
            assert!(load(&f.journal, &f.identity, &f.consent, &f.saved).is_err());

            // When nothing follows the last batch the import is finished for good.
            let mut claimed = next;
            claimed.more = true;
            let mut last = Cursor::new(&claimed).unwrap();
            last.position = 1;
            last.state = "complete".into();
            f.journal
                .write("manifest.json", &claimed, &f.identity)
                .unwrap();
            f.journal.write("cursor.json", &last, &f.identity).unwrap();
            execute_all(
                &transport::client().unwrap(),
                &offline,
                &f.saved,
                &f.identity,
                &f.consent,
                &f.journal,
                &data,
                history::Kind::Folder,
                &AtomicBool::new(false),
                &|| Ok(()),
                &|_| {},
            )
            .await
            .unwrap();
            let (claimed, cursor) = load(&f.journal, &f.identity, &f.consent, &f.saved).unwrap();
            assert!(cursor.exhausted && !continues(&claimed, &cursor));
            assert_eq!(resting(&claimed, &cursor), "complete");
        });
    }
}

#[cfg(test)]
mod native_nas_tests;
