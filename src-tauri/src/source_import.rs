//! One bounded approved-folder copy, with immutable inventory and a small signed progress checkpoint.
use crate::{
    connection::{DeviceIdentity, SavedConnection},
    copy_source::StagedCopy,
    copy_upload::UploadSession,
    photo_sources::SourceFile,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
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
    files: Vec<SourceFile>,
    total_bytes: u64,
    skipped: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    availability: Option<crate::source_metadata::AvailabilitySummary>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Active {
    stage_id: String,
    item_id: String,
    copy: Option<StagedCopy>,
    upload: Option<UploadSession>,
    receipt: Option<serde_json::Value>,
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
    state: String,
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
            || !matches!(
                self.state.as_str(),
                "ready" | "open" | "paused" | "cancelled" | "complete"
            )
            || (self.active.is_some() && self.position >= manifest.files.len())
            || self
                .active
                .as_ref()
                .is_some_and(|a| !uuid(&a.stage_id) || !uuid(&a.item_id))
            || (self.state == "complete"
                && (self.position != manifest.files.len() || self.active.is_some()))
        {
            return Err("source_journal_invalid".into());
        }
        Ok(())
    }
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
use tauri::Emitter;
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
    pub availability: Option<crate::source_metadata::AvailabilitySummary>,
}
fn view(manifest: &Manifest, cursor: &Cursor, state: &str, code: Option<String>) -> ImportView {
    ImportView {
        state: state.into(),
        source_id: manifest.source_id.clone(),
        total: manifest.files.len(),
        completed: cursor.position,
        logical_bytes: manifest.total_bytes,
        upload_remaining: cursor
            .upload_budget
            .as_ref()
            .map(|budget| budget.limit - budget.used),
        additional_upload_allowance: manifest.files[cursor.position..]
            .iter()
            .map(|file| file.bytes)
            .sum::<u64>()
            .saturating_mul(2),
        skipped: manifest.skipped,
        availability: manifest.availability.clone(),
        code,
    }
}
fn current(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    source: &str,
) -> Result<Consent, String> {
    let consent = credentials::load::<Consent>(CREDENTIAL)?.ok_or("source_approval_required")?;
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
    if base.starts_with(approval.root()) || approval.root().starts_with(base) {
        return Err("source_staging_overlap".into());
    }
    let scan = crate::photo_sources::scan(approval.root(), 10_000)?;
    if scan.inventory.truncated {
        return Err("source_inventory_partial".into());
    }
    if scan.unreadable > 0 {
        return Err("source_inventory_unreadable".into());
    }
    if scan.files.is_empty() {
        return Err("source_no_media".into());
    }
    let mut total_bytes = 0u64;
    for file in &scan.files {
        if file.bytes == 0 || file.bytes > (1u64 << 31) {
            return Err("source_copy_budget_exceeded".into());
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
        files: scan.files,
        total_bytes,
        skipped: scan.inventory.skipped,
        availability: Some(scan.inventory.availability),
    })
}
fn load(
    journal: &Journal,
    identity: &DeviceIdentity,
    consent: &Consent,
    saved: &SavedConnection,
) -> Result<(Manifest, Cursor), String> {
    let manifest: Manifest = journal.read("manifest.json", identity)?;
    if !uuid(&manifest.id)
        || manifest.source_id != consent.source_id()
        || manifest.scope != consent.approval(saved, identity)?.fingerprint()
    {
        return Err("source_journal_invalid".into());
    }
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
    cursor.validate(&manifest)?;
    Ok((manifest, cursor))
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
        let state = api.run(&manifest).await?;
        if state["state"] == "cancelled" {
            cursor.state = "cancelled".into();
            journal.write("cursor.json", &cursor, identity)?;
            notify(view(&manifest, &cursor, "cancelled", None));
            return Ok(());
        }
        if state["state"] == "complete" {
            if cursor.position != manifest.files.len() || cursor.active.is_some() {
                return Err("source_receipt_invalid".into());
            }
            cursor.state = "complete".into();
            journal.write("cursor.json", &cursor, identity)?;
            notify(view(&manifest, &cursor, "complete", None));
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
                    consent.approval(saved, identity)?.stage_to(
                        saved,
                        identity,
                        &entry.relative,
                        &stage,
                        id,
                        Some(entry.bytes),
                        cancel,
                        gate,
                    )?
                };
                if !copy.matches_entry(&entry.relative, entry.bytes)
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
                || copy.source_id() != manifest.source_id
            {
                return Err("source_item_changed".into());
            }
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
                            let budget = cursor
                                .upload_budget
                                .as_mut()
                                .ok_or("source_upload_budget_required")?;
                            budget.used =
                                crate::upload_budget::reserve(budget.used, bytes, budget.limit)?;
                            cursor.active.as_mut().unwrap().upload = Some(session.clone());
                            journal.write("cursor.json", &cursor, identity)?;
                            notify(view(&manifest, &cursor, "copying", None));
                            Ok(())
                        },
                        cancel,
                        gate,
                    )
                    .await?;
                    cursor.active.as_mut().unwrap().upload = upload;
                    match outcome {
                        UploadOutcome::Pending => return Err("source_server_processing".into()),
                        UploadOutcome::Ingested { asset_id, .. } => asset = Some(asset_id),
                    }
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
        notify(view(&manifest, &cursor, "complete", None));
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
struct Running {
    cancel: Arc<AtomicBool>,
    task: tauri::async_runtime::JoinHandle<()>,
}
#[derive(Default)]
pub(crate) struct SourceJobs {
    running: tokio::sync::Mutex<Option<Running>>,
    status: Arc<Mutex<ImportView>>,
}
impl SourceJobs {
    pub async fn stop(&self) {
        if let Some(running) = self.running.lock().await.take() {
            running.cancel.store(true, Ordering::Release);
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
            credentials::load::<Consent>(CREDENTIAL)?.ok_or("source_approval_required")?;
        consent.require(saved, &identity)?;
        let live = self
            .status
            .lock()
            .map_err(|_| "source_status_unavailable")?
            .clone();
        if live.source_id == consent.source_id() && !live.state.is_empty() {
            return Ok(Some(live));
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
            if cursor.state == "open" {
                "paused"
            } else {
                &cursor.state
            },
            None,
        )))
    }
    pub async fn prepare(
        &self,
        base: &Path,
        saved: &SavedConnection,
    ) -> Result<ImportView, String> {
        self.stop().await;
        let identity = credentials::identity()?;
        let consent =
            credentials::load::<Consent>(CREDENTIAL)?.ok_or("source_approval_required")?;
        let approval = consent.approval(saved, &identity)?;
        if base.starts_with(approval.root()) || approval.root().starts_with(base) {
            return Err("source_staging_overlap".into());
        }
        let journal = Journal::new(base, consent.source_id())?;
        let (manifest, cursor) = if journal.root.join("manifest.json").exists()
            || journal.root.join("cursor.json").exists()
        {
            load(&journal, &identity, &consent, saved)?
        } else {
            let manifest = manifest_for(&consent, saved, &identity, base)?;
            let cursor = Cursor::new(&manifest)?;
            journal.write("manifest.json", &manifest, &identity)?;
            journal.write("cursor.json", &cursor, &identity)?;
            (manifest, cursor)
        };
        let value = view(
            &manifest,
            &cursor,
            if cursor.state == "open" {
                "paused"
            } else {
                &cursor.state
            },
            None,
        );
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
        let value = self
            .status(&base, &saved)?
            .ok_or("source_manifest_required")?;
        if matches!(value.state.as_str(), "complete" | "cancelled") {
            return Err("source_run_terminal".into());
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let status = self.status.clone();
        let mut value = value;
        value.state = "copying".into();
        value.code = None;
        *status.lock().map_err(|_| "source_status_unavailable")? = value.clone();
        // Network probes and journal I/O must not occupy an async worker.
        let task = tauri::async_runtime::spawn_blocking(move || {
            tauri::async_runtime::block_on(async move {
                let notify = |value: ImportView| {
                    if let Ok(mut current) = status.lock() {
                        *current = value.clone();
                    }
                    let _ = app.emit_to("main", "photo-import", value);
                };
                let result = async {
                    let identity = credentials::identity()?;
                    let source = credentials::load::<Consent>(CREDENTIAL)?
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
                        current(&saved, &identity, source.source_id())?;
                        let mut snapshot = network.lock().map_err(|_| "network_unknown")?;
                        if snapshot.0.elapsed() >= std::time::Duration::from_secs(1) {
                            *snapshot = (
                                std::time::Instant::now(),
                                crate::resource_policy::sample().unmetered,
                            );
                        }
                        match snapshot.1 {
                            Some(true) => Ok(()),
                            Some(false) => Err("metered_network".into()),
                            None => Err("network_unknown".into()),
                        }
                    };
                    execute(
                        &transport::client()?,
                        &crate::connection::normalize_server(&saved.server)?,
                        &saved,
                        &identity,
                        &source,
                        &journal,
                        &stop,
                        &gate,
                        &notify,
                    )
                    .await
                }
                .await;
                if let Err(code) = result {
                    if let Ok(mut current) = status.lock() {
                        if current.state == "copying" {
                            current.state = "needs-attention".into();
                            current.code = Some(code);
                            let _ = app.emit_to("main", "photo-import", current.clone());
                        }
                    }
                }
            });
        });
        *self.running.lock().await = Some(Running { cancel, task });
        Ok(value)
    }
    pub async fn approve_upload(
        &self,
        base: &Path,
        saved: &SavedConnection,
    ) -> Result<ImportView, String> {
        self.stop().await;
        let identity = credentials::identity()?;
        let consent =
            credentials::load::<Consent>(CREDENTIAL)?.ok_or("source_approval_required")?;
        let journal = Journal::new(base, consent.source_id())?;
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
        self.stop().await;
        let identity = credentials::identity()?;
        let consent =
            credentials::load::<Consent>(CREDENTIAL)?.ok_or("source_approval_required")?;
        let journal = Journal::new(base, consent.source_id())?;
        let (manifest, mut cursor) = load(&journal, &identity, &consent, saved)?;
        if !matches!(cursor.state.as_str(), "complete" | "cancelled") {
            cursor.state = if cancel { "cancelled" } else { "paused" }.into();
            journal.write("cursor.json", &cursor, &identity)?;
        }
        let client = transport::client()?;
        let base = crate::connection::normalize_server(&saved.server)?;
        let pending = AtomicBool::new(false);
        let control_gate = || current(saved, &identity, consent.source_id()).map(|_| ());
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
                cursor.upload_budget = Some(UploadBudget { used: 0, limit: 4 });
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
                assert_eq!(cursor.upload_budget.as_ref().unwrap().used, 4);
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
                assert_eq!(cursor.upload_budget.as_ref().unwrap().used, 4);
                cursor.approve_upload(&f.manifest).unwrap();
                assert_eq!(cursor.upload_budget.as_ref().unwrap().used, 4);
                assert_eq!(cursor.upload_budget.as_ref().unwrap().limit, 24);
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
                    if acknowledged { 10 } else { 14 }
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
            files: vec![SourceFile {
                relative: "nested/photo.jpg".into(),
                bytes: 8,
            }],
            total_bytes: 8,
            skipped: 0,
            availability: None,
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
                .approve(&saved, &identity, &selected.selection_id, true, |_| Ok(()))
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
            let server = Server::new(f.replies(f.receipt(), false, false));
            assert_eq!(
                f.run(&server, &|| Ok(())).await.err().as_deref(),
                Some("source_item_excluded")
            );
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
}

#[cfg(test)]
mod native_nas_tests;
