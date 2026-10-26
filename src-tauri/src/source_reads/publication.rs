//! Durable metadata-only reference publication; cache and original-read allowances stay with Job.
use super::{canonical_uuid, Job};
use crate::{
    connection::{normalize_server, DeviceIdentity, SavedConnection},
    source_import::Journal,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    server: String,
    server_id: String,
    owner_id: String,
    device_id: String,
    installation_id: String,
    source_id: String,
    scope: String,
    resource_key: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Target {
    version: String,
    sha256: String,
    bytes: u64,
    original_file_name: String,
    asset_type: String,
    file_created_at: String,
    file_modified_at: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub source_id: String,
    pub run_id: String,
    pub item_id: String,
    pub asset_id: String,
    pub owner_id: String,
    pub server_id: String,
    pub resource_id: String,
    pub version: String,
    pub sha256: String,
    pub bytes: u64,
    pub published_at: String,
    pub storage: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Phase {
    Run,
    Item,
    Publish,
    Complete,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Attempt {
    run_id: String,
    item_id: String,
    target: Target,
    phase: Phase,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Published {
    target: Target,
    receipt: Receipt,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    binding: Binding,
    asset_id: String,
    current: Option<Published>,
    pending: Option<Attempt>,
}
pub(super) struct Publication {
    journal: Journal,
    name: String,
    state: State,
}
fn valid_date(value: &str) -> bool {
    value.len() <= 40
        && time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            .is_ok()
}
impl Target {
    fn validate(&self) -> Result<(), String> {
        if !crate::native_runtime::digest_valid(&self.version, 64)
            || !crate::native_runtime::digest_valid(&self.sha256, 64)
            || self.bytes == 0
            || self.bytes > 2 * 1024 * 1024 * 1024
            || !crate::photo_sources::is_media_filename(&self.original_file_name)
            || self.original_file_name.encode_utf16().count() > 255
            || self
                .original_file_name
                .chars()
                .any(|c| c == '/' || c == '\\' || c.is_control())
            || !matches!(self.asset_type.as_str(), "IMAGE" | "VIDEO")
            || !valid_date(&self.file_created_at)
            || !valid_date(&self.file_modified_at)
        {
            return Err("source_publication_invalid".into());
        }
        Ok(())
    }
}
impl Receipt {
    fn validate(&self, binding: &Binding, asset: &str, attempt: &Attempt) -> Result<(), String> {
        if self.source_id != binding.source_id
            || self.run_id != attempt.run_id
            || self.item_id != attempt.item_id
            || self.asset_id != asset
            || self.owner_id != binding.owner_id
            || self.server_id != binding.server_id
            || self.resource_id != attempt.item_id
            || self.version != attempt.target.version
            || self.sha256 != attempt.target.sha256
            || self.bytes != attempt.target.bytes
            || self.storage != "reference"
            || !valid_date(&self.published_at)
        {
            return Err("source_reference_receipt_invalid".into());
        }
        Ok(())
    }
}
impl State {
    fn validate(&self) -> Result<(), String> {
        let b = &self.binding;
        if normalize_server(&b.server)?.as_str() != b.server
            || b.server_id.is_empty()
            || b.server_id.len() > 128
            || [
                &b.owner_id,
                &b.device_id,
                &b.installation_id,
                &b.source_id,
                &self.asset_id,
            ]
            .iter()
            .any(|s| !canonical_uuid(s))
            || [&b.scope, &b.resource_key]
                .iter()
                .any(|s| !crate::native_runtime::digest_valid(s, 64))
        {
            return Err("source_publication_invalid".into());
        }
        if let Some(current) = &self.current {
            current.target.validate()?;
            if !canonical_uuid(&current.receipt.run_id) || !canonical_uuid(&current.receipt.item_id)
            {
                return Err("source_publication_invalid".into());
            }
            current.receipt.validate(
                b,
                &self.asset_id,
                &Attempt {
                    run_id: current.receipt.run_id.clone(),
                    item_id: current.receipt.item_id.clone(),
                    target: current.target.clone(),
                    phase: Phase::Publish,
                },
            )?;
        }
        if let Some(pending) = &self.pending {
            pending.target.validate()?;
            if !canonical_uuid(&pending.run_id) || !canonical_uuid(&pending.item_id) {
                return Err("source_publication_invalid".into());
            }
            if pending.phase == Phase::Complete {
                self.current
                    .as_ref()
                    .ok_or("source_publication_invalid")?
                    .receipt
                    .validate(b, &self.asset_id, pending)?;
            }
        }
        Ok(())
    }
}
impl Publication {
    fn begin(
        root: &Path,
        binding: Binding,
        target: Target,
        identity: &DeviceIdentity,
    ) -> Result<Self, String> {
        target.validate()?;
        if !crate::native_runtime::digest_valid(&binding.resource_key, 64) {
            return Err("source_publication_invalid".into());
        }
        crate::runtime_store::private_directory(root)?;
        let journal = Journal {
            root: root.to_owned(),
        };
        let name = format!("{}.json", binding.resource_key);
        let mut state = match std::fs::symlink_metadata(root.join(&name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => State {
                binding: binding.clone(),
                asset_id: uuid::Uuid::new_v4().to_string(),
                current: None,
                pending: None,
            },
            Ok(_) => journal.read::<State>(&name, identity)?,
            Err(_) => return Err("source_journal_invalid".into()),
        };
        state.validate()?;
        if state.binding != binding {
            return Err("source_approval_changed".into());
        }
        if let Some(pending) = &state.pending {
            if pending.target != target {
                return Err("source_publication_pending".into());
            }
        } else {
            let replay = state.current.as_ref().filter(|p| p.target == target);
            if state
                .current
                .as_ref()
                .is_some_and(|p| p.target.version == target.version && p.target != target)
            {
                return Err("source_item_changed".into());
            }
            state.pending = Some(Attempt {
                run_id: replay
                    .map(|p| p.receipt.run_id.clone())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                item_id: replay
                    .map(|p| p.receipt.item_id.clone())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                target,
                phase: if replay.is_some() {
                    Phase::Publish
                } else {
                    Phase::Run
                },
            });
        }
        // Identity and the entire attempt precede every request, including an unknown prior response.
        journal.write(&name, &state, identity)?;
        Ok(Self {
            journal,
            name,
            state,
        })
    }
    fn open_recovery(
        root: &Path,
        binding: Binding,
        identity: &DeviceIdentity,
    ) -> Result<Self, String> {
        if !crate::native_runtime::digest_valid(&binding.resource_key, 64) {
            return Err("source_publication_invalid".into());
        }
        let journal = Journal {
            root: root.to_owned(),
        };
        let name = format!("{}.json", binding.resource_key);
        let state: State = journal.read(&name, identity)?;
        state.validate()?;
        if state.binding != binding {
            return Err("source_approval_changed".into());
        }
        let publication = Self {
            journal,
            name,
            state,
        };
        publication.recovery_path()?;
        Ok(publication)
    }
    pub(super) fn recover(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        source: &str,
        scope: String,
        resource_key: String,
    ) -> Result<Self, String> {
        if !canonical_uuid(source) {
            return Err("source_read_request_invalid".into());
        }
        Self::open_recovery(
            &base.join("photo-reads").join(source).join("publications"),
            Binding {
                server: normalize_server(&saved.server)?.to_string(),
                server_id: saved.server_id.clone(),
                owner_id: saved.account_id.clone(),
                device_id: saved.device_id.clone().ok_or("source_approval_changed")?,
                installation_id: identity.installation_id.clone(),
                source_id: source.into(),
                scope,
                resource_key,
            },
            identity,
        )
    }
    pub(super) fn recovery_path(&self) -> Result<String, String> {
        let (run, item) = if let Some(a) = &self.state.pending {
            if !matches!(a.phase, Phase::Publish | Phase::Complete) {
                return Err("source_publication_not_committed".into());
            }
            (&a.run_id, &a.item_id)
        } else {
            let r = &self
                .state
                .current
                .as_ref()
                .ok_or("source_publication_not_committed")?
                .receipt;
            (&r.run_id, &r.item_id)
        };
        Ok(format!("runs/{run}/items/{item}/reference"))
    }
    pub(super) fn recover_receipt(
        &mut self,
        value: Value,
        identity: &DeviceIdentity,
    ) -> Result<(), String> {
        self.recovery_path()?;
        if self
            .state
            .pending
            .as_ref()
            .is_some_and(|a| a.phase == Phase::Publish)
        {
            return self.ack(value, identity);
        }
        let receipt: Receipt =
            serde_json::from_value(value).map_err(|_| "source_reference_receipt_invalid")?;
        if self.receipt() != Some(&receipt) {
            return Err("source_reference_receipt_invalid".into());
        }
        Ok(())
    }
    pub(super) fn recovery_completion(&self) -> Option<(String, Value)> {
        let a = self
            .state
            .pending
            .as_ref()
            .filter(|a| a.phase == Phase::Complete)?;
        Some((
            format!("runs/{}", a.run_id),
            json!({"state":"complete","inventoryComplete":true}),
        ))
    }
    pub(super) fn receipt(&self) -> Option<&Receipt> {
        self.state.current.as_ref().map(|p| &p.receipt)
    }
    pub(super) fn next(&self) -> Option<(Method, String, Value)> {
        let a = self.state.pending.as_ref()?;
        let prefix = format!("runs/{}", a.run_id);
        Some(match a.phase {
            Phase::Run => (
                Method::POST,
                "runs".into(),
                json!({"id":a.run_id,"maxItems":1,"maxBytes":a.target.bytes}),
            ),
            Phase::Item => (
                Method::POST,
                format!("{prefix}/items"),
                json!({"id":a.item_id,"resourceKey":self.state.binding.resource_key,"version":a.target.version,"sha256":a.target.sha256,"bytes":a.target.bytes}),
            ),
            Phase::Publish => {
                let mut body = json!({"assetId":self.state.asset_id,"type":a.target.asset_type,"originalFileName":a.target.original_file_name,"fileCreatedAt":a.target.file_created_at,"fileModifiedAt":a.target.file_modified_at});
                if let Some(p) = self.state.current.as_ref().filter(|p| p.target != a.target) {
                    body["previous"] = json!({"resourceId":p.receipt.resource_id,"version":p.receipt.version,"sha256":p.receipt.sha256});
                }
                (
                    Method::POST,
                    format!("{prefix}/items/{}/reference", a.item_id),
                    body,
                )
            }
            Phase::Complete => (
                Method::PATCH,
                prefix,
                json!({"state":"complete","inventoryComplete":true}),
            ),
        })
    }
    pub(super) fn ack(&mut self, value: Value, identity: &DeviceIdentity) -> Result<(), String> {
        let mut state = self.state.clone();
        let a = state.pending.as_mut().ok_or("source_publication_invalid")?;
        match a.phase {
            Phase::Run | Phase::Complete => {
                if value["id"] != a.run_id
                    || value["sourceId"] != state.binding.source_id
                    || value["maxItems"] != 1
                    || value["maxBytes"] != a.target.bytes
                    || value["state"]
                        != if a.phase == Phase::Complete {
                            "complete"
                        } else {
                            "open"
                        }
                {
                    return Err("source_run_changed".into());
                }
                if a.phase == Phase::Complete {
                    state.pending = None;
                } else {
                    a.phase = Phase::Item;
                }
            }
            Phase::Item => {
                let (_, _, request) = self.next().ok_or("source_publication_invalid")?;
                if request
                    .as_object()
                    .ok_or("source_publication_invalid")?
                    .iter()
                    .any(|(k, v)| value.get(k) != Some(v))
                    || value["runId"] != a.run_id
                    || !matches!(value["state"].as_str(), Some("planned" | "verified"))
                {
                    return Err("source_item_changed".into());
                }
                a.phase = Phase::Publish;
            }
            Phase::Publish => {
                let receipt: Receipt = serde_json::from_value(value)
                    .map_err(|_| "source_reference_receipt_invalid")?;
                receipt.validate(&state.binding, &state.asset_id, a)?;
                if let Some(current) = &state.current {
                    if (current.target == a.target)
                        != (current.receipt.resource_id == receipt.resource_id)
                    {
                        return Err("source_reference_receipt_invalid".into());
                    }
                }
                state.current = Some(Published {
                    target: a.target.clone(),
                    receipt,
                });
                a.phase = Phase::Complete;
            }
        }
        state.validate()?;
        self.journal.write(&self.name, &state, identity)?;
        self.state = state;
        Ok(())
    }
}
pub(crate) fn validate_directory(
    root: &Path,
    source: &str,
    identity: &DeviceIdentity,
    count: &mut usize,
) -> Result<(), String> {
    crate::native_runtime::absolute_directory(root)?;
    let journal = Journal {
        root: root.to_owned(),
    };
    for entry in std::fs::read_dir(root).map_err(|_| "source_journal_invalid")? {
        *count += 1;
        if *count > 50_000 {
            return Err("source_inventory_partial".into());
        }
        let entry = entry.map_err(|_| "source_journal_invalid")?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("source_journal_invalid")?;
        let metadata =
            std::fs::symlink_metadata(entry.path()).map_err(|_| "source_journal_invalid")?;
        if !metadata.is_file() || metadata.is_symlink() || metadata.len() > 4 * 1024 * 1024 {
            return Err("source_journal_invalid".into());
        }
        // A crash may leave a bounded atomic-write temporary; it never contains original media.
        if name
            .strip_prefix(".checkpoint-")
            .is_some_and(canonical_uuid)
        {
            continue;
        }
        if !name
            .strip_suffix(".json")
            .is_some_and(|s| crate::native_runtime::digest_valid(s, 64))
        {
            return Err("source_journal_invalid".into());
        }
        let state: State = journal.read(name, identity)?;
        state.validate()?;
        if state.binding.source_id != source
            || state.binding.installation_id != identity.installation_id
            || name != format!("{}.json", state.binding.resource_key)
        {
            return Err("source_journal_invalid".into());
        }
    }
    Ok(())
}
impl Job {
    pub(super) fn publication(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<Publication, String> {
        self.require_owner()?;
        self.resource.validate_current(saved, identity)?;
        let parent = self.source_root.join("publications");
        crate::runtime_store::private_directory(&parent)?;
        let filename = self.resource.filename()?.to_owned();
        let lower = filename.to_ascii_lowercase();
        let video = lower
            .rsplit('.')
            .next()
            .is_some_and(|ext| matches!(ext, "mp4" | "mov" | "m4v"));
        Publication::begin(
            &parent,
            Binding {
                server: normalize_server(&saved.server)?.to_string(),
                server_id: saved.server_id.clone(),
                owner_id: saved.account_id.clone(),
                device_id: saved.device_id.clone().ok_or("source_approval_changed")?,
                installation_id: identity.installation_id.clone(),
                source_id: self.resource.source_id().into(),
                scope: self.resource.scope_fingerprint(),
                resource_key: self.resource.resource_key(),
            },
            Target {
                version: self.resource.version(),
                sha256: self.resource.sha256.clone(),
                bytes: self.resource.bytes,
                original_file_name: filename,
                asset_type: if video { "VIDEO" } else { "IMAGE" }.into(),
                file_created_at: crate::copy_upload::date(self.resource.file_created_at_ms)?,
                file_modified_at: crate::copy_upload::date(self.resource.file_modified_at_ms)?,
            },
            identity,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    struct Fixture {
        root: std::path::PathBuf,
        identity: crate::connection::DeviceIdentity,
        binding: Binding,
        target: Target,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-publication-{}", uuid::Uuid::new_v4()));
            crate::runtime_store::private_directory(&root).unwrap();
            Self {
                root: root.join("record"),
                identity: crate::connection::DeviceIdentity::generate(),
                binding: Binding {
                    server: "https://server.test/".into(),
                    server_id: "server".into(),
                    owner_id: "11111111-1111-4111-8111-111111111111".into(),
                    device_id: "22222222-2222-4222-8222-222222222222".into(),
                    installation_id: "33333333-3333-4333-8333-333333333333".into(),
                    source_id: "44444444-4444-4444-8444-444444444444".into(),
                    scope: "a".repeat(64),
                    resource_key: "b".repeat(64),
                },
                target: Target {
                    version: "c".repeat(64),
                    sha256: "d".repeat(64),
                    bytes: 10,
                    original_file_name: "original.jpg".into(),
                    asset_type: "IMAGE".into(),
                    file_created_at: "2026-10-25T01:00:00.000Z".into(),
                    file_modified_at: "2026-10-25T02:00:00.000Z".into(),
                },
            }
        }
        fn open(&self) -> Publication {
            Publication::begin(
                &self.root,
                self.binding.clone(),
                self.target.clone(),
                &self.identity,
            )
            .unwrap()
        }
        fn advance_to_publish(&self, p: &mut Publication) {
            let (_, _, run) = p.next().unwrap();
            p.ack(json!({"id":run["id"],"sourceId":self.binding.source_id,"maxItems":1,"maxBytes":10,"state":"open"}), &self.identity).unwrap();
            let (_, _, item) = p.next().unwrap();
            let mut reply = item;
            reply["runId"] = run["id"].clone();
            reply["state"] = json!("planned");
            p.ack(reply, &self.identity).unwrap();
        }
        fn response(&self, p: &Publication) -> serde_json::Value {
            let a = p.state.pending.as_ref().unwrap();
            json!({"sourceId":self.binding.source_id,"runId":a.run_id,"itemId":a.item_id,
                "assetId":p.state.asset_id,"ownerId":self.binding.owner_id,"serverId":"server",
                "resourceId":a.item_id,"version":self.target.version,
                "sha256":self.target.sha256,"bytes":10,"publishedAt":"2026-10-25T03:00:00.000Z","storage":"reference"})
        }
        fn complete(&self, p: &mut Publication) {
            let run = p.state.pending.as_ref().unwrap().run_id.clone();
            p.ack(json!({"id":run,"sourceId":self.binding.source_id,"maxItems":1,"maxBytes":10,"state":"complete"}), &self.identity).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.root.parent().unwrap());
        }
    }
    #[test]
    fn receipt_recovery_never_allocates_or_reposts_an_attempt() {
        let f = Fixture::new();
        assert!(Publication::open_recovery(&f.root, f.binding.clone(), &f.identity).is_err());
        assert!(!f.root.exists());
        let mut p = f.open();
        assert!(p.recovery_path().is_err());
        f.advance_to_publish(&mut p);
        let before = p.next().unwrap();
        let response = f.response(&p);
        drop(p);
        let mut p = Publication::open_recovery(&f.root, f.binding.clone(), &f.identity).unwrap();
        assert_eq!(p.next().unwrap(), before);
        assert_eq!(p.recovery_path().unwrap(), before.1);
        assert!(p.recovery_completion().is_none());
        let mut foreign = response.clone();
        foreign["ownerId"] = json!("66666666-6666-4666-8666-666666666666");
        assert!(p.recover_receipt(foreign, &f.identity).is_err());
        assert_eq!(p.next().unwrap(), before);
        p.recover_receipt(response.clone(), &f.identity).unwrap();
        assert_eq!(p.recovery_path().unwrap(), before.1);
        let completion = p.recovery_completion().unwrap();
        assert_eq!(
            completion.1,
            json!({"state":"complete","inventoryComplete":true})
        );
        // An unknown completion reply is recovered with GET before PATCH, using the same receipt.
        drop(p);
        let mut p = Publication::open_recovery(&f.root, f.binding.clone(), &f.identity).unwrap();
        let mut changed = response.clone();
        changed["publishedAt"] = json!("2026-10-25T04:00:00.000Z");
        assert!(p.recover_receipt(changed, &f.identity).is_err());
        p.recover_receipt(response.clone(), &f.identity).unwrap();
        f.complete(&mut p);
        drop(p);
        let mut p = Publication::open_recovery(&f.root, f.binding.clone(), &f.identity).unwrap();
        assert!(p.next().is_none());
        assert_eq!(p.recovery_path().unwrap(), before.1);
        p.recover_receipt(response, &f.identity).unwrap();
        assert!(p.next().is_none());
        assert!(p.recovery_completion().is_none());
        let mut foreign = f.binding.clone();
        foreign.scope = "f".repeat(64);
        assert!(Publication::open_recovery(&f.root, foreign, &f.identity).is_err());
        assert!(Publication::open_recovery(
            &f.root,
            f.binding.clone(),
            &DeviceIdentity::generate()
        )
        .is_err());
    }
    #[test]
    fn quota_metadata_validation_accepts_only_bound_journals_and_bounded_temporaries() {
        let mut f = Fixture::new();
        f.binding.installation_id = f.identity.installation_id.clone();
        let p = f.open();
        let check = || validate_directory(&f.root, &f.binding.source_id, &f.identity, &mut 0);
        check().unwrap();
        std::fs::write(
            f.root.join(format!(".checkpoint-{}", uuid::Uuid::new_v4())),
            b"partial",
        )
        .unwrap();
        check().unwrap();
        assert!(validate_directory(
            &f.root,
            "66666666-6666-4666-8666-666666666666",
            &f.identity,
            &mut 0
        )
        .is_err());
        std::fs::write(f.root.join("original"), b"media").unwrap();
        assert!(check().is_err());
        std::fs::remove_file(f.root.join("original")).unwrap();
        std::fs::create_dir(f.root.join("nested")).unwrap();
        assert!(check().is_err());
        std::fs::remove_dir(f.root.join("nested")).unwrap();
        let mut foreign = p.state.clone();
        foreign.binding.installation_id = "66666666-6666-4666-8666-666666666666".into();
        p.journal.write(&p.name, &foreign, &f.identity).unwrap();
        assert!(check().is_err());
        std::fs::write(f.root.join(&p.name), b"unsigned").unwrap();
        assert!(check().is_err());
    }
    #[test]
    fn empty_directory_and_interrupted_first_write_can_restart_without_a_request() {
        let f = Fixture::new();
        crate::runtime_store::private_directory(&f.root).unwrap();
        std::fs::write(
            f.root.join(".checkpoint-interrupted"),
            b"partial prior write",
        )
        .unwrap();
        let p = f.open();
        assert_eq!(p.next().unwrap().1, "runs");
        assert!(p.receipt().is_none());
        let before = p.next().unwrap();
        drop(p);
        assert_eq!(f.open().next().unwrap(), before);
    }
    #[cfg(unix)]
    #[test]
    fn failed_initial_checkpoint_is_retryable_before_any_request() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        crate::runtime_store::private_directory(&f.root).unwrap();
        std::fs::set_permissions(&f.root, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = Publication::begin(&f.root, f.binding.clone(), f.target.clone(), &f.identity);
        std::fs::set_permissions(&f.root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result.err().as_deref(), Some("source_journal_write_failed"));
        assert_eq!(f.open().next().unwrap().1, "runs");
    }
    #[test]
    fn wrong_run_and_item_echo_leave_the_last_request_pending() {
        let f = Fixture::new();
        let mut p = f.open();
        let before = p.next().unwrap();
        let mut run = before.2.clone();
        run["sourceId"] = json!(f.binding.source_id);
        run["state"] = json!("open");
        let mut wrong = run.clone();
        wrong["maxBytes"] = json!(11);
        assert!(p.ack(wrong, &f.identity).is_err());
        assert_eq!(f.open().next().unwrap(), before);
        p.ack(run, &f.identity).unwrap();
        let before = p.next().unwrap();
        let mut wrong = before.2.clone();
        wrong["runId"] = json!("66666666-6666-4666-8666-666666666666");
        wrong["state"] = json!("planned");
        assert!(p.ack(wrong, &f.identity).is_err());
        assert_eq!(f.open().next().unwrap(), before);
    }
    #[test]
    fn interrupted_request_reopens_with_the_same_durably_saved_ids() {
        let f = Fixture::new();
        let mut p = f.open();
        let run = p.next().unwrap();
        assert_eq!(run.0, reqwest::Method::POST);
        assert_eq!(run.1, "runs");
        assert_eq!(run.2["maxItems"], 1);
        assert_eq!(run.2["maxBytes"], 10);
        assert!(super::super::canonical_uuid(run.2["id"].as_str().unwrap()));
        let asset = p.state.asset_id.clone();
        drop(p);
        p = f.open();
        assert_eq!(p.state.asset_id, asset);
        assert_eq!(p.next().unwrap(), run);
        f.advance_to_publish(&mut p);
        let request = p.next().unwrap();
        assert_eq!(request.2["assetId"], asset);
        assert_eq!(request.2["type"], "IMAGE");
        assert_eq!(request.2["originalFileName"], "original.jpg");
        assert!(request.2.get("previous").is_none());
        drop(p);
        assert_eq!(f.open().next().unwrap(), request);
    }
    #[test]
    fn unknown_pending_target_cannot_be_replaced_or_reset() {
        let f = Fixture::new();
        let p = f.open();
        let before = p.next().unwrap();
        drop(p);
        let mut target = f.target.clone();
        target.version = "e".repeat(64);
        assert_eq!(
            Publication::begin(&f.root, f.binding.clone(), target, &f.identity)
                .err()
                .as_deref(),
            Some("source_publication_pending")
        );
        assert_eq!(f.open().next().unwrap(), before);
    }
    #[test]
    fn foreign_or_malformed_receipt_never_advances_the_attempt() {
        let f = Fixture::new();
        let mut p = f.open();
        f.advance_to_publish(&mut p);
        let before = p.next().unwrap();
        let response = f.response(&p);
        for (key, value) in [
            ("sourceId", json!("66666666-6666-4666-8666-666666666666")),
            ("runId", json!("66666666-6666-4666-8666-666666666666")),
            ("itemId", json!("66666666-6666-4666-8666-666666666666")),
            ("assetId", json!("66666666-6666-4666-8666-666666666666")),
            ("ownerId", json!("66666666-6666-4666-8666-666666666666")),
            ("serverId", json!("other")),
            ("resourceId", json!("invalid")),
            ("resourceId", json!("66666666-6666-4666-8666-666666666666")),
            ("version", json!("e".repeat(64))),
            ("sha256", json!("e".repeat(64))),
            ("bytes", json!(11)),
            ("storage", json!("managed")),
            ("publishedAt", json!("invalid")),
        ] {
            let mut bad = response.clone();
            bad[key] = value;
            assert!(p.ack(bad, &f.identity).is_err(), "{key}");
            assert!(p.receipt().is_none());
            assert_eq!(f.open().next().unwrap(), before);
        }
    }
    #[test]
    fn receipt_survives_unknown_completion_and_next_version_uses_exact_previous() {
        let mut f = Fixture::new();
        let mut p = f.open();
        f.advance_to_publish(&mut p);
        p.ack(f.response(&p), &f.identity).unwrap();
        let asset = p.receipt().unwrap().asset_id.clone();
        let previous_resource = p.receipt().unwrap().resource_id.clone();
        assert_eq!(p.next().unwrap().0, reqwest::Method::PATCH);
        drop(p);
        p = f.open();
        assert_eq!(p.receipt().unwrap().asset_id, asset);
        f.complete(&mut p);
        assert!(p.next().is_none());
        drop(p);
        p = f.open();
        assert!(p.next().unwrap().1.ends_with("/reference"));
        assert!(p.next().unwrap().2.get("previous").is_none());
        p.ack(f.response(&p), &f.identity).unwrap();
        f.complete(&mut p);
        drop(p);
        f.target.version = "e".repeat(64);
        f.target.sha256 = "f".repeat(64);
        p = f.open();
        f.advance_to_publish(&mut p);
        let (_, _, request) = p.next().unwrap();
        assert_eq!(request["assetId"], asset);
        assert_eq!(
            request["previous"],
            json!({"resourceId":previous_resource,"version":"c".repeat(64),"sha256":"d".repeat(64)})
        );
        let reply = f.response(&p);
        let mut bad = reply.clone();
        bad["resourceId"] = json!(previous_resource);
        assert!(p.ack(bad, &f.identity).is_err());
        p.ack(reply, &f.identity).unwrap();
        f.complete(&mut p);
        assert_eq!(p.receipt().unwrap().version, "e".repeat(64));
    }
    #[test]
    fn source_owner_scope_and_installation_changes_cannot_reuse_a_journal() {
        let f = Fixture::new();
        drop(f.open());
        for field in [
            "ownerId",
            "sourceId",
            "scope",
            "deviceId",
            "installationId",
            "serverId",
            "server",
            "resourceKey",
        ] {
            let mut value = serde_json::to_value(&f.binding).unwrap();
            value[field] = json!("changed");
            let binding = serde_json::from_value(value).unwrap();
            assert!(
                Publication::begin(&f.root, binding, f.target.clone(), &f.identity).is_err(),
                "{field}"
            );
        }
        let path = f.root.join(format!("{}.json", f.binding.resource_key));
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["value"]["assetId"] = json!("66666666-6666-4666-8666-666666666666");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            Publication::begin(&f.root, f.binding.clone(), f.target.clone(), &f.identity).is_err()
        );
    }
}
