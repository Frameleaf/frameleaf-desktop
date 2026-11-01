//! Picker-issued, photo-session-bound folder permission, stored only in the OS credential store.
use crate::{
    connection::{normalize_server, DeviceIdentity, SavedConnection},
    copy_source::CopyApproval,
    photo_sources::{self, FolderInventory},
    transport,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Mutex};

pub const CREDENTIAL: &str = "photo-source-copy";
#[derive(Default)]
pub struct SourceConsent {
    pending: Mutex<Pending>,
}
#[derive(Default)]
struct Pending {
    generation: u64,
    selected: Option<(String, PathBuf)>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedFolder {
    pub selection_id: String,
    #[serde(flatten)]
    pub inventory: FolderInventory,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Consent {
    approval: CopyApproval,
    session_signature: String,
    name: String,
    allow_download: bool,
    pub registered: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentView {
    id: String,
    name: String,
    path: String,
    allow_download: bool,
    registered: bool,
}
impl SourceConsent {
    pub fn generation(&self) -> Result<u64, String> {
        Ok(self
            .pending
            .lock()
            .map_err(|_| "source_selection_unavailable")?
            .generation)
    }
    pub fn clear(&self) -> Result<(), String> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| "source_selection_unavailable")?;
        pending.generation = pending
            .generation
            .checked_add(1)
            .ok_or("source_selection_unavailable")?;
        pending.selected = None;
        Ok(())
    }
    pub fn select(&self, generation: u64, path: PathBuf) -> Result<SelectedFolder, String> {
        let inventory = photo_sources::inventory(&path, 10_000)?;
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| "source_selection_unavailable")?;
        if generation != pending.generation {
            return Err("source_selection_changed".into());
        }
        let selection_id = uuid::Uuid::new_v4().to_string();
        pending.selected = Some((selection_id.clone(), path));
        Ok(SelectedFolder {
            selection_id,
            inventory,
        })
    }
    pub fn approve(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        selection: &str,
        allow_download: bool,
        persist: impl FnOnce(&Consent) -> Result<(), String>,
    ) -> Result<Consent, String> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| "source_selection_unavailable")?;
        let path = &pending
            .selected
            .as_ref()
            .filter(|(id, _)| id == selection)
            .ok_or("source_selection_changed")?
            .1;
        let approval = CopyApproval::approve(
            saved,
            identity,
            path,
            2 * 1024 * 1024 * 1024,
            allow_download,
        )?;
        let name = source_label(
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or("source_folder_name_invalid")?,
        );
        let consent = Consent {
            approval,
            session_signature: session_signature(saved, identity),
            name,
            allow_download,
            registered: false,
        };
        persist(&consent)?;
        pending.selected = None;
        Ok(consent)
    }
}
// Match the server's trimmed, control-free 128 UTF-16-unit label without changing the root path.
fn source_label(raw: &str) -> String {
    let mut units = 0;
    let name: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take_while(|c| {
            units += c.len_utf16();
            units <= 128
        })
        .collect();
    let name = name.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if name.is_empty() {
        "Photo folder".into()
    } else {
        name.into()
    }
}
fn session_signature(saved: &SavedConnection, identity: &DeviceIdentity) -> String {
    identity.sign(&format!(
        "frameleaf-desktop/photo-source-session/v1\n{}",
        saved.token
    ))
}
impl Consent {
    pub(crate) fn approval(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<&CopyApproval, String> {
        self.require(saved, identity)?;
        if !self.registered || !self.allow_download {
            return Err("source_approval_required".into());
        }
        Ok(&self.approval)
    }
    pub(crate) fn source_id(&self) -> &str {
        self.approval.source_id()
    }
    pub fn require(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<(), String> {
        self.approval.validate_current(saved, identity)?;
        if self.session_signature != session_signature(saved, identity) {
            return Err("source_photo_session_changed".into());
        }
        Ok(())
    }
    pub fn view(&self) -> ConsentView {
        ConsentView {
            id: self.approval.source_id().into(),
            name: self.name.clone(),
            path: self.approval.root().to_string_lossy().into(),
            allow_download: self.allow_download,
            registered: self.registered,
        }
    }
    fn request(&self, saved: &SavedConnection) -> Value {
        json!({"id":self.approval.source_id(),"deviceId":saved.device_id,"kind":"folder","mode":"copy","name":source_label(&self.name),"scopeFingerprint":self.approval.fingerprint()})
    }
    fn accept(&self, saved: &SavedConnection, ack: &Value) -> Result<(), String> {
        let request = self.request(saved);
        if request
            .as_object()
            .unwrap()
            .iter()
            .any(|(key, value)| ack.get(key) != Some(value))
            || ack.get("revokedAt") != Some(&Value::Null)
        {
            return Err("source_registration_response_invalid".into());
        }
        Ok(())
    }
    pub async fn register(
        &mut self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<(), String> {
        self.require(saved, identity)?;
        let client = transport::client()?;
        transport::capabilities(&client, saved)
            .await?
            .ok_or("source_server_update_required")?;
        let base = normalize_server(&saved.server)?;
        let response = client
            .post(base.join("api/photo-sources").unwrap())
            .bearer_auth(&saved.token)
            .json(&self.request(saved))
            .send()
            .await
            .map_err(|_| "source_registration_unavailable")?;
        let ack: Value = transport::json(response).await?;
        self.accept(saved, &ack)?;
        self.name = source_label(&self.name);
        self.registered = true;
        Ok(())
    }
    pub async fn revoke(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<(), String> {
        self.require(saved, identity)?;
        let client = transport::client()?;
        transport::capabilities(&client, saved)
            .await?
            .ok_or("source_server_update_required")?;
        let response = client
            .delete(
                normalize_server(&saved.server)?
                    .join(&format!("api/photo-sources/{}", self.approval.source_id()))
                    .unwrap(),
            )
            .bearer_auth(&saved.token)
            .send()
            .await
            .map_err(|_| "source_revocation_unavailable")?;
        if response.status().as_u16() != 204 {
            return Err("source_revocation_unavailable".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    fn saved() -> SavedConnection {
        SavedConnection {
            server: "https://nas.test/".into(),
            server_id: "nas".into(),
            account_id: "owner".into(),
            name: "Fixture".into(),
            token: "synthetic-photo-session".into(),
            device_name: "Fixture".into(),
            mode: "client-worker".into(),
            device_id: Some("device".into()),
        }
    }
    #[test]
    fn picker_handles_expire_on_signout_and_failed_secure_persistence_keeps_the_selection_retryable(
    ) {
        let root = std::env::temp_dir().join(format!("frameleaf-consent-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let state = SourceConsent::default();
        let identity = DeviceIdentity::generate();
        let generation = state.generation().unwrap();
        let selected = state.select(generation, root.clone()).unwrap();
        let called = AtomicBool::new(false);
        assert_eq!(
            state
                .approve(&saved(), &identity, "forged", true, |_| {
                    called.store(true, Ordering::Release);
                    Ok(())
                })
                .err()
                .as_deref(),
            Some("source_selection_changed")
        );
        assert!(!called.load(Ordering::Acquire));
        assert!(state
            .approve(&saved(), &identity, &selected.selection_id, true, |_| Err(
                "credential_store_locked_or_unavailable".into()
            ))
            .is_err());
        let consent = state
            .approve(
                &saved(),
                &identity,
                &selected.selection_id,
                true,
                |_| Ok(()),
            )
            .unwrap();
        consent.require(&saved(), &identity).unwrap();
        assert!(state
            .approve(
                &saved(),
                &identity,
                &selected.selection_id,
                true,
                |_| Ok(())
            )
            .is_err());
        let mut replaced = saved();
        replaced.token = "new-session".into();
        assert!(consent.require(&replaced, &identity).is_err());
        replaced = saved();
        replaced.account_id = "other-owner".into();
        assert!(consent.require(&replaced, &identity).is_err());
        state.clear().unwrap();
        assert!(state.select(generation, root.clone()).is_err());
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn registration_requires_an_exact_source_echo_and_never_discloses_the_local_root() {
        let root = std::env::temp_dir().join(format!("frameleaf-consent-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let identity = DeviceIdentity::generate();
        let state = SourceConsent::default();
        let selected = state
            .select(state.generation().unwrap(), root.clone())
            .unwrap();
        let consent = state
            .approve(
                &saved(),
                &identity,
                &selected.selection_id,
                true,
                |_| Ok(()),
            )
            .unwrap();
        let request = consent.request(&saved());
        assert!(!request.to_string().contains(root.to_str().unwrap()));
        let mut ack = request.clone();
        ack["revokedAt"] = serde_json::Value::Null;
        assert!(consent.accept(&saved(), &ack).is_ok());
        for field in ["id", "deviceId", "kind", "mode", "name", "scopeFingerprint"] {
            let mut altered = ack.clone();
            altered[field] = serde_json::json!("changed");
            assert!(consent.accept(&saved(), &altered).is_err());
        }
        ack["revokedAt"] = serde_json::json!("2026-10-16T00:00:00Z");
        assert!(consent.accept(&saved(), &ack).is_err());
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn folder_labels_match_the_servers_trimmed_bounded_name_contract() {
        let base = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("frameleaf-label-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir(base.join(" Photos ")).unwrap();
        let root = std::fs::canonicalize(base.join(" Photos ")).unwrap();
        let identity = DeviceIdentity::generate();
        let state = SourceConsent::default();
        let selected = state.select(state.generation().unwrap(), root).unwrap();
        let consent = state
            .approve(
                &saved(),
                &identity,
                &selected.selection_id,
                true,
                |_| Ok(()),
            )
            .unwrap();
        assert_eq!(consent.request(&saved())["name"], "Photos");
        assert_eq!(source_label("\u{0001} Photos \n"), "Photos");
        assert_eq!(source_label(&"📷".repeat(100)).encode_utf16().count(), 128);
        assert_eq!(source_label("   "), "Photo folder");
        let mut legacy = consent;
        legacy.name = " Photos ".into();
        assert_eq!(legacy.request(&saved())["name"], "Photos");
        std::fs::remove_dir_all(base).unwrap();
    }
}
