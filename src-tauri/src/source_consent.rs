//! Picker-issued, photo-session-bound folder permission, stored only in the OS credential store.
use crate::{
    connection::{normalize_server, DeviceIdentity, SavedConnection},
    copy_source::CopyApproval,
    credentials,
    photo_sources::{self, FolderInventory},
    transport,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Mutex};

pub const CREDENTIAL: &str = "photo-source-copy";
const REFERENCE_CREDENTIAL: &str = "photo-source-reference-record";
fn registration_path(photos: bool) -> &'static str {
    if photos {
        "api/photo-sources/apple-photos"
    } else {
        "api/photo-sources"
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceMode {
    #[default]
    Copy,
    Reference,
}
#[derive(Default)]
pub struct SourceConsent {
    pending: Mutex<Pending>,
}
#[derive(Default)]
struct Pending {
    generation: u64,
    selected: Option<(String, PathBuf)>,
    photos: Option<(String, crate::apple_photos::Selection)>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedFolder {
    pub kind: String,
    pub selection_id: String,
    #[serde(flatten)]
    pub inventory: FolderInventory,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Consent {
    #[serde(default)]
    pub(crate) mode: SourceMode,
    approval: CopyApproval,
    session_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intent_signature: Option<String>,
    name: String,
    allow_download: bool,
    pub registered: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentView {
    mode: SourceMode,
    id: String,
    name: String,
    path: String,
    kind: String,
    allow_photos_hydration: bool,
    allow_download: bool,
    registered: bool,
    reconnect_required: bool,
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
        pending.photos = None;
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
        pending.photos = None;
        pending.selected = Some((selection_id.clone(), path));
        Ok(SelectedFolder {
            kind: "folder".into(),
            selection_id,
            inventory,
        })
    }
    pub fn select_photos(
        &self,
        generation: u64,
        photos: crate::apple_photos::Selection,
    ) -> Result<SelectedFolder, String> {
        photos.validate()?;
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| "source_selection_unavailable")?;
        if generation != pending.generation {
            return Err("source_selection_changed".into());
        }
        let selection_id = uuid::Uuid::new_v4().to_string();
        let inventory = FolderInventory {
            path: format!(
                "Apple Photos: {} selected recent assets, {} original resources",
                photos.assets,
                photos.resources.len()
            ),
            photos: photos.resources.len() as u64,
            logical_bytes: photos.resources.len() as u64 * crate::apple_photos::RESOURCE_CEILING,
            skipped: 0,
            truncated: false,
            availability: Default::default(),
        };
        pending.selected = None;
        pending.photos = Some((selection_id.clone(), photos));
        Ok(SelectedFolder {
            kind: "apple-photos".into(),
            selection_id,
            inventory,
        })
    }
    #[cfg(test)]
    pub fn approve(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        selection: &str,
        allow_download: bool,
        persist: impl FnOnce(&Consent) -> Result<(), String>,
    ) -> Result<Consent, String> {
        self.approve_with_hydration(
            saved,
            identity,
            selection,
            SourceMode::Copy,
            allow_download,
            false,
            persist,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn approve_with_hydration(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        selection: &str,
        mode: SourceMode,
        allow_download: bool,
        allow_photos_hydration: bool,
        persist: impl FnOnce(&Consent) -> Result<(), String>,
    ) -> Result<Consent, String> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| "source_selection_unavailable")?;
        let (approval, name) = if let Some((id, photos)) = &pending.photos {
            if id != selection {
                return Err("source_selection_changed".into());
            }
            let mut photos = photos.clone();
            photos.allow_hydration = allow_photos_hydration;
            (
                CopyApproval::approve_photos(saved, identity, photos, allow_download)?,
                "Apple Photos originals".into(),
            )
        } else {
            let path = &pending
                .selected
                .as_ref()
                .filter(|(id, _)| id == selection)
                .ok_or("source_selection_changed")?
                .1;
            (
                CopyApproval::approve(
                    saved,
                    identity,
                    path,
                    2 * 1024 * 1024 * 1024,
                    allow_download,
                )?,
                source_label(
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .ok_or("source_folder_name_invalid")?,
                ),
            )
        };
        let mut consent = Consent {
            mode,
            approval,
            session_signature: session_signature(saved, identity, mode),
            intent_signature: None,
            name,
            allow_download,
            registered: false,
        };
        consent.intent_signature = Some(consent.signed_intent(identity)?);
        persist(&consent)?;
        pending.selected = None;
        pending.photos = None;
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
fn session_signature(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    mode: SourceMode,
) -> String {
    // Preserve legacy copy credentials; a reference grant signs a distinct, explicit intent.
    let domain = match mode {
        SourceMode::Copy => "frameleaf-desktop/photo-source-session/v1",
        SourceMode::Reference => "frameleaf-desktop/photo-source-session/v2\nreference",
    };
    identity.sign(&format!("{domain}\n{}", saved.token))
}

impl Consent {
    fn signed_intent(&self, identity: &DeviceIdentity) -> Result<String, String> {
        let value = serde_json_canonicalizer::to_vec(&(
            self.mode,
            self.approval.fingerprint(),
            source_label(&self.name),
            self.allow_download,
        ))
        .map_err(|_| "source_approval_invalid")?;
        Ok(identity.sign(&format!(
            "frameleaf-desktop/photo-source-consent/v1\n{}",
            String::from_utf8(value).map_err(|_| "source_approval_invalid")?
        )))
    }
    fn require_bound_session(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<(), String> {
        self.approval.validate(saved, identity)?;
        if self
            .intent_signature
            .as_ref()
            .is_some_and(|signature| self.signed_intent(identity).as_ref() != Ok(signature))
        {
            return Err("source_approval_invalid".into());
        }
        if self.session_signature != session_signature(saved, identity, self.mode) {
            return Err("source_photo_session_changed".into());
        }
        Ok(())
    }
    pub(crate) fn reconnect_candidate(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<Self, String> {
        if self.mode != SourceMode::Reference {
            return Err("source_reference_mode_required".into());
        }
        self.approval.validate(saved, identity)?;
        if self.intent_signature.as_ref() != Some(&self.signed_intent(identity)?) {
            return Err("source_reference_reapproval_required".into());
        }
        let mut next = self.clone();
        next.session_signature = session_signature(saved, identity, self.mode);
        next.registered = false;
        Ok(next)
    }
    pub(crate) fn revocation_candidate(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<Self, String> {
        if self.require_bound_session(saved, identity).is_ok() {
            return Ok(self.clone());
        }
        self.reconnect_candidate(saved, identity)
    }
    fn reference_record(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<Option<Self>, String> {
        if self.mode != SourceMode::Reference {
            return Ok(None);
        }
        let mut record = self.reconnect_candidate(saved, identity)?;
        // An inactive record retains identity and consent, never a live photo-session grant.
        record.session_signature.clear();
        Ok(Some(record))
    }
    pub(crate) fn session_view(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<ConsentView, String> {
        match self.require(saved, identity) {
            Ok(()) => Ok(self.view()),
            Err(code)
                if code == "source_photo_session_changed" && self.mode == SourceMode::Reference =>
            {
                let mut view = self.reconnect_candidate(saved, identity)?.view();
                view.reconnect_required = true;
                Ok(view)
            }
            Err(code) => Err(code),
        }
    }
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
    pub(crate) fn copy_approval(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<&CopyApproval, String> {
        let approval = self.approval(saved, identity)?;
        if self.mode != SourceMode::Copy {
            return Err("source_copy_mode_required".into());
        }
        Ok(approval)
    }
    pub(crate) fn reference_approval(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<&CopyApproval, String> {
        let approval = self.approval(saved, identity)?;
        if self.mode != SourceMode::Reference {
            return Err("source_reference_mode_required".into());
        }
        Ok(approval)
    }
    /// Metadata reconciliation grants neither provider access nor an original-read capability.
    pub(crate) fn reference_metadata_scope(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<String, String> {
        self.require_bound_session(saved, identity)?;
        if self.mode != SourceMode::Reference || !self.registered || !self.allow_download {
            return Err("source_approval_required".into());
        }
        Ok(self.approval.fingerprint())
    }
    pub(crate) fn reference_control_approval(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<&CopyApproval, String> {
        self.reference_metadata_scope(saved, identity)?;
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
        self.require_bound_session(saved, identity)?;
        self.approval.validate_current(saved, identity)
    }
    pub fn view(&self) -> ConsentView {
        ConsentView {
            mode: self.mode,
            id: self.approval.source_id().into(),
            name: self.name.clone(),
            path: if self.approval.is_photos() {
                "System Photo Library (selected originals)".into()
            } else {
                self.approval.root().to_string_lossy().into()
            },
            kind: self.approval.kind().into(),
            allow_photos_hydration: self.approval.allows_photos_hydration(),
            allow_download: self.allow_download,
            registered: self.registered,
            reconnect_required: false,
        }
    }
    fn request(&self, saved: &SavedConnection) -> Value {
        json!({"id":self.approval.source_id(),"deviceId":saved.device_id,"kind":self.approval.kind(),"mode":self.mode,"name":source_label(&self.name),"scopeFingerprint":self.approval.fingerprint()})
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
        if self.mode == SourceMode::Reference {
            transport::reference_capabilities(&client, saved).await?;
        } else {
            transport::capabilities(&client, saved)
                .await?
                .ok_or("source_server_update_required")?;
        }
        let base = normalize_server(&saved.server)?;
        let response = client
            .post(
                base.join(registration_path(self.approval.is_photos()))
                    .unwrap(),
            )
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
        self.require_bound_session(saved, identity)?;
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

/// The inactive record is ignored by original readers and scoped before any path reaches the UI.
pub(crate) fn stored(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
) -> Result<Option<Consent>, String> {
    if let Some(active) = credentials::load::<Consent>(CREDENTIAL)? {
        return Ok(Some(active));
    }
    Ok(credentials::load::<Consent>(REFERENCE_CREDENTIAL)?
        .filter(|record| record.reconnect_candidate(saved, identity).is_ok()))
}
pub(crate) fn persist(
    consent: &Consent,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
) -> Result<(), String> {
    consent.require(saved, identity)?;
    if let Some(record) = consent.reference_record(saved, identity)? {
        credentials::save(REFERENCE_CREDENTIAL, &record)?;
    }
    credentials::save(CREDENTIAL, consent)
}
pub(crate) fn forget_reference(
    source: &str,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
) -> Result<(), String> {
    if let Some(record) = credentials::load::<Consent>(REFERENCE_CREDENTIAL)? {
        if record.source_id() == source && record.reconnect_candidate(saved, identity).is_ok() {
            credentials::delete(REFERENCE_CREDENTIAL)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    #[test]
    fn apple_registration_uses_the_additive_endpoint_and_preserves_the_folder_route() {
        assert_eq!(registration_path(false), "api/photo-sources");
        assert_eq!(registration_path(true), "api/photo-sources/apple-photos");
    }
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
    fn copy_mode_round_trips_explicit_and_legacy_credentials() {
        let root =
            std::env::temp_dir().join(format!("frameleaf-consent-mode-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let identity = DeviceIdentity::generate();
        let state = SourceConsent::default();
        let selected = state
            .select(state.generation().unwrap(), root.clone())
            .unwrap();
        let mut consent = state
            .approve(
                &saved(),
                &identity,
                &selected.selection_id,
                true,
                |_| Ok(()),
            )
            .unwrap();
        consent.registered = true;
        let mut value = serde_json::to_value(&consent).unwrap();
        value["mode"] = json!("copy");
        let explicit: Consent = serde_json::from_value(value.clone()).unwrap();
        explicit.copy_approval(&saved(), &identity).unwrap();
        assert_eq!(
            serde_json::to_value(explicit.view()).unwrap()["mode"],
            "copy"
        );
        value.as_object_mut().unwrap().remove("mode");
        value.as_object_mut().unwrap().remove("intentSignature");
        let legacy: Consent = serde_json::from_value(value).unwrap();
        legacy.copy_approval(&saved(), &identity).unwrap();
        assert_eq!(serde_json::to_value(legacy.view()).unwrap()["mode"], "copy");
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn reference_permission_is_explicit_signed_and_never_grants_copy_authority() {
        let root = std::env::temp_dir().join(format!(
            "frameleaf-consent-reference-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let identity = DeviceIdentity::generate();
        let picker = SourceConsent::default();
        let selected = picker
            .select(picker.generation().unwrap(), root.clone())
            .unwrap();
        let mut consent = picker
            .approve_with_hydration(
                &saved(),
                &identity,
                &selected.selection_id,
                SourceMode::Reference,
                true,
                false,
                |_| Ok(()),
            )
            .unwrap();
        consent.require(&saved(), &identity).unwrap();
        assert_eq!(consent.mode, SourceMode::Reference);
        let mut ack = consent.request(&saved());
        assert_eq!(ack["mode"], "reference");
        assert!(!ack.to_string().contains(root.to_str().unwrap()));
        ack["revokedAt"] = Value::Null;
        consent.accept(&saved(), &ack).unwrap();
        ack["mode"] = json!("copy");
        assert!(consent.accept(&saved(), &ack).is_err());
        assert!(consent
            .reference_metadata_scope(&saved(), &identity)
            .is_err());
        consent.registered = true;
        consent.reference_approval(&saved(), &identity).unwrap();
        let scope = consent
            .reference_metadata_scope(&saved(), &identity)
            .unwrap();
        assert_eq!(scope, consent.approval.fingerprint());
        let mut next = saved();
        next.token = "changed-session".into();
        assert!(consent.reference_metadata_scope(&next, &identity).is_err());
        assert!(consent
            .reference_record(&saved(), &identity)
            .unwrap()
            .unwrap()
            .reference_metadata_scope(&saved(), &identity)
            .is_err());
        assert_eq!(
            consent.copy_approval(&saved(), &identity).err().as_deref(),
            Some("source_copy_mode_required")
        );
        let encoded = serde_json::to_value(&consent).unwrap();
        for mode in [json!("copy"), Value::Null, json!("unknown")] {
            let mut altered = encoded.clone();
            altered["mode"] = mode;
            if let Ok(changed) = serde_json::from_value::<Consent>(altered) {
                assert!(changed.require(&saved(), &identity).is_err());
            }
        }
        let selected = picker
            .select(picker.generation().unwrap(), root.clone())
            .unwrap();
        let mut copy = picker
            .approve(
                &saved(),
                &identity,
                &selected.selection_id,
                true,
                |_| Ok(()),
            )
            .unwrap();
        copy.registered = true;
        copy.copy_approval(&saved(), &identity).unwrap();
        assert_eq!(
            copy.reference_approval(&saved(), &identity)
                .err()
                .as_deref(),
            Some("source_reference_mode_required")
        );
        let mut changed = serde_json::to_value(&copy).unwrap();
        changed["mode"] = json!("reference");
        assert!(serde_json::from_value::<Consent>(changed)
            .unwrap()
            .require(&saved(), &identity)
            .is_err());
        assert!(copy.reference_metadata_scope(&saved(), &identity).is_err());
        std::fs::remove_dir(root).unwrap();
        assert_eq!(
            consent
                .reference_metadata_scope(&saved(), &identity)
                .unwrap(),
            scope
        );
    }
    #[test]
    fn fresh_session_signature_cannot_turn_reference_consent_into_copy_permission() {
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("frameleaf-reconnect-mode-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let identity = DeviceIdentity::generate();
        let picker = SourceConsent::default();
        let selected = picker
            .select(picker.generation().unwrap(), root.clone())
            .unwrap();
        let mut consent = picker
            .approve_with_hydration(
                &saved(),
                &identity,
                &selected.selection_id,
                SourceMode::Reference,
                true,
                false,
                |_| Ok(()),
            )
            .unwrap();
        consent.registered = true;
        let mut next = saved();
        next.token = "synthetic-fresh-session".into();
        let mut record = serde_json::to_value(consent).unwrap();
        record["mode"] = json!("copy");
        record["sessionSignature"] = json!(session_signature(&next, &identity, SourceMode::Copy));
        let changed: Consent = serde_json::from_value(record).unwrap();
        assert!(changed.copy_approval(&next, &identity).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn inactive_reference_record_preserves_identity_but_cannot_authorize_reads() {
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("frameleaf-reconnect-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let identity = DeviceIdentity::generate();
        let picker = SourceConsent::default();
        let selected = picker
            .select(picker.generation().unwrap(), root.clone())
            .unwrap();
        let mut consent = picker
            .approve_with_hydration(
                &saved(),
                &identity,
                &selected.selection_id,
                SourceMode::Reference,
                true,
                false,
                |_| Ok(()),
            )
            .unwrap();
        consent.registered = true;
        let record = consent
            .reference_record(&saved(), &identity)
            .unwrap()
            .unwrap();
        assert!(record.reference_approval(&saved(), &identity).is_err());
        let mut next = saved();
        next.token = "synthetic-new-session".into();
        assert!(record.reference_approval(&next, &identity).is_err());
        let candidate = record.reconnect_candidate(&next, &identity).unwrap();
        assert_eq!(candidate.request(&next), consent.request(&saved()));
        assert_eq!(
            candidate.approval.fingerprint(),
            consent.approval.fingerprint()
        );
        candidate.require(&next, &identity).unwrap();
        assert!(!candidate.registered);
        assert!(candidate.reference_approval(&next, &identity).is_err());
        assert!(candidate.require(&saved(), &identity).is_err());
        assert!(
            record
                .session_view(&next, &identity)
                .unwrap()
                .reconnect_required
        );
        for field in ["server", "serverId", "accountId", "deviceId"] {
            let mut value = serde_json::to_value(&next).unwrap();
            value[field] = json!(if field == "server" {
                "https://other.test/"
            } else {
                "other"
            });
            let foreign: SavedConnection = serde_json::from_value(value).unwrap();
            assert!(
                record.reconnect_candidate(&foreign, &identity).is_err(),
                "{field}"
            );
        }
        assert!(record
            .reconnect_candidate(&next, &DeviceIdentity::generate())
            .is_err());
        for field in ["mode", "allowDownload", "name", "intentSignature"] {
            let mut value = serde_json::to_value(&record).unwrap();
            value[field] = match field {
                "mode" => json!("copy"),
                "allowDownload" => json!(false),
                "intentSignature" => Value::Null,
                _ => json!("Other"),
            };
            let changed: Consent = serde_json::from_value(value).unwrap();
            assert!(
                changed.reconnect_candidate(&next, &identity).is_err(),
                "{field}"
            );
        }
        let mut legacy = serde_json::to_value(&consent).unwrap();
        legacy.as_object_mut().unwrap().remove("intentSignature");
        let legacy: Consent = serde_json::from_value(legacy).unwrap();
        legacy.require(&saved(), &identity).unwrap();
        legacy.revocation_candidate(&saved(), &identity).unwrap();
        assert!(legacy.revocation_candidate(&next, &identity).is_err());
        assert!(legacy.reconnect_candidate(&next, &identity).is_err());
        std::fs::remove_dir_all(root).unwrap();
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
