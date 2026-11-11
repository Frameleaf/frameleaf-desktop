//! Candidate native media transaction. A selected destination stays fenced until an installed
//! Manager/owner handshake can admit writers there.
use super::{
    activation, identity, options, valid_sized_file, Marker, Owner, SafetySnapshot, MEDIA_MOVE,
};
use crate::{
    connection::DeviceIdentity,
    copy_source::{opened_stamp, parent_dir, root_identity, staged_file, unchanged},
    runtime_store,
};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[cfg(any(windows, test))]
const CUTOVER: &str = "cutover.json";
#[cfg(all(windows, feature = "qualify-windows-media-move"))]
pub(crate) mod qualification;
const INVALID: &str = "host_media_move_invalid";
const CHANGED: &str = "host_media_move_changed";
const CANCELLED: &str = "host_media_move_cancelled";
const MAX_ENTRIES: u64 = 1_000_000;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inventory {
    sha256: String,
    entries: u64,
    bytes: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    operation_id: Uuid,
    owner: Marker,
    library_id: String,
    source_identity: String,
    target: PathBuf,
    target_identity: String,
    inventory: Inventory,
    backup: SafetySnapshot,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Approval {
    review: Review,
    signature: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CopyReceipt {
    operation_id: Uuid,
    approval_sha256: String,
    target_identity: String,
    stage_identity: String,
    inventory: Inventory,
    signature: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Fenced,
    Copied,
    SelectedFenced,
    RolledBack,
}

struct Target {
    path: PathBuf,
    directory: Dir,
    #[cfg(windows)]
    _pins: Vec<std::fs::File>,
}

impl Target {
    fn open(profile: &Path, path: &Path) -> Result<Self, String> {
        if !path.is_absolute() || path.starts_with(profile) || profile.starts_with(path) {
            return Err(INVALID.into());
        }
        crate::native_runtime::absolute_directory(path)?;
        let canonical_profile = profile.canonicalize().map_err(|_| INVALID)?;
        let canonical_target = path.canonicalize().map_err(|_| INVALID)?;
        if canonical_target.starts_with(&canonical_profile)
            || canonical_profile.starts_with(&canonical_target)
        {
            return Err(INVALID.into());
        }
        #[cfg(windows)]
        let pins = crate::windows_protection::pin_private_directory(path)?;
        #[cfg(windows)]
        crate::host_storage::check_cleanup(path)?;
        let directory = Dir::from_std_file(crate::host_storage::directory(path)?);
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt;
            if directory.dir_metadata().map_err(|_| INVALID)?.mode() & 0o077 != 0 {
                return Err(INVALID.into());
            }
        }
        Ok(Self {
            path: path.into(),
            directory,
            #[cfg(windows)]
            _pins: pins,
        })
    }

    fn stage(&self, operation: Uuid) -> String {
        format!("frameleaf-media-{operation}")
    }

    fn names(&self) -> Result<Vec<std::ffi::OsString>, String> {
        self.directory
            .entries()
            .map_err(|_| INVALID)?
            .take(2)
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|_| INVALID.into())
            })
            .collect()
    }
}

impl Review {
    /// Read-only review for a stopped, exclusively owned native library and a private empty target.
    pub fn prepare(
        profile: &Path,
        target: &Path,
        installation_id: &str,
        manifest: &str,
        library_id: &str,
        backup: serde_json::Value,
        cancelled: impl Fn() -> bool,
    ) -> Result<Self, String> {
        let mut owner = Owner::acquire(profile, true)?;
        super::no_media_move(&owner.root)?;
        owner.check_movable(installation_id, manifest)?;
        let marker = owner.inspect(installation_id, manifest)?;
        if marker.media_reference.is_some() {
            return Err(INVALID.into());
        }
        let backup: SafetySnapshot = serde_json::from_value(backup).map_err(|_| INVALID)?;
        verify_backup(&owner, &marker, library_id, &backup)?;
        let source = source(&owner)?;
        let target = Target::open(profile, target)?;
        if !target.names()?.is_empty() {
            return Err(INVALID.into());
        }
        let source_identity = identity(&source)?;
        let inventory = inventory(&source, None, &cancelled)?;
        if identity(&self::source(&owner)?)? != source_identity {
            return Err(CHANGED.into());
        }
        Ok(Self {
            operation_id: Uuid::new_v4(),
            owner: marker,
            library_id: library_id.into(),
            source_identity,
            target_identity: identity(&target.directory)?,
            target: target.path,
            inventory,
            backup,
        })
    }

    /// Call only after the native consent surface approves this exact review and backup receipt.
    pub fn approve(self, device: &DeviceIdentity) -> Result<Approval, String> {
        let signature = sign(device, "approval", &self)?;
        Ok(Approval {
            review: self,
            signature,
        })
    }
}

impl Approval {
    /// Copies once. An interrupted, unreceipted stage is retained and requires rollback.
    pub fn copy(
        &self,
        profile: &Path,
        device: &DeviceIdentity,
        cancelled: impl Fn() -> bool,
    ) -> Result<Status, String> {
        let mut owner = self.open(profile, device)?;
        let source = self.verified_source(&owner, &cancelled)?;
        let target = self.target(profile)?;
        let stage = target.stage(self.review.operation_id);
        let signed = bytes(self)?;
        if activation::read_record(&owner.root, MEDIA_MOVE)?.is_some_and(|value| value != signed) {
            return Err(INVALID.into());
        }
        if let Some(journal) = self.existing_journal(&owner)? {
            if self.has_rollback(&journal, device)? {
                return Err(INVALID.into());
            }
            if let Some(receipt) = self.receipt(&journal, device)? {
                self.require_fence(&owner)?;
                self.verify_stage(&target, &stage, &receipt, &cancelled)?;
                return self.copied_status(&journal, &receipt, device);
            }
        }
        if !target.names()?.is_empty() {
            return Err(CHANGED.into());
        }
        if crate::copy_source::available_bytes(&target.directory)? < self.review.inventory.bytes {
            return Err("host_media_move_space_insufficient".into());
        }
        let parent = owner.path.join("media-moves");
        runtime_store::private_directory(&parent)?;
        runtime_store::private_directory(&parent.join(self.review.operation_id.to_string()))?;
        let journal = self.journal(&owner)?;
        persist(&journal, "approval.json", &signed)?;
        persist(&owner.root, MEDIA_MOVE, &signed)?;
        runtime_store::create_private_directory(&target.path.join(&stage))?;
        let stage_dir = child(&target.directory, &stage)?;
        let stage_identity = identity(&stage_dir)?;
        if inventory(&source, Some(&stage_dir), &cancelled)? != self.review.inventory {
            return Err(CHANGED.into());
        }
        let copied = inventory(&stage_dir, None, &cancelled)?;
        if copied != self.review.inventory
            || identity(&child(&target.directory, &stage)?)? != stage_identity
        {
            return Err(CHANGED.into());
        }
        self.verified_source(&owner, &cancelled)?;
        let marker = owner.inspect(
            &self.review.owner.installation_id,
            &self.review.owner.manifest_sha256,
        )?;
        if marker != self.review.owner {
            return Err(CHANGED.into());
        }
        activation::sync_directory(&stage_dir)?;
        activation::sync_directory(&target.directory)?;
        let mut receipt = CopyReceipt {
            operation_id: self.review.operation_id,
            approval_sha256: digest(&bytes(self)?),
            target_identity: self.review.target_identity.clone(),
            stage_identity,
            inventory: copied,
            signature: String::new(),
        };
        receipt.signature = self.sign_receipt(&receipt, device)?;
        persist(&journal, "copied.json", &bytes(&receipt)?)?;
        Ok(Status::Copied)
    }

    /// Selects the verified target in the journal but deliberately retains the writer fence.
    pub fn select_fenced(
        &self,
        profile: &Path,
        device: &DeviceIdentity,
        cancelled: impl Fn() -> bool,
    ) -> Result<Status, String> {
        let owner = self.open(profile, device)?;
        self.require_fence(&owner)?;
        self.verified_source(&owner, &cancelled)?;
        let target = self.target(profile)?;
        let journal = self.journal(&owner)?;
        let stage = target.stage(self.review.operation_id);
        if self.has_rollback(&journal, device)? {
            return Err(INVALID.into());
        }
        let receipt = self.receipt(&journal, device)?.ok_or(INVALID)?;
        self.verify_stage(&target, &stage, &receipt, &cancelled)?;
        self.verified_source(&owner, &cancelled)?;
        let selection = self.selection(&receipt, device)?;
        persist(&journal, "selected.json", selection.as_bytes())?;
        Ok(Status::SelectedFenced)
    }

    /// Restores admission of the original only. The destination and journal remain for inspection.
    pub fn rollback(
        &self,
        profile: &Path,
        device: &DeviceIdentity,
        cancelled: impl Fn() -> bool,
    ) -> Result<Status, String> {
        let owner = self.open(profile, device)?;
        let journal = self.journal(&owner)?;
        #[cfg(any(windows, test))]
        if activation::read_record(&journal, CUTOVER)?.is_some() {
            return Err(INVALID.into());
        }
        let previous = self.has_rollback(&journal, device)?;
        if activation::read_record(&owner.root, MEDIA_MOVE)?.is_none() && previous {
            return Ok(Status::RolledBack);
        }
        self.require_fence(&owner)?;
        self.verified_source(&owner, &cancelled)?;
        let value = self.rollback_record(device)?;
        persist(&journal, "rolled-back.json", value.as_bytes())?;
        owner.root.remove_file(MEDIA_MOVE).map_err(|_| INVALID)?;
        activation::sync_directory(&owner.root)?;
        Ok(Status::RolledBack)
    }

    pub fn status(&self, profile: &Path, device: &DeviceIdentity) -> Result<Status, String> {
        let owner = self.open(profile, device)?;
        let journal = self.journal(&owner)?;
        if activation::read_record(&owner.root, MEDIA_MOVE)?.is_none()
            && self.has_rollback(&journal, device)?
        {
            return Ok(Status::RolledBack);
        }
        self.require_fence(&owner)?;
        match self.receipt(&journal, device)? {
            Some(receipt) => self.copied_status(&journal, &receipt, device),
            None => Ok(Status::Fenced),
        }
    }

    fn open(&self, profile: &Path, device: &DeviceIdentity) -> Result<Owner, String> {
        if self.review.operation_id.is_nil()
            || self.signature != sign(device, "approval", &self.review)?
        {
            return Err(INVALID.into());
        }
        let mut owner = Owner::acquire(profile, true)?;
        let expected = &self.review.owner;
        owner.check_movable(&expected.installation_id, &expected.manifest_sha256)?;
        if expected.media_reference.is_some() {
            return Err(INVALID.into());
        }
        if owner.inspect(&expected.installation_id, &expected.manifest_sha256)? != *expected {
            return Err(CHANGED.into());
        }
        verify_backup(
            &owner,
            expected,
            &self.review.library_id,
            &self.review.backup,
        )?;
        Ok(owner)
    }

    fn verified_source(&self, owner: &Owner, cancelled: &impl Fn() -> bool) -> Result<Dir, String> {
        let directory = source(owner)?;
        if identity(&directory)? != self.review.source_identity
            || inventory(&directory, None, cancelled)? != self.review.inventory
            || identity(&source(owner)?)? != self.review.source_identity
        {
            return Err(CHANGED.into());
        }
        Ok(directory)
    }

    fn target(&self, profile: &Path) -> Result<Target, String> {
        let target = Target::open(profile, &self.review.target)?;
        if identity(&target.directory)? != self.review.target_identity {
            return Err(CHANGED.into());
        }
        Ok(target)
    }

    fn existing_journal(&self, owner: &Owner) -> Result<Option<Dir>, String> {
        let path = owner
            .path
            .join("media-moves")
            .join(self.review.operation_id.to_string());
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            _ => return Err(INVALID.into()),
        }
        #[cfg(windows)]
        let _pins = crate::windows_protection::pin_private_directory(&path)?;
        let directory = Dir::from_std_file(crate::host_storage::directory(&path)?);
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt;
            if directory.dir_metadata().map_err(|_| INVALID)?.mode() & 0o077 != 0 {
                return Err(INVALID.into());
            }
        }
        Ok(Some(directory))
    }

    fn journal(&self, owner: &Owner) -> Result<Dir, String> {
        self.existing_journal(owner)?.ok_or_else(|| INVALID.into())
    }

    fn require_fence(&self, owner: &Owner) -> Result<(), String> {
        if activation::read_record(&owner.root, MEDIA_MOVE)?.as_deref()
            != Some(bytes(self)?.as_slice())
        {
            return Err(INVALID.into());
        }
        Ok(())
    }

    fn sign_receipt(
        &self,
        receipt: &CopyReceipt,
        device: &DeviceIdentity,
    ) -> Result<String, String> {
        sign(
            device,
            "copied",
            &(
                receipt.operation_id,
                &receipt.approval_sha256,
                &receipt.target_identity,
                &receipt.stage_identity,
                &receipt.inventory,
            ),
        )
    }

    fn receipt(
        &self,
        journal: &Dir,
        device: &DeviceIdentity,
    ) -> Result<Option<CopyReceipt>, String> {
        let Some(raw) = activation::read_record(journal, "copied.json")? else {
            return Ok(None);
        };
        let receipt: CopyReceipt = serde_json::from_slice(&raw).map_err(|_| INVALID)?;
        if receipt.signature != self.sign_receipt(&receipt, device)?
            || receipt.operation_id != self.review.operation_id
            || receipt.approval_sha256 != digest(&bytes(self)?)
            || receipt.target_identity != self.review.target_identity
            || receipt.inventory != self.review.inventory
        {
            return Err(INVALID.into());
        }
        Ok(Some(receipt))
    }

    fn verify_stage(
        &self,
        target: &Target,
        stage: &str,
        receipt: &CopyReceipt,
        cancelled: &impl Fn() -> bool,
    ) -> Result<(), String> {
        if target.names()? != [std::ffi::OsString::from(stage)] {
            return Err(CHANGED.into());
        }
        let directory = child(&target.directory, stage)?;
        if identity(&directory)? != receipt.stage_identity
            || inventory(&directory, None, cancelled)? != receipt.inventory
            || identity(&child(&target.directory, stage)?)? != receipt.stage_identity
        {
            return Err(CHANGED.into());
        }
        Ok(())
    }

    fn selection(&self, receipt: &CopyReceipt, device: &DeviceIdentity) -> Result<String, String> {
        sign(device, "selected-fenced", &digest(&bytes(receipt)?))
    }

    fn copied_status(
        &self,
        journal: &Dir,
        receipt: &CopyReceipt,
        device: &DeviceIdentity,
    ) -> Result<Status, String> {
        match activation::read_record(journal, "selected.json")? {
            None => Ok(Status::Copied),
            Some(raw) if raw == self.selection(receipt, device)?.as_bytes() => {
                Ok(Status::SelectedFenced)
            }
            Some(_) => Err(INVALID.into()),
        }
    }

    fn rollback_record(&self, device: &DeviceIdentity) -> Result<String, String> {
        sign(device, "rolled-back", &digest(&bytes(self)?))
    }

    fn has_rollback(&self, journal: &Dir, device: &DeviceIdentity) -> Result<bool, String> {
        match activation::read_record(journal, "rolled-back.json")? {
            None => Ok(false),
            Some(raw) if raw == self.rollback_record(device)?.as_bytes() => Ok(true),
            Some(_) => Err(INVALID.into()),
        }
    }
}

/// Written only by the protected owner. Paths from IPC cannot become media roots.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MediaReference {
    pub path: PathBuf,
    pub identity: String,
    parent_identity: String,
}

#[cfg(windows)]
pub(crate) struct PinnedMedia {
    pub path: PathBuf,
    pub identity: String,
    _pins: Vec<std::fs::File>,
}

impl MediaReference {
    #[cfg(not(windows))]
    pub(crate) fn resolve(&self, _profile: &Path) -> Result<(), String> {
        Err(INVALID.into())
    }

    #[cfg(windows)]
    pub(crate) fn resolve(&self, profile: &Path) -> Result<PinnedMedia, String> {
        let parent = self.path.parent().ok_or(INVALID)?;
        let target = Target::open(profile, parent)?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(INVALID)?;
        let pins = crate::windows_protection::pin_private_directory(&self.path)?;
        if identity(&target.directory)? != self.parent_identity
            || identity(&child(&target.directory, name)?)? != self.identity
        {
            return Err(CHANGED.into());
        }
        let path = crate::windows_protection::stable_state_path(&self.path)?;
        Ok(PinnedMedia {
            path,
            identity: self.identity.clone(),
            _pins: pins,
        })
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CutoverRequest {
    protocol_version: u32,
    operation_id: Uuid,
    binding: CutoverBinding,
}

#[cfg(any(windows, test))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CutoverBinding {
    move_id: Uuid,
    secure_installation_id: Uuid,
    manifest_sha256: String,
    library_id: String,
    profile_identity: String,
    source_generation: Uuid,
    source_identity: String,
    target_identity: String,
    staged_identity: String,
    approval_sha256: String,
    copy_receipt_sha256: String,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Decision {
    Target,
    Original,
}

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CutoverIntent {
    request: CutoverRequest,
    decision: Decision,
    generation: Uuid,
}

#[cfg(any(windows, test))]
impl CutoverRequest {
    #[cfg(windows)]
    pub(crate) fn matches_host(&self, secure: Uuid, manifest: &str) -> bool {
        self.protocol_version == 1
            && !self.operation_id.is_nil()
            && !self.binding.move_id.is_nil()
            && self.binding.secure_installation_id == secure
            && self.binding.manifest_sha256 == manifest
    }

    pub(crate) fn apply_or_inspect(
        self,
        mut owner: Owner,
        installation_id: &str,
        device: &DeviceIdentity,
        decision: Option<Decision>,
        reviewed_backup: Option<serde_json::Value>,
        cancelled: impl Fn() -> bool,
    ) -> Result<serde_json::Value, String> {
        if self.protocol_version != 1
            || self.operation_id.is_nil()
            || self.binding.move_id.is_nil()
            || self.binding.secure_installation_id != owner.secure_installation_id()
        {
            return Err(INVALID.into());
        }
        let binding = &self.binding;
        let move_id = binding.move_id;
        let journal_path = owner.path.join("media-moves").join(move_id.to_string());
        #[cfg(windows)]
        let _journal_pins = crate::windows_protection::pin_private_directory(&journal_path)?;
        let journal = Dir::from_std_file(crate::host_storage::directory(&journal_path)?);
        let raw = activation::read_record(&journal, "approval.json")?.ok_or(INVALID)?;
        let approval: Approval = serde_json::from_slice(&raw).map_err(|_| INVALID)?;
        let review = &approval.review;
        let source_marker = &review.owner;
        if approval.signature != sign(device, "approval", review)?
            || move_id != review.operation_id
            || installation_id != source_marker.installation_id
            || binding.manifest_sha256 != source_marker.manifest_sha256
            || binding.profile_identity != source_marker.profile_identity
            || binding.source_generation != source_marker.generation
            || binding.library_id != review.library_id
            || binding.source_identity != review.source_identity
            || binding.target_identity != review.target_identity
            || binding.approval_sha256 != digest(&raw)
            || source_marker.media_reference.is_some()
        {
            return Err(INVALID.into());
        }
        let copy = approval.receipt(&journal, device)?.ok_or(INVALID)?;
        if binding.staged_identity != copy.stage_identity
            || binding.copy_receipt_sha256 != digest(&bytes(&copy)?)
            || approval.copied_status(&journal, &copy, device)? != Status::SelectedFenced
        {
            return Err(INVALID.into());
        }
        let reference = MediaReference {
            path: review.target.join(format!("frameleaf-media-{move_id}")),
            identity: copy.stage_identity.clone(),
            parent_identity: copy.target_identity.clone(),
        };
        let current = owner.inspect(installation_id, &binding.manifest_sha256)?;
        let mut output = serde_json::to_value(&self).map_err(|_| INVALID)?;
        let complete = |mut output: serde_json::Value, intent: &CutoverIntent| {
            let target = intent.decision == Decision::Target;
            output["state"] = serde_json::json!(if target {
                "target-admitted"
            } else {
                "original-restored"
            });
            output["writerFence"] = serde_json::json!("released");
            output["activeMediaIdentity"] = serde_json::json!(if target {
                &binding.staged_identity
            } else {
                &binding.source_identity
            });
            output["generation"] = serde_json::json!(intent.generation);
            output
        };
        let intent: Option<CutoverIntent> = activation::read_record(&journal, CUTOVER)?
            .map(|raw| serde_json::from_slice(&raw).map_err(|_| INVALID))
            .transpose()?;
        let expected = |intent: &CutoverIntent| {
            let mut marker = source_marker.clone();
            if intent.decision == Decision::Target {
                marker.generation = intent.generation;
                marker.media_reference = Some(reference.clone());
            }
            marker
        };
        if let Some(previous) = &intent {
            if previous.request != self
                || decision.is_some_and(|decision| decision != previous.decision)
                || previous.generation.is_nil()
                || (previous.decision == Decision::Target)
                    == (previous.generation == source_marker.generation)
                || (current != *source_marker && current != expected(previous))
            {
                return Err(INVALID.into());
            }
        } else if current != *source_marker {
            return Err(CHANGED.into());
        }
        if activation::read_record(&owner.root, MEDIA_MOVE)?.is_none() {
            if reviewed_backup.is_some() {
                return Err(INVALID.into());
            }
            let previous = intent.as_ref().ok_or(INVALID)?;
            if current != expected(previous) {
                return Err(CHANGED.into());
            }
            if previous.decision == Decision::Target {
                reference.resolve(&owner.path)?;
            } else if !approval.has_rollback(&journal, device)? {
                return Err(INVALID.into());
            }
            return Ok(complete(output, previous));
        }
        approval.require_fence(&owner)?;
        if let Some(backup) = reviewed_backup {
            let safety: SafetySnapshot = serde_json::from_value(backup).map_err(|_| INVALID)?;
            if safety != review.backup
                || intent.is_some()
                || approval.has_rollback(&journal, device)?
            {
                return Err(INVALID.into());
            }
            verify_backup(&owner, source_marker, &review.library_id, &safety)?;
        }
        let Some(decision) = decision else {
            output["state"] = serde_json::json!("selected-fenced");
            output["writerFence"] = serde_json::json!("held");
            return Ok(output);
        };
        if approval.has_rollback(&journal, device)? && decision != Decision::Original {
            return Err(INVALID.into());
        }
        owner.check_movable(installation_id, &binding.manifest_sha256)?;
        verify_backup(&owner, source_marker, &review.library_id, &review.backup)?;
        approval.verified_source(&owner, &cancelled)?;
        let _pins = if decision == Decision::Target {
            let target = approval.target(&owner.path)?;
            approval.verify_stage(&target, &target.stage(move_id), &copy, &cancelled)?;
            Some(reference.resolve(&owner.path)?)
        } else {
            None
        };
        if cancelled() {
            return Err(CANCELLED.into());
        }
        // Once intent is durable, only the same Manager operation and decision can resume.
        let intent = intent.unwrap_or_else(|| CutoverIntent {
            request: self.clone(),
            decision,
            generation: if decision == Decision::Target {
                Uuid::new_v4()
            } else {
                source_marker.generation
            },
        });
        persist(&journal, CUTOVER, &bytes(&intent)?)?;
        #[cfg(all(windows, feature = "qualify-windows-media-move"))]
        qualification::interrupt_after_intent(&owner.path)?;
        if decision == Decision::Target {
            let marker = expected(&intent);
            if current != marker {
                owner.write(&marker)?;
            }
        } else {
            persist(
                &journal,
                "rolled-back.json",
                approval.rollback_record(device)?.as_bytes(),
            )?;
        }
        owner.root.remove_file(MEDIA_MOVE).map_err(|_| INVALID)?;
        activation::sync_directory(&owner.root)?;
        Ok(complete(output, &intent))
    }
}

fn verify_backup(
    owner: &Owner,
    marker: &Marker,
    library: &str,
    backup: &SafetySnapshot,
) -> Result<(), String> {
    if !crate::native_runtime::digest_valid(library, 12)
        || !backup.checkpoint_matches_manifest(&marker.manifest_sha256)
    {
        return Err(INVALID.into());
    }
    backup.verify_snapshot(
        &owner.root,
        backup.operation_id(),
        &marker.installation_id,
        library,
    )
}

fn source(owner: &Owner) -> Result<Dir, String> {
    child(&owner.root, "media")
}

fn child(root: &Dir, name: &str) -> Result<Dir, String> {
    parent_dir(root, &Path::new(name).join("placeholder")).map(|(directory, _)| directory)
}

fn bytes(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(value).map_err(|_| INVALID)?;
    if bytes.len() > 4096 {
        return Err(INVALID.into());
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sign(device: &DeviceIdentity, domain: &str, value: &impl Serialize) -> Result<String, String> {
    Ok(device.sign(&format!(
        "frameleaf/native-media-move/v1\n{domain}\n{}",
        digest(&bytes(value)?)
    )))
}

fn persist(root: &Dir, name: &str, expected: &[u8]) -> Result<(), String> {
    match activation::read_record(root, name)? {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => Err(INVALID.into()),
        None => activation::record(root, name, expected),
    }
}

struct Walk<'a, F> {
    hash: Sha256,
    entries: u64,
    bytes: u64,
    volume: &'a str,
    cancelled: &'a F,
}

fn inventory(
    root: &Dir,
    destination: Option<&Dir>,
    cancelled: &impl Fn() -> bool,
) -> Result<Inventory, String> {
    let physical = root_identity(root)?;
    let volume = physical.split(':').next().ok_or(INVALID)?;
    let mut walk = Walk {
        hash: Sha256::new(),
        entries: 0,
        bytes: 0,
        volume,
        cancelled,
    };
    walk.scan(root, destination, "", 0)?;
    Ok(Inventory {
        sha256: format!("{:x}", walk.hash.finalize()),
        entries: walk.entries,
        bytes: walk.bytes,
    })
}

impl<F: Fn() -> bool> Walk<'_, F> {
    fn scan(
        &mut self,
        dir: &Dir,
        output: Option<&Dir>,
        prefix: &str,
        depth: usize,
    ) -> Result<(), String> {
        if (self.cancelled)() {
            return Err(CANCELLED.into());
        }
        if depth > MAX_DEPTH || root_identity(dir)?.split(':').next() != Some(self.volume) {
            return Err(INVALID.into());
        }
        let mut names: Vec<_> = dir
            .entries()
            .map_err(|_| INVALID)?
            .take((MAX_ENTRIES - self.entries + 1) as usize)
            .map(|entry| entry.map(|entry| entry.file_name()).map_err(|_| INVALID))
            .collect::<Result<_, _>>()?;
        if names.len() as u64 > MAX_ENTRIES - self.entries {
            return Err(INVALID.into());
        }
        names.sort_unstable();
        for name in names {
            if (self.cancelled)() {
                return Err(CANCELLED.into());
            }
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                return Err(INVALID.into());
            }
            let name = name
                .to_str()
                .filter(|name| !name.contains(['/', '\\', ':']) && !name.is_empty())
                .ok_or(INVALID)?;
            let relative = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            let meta = dir.symlink_metadata(name).map_err(|_| INVALID)?;
            if meta.is_symlink() {
                return Err(INVALID.into());
            }
            self.hash.update((relative.len() as u64).to_be_bytes());
            self.hash.update(relative.as_bytes());
            if meta.is_dir() {
                self.hash.update([0]);
                let child_dir = child(dir, name)?;
                let staged = output
                    .map(|dir| {
                        dir.create_dir(name).map_err(|_| INVALID)?;
                        child(dir, name)
                    })
                    .transpose()?;
                self.scan(&child_dir, staged.as_ref(), &relative, depth + 1)?;
                if let Some(staged) = staged {
                    activation::sync_directory(&staged)?;
                }
            } else if meta.is_file() {
                self.hash.update([1]);
                self.file(dir, output, name)?;
            } else {
                return Err(INVALID.into());
            }
        }
        Ok(())
    }

    fn file(&mut self, dir: &Dir, output: Option<&Dir>, name: &str) -> Result<(), String> {
        let path = Path::new(name);
        let mut file = staged_file(dir, path)?;
        let len = file.metadata().map_err(|_| INVALID)?.len();
        valid_sized_file(&file.try_clone().map_err(|_| INVALID)?.into_std(), len)?;
        #[cfg(windows)]
        single_windows_stream(&file)?;
        let stamp = opened_stamp(&file)?;
        let mut write = options(true);
        write.create_new(true);
        let mut staged = output
            .map(|dir| dir.open_with(path, &write).map_err(|_| INVALID))
            .transpose()?;
        self.hash.update(len.to_be_bytes());
        let mut buffer = [0u8; 64 * 1024];
        let mut remaining = len;
        while remaining > 0 {
            if (self.cancelled)() {
                return Err(CANCELLED.into());
            }
            let limit = remaining.min(buffer.len() as u64) as usize;
            let count = file.read(&mut buffer[..limit]).map_err(|_| INVALID)?;
            if count == 0 {
                return Err(CHANGED.into());
            }
            self.hash.update(&buffer[..count]);
            if let Some(staged) = &mut staged {
                staged.write_all(&buffer[..count]).map_err(|_| INVALID)?;
            }
            remaining -= count as u64;
        }
        unchanged(dir, path, &file, &stamp, len, len)?;
        #[cfg(windows)]
        single_windows_stream(&file)?;
        self.bytes = self.bytes.checked_add(len).ok_or(INVALID)?;
        if let Some(staged) = staged {
            staged.sync_all().map_err(|_| INVALID)?;
        }
        Ok(())
    }
}

#[cfg(windows)]
fn single_windows_stream(file: &cap_std::fs::File) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileStreamInfo, GetFileInformationByHandleEx, FILE_STREAM_INFO,
    };
    let mut data = [0u64; 64];
    let base = data.as_mut_ptr();
    let success = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStreamInfo,
            base.cast(),
            std::mem::size_of_val(&data) as u32,
        )
    };
    if success == 0 {
        return Err("host_media_move_stream_unsupported".into());
    }
    // NTFS returns one unnamed data stream for an ordinary file. Reject extra streams.
    let record = unsafe { &*base.cast::<FILE_STREAM_INFO>() };
    let expected = [
        b':' as u16,
        b':' as u16,
        b'$' as u16,
        b'D' as u16,
        b'A' as u16,
        b'T' as u16,
        b'A' as u16,
    ];
    if record.NextEntryOffset != 0
        || record.StreamNameLength as usize != std::mem::size_of_val(&expected)
    {
        return Err("host_media_move_stream_unsupported".into());
    }
    let stream_name = unsafe {
        std::slice::from_raw_parts(
            base.cast::<u8>()
                .add(std::mem::offset_of!(FILE_STREAM_INFO, StreamName))
                .cast::<u16>(),
            expected.len(),
        )
    };
    if stream_name != expected {
        return Err("host_media_move_stream_unsupported".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, fs};
    const ID: &str = "aaaaaaaaaaaa";
    const LIBRARY: &str = "cccccccccccc";
    const BACKUP: &str = "11111111-1111-4111-8111-111111111111";
    const VIDEO: &[u8] = b"synthetic-video-content";
    const PHOTO: &[u8] = b"synthetic-original-content";

    struct Fixture {
        base: PathBuf,
        profile: PathBuf,
        target: PathBuf,
        sha: String,
        backup: serde_json::Value,
        device: DeviceIdentity,
    }
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-native-move-{}", Uuid::new_v4()));
            let profile = base.join("profile");
            let target = base.join("target");
            for path in [&base, &profile, &target] {
                runtime_store::create_private_directory(path).unwrap();
            }
            let sha = "b".repeat(64);
            let mut owner = Owner::acquire(&profile, true).unwrap();
            owner
                .activate(ID, &sha, crate::host_runtime::HostMode::Server)
                .unwrap();
            owner.clean_stop().unwrap();
            drop(owner);
            let media = profile.join("media");
            let safety = profile.join("restore-safety");
            let snapshot = safety.join(BACKUP);
            for path in [
                &media,
                &media.join("originals"),
                &media.join("empty"),
                &safety,
                &snapshot,
            ] {
                runtime_store::create_private_directory(path).unwrap();
            }
            write(&media.join("originals/photo.jpg"), PHOTO);
            write(&media.join("originals/video.mp4"), VIDEO);
            let dump = b"PGDMP synthetic canonical backup";
            let checkpoint = serde_json::json!({"schemaVersion":1,"operationId":BACKUP,"manifestSha256":sha,
                "sourceRevision":"d".repeat(40),"postgresMajor":"19","databaseFormat":"frameleaf-canonical",
                "dump":{"bytes":dump.len(),"sha256":digest(dump)}});
            let mut envelope = checkpoint.clone();
            envelope["protocolVersion"] = serde_json::json!(1);
            envelope["state"] = serde_json::json!("checkpoint");
            let recovery = serde_json::json!({"schemaVersion":1,"runtime":"native","mediaIncluded":false,
                "databaseFormat":"frameleaf-canonical","libraryId":LIBRARY,"installation":{"id":ID},"checkpoint":envelope});
            let json = serde_json::to_vec(&recovery).unwrap();
            write(&snapshot.join("database.dump"), dump);
            write(&snapshot.join("recovery.json"), &json);
            let backup = serde_json::json!({"snapshotId":"e".repeat(64),"recoverySha256":digest(&json),"checkpoint":checkpoint});
            Self {
                base,
                profile,
                target,
                sha,
                backup,
                device: DeviceIdentity::generate(),
            }
        }
        fn approval(&self) -> Approval {
            Review::prepare(
                &self.profile,
                &self.target,
                ID,
                &self.sha,
                LIBRARY,
                self.backup.clone(),
                || false,
            )
            .unwrap()
            .approve(&self.device)
            .unwrap()
        }
        fn assert_fenced(&self) {
            let mut owner = Owner::acquire(&self.profile, true).unwrap();
            assert_eq!(
                owner
                    .activate(ID, &self.sha, crate::host_runtime::HostMode::Server)
                    .unwrap_err(),
                "host_media_move_pending"
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
    fn write(path: &Path, contents: &[u8]) {
        let directory =
            Dir::from_std_file(crate::host_storage::directory(path.parent().unwrap()).unwrap());
        directory
            .open_with(path.file_name().unwrap(), &options(true))
            .unwrap()
            .write_all(contents)
            .unwrap();
    }

    fn selected(f: &Fixture) -> CutoverRequest {
        let approval = f.approval();
        approval.copy(&f.profile, &f.device, || false).unwrap();
        approval
            .select_fenced(&f.profile, &f.device, || false)
            .unwrap();
        let owner = Owner::acquire(&f.profile, true).unwrap();
        let journal = approval.journal(&owner).unwrap();
        let copy = approval.receipt(&journal, &f.device).unwrap().unwrap();
        CutoverRequest {
            protocol_version: 1,
            operation_id: Uuid::new_v4(),
            binding: CutoverBinding {
                move_id: approval.review.operation_id,
                secure_installation_id: owner.secure_installation_id(),
                manifest_sha256: f.sha.clone(),
                library_id: LIBRARY.into(),
                profile_identity: approval.review.owner.profile_identity,
                source_generation: approval.review.owner.generation,
                source_identity: approval.review.source_identity,
                target_identity: copy.target_identity.clone(),
                staged_identity: copy.stage_identity.clone(),
                approval_sha256: copy.approval_sha256.clone(),
                copy_receipt_sha256: digest(&bytes(&copy).unwrap()),
            },
        }
    }

    fn owner_request(
        f: &Fixture,
        request: &CutoverRequest,
        decision: Option<Decision>,
    ) -> Result<serde_json::Value, String> {
        let owner = Owner::acquire(&f.profile, true).unwrap();
        request
            .clone()
            .apply_or_inspect(owner, ID, &f.device, decision, None, || false)
    }

    #[test]
    fn admission_requires_the_signed_backup_and_reads_the_retained_bytes_again() {
        let f = Fixture::new();
        let selected = selected(&f);
        let inspect = |backup: serde_json::Value| {
            let owner = Owner::acquire(&f.profile, true).unwrap();
            selected
                .clone()
                .apply_or_inspect(owner, ID, &f.device, None, Some(backup), || false)
        };
        let held = inspect(f.backup.clone()).unwrap();
        assert_eq!(held["writerFence"], "held");
        let mut different = f.backup.clone();
        different["snapshotId"] = serde_json::json!("0".repeat(64));
        assert!(inspect(different).is_err());
        fs::write(
            f.profile
                .join("restore-safety")
                .join(BACKUP)
                .join("database.dump"),
            b"invalid",
        )
        .unwrap();
        assert!(inspect(f.backup.clone()).is_err());
        f.assert_fenced();
    }

    #[test]
    fn protected_cutover_binds_manager_operation_and_recovers_rollback_after_lost_reply() {
        let f = Fixture::new();
        let selected = selected(&f);
        let mut wrong_copy = selected.clone();
        wrong_copy.binding.copy_receipt_sha256 = "0".repeat(64);
        assert!(owner_request(&f, &wrong_copy, Some(Decision::Original)).is_err());
        f.assert_fenced();

        let held = owner_request(&f, &selected, None).unwrap();
        assert_eq!(held["state"], "selected-fenced");
        assert_eq!(held["writerFence"], "held");

        let final_receipt = owner_request(&f, &selected, Some(Decision::Original)).unwrap();
        assert_eq!(final_receipt["state"], "original-restored");
        assert_eq!(final_receipt["writerFence"], "released");
        assert_eq!(
            final_receipt["generation"],
            serde_json::json!(selected.binding.source_generation)
        );
        assert_eq!(final_receipt, owner_request(&f, &selected, None).unwrap());
        assert!(owner_request(&f, &selected, Some(Decision::Target)).is_err());
        let mut other_operation = selected.clone();
        other_operation.operation_id = Uuid::new_v4();
        assert!(owner_request(&f, &other_operation, None).is_err());
        assert_eq!(
            fs::read(f.profile.join("media/originals/photo.jpg")).unwrap(),
            PHOTO
        );
    }

    #[cfg(windows)]
    #[test]
    fn target_admission_resumes_durable_intent_and_refuses_replaced_root_on_startup() {
        let f = Fixture::new();
        let selected = selected(&f);
        let stage = f
            .target
            .join(format!("frameleaf-media-{}", selected.binding.move_id));
        let generation = Uuid::new_v4();
        {
            let owner = Owner::acquire(&f.profile, true).unwrap();
            let journal_path = f
                .profile
                .join("media-moves")
                .join(selected.binding.move_id.to_string());
            let journal =
                Dir::from_std_file(crate::host_storage::directory(&journal_path).unwrap());
            let intent = CutoverIntent {
                request: selected.clone(),
                decision: Decision::Target,
                generation,
            };
            persist(&journal, CUTOVER, &bytes(&intent).unwrap()).unwrap();
            drop(owner);
        }
        f.assert_fenced();
        assert!(owner_request(&f, &selected, Some(Decision::Original)).is_err());
        let final_receipt = owner_request(&f, &selected, Some(Decision::Target)).unwrap();
        assert_eq!(final_receipt["state"], "target-admitted");
        assert_eq!(final_receipt["generation"], serde_json::json!(generation));
        assert_eq!(final_receipt, owner_request(&f, &selected, None).unwrap());
        assert_eq!(
            fs::read(f.profile.join("media/originals/photo.jpg")).unwrap(),
            PHOTO
        );
        assert_eq!(fs::read(stage.join("originals/photo.jpg")).unwrap(), PHOTO);
        {
            let mut owner = Owner::acquire(&f.profile, true).unwrap();
            owner
                .activate(ID, &f.sha, crate::host_runtime::HostMode::Server)
                .unwrap();
            assert_eq!(
                owner.media_reference().unwrap().identity,
                selected.binding.staged_identity
            );
            owner.clean_stop().unwrap();
        }
        fs::rename(&stage, stage.with_extension("retained")).unwrap();
        runtime_store::create_private_directory(&stage).unwrap();
        let mut owner = Owner::acquire(&f.profile, true).unwrap();
        assert!(owner
            .activate(ID, &f.sha, crate::host_runtime::HostMode::Server)
            .is_err());
    }

    #[test]
    fn verified_copy_and_selection_preserve_both_trees_and_fence_writers_until_rollback() {
        let f = Fixture::new();
        let approval = f.approval();
        assert_eq!(
            approval.copy(&f.profile, &f.device, || false).unwrap(),
            Status::Copied
        );
        f.assert_fenced();
        let staged = f
            .target
            .join(format!("frameleaf-media-{}", approval.review.operation_id));
        assert_eq!(fs::read(staged.join("originals/video.mp4")).unwrap(), VIDEO);
        assert_eq!(fs::read(staged.join("originals/photo.jpg")).unwrap(), PHOTO);
        assert!(staged.join("empty").is_dir());
        let recovered: Approval =
            serde_json::from_slice(&fs::read(f.profile.join(MEDIA_MOVE)).unwrap()).unwrap();
        assert_eq!(
            recovered.copy(&f.profile, &f.device, || false).unwrap(),
            Status::Copied
        );
        assert_eq!(
            recovered
                .select_fenced(&f.profile, &f.device, || false)
                .unwrap(),
            Status::SelectedFenced
        );
        assert_eq!(
            recovered.status(&f.profile, &f.device).unwrap(),
            Status::SelectedFenced
        );
        f.assert_fenced();
        assert_eq!(
            recovered.rollback(&f.profile, &f.device, || false).unwrap(),
            Status::RolledBack
        );
        assert_eq!(
            recovered.rollback(&f.profile, &f.device, || false).unwrap(),
            Status::RolledBack
        );
        assert_eq!(
            fs::read(f.profile.join("media/originals/video.mp4")).unwrap(),
            VIDEO
        );
        assert_eq!(fs::read(staged.join("originals/video.mp4")).unwrap(), VIDEO);
        let mut owner = Owner::acquire(&f.profile, true).unwrap();
        owner
            .activate(ID, &f.sha, crate::host_runtime::HostMode::Server)
            .unwrap();
        owner.clean_stop().unwrap();
    }

    #[test]
    fn a_partial_stage_cannot_select_or_overwrite_and_rolls_back_to_verified_original() {
        let f = Fixture::new();
        let approval = f.approval();
        let checks = Cell::new(0);
        let result = approval.copy(&f.profile, &f.device, || {
            let count = checks.get() + 1;
            checks.set(count);
            count >= 15
        });
        assert_eq!(result.unwrap_err(), CANCELLED);
        assert_eq!(
            approval.status(&f.profile, &f.device).unwrap(),
            Status::Fenced
        );
        f.assert_fenced();
        assert!(approval
            .select_fenced(&f.profile, &f.device, || false)
            .is_err());
        assert!(approval.copy(&f.profile, &f.device, || false).is_err());
        assert_eq!(
            approval.rollback(&f.profile, &f.device, || false).unwrap(),
            Status::RolledBack
        );
        assert_eq!(
            fs::read(f.profile.join("media/originals/photo.jpg")).unwrap(),
            PHOTO
        );
    }

    #[test]
    fn replaced_target_changed_video_and_untrusted_or_damaged_backup_fail_closed() {
        let f = Fixture::new();
        let approval = f.approval();
        assert!(approval
            .copy(&f.profile, &DeviceIdentity::generate(), || false)
            .is_err());
        assert!(!f.profile.join(MEDIA_MOVE).exists());
        approval.copy(&f.profile, &f.device, || false).unwrap();
        let stage = f
            .target
            .join(format!("frameleaf-media-{}", approval.review.operation_id));
        write(&stage.join("originals/video.mp4"), b"substituted");
        assert_eq!(
            approval
                .select_fenced(&f.profile, &f.device, || false)
                .unwrap_err(),
            CHANGED
        );
        let retained = f.base.join("retained");
        fs::rename(&f.target, &retained).unwrap();
        runtime_store::create_private_directory(&f.target).unwrap();
        assert_eq!(
            approval
                .select_fenced(&f.profile, &f.device, || false)
                .unwrap_err(),
            CHANGED
        );
        write(
            &f.profile
                .join("restore-safety")
                .join(BACKUP)
                .join("database.dump"),
            b"damaged",
        );
        assert!(approval.rollback(&f.profile, &f.device, || false).is_err());
        f.assert_fenced();
        assert_eq!(
            fs::read(f.profile.join("media/originals/video.mp4")).unwrap(),
            VIDEO
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_ntfs_alternate_streams_are_refused_before_fencing_or_copying() {
        let f = Fixture::new();
        fs::write(
            f.profile.join("media/originals/photo.jpg:alternate"),
            b"metadata",
        )
        .unwrap();
        assert_eq!(
            Review::prepare(
                &f.profile,
                &f.target,
                ID,
                &f.sha,
                LIBRARY,
                f.backup.clone(),
                || false
            )
            .err()
            .as_deref(),
            Some("host_media_move_stream_unsupported")
        );
        assert!(!f.profile.join(MEDIA_MOVE).exists());
        assert_eq!(fs::read_dir(&f.target).unwrap().count(), 0);
    }
}
