//! Host packs have separate authority and component requirements from ML packs.
use crate::native_runtime::{digest_valid, relative, verify_files, Artifact};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EntryPoints {
    node: String,
    server: String,
    postgres: String,
    initdb: String,
    pg_dump: String,
    pg_restore: String,
    pg_isready: String,
    pg_checksums: String,
    pg_ctl: String,
    createdb: String,
    psql: String,
    vector: String,
    hdr: String,
    ffmpeg: String,
    ffprobe: String,
    exiftool: String,
    raw_renderer: String,
    raw_decoder: String,
    web_index: String,
    studio: String,
    studio_browser: String,
    studio_browser_guard: String,
    core_plugin: String,
    ml_manifest: String,
    manager: String,
    manager_web_index: String,
    backup_engine: String,
}
impl EntryPoints {
    fn paths(&self) -> [&str; 27] {
        [
            &self.node,
            &self.server,
            &self.postgres,
            &self.initdb,
            &self.pg_dump,
            &self.pg_restore,
            &self.pg_isready,
            &self.pg_checksums,
            &self.pg_ctl,
            &self.createdb,
            &self.psql,
            &self.vector,
            &self.hdr,
            &self.ffmpeg,
            &self.ffprobe,
            &self.exiftool,
            &self.raw_renderer,
            &self.raw_decoder,
            &self.web_index,
            &self.studio,
            &self.studio_browser,
            &self.studio_browser_guard,
            &self.core_plugin,
            &self.ml_manifest,
            &self.manager,
            &self.manager_web_index,
            &self.backup_engine,
        ]
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostManifest {
    schema_version: u32,
    protocol_version: u32,
    epoch: u64,
    platform: String,
    architecture: String,
    source_revision: String,
    node_version: String,
    postgres_version: String,
    vector_version: String,
    certified: bool,
    entry_points: EntryPoints,
    files: BTreeMap<String, Artifact>,
}

pub struct VerifiedHostRuntime {
    root: PathBuf,
    manifest: HostManifest,
    manifest_sha256: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupEngine {
    pub executable: PathBuf,
    pub sha256: String,
}
impl VerifiedHostRuntime {
    /// Keys and rollback floor are supplied by compiled desktop release authority, never by a server.
    pub fn verify(
        root: &Path,
        raw: &[u8],
        signature: &[u8; 64],
        trusted: &[VerifyingKey],
        minimum_epoch: u64,
    ) -> Result<Self, String> {
        if raw.is_empty()
            || raw.len() > 16 * 1024 * 1024
            || !trusted.iter().any(|key| {
                key.verify_strict(raw, &Signature::from_bytes(signature))
                    .is_ok()
            })
        {
            return Err("host_signature_invalid".into());
        }
        let manifest: HostManifest =
            serde_json::from_slice(raw).map_err(|_| "host_manifest_invalid")?;
        let pins: serde_json::Value =
            serde_json::from_str(include_str!("../../runtime/host-database.json"))
                .map_err(|_| "host_release_contract_invalid")?;
        if manifest.schema_version != 1
            || manifest.protocol_version != 2
            || minimum_epoch == 0
            || manifest.epoch < minimum_epoch
            || manifest.platform != std::env::consts::OS
            || manifest.architecture != std::env::consts::ARCH
            || !digest_valid(&manifest.source_revision, 40)
            || manifest.node_version != "26.11.1"
            || Some(manifest.postgres_version.as_str()) != pins["postgresVersion"].as_str()
            || Some(manifest.vector_version.as_str()) != pins["pgvectorVersion"].as_str()
            || Some(manifest.certified) != pins["certified"].as_bool()
            || manifest.files.is_empty()
            || manifest.files.len() > 100_000
        {
            return Err("host_manifest_incompatible".into());
        }
        for name in manifest.entry_points.paths().into_iter().chain([
            "backup/LICENSE",
            "backup/component.json",
            "studio/engine-build.json",
            "studio/guard/studio-browser-guard.mjs",
            "studio/tools/bundled-worker-fonts.mjs",
            "studio/tools/render-worker-font-inputs.mjs",
            "studio/runtime/admission-font.json",
            "studio/runtime/admission-font.ttf",
            "build/geodata/geodata-date.txt",
            "build/geodata/cities500.txt",
            "build/geodata/admin1CodesASCII.txt",
            "build/geodata/admin2Codes.txt",
            "build/geodata/countryInfo.txt",
            "build/geodata/ne_10m_admin_0_countries.geojson",
            "build/geodata/landmarks.ndjson.gz",
            "manager/app/release-worker.cjs",
            "manager/app/media-copy.cjs",
            "manager/.github/frameleaf-release.cjs",
            "manager/.github/verify-release-bundle.cjs",
            "manager/cosign.pub",
            "manager/component.json",
            "manager/package.json",
            "manager/LICENSE",
            "manager/node_modules/@nestjs/common/package.json",
            "manager/node_modules/@nestjs/core/package.json",
            "manager/node_modules/@nestjs/platform-express/package.json",
            "manager/node_modules/express/package.json",
            "manager/node_modules/js-yaml/package.json",
            "manager/node_modules/reflect-metadata/package.json",
            "manager/node_modules/rxjs/package.json",
            "manager/node_modules/zod/package.json",
        ]) {
            relative(name)?;
            if !manifest.files.contains_key(name) {
                return Err("host_component_missing".into());
            }
        }
        #[cfg(windows)]
        let stable_root = crate::windows_protection::stable_path(root)
            .map_err(|_| "host_runtime_path_unavailable")?;
        #[cfg(windows)]
        let root = stable_root.as_path();
        verify_files(root, &manifest.files)?;
        Ok(Self {
            root: root.into(),
            manifest,
            manifest_sha256: format!("{:x}", Sha256::digest(raw)),
        })
    }
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
    pub fn source_revision(&self) -> &str {
        &self.manifest.source_revision
    }
    pub fn certified(&self) -> bool {
        self.manifest.certified
    }
    pub fn backup_engine(&self) -> Result<BackupEngine, String> {
        let role = &self.manifest.entry_points.backup_engine;
        let artifact = self
            .manifest
            .files
            .get(role)
            .ok_or("host_backup_engine_missing")?;
        Ok(BackupEngine {
            executable: self.root.join(role),
            sha256: artifact.sha256.clone(),
        })
    }
    pub fn manager_programs(&self) -> Result<crate::manager_host::Programs<'_>, String> {
        let programs = crate::manager_host::Programs {
            runtime: self,
            root: self.root.clone(),
            node: self.root.join(&self.manifest.entry_points.node),
            main: self.root.join(&self.manifest.entry_points.manager),
        };
        programs.check()?;
        Ok(programs)
    }
    pub fn check_files(&self) -> Result<(), String> {
        verify_files(&self.root, &self.manifest.files)
    }
}

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const AGENT: &str = include_str!("../../runtime/host-agent.mjs");

pub(crate) fn checkpoint_operation_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| {
        id.to_string() == value
            && (1..=8).contains(&id.get_version_num())
            && id.get_variant() == uuid::Variant::RFC4122
    })
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CheckpointDump {
    bytes: u64,
    sha256: String,
}
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CheckpointReceipt {
    schema_version: u32,
    operation_id: String,
    manifest_sha256: String,
    source_revision: String,
    postgres_major: String,
    database_format: String,
    dump: CheckpointDump,
}
impl CheckpointReceipt {
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub(crate) fn matches_restore_runtime(&self, prepared: &PreparedRestore) -> bool {
        self.operation_id == prepared.binding.operation_id
            && self.manifest_sha256 == prepared.binding.manifest_sha256
            && self.source_revision == prepared.binding.source_revision
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || !checkpoint_operation_id(&self.operation_id)
            || !digest_valid(&self.manifest_sha256, 64)
            || !digest_valid(&self.source_revision, 40)
            || self.postgres_major != "19"
            || self.database_format != "frameleaf-canonical"
            || self.dump.bytes == 0
            || self.dump.bytes > 9_007_199_254_740_991
            || !digest_valid(&self.dump.sha256, 64)
        {
            return Err("host_checkpoint_request_invalid".into());
        }
        Ok(())
    }
}
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RestoreBinding {
    schema_version: u32,
    runtime: String,
    pub(crate) operation_id: String,
    review_id: String,
    snapshot_id: String,
    pub(crate) installation_id: String,
    pub(crate) manifest_sha256: String,
    source_revision: String,
    library_id: String,
    recovery_sha256: String,
}
impl RestoreBinding {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.runtime != "native"
            || !checkpoint_operation_id(&self.operation_id)
            || !checkpoint_operation_id(&self.review_id)
            || !digest_valid(&self.snapshot_id, 64)
            || !digest_valid(&self.recovery_sha256, 64)
            || !digest_valid(&self.installation_id, 12)
            || !digest_valid(&self.library_id, 12)
            || !digest_valid(&self.manifest_sha256, 64)
            || !digest_valid(&self.source_revision, 40)
        {
            return Err("host_restore_request_invalid".into());
        }
        Ok(())
    }
}
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreValidation {
    postgres_major: u32,
    vector_version: String,
    canonical: bool,
    execution_state_reconstructed: bool,
}
fn restore_identity(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    value.len() <= 128
        && parts.len() == 2
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()))
}
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PreparedRestore {
    schema_version: u32,
    state: String,
    pub(crate) binding: RestoreBinding,
    pub(crate) attempt_id: String,
    profile_identity: String,
    target_identity: String,
    database_identity: String,
    validation: RestoreValidation,
}
impl PreparedRestore {
    pub(crate) fn validate_reference(
        &self,
        reference: &crate::host_database::Reference,
    ) -> Result<(), String> {
        self.validate()?;
        if !reference.binds_restore(
            &self.binding.operation_id,
            &self.attempt_id,
            [
                &self.profile_identity,
                &self.target_identity,
                &self.database_identity,
            ],
        ) {
            return Err("host_restore_proof_invalid".into());
        }
        Ok(())
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        self.binding.validate()?;
        if self.schema_version != 1
            || self.state != "restore-prepared"
            || !checkpoint_operation_id(&self.attempt_id)
            || ![
                &self.profile_identity,
                &self.target_identity,
                &self.database_identity,
            ]
            .iter()
            .all(|id| restore_identity(id))
            || self.validation.postgres_major != 19
            || self.validation.vector_version != "0.8.7"
            || !self.validation.canonical
            || !self.validation.execution_state_reconstructed
        {
            return Err("host_restore_request_invalid".into());
        }
        Ok(())
    }
}
// Only a successfully correlated private agent event can construct this capability.
pub(crate) struct VerifiedRestore {
    pub(crate) prepared: PreparedRestore,
    pub(crate) reference: crate::host_database::Reference,
    pub(crate) generation: uuid::Uuid,
    pub(crate) verification_id: String,
    _sealed: (),
}
impl VerifiedRestore {
    #[cfg(test)]
    pub(crate) fn test_capture(
        profile: &Path,
        generation: uuid::Uuid,
        prepared: PreparedRestore,
    ) -> Self {
        Self::capture(
            profile,
            generation,
            prepared,
            uuid::Uuid::new_v4().to_string(),
        )
        .unwrap()
    }
    fn capture(
        profile: &Path,
        generation: uuid::Uuid,
        prepared: PreparedRestore,
        verification_id: String,
    ) -> Result<Self, String> {
        prepared.validate()?;
        if generation.is_nil() || !checkpoint_operation_id(&verification_id) {
            return Err("host_restore_proof_invalid".into());
        }
        let reference = crate::host_database::Reference::capture(
            profile,
            &prepared.binding.operation_id,
            &prepared.attempt_id,
        )?;
        if !reference.matches_node_identities([
            &prepared.profile_identity,
            &prepared.target_identity,
            &prepared.database_identity,
        ]) {
            return Err("host_restore_proof_invalid".into());
        }
        Ok(Self {
            prepared,
            reference,
            generation,
            verification_id,
            _sealed: (),
        })
    }
}
#[derive(Deserialize, Serialize, Debug)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
enum AgentEvent {
    #[serde(rename_all = "camelCase")]
    Checkpoint {
        schema_version: u32,
        operation_id: String,
        manifest_sha256: String,
        source_revision: String,
        postgres_major: String,
        database_format: String,
        dump: CheckpointDump,
    },
    #[serde(rename_all = "camelCase")]
    CheckpointCleaned {
        schema_version: u32,
        operation_id: String,
        manifest_sha256: String,
        source_revision: String,
        postgres_major: String,
        database_format: String,
        dump: CheckpointDump,
    },
    #[serde(rename_all = "camelCase")]
    CheckpointCleanupFailed {
        operation_id: String,
        code: String,
    },
    #[serde(rename_all = "camelCase")]
    CheckpointFailed {
        operation_id: String,
        code: String,
    },
    #[serde(rename_all = "camelCase")]
    RestorePrepared {
        schema_version: u32,
        binding: RestoreBinding,
        attempt_id: String,
        profile_identity: String,
        target_identity: String,
        database_identity: String,
        validation: RestoreValidation,
    },
    #[serde(rename_all = "camelCase")]
    RestorePrepareFailed {
        operation_id: String,
        code: String,
    },
    #[serde(rename_all = "camelCase")]
    RestoreVerified {
        prepared: PreparedRestore,
        offline_checksums: bool,
        schema_validated: bool,
        verification_id: String,
    },
    #[serde(rename_all = "camelCase")]
    RestoreVerifyFailed {
        operation_id: String,
        code: String,
        verification_id: String,
    },
    Stopped,
}
struct PendingVerification {
    prepared: PreparedRestore,
    verification_id: String,
}
struct PendingCheckpoint {
    operation: String,
    accepted: bool,
    cleanup: Option<CheckpointReceipt>,
    restore: Option<RestoreBinding>,
    verify: Option<PendingVerification>,
}
struct CheckpointProtocol {
    pending: Mutex<Option<PendingCheckpoint>>,
    failed: AtomicBool,
    stopping: AtomicBool,
    manifest_sha256: String,
    source_revision: String,
}
impl CheckpointProtocol {
    fn new(manifest_sha256: String, source_revision: String) -> Self {
        Self {
            pending: Mutex::new(None),
            failed: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            manifest_sha256,
            source_revision,
        }
    }
    fn begin(&self, operation: &str) -> Result<(), String> {
        self.begin_request(operation, None, None, None)
    }
    fn begin_cleanup(&self, receipt: &CheckpointReceipt) -> Result<(), String> {
        receipt.validate()?;
        if receipt.manifest_sha256 != self.manifest_sha256
            || receipt.source_revision != self.source_revision
        {
            return Err("host_checkpoint_request_invalid".into());
        }
        self.begin_request(&receipt.operation_id, Some(receipt.clone()), None, None)
    }
    fn begin_restore(&self, binding: &RestoreBinding) -> Result<(), String> {
        binding.validate()?;
        if binding.manifest_sha256 != self.manifest_sha256
            || binding.source_revision != self.source_revision
        {
            return Err("host_restore_request_invalid".into());
        }
        self.begin_request(&binding.operation_id, None, Some(binding.clone()), None)
    }
    fn begin_verify_restore(&self, prepared: &PreparedRestore) -> Result<String, String> {
        prepared.validate()?;
        if prepared.binding.manifest_sha256 != self.manifest_sha256
            || prepared.binding.source_revision != self.source_revision
        {
            return Err("host_restore_request_invalid".into());
        }
        let verification_id = uuid::Uuid::new_v4().to_string();
        self.begin_request(
            &prepared.binding.operation_id,
            None,
            None,
            Some(PendingVerification {
                prepared: prepared.clone(),
                verification_id: verification_id.clone(),
            }),
        )?;
        Ok(verification_id)
    }
    fn begin_request(
        &self,
        operation: &str,
        cleanup: Option<CheckpointReceipt>,
        restore: Option<RestoreBinding>,
        verify: Option<PendingVerification>,
    ) -> Result<(), String> {
        if !checkpoint_operation_id(operation) {
            return Err("host_checkpoint_request_invalid".into());
        }
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| "host_checkpoint_protocol_invalid")?;
        if pending.is_some() {
            return Err("host_checkpoint_busy".into());
        }
        *pending = Some(PendingCheckpoint {
            operation: operation.to_owned(),
            accepted: false,
            cleanup,
            restore,
            verify,
        });
        Ok(())
    }
    fn finish(&self, event: &AgentEvent) -> Result<(), String> {
        let operation = match event {
            AgentEvent::Checkpoint { operation_id, .. }
            | AgentEvent::CheckpointCleaned { operation_id, .. }
            | AgentEvent::CheckpointCleanupFailed { operation_id, .. }
            | AgentEvent::CheckpointFailed { operation_id, .. } => operation_id,
            AgentEvent::RestorePrepared { binding, .. } => &binding.operation_id,
            AgentEvent::RestorePrepareFailed { operation_id, .. }
            | AgentEvent::RestoreVerifyFailed { operation_id, .. } => operation_id,
            AgentEvent::RestoreVerified { prepared, .. } => &prepared.binding.operation_id,
            AgentEvent::Stopped => return Err("host_checkpoint_protocol_invalid".into()),
        };
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| "host_checkpoint_protocol_invalid")?;
        if !pending
            .as_ref()
            .is_some_and(|expected| expected.operation == *operation && expected.accepted)
        {
            return Err("host_checkpoint_protocol_invalid".into());
        }
        pending.take();
        Ok(())
    }
    fn parse(&self, raw: &[u8]) -> Result<AgentEvent, String> {
        let invalid = || "host_checkpoint_protocol_invalid".to_owned();
        if raw.len() > 8192 || !raw.ends_with(b"\n") || raw[..raw.len() - 1].contains(&b'\n') {
            return Err(invalid());
        }
        let event: AgentEvent = serde_json::from_slice(raw).map_err(|_| invalid())?;
        let operation = match &event {
            AgentEvent::Checkpoint {
                schema_version,
                operation_id,
                manifest_sha256,
                source_revision,
                postgres_major,
                database_format,
                dump,
            }
            | AgentEvent::CheckpointCleaned {
                schema_version,
                operation_id,
                manifest_sha256,
                source_revision,
                postgres_major,
                database_format,
                dump,
            } => {
                if *schema_version != 1
                    || manifest_sha256 != &self.manifest_sha256
                    || source_revision != &self.source_revision
                    || postgres_major != "19"
                    || database_format != "frameleaf-canonical"
                    || dump.bytes == 0
                    || dump.bytes > 9_007_199_254_740_991
                    || !digest_valid(&dump.sha256, 64)
                {
                    return Err(invalid());
                }
                operation_id
            }
            AgentEvent::CheckpointFailed { operation_id, code } => {
                if code != "host_checkpoint_failed" {
                    return Err(invalid());
                }
                operation_id
            }
            AgentEvent::CheckpointCleanupFailed { operation_id, code } => {
                if code != "host_checkpoint_cleanup_failed" {
                    return Err(invalid());
                }
                operation_id
            }
            AgentEvent::RestorePrepared {
                schema_version,
                binding,
                attempt_id,
                profile_identity,
                target_identity,
                database_identity,
                validation,
            } => {
                binding.validate().map_err(|_| invalid())?;
                if *schema_version != 1
                    || !checkpoint_operation_id(attempt_id)
                    || ![profile_identity, target_identity, database_identity]
                        .iter()
                        .all(|id| restore_identity(id))
                    || validation.postgres_major != 19
                    || validation.vector_version != "0.8.7"
                    || !validation.canonical
                    || !validation.execution_state_reconstructed
                {
                    return Err(invalid());
                }
                &binding.operation_id
            }
            AgentEvent::RestorePrepareFailed { operation_id, code } => {
                if code != "host_restore_failed" {
                    return Err(invalid());
                }
                operation_id
            }
            AgentEvent::RestoreVerified {
                prepared,
                offline_checksums,
                schema_validated,
                verification_id,
            } => {
                prepared.validate().map_err(|_| invalid())?;
                if !offline_checksums
                    || !schema_validated
                    || !checkpoint_operation_id(verification_id)
                {
                    return Err(invalid());
                }
                &prepared.binding.operation_id
            }
            AgentEvent::RestoreVerifyFailed {
                operation_id,
                code,
                verification_id,
            } => {
                if code != "host_restore_verification_failed"
                    || !checkpoint_operation_id(verification_id)
                {
                    return Err(invalid());
                }
                operation_id
            }
            AgentEvent::Stopped => {
                return if self.stopping.load(Ordering::Acquire) {
                    Ok(event)
                } else {
                    Err(invalid())
                }
            }
        };
        let mut pending = self.pending.lock().map_err(|_| invalid())?;
        let cleanup = matches!(
            event,
            AgentEvent::CheckpointCleaned { .. } | AgentEvent::CheckpointCleanupFailed { .. }
        );
        let restore = matches!(
            event,
            AgentEvent::RestorePrepared { .. } | AgentEvent::RestorePrepareFailed { .. }
        );
        let verify = matches!(
            event,
            AgentEvent::RestoreVerified { .. } | AgentEvent::RestoreVerifyFailed { .. }
        );
        match pending.as_mut() {
            Some(expected)
                if expected.operation == *operation
                    && !expected.accepted
                    && expected.cleanup.is_some() == cleanup
                    && expected.restore.is_some() == restore
                    && expected.verify.is_some() == verify =>
            {
                if let (Some(receipt), AgentEvent::CheckpointCleaned { .. }) =
                    (&expected.cleanup, &event)
                {
                    let mut returned = serde_json::to_value(&event).map_err(|_| invalid())?;
                    returned
                        .as_object_mut()
                        .ok_or_else(invalid)?
                        .remove("state");
                    if returned != serde_json::to_value(receipt).map_err(|_| invalid())? {
                        return Err(invalid());
                    }
                }
                if let (
                    Some(binding),
                    AgentEvent::RestorePrepared {
                        binding: returned, ..
                    },
                ) = (&expected.restore, &event)
                {
                    if binding != returned {
                        return Err(invalid());
                    }
                }
                if let Some(expected) = &expected.verify {
                    match &event {
                        AgentEvent::RestoreVerified {
                            prepared,
                            verification_id,
                            ..
                        } if expected.prepared == *prepared
                            && expected.verification_id == *verification_id => {}
                        AgentEvent::RestoreVerifyFailed {
                            verification_id, ..
                        } if expected.verification_id == *verification_id => {}
                        _ => return Err(invalid()),
                    }
                }
                expected.accepted = true;
            }
            _ => return Err(invalid()),
        }
        drop(pending);
        Ok(event)
    }
}
fn agent_line(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, String> {
    let mut raw = Vec::new();
    let count = Read::by_ref(reader)
        .take(8193)
        .read_until(b'\n', &mut raw)
        .map_err(|_| "host_agent_pipe_failed")?;
    if count == 0 {
        return Ok(None);
    }
    if count > 8192 || !raw.ends_with(b"\n") {
        return Err("host_checkpoint_protocol_invalid".into());
    }
    Ok(Some(raw))
}
fn read_agent_output(
    mut reader: impl BufRead,
    ready: mpsc::Sender<Result<(), String>>,
    checkpoints: mpsc::SyncSender<AgentEvent>,
    protocol: Arc<CheckpointProtocol>,
    mode: HostMode,
    fault: impl FnOnce(),
) {
    let result = (|| -> Result<(), String> {
        let raw = agent_line(&mut reader)?.ok_or("host_readiness_failed")?;
        if serde_json::from_slice::<serde_json::Value>(&raw).ok()
            != Some(serde_json::json!({"state":mode.ready_state()}))
        {
            return Err("host_readiness_failed".into());
        }
        let _ = ready.send(Ok(()));
        let mut stopped = false;
        while let Some(raw) = agent_line(&mut reader)? {
            if stopped {
                return Err("host_checkpoint_protocol_invalid".into());
            }
            match protocol.parse(&raw)? {
                AgentEvent::Stopped => stopped = true,
                event => checkpoints
                    .try_send(event)
                    .map_err(|_| "host_checkpoint_protocol_invalid")?,
            }
        }
        if !protocol.stopping.load(Ordering::Acquire) {
            return Err("host_agent_pipe_failed".into());
        }
        Ok(())
    })();
    if result.is_err() {
        protocol.failed.store(true, Ordering::Release);
        let _ = ready.send(Err("host_readiness_failed".into()));
        fault();
    }
}

fn private_file(path: &Path, append: bool) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .append(append);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options.open(path).map_err(|_| "host_state_file_invalid")?;
    let meta = file.metadata().map_err(|_| "host_state_file_invalid")?;
    if !meta.is_file() {
        return Err("host_state_file_invalid".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err("host_state_file_invalid".into());
        }
    }
    Ok(file)
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HostMode {
    #[default]
    Server,
    Database,
    CheckpointCleanup,
    RestorePrepare,
}
impl HostMode {
    pub(crate) fn uses_database(self) -> bool {
        matches!(self, Self::Server | Self::Database)
    }
    pub(crate) fn ready_state(self) -> &'static str {
        match self {
            Self::Server => "running",
            Self::Database => "database-ready",
            Self::CheckpointCleanup => "checkpoint-cleanup-ready",
            Self::RestorePrepare => "restore-prepare-ready",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HostStart<'a> {
    mode: HostMode,
    state: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    database_reference: Option<&'a crate::host_database::Reference>,
    runtime: &'a Path,
    manifest_sha256: &'a str,
    source_revision: &'a str,
    postgres_major: &'a str,
    password: &'a str,
    database_port: u16,
    api_port: u16,
    entry_points: &'a EntryPoints,
}

struct HostOwner {
    tree: crate::process_tree::ProcessTree,
    terminated: Mutex<bool>,
    _code_lease: crate::package_lease::CodeLease,
}
impl HostOwner {
    fn terminate(&self) {
        let mut terminated = self
            .terminated
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !*terminated {
            self.tree.terminate();
            *terminated = true;
        }
    }
}
#[cfg(unix)]
fn owned_exit(child: &mut Child, owner: &HostOwner) -> Result<Option<ExitStatus>, String> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            return Ok(None);
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            *owner
                .terminated
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = true;
        }
        return Err("host_process_state_failed".into());
    }
    if unsafe { info.assume_init().si_pid() } == 0 {
        return Ok(None);
    }
    // Keep the owned leader unreaped until its group is terminated: the PID cannot be reused here.
    owner.terminate();
    child
        .wait()
        .map(Some)
        .map_err(|_| "host_process_state_failed".into())
}
#[cfg(windows)]
fn owned_exit(child: &mut Child, _owner: &HostOwner) -> Result<Option<ExitStatus>, String> {
    child
        .try_wait()
        .map_err(|_| "host_process_state_failed".into())
}
pub struct HostProcess {
    owner: Arc<HostOwner>,
    pid: u32,
    input: Option<ChildStdin>,
    ready: Receiver<Result<(), String>>,
    exited: Receiver<Result<(), String>>,
    stopped: Option<Result<(), String>>,
    protocol: Arc<CheckpointProtocol>,
    checkpoints: Receiver<AgentEvent>,
    checkpoint_started: Option<Instant>,
    ready_seen: bool,
    profile: PathBuf,
    controller_generation: Option<uuid::Uuid>,
    verified_restore: Option<VerifiedRestore>,
    mode: HostMode,
}
fn direct_profile(state: &Path) -> Result<(), String> {
    // Controller-managed profiles must enter through their exact journal owner.
    match std::fs::symlink_metadata(state.join("controller-state.json")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("host_controller_required".into()),
    }
}
impl VerifiedHostRuntime {
    /// Credentials are native-only; callers persist them in the OS credential store before first start.
    pub fn start(
        &self,
        state: &Path,
        password: &Zeroizing<String>,
        database_port: u16,
        api_port: u16,
    ) -> Result<HostProcess, String> {
        self.start_mode(
            state,
            password,
            database_port,
            api_port,
            HostMode::Server,
            None,
        )
    }
    pub(crate) fn start_mode(
        &self,
        state: &Path,
        password: &Zeroizing<String>,
        database_port: u16,
        api_port: u16,
        mode: HostMode,
        mut owner: Option<&mut crate::host_state::Owner>,
    ) -> Result<HostProcess, String> {
        let (database_reference, controller_generation) = if let Some(owner) = owner.as_mut() {
            let (profile, reference, generation) =
                owner.launch_state(&self.manifest_sha256, mode)?;
            if profile != state {
                return Err("host_controller_binding_changed".into());
            }
            (reference, Some(generation))
        } else {
            direct_profile(state)?;
            (None, None)
        };
        self.check_files()?;
        if password.len() < 24
            || password.len() > 512
            || password.contains(['\r', '\n', '\0'])
            || database_port == 0
            || api_port == 0
            || database_port == api_port
        {
            return Err("host_config_invalid".into());
        }
        if state.starts_with(&self.root) || self.root.starts_with(state) {
            return Err("host_state_overlaps_runtime".into());
        }
        let code_lease = crate::package_lease::CodeLease::acquire(
            self.root.parent().ok_or("native_manager_layout_invalid")?,
        )?;
        crate::runtime_store::private_directory(state)?;
        if mode == HostMode::CheckpointCleanup {
            crate::host_storage::check_cleanup(state)?;
        } else {
            crate::host_storage::check(state)?;
        }
        if mode.uses_database() {
            let database = match &database_reference {
                Some(reference) => reference.resolve(state)?,
                None => state.join("database"),
            };
            match std::fs::symlink_metadata(&database) {
                Ok(_) => crate::host_storage::check(&database)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("host_storage_unavailable".into()),
            }
        }
        let lease = private_file(&state.join("lease.lock"), false)?;
        lease.try_lock().map_err(|_| "host_already_owned")?;
        let message = Zeroizing::new(
            serde_json::to_vec(&HostStart {
                mode,
                state,
                database_reference: if mode.uses_database() {
                    database_reference.as_ref()
                } else {
                    None
                },
                runtime: &self.root,
                manifest_sha256: &self.manifest_sha256,
                source_revision: &self.manifest.source_revision,
                postgres_major: "19",
                password,
                database_port,
                api_port,
                entry_points: &self.manifest.entry_points,
            })
            .map_err(|_| "host_config_invalid")?,
        );
        if let Some(owner) = owner.as_mut() {
            owner.launch_state(&self.manifest_sha256, mode)?;
        } else {
            direct_profile(state)?;
        }
        let mut command = Command::new(self.root.join(relative(&self.manifest.entry_points.node)?));
        command
            .args(["--input-type=module", "--eval", AGENT])
            .env_clear()
            .env("FRAMELEAF_HOST_AGENT", "1")
            .current_dir(state)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(private_file(&state.join("agent.log"), true)?);
        #[cfg(windows)]
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
        #[cfg(windows)]
        command.env("NODE_OPTIONS", crate::windows_protection::NODE_PATH_OPTIONS);
        code_lease.inherit(&mut command);
        crate::process_tree::configure(&mut command);
        let mut child = command.spawn().map_err(|_| "host_agent_start_failed")?;
        let tree = match crate::process_tree::ProcessTree::attach(&child) {
            Ok(tree) => tree,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let input = child.stdin.take();
        let output = child.stdout.take();
        let (sender, ready) = mpsc::channel();
        let owner = Arc::new(HostOwner {
            tree,
            terminated: Mutex::new(false),
            _code_lease: code_lease,
        });
        let pid = child.id();
        let monitor_owner = owner.clone();
        let (exit_sender, exited) = mpsc::channel();
        std::thread::spawn(move || {
            let _lease = lease;
            let result = loop {
                match owned_exit(&mut child, &monitor_owner) {
                    Ok(Some(status)) => {
                        break if status.success() {
                            Ok(())
                        } else {
                            Err("host_process_exited".into())
                        }
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                    Err(_) => {
                        monitor_owner.terminate();
                        let _ = child.wait();
                        break Err("host_process_state_failed".into());
                    }
                }
            };
            monitor_owner.terminate();
            drop(_lease);
            let _ = exit_sender.send(result);
        });
        let protocol = Arc::new(CheckpointProtocol::new(
            self.manifest_sha256.clone(),
            self.manifest.source_revision.clone(),
        ));
        let (checkpoint_sender, checkpoints) = mpsc::sync_channel(1);
        let mut process = HostProcess {
            owner,
            pid,
            input,
            ready,
            exited,
            stopped: None,
            protocol: protocol.clone(),
            checkpoints,
            checkpoint_started: None,
            ready_seen: false,
            profile: state.into(),
            controller_generation,
            verified_restore: None,
            mode,
        };
        let Some(output) = output else {
            return Err("host_agent_pipe_failed".into());
        };
        let output_owner = process.owner.clone();
        std::thread::spawn(move || {
            read_agent_output(
                BufReader::new(output),
                sender,
                checkpoint_sender,
                protocol,
                mode,
                || output_owner.terminate(),
            )
        });
        process
            .input
            .as_mut()
            .ok_or("host_agent_pipe_failed")?
            .write_all(&message)
            .and_then(|_| process.input.as_mut().unwrap().write_all(b"\n"))
            .map_err(|_| "host_agent_pipe_failed")?;
        Ok(process)
    }
}
impl HostProcess {
    /// Only this owned child's exit channel is authoritative; never reconnect to a saved PID.
    pub fn is_running(&mut self) -> Result<bool, String> {
        if self.protocol.failed.load(Ordering::Acquire) {
            return Err("host_checkpoint_protocol_invalid".into());
        }
        if let Some(result) = &self.stopped {
            return result.clone().map(|()| false);
        }
        match self.exited.try_recv() {
            Ok(result) => {
                self.stopped = Some(result.clone());
                result.map(|()| false)
            }
            Err(mpsc::TryRecvError::Empty) => Ok(true),
            Err(mpsc::TryRecvError::Disconnected) => Err("host_process_state_failed".into()),
        }
    }

    /// An owner disappearing during startup must drain the host without waiting for API readiness.
    pub fn wait_ready_or_cancel(
        &mut self,
        timeout: Duration,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<bool, String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                self.stop()?;
                return Ok(false);
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err("host_readiness_timeout".into());
            }
            match self
                .ready
                .recv_timeout(remaining.min(Duration::from_millis(100)))
            {
                Ok(result) => {
                    result?;
                    if !self.is_running()? {
                        return Err("host_process_exited".into());
                    }
                    self.ready_seen = true;
                    return Ok(true);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("host_readiness_failed".into());
                }
            }
        }
    }

    pub fn process_id(&self) -> u32 {
        self.pid
    }
    pub fn wait_ready(&mut self, timeout: Duration) -> Result<(), String> {
        let result = self
            .ready
            .recv_timeout(timeout)
            .map_err(|_| "host_readiness_timeout".to_string())
            .and_then(|result| result);
        if let Err(error) = result {
            self.input.take();
            self.owner.terminate();
            let _ = self.exited.recv_timeout(Duration::from_secs(10));
            self.stopped = Some(Err(error.clone()));
            return Err(error);
        }
        if !self.is_running()? {
            return Err("host_process_exited".into());
        }
        self.ready_seen = true;
        Ok(())
    }
    pub fn request_checkpoint(&mut self, operation: &str) -> Result<(), String> {
        self.send_checkpoint_request(operation, None)
    }
    pub(crate) fn request_checkpoint_cleanup(
        &mut self,
        receipt: &CheckpointReceipt,
    ) -> Result<(), String> {
        self.send_checkpoint_request(&receipt.operation_id, Some(receipt))
    }
    pub(crate) fn request_restore(&mut self, binding: &RestoreBinding) -> Result<(), String> {
        self.verified_restore = None;
        if self.mode != HostMode::RestorePrepare
            || !self.ready_seen
            || self.protocol.stopping.load(Ordering::Acquire)
            || !self.is_running()?
        {
            return Err("host_restore_unavailable".into());
        }
        self.protocol.begin_restore(binding)?;
        self.checkpoint_started = Some(Instant::now());
        let request = serde_json::json!({"protocolVersion":1,"action":"prepare-restore","operationId":binding.operation_id,"binding":binding});
        self.input
            .as_mut()
            .ok_or("host_agent_pipe_failed")?
            .write_all(format!("{request}\n").as_bytes())
            .map_err(|_| "host_agent_pipe_failed".into())
    }
    pub(crate) fn request_verify_restore(
        &mut self,
        prepared: &PreparedRestore,
    ) -> Result<(), String> {
        self.verified_restore = None;
        if self.mode != HostMode::RestorePrepare
            || !self.ready_seen
            || self.protocol.stopping.load(Ordering::Acquire)
            || !self.is_running()?
        {
            return Err("host_restore_unavailable".into());
        }
        let verification_id = self.protocol.begin_verify_restore(prepared)?;
        self.checkpoint_started = Some(Instant::now());
        let request = serde_json::json!({"protocolVersion":1,"action":"verify-restore","operationId":prepared.binding.operation_id,"prepared":prepared,"verificationId":verification_id});
        self.input
            .as_mut()
            .ok_or("host_agent_pipe_failed")?
            .write_all(format!("{request}\n").as_bytes())
            .map_err(|_| "host_agent_pipe_failed".into())
    }
    fn send_checkpoint_request(
        &mut self,
        operation: &str,
        cleanup: Option<&CheckpointReceipt>,
    ) -> Result<(), String> {
        if self.mode == HostMode::RestorePrepare
            || !self.ready_seen
            || self.protocol.stopping.load(Ordering::Acquire)
            || !self.is_running()?
        {
            return Err("host_checkpoint_unavailable".into());
        }
        let request = if let Some(receipt) = cleanup {
            self.protocol.begin_cleanup(receipt)?;
            serde_json::json!({"protocolVersion":1,"action":"cleanup-checkpoint","operationId":operation,"checkpoint":receipt})
        } else {
            self.protocol.begin(operation)?;
            serde_json::json!({"protocolVersion":1,"action":"checkpoint","operationId":operation})
        };
        self.checkpoint_started = Some(Instant::now());
        let wire = format!("{request}\n");
        self.input
            .as_mut()
            .ok_or("host_agent_pipe_failed")?
            .write_all(wire.as_bytes())
            .map_err(|_| "host_agent_pipe_failed".into())
    }
    pub fn poll_checkpoint(&mut self) -> Result<Option<serde_json::Value>, String> {
        if self.protocol.failed.load(Ordering::Acquire) {
            return Err("host_checkpoint_protocol_invalid".into());
        }
        match self.checkpoints.try_recv() {
            Ok(event) => {
                if self.checkpoint_started.take().is_none() {
                    return Err("host_checkpoint_protocol_invalid".into());
                }
                self.protocol.finish(&event)?;
                if let (
                    Some(generation),
                    AgentEvent::RestoreVerified {
                        prepared,
                        verification_id,
                        ..
                    },
                ) = (self.controller_generation, &event)
                {
                    self.verified_restore = Some(VerifiedRestore::capture(
                        &self.profile,
                        generation,
                        prepared.clone(),
                        verification_id.clone(),
                    )?);
                }
                serde_json::to_value(event)
                    .map(Some)
                    .map_err(|_| "host_checkpoint_protocol_invalid".into())
            }
            Err(mpsc::TryRecvError::Empty) => {
                if self
                    .checkpoint_started
                    .is_some_and(|start| start.elapsed() >= Duration::from_secs(7200))
                {
                    return Err("host_checkpoint_timeout".into());
                }
                Ok(None)
            }
            Err(mpsc::TryRecvError::Disconnected) => Err("host_agent_pipe_failed".into()),
        }
    }
    pub(crate) fn take_verified_restore(
        &mut self,
        operation: &str,
        nonce: &str,
    ) -> Result<VerifiedRestore, String> {
        let proof = self
            .verified_restore
            .take()
            .ok_or("host_restore_proof_invalid")?;
        if self.stopped != Some(Ok(()))
            || self.protocol.failed.load(Ordering::Acquire)
            || self.checkpoint_started.is_some()
            || proof.prepared.binding.operation_id != operation
            || proof.verification_id != nonce
        {
            return Err("host_restore_proof_invalid".into());
        }
        proof.reference.resolve(&self.profile)?;
        Ok(proof)
    }
    pub fn stop(&mut self) -> Result<(), String> {
        self.protocol.stopping.store(true, Ordering::Release);
        if let Some(result) = &self.stopped {
            return result.clone();
        }
        if let Some(mut input) = self.input.take() {
            let _ = input.write_all(b"stop\n");
        }
        let result = match self.exited.recv_timeout(Duration::from_secs(150)) {
            Ok(result) => result,
            Err(_) => {
                self.owner.terminate();
                let _ = self.exited.recv_timeout(Duration::from_secs(10));
                Err("host_shutdown_failed".into())
            }
        };
        self.stopped = Some(result.clone());
        result
    }
}
impl Drop for HostProcess {
    fn drop(&mut self) {
        self.input.take();
        if self.stopped.is_none() {
            self.owner.terminate();
            let _ = self.exited.recv_timeout(Duration::from_secs(10));
        }
    }
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    const OPERATION: &str = "11111111-1111-4111-8111-111111111111";
    fn receipt() -> serde_json::Value {
        serde_json::json!({"state":"checkpoint","schemaVersion":1,"operationId":OPERATION,
            "manifestSha256":"a".repeat(64),"sourceRevision":"b".repeat(40),"postgresMajor":"19",
            "databaseFormat":"frameleaf-canonical","dump":{"bytes":27,"sha256":"c".repeat(64)}})
    }
    fn wire(value: &serde_json::Value) -> Vec<u8> {
        format!("{value}\n").into_bytes()
    }

    fn restore_binding() -> RestoreBinding {
        serde_json::from_value(serde_json::json!({"schemaVersion":1,"runtime":"native","operationId":OPERATION,
            "reviewId":"22222222-2222-4222-8222-222222222222","snapshotId":"c".repeat(64),"installationId":"d".repeat(12),
            "manifestSha256":"a".repeat(64),"sourceRevision":"b".repeat(40),"libraryId":"e".repeat(12),"recoverySha256":"f".repeat(64)})).unwrap()
    }
    fn prepared() -> serde_json::Value {
        serde_json::json!({"schemaVersion":1,"state":"restore-prepared","binding":restore_binding(),
            "attemptId":"33333333-3333-4333-8333-333333333333","profileIdentity":"1:2","targetIdentity":"1:3","databaseIdentity":"1:4",
            "validation":{"postgresMajor":19,"vectorVersion":"0.8.7","canonical":true,"executionStateReconstructed":true}})
    }
    #[test]
    fn verified_restore_authority_is_bound_to_the_native_physical_target_and_generation() {
        let profile = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-verified-{}", uuid::Uuid::new_v4()));
        let operation = profile.join("restore-targets").join(OPERATION);
        let target = operation.join("33333333-3333-4333-8333-333333333333");
        for path in [
            &profile,
            &profile.join("restore-targets"),
            &operation,
            &target,
            &target.join("database"),
        ] {
            crate::runtime_store::private_directory(path).unwrap();
        }
        let mut value = prepared();
        for (field, path) in [
            ("profileIdentity", profile.clone()),
            ("targetIdentity", target.clone()),
            ("databaseIdentity", target.join("database")),
        ] {
            let root =
                cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&path).unwrap());
            let id = crate::copy_source::root_identity(&root).unwrap();
            #[cfg(windows)]
            let id = {
                let parts: Vec<_> = id.split(':').collect();
                format!(
                    "{}:{}",
                    parts[0],
                    (parts[1].parse::<u64>().unwrap() << 32) | parts[2].parse::<u64>().unwrap()
                )
            };
            value[field] = serde_json::json!(id);
        }
        let expected: PreparedRestore = serde_json::from_value(value.clone()).unwrap();
        let generation = uuid::Uuid::new_v4();
        let proof =
            VerifiedRestore::capture(&profile, generation, expected.clone(), OPERATION.into())
                .unwrap();
        assert_eq!(proof.generation, generation);
        assert_eq!(
            proof.reference.resolve(&profile).unwrap(),
            target.join("database")
        );
        assert!(VerifiedRestore::capture(
            &profile,
            uuid::Uuid::nil(),
            expected.clone(),
            OPERATION.into()
        )
        .is_err());
        value["databaseIdentity"] = serde_json::json!("1:999");
        assert!(VerifiedRestore::capture(
            &profile,
            generation,
            serde_json::from_value(value).unwrap(),
            OPERATION.into()
        )
        .is_err());
        // Exercise one-shot admission on the real HostProcess cache without an installed host pack.
        let mut command = std::process::Command::new("node");
        command
            .args(["--eval", "process.stdin.resume()"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        crate::process_tree::configure(&mut command);
        let mut child = command.spawn().unwrap();
        let owner = Arc::new(HostOwner {
            tree: crate::process_tree::ProcessTree::attach(&child).unwrap(),
            terminated: Mutex::new(false),
            _code_lease: crate::package_lease::CodeLease::acquire(&profile).unwrap(),
        });
        let (_, ready) = mpsc::channel();
        let (_, exited) = mpsc::channel();
        let (_, checkpoints) = mpsc::sync_channel(1);
        let mut process = HostProcess {
            owner,
            pid: child.id(),
            input: None,
            ready,
            exited,
            stopped: Some(Ok(())),
            protocol: Arc::new(CheckpointProtocol::new("a".repeat(64), "b".repeat(40))),
            checkpoints,
            checkpoint_started: None,
            ready_seen: true,
            profile: profile.clone(),
            controller_generation: Some(generation),
            verified_restore: None,
            mode: HostMode::RestorePrepare,
        };
        for mutation in [
            "valid",
            "operation",
            "nonce",
            "running",
            "failed-stop",
            "pending",
            "protocol",
        ] {
            process.verified_restore = Some(
                VerifiedRestore::capture(&profile, generation, expected.clone(), OPERATION.into())
                    .unwrap(),
            );
            process.stopped = Some(Ok(()));
            process.checkpoint_started = None;
            process.protocol.failed.store(false, Ordering::Release);
            match mutation {
                "running" => process.stopped = None,
                "failed-stop" => process.stopped = Some(Err("host_shutdown_failed".into())),
                "pending" => process.checkpoint_started = Some(Instant::now()),
                "protocol" => process.protocol.failed.store(true, Ordering::Release),
                _ => {}
            }
            let operation = if mutation == "operation" {
                "22222222-2222-4222-8222-222222222222"
            } else {
                OPERATION
            };
            let nonce = if mutation == "nonce" {
                "33333333-3333-4333-8333-333333333333"
            } else {
                OPERATION
            };
            assert_eq!(
                process.take_verified_restore(operation, nonce).is_ok(),
                mutation == "valid",
                "{mutation}"
            );
            assert!(process.take_verified_restore(OPERATION, OPERATION).is_err());
        }
        process.owner.terminate();
        child.wait().unwrap();
        drop(process);
        std::fs::write(target.join("database/postmaster.pid"), b"not adopted").unwrap();
        assert!(
            VerifiedRestore::capture(&profile, generation, expected, OPERATION.into()).is_err()
        );
        std::fs::remove_dir_all(profile).unwrap();
    }
    #[test]
    fn verified_restore_matches_the_entire_pending_prepared_receipt_and_checksum_proof() {
        let protocol = CheckpointProtocol::new("a".repeat(64), "b".repeat(40));
        let expected: PreparedRestore = serde_json::from_value(prepared()).unwrap();
        let mut verified = serde_json::json!({"state":"restore-verified","prepared":expected,"offlineChecksums":true,"schemaValidated":true});
        assert!(protocol.parse(&wire(&verified)).is_err());
        let verification_id = protocol.begin_verify_restore(&expected).unwrap();
        verified["verificationId"] = serde_json::json!(verification_id);
        assert!(protocol.begin_verify_restore(&expected).is_err());
        assert!(protocol.parse(&wire(&prepared())).is_err());
        for mutation in [
            "attempt",
            "database",
            "binding",
            "checksum",
            "schema",
            "missing-schema",
            "path",
        ] {
            let mut changed = verified.clone();
            match mutation {
                "attempt" => changed["prepared"]["attemptId"] = serde_json::json!(OPERATION),
                "database" => changed["prepared"]["databaseIdentity"] = serde_json::json!("1:999"),
                "binding" => {
                    changed["prepared"]["binding"]["snapshotId"] = serde_json::json!("0".repeat(64))
                }
                "checksum" => changed["offlineChecksums"] = serde_json::json!(false),
                "schema" => changed["schemaValidated"] = serde_json::json!(false),
                "missing-schema" => {
                    changed.as_object_mut().unwrap().remove("schemaValidated");
                }
                _ => changed["path"] = serde_json::json!("/outside"),
            }
            assert!(protocol.parse(&wire(&changed)).is_err(), "{mutation}");
        }
        let accepted = protocol.parse(&wire(&verified)).unwrap();
        assert!(protocol.parse(&wire(&verified)).is_err());
        protocol.finish(&accepted).unwrap();
        assert!(protocol.parse(&wire(&verified)).is_err());
        protocol.begin_verify_restore(&expected).unwrap();
        assert!(
            protocol.parse(&wire(&verified)).is_err(),
            "a delayed prior verification must not satisfy a fresh retry"
        );
    }

    #[test]
    fn restore_receipt_requires_exact_pending_binding_and_canonical_validation() {
        let protocol = CheckpointProtocol::new("a".repeat(64), "b".repeat(40));
        assert!(protocol.parse(&wire(&prepared())).is_err());
        let binding = restore_binding();
        protocol.begin_restore(&binding).unwrap();
        assert!(protocol.begin_restore(&binding).is_err());
        assert!(protocol.parse(&wire(&receipt())).is_err());
        for changed in [
            {
                let mut v = prepared();
                v["binding"]["reviewId"] = serde_json::json!(OPERATION);
                v
            },
            {
                let mut v = prepared();
                v["binding"]["snapshotId"] = serde_json::json!("0".repeat(64));
                v
            },
            {
                let mut v = prepared();
                v["validation"]["canonical"] = serde_json::json!(false);
                v
            },
            {
                let mut v = prepared();
                v["validation"]["executionStateReconstructed"] = serde_json::json!(false);
                v
            },
            {
                let mut v = prepared();
                v["attemptId"] = serde_json::json!("../outside");
                v
            },
            {
                let mut v = prepared();
                v["targetIdentity"] = serde_json::json!("/outside");
                v
            },
            {
                let mut v = prepared();
                v["path"] = serde_json::json!("/outside");
                v
            },
        ] {
            assert!(protocol.parse(&wire(&changed)).is_err());
        }
        let event = protocol.parse(&wire(&prepared())).unwrap();
        protocol.finish(&event).unwrap();
        assert!(protocol.parse(&wire(&prepared())).is_err());
        protocol.begin(OPERATION).unwrap();
        assert!(protocol.parse(&wire(&prepared())).is_err());
        let other = CheckpointProtocol::new("0".repeat(64), "b".repeat(40));
        assert!(other.begin_restore(&binding).is_err());
        let failure = serde_json::json!({"state":"restore-prepare-failed","operationId":OPERATION,"code":"host_restore_failed"});
        let failed = CheckpointProtocol::new("a".repeat(64), "b".repeat(40));
        failed.begin_restore(&binding).unwrap();
        let mut changed = failure.clone();
        changed["code"] = serde_json::json!("private-error");
        assert!(failed.parse(&wire(&changed)).is_err());
        let event = failed.parse(&wire(&failure)).unwrap();
        failed.finish(&event).unwrap();
    }

    #[test]
    fn checkpoint_receipts_require_an_outstanding_operation_and_its_exact_runtime() {
        let protocol = CheckpointProtocol::new("a".repeat(64), "b".repeat(40));
        assert!(protocol.parse(&wire(&receipt())).is_err());
        protocol.begin(OPERATION).unwrap();
        assert!(protocol.begin(OPERATION).is_err());
        for (field, value) in [
            (
                "operationId",
                serde_json::json!("22222222-2222-4222-8222-222222222222"),
            ),
            ("manifestSha256", serde_json::json!("d".repeat(64))),
            ("sourceRevision", serde_json::json!("e".repeat(40))),
            ("schemaVersion", serde_json::json!(2)),
            ("postgresMajor", serde_json::json!("18")),
            ("databaseFormat", serde_json::json!("immich-source")),
            ("extra", serde_json::json!(true)),
            (
                "dump",
                serde_json::json!({"bytes":0,"sha256":"c".repeat(64)}),
            ),
            (
                "dump",
                serde_json::json!({"bytes":9007199254740992u64,"sha256":"c".repeat(64)}),
            ),
            ("dump", serde_json::json!({"bytes":1,"sha256":"not-a-hash"})),
            (
                "dump",
                serde_json::json!({"bytes":1.5,"sha256":"c".repeat(64)}),
            ),
        ] {
            let mut changed = receipt();
            changed[field] = value;
            assert!(protocol.parse(&wire(&changed)).is_err(), "accepted {field}");
        }
        let event = protocol.parse(&wire(&receipt())).unwrap();
        protocol.finish(&event).unwrap();
        assert!(protocol.parse(&wire(&receipt())).is_err());
        for value in [
            "../outside",
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(protocol.begin(value).is_err());
        }
    }

    #[test]
    fn cleanup_receipts_cannot_cross_actions_or_change_the_expected_dump() {
        let protocol = CheckpointProtocol::new("a".repeat(64), "b".repeat(40));
        let mut expected = receipt();
        expected.as_object_mut().unwrap().remove("state");
        let expected: CheckpointReceipt = serde_json::from_value(expected).unwrap();
        protocol.begin_cleanup(&expected).unwrap();
        assert!(protocol.parse(&wire(&receipt())).is_err());
        let mut cleaned = receipt();
        cleaned["state"] = serde_json::json!("checkpoint-cleaned");
        let mut changed = cleaned.clone();
        changed["dump"]["sha256"] = serde_json::json!("d".repeat(64));
        assert!(protocol.parse(&wire(&changed)).is_err());
        let event = protocol.parse(&wire(&cleaned)).unwrap();
        protocol.finish(&event).unwrap();
        protocol.begin(OPERATION).unwrap();
        assert!(protocol.parse(&wire(&cleaned)).is_err());
        let event = protocol.parse(&wire(&receipt())).unwrap();
        protocol.finish(&event).unwrap();
        protocol.begin_cleanup(&expected).unwrap();
        let failure = serde_json::json!({"state":"checkpoint-cleanup-failed", "operationId":OPERATION, "code":"host_checkpoint_cleanup_failed"});
        let event = protocol.parse(&wire(&failure)).unwrap();
        protocol.finish(&event).unwrap();
    }

    #[test]
    fn checkpoint_failures_are_scoped_and_never_carry_untrusted_error_details() {
        let protocol = CheckpointProtocol::new("a".repeat(64), "b".repeat(40));
        protocol.begin(OPERATION).unwrap();
        let failure = serde_json::json!({"state":"checkpoint-failed","operationId":OPERATION,"code":"host_checkpoint_failed"});
        let mut secret = failure.clone();
        secret["code"] = serde_json::json!("synthetic-private-error");
        assert!(protocol.parse(&wire(&secret)).is_err());
        assert!(protocol.parse(&wire(&failure)).is_ok());
        assert!(protocol.parse(b"{\n").is_err());
        assert!(protocol.parse(&vec![b'x'; 8193]).is_err());
        assert!(protocol
            .parse(&wire(&serde_json::json!({"state":"stopped"})))
            .is_err());
        protocol.stopping.store(true, Ordering::Release);
        assert!(protocol
            .parse(&wire(&serde_json::json!({"state":"stopped"})))
            .is_ok());
    }

    #[test]
    fn checkpoint_duplicate_is_refused_before_the_first_response_is_consumed() {
        let protocol = CheckpointProtocol::new("a".repeat(64), "b".repeat(40));
        protocol.begin(OPERATION).unwrap();
        let first = protocol.parse(&wire(&receipt())).unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        tx.try_send(first).unwrap();
        let drained = rx.try_recv().unwrap();
        // The consumer has drained the channel but has not yet finished the operation.
        assert!(protocol.parse(&wire(&receipt())).is_err());
        protocol.finish(&drained).unwrap();
        let next = "22222222-2222-4222-8222-222222222222";
        protocol.begin(next).unwrap();
        assert!(protocol.finish(&drained).is_err());
        let mut next_receipt = receipt();
        next_receipt["operationId"] = serde_json::json!(next);
        let next_event = protocol.parse(&wire(&next_receipt)).unwrap();
        assert!(protocol.finish(&drained).is_err());
        protocol.finish(&next_event).unwrap();
    }

    #[test]
    fn database_readiness_cannot_be_confused_with_a_running_application() {
        for (mode, state, accepted) in [
            (HostMode::Server, "running", true),
            (HostMode::Database, "database-ready", true),
            (HostMode::Server, "database-ready", false),
            (HostMode::Database, "running", false),
            (HostMode::RestorePrepare, "restore-prepare-ready", true),
            (HostMode::RestorePrepare, "checkpoint-cleanup-ready", false),
            (HostMode::CheckpointCleanup, "restore-prepare-ready", false),
            (
                HostMode::CheckpointCleanup,
                "checkpoint-cleanup-ready",
                true,
            ),
            (HostMode::CheckpointCleanup, "database-ready", false),
            (HostMode::CheckpointCleanup, "running", false),
            (HostMode::Server, "checkpoint-cleanup-ready", false),
            (HostMode::Database, "checkpoint-cleanup-ready", false),
        ] {
            let protocol = Arc::new(CheckpointProtocol::new("a".repeat(64), "b".repeat(40)));
            protocol.stopping.store(true, Ordering::Release);
            let (ready_tx, ready) = mpsc::channel();
            let (tx, _rx) = mpsc::sync_channel(1);
            let failed = AtomicBool::new(false);
            let input = format!("{{\"state\":\"{state}\"}}\n{{\"state\":\"stopped\"}}\n");
            read_agent_output(
                std::io::Cursor::new(input),
                ready_tx,
                tx,
                protocol,
                mode,
                || failed.store(true, Ordering::Release),
            );
            assert_eq!(ready.recv().unwrap().is_ok(), accepted);
            assert_eq!(failed.load(Ordering::Acquire), !accepted);
        }
    }

    #[test]
    fn output_reader_rejects_a_duplicate_receipt_instead_of_blocking_on_a_full_channel() {
        let protocol = Arc::new(CheckpointProtocol::new("a".repeat(64), "b".repeat(40)));
        protocol.begin(OPERATION).unwrap();
        let (ready_tx, ready) = mpsc::channel();
        let (tx, _rx) = mpsc::sync_channel(1);
        let failed = AtomicBool::new(false);
        let input = format!(
            "{{\"state\":\"running\"}}\n{}{}",
            String::from_utf8(wire(&receipt())).unwrap(),
            String::from_utf8(wire(&receipt())).unwrap()
        );
        read_agent_output(
            std::io::Cursor::new(input),
            ready_tx,
            tx,
            protocol.clone(),
            HostMode::Server,
            || failed.store(true, Ordering::Release),
        );
        assert!(ready.recv().unwrap().is_ok());
        assert!(failed.load(Ordering::Acquire));
        assert!(protocol.failed.load(Ordering::Acquire));
    }

    #[test]
    fn cancellation_failure_and_stopped_receipt_drain_without_overflowing_the_checkpoint_channel() {
        let protocol = Arc::new(CheckpointProtocol::new("a".repeat(64), "b".repeat(40)));
        protocol.begin(OPERATION).unwrap();
        protocol.stopping.store(true, Ordering::Release);
        let (ready_tx, ready) = mpsc::channel();
        let (tx, rx) = mpsc::sync_channel(1);
        let input = format!("{{\"state\":\"running\"}}\n{{\"state\":\"checkpoint-failed\",\"operationId\":\"{OPERATION}\",\"code\":\"host_checkpoint_failed\"}}\n{{\"state\":\"stopped\"}}\n");
        read_agent_output(
            std::io::Cursor::new(input),
            ready_tx,
            tx,
            protocol.clone(),
            HostMode::Server,
            || panic!("valid cancellation was refused"),
        );
        assert!(ready.recv().unwrap().is_ok());
        assert!(rx.try_recv().is_ok());
        assert!(!protocol.failed.load(Ordering::Acquire));
    }
}
