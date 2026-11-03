//! Immutable verified releases and atomic activation, fenced by live runtime leases.
use crate::native_runtime::{absolute_directory, NativeSidecar, QualifiedRuntime, VerifiedRuntime};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
};
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Active {
    manifest_sha256: String,
    epoch: u64,
}
pub struct RuntimeStore {
    root: PathBuf,
    keys: Vec<VerifyingKey>,
    minimum_epoch: u64,
    epochs: Arc<dyn crate::runtime_epochs::EpochAuthority>,
    installation_id: String,
}
pub struct InstalledRuntime {
    runtime: VerifiedRuntime,
    lease: Arc<File>,
    epochs: Arc<dyn crate::runtime_epochs::EpochAuthority>,
    installation_id: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestation {
    #[serde(skip_serializing)]
    manifest_sha256: String,
    manifest_gzip_base64: String,
    signature_base64: String,
}
impl RuntimeAttestation {
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
}
pub(crate) struct Staging(PathBuf);
impl Staging {
    /// Acquire cleanup ownership only after exclusive creation; admission failures clean up our root.
    pub(crate) fn create(path: PathBuf) -> Result<Self, String> {
        create_private_directory(&path)?;
        let staging = Self(path);
        private_directory(&staging.0)?;
        Ok(staging)
    }
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "runtime_store_read_failed")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > max {
        return Err("runtime_store_file_invalid".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err("runtime_store_file_invalid".into());
        }
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(max + 1).read_to_end(&mut bytes))
        .map_err(|_| "runtime_store_read_failed")?;
    if bytes.len() as u64 > max {
        return Err("runtime_store_file_invalid".into());
    }
    Ok(bytes)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "runtime_store_write_failed")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "runtime_store_write_failed".into())
}
/// Admit a private data directory; existing Windows permissions are checked, never repaired.
pub(crate) fn private_directory(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::windows_protection::private_directory(path)
    }
    #[cfg(not(windows))]
    {
        absolute_directory(path.parent().ok_or("runtime_store_path_invalid")?)?;
        if !path.exists() {
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            let mut builder = builder;
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(path)
                .map_err(|_| "runtime_store_directory_failed")?;
        }
        absolute_directory(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(path)
                .map_err(|_| "runtime_store_directory_failed")?
                .permissions()
                .mode()
                & 0o077
                != 0
            {
                return Err("runtime_store_directory_not_private".into());
            }
        }
        Ok(())
    }
}
/// Exclusively create private staging; callers retain cleanup ownership and admit it before use.
pub(crate) fn create_private_directory(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::windows_protection::create_private_directory(path)
    }
    #[cfg(not(windows))]
    {
        absolute_directory(path.parent().ok_or("runtime_store_path_invalid")?)?;
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .map_err(|_| "runtime_store_directory_failed".into())
    }
}
impl RuntimeStore {
    /// App-owned trust keys and minimum epoch must never come from a server response or runtime pack.
    pub fn new(
        root: &Path,
        keys: Vec<VerifyingKey>,
        minimum_epoch: u64,
        epochs: Arc<dyn crate::runtime_epochs::EpochAuthority>,
    ) -> Result<Self, String> {
        if minimum_epoch == 0 {
            return Err("runtime_epoch_invalid".into());
        }
        let identity = epochs.installation_id()?;
        if uuid::Uuid::parse_str(&identity).is_err()
            || uuid::Uuid::parse_str(&identity).is_ok_and(|id| id.is_nil())
        {
            return Err("runtime_epoch_identity_invalid".into());
        }
        private_directory(root)?;
        private_directory(&root.join("releases"))?;
        let binding = root.join("epoch-authority.json");
        match fs::symlink_metadata(&binding) {
            Ok(_) => {
                let saved: String = serde_json::from_slice(&read_bounded(&binding, 128)?)
                    .map_err(|_| "runtime_epoch_binding_invalid")?;
                if saved != identity {
                    return Err("runtime_epoch_identity_changed".into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if fs::symlink_metadata(root.join("active.json")).is_ok()
                    || fs::read_dir(root.join("releases"))
                        .map_err(|_| "runtime_store_read_failed")?
                        .next()
                        .is_some()
                {
                    return Err("runtime_epoch_recovery_required".into());
                }
                write_new(
                    &binding,
                    &serde_json::to_vec(&identity).map_err(|_| "runtime_epoch_binding_invalid")?,
                )?;
            }
            Err(_) => return Err("runtime_store_read_failed".into()),
        }
        Ok(Self {
            root: root.into(),
            keys,
            minimum_epoch,
            epochs,
            installation_id: identity,
        })
    }
    fn lock(&self, shared: bool) -> Result<Arc<File>, String> {
        absolute_directory(&self.root)?;
        let path = self.root.join("lease.lock");
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err("runtime_store_lock_invalid".into());
            }
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
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
        let file = options
            .open(path)
            .map_err(|_| "runtime_store_lock_failed")?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if file
                .metadata()
                .map_err(|_| "runtime_store_lock_failed")?
                .file_attributes()
                & 0x400
                != 0
            {
                return Err("runtime_store_lock_invalid".into());
            }
        }
        if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        }
        .map_err(|_| "runtime_store_busy")?;
        Ok(Arc::new(file))
    }
    fn active(&self) -> Result<Option<Active>, String> {
        let path = self.root.join("active.json");
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("runtime_store_read_failed".into()),
            Ok(_) => {}
        }
        let active: Active = serde_json::from_slice(&read_bounded(&path, 1024)?)
            .map_err(|_| "runtime_active_invalid")?;
        if active.manifest_sha256.len() != 64
            || !active
                .manifest_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || active.epoch < self.minimum_epoch
        {
            return Err("runtime_active_invalid".into());
        }
        Ok(Some(active))
    }
    fn read_release(&self, id: &str, minimum_epoch: u64) -> Result<VerifiedRuntime, String> {
        let release = self.root.join("releases").join(id);
        absolute_directory(&release)?;
        let raw = read_bounded(&release.join("manifest.json"), 8 * 1024 * 1024)?;
        let signature: [u8; 64] = read_bounded(&release.join("manifest.sig"), 64)?
            .try_into()
            .map_err(|_| "runtime_signature_invalid")?;
        let runtime = VerifiedRuntime::verify(
            &release.join("payload"),
            &raw,
            &signature,
            &self.keys,
            minimum_epoch,
        )?;
        if runtime.manifest_sha256() != id {
            return Err("runtime_release_identity_changed".into());
        }
        Ok(runtime)
    }
    /// Reverify the leased release before sending its exact factory-signed manifest.
    pub fn attestation(&self, installed: &InstalledRuntime) -> Result<RuntimeAttestation, String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use flate2::{write::GzEncoder, Compression};
        let id = installed.manifest_sha256();
        self.read_release(id, installed.runtime.epoch())?;
        self.epochs
            .check(&self.installation_id, &installed.runtime)?;
        let release = self.root.join("releases").join(id);
        let raw = read_bounded(&release.join("manifest.json"), 8 * 1024 * 1024)?;
        let signature = read_bounded(&release.join("manifest.sig"), 64)?;
        // Match the bytes read after verification as well as the retained runtime identity.
        use sha2::{Digest, Sha256};
        if format!("{:x}", Sha256::digest(&raw)) != id || signature.len() != 64 {
            return Err("runtime_release_identity_changed".into());
        }
        let signature_array: [u8; 64] = signature
            .as_slice()
            .try_into()
            .map_err(|_| "runtime_signature_invalid")?;
        if !self.keys.iter().any(|key| {
            key.verify_strict(
                &raw,
                &ed25519_dalek::Signature::from_bytes(&signature_array),
            )
            .is_ok()
        }) {
            return Err("runtime_signature_invalid".into());
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&raw)
            .map_err(|_| "runtime_attestation_compression_failed")?;
        let compressed = encoder
            .finish()
            .map_err(|_| "runtime_attestation_compression_failed")?;
        if compressed.len() > 2 * 1024 * 1024 {
            return Err("runtime_attestation_too_large".into());
        }
        Ok(RuntimeAttestation {
            manifest_sha256: id.to_owned(),
            manifest_gzip_base64: STANDARD.encode(compressed),
            signature_base64: STANDARD.encode(signature),
        })
    }
    pub fn load_active(&self) -> Result<Option<InstalledRuntime>, String> {
        let lease = self.lock(true)?;
        let Some(active) = self.active()? else {
            return Ok(None);
        };
        let runtime = self.read_release(&active.manifest_sha256, active.epoch)?;
        if runtime.epoch() != active.epoch {
            return Err("runtime_active_epoch_changed".into());
        }
        self.epochs.check(&self.installation_id, &runtime)?;
        Ok(Some(InstalledRuntime {
            runtime,
            lease,
            epochs: self.epochs.clone(),
            installation_id: self.installation_id.clone(),
        }))
    }
    pub fn install_and_activate(
        &self,
        candidate: &Path,
        raw: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), String> {
        let _lock = self.lock(false)?;
        absolute_directory(&self.root.join("releases"))?;
        let active = self.active()?;
        let minimum = active
            .as_ref()
            .map(|value| value.epoch)
            .unwrap_or(self.minimum_epoch);
        let verified = VerifiedRuntime::verify(candidate, raw, signature, &self.keys, minimum)?;
        self.epochs.check(&self.installation_id, &verified)?;
        let id = verified.manifest_sha256();
        if active
            .as_ref()
            .is_some_and(|value| value.epoch == verified.epoch() && value.manifest_sha256 != id)
        {
            return Err("runtime_epoch_reused".into());
        }
        let release = self.root.join("releases").join(id);
        if release.exists() {
            self.read_release(id, minimum)?;
        } else {
            let staging = Staging::create(self.root.join(format!(".staging-{}", Uuid::new_v4())))?;
            private_directory(&staging.0.join("payload"))?;
            verified.copy_payload(&staging.0.join("payload"))?;
            VerifiedRuntime::verify(
                &staging.0.join("payload"),
                raw,
                signature,
                &self.keys,
                minimum,
            )?;
            write_new(&staging.0.join("manifest.json"), raw)?;
            write_new(&staging.0.join("manifest.sig"), signature)?;
            fs::rename(&staging.0, &release).map_err(|_| "runtime_store_activation_failed")?;
        }
        self.epochs
            .activate(&self.installation_id, &verified, &mut || {
                let pointer = Active {
                    manifest_sha256: id.into(),
                    epoch: verified.epoch(),
                };
                let temporary = self.root.join(format!(".active-{}.json", Uuid::new_v4()));
                write_new(
                    &temporary,
                    &serde_json::to_vec(&pointer).map_err(|_| "runtime_active_invalid")?,
                )?;
                if fs::rename(&temporary, self.root.join("active.json")).is_err() {
                    let _ = fs::remove_file(temporary);
                    return Err("runtime_store_activation_failed".into());
                }
                #[cfg(unix)]
                File::open(&self.root)
                    .and_then(|root| root.sync_all())
                    .map_err(|_| "runtime_store_activation_sync_failed")?;
                Ok(())
            })
    }
}
impl InstalledRuntime {
    fn checked<T>(&self, mut operation: impl FnMut() -> Result<T, String>) -> Result<T, String> {
        let mut result = None;
        self.epochs
            .with_current(&self.installation_id, &self.runtime, &mut || {
                result = Some(operation()?);
                Ok(())
            })?;
        result.ok_or_else(|| "runtime_epoch_operation_missing".into())
    }
    pub fn source_revision(&self) -> &str {
        self.runtime.source_revision()
    }
    pub fn manifest_sha256(&self) -> &str {
        self.runtime.manifest_sha256()
    }
    pub fn provider(&self) -> &str {
        self.runtime.provider()
    }
    pub fn start_sidecar(
        &self,
        cache: &Path,
        private_root: &Path,
        port: u16,
    ) -> Result<NativeSidecar, String> {
        let mut child = self.checked(|| self.runtime.start_sidecar(cache, private_root, port))?;
        child.hold_lease(self.lease.clone());
        Ok(child)
    }
    pub fn start_qualified_sidecar(
        &self,
        qualified: &QualifiedRuntime,
        cache: &Path,
        private_root: &Path,
        port: u16,
    ) -> Result<NativeSidecar, String> {
        let mut child = self.checked(|| {
            self.runtime
                .start_qualified_sidecar(qualified, cache, private_root, port)
        })?;
        child.hold_lease(self.lease.clone());
        Ok(child)
    }
    pub fn start_bound_sidecar(
        &self,
        qualified: &[&QualifiedRuntime],
        cache: &Path,
        private_root: &Path,
        port: u16,
    ) -> Result<NativeSidecar, String> {
        let mut child = self.checked(|| {
            self.runtime
                .start_bound_sidecar(qualified, cache, private_root, port)
        })?;
        child.hold_lease(self.lease.clone());
        Ok(child)
    }
    pub fn qualify(
        &self,
        cache: &Path,
        private_root: &Path,
        spec: &[u8],
        fixture: &[u8],
        cancel: &AtomicBool,
    ) -> Result<QualifiedRuntime, String> {
        self.checked(|| {
            self.runtime
                .qualify(cache, private_root, spec, fixture, cancel)
        })
    }
}

#[cfg(test)]
mod private_directory_tests {
    use super::*;

    #[test]
    fn staging_cleanup_never_owns_an_existing_directory() {
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "frameleaf-stage-collision-{}",
                uuid::Uuid::new_v4()
            ));
        private_directory(&root).unwrap();
        let _cleanup = Staging(root.clone());
        let file = root.join("existing");
        fs::write(&file, b"preserve pre-existing bytes").unwrap();
        let stage = Staging::create(root);
        let refused = stage.is_err();
        drop(stage);
        assert_eq!(fs::read(file).unwrap(), b"preserve pre-existing bytes");
        assert!(
            refused,
            "a cleanup guard must never adopt an existing directory"
        );
    }

    #[test]
    fn private_staging_creation_is_exclusive_and_preserves_existing_contents() {
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("frameleaf-private-create-{}", uuid::Uuid::new_v4()));
        assert!(!root.exists());
        let _cleanup = Staging(root.clone());
        create_private_directory(&root).unwrap();
        private_directory(&root).unwrap();
        let file = root.join("existing");
        fs::write(&file, b"retain owned bytes").unwrap();
        assert!(create_private_directory(&root).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"retain owned bytes");
        private_directory(&root).unwrap();
    }
}
