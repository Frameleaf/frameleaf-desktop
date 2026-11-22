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
/// Whether a path exists. Only a confirmed absence is `false`: a lookup that fails proves nothing.
fn confirmed_present(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("runtime_store_read_failed".into()),
    }
}
/// A Windows tool limited to 260-character paths deletes a runtime's data but leaves its deepest
/// files. Without a manifest such a folder can never be loaded, and the accepted epochs live in the
/// credential store, so clearing it cannot roll anything back. Anything else stays refused, and
/// nothing is removed unless every entry qualifies.
fn clear_partly_deleted_releases(releases: &Path) -> Result<(), String> {
    const REFUSED: &str = "runtime_epoch_recovery_required";
    let mut leftovers = Vec::new();
    for entry in fs::read_dir(releases).map_err(|_| "runtime_store_read_failed")? {
        let path = entry.map_err(|_| "runtime_store_read_failed")?.path();
        let plain_directory = fs::symlink_metadata(&path)
            .map_err(|_| "runtime_store_read_failed")?
            .is_dir();
        if !plain_directory {
            return Err(REFUSED.into());
        }
        for name in ["manifest.json", "manifest.sig"] {
            if confirmed_present(&path.join(name))? {
                return Err(REFUSED.into());
            }
        }
        leftovers.push(path);
    }
    for path in leftovers {
        fs::remove_dir_all(path).map_err(|_| REFUSED)?;
    }
    Ok(())
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
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
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
                if confirmed_present(&root.join("active.json"))? {
                    return Err("runtime_epoch_recovery_required".into());
                }
                clear_partly_deleted_releases(&root.join("releases"))?;
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
    /// Remove releases that can never run again, and staging an interrupted install left behind.
    ///
    /// `expected_active` is the release the caller just qualified with: if the store's pointer is
    /// missing, unreadable or names another release, nothing is removed. `rollback` is the
    /// release the app's own bundle would install; it is kept as well. Epochs never go back, so
    /// every other release is dead weight. The shared lease keeps activation (which needs the
    /// exclusive one) from publishing or staging a release while this runs; a sidecar can only be
    /// running from the active release for the same reason.
    pub fn prune(&self, expected_active: &str, rollback: Option<&str>) -> Result<usize, String> {
        let _lease = self.lock(true)?;
        match self.active()? {
            Some(active) if active.manifest_sha256 == expected_active => {}
            _ => return Ok(0),
        }
        let mut removed = 0;
        let hex = |name: &str| name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit());
        for (directory, stale) in [
            (
                self.root.join("releases"),
                &(|name: &str| hex(name) && name != expected_active && Some(name) != rollback)
                    as &dyn Fn(&str) -> bool,
            ),
            (self.root.clone(), &|name: &str| {
                name.strip_prefix(".staging-")
                    .is_some_and(|id| Uuid::parse_str(id).is_ok())
            }),
        ] {
            absolute_directory(&directory)?;
            for entry in fs::read_dir(&directory).map_err(|_| "runtime_store_read_failed")? {
                let Ok(entry) = entry else { continue };
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                if entry.file_type().is_ok_and(|kind| kind.is_dir())
                    && stale(&name)
                    && crate::model_cache::remove_contained(&directory, &name).is_ok()
                {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
    pub fn install_and_activate(
        &self,
        candidate: &Path,
        raw: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), String> {
        self.install_and_activate_sharing(candidate, raw, signature, None)
    }
    /// The directory of one installed release, for `install_and_activate_sharing`.
    pub fn release_payload(&self, manifest_sha256: &str) -> PathBuf {
        self.root
            .join("releases")
            .join(manifest_sha256)
            .join("payload")
    }
    /// As `install_and_activate`; files identical to those of `share` (an installed release of
    /// the same pack in another store) are linked rather than stored twice.
    pub fn install_and_activate_sharing(
        &self,
        candidate: &Path,
        raw: &[u8],
        signature: &[u8; 64],
        share: Option<&Path>,
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
        // An installed copy that no longer verifies (a file changed, went missing or was cut
        // short) could never be used or replaced. Under the exclusive lock nothing runs from
        // it: move it aside and stage it again from the bundle just verified.
        // Anything at the path counts, a link that leads nowhere included.
        let occupied = |path: &Path| fs::symlink_metadata(path).is_ok();
        let damaged = occupied(&release) && self.read_release(id, minimum).is_err();
        if damaged {
            let aside = self.root.join(format!(".staging-{}", Uuid::new_v4()));
            fs::rename(&release, &aside).map_err(|_| "runtime_store_activation_failed")?;
            // A link is removed as a link, never followed.
            if fs::remove_dir_all(&aside).is_err() {
                let _ = fs::remove_file(&aside);
            }
        }
        if !occupied(&release) {
            let staging = Staging::create(self.root.join(format!(".staging-{}", Uuid::new_v4())))?;
            private_directory(&staging.0.join("payload"))?;
            // A repair copies every file from the bundle: a file shared with another installed
            // release may be the damaged one.
            let share = if damaged { None } else { share };
            verified.copy_payload(&staging.0.join("payload"), share)?;
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
    pub fn epoch(&self) -> u64 {
        self.runtime.epoch()
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
        self.start_bound_sidecar_threads(qualified, cache, private_root, port, 1)
    }
    pub(crate) fn start_bound_sidecar_threads(
        &self,
        qualified: &[&QualifiedRuntime],
        cache: &Path,
        private_root: &Path,
        port: u16,
        threads: u32,
    ) -> Result<NativeSidecar, String> {
        let mut child = self.checked(|| {
            self.runtime
                .start_bound_sidecar_threads(qualified, cache, private_root, port, threads)
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

#[cfg(test)]
mod leftover_tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    struct Authority;
    impl crate::runtime_epochs::EpochAuthority for Authority {
        fn installation_id(&self) -> Result<String, String> {
            Ok("7b0d3c1e-5a4f-4e6b-9c2d-1f0e8a7b6c5d".into())
        }
        fn with_current(
            &self,
            _: &str,
            _: &VerifiedRuntime,
            operation: &mut dyn FnMut() -> Result<(), String>,
        ) -> Result<(), String> {
            operation()
        }
        fn activate(
            &self,
            _: &str,
            _: &VerifiedRuntime,
            publish: &mut dyn FnMut() -> Result<(), String>,
        ) -> Result<(), String> {
            publish()
        }
    }
    fn open(root: &Path) -> Result<RuntimeStore, String> {
        let key = SigningKey::from_bytes(&[42; 32]).verifying_key();
        RuntimeStore::new(root, vec![key], 1, Arc::new(Authority))
    }
    fn store_with_release() -> (PathBuf, PathBuf) {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("frameleaf-leftovers-{}", Uuid::new_v4()));
        // As the app creates them: Windows refuses a store whose folders lack its private ACL.
        private_directory(&root).unwrap();
        private_directory(&root.join("releases")).unwrap();
        let release = root.join("releases").join("a".repeat(64));
        // Past Windows' 260-character limit, as the files such a delete leaves behind are.
        let deep = release
            .join("payload/python")
            .join("d".repeat(120))
            .join("e".repeat(120));
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("deep.pyd"), b"left behind").unwrap();
        assert!(deep.join("deep.pyd").as_os_str().len() > 260);
        (root, release)
    }

    // Windows tools limited to 260-character paths delete a runtime's data but leave its deepest files.
    #[test]
    fn files_left_by_a_partial_delete_are_cleared_and_the_store_opens() {
        let (root, release) = store_with_release();
        open(&root).unwrap();
        assert!(!release.exists());
        assert!(root.join("epoch-authority.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_release_that_still_has_its_manifest_is_never_cleared() {
        for name in ["manifest.json", "manifest.sig"] {
            let (root, release) = store_with_release();
            fs::write(release.join(name), b"{}").unwrap();
            assert_eq!(
                open(&root).err().as_deref(),
                Some("runtime_epoch_recovery_required")
            );
            assert!(release.join("payload/python").exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn an_active_pointer_without_a_binding_stays_refused() {
        let (root, release) = store_with_release();
        fs::write(root.join("active.json"), b"{}").unwrap();
        assert_eq!(
            open(&root).err().as_deref(),
            Some("runtime_epoch_recovery_required")
        );
        assert!(release.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nothing_is_cleared_when_any_release_is_complete() {
        let (root, partial) = store_with_release();
        let complete = root.join("releases").join("b".repeat(64));
        fs::create_dir_all(&complete).unwrap();
        fs::write(complete.join("manifest.json"), b"{}").unwrap();
        assert_eq!(
            open(&root).err().as_deref(),
            Some("runtime_epoch_recovery_required")
        );
        assert!(partial.exists() && complete.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_manifest_that_cannot_be_checked_keeps_the_release() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root reads past the permission this test relies on
        }
        let (root, release) = store_with_release();
        fs::write(release.join("manifest.json"), b"{}").unwrap();
        fs::set_permissions(&release, fs::Permissions::from_mode(0o000)).unwrap();
        let opened = open(&root).err();
        fs::set_permissions(&release, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(opened.as_deref(), Some("runtime_store_read_failed"));
        assert!(release.join("manifest.json").exists());
        assert!(!root.join("epoch-authority.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_cannot_be_checked_is_not_reported_absent() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (root, release) = store_with_release();
        fs::set_permissions(&release, fs::Permissions::from_mode(0o000)).unwrap();
        let checked = confirmed_present(&release.join("manifest.json"));
        fs::set_permissions(&release, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(checked, Err("runtime_store_read_failed".to_string()));
        assert_eq!(confirmed_present(&release), Ok(true));
        assert_eq!(confirmed_present(&release.join("absent")), Ok(false));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_link_in_releases_is_refused_and_its_target_kept() {
        let (root, release) = store_with_release();
        let outside = root.with_extension("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::remove_dir_all(&release).unwrap();
        std::os::unix::fs::symlink(&outside, &release).unwrap();
        assert_eq!(
            open(&root).err().as_deref(),
            Some("runtime_epoch_recovery_required")
        );
        assert!(outside.exists());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }
}
