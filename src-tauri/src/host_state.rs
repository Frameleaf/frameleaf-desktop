//! The fixed journal inode is also the controller lease. A torn write is never a clean-stop proof.
use cap_std::fs::{Dir, OpenOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

mod activation;
pub(crate) use activation::SafetySnapshot;

const NAME: &str = "controller-state.json";
const ACTIVATION: &str = "restore-activation.json";
fn no_activation(root: &Dir) -> Result<(), String> {
    match root.symlink_metadata(ACTIVATION) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("host_restore_activation_pending".into()),
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Active,
    Stopped,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Marker {
    schema_version: u32,
    pub installation_id: String,
    pub manifest_sha256: String,
    pub profile_identity: String,
    pub generation: Uuid,
    pub phase: Phase,
    #[serde(default)]
    restore_pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    database_reference: Option<crate::host_database::Reference>,
}
pub(crate) struct Owner {
    #[cfg(windows)]
    _profile_pins: Vec<File>,
    path: PathBuf,
    root: Dir,
    file: File,
    profile_identity: String,
    active: Option<Marker>,
    writable: bool,
}
struct TransientHostLease(File);
impl Drop for TransientHostLease {
    fn drop(&mut self) {
        // A concurrent fork may still hold a copy when this operation finishes.
        let _ = self.0.unlock();
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        // A concurrent fork can retain the file description until its CLOEXEC copies close.
        let _ = self.file.unlock();
    }
}
fn identity(root: &Dir) -> Result<String, String> {
    let value =
        crate::copy_source::root_identity(root).map_err(|_| "host_profile_identity_unavailable")?;
    Ok(format!("{:x}", Sha256::digest(value.as_bytes())))
}
// Use the same physical profile identity as the controller journal, independent of runtime upgrades.
fn installation_uuid(profile_identity: &str) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"frameleaf-native-installation:");
    digest.update(profile_identity.as_bytes());
    let digest = digest.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
}

pub(crate) fn secure_installation_id(path: &Path) -> Result<Uuid, String> {
    let root = Dir::from_std_file(crate::host_storage::directory(path)?);
    Ok(installation_uuid(&identity(&root)?))
}

pub(crate) fn options(write: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(write)
        .create(write)
        .truncate(false);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        // No delete sharing: the leased file and its parent cannot be replaced while owned.
        options.share_mode(3).custom_flags(0x00200000);
    }
    options
}
pub(crate) fn valid_file(file: &File) -> Result<(), String> {
    valid_sized_file(file, 4096)
}
fn valid_sized_file(file: &File, maximum: u64) -> Result<(), String> {
    let meta = file
        .metadata()
        .map_err(|_| "host_controller_state_invalid")?;
    if !meta.is_file() || meta.len() > maximum {
        return Err("host_controller_state_invalid".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
            return Err("host_controller_state_invalid".into());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        if meta.file_attributes() & 0x400 != 0
            || unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0
        {
            return Err("host_controller_state_invalid".into());
        }
        if unsafe { info.assume_init() }.nNumberOfLinks != 1 {
            return Err("host_controller_state_invalid".into());
        }
    }
    Ok(())
}
impl Owner {
    pub fn secure_installation_id(&self) -> Uuid {
        installation_uuid(&self.profile_identity)
    }

    pub fn acquire(path: &Path, writable: bool) -> Result<Self, String> {
        if writable {
            crate::runtime_store::private_directory(path)?;
        }
        #[cfg(windows)]
        let profile_pins = crate::windows_protection::pin_private_directory(path)?;
        let root = Dir::from_std_file(crate::host_storage::directory(path)?);
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt;
            if root
                .dir_metadata()
                .map_err(|_| "host_state_not_private")?
                .mode()
                & 0o077
                != 0
            {
                return Err("host_state_not_private".into());
            }
        }
        let file = root
            .open_with(NAME, &options(writable))
            .map_err(|_| "host_controller_state_unavailable")?
            .into_std();
        valid_file(&file)?;
        if writable {
            file.try_lock()
        } else {
            file.try_lock_shared()
        }
        .map_err(|_| "host_controller_already_owned")?;
        let profile_identity = identity(&root)?;
        let owner = Self {
            #[cfg(windows)]
            _profile_pins: profile_pins,
            path: path.into(),
            root,
            file,
            profile_identity,
            active: None,
            writable,
        };
        owner.placement()?;
        Ok(owner)
    }
    fn placement(&self) -> Result<(), String> {
        let current = Dir::from_std_file(crate::host_storage::directory(&self.path)?);
        if identity(&current)? != self.profile_identity {
            return Err("host_profile_identity_changed".into());
        }
        valid_file(&self.file)?;
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt as CapMetadataExt;
            use std::os::unix::fs::MetadataExt as StdMetadataExt;
            let entry = self
                .root
                .symlink_metadata(NAME)
                .map_err(|_| "host_profile_identity_changed")?;
            let held = self
                .file
                .metadata()
                .map_err(|_| "host_profile_identity_changed")?;
            if entry.dev() != held.dev() || entry.ino() != held.ino() {
                return Err("host_profile_identity_changed".into());
            }
        }
        Ok(())
    }
    fn read(&mut self) -> Result<Option<Marker>, String> {
        self.placement()?;
        self.file
            .rewind()
            .map_err(|_| "host_controller_state_invalid")?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut self.file)
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| "host_controller_state_invalid")?;
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes.len() > 4096 {
            return Err("host_controller_state_invalid".into());
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| "host_controller_state_invalid".into())
    }
    fn binding(&self, marker: &Marker, id: &str, sha: &str) -> Result<(), String> {
        if marker.schema_version != 1
            || marker.installation_id != id
            || marker.manifest_sha256 != sha
            || marker.generation.is_nil()
        {
            return Err("host_controller_binding_changed".into());
        }
        if marker.profile_identity != self.profile_identity {
            return Err("host_profile_identity_changed".into());
        }
        Ok(())
    }
    fn write(&mut self, marker: &Marker) -> Result<(), String> {
        if !self.writable {
            return Err("host_controller_read_only".into());
        }
        self.placement()?;
        let bytes = serde_json::to_vec(marker).map_err(|_| "host_controller_state_invalid")?;
        // Keep the locked inode fixed. A partial write is invalid; fsync completes before any host effect.
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.set_len(0))
            .and_then(|_| self.file.write_all(&bytes))
            .and_then(|_| self.file.sync_all())
            .map_err(|_| "host_controller_state_write_failed".into())
    }
    pub fn activate(
        &mut self,
        id: &str,
        sha: &str,
        mode: crate::host_runtime::HostMode,
    ) -> Result<(), String> {
        if mode == crate::host_runtime::HostMode::RestorePrepare {
            self.reconcile_restore(id, sha)?;
        }
        if mode == crate::host_runtime::HostMode::Server {
            no_activation(&self.root)?;
        }
        let (database_reference, restore_pending) = match self.read()? {
            Some(marker) => {
                self.binding(&marker, id, sha)?;
                // An active journal under this exclusive lease means its controller died without
                // a clean stop. A server start may continue from it: the database replays its own
                // write-ahead log, and the binding, restore and storage checks still apply. Backup
                // and restore modes keep requiring a clean stop first.
                let interrupted = marker.phase != Phase::Stopped;
                if (interrupted && mode != crate::host_runtime::HostMode::Server)
                    || (mode == crate::host_runtime::HostMode::Server && marker.restore_pending)
                {
                    return Err("host_recovery_requires_manager".into());
                }
                if mode.uses_database() {
                    if let Some(reference) = &marker.database_reference {
                        reference.resolve(&self.path)?;
                    }
                }
                (marker.database_reference, marker.restore_pending)
            }
            None => {
                for entry in self
                    .root
                    .entries()
                    .map_err(|_| "host_controller_state_invalid")?
                {
                    if entry
                        .map_err(|_| "host_controller_state_invalid")?
                        .file_name()
                        != NAME
                    {
                        return Err("host_recovery_requires_manager".into());
                    }
                }
                (None, false)
            }
        };
        let marker = Marker {
            schema_version: 1,
            installation_id: id.into(),
            manifest_sha256: sha.into(),
            profile_identity: self.profile_identity.clone(),
            generation: Uuid::new_v4(),
            phase: Phase::Active,
            restore_pending,
            database_reference,
        };
        self.write(&marker)?;
        self.active = Some(marker);
        Ok(())
    }
    /// Read the stopped journal without taking ownership; None means a fresh profile.
    pub(crate) fn peek(path: &Path) -> Result<Option<Marker>, String> {
        let root = Dir::from_std_file(crate::host_storage::directory(path)?);
        match root.symlink_metadata(NAME) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("host_controller_state_invalid".into()),
            Ok(_) => {}
        }
        let mut owner = Self::acquire(path, false)?;
        let marker = owner.read()?;
        if let Some(marker) = &marker {
            owner.binding(marker, &marker.installation_id, &marker.manifest_sha256)?;
        }
        Ok(marker)
    }
    /// Whether a controller holds this profile's journal lease right now. A profile that never
    /// started has no journal and no controller.
    pub(crate) fn controller_running(path: &Path) -> Result<bool, String> {
        match Self::acquire(path, false) {
            Ok(_) => Ok(false),
            Err(error) if error == "host_controller_already_owned" => Ok(true),
            Err(error) if error == "host_controller_state_unavailable" => Ok(false),
            Err(error) => Err(error),
        }
    }
    /// Only a cleanly stopped library with no unfinished backup or restore work may change package.
    pub(crate) fn check_movable(&mut self, id: &str, previous: &str) -> Result<(), String> {
        if !self.writable {
            return Err("host_controller_read_only".into());
        }
        if self.active.is_some() {
            return Err("host_recovery_requires_manager".into());
        }
        no_activation(&self.root)?;
        // Same liveness proof as recovery: no host lease holder and no database PID file.
        let current = self.inspect(id, previous)?;
        if current.restore_pending {
            return Err("host_recovery_requires_manager".into());
        }
        self.operations_clear(&current, None)
    }
    /// Unfinished backup or restore work names the package that started it and must be
    /// finished or discarded with it first. Two things are not unfinished work: the directory
    /// a completed carry-forward restored this library into, which is its database now, with
    /// the export it came from; and what the carry-forward under way (`permit`) has written.
    fn operations_clear(&self, current: &Marker, permit: Option<&str>) -> Result<(), String> {
        let carried = current
            .database_reference
            .as_ref()
            .map(crate::host_database::Reference::operation_id)
            .filter(|operation| {
                self.root
                    .symlink_metadata(
                        Path::new("carry-forward")
                            .join(operation)
                            .join("restore.json"),
                    )
                    .is_ok_and(|record| record.is_file())
            });
        for name in ["checkpoints", "restore-input", "restore-targets"] {
            let clear = match self.root.read_dir(name) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Ok(mut entries) => entries.all(|entry| {
                    name != "restore-input"
                        && entry.is_ok_and(|entry| {
                            [carried, permit]
                                .into_iter()
                                .flatten()
                                .any(|allowed| entry.file_name() == allowed)
                        })
                }),
                Err(_) => false,
            };
            if !clear {
                return Err("host_upgrade_operation_pending".into());
            }
        }
        Ok(())
    }
    /// The journal of a library that is being carried forward, as a carry-forward step may
    /// start from it: bound to the package the library last ran with, cleanly stopped, with no
    /// restore under way. Nothing is written. A database process file is deliberately not
    /// required to be absent: an export run that was killed leaves one, and only the previous
    /// Postgres, which refuses a directory another Postgres holds, can clear it.
    #[cfg(unix)]
    pub(crate) fn carry_state(
        &mut self,
        id: &str,
        previous: &str,
    ) -> Result<(PathBuf, Option<crate::host_database::Reference>), String> {
        if !self.writable {
            return Err("host_controller_read_only".into());
        }
        if self.active.is_some() {
            return Err("host_recovery_requires_manager".into());
        }
        no_activation(&self.root)?;
        let marker = self.read()?.ok_or("host_recovery_requires_manager")?;
        self.binding(&marker, id, previous)?;
        if marker.phase != Phase::Stopped || marker.restore_pending {
            return Err("host_recovery_requires_manager".into());
        }
        if let Some(reference) = &marker.database_reference {
            reference.resolve(&self.path)?;
        }
        self.placement()?;
        Ok((self.path.clone(), marker.database_reference))
    }
    /// `carry_state`, and nothing in the operation directories but this permit's own work.
    /// This is what an export run needs; the restore and the switch need `check_carriable`.
    #[cfg(unix)]
    pub(crate) fn carry_admitted(
        &mut self,
        id: &str,
        previous: &str,
        permit: &str,
    ) -> Result<(), String> {
        if !crate::host_runtime::checkpoint_operation_id(permit) {
            return Err("host_recovery_requires_manager".into());
        }
        self.carry_state(id, previous)?;
        let current = self.read()?.ok_or("host_recovery_requires_manager")?;
        self.operations_clear(&current, Some(permit))
    }
    /// Whether a library may be carried forward under `permit`: cleanly stopped with nothing
    /// holding it and no database process file, no restore under way, and nothing in the
    /// operation directories but this permit's own work.
    pub(crate) fn check_carriable(
        &mut self,
        id: &str,
        previous: &str,
        permit: &str,
    ) -> Result<(), String> {
        if !self.writable {
            return Err("host_controller_read_only".into());
        }
        if self.active.is_some() || !crate::host_runtime::checkpoint_operation_id(permit) {
            return Err("host_recovery_requires_manager".into());
        }
        no_activation(&self.root)?;
        let current = self.inspect(id, previous)?;
        if current.restore_pending {
            return Err("host_recovery_requires_manager".into());
        }
        self.operations_clear(&current, Some(permit))
    }
    /// Select the newer package and the directory it restored this library into. Every check
    /// runs first and this one write commits both; the original directory stays where it is.
    pub(crate) fn carry_forward_database(
        &mut self,
        id: &str,
        previous: &str,
        next: &str,
        permit: &str,
        reference: &crate::host_database::Reference,
    ) -> Result<(), String> {
        if !crate::native_runtime::digest_valid(next, 64)
            || previous == next
            || reference.operation_id() != permit
        {
            return Err("host_controller_binding_changed".into());
        }
        self.check_carriable(id, previous, permit)?;
        let selected = reference.resolve(&self.path)?;
        match std::fs::symlink_metadata(selected.join("postmaster.pid")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("host_process_state_requires_review".into()),
        }
        let current = self.read()?.ok_or("host_controller_state_invalid")?;
        let marker = Marker {
            manifest_sha256: next.into(),
            generation: Uuid::new_v4(),
            database_reference: Some(reference.clone()),
            ..current
        };
        self.write(&marker)?;
        if self.read()? != Some(marker) {
            return Err("host_controller_state_write_failed".into());
        }
        Ok(())
    }
    /// Repoint a cleanly stopped library at a newer package. This write commits the move.
    pub(crate) fn carry_forward(
        &mut self,
        id: &str,
        previous: &str,
        next: &str,
    ) -> Result<(), String> {
        if !crate::native_runtime::digest_valid(next, 64) || previous == next {
            return Err("host_controller_binding_changed".into());
        }
        self.check_movable(id, previous)?;
        let current = self.read()?.ok_or("host_controller_state_invalid")?;
        let marker = Marker {
            manifest_sha256: next.into(),
            generation: Uuid::new_v4(),
            ..current
        };
        self.write(&marker)
    }
    pub fn clean_stop(&mut self) -> Result<(), String> {
        let mut marker = self.active.clone().ok_or("host_controller_state_invalid")?;
        let current = self.read()?.ok_or("host_controller_state_invalid")?;
        if current != marker || current.phase != Phase::Active {
            return Err("host_controller_binding_changed".into());
        }
        self.binding(&current, &marker.installation_id, &marker.manifest_sha256)?;
        marker.phase = Phase::Stopped;
        self.write(&marker)?;
        self.active = None;
        Ok(())
    }
    /// Only the active controller can derive the internal host configuration.
    pub(crate) fn launch_state(
        &mut self,
        manifest_sha256: &str,
        mode: crate::host_runtime::HostMode,
    ) -> Result<(PathBuf, Option<crate::host_database::Reference>, Uuid), String> {
        if mode == crate::host_runtime::HostMode::Server {
            no_activation(&self.root)?;
        }
        let marker = self
            .active
            .as_ref()
            .ok_or("host_controller_state_invalid")?
            .clone();
        let current = self.read()?.ok_or("host_controller_state_invalid")?;
        if current != marker
            || current.phase != Phase::Active
            || (mode == crate::host_runtime::HostMode::Server && marker.restore_pending)
            || marker.manifest_sha256 != manifest_sha256
        {
            return Err("host_controller_binding_changed".into());
        }
        self.binding(&current, &marker.installation_id, &marker.manifest_sha256)?;
        if mode.uses_database() {
            if let Some(reference) = &marker.database_reference {
                reference.resolve(&self.path)?;
            }
        }
        Ok((
            self.path.clone(),
            marker.database_reference,
            marker.generation,
        ))
    }
    /// With this lease held: whether anything of this library other than Manager could be
    /// listening. `Clear` for a profile that holds nothing but an unwritten journal (no
    /// controller ever started, so there is no photo server or database), and for a journal
    /// that proves a clean stop with no database process file. Anything unread, unfinished or
    /// bound to something else is `Unknown`.
    pub(crate) fn idle(&mut self, id: &str, sha: &str) -> crate::manager_host::Evidence {
        use crate::manager_host::Evidence;
        match self.admit_idle(id, sha) {
            Ok(()) => Evidence::Clear,
            Err(code) if code == "host_already_owned" => Evidence::Running,
            Err(_) => Evidence::Unknown,
        }
    }
    /// Keep this lease alive through Manager shutdown so a controller cannot start concurrently.
    pub(crate) fn admit_idle(&mut self, id: &str, sha: &str) -> Result<(), String> {
        if !crate::native_runtime::digest_valid(id, 12)
            || !crate::native_runtime::digest_valid(sha, 64)
        {
            return Err("host_controller_binding_changed".into());
        }
        if self.read()?.is_some() {
            return self.inspect(id, sha).map(|_| ());
        }
        self.empty()
    }
    fn empty(&self) -> Result<(), String> {
        for entry in self
            .root
            .entries()
            .map_err(|_| "host_controller_state_invalid")?
        {
            if entry
                .map_err(|_| "host_controller_state_invalid")?
                .file_name()
                != NAME
            {
                return Err("host_recovery_requires_manager".into());
            }
        }
        self.placement()
    }
    /// Package maintenance checks liveness only; this never authorizes starting or restoring a host.
    #[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
    pub(crate) fn package_idle(path: &Path) -> Result<(), String> {
        let root = Dir::from_std_file(crate::host_storage::directory(path)?);
        no_activation(&root)?;
        match root.symlink_metadata(NAME) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return if root
                    .entries()
                    .map_err(|_| "host_controller_state_invalid")?
                    .next()
                    .is_none()
                {
                    Ok(())
                } else {
                    Err("host_recovery_requires_manager".into())
                };
            }
            Err(_) => return Err("host_controller_state_invalid".into()),
            Ok(_) => {}
        }
        let mut owner = Self::acquire(path, false)?;
        match owner.read()? {
            None => owner.empty(),
            Some(marker) => {
                if marker.restore_pending {
                    return Err("host_restore_activation_pending".into());
                }
                if !crate::native_runtime::digest_valid(&marker.installation_id, 12)
                    || !crate::native_runtime::digest_valid(&marker.manifest_sha256, 64)
                {
                    return Err("host_controller_binding_changed".into());
                }
                owner
                    .inspect(&marker.installation_id, &marker.manifest_sha256)
                    .map(|_| ())
            }
        }
    }
    /// The lease an older direct host holds on this library for as long as it runs, taken
    /// shared for the moment: none when that host never ran here.
    fn host_lease(&self) -> Result<Option<TransientHostLease>, String> {
        match self.root.open_with("lease.lock", &options(false)) {
            Ok(file) => {
                let file = file.into_std();
                valid_file(&file)?;
                file.try_lock_shared().map_err(|_| "host_already_owned")?;
                Ok(Some(TransientHostLease(file)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err("host_process_state_requires_review".into()),
        }
    }
    /// With this lease held: whether an older direct host still runs this library, whatever
    /// the journal says. A lease file that cannot be read is `Unknown`.
    pub(crate) fn older_host(&self) -> crate::manager_host::Evidence {
        use crate::manager_host::Evidence;
        match self.host_lease() {
            Ok(_) => Evidence::Clear,
            Err(code) if code == "host_already_owned" => Evidence::Running,
            Err(_) => Evidence::Unknown,
        }
    }
    pub fn inspect(&mut self, id: &str, sha: &str) -> Result<Marker, String> {
        let marker = self.read()?.ok_or("host_recovery_requires_manager")?;
        self.binding(&marker, id, sha)?;
        if marker.phase != Phase::Stopped {
            return Err("host_recovery_requires_manager".into());
        }
        // Older direct-host ownership must also be absent. The PID file is never read or adopted.
        let _host_lease = self.host_lease()?;
        let mut databases = vec![self.path.join("database")];
        if let Some(reference) = &marker.database_reference {
            databases.push(reference.resolve(&self.path)?);
        }
        for database in databases {
            match std::fs::symlink_metadata(&database) {
                Ok(_) => {
                    crate::native_runtime::absolute_directory(&database)?;
                    match std::fs::symlink_metadata(database.join("postmaster.pid")) {
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        _ => return Err("host_process_state_requires_review".into()),
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("host_process_state_requires_review".into()),
            }
        }
        self.placement()?;
        Ok(marker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-host-owner-{}", uuid::Uuid::new_v4()));
            crate::runtime_store::private_directory(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    const ID: &str = "aaaaaaaaaaaa";
    fn sha() -> String {
        "b".repeat(64)
    }

    #[cfg(unix)]
    #[test]
    fn transient_host_lease_releases_fork_style_descriptors_on_scope_exit() {
        let fixture = Fixture::new();
        let root = Dir::from_std_file(crate::host_storage::directory(&fixture.0).unwrap());
        for shared in [false, true] {
            let file = root
                .open_with("lease.lock", &options(true))
                .unwrap()
                .into_std();
            if shared {
                file.try_lock_shared()
            } else {
                file.try_lock()
            }
            .unwrap();
            let lease = TransientHostLease(file);
            let inherited = lease.0.try_clone().unwrap();
            let next = root
                .open_with("lease.lock", &options(true))
                .unwrap()
                .into_std();
            assert!(
                next.try_lock().is_err(),
                "live lease must still exclude writers"
            );
            drop(lease);
            assert!(
                next.try_lock().is_ok(),
                "scope exit must release even while a fork-style descriptor exists"
            );
            drop(inherited);
            next.unlock().unwrap();
        }
    }

    #[test]
    fn stopped_library_moves_to_a_newer_package_only_once_and_only_when_cleanly_stopped() {
        let fixture = Fixture::new();
        assert!(Owner::peek(&fixture.0).unwrap().is_none());
        let next = "c".repeat(64);
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        assert_eq!(
            owner.carry_forward(ID, &sha(), &next).unwrap_err(),
            "host_recovery_requires_manager"
        );
        owner.clean_stop().unwrap();
        drop(owner);
        let before = Owner::peek(&fixture.0).unwrap().unwrap();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        crate::runtime_store::private_directory(&fixture.0.join("database")).unwrap();
        fs::write(fixture.0.join("database/postmaster.pid"), b"synthetic").unwrap();
        assert_eq!(
            owner.carry_forward(ID, &sha(), &next).unwrap_err(),
            "host_process_state_requires_review"
        );
        fs::remove_file(fixture.0.join("database/postmaster.pid")).unwrap();
        fs::remove_dir(fixture.0.join("database")).unwrap();
        for (id, previous) in [("bbbbbbbbbbbb", sha()), (ID, "d".repeat(64))] {
            assert_eq!(
                owner.carry_forward(id, &previous, &next).unwrap_err(),
                "host_controller_binding_changed"
            );
        }
        owner.carry_forward(ID, &sha(), &next).unwrap();
        assert!(owner.carry_forward(ID, &sha(), &next).is_err());
        drop(owner);
        let after = Owner::peek(&fixture.0).unwrap().unwrap();
        assert_eq!(after.manifest_sha256, next);
        assert_eq!(after.installation_id, before.installation_id);
        assert_eq!(after.phase, Phase::Stopped);
        assert_ne!(after.generation, before.generation);
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner
            .activate(ID, &next, crate::host_runtime::HostMode::Server)
            .unwrap();
        owner.clean_stop().unwrap();
    }

    /// A stopped library of package `sha()` with a restore target under `permit`.
    #[cfg(unix)]
    fn carried(fixture: &Fixture, permit: &str) -> crate::host_database::Reference {
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        owner.clean_stop().unwrap();
        drop(owner);
        let attempt = Uuid::new_v4().to_string();
        let target = fixture
            .0
            .join("restore-targets")
            .join(permit)
            .join(&attempt);
        for path in [
            fixture.0.join("database"),
            fixture.0.join("restore-targets"),
            fixture.0.join("restore-targets").join(permit),
            target.clone(),
            target.join("database"),
        ] {
            crate::runtime_store::private_directory(&path).unwrap();
        }
        crate::host_database::Reference::capture(&fixture.0, permit, &attempt).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn a_carried_library_switches_package_and_directory_in_one_write_and_keeps_the_original() {
        let fixture = Fixture::new();
        let (permit, next) = (Uuid::new_v4().to_string(), "c".repeat(64));
        let reference = carried(&fixture, &permit);
        fs::write(fixture.0.join("database/PG_VERSION"), b"18\n").unwrap();
        let before = Owner::peek(&fixture.0).unwrap().unwrap();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        // The export run starts from the journal as it is, and changes nothing in it.
        assert_eq!(
            owner.carry_state(ID, &sha()).unwrap(),
            (fixture.0.clone(), None)
        );
        owner.carry_admitted(ID, &sha(), &permit).unwrap();
        for (id, previous) in [("bbbbbbbbbbbb", sha()), (ID, "d".repeat(64))] {
            assert_eq!(
                owner.carry_state(id, &previous).unwrap_err(),
                "host_controller_binding_changed"
            );
        }
        assert_eq!(owner.read().unwrap(), Some(before.clone()));
        // Bound to this permit's own directory and to a different, valid package.
        let other = Uuid::new_v4().to_string();
        for (to, permit) in [
            (sha(), permit.as_str()),
            ("x".repeat(64), permit.as_str()),
            (next.clone(), other.as_str()),
        ] {
            assert_eq!(
                owner
                    .carry_forward_database(ID, &sha(), &to, permit, &reference)
                    .unwrap_err(),
                "host_controller_binding_changed"
            );
        }
        owner
            .carry_forward_database(ID, &sha(), &next, &permit, &reference)
            .unwrap();
        // Once: the journal no longer names the previous package.
        assert_eq!(
            owner
                .carry_forward_database(ID, &sha(), &next, &permit, &reference)
                .unwrap_err(),
            "host_controller_binding_changed"
        );
        drop(owner);
        let after = Owner::peek(&fixture.0).unwrap().unwrap();
        assert_eq!(after.manifest_sha256, next);
        assert_eq!(after.database_reference, Some(reference.clone()));
        assert_eq!(
            (after.phase, after.restore_pending),
            (Phase::Stopped, false)
        );
        assert_eq!(after.installation_id, before.installation_id);
        assert_ne!(after.generation, before.generation);
        // The original directory is where it was, with what it held.
        assert_eq!(
            fs::read(fixture.0.join("database/PG_VERSION")).unwrap(),
            b"18\n"
        );
        // The new package starts from the selected directory.
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner
            .activate(ID, &next, crate::host_runtime::HostMode::Server)
            .unwrap();
        assert_eq!(
            owner
                .launch_state(&next, crate::host_runtime::HostMode::Server)
                .unwrap()
                .1,
            Some(reference)
        );
        owner.clean_stop().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn nothing_is_switched_while_anything_about_the_library_is_unknown() {
        let next = "c".repeat(64);
        type Spoil = fn(&Fixture, &str, &crate::host_database::Reference);
        let cases: [(&str, Spoil); 7] = [
            // A database process file in the original: something may still be running there.
            ("host_process_state_requires_review", |fixture, _, _| {
                fs::write(fixture.0.join("database/postmaster.pid"), b"1").unwrap()
            }),
            // One in the new directory.
            (
                "host_process_state_requires_review",
                |fixture, _, reference| {
                    let database = reference.resolve(&fixture.0).unwrap();
                    fs::write(database.join("postmaster.pid"), b"1").unwrap()
                },
            ),
            // A restore selection under way.
            ("host_restore_activation_pending", |fixture, _, _| {
                fs::write(fixture.0.join(ACTIVATION), b"{}").unwrap()
            }),
            // Unfinished work of the previous package, in each operation directory.
            ("host_upgrade_operation_pending", |fixture, _, _| {
                let other = Uuid::new_v4().to_string();
                fs::create_dir_all(fixture.0.join("checkpoints").join(other)).unwrap()
            }),
            ("host_upgrade_operation_pending", |fixture, permit, _| {
                fs::create_dir_all(fixture.0.join("restore-input").join(permit)).unwrap()
            }),
            ("host_upgrade_operation_pending", |fixture, _, _| {
                let other = Uuid::new_v4().to_string();
                fs::create_dir(fixture.0.join("restore-targets").join(other)).unwrap()
            }),
            // The directory is no longer the one that was proven.
            (
                "host_database_reference_invalid",
                |fixture, _, reference| {
                    let database = reference.resolve(&fixture.0).unwrap();
                    fs::rename(&database, database.with_file_name("moved")).unwrap();
                    crate::runtime_store::private_directory(&database).unwrap();
                },
            ),
        ];
        for (index, (code, spoil)) in cases.into_iter().enumerate() {
            let fixture = Fixture::new();
            let permit = Uuid::new_v4().to_string();
            let reference = carried(&fixture, &permit);
            // This permit's own export is not unfinished work.
            fs::create_dir_all(fixture.0.join("checkpoints").join(&permit)).unwrap();
            let before = Owner::peek(&fixture.0).unwrap().unwrap();
            spoil(&fixture, &permit, &reference);
            let mut owner = Owner::acquire(&fixture.0, true).unwrap();
            let refusal = owner
                .carry_forward_database(ID, &sha(), &next, &permit, &reference)
                .unwrap_err();
            assert_eq!(refusal, code, "case {index}");
            assert_eq!(owner.read().unwrap(), Some(before), "case {index}");
        }
        // A library that did not stop cleanly is not carried at all, not even for its export.
        let fixture = Fixture::new();
        let permit = Uuid::new_v4().to_string();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        drop(owner);
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        for result in [
            owner.carry_state(ID, &sha()).map(|_| ()),
            owner.carry_admitted(ID, &sha(), &permit),
            owner.check_carriable(ID, &sha(), &permit),
        ] {
            assert_eq!(result.unwrap_err(), "host_recovery_requires_manager");
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_export_run_may_follow_a_killed_one_but_the_restore_and_the_switch_may_not() {
        let fixture = Fixture::new();
        let permit = Uuid::new_v4().to_string();
        carried(&fixture, &permit);
        // What a killed export run leaves: the previous Postgres's process file.
        fs::write(fixture.0.join("database/postmaster.pid"), b"1").unwrap();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner.carry_admitted(ID, &sha(), &permit).unwrap();
        assert_eq!(
            owner.check_carriable(ID, &sha(), &permit).unwrap_err(),
            "host_process_state_requires_review"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_finished_carry_forward_does_not_block_the_next_package_move() {
        let fixture = Fixture::new();
        let (permit, next, later) = (Uuid::new_v4().to_string(), "c".repeat(64), "d".repeat(64));
        let reference = carried(&fixture, &permit);
        fs::create_dir_all(fixture.0.join("checkpoints").join(&permit)).unwrap();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner
            .carry_forward_database(ID, &sha(), &next, &permit, &reference)
            .unwrap();
        // Without the record of a finished restore, what is there is still unfinished work.
        assert_eq!(
            owner.carry_forward(ID, &next, &later).unwrap_err(),
            "host_upgrade_operation_pending"
        );
        let records = fixture.0.join("carry-forward").join(&permit);
        fs::create_dir_all(&records).unwrap();
        fs::write(records.join("restore.json"), b"{}").unwrap();
        // Another operation's leftovers still block.
        let stray = fixture
            .0
            .join("checkpoints")
            .join(Uuid::new_v4().to_string());
        fs::create_dir(&stray).unwrap();
        assert_eq!(
            owner.carry_forward(ID, &next, &later).unwrap_err(),
            "host_upgrade_operation_pending"
        );
        fs::remove_dir(&stray).unwrap();
        owner.carry_forward(ID, &next, &later).unwrap();
        let after = owner.read().unwrap().unwrap();
        assert_eq!(after.manifest_sha256, later);
        assert_eq!(after.database_reference, Some(reference));
    }

    #[test]
    fn owner_drop_releases_fork_style_descriptor_without_claiming_clean_shutdown() {
        let fixture = Fixture::new();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        let inherited = owner.file.try_clone().unwrap();
        assert!(Owner::acquire(&fixture.0, true).is_err());
        drop(owner);
        let mut inspector = Owner::acquire(&fixture.0, false).unwrap();
        assert_eq!(
            inspector.inspect(ID, &sha()).unwrap_err(),
            "host_recovery_requires_manager"
        );
        drop(inspector);
        drop(inherited);
    }

    #[test]
    fn controller_lease_excludes_inspection_from_before_start_until_shutdown() {
        let fixture = Fixture::new();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        assert!(Owner::acquire(&fixture.0, true).is_err());
        assert!(Owner::acquire(&fixture.0, false).is_err());
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        drop(owner);
        let mut inspector = Owner::acquire(&fixture.0, false).unwrap();
        assert_eq!(
            inspector.inspect(ID, &sha()).unwrap_err(),
            "host_recovery_requires_manager"
        );
    }

    #[test]
    fn interrupted_server_journal_restarts_through_recovery_without_proving_a_clean_stop() {
        use crate::host_runtime::HostMode;
        let fixture = Fixture::new();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner.activate(ID, &sha(), HostMode::Server).unwrap();
        let interrupted = owner.active.clone().unwrap();
        // The controller dies here: nothing writes the stopped phase.
        drop(owner);
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        assert_eq!(owner.read().unwrap().unwrap().phase, Phase::Active);
        for mode in [
            HostMode::Database,
            HostMode::CheckpointCleanup,
            HostMode::RestorePrepare,
        ] {
            assert_eq!(
                owner.activate(ID, &sha(), mode).unwrap_err(),
                "host_recovery_requires_manager"
            );
        }
        for (id, manifest) in [("cccccccccccc", sha()), (ID, "d".repeat(64))] {
            assert_eq!(
                owner.activate(id, &manifest, HostMode::Server).unwrap_err(),
                "host_controller_binding_changed"
            );
        }
        // Package moves and Manager shutdown still need a proven clean stop.
        assert_eq!(
            owner.inspect(ID, &sha()).unwrap_err(),
            "host_recovery_requires_manager"
        );
        owner.activate(ID, &sha(), HostMode::Server).unwrap();
        assert_ne!(
            owner.active.as_ref().unwrap().generation,
            interrupted.generation
        );
        owner.launch_state(&sha(), HostMode::Server).unwrap();
        owner.clean_stop().unwrap();
        assert_eq!(owner.inspect(ID, &sha()).unwrap().phase, Phase::Stopped);
    }

    #[test]
    fn interrupted_journal_with_a_pending_restore_still_refuses_a_server_start() {
        let fixture = Fixture::new();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        let mut marker = owner.active.clone().unwrap();
        marker.restore_pending = true;
        owner.write(&marker).unwrap();
        drop(owner);
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        assert_eq!(
            owner
                .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
                .unwrap_err(),
            "host_recovery_requires_manager"
        );
    }

    #[test]
    fn only_matching_clean_stop_and_current_physical_root_can_be_inspected() {
        let fixture = Fixture::new();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        owner.clean_stop().unwrap();
        drop(owner);
        let mut inspector = Owner::acquire(&fixture.0, false).unwrap();
        assert_eq!(inspector.inspect(ID, &sha()).unwrap().phase, Phase::Stopped);
        assert!(inspector.inspect("cccccccccccc", &sha()).is_err());
        assert!(inspector.inspect(ID, &"d".repeat(64)).is_err());
        drop(inspector);
        let copy = Fixture::new();
        fs::copy(fixture.0.join(NAME), copy.0.join(NAME)).unwrap();
        let mut inspector = Owner::acquire(&copy.0, false).unwrap();
        assert_eq!(
            inspector.inspect(ID, &sha()).unwrap_err(),
            "host_profile_identity_changed"
        );
    }

    #[test]
    fn absent_torn_legacy_or_live_database_state_never_proves_stopped() {
        let fixture = Fixture::new();
        assert!(Owner::acquire(&fixture.0, false).is_err());
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        fs::write(fixture.0.join("legacy-data"), b"retained").unwrap();
        assert_eq!(
            owner
                .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
                .unwrap_err(),
            "host_recovery_requires_manager"
        );
        fs::remove_file(fixture.0.join("legacy-data")).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        owner.clean_stop().unwrap();
        drop(owner);
        fs::create_dir(fixture.0.join("database")).unwrap();
        let pid = fixture.0.join("database/postmaster.pid");
        fs::write(&pid, b"not-a-pid-to-adopt").unwrap();
        let mut inspector = Owner::acquire(&fixture.0, false).unwrap();
        assert_eq!(
            inspector.inspect(ID, &sha()).unwrap_err(),
            "host_process_state_requires_review"
        );
        assert_eq!(fs::read(&pid).unwrap(), b"not-a-pid-to-adopt");
        drop(inspector);
        fs::write(fixture.0.join(NAME), b"{").unwrap();
        let mut inspector = Owner::acquire(&fixture.0, false).unwrap();
        assert!(inspector.inspect(ID, &sha()).is_err());
    }

    #[test]
    fn selected_database_survives_start_stop_and_idle_inspection_checks_its_pid() {
        let fixture = Fixture::new();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        owner.clean_stop().unwrap();
        let op = "11111111-1111-4111-8111-111111111111";
        let attempt = "22222222-2222-4222-8222-222222222222";
        let target = fixture.0.join("restore-targets").join(op).join(attempt);
        for path in [
            fixture.0.join("database"),
            fixture.0.join("restore-targets"),
            fixture.0.join("restore-targets").join(op),
            target.clone(),
            target.join("database"),
        ] {
            crate::runtime_store::private_directory(&path).unwrap();
        }
        fs::write(fixture.0.join("database/sentinel"), b"retained").unwrap();
        let reference = crate::host_database::Reference::capture(&fixture.0, op, attempt).unwrap();
        let mut marker = owner.read().unwrap().unwrap();
        marker.database_reference = Some(reference.clone());
        owner.write(&marker).unwrap();
        owner.inspect(ID, &sha()).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        let (profile, selected, _) = owner
            .launch_state(&sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        assert_eq!(profile, fixture.0);
        assert_eq!(selected, Some(reference.clone()));
        owner.clean_stop().unwrap();
        let stopped = owner.read().unwrap().unwrap();
        assert_eq!(stopped.database_reference, Some(reference.clone()));
        fs::write(target.join("database/postmaster.pid"), b"never adopt").unwrap();
        assert_eq!(
            owner.inspect(ID, &sha()).unwrap_err(),
            "host_process_state_requires_review"
        );
        fs::remove_file(target.join("database/postmaster.pid")).unwrap();
        fs::rename(target.join("database"), target.join("retained-database")).unwrap();
        crate::runtime_store::private_directory(&target.join("database")).unwrap();
        let journal = owner.read().unwrap().unwrap();
        assert!(owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .is_err());
        assert_eq!(owner.read().unwrap().unwrap(), journal);
        // Neither cleanup nor preparation may depend on the original selected database.
        for mode in [
            crate::host_runtime::HostMode::CheckpointCleanup,
            crate::host_runtime::HostMode::RestorePrepare,
        ] {
            owner.activate(ID, &sha(), mode).unwrap();
            assert_eq!(
                owner.launch_state(&sha(), mode).unwrap().1,
                Some(reference.clone())
            );
            owner.clean_stop().unwrap();
        }
        assert_eq!(
            fs::read(fixture.0.join("database/sentinel")).unwrap(),
            b"retained"
        );
    }

    #[cfg(windows)]
    #[test]
    fn controller_owner_pins_its_profile_until_the_journal_lease_is_released() {
        let fixture = Fixture::new();
        let owner = Owner::acquire(&fixture.0, true).unwrap();
        let moved = fixture.0.with_extension("moved");
        assert!(fs::rename(&fixture.0, &moved).is_err());
        fs::write(fixture.0.join("sentinel"), b"retained").unwrap();
        drop(owner);
        fs::rename(&fixture.0, &moved).unwrap();
        fs::rename(&moved, &fixture.0).unwrap();
        assert_eq!(fs::read(fixture.0.join("sentinel")).unwrap(), b"retained");
    }
    #[cfg(unix)]
    #[test]
    fn journal_refuses_symlinks_and_hardlinks_and_a_replaced_root() {
        let fixture = Fixture::new();
        let external = fixture.0.with_extension("external");
        fs::write(&external, b"retained").unwrap();
        std::os::unix::fs::symlink(&external, fixture.0.join(NAME)).unwrap();
        assert!(Owner::acquire(&fixture.0, true).is_err());
        fs::remove_file(fixture.0.join(NAME)).unwrap();
        fs::hard_link(&external, fixture.0.join(NAME)).unwrap();
        assert!(Owner::acquire(&fixture.0, true).is_err());
        fs::remove_file(fixture.0.join(NAME)).unwrap();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        let moved = fixture.0.with_extension("moved");
        fs::rename(&fixture.0, &moved).unwrap();
        fs::create_dir(&fixture.0).unwrap();
        assert!(owner.clean_stop().is_err());
        drop(owner);
        assert_eq!(fs::read(&external).unwrap(), b"retained");
        fs::remove_file(external).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }
    #[test]
    fn idle_shutdown_proof_holds_the_controller_lease_and_refuses_active_or_foreign_state() {
        let f = Fixture::new();
        let mut owner = Owner::acquire(&f.0, true).unwrap();
        owner.admit_idle(ID, &sha()).unwrap();
        assert!(Owner::acquire(&f.0, true).is_err());
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        assert!(owner.admit_idle(ID, &sha()).is_err());
        owner.clean_stop().unwrap();
        owner.admit_idle(ID, &sha()).unwrap();
        assert!(owner.admit_idle("cccccccccccc", &sha()).is_err());
        let g = Fixture::new();
        let mut other = Owner::acquire(&g.0, true).unwrap();
        fs::write(g.0.join("unreviewed-data"), b"preserve").unwrap();
        assert!(other.admit_idle(ID, &sha()).is_err());
        assert_eq!(fs::read(g.0.join("unreviewed-data")).unwrap(), b"preserve");
    }
    #[test]
    fn package_maintenance_requires_empty_or_clean_stopped_state_and_current_root() {
        let fixture = Fixture::new();
        Owner::package_idle(&fixture.0).unwrap();
        let mut owner = Owner::acquire(&fixture.0, true).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        assert!(Owner::package_idle(&fixture.0).is_err());
        owner.clean_stop().unwrap();
        drop(owner);
        Owner::package_idle(&fixture.0).unwrap();
        let crashed = Fixture::new();
        let mut owner = Owner::acquire(&crashed.0, true).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        drop(owner);
        assert!(Owner::package_idle(&crashed.0).is_err());
    }
    #[test]
    fn activation_intent_fences_writers_and_packages_but_keeps_read_only_recovery() {
        for contents in [b"{".as_slice(), b"{}", b""] {
            let f = Fixture::new();
            let mut owner = Owner::acquire(&f.0, true).unwrap();
            owner
                .activate(ID, &sha(), crate::host_runtime::HostMode::RestorePrepare)
                .unwrap();
            owner.clean_stop().unwrap();
            fs::write(f.0.join("restore-activation.json"), contents).unwrap();
            assert!(owner
                .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
                .is_err());
            drop(owner);
            assert!(Owner::package_idle(&f.0).is_err());
            let mut owner = Owner::acquire(&f.0, true).unwrap();
            for mode in [
                crate::host_runtime::HostMode::Database,
                crate::host_runtime::HostMode::CheckpointCleanup,
            ] {
                owner.activate(ID, &sha(), mode).unwrap();
                owner.launch_state(&sha(), mode).unwrap();
                owner.clean_stop().unwrap();
            }
        }
        let f = Fixture::new();
        let mut owner = Owner::acquire(&f.0, true).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .unwrap();
        fs::write(f.0.join("restore-activation.json"), b"{}").unwrap();
        assert!(owner
            .launch_state(&sha(), crate::host_runtime::HostMode::Server)
            .is_err());
    }
    #[test]
    fn pending_selection_marker_alone_fences_writers_and_survives_read_only_maintenance() {
        let f = Fixture::new();
        let mut owner = Owner::acquire(&f.0, true).unwrap();
        owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::RestorePrepare)
            .unwrap();
        owner.clean_stop().unwrap();
        let mut marker = owner.read().unwrap().unwrap();
        marker.restore_pending = true;
        owner.write(&marker).unwrap();
        for mode in [
            crate::host_runtime::HostMode::Database,
            crate::host_runtime::HostMode::CheckpointCleanup,
        ] {
            owner.activate(ID, &sha(), mode).unwrap();
            owner.clean_stop().unwrap();
            assert!(owner.read().unwrap().unwrap().restore_pending);
        }
        assert!(owner
            .activate(ID, &sha(), crate::host_runtime::HostMode::Server)
            .is_err());
        drop(owner);
        assert!(Owner::package_idle(&f.0).is_err());
    }
}
