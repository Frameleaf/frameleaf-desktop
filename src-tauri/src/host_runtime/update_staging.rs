//! Private plaintext staging under admitted target recovery; never execution or selection authority.
use super::*;
use cap_std::fs::Dir;
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
const BAD: &str = "host_update_input_invalid";
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostUpdateInput {
    schema_version: u32,
    kind: &'static str,
    source_epoch: u64,
    target_epoch: u64,
    source_checkpoint: ApprovalCheckpoint,
    restore: RestoreBinding,
}
fn active(cancel: &AtomicBool, deadline: Instant) -> Result<(), String> {
    if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
        Err(BAD.into())
    } else {
        Ok(())
    }
}
struct Directory {
    path: PathBuf,
    dir: Dir,
    identity: String,
    #[cfg(windows)]
    _pins: Vec<File>,
}
impl Directory {
    fn open(path: PathBuf) -> Result<Self, String> {
        let dir = Dir::from_std_file(crate::host_storage::directory(&path)?);
        #[cfg(windows)]
        let pins = crate::windows_protection::pin_private_directory(&path)?;
        let identity = crate::copy_source::root_identity(&dir)?;
        let result = Self {
            path,
            dir,
            identity,
            #[cfg(windows)]
            _pins: pins,
        };
        result.check()?;
        Ok(result)
    }
    fn child(&self, name: &str, fresh: bool) -> Result<Self, String> {
        self.check()?;
        #[cfg(windows)]
        if fresh {
            crate::windows_protection::new_private_directory(&self.path.join(name))?;
        } else {
            crate::windows_protection::private_directory(&self.path.join(name))?;
        }
        #[cfg(not(windows))]
        {
            let builder = cap_std::fs::DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use cap_std::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            match self.dir.create_dir_with(name, &builder) {
                Ok(()) => {}
                Err(error) if !fresh && error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(BAD.into()),
            }
        }
        let result = Self::open(self.path.join(name))?;
        let (anchored, _) =
            crate::copy_source::parent_dir(&self.dir, &Path::new(name).join("binding"))?;
        if crate::copy_source::root_identity(&anchored)? != result.identity {
            return Err(BAD.into());
        }
        self.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<(), String> {
        let current = Dir::from_std_file(crate::host_storage::directory(&self.path)?);
        crate::host_storage::check_cleanup(&self.path)?;
        #[cfg(unix)]
        {
            use cap_std::fs::PermissionsExt;
            if current
                .dir_metadata()
                .map_err(|_| BAD)?
                .permissions()
                .mode()
                & 0o077
                != 0
            {
                return Err(BAD.into());
            }
        }
        #[cfg(target_os = "macos")]
        crate::manager_host::no_acl(&self.path)?;
        #[cfg(windows)]
        crate::windows_protection::require_private_directory(&self.path)?;
        if crate::copy_source::root_identity(&current)? != self.identity {
            return Err(BAD.into());
        }
        Ok(())
    }
    fn create(&self, name: &str) -> Result<File, String> {
        self.check()?;
        let mut opts = crate::host_state::options(true);
        opts.create_new(true);
        let file = self.dir.open_with(name, &opts).map_err(|_| BAD)?.into_std();
        crate::host_state::valid_file(&file)?;
        Ok(file)
    }
    fn record(
        &self,
        name: &str,
        bytes: &[u8],
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<(), String> {
        active(cancel, deadline)?;
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(BAD.into());
        }
        let mut file = self.create(name)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| BAD)?;
        // Readback denies write sharing on Windows.
        drop(file);
        self.verify(
            name,
            bytes.len() as u64,
            &format!("{:x}", Sha256::digest(bytes)),
            cancel,
            deadline,
        )
    }
    fn verify(
        &self,
        name: &str,
        bytes: u64,
        sha: &str,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<(), String> {
        self.check()?;
        active(cancel, deadline)?;
        let mut file = crate::copy_source::staged_file(&self.dir, Path::new(name))?;
        crate::host_state::valid_sized_file(&file.try_clone().map_err(|_| BAD)?.into_std(), bytes)?;
        let stamp = crate::copy_source::opened_stamp(&file)?;
        let mut length = 0u64;
        let mut hash = Sha256::new();
        let mut buffer = [0; 65536];
        loop {
            active(cancel, deadline)?;
            let count = file.read(&mut buffer).map_err(|_| BAD)?;
            if count == 0 {
                break;
            }
            length = length.checked_add(count as u64).ok_or(BAD)?;
            if length > bytes {
                return Err(BAD.into());
            }
            hash.update(&buffer[..count]);
        }
        if length != bytes || format!("{:x}", hash.finalize()) != sha {
            return Err(BAD.into());
        }
        crate::copy_source::unchanged(&self.dir, Path::new(name), &file, &stamp, bytes, length)?;
        self.check()
    }
    fn require_names(&self, expected: &[&str]) -> Result<(), String> {
        self.check()?;
        let mut names = self
            .dir
            .entries()
            .map_err(|_| BAD)?
            .take(expected.len() + 1)
            .map(|entry| entry.map(|e| e.file_name()).map_err(|_| BAD))
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        let mut expected = expected
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>();
        expected.sort();
        if names != expected {
            return Err(BAD.into());
        }
        Ok(())
    }
    fn sync(&self) -> Result<(), String> {
        self.check()?;
        #[cfg(unix)]
        self.dir
            .try_clone()
            .and_then(|d| d.into_std_file().sync_all())
            .map_err(|_| BAD)?;
        Ok(())
    }
}
struct Stage {
    profile: Directory,
    root: Directory,
    operation: Directory,
    input: Directory,
}
impl Stage {
    fn new(state: &Path, binding: &RestoreBinding, dump_bytes: u64) -> Result<Self, String> {
        binding.validate()?;
        let profile = Directory::open(state.into())?;
        let required = dump_bytes.checked_add(256 * 1024 * 1024).ok_or(BAD)?;
        if dump_bytes == 0 || dump_bytes > MAX_SAFE {
            return Err(BAD.into());
        }
        if crate::copy_source::available_bytes(&profile.dir)? < required {
            return Err("host_update_capacity_insufficient".into());
        }
        let root = profile.child("restore-input", false)?;
        let operation = root.child(&binding.operation_id, true)?;
        let input = operation.child("input", true)?;
        Ok(Self {
            profile,
            root,
            operation,
            input,
        })
    }
    fn publish(
        &self,
        request: &HostUpdateInput,
        payload: &Payload,
        config: &Configuration,
        raw: &[u8],
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<(), String> {
        active(cancel, deadline)?;
        self.operation.require_names(&["input"])?;
        self.input.require_names(&["database.dump"])?;
        backup::recovery(raw, payload, config)?;
        self.input.verify(
            "database.dump",
            payload.checkpoint.dump.bytes,
            &payload.checkpoint.dump.sha256,
            cancel,
            deadline,
        )?;
        self.input.record("recovery.json", raw, cancel, deadline)?;
        self.input
            .require_names(&["database.dump", "recovery.json"])?;
        self.input.sync()?;
        active(cancel, deadline)?;
        self.operation.record(
            "restore-intent.json",
            &serde_json::to_vec(&request.restore).map_err(|_| BAD)?,
            cancel,
            deadline,
        )?;
        self.operation
            .require_names(&["input", "restore-intent.json"])?;
        for directory in [&self.input, &self.operation, &self.root, &self.profile] {
            directory.sync()?;
        }
        active(cancel, deadline)
    }
}
impl VerifiedHostRuntime {
    /// Stage only the authenticated backup using the currently admitted target. Does not start a database.
    pub fn stage_update_input(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
    ) -> Result<HostUpdateInput, String> {
        self.stage_update_input_with(
            target,
            [source, destination],
            execution,
            cancel,
            &mut crate::manager_profile::Keystore,
        )
    }
    pub(in crate::host_runtime) fn stage_update_input_with(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateInput, String> {
        let deadline = Instant::now() + Duration::from_secs(7200);
        self.stage_with_backup(
            target,
            profiles,
            (execution, cancel, deadline),
            store,
            |payload, key, file| {
                target.stage_update_backup_held(profiles[0], payload, key, cancel, deadline, file)
            },
        )
    }
    #[cfg(test)]
    pub(in crate::host_runtime) fn stage_update_input_test(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
        store: &mut impl crate::manager_profile::UpdateStore,
        write: impl FnMut(&Payload, &str, File) -> Result<Vec<u8>, String>,
    ) -> Result<HostUpdateInput, String> {
        self.stage_with_backup(
            target,
            profiles,
            (
                execution,
                cancel,
                Instant::now() + Duration::from_secs(7200),
            ),
            store,
            write,
        )
    }
    fn stage_with_backup(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        authority: (&HostExecution<'_>, &AtomicBool, Instant),
        store: &mut impl crate::manager_profile::UpdateStore,
        mut write: impl FnMut(&Payload, &str, File) -> Result<Vec<u8>, String>,
    ) -> Result<HostUpdateInput, String> {
        let (execution, cancel, deadline) = authority;
        active(cancel, deadline)?;
        if self.epoch() == 0 || target.epoch() <= self.epoch() || target.epoch() > MAX_SAFE {
            return Err(BAD.into());
        }
        let mut result = None;
        self.with_consumption_context(
            target,
            profiles,
            (execution, ContextAdmission::TargetRecovery),
            None,
            clock,
            store,
            |payload, credentials, owner, _| {
                let key = credentials.backup_key;
                let (request, stage) = stage_input_held(
                    self,
                    target,
                    profiles[0],
                    (payload, key, owner),
                    (cancel, deadline),
                    &mut write,
                )?;
                result = Some((request, stage));
                Ok(())
            },
        )?;
        active(cancel, deadline)?;
        let (request, stage) = result.ok_or(BAD)?;
        for directory in [&stage.input, &stage.operation, &stage.root, &stage.profile] {
            directory.check()?;
        }
        Ok(request)
    }
}

fn update_input(
    source: &VerifiedHostRuntime,
    target: &VerifiedHostRuntime,
    payload: &Payload,
    operation: String,
) -> HostUpdateInput {
    let binding = RestoreBinding {
        schema_version: 1,
        runtime: "native".into(),
        operation_id: operation,
        review_id: payload.approval_id.clone(),
        snapshot_id: payload.snapshot_id.clone(),
        installation_id: payload.installation_id.clone(),
        manifest_sha256: target.manifest_sha256().into(),
        source_revision: target.source_revision().into(),
        library_id: payload.library_id.clone(),
        recovery_sha256: payload.recovery_sha256.clone(),
    };
    HostUpdateInput {
        schema_version: 1,
        kind: "native-update",
        source_epoch: source.epoch(),
        target_epoch: target.epoch(),
        source_checkpoint: payload.checkpoint.clone(),
        restore: binding,
    }
}
fn stage_input_held(
    source: &VerifiedHostRuntime,
    target: &VerifiedHostRuntime,
    config: &Configuration,
    context: (&Payload, &str, &mut crate::host_state::Owner),
    activity: (&AtomicBool, Instant),
    write: &mut impl FnMut(&Payload, &str, File) -> Result<Vec<u8>, String>,
) -> Result<(HostUpdateInput, Stage), String> {
    let (payload, key, owner) = context;
    let (cancel, deadline) = activity;
    active(cancel, deadline)?;
    source.update_recovery_record_held(target, payload, key, owner, true)?;
    let request = update_input(source, target, payload, uuid::Uuid::new_v4().to_string());
    let stage = Stage::new(
        &config.state,
        &request.restore,
        payload.checkpoint.dump.bytes,
    )?;
    if crate::copy_source::available_bytes(&stage.input.dir)?
        < payload
            .checkpoint
            .dump
            .bytes
            .checked_add(256 * 1024 * 1024)
            .ok_or(BAD)?
    {
        return Err("host_update_capacity_insufficient".into());
    }
    let raw = write(payload, key, stage.input.create("database.dump")?)?;
    stage.publish(&request, payload, config, &raw, cancel, deadline)?;
    Ok((request, stage))
}

#[path = "update_preparation.rs"]
mod preparation;
pub use preparation::HostUpdateCandidate;
