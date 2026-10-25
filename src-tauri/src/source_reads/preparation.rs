use super::*;

impl Job {
    /// Transfers a verified preparation cache into this job without adding any allowances.
    /// The caller must exclusively own the preparation worker until the handoff returns.
    pub fn adopt_prepared(
        self: &Arc<Self>,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        from: &Path,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<(), String> {
        let consent = crate::source_import::current(saved, identity, self.resource.source_id())?;
        if consent.reference_approval(saved, identity)?.fingerprint()
            != self.resource.scope_fingerprint()
        {
            return Err("source_approval_changed".into());
        }
        self.adopt(saved, identity, from, gate)
    }
    pub(super) fn adopt(
        self: &Arc<Self>,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        from: &Path,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<(), String> {
        let _owner = self.begin()?;
        gate()?;
        let mut state = self.state(saved, identity)?;
        let id = &self.resource.id;
        let base = self
            .source_root
            .parent()
            .and_then(Path::parent)
            .ok_or("source_journal_invalid")?;
        let mut budget = crate::private_inputs::InputBudget::open(base, identity)?;
        budget.reserve(self.resource.source_id(), id, self.resource.bytes)?;
        let target = self.journal.root.join("stage");
        self.resource.staging_root(from)?;
        if !from.is_absolute()
            || from.starts_with(&self.journal.root)
            || self.journal.root.starts_with(from)
        {
            return Err("source_staging_overlap".into());
        }
        if state.stage.as_ref().is_some_and(|current| current != id) {
            return Err("source_cache_cleanup_pending".into());
        }
        let destination_present = present(&target.join(id))?;
        let source_present = present(&from.join(id))?;
        if destination_present {
            if source_present || state.stage.as_ref() != Some(id) {
                return Err("source_cache_cleanup_pending".into());
            }
            return self.prepared_stage(saved, identity, &target, gate);
        }
        if !source_present {
            return Err("source_stage_unavailable".into());
        }
        self.prepared_stage(saved, identity, from, gate)?;
        crate::native_runtime::absolute_directory(from)?;
        let source = Dir::open_ambient_dir(from, ambient_authority())
            .map_err(|_| "source_stage_unavailable")?;
        let destination = Dir::open_ambient_dir(&target, ambient_authority())
            .map_err(|_| "source_stage_unavailable")?;
        // The durable pointer precedes the atomic move; either location remains recoverable after a crash.
        state.stage = Some(id.clone());
        self.journal.write("state.json", &state, identity)?;
        gate()?;
        self.require_owner()?;
        self.resource.validate_current(saved, identity)?;
        transfer(&source, &destination, id)?;
        #[cfg(unix)]
        for dir in [&source, &destination] {
            dir.try_clone()
                .and_then(|dir| dir.into_std_file().sync_all())
                .map_err(|_| "source_stage_transfer_failed")?;
        }
        gate()?;
        self.require_owner()?;
        self.prepared_stage(saved, identity, &target, gate)
    }
    fn prepared_stage(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        root: &Path,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<(), String> {
        self.resource.validate_current(saved, identity)?;
        let copy = StagedCopy::restore_with_gate(saved, identity, root, &self.resource.id, gate)?;
        if copy.resource_key() != self.resource.resource_key()
            || copy.version() != self.resource.version()
            || copy.bytes != self.resource.bytes
            || copy.sha256 != self.resource.sha256
        {
            return Err("source_stage_changed".into());
        }
        let dir = Dir::open_ambient_dir(root.join(&copy.id), ambient_authority())
            .map_err(|_| "source_stage_unavailable")?;
        let mut count = 0;
        for entry in dir.entries().map_err(|_| "source_stage_unavailable")? {
            let entry = entry.map_err(|_| "source_stage_unavailable")?;
            count += 1;
            if count > 2
                || !matches!(
                    entry.file_name().to_str(),
                    Some("original" | "receipt.json")
                )
            {
                return Err("source_stage_invalid".into());
            }
        }
        if count != 2 {
            return Err("source_stage_invalid".into());
        }
        self.resource.validate_current(saved, identity)?;
        gate()
    }
}
pub(super) fn present(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("source_stage_unavailable".into()),
    }
}
fn transfer(source: &Dir, target: &Dir, id: &str) -> Result<(), String> {
    if !canonical_uuid(id) {
        return Err("source_stage_invalid".into());
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::os::fd::AsRawFd;
        let name = std::ffi::CString::new(id).map_err(|_| "source_stage_invalid")?;
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                source.as_raw_fd(),
                name.as_ptr(),
                target.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                source.as_raw_fd(),
                name.as_ptr(),
                target.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            return Err("source_stage_transfer_failed".into());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use cap_std::fs::{MetadataExt, OpenOptionsExt};
        use std::os::windows::io::AsRawHandle;
        use windows_sys::{
            Wdk::Storage::FileSystem::{
                FileRenameInformation, NtSetInformationFile, FILE_RENAME_INFORMATION,
            },
            Win32::{
                Storage::FileSystem::{
                    DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
                    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
                },
                System::IO::IO_STATUS_BLOCK,
            },
        };
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(DELETE | FILE_GENERIC_READ)
            .share_mode(7)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let file = source
            .open_with(id, &options)
            .map_err(|_| "source_stage_transfer_failed")?;
        let meta = file
            .metadata()
            .map_err(|_| "source_stage_transfer_failed")?;
        if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("source_stage_invalid".into());
        }
        let name: Vec<u16> = id.encode_utf16().chain(std::iter::once(0)).collect();
        let size = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName) + name.len() * 2;
        let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let mut status = IO_STATUS_BLOCK::default();
        let result = unsafe {
            (*info).Anonymous.ReplaceIfExists = false;
            (*info).RootDirectory = target.as_raw_handle();
            (*info).FileNameLength = ((name.len() - 1) * 2) as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                name.len(),
            );
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut status,
                info.cast(),
                size as u32,
                FileRenameInformation,
            )
        };
        if result != 0 {
            return Err("source_stage_transfer_failed".into());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (source, target);
        Err("source_stage_transfer_failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_stage_atomic_transfer_never_replaces_an_existing_empty_directory() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-stage-handoff-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let id = uuid::Uuid::new_v4().to_string();
        for parent in ["source", "target"] {
            crate::runtime_store::private_directory(&root.join(parent)).unwrap();
            fs::create_dir(root.join(parent).join(&id)).unwrap();
        }
        fs::write(root.join("source").join(&id).join("retained"), b"keep").unwrap();
        let source = Dir::open_ambient_dir(root.join("source"), ambient_authority()).unwrap();
        let target = Dir::open_ambient_dir(root.join("target"), ambient_authority()).unwrap();
        assert!(transfer(&source, &target, &id).is_err());
        assert_eq!(
            fs::read(root.join("source").join(&id).join("retained")).unwrap(),
            b"keep"
        );
        assert_eq!(
            fs::read_dir(root.join("target").join(&id)).unwrap().count(),
            0
        );
    }
}
