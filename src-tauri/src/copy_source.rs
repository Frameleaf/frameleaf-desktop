//! Approved, account-bound source reads into independent, verified staging bytes.
use crate::connection::{normalize_server, DeviceIdentity, SavedConnection};
use cap_std::{
    ambient_authority,
    fs::{Dir, Metadata, OpenOptions},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, Write},
    path::{Component, Path},
    sync::atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CopyScope {
    version: u8,
    source_id: String,
    server: String,
    server_id: String,
    account_id: String,
    device_id: String,
    installation_id: String,
    root: String,
    root_identity: String,
    max_item_bytes: u64,
    allow_download: bool,
}
const LEGACY_ITEM_CAP: u64 = 2 * 1024 * 1024 * 1024;
/// FL-1268: no per-file ceiling. The largest integer that survives canonical JSON signing exactly.
pub(crate) const UNLIMITED_ITEM_BYTES: u64 = (1 << 53) - 1;
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CopyApproval {
    scope: CopyScope,
    signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StagedCopy {
    pub id: String,
    pub bytes: u64,
    pub sha256: String,
    pub file_created_at_ms: i64,
    pub file_modified_at_ms: i64,
    source_signature: String,
    source_stamp: String,
    relative: String,
    approval: CopyApproval,
    signature: String,
}
fn signed(
    identity: &DeviceIdentity,
    domain: &str,
    value: &impl Serialize,
) -> Result<String, String> {
    let bytes = serde_json_canonicalizer::to_vec(value).map_err(|_| "source_approval_invalid")?;
    Ok(identity.sign(&format!(
        "frameleaf-desktop/{domain}/v1\n{}",
        String::from_utf8(bytes).map_err(|_| "source_approval_invalid")?
    )))
}
fn cancel(cancelled: &AtomicBool) -> Result<(), String> {
    if cancelled.load(Ordering::Acquire) {
        Err("source_copy_cancelled".into())
    } else {
        Ok(())
    }
}
fn stamp(meta: &Metadata) -> Result<String, String> {
    let modified = match meta
        .modified()
        .map_err(|_| "source_identity_unavailable")?
        .into_std()
        .duration_since(std::time::UNIX_EPOCH)
    {
        Ok(duration) => duration.as_nanos().to_string(),
        Err(error) => format!("-{}", error.duration().as_nanos()),
    };
    #[cfg(unix)]
    let extra = {
        use cap_std::fs::MetadataExt;
        format!(
            "{}:{}:{}:{}",
            meta.dev(),
            meta.ino(),
            meta.ctime(),
            meta.ctime_nsec()
        )
    };
    #[cfg(windows)]
    let extra = {
        use cap_std::fs::MetadataExt;
        format!("{}:{}", meta.creation_time(), meta.file_attributes())
    };
    Ok(format!("{}:{modified}:{extra}", meta.len()))
}
pub(crate) fn opened_stamp(file: &cap_std::fs::File) -> Result<String, String> {
    let value = stamp(&file.metadata().map_err(|_| "source_identity_unavailable")?)?;
    #[cfg(unix)]
    {
        Ok(value)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
        };
        // ReFS identity needs all 128 bits; a legacy 64-bit file index can collide.
        let mut info = std::mem::MaybeUninit::<FILE_ID_INFO>::zeroed();
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                info.as_mut_ptr().cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err("source_identity_unavailable".into());
        }
        let info = unsafe { info.assume_init() };
        let id: String = info
            .FileId
            .Identifier
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(format!(
            "{value}:file-id-v2:{}:{id}",
            info.VolumeSerialNumber
        ))
    }
}
fn path_stamp(dir: &Dir, relative: &Path, expected: &Metadata) -> Result<String, String> {
    #[cfg(unix)]
    {
        let _ = (dir, relative);
        stamp(expected)
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_NO_RECALL, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_READ_ATTRIBUTES,
        };
        // Capture identity without reading or recalling original data before capacity admission.
        let mut options = OpenOptions::new();
        options
            .read(true)
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(7)
            .custom_flags(
                FILE_FLAG_OPEN_NO_RECALL
                    | FILE_FLAG_OPEN_REPARSE_POINT
                    | FILE_FLAG_BACKUP_SEMANTICS,
            );
        let file = dir
            .open_with(relative, &options)
            .map_err(|_| "source_identity_unavailable")?;
        let meta = file.metadata().map_err(|_| "source_identity_unavailable")?;
        if !meta.is_file() || link(&meta) || stamp(&meta)? != stamp(expected)? {
            #[cfg(test)]
            eprintln!(
                "source_identity/path_stamp expected={:?} opened={:?}",
                stamp(expected),
                stamp(&meta)
            );
            return Err("source_item_changed".into());
        }
        opened_stamp(&file)
    }
}
/// The same metadata identity used by the staging receipt, without opening original data.
pub(crate) fn watch_version(dir: &Dir, name: &Path, meta: &Metadata) -> Result<String, String> {
    Ok(version(&path_stamp(dir, name, meta)?))
}
fn version(stamp: &str) -> String {
    format!("{:x}", Sha256::digest(stamp.as_bytes()))
}
pub(crate) fn watchable(meta: &Metadata, observation: crate::source_metadata::Observation) -> bool {
    !link(meta)
        && !matches!(
            observation.availability,
            crate::source_metadata::Availability::NeedsDownload
                | crate::source_metadata::Availability::NotReady
        )
}
pub(crate) fn root_identity(dir: &Dir) -> Result<String, String> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        let meta = dir.dir_metadata().map_err(|_| "source_root_unavailable")?;
        Ok(format!("{}:{}", meta.dev(), meta.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        if unsafe { GetFileInformationByHandle(dir.as_raw_handle(), info.as_mut_ptr()) } == 0 {
            return Err("source_identity_unavailable".into());
        }
        let info = unsafe { info.assume_init() };
        Ok(format!(
            "{}:{}:{}",
            info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
        ))
    }
}
fn available_bytes(dir: &Dir) -> Result<u64, String> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let mut info = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
        if unsafe { libc::fstatvfs(dir.as_raw_fd(), info.as_mut_ptr()) } != 0 {
            return Err("source_capacity_unavailable".into());
        }
        let info = unsafe { info.assume_init() };
        u64::try_from(u128::from(info.f_bavail) * u128::from(info.f_frsize))
            .map_err(|_| "source_capacity_unavailable".into())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFinalPathNameByHandleW, FILE_NAME_OPENED,
        };
        let mut path = vec![0u16; 32768];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                dir.as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                FILE_NAME_OPENED,
            )
        } as usize;
        if length == 0 || length >= path.len() - 1 {
            return Err("source_capacity_unavailable".into());
        }
        // GetDiskFreeSpaceEx requires a trailing separator for UNC share roots.
        if path[length - 1] != b'\\' as u16 {
            path[length] = b'\\' as u16;
            path[length + 1] = 0;
        }
        let mut available = 0;
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                path.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err("source_capacity_unavailable".into());
        }
        Ok(available)
    }
}
fn check_capacity(
    bytes: u64,
    source_free: u64,
    staging_free: u64,
    same_volume: bool,
    may_download: bool,
) -> Result<(), String> {
    const RESERVE: u64 = 256 * 1024 * 1024;
    let hydration = if may_download { bytes } else { 0 };
    let staging_required = bytes
        .checked_add(if same_volume { hydration } else { 0 })
        .and_then(|value| value.checked_add(RESERVE))
        .ok_or("source_capacity_insufficient")?;
    let source_required = hydration
        .checked_add(RESERVE)
        .ok_or("source_capacity_insufficient")?;
    if staging_free < staging_required || (may_download && source_free < source_required) {
        return Err("source_capacity_insufficient".into());
    }
    Ok(())
}
fn relative_path(path: &str) -> Result<&Path, String> {
    let path = Path::new(path);
    if !path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(crate::photo_sources::is_media_filename)
    {
        return Err("source_item_invalid".into());
    }
    if path.as_os_str().is_empty()
        || path.components().any(|part| {
            !matches!(part, Component::Normal(_))
                || part.as_os_str().to_string_lossy().starts_with('.')
                || [".photoslibrary", ".photolibrary", ".app", ".bundle"]
                    .iter()
                    .any(|suffix| {
                        part.as_os_str()
                            .to_string_lossy()
                            .to_lowercase()
                            .ends_with(suffix)
                    })
        })
    {
        return Err("source_item_invalid".into());
    }
    Ok(path)
}
impl CopyApproval {
    pub(crate) fn source_id(&self) -> &str {
        &self.scope.source_id
    }
    pub(crate) fn fingerprint(&self) -> String {
        format!("{:x}", Sha256::digest(self.signature.as_bytes()))
    }
    pub(crate) fn root(&self) -> &Path {
        Path::new(&self.scope.root)
    }
    pub(crate) fn root_identity(&self) -> &str {
        &self.scope.root_identity
    }
    pub(crate) fn validate_current(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
    ) -> Result<(), String> {
        self.validate(saved, identity)
    }
    pub fn approve(
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        root: &Path,
        max_item_bytes: u64,
        allow_download: bool,
    ) -> Result<Self, String> {
        normalize_server(&saved.server)?;
        // Reuse the preview's broad-root and package refusals, without opening media.
        crate::photo_sources::inventory(root, 1)?;
        #[cfg(windows)]
        crate::native_runtime::absolute_directory(root).map_err(|code| {
            if code == "runtime_link_forbidden" {
                "source_cloud_copy_pending".into()
            } else {
                code
            }
        })?;
        if saved.server_id.is_empty()
            || saved.account_id.is_empty()
            || saved.device_id.as_deref().is_none_or(str::is_empty)
            || max_item_bytes == 0
            // Reserved: approvals signed with the old 2 GiB default are read as unlimited.
            || max_item_bytes == LEGACY_ITEM_CAP
            || max_item_bytes > UNLIMITED_ITEM_BYTES
        {
            return Err("source_approval_invalid".into());
        }
        let dir = Dir::open_ambient_dir(root, ambient_authority())
            .map_err(|_| "source_root_unavailable")?;
        let scope = CopyScope {
            version: 1,
            source_id: Uuid::new_v4().to_string(),
            server: saved.server.clone(),
            server_id: saved.server_id.clone(),
            account_id: saved.account_id.clone(),
            device_id: saved.device_id.clone().unwrap(),
            installation_id: identity.installation_id.clone(),
            root: root.to_str().ok_or("source_root_invalid")?.into(),
            root_identity: root_identity(&dir)?,
            max_item_bytes,
            allow_download,
        };
        Ok(Self {
            signature: signed(identity, "copy-approval", &scope)?,
            scope,
        })
    }
    fn validate(&self, saved: &SavedConnection, identity: &DeviceIdentity) -> Result<(), String> {
        let scope = &self.scope;
        // Canonical signing rounds larger integers, so a changed limit could share a signature.
        if scope.version != 1
            || scope.max_item_bytes == 0
            || scope.max_item_bytes > UNLIMITED_ITEM_BYTES
            || scope.server != saved.server
            || scope.server_id != saved.server_id
            || scope.account_id != saved.account_id
            || Some(&scope.device_id) != saved.device_id.as_ref()
            || scope.installation_id != identity.installation_id
            || self.signature != signed(identity, "copy-approval", scope)?
        {
            return Err("source_approval_invalid".into());
        }
        Ok(())
    }
    pub fn stage(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        relative: &str,
        destination: &Path,
        cancelled: &AtomicBool,
    ) -> Result<StagedCopy, String> {
        self.stage_to(
            saved,
            identity,
            relative,
            destination,
            &Uuid::new_v4().to_string(),
            None,
            None,
            cancelled,
            &|| Ok(()),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stage_to(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        relative: &str,
        destination: &Path,
        stage_id: &str,
        expected_bytes: Option<u64>,
        expected_watch_version: Option<&str>,
        cancelled: &AtomicBool,
        gate: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<StagedCopy, String> {
        if !Uuid::parse_str(stage_id).is_ok_and(|id| !id.is_nil() && id.to_string() == stage_id) {
            return Err("source_stage_invalid".into());
        }
        #[cfg(target_os = "macos")]
        let _no_materialization = expected_watch_version
            .map(|_| crate::photo_sources::metadata_only::Guard::new())
            .transpose()?;
        gate()?;
        self.validate(saved, identity)?;
        cancel(cancelled)?;
        if !self.scope.allow_download {
            return Err("source_download_permission_required".into());
        }
        let relative_path = relative_path(relative)?;
        let root = Path::new(&self.scope.root);
        crate::native_runtime::absolute_directory(root)?;
        crate::native_runtime::absolute_directory(destination)?;
        if destination.starts_with(root) || root.starts_with(destination) {
            return Err("source_staging_overlap".into());
        }
        let dir = Dir::open_ambient_dir(root, ambient_authority())
            .map_err(|_| "source_root_unavailable")?;
        if root_identity(&dir)? != self.scope.root_identity {
            return Err("source_root_changed".into());
        }
        let root_meta = dir.dir_metadata().map_err(|_| "source_root_unavailable")?;
        if crate::source_metadata::probe(&dir, Path::new("."), &root_meta)?.excluded {
            return Err("source_item_excluded".into());
        }
        let (dir, name) = parent_dir(&dir, relative_path)?;
        let relative_path = name.as_path();
        let before = dir
            .symlink_metadata(relative_path)
            .map_err(|_| "source_item_unavailable")?;
        if !before.is_file() || link(&before) || before.len() == 0 {
            return Err("source_item_invalid".into());
        }
        let availability = crate::source_metadata::probe(&dir, relative_path, &before)?;
        if availability.excluded {
            return Err("source_item_excluded".into());
        }
        if expected_bytes.is_some_and(|bytes| bytes != before.len()) {
            return Err("source_item_changed".into());
        }
        // Approvals signed before FL-1268 carry the old 2 GiB default, which is no longer a per-file limit.
        if self.scope.max_item_bytes != LEGACY_ITEM_CAP && before.len() > self.scope.max_item_bytes
        {
            return Err("source_copy_budget_exceeded".into());
        }
        if expected_watch_version.is_some() && !watchable(&before, availability) {
            return Err("source_item_changed".into());
        }
        let source_stamp = path_stamp(&dir, relative_path, &before)?;
        if expected_watch_version.is_some_and(|expected| expected != version(&source_stamp)) {
            return Err("source_item_changed".into());
        }
        let staging = Dir::open_ambient_dir(destination, ambient_authority())
            .map_err(|_| "source_stage_unavailable")?;
        // Unknown residency reserves a full original; pinning and allocated blocks are not proof.
        let may_download =
            availability.availability != crate::source_metadata::Availability::Available;
        // shortcut: volume IDs do not reveal shared APFS pools; add pool admission before parallel imports.
        let source_volume = root_identity(&dir)?;
        let staging_volume = root_identity(&staging)?;
        check_capacity(
            before.len(),
            if may_download {
                available_bytes(&dir)?
            } else {
                0
            },
            available_bytes(&staging)?,
            source_volume.split(':').next() == staging_volume.split(':').next(),
            may_download,
        )?;
        let options = no_follow_options(false);
        #[cfg(windows)]
        let options = {
            use cap_std::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_NO_RECALL, FILE_FLAG_OPEN_REPARSE_POINT,
            };
            let mut options = options;
            if expected_watch_version.is_some() {
                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL);
            }
            options
        };
        let mut source = dir
            .open_with(relative_path, &options)
            .map_err(|_| "source_item_unavailable")?;
        let opened = source.metadata().map_err(|_| "source_item_unavailable")?;
        if !opened.is_file() || link(&opened) || opened_stamp(&source)? != source_stamp {
            #[cfg(test)]
            eprintln!(
                "source_identity/stage_open expected={source_stamp} opened={:?}",
                opened_stamp(&source)
            );
            return Err("source_item_changed".into());
        }
        let id = stage_id.to_string();
        let path = destination.join(&id);
        crate::runtime_store::create_private_directory(&path)
            .map_err(|_| "source_stage_unavailable")?;
        let mut cleanup = Partial(Some(path.clone()));
        crate::runtime_store::private_directory(&path).map_err(|_| "source_stage_unavailable")?;
        let mut output = fs::OpenOptions::new();
        output.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            output.mode(0o600);
        }
        let mut output = output
            .open(path.join("original"))
            .map_err(|_| "source_stage_unavailable")?;
        let mut bytes = 0u64;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut next_check = 0;
        loop {
            cancel(cancelled)?;
            if bytes >= next_check {
                gate()?;
                next_check = bytes + 1024 * 1024;
            }
            let count = source
                .read(&mut buffer)
                .map_err(|_| "source_copy_interrupted")?;
            if count == 0 {
                break;
            }
            bytes += count as u64;
            if bytes > before.len() {
                return Err("source_item_changed".into());
            }
            output
                .write_all(&buffer[..count])
                .map_err(|_| "source_stage_write_failed")?;
            hash.update(&buffer[..count]);
        }
        cancel(cancelled)?;
        gate()?;
        unchanged(
            &dir,
            relative_path,
            &source,
            &source_stamp,
            before.len(),
            bytes,
        )?;
        output.sync_all().map_err(|_| "source_stage_write_failed")?;
        drop(output);
        let approval = self.clone();
        let mut result = StagedCopy {
            id,
            bytes,
            sha256: format!("{:x}", hash.finalize()),
            file_modified_at_ms: milliseconds(
                before
                    .modified()
                    .map_err(|_| "source_identity_unavailable")?
                    .into_std(),
            )?,
            file_created_at_ms: milliseconds(
                before
                    .created()
                    .or_else(|_| before.modified())
                    .map_err(|_| "source_identity_unavailable")?
                    .into_std(),
            )?,
            source_signature: self.signature.clone(),
            source_stamp,
            relative: relative.into(),
            approval,
            signature: String::new(),
        };
        result.signature = result.sign(identity)?;
        let data = serde_json::to_vec(&result).map_err(|_| "source_stage_write_failed")?;
        let mut receipt = fs::OpenOptions::new();
        receipt.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            receipt.mode(0o600);
        }
        let mut receipt = receipt
            .open(path.join("receipt.json"))
            .map_err(|_| "source_stage_write_failed")?;
        receipt
            .write_all(&data)
            .and_then(|_| receipt.sync_all())
            .map_err(|_| "source_stage_write_failed")?;
        cleanup.0.take();
        Ok(result)
    }
}
struct Partial(Option<std::path::PathBuf>);
impl Drop for Partial {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}
impl StagedCopy {
    pub(crate) fn matches_entry(&self, relative: &str, bytes: u64) -> bool {
        self.relative == relative && self.bytes == bytes
    }
    pub(crate) fn resource_key(&self) -> String {
        format!(
            "{:x}",
            Sha256::digest(format!("{}\n{}", self.source_signature, self.relative).as_bytes())
        )
    }
    pub(crate) fn version(&self) -> String {
        version(&self.source_stamp)
    }
    pub(crate) fn release(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        destination: &Path,
    ) -> Result<(), String> {
        self.approval.validate(saved, identity)?;
        if self.signature != self.sign(identity)?
            || Uuid::parse_str(&self.id)
                .map_err(|_| "source_stage_invalid")?
                .to_string()
                != self.id
        {
            return Err("source_stage_invalid".into());
        }
        release_stage(destination, &self.id)
    }
    pub(crate) fn source_id(&self) -> &str {
        self.approval.source_id()
    }
    pub(crate) fn filename(&self) -> Result<&str, String> {
        relative_path(&self.relative)?
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "source_item_invalid".into())
    }

    pub fn restore(
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        destination: &Path,
        id: &str,
    ) -> Result<Self, String> {
        if Uuid::parse_str(id)
            .map_err(|_| "source_stage_invalid")?
            .to_string()
            != id
        {
            return Err("source_stage_invalid".into());
        }
        crate::native_runtime::absolute_directory(&destination.join(id))?;
        let dir = Dir::open_ambient_dir(destination, ambient_authority())
            .map_err(|_| "source_stage_unavailable")?;
        let file = staged_file(&dir, &Path::new(id).join("receipt.json"))?;
        let mut bytes = Vec::new();
        file.take(262_145)
            .read_to_end(&mut bytes)
            .map_err(|_| "source_stage_unavailable")?;
        if bytes.len() > 262_144 {
            return Err("source_stage_invalid".into());
        }
        let copy: Self = serde_json::from_slice(&bytes).map_err(|_| "source_stage_invalid")?;
        if copy.id != id {
            return Err("source_stage_invalid".into());
        }
        copy.verify(saved, identity, destination)?;
        Ok(copy)
    }
    fn sign(&self, identity: &DeviceIdentity) -> Result<String, String> {
        signed(
            identity,
            "copy-stage",
            &(
                &self.id,
                self.bytes,
                &self.sha256,
                self.file_created_at_ms,
                self.file_modified_at_ms,
                &self.source_signature,
                &self.source_stamp,
                &self.relative,
            ),
        )
    }
    pub fn verify(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        destination: &Path,
    ) -> Result<cap_std::fs::File, String> {
        self.approval.validate(saved, identity)?;
        if Uuid::parse_str(&self.id)
            .map_err(|_| "source_stage_invalid")?
            .to_string()
            != self.id
            || self.source_signature != self.approval.signature
            || self.signature != self.sign(identity)?
        {
            return Err("source_stage_invalid".into());
        }
        crate::native_runtime::absolute_directory(destination)?;
        let dir = Dir::open_ambient_dir(destination, ambient_authority())
            .map_err(|_| "source_stage_unavailable")?;
        crate::native_runtime::absolute_directory(&destination.join(&self.id))?;
        let relative = Path::new(&self.id).join("original");
        let mut file = staged_file(&dir, &relative)?;
        let mut hash = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|_| "source_stage_unavailable")?;
            if count == 0 {
                break;
            }
            bytes += count as u64;
            if bytes > self.bytes {
                return Err("source_stage_changed".into());
            }
            hash.update(&buffer[..count]);
        }
        if bytes != self.bytes || format!("{:x}", hash.finalize()) != self.sha256 {
            return Err("source_stage_changed".into());
        }
        file.rewind().map_err(|_| "source_stage_unavailable")?;
        Ok(file)
    }
}

fn no_follow_options(directory: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(
            libc::O_NOFOLLOW | libc::O_NONBLOCK | if directory { libc::O_DIRECTORY } else { 0 },
        );
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };
        options.share_mode(1).custom_flags(
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
        );
    }
    options
}
fn link(meta: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    meta.is_symlink()
}
pub(crate) fn parent_dir(root: &Dir, relative: &Path) -> Result<(Dir, std::path::PathBuf), String> {
    let mut dir = root.try_clone().map_err(|_| "source_item_unavailable")?;
    let parts: Vec<_> = relative.components().collect();
    let (leaf, parents) = parts.split_last().ok_or("source_item_invalid")?;
    if !matches!(leaf, Component::Normal(_)) {
        return Err("source_item_invalid".into());
    }
    for part in parents {
        if !matches!(part, Component::Normal(_)) {
            return Err("source_item_invalid".into());
        }
        let before = dir
            .symlink_metadata(part.as_os_str())
            .map_err(|_| "source_item_unavailable")?;
        if crate::source_metadata::probe(&dir, Path::new(part.as_os_str()), &before)?.excluded {
            return Err("source_item_excluded".into());
        }
        let child = dir
            .open_with(part.as_os_str(), &no_follow_options(true))
            .map_err(|_| "source_item_invalid")?;
        let meta = child.metadata().map_err(|_| "source_item_unavailable")?;
        if !meta.is_dir() || link(&meta) {
            return Err("source_item_invalid".into());
        }
        dir = Dir::from_std_file(child.into_std());
    }
    Ok((dir, leaf.as_os_str().into()))
}
pub(crate) fn staged_file(dir: &Dir, relative: &Path) -> Result<cap_std::fs::File, String> {
    let (dir, name) = parent_dir(dir, relative)?;
    let meta = dir
        .symlink_metadata(&name)
        .map_err(|_| "source_stage_unavailable")?;
    if !meta.is_file() || link(&meta) {
        return Err("source_stage_invalid".into());
    }
    let file = dir
        .open_with(&name, &no_follow_options(false))
        .map_err(|_| "source_stage_unavailable")?;
    let opened = file.metadata().map_err(|_| "source_stage_unavailable")?;
    if !opened.is_file() || link(&opened) {
        return Err("source_stage_invalid".into());
    }
    Ok(file)
}

pub(crate) fn unchanged(
    dir: &Dir,
    relative: &Path,
    source: &cap_std::fs::File,
    before: &str,
    expected: u64,
    copied: u64,
) -> Result<(), String> {
    if copied != expected
        || opened_stamp(source)? != before
        || path_stamp(
            dir,
            relative,
            &dir.symlink_metadata(relative)
                .map_err(|_| "source_item_changed")?,
        )? != before
    {
        #[cfg(test)]
        eprintln!("source_identity/unchanged expected={before} opened={:?} named={:?} expected_bytes={expected} copied={copied}", opened_stamp(source), dir.symlink_metadata(relative).and_then(|meta| stamp(&meta).map_err(std::io::Error::other)));
        return Err("source_item_changed".into());
    }
    Ok(())
}
fn milliseconds(value: std::time::SystemTime) -> Result<i64, String> {
    let value = match value.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => {
            i128::try_from(duration.as_millis()).map_err(|_| "source_identity_unavailable")?
        }
        Err(error) => -i128::try_from(error.duration().as_millis())
            .map_err(|_| "source_identity_unavailable")?,
    };
    if !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&value) {
        return Err("source_identity_unavailable".into());
    }
    i64::try_from(value).map_err(|_| "source_identity_unavailable".into())
}

/// Only app-owned named files are removed; unexpected data or links are retained for attention.
pub(crate) fn release_stage(destination: &Path, id: &str) -> Result<(), String> {
    if !Uuid::parse_str(id).is_ok_and(|value| !value.is_nil() && value.to_string() == id) {
        return Err("source_stage_invalid".into());
    }
    crate::native_runtime::absolute_directory(destination)?;
    let root = Dir::open_ambient_dir(destination, ambient_authority())
        .map_err(|_| "source_stage_unavailable")?;
    match root.symlink_metadata(id) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(meta) if meta.is_dir() && !link(&meta) => {}
        _ => return Err("source_stage_invalid".into()),
    }
    let dir = root.open_dir(id).map_err(|_| "source_stage_unavailable")?;
    for name in ["original", "receipt.json"] {
        match dir.symlink_metadata(name) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(meta) if meta.is_file() && !link(&meta) => dir
                .remove_file(name)
                .map_err(|_| "source_cache_cleanup_pending")?,
            _ => return Err("source_stage_invalid".into()),
        }
    }
    // Windows directory handles deny deletion until closed.
    drop(dir);
    root.remove_dir(id)
        .map_err(|_| "source_cache_cleanup_pending")?;
    #[cfg(unix)]
    {
        std::fs::File::open(destination)
            .and_then(|file| file.sync_all())
            .map_err(|_| "source_cache_cleanup_pending")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn fresh_windows_source_metadata_matches_opened_handles() {
        for iteration in 0..64 {
            let path = std::env::temp_dir().join(format!("frameleaf-fresh-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            let cleanup = Partial(Some(path.clone()));
            fs::write(path.join("旅行.jpg"), b"abcdefghij").unwrap();
            let dir = Dir::open_ambient_dir(&path, ambient_authority()).unwrap();
            let root = dir.dir_metadata().unwrap();
            crate::source_metadata::probe(&dir, Path::new("."), &root)
                .unwrap_or_else(|code| panic!("iteration={iteration} root probe: {code}"));
            let name = Path::new("旅行.jpg");
            let before = dir.symlink_metadata(name).unwrap();
            crate::source_metadata::probe(&dir, name, &before)
                .unwrap_or_else(|code| panic!("iteration={iteration} file probe: {code}"));
            let expected = path_stamp(&dir, name, &before)
                .unwrap_or_else(|code| panic!("iteration={iteration} path stamp: {code}"));
            let file = dir.open_with(name, &no_follow_options(false)).unwrap();
            assert_eq!(
                opened_stamp(&file).unwrap(),
                expected,
                "iteration={iteration}"
            );
            unchanged(&dir, name, &file, &expected, 10, 10)
                .unwrap_or_else(|code| panic!("iteration={iteration} after read: {code}"));
            drop(file);
            drop(dir);
            drop(cleanup);
        }
    }
    #[test]
    fn opened_source_identity_survives_reopen_and_distinguishes_another_file() {
        let path = std::env::temp_dir().join(format!("frameleaf-identity-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        let cleanup = Partial(Some(path.clone()));
        fs::write(path.join("first.jpg"), b"original").unwrap();
        fs::write(path.join("second.jpg"), b"replaced").unwrap();
        let dir = Dir::open_ambient_dir(&path, ambient_authority()).unwrap();
        let first = dir.open("first.jpg").unwrap();
        let second = dir.open("second.jpg").unwrap();
        #[cfg(windows)]
        {
            use cap_std::fs::MetadataExt;
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::{Foundation::FILETIME, Storage::FileSystem::SetFileTime};
            let meta = first.metadata().unwrap();
            let time = |value: u64| FILETIME {
                dwLowDateTime: value as u32,
                dwHighDateTime: (value >> 32) as u32,
            };
            let writable = fs::OpenOptions::new()
                .write(true)
                .open(path.join("second.jpg"))
                .unwrap();
            assert_ne!(
                unsafe {
                    SetFileTime(
                        writable.as_raw_handle(),
                        &time(meta.creation_time()),
                        std::ptr::null(),
                        &time(meta.last_write_time()),
                    )
                },
                0
            );
            drop(writable);
            assert_eq!(
                stamp(&first.metadata().unwrap()).unwrap(),
                stamp(&second.metadata().unwrap()).unwrap()
            );
        }
        let before = opened_stamp(&first).unwrap();
        assert_eq!(
            before,
            path_stamp(&dir, Path::new("first.jpg"), &first.metadata().unwrap()).unwrap()
        );
        unchanged(&dir, Path::new("first.jpg"), &first, &before, 8, 8).unwrap();
        assert_eq!(
            before,
            opened_stamp(&dir.open("first.jpg").unwrap()).unwrap()
        );
        assert_ne!(before, opened_stamp(&second).unwrap());
        #[cfg(unix)]
        assert_eq!(before, stamp(&first.metadata().unwrap()).unwrap());
        fs::rename(path.join("second.jpg"), path.join("first.jpg")).unwrap();
        assert_eq!(
            unchanged(&dir, Path::new("first.jpg"), &first, &before, 8, 8).unwrap_err(),
            "source_item_changed"
        );
        drop(first);
        drop(second);
        drop(dir);
        drop(cleanup);
    }
    #[test]
    fn stage_release_removes_only_owned_files_and_is_retryable() {
        let path = std::env::temp_dir().join(format!("frameleaf-release-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        let cleanup = Partial(Some(path.clone()));
        let path = fs::canonicalize(path).unwrap();
        let id = Uuid::new_v4().to_string();
        let stage = path.join(&id);
        fs::create_dir(&stage).unwrap();
        fs::write(stage.join("original"), b"staged original").unwrap();
        fs::write(stage.join("receipt.json"), b"receipt").unwrap();
        fs::write(stage.join("unexpected"), b"retain").unwrap();
        assert_eq!(
            release_stage(&path, &id).err().as_deref(),
            Some("source_cache_cleanup_pending")
        );
        assert_eq!(fs::read(stage.join("unexpected")).unwrap(), b"retain");
        fs::remove_file(stage.join("unexpected")).unwrap();
        release_stage(&path, &id).unwrap();
        assert!(!stage.exists());
        release_stage(&path, &id).unwrap();
        drop(cleanup);
    }
    #[test]
    fn capacity_accounts_for_original_and_stage_on_shared_volume() {
        const RESERVE: u64 = 256 * 1024 * 1024;
        assert!(check_capacity(100, 100 + RESERVE, 100 + RESERVE, true, true).is_err());
        assert!(check_capacity(100, 200 + RESERVE, 200 + RESERVE, true, true).is_ok());
        assert!(check_capacity(100, 100 + RESERVE, 100 + RESERVE, false, true).is_ok());
        assert!(check_capacity(100, 99 + RESERVE, 100 + RESERVE, false, true).is_err());
        assert!(check_capacity(100, 0, 100 + RESERVE, false, false).is_ok());
        assert!(check_capacity(100, 0, 99 + RESERVE, false, false).is_err());
        assert!(check_capacity(u64::MAX, u64::MAX, u64::MAX, true, true).is_err());
    }
    #[test]
    fn capacity_uses_the_open_directory_volume() {
        let root = Dir::open_ambient_dir(std::env::temp_dir(), ambient_authority()).unwrap();
        assert!(available_bytes(&root).unwrap() > 0);
    }
    #[test]
    fn source_version_change_is_rejected_before_staging_publication() {
        let path = std::env::temp_dir().join(format!("frameleaf-copy-version-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        let cleanup = Partial(Some(path.clone()));
        fs::write(path.join("photo.jpg"), b"original").unwrap();
        let root = Dir::open_ambient_dir(&path, ambient_authority()).unwrap();
        let source = root.open("photo.jpg").unwrap();
        let before = stamp(&source.metadata().unwrap()).unwrap();
        fs::write(path.join("photo.jpg"), b"modified").unwrap();
        assert_eq!(
            unchanged(&root, Path::new("photo.jpg"), &source, &before, 8, 8)
                .err()
                .as_deref(),
            Some("source_item_changed")
        );
        drop(source);
        drop(root);
        drop(cleanup);
    }
}
