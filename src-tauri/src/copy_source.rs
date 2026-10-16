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
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CopyApproval {
    scope: CopyScope,
    signature: String,
}
#[derive(Serialize, Deserialize)]
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
fn root_identity(dir: &Dir) -> Result<String, String> {
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
fn available_bytes(path: &Path) -> Result<u64, String> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "source_capacity_unavailable")?;
        let mut info = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
        if unsafe { libc::statvfs(path.as_ptr(), info.as_mut_ptr()) } != 0 {
            return Err("source_capacity_unavailable".into());
        }
        let info = unsafe { info.assume_init() };
        u64::try_from(u128::from(info.f_bavail) * u128::from(info.f_frsize))
            .map_err(|_| "source_capacity_unavailable".into())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let path: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
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
        if saved.server_id.is_empty()
            || saved.account_id.is_empty()
            || saved.device_id.as_deref().is_none_or(str::is_empty)
            || max_item_bytes == 0
            || max_item_bytes > 2 * 1024 * 1024 * 1024
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
        if scope.version != 1
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
        let (dir, name) = parent_dir(&dir, relative_path)?;
        let relative_path = name.as_path();
        let before = dir
            .symlink_metadata(relative_path)
            .map_err(|_| "source_item_unavailable")?;
        if !before.is_file() || link(&before) || before.len() == 0 {
            return Err("source_item_invalid".into());
        }
        if before.len() > self.scope.max_item_bytes {
            return Err("source_copy_budget_exceeded".into());
        }
        if available_bytes(destination)? < before.len().saturating_add(256 * 1024 * 1024) {
            return Err("source_capacity_insufficient".into());
        }
        let options = no_follow_options(false);
        let mut source = dir
            .open_with(relative_path, &options)
            .map_err(|_| "source_item_unavailable")?;
        let source_stamp = stamp(&before)?;
        let opened = source.metadata().map_err(|_| "source_item_unavailable")?;
        if !opened.is_file() || link(&opened) || stamp(&opened)? != source_stamp {
            return Err("source_item_changed".into());
        }
        let id = Uuid::new_v4().to_string();
        let path = destination.join(&id);
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .map_err(|_| "source_stage_unavailable")?;
        let mut cleanup = Partial(Some(path.clone()));
        crate::runtime_store::private_directory(&path)?;
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
        loop {
            cancel(cancelled)?;
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
fn parent_dir(root: &Dir, relative: &Path) -> Result<(Dir, std::path::PathBuf), String> {
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
fn staged_file(dir: &Dir, relative: &Path) -> Result<cap_std::fs::File, String> {
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

fn unchanged(
    dir: &Dir,
    relative: &Path,
    source: &cap_std::fs::File,
    before: &str,
    expected: u64,
    copied: u64,
) -> Result<(), String> {
    if copied != expected
        || stamp(&source.metadata().map_err(|_| "source_item_changed")?)? != before
        || stamp(
            &dir.symlink_metadata(relative)
                .map_err(|_| "source_item_changed")?,
        )? != before
    {
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

#[cfg(test)]
mod tests {
    use super::*;
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
