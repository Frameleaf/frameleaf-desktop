//! Handle-relative source admission and finite CfApi reads in the owned reader process.
use super::{version_metadata, Copied, Event, Request, CHUNK_BYTES, MAX_ORIGINAL_BYTES};
use cap_std::{
    ambient_authority,
    fs::{Dir, File, OpenOptions, OpenOptionsExt},
};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    mem::size_of,
    os::windows::io::AsRawHandle,
    path::{Component, Path, Prefix},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_HANDLE_EOF, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING,
        ERROR_OPERATION_ABORTED, HANDLE, WAIT_FAILED,
    },
    Storage::{CloudFilters::*, FileSystem::*},
    System::{
        Threading::{CreateEventW, WaitForSingleObject},
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0},
    },
};

fn information<T: Default>(handle: HANDLE, class: FILE_INFO_BY_HANDLE_CLASS) -> Result<T, String> {
    let mut value = T::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            class,
            (&mut value as *mut T).cast(),
            size_of::<T>() as u32,
        )
    } == 0
    {
        return Err("source_identity_unavailable".into());
    }
    Ok(value)
}
fn attributes(handle: HANDLE, hidden: bool, cloud_allowed: bool) -> Result<bool, String> {
    let info: FILE_ATTRIBUTE_TAG_INFO = information(handle, FileAttributeTagInfo)?;
    if hidden && info.FileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0 {
        return Err("source_item_excluded".into());
    }
    let reparse = info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    let state =
        unsafe { CfGetPlaceholderStateFromAttributeTag(info.FileAttributes, info.ReparseTag) };
    if reparse
        && (!cloud_allowed
            || state == CF_PLACEHOLDER_STATE_INVALID
            || state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0)
    {
        return Err("source_item_excluded".into());
    }
    Ok(reparse)
}
fn metadata_options(list: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_READ_ATTRIBUTES | if list { FILE_LIST_DIRECTORY } else { 0 })
        .share_mode(1)
        .custom_flags(
            FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        );
    options
}
pub(super) fn directories(path: &Path, source: bool) -> Result<(Vec<Dir>, bool), String> {
    let mut parts = path.components().peekable();
    let Some(Component::Prefix(prefix)) = parts.next() else {
        return Err("source_item_invalid".into());
    };
    if !matches!(
        prefix.kind(),
        Prefix::Disk(_) | Prefix::VerbatimDisk(_) | Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _)
    ) || !matches!(parts.next(), Some(Component::RootDir))
    {
        return Err("source_item_invalid".into());
    }
    let mut anchor = std::path::PathBuf::from(prefix.as_os_str());
    anchor.push(std::path::MAIN_SEPARATOR_STR);
    let mut held = vec![Dir::open_ambient_dir(anchor, ambient_authority())
        .map_err(|_| "source_item_unavailable")?];
    let mut cloud = false;
    while let Some(part) = parts.next() {
        if !matches!(part, Component::Normal(_)) {
            return Err("source_item_invalid".into());
        }
        let parent = held.last().ok_or("source_item_invalid")?;
        let file = parent
            .open_with(part.as_os_str(), &metadata_options(false))
            .map_err(|_| "source_item_unavailable")?;
        let candidate = Dir::from_std_file(file.into_std());
        if !candidate
            .dir_metadata()
            .map_err(|_| "source_identity_unavailable")?
            .is_dir()
        {
            return Err("source_item_invalid".into());
        }
        cloud |= attributes(
            candidate.as_raw_handle(),
            source && parts.peek().is_none(),
            source,
        )?;
        let expected = super::super::source_root_identity(&candidate)?;
        // Reopen only this pinned directory object, never the ambient pathname.
        let listed = candidate
            .open_with(".", &metadata_options(true))
            .map_err(|_| "source_item_unavailable")?;
        let listed = Dir::from_std_file(listed.into_std());
        if super::super::source_root_identity(&listed)? != expected {
            return Err("source_item_changed".into());
        }
        cloud |= attributes(
            listed.as_raw_handle(),
            source && parts.peek().is_none(),
            source,
        )?;
        held.push(listed);
    }
    Ok((held, cloud))
}
#[derive(PartialEq, Eq)]
pub(super) struct Version {
    pub(super) volume: u64,
    id: [u8; 16],
    pub(super) bytes: u64,
    created: i64,
    modified: i64,
}
impl Version {
    fn read(handle: HANDLE) -> Result<Self, String> {
        let identity = super::super::windows_file_id(handle)?;
        let basic: FILE_BASIC_INFO = information(handle, FileBasicInfo)?;
        let standard: FILE_STANDARD_INFO = information(handle, FileStandardInfo)?;
        if standard.Directory
            || standard.DeletePending
            || standard.EndOfFile <= 0
            || basic.CreationTime < 0
            || basic.LastWriteTime < 0
        {
            return Err("source_item_invalid".into());
        }
        Ok(Self {
            volume: identity.VolumeSerialNumber,
            id: identity.FileId.Identifier,
            bytes: standard.EndOfFile as u64,
            created: basic.CreationTime,
            modified: basic.LastWriteTime,
        })
    }
    pub(super) fn stamp(&self) -> String {
        let id: String = self.id.iter().map(|byte| format!("{byte:02x}")).collect();
        format!(
            "cloud-file-v1:{}:{id}:{}:{}:{}",
            self.volume, self.bytes, self.created, self.modified
        )
    }
}
pub(super) struct Source {
    held: Vec<Dir>,
    root: usize,
    _leaf: Option<File>,
    leaf_cloud: bool,
    pub(super) version: Version,
    pub(super) cloud: bool,
}
impl Source {
    pub(super) fn open(
        root: &str,
        identity: &str,
        relative: &str,
        bytes: Option<u64>,
    ) -> Result<Self, String> {
        let (mut held, mut cloud) = directories(Path::new(root), true)?;
        let root = held.len() - 1;
        super::super::check_source_root(
            identity,
            &super::super::source_root_identity(&held[root])?,
        )?;
        let normalized = relative.replace('\\', "/");
        let path = super::super::relative_path(&normalized)?;
        let parts: Vec<_> = path.components().collect();
        let (leaf, parents) = parts.split_last().ok_or("source_item_invalid")?;
        for part in parents {
            let current = held.last().ok_or("source_item_invalid")?;
            let file = current
                .open_with(part.as_os_str(), &metadata_options(false))
                .map_err(|_| "source_item_unavailable")?;
            let candidate = Dir::from_std_file(file.into_std());
            if !candidate
                .dir_metadata()
                .map_err(|_| "source_identity_unavailable")?
                .is_dir()
            {
                return Err("source_item_invalid".into());
            }
            cloud |= attributes(candidate.as_raw_handle(), true, true)?;
            let identity = super::super::source_root_identity(&candidate)?;
            let listed = candidate
                .open_with(".", &metadata_options(true))
                .map_err(|_| "source_item_unavailable")?;
            let listed = Dir::from_std_file(listed.into_std());
            if super::super::source_root_identity(&listed)? != identity {
                return Err("source_item_changed".into());
            }
            cloud |= attributes(listed.as_raw_handle(), true, true)?;
            held.push(listed);
        }
        let leaf = held
            .last()
            .ok_or("source_item_invalid")?
            .open_with(leaf.as_os_str(), &metadata_options(false))
            .map_err(|_| "source_item_unavailable")?;
        if !leaf
            .metadata()
            .map_err(|_| "source_identity_unavailable")?
            .is_file()
        {
            return Err("source_item_invalid".into());
        }
        let leaf_cloud = attributes(leaf.as_raw_handle(), true, true)?;
        cloud |= leaf_cloud;
        let version = Version::read(leaf.as_raw_handle())?;
        let root_info = super::super::windows_file_id(held[root].as_raw_handle())?;
        if bytes.is_some_and(|bytes| version.bytes != bytes)
            || version.volume != root_info.VolumeSerialNumber
        {
            return Err("source_item_changed".into());
        }
        if version.bytes > MAX_ORIGINAL_BYTES {
            return Err("source_copy_budget_exceeded".into());
        }
        Ok(Self {
            held,
            root,
            _leaf: Some(leaf),
            leaf_cloud,
            version,
            cloud,
        })
    }
    fn protected_path(&self) -> Result<Vec<u16>, String> {
        let leaf = self._leaf.as_ref().ok_or("source_identity_unavailable")?;
        let mut name = vec![0u16; 32_768];
        // A placeholder can become resident between the parent and reader's metadata observations.
        let count = unsafe {
            GetFinalPathNameByHandleW(
                leaf.as_raw_handle(),
                name.as_mut_ptr(),
                name.len() as u32,
                VOLUME_NAME_DOS,
            )
        } as usize;
        if count == 0 || count >= name.len() {
            return Err("source_identity_unavailable".into());
        }
        name.truncate(count + 1);
        name[count] = 0;
        Ok(name)
    }
    pub(super) fn release_leaf(&mut self) {
        drop(self._leaf.take());
    }
    pub(super) fn root(&self) -> &Dir {
        &self.held[self.root]
    }
    pub(super) fn overlaps(&self, staging: &[Dir]) -> Result<bool, String> {
        let stage = staging.last().ok_or("source_stage_unavailable")?;
        let source_id = super::super::source_root_identity(self.root())?;
        let stage_id = super::super::source_root_identity(stage)?;
        for dir in &self.held[..=self.root] {
            if super::super::source_root_identity(dir)? == stage_id {
                return Ok(true);
            }
        }
        for dir in staging {
            if super::super::source_root_identity(dir)? == source_id {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
struct Protected(HANDLE);
impl Protected {
    fn open(path: &[u16]) -> Result<Self, String> {
        if !super::valid_cloud_path(path) {
            return Err("source_identity_unavailable".into());
        }
        let mut handle = std::ptr::null_mut();
        let result = unsafe {
            CfOpenFileWithOplock(path.as_ptr(), CF_OPEN_FILE_FLAG_EXCLUSIVE, &mut handle)
        };
        if result < 0 || handle.is_null() {
            return Err(format!("source_cloud_open_failed:{result:08x}"));
        }
        Ok(Self(handle))
    }
    fn reference(&self, phase: &'static str) -> Result<Reference<'_>, String> {
        if !unsafe { CfReferenceProtectedHandle(self.0) } {
            return Err(format!("source_item_changed:oplock-{phase}"));
        }
        let reference = Reference {
            owner: self,
            raw: unsafe { CfGetWin32HandleFromProtectedHandle(self.0) },
        };
        if reference.raw.is_null() {
            return Err("source_item_changed:borrowed-handle".into());
        }
        Ok(reference)
    }
}
impl Drop for Protected {
    fn drop(&mut self) {
        unsafe { CfCloseHandle(self.0) };
    }
}
struct Reference<'a> {
    owner: &'a Protected,
    raw: HANDLE,
}
impl Drop for Reference<'_> {
    fn drop(&mut self) {
        unsafe { CfReleaseProtectedHandle(self.owner.0) };
    }
}
struct Operation {
    event: HANDLE,
    overlapped: Box<OVERLAPPED>,
}
impl Operation {
    fn new(offset: u64) -> Result<Self, String> {
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err("source_copy_interrupted".into());
        }
        let mut overlapped = Box::<OVERLAPPED>::default();
        overlapped.hEvent = event;
        overlapped.Anonymous = OVERLAPPED_0 {
            Anonymous: OVERLAPPED_0_0 {
                Offset: offset as u32,
                OffsetHigh: (offset >> 32) as u32,
            },
        };
        Ok(Self { event, overlapped })
    }
    fn wait(&mut self, handle: HANDLE, stalled: &mut dyn FnMut()) -> Result<u32, String> {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut aborting = false;
        loop {
            let mut bytes = 0;
            if unsafe { GetOverlappedResult(handle, &*self.overlapped, &mut bytes, 0) } != 0 {
                return if aborting {
                    Err("source_copy_interrupted".into())
                } else {
                    Ok(bytes)
                };
            }
            match unsafe { GetLastError() } {
                ERROR_OPERATION_ABORTED => return Err("source_copy_interrupted".into()),
                ERROR_HANDLE_EOF => return Err("source_item_changed:unexpected-eof".into()),
                ERROR_IO_INCOMPLETE => {}
                // This isolated process exits without freeing memory still possibly owned by the kernel.
                _ => std::process::exit(2),
            }
            let failed = unsafe { WaitForSingleObject(self.event, 100) } == WAIT_FAILED;
            if !aborting && (failed || Instant::now() >= deadline) {
                unsafe { CancelIoEx(handle, &*self.overlapped) };
                aborting = true;
                stalled();
            }
            if failed {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.event) };
    }
}

pub(super) fn copy(
    request: &Request,
    emit: &mut dyn FnMut(Event) -> Result<(), String>,
) -> Result<Copied, String> {
    request.validate()?;
    let mut source = Source::open(
        &request.root,
        &request.root_identity,
        &request.relative,
        Some(request.bytes),
    )
    .map_err(|code| {
        if code == "source_item_changed" {
            "source_item_changed:admission".into()
        } else {
            code
        }
    })?;
    if source.version.stamp() != request.source_stamp {
        return Err("source_item_changed:parent-version".into());
    }
    let (staging, _) = directories(Path::new(&request.staging), false)?;
    if source.overlaps(&staging)? {
        return Err("source_staging_overlap".into());
    }
    crate::runtime_store::private_directory(Path::new(&request.staging))?;
    let stage = staging.last().ok_or("source_stage_unavailable")?;
    let stage_info = super::super::windows_file_id(stage.as_raw_handle())?;
    super::super::check_capacity(
        request.bytes,
        super::super::available_bytes(source.root())?,
        super::super::available_bytes(stage)?,
        source.version.volume == stage_info.VolumeSerialNumber,
        true,
    )?;
    if source.leaf_cloud {
        source.release_leaf();
        let mut offset = 0;
        while offset < request.bytes {
            let length = (request.bytes - offset).min(CHUNK_BYTES) as usize;
            let mut current = Source::open(
                &request.root,
                &request.root_identity,
                &request.relative,
                Some(request.bytes),
            )?;
            if current.version != source.version {
                return Err("source_item_changed:before-read".into());
            }
            let file = Protected::open(&current.protected_path()?)?;
            let reference = file.reference("hydrate")?;
            if Version::read(reference.raw)? != source.version {
                return Err("source_item_changed:before-read".into());
            }
            current.release_leaf();
            let mut hydrate = Operation::new(offset)?;
            let result = unsafe {
                CfHydratePlaceholder(
                    reference.raw,
                    offset as i64,
                    length as i64,
                    CF_HYDRATE_FLAG_NONE,
                    &mut *hydrate.overlapped,
                )
            };
            if result == (0x80070000u32 | ERROR_IO_PENDING) as i32 {
                hydrate.wait(reference.raw, &mut || {
                    if emit(Event::Error {
                        operation_id: request.operation_id.clone(),
                        code: "source_cloud_provider_unavailable".into(),
                    })
                    .is_err()
                    {
                        std::process::exit(2);
                    }
                })?;
            } else if result < 0 {
                return Err(format!("source_cloud_hydration_failed:{result:08x}"));
            }
            if Version::read(reference.raw)? != source.version {
                return Err("source_item_changed:after-read".into());
            }
            offset += length as u64;
        }
        let hydrated = Source::open(
            &request.root,
            &request.root_identity,
            &request.relative,
            Some(request.bytes),
        )?;
        if hydrated.version != source.version {
            return Err("source_item_changed:before-read".into());
        }
        source = hydrated;
    }
    // Copy only after hydration, under one oplock that no between-chunk writer can bypass.
    let file = Protected::open(&source.protected_path()?)?;
    if Version::read(file.reference("open")?.raw)? != source.version {
        return Err("source_item_changed:protected-open".into());
    }
    source.release_leaf();
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .share_mode(1)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut output = stage
        .open_with("original", &options)
        .map_err(|_| "source_stage_write_failed")?;
    let mut data = vec![0u8; CHUNK_BYTES as usize];
    let mut copied = 0;
    let mut hash = Sha256::new();
    while copied < request.bytes {
        let length = (request.bytes - copied).min(CHUNK_BYTES) as usize;
        let reference = file.reference(if copied == 0 {
            "first-read"
        } else {
            "next-read"
        })?;
        if Version::read(reference.raw)? != source.version {
            return Err("source_item_changed:before-read".into());
        }
        let mut read = Operation::new(copied)?;
        let started = unsafe {
            ReadFile(
                reference.raw,
                data.as_mut_ptr(),
                length as u32,
                std::ptr::null_mut(),
                &mut *read.overlapped,
            )
        };
        if started == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err("source_copy_interrupted".into());
        }
        let bytes = read.wait(reference.raw, &mut || {
            if emit(Event::Error {
                operation_id: request.operation_id.clone(),
                code: "source_cloud_provider_unavailable".into(),
            })
            .is_err()
            {
                std::process::exit(2);
            }
        })? as usize;
        if bytes != length {
            return Err("source_item_changed:read-length".into());
        }
        if Version::read(reference.raw)? != source.version {
            return Err("source_item_changed:after-read".into());
        }
        output
            .write_all(&data[..bytes])
            .map_err(|_| "source_stage_write_failed")?;
        hash.update(&data[..bytes]);
        copied += bytes as u64;
        emit(Event::Progress {
            operation_id: request.operation_id.clone(),
            bytes: copied,
        })?;
        // Finish this bounded chunk before acknowledging an oplock break, including the final version check.
        if copied == request.bytes && Version::read(reference.raw)? != source.version {
            return Err("source_item_changed:completion".into());
        }
        drop(reference);
    }
    output.sync_all().map_err(|_| "source_stage_write_failed")?;
    let stamp = source.version.stamp();
    let (created, modified) =
        version_metadata(&stamp, copied).ok_or("source_identity_unavailable")?;
    Ok(Copied {
        bytes: copied,
        sha256: format!("{:x}", hash.finalize()),
        source_stamp: stamp,
        created_at_ms: created,
        modified_at_ms: modified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_reader_keeps_a_terminated_handle_path_when_the_file_is_resident() {
        let base = std::env::temp_dir().join(format!(
            "frameleaf-resident-reader-{}",
            uuid::Uuid::new_v4()
        ));
        crate::windows_protection::new_private_directory(&base).unwrap();
        let root = base.join("source");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("旅行-original.jpg"), b"verified resident bytes").unwrap();
        let operation_id = uuid::Uuid::new_v4().to_string();
        let staging = base.join(&operation_id);
        crate::windows_protection::new_private_directory(&staging).unwrap();
        let request = {
            let directory = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
            let root_identity = super::super::super::source_root_identity(&directory).unwrap();
            let source = Source::open(
                root.to_str().unwrap(),
                &root_identity,
                "旅行-original.jpg",
                None,
            )
            .unwrap();
            assert!(!source.cloud && !source.leaf_cloud);
            assert!(super::super::valid_cloud_path(
                &source.protected_path().unwrap()
            ));
            Request {
                version: 1,
                operation_id,
                root: root.to_str().unwrap().into(),
                root_identity,
                source_stamp: source.version.stamp(),
                relative: "旅行-original.jpg".into(),
                staging: staging.to_str().unwrap().into(),
                bytes: source.version.bytes,
            }
        };
        let copied = copy(&request, &mut |_| Ok(())).unwrap();
        let original = std::fs::read(root.join("旅行-original.jpg")).unwrap();
        assert_eq!(std::fs::read(staging.join("original")).unwrap(), original);
        assert_eq!(copied.sha256, format!("{:x}", Sha256::digest(&original)));
        assert_eq!(copied.bytes, original.len() as u64);
        assert_eq!(copied.source_stamp, request.source_stamp);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn timestamp_preserving_writer_between_chunks_cannot_publish_a_mixed_copy() {
        let base = std::env::temp_dir().join(format!(
            "frameleaf-reader-mutation-{}",
            uuid::Uuid::new_v4()
        ));
        crate::windows_protection::new_private_directory(&base).unwrap();
        let root = base.join("source");
        std::fs::create_dir(&root).unwrap();
        let path = root.join("original.bin");
        std::fs::write(&path, vec![0x5a; CHUNK_BYTES as usize * 3 + 17]).unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        let directory = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
        let root_identity = super::super::super::source_root_identity(&directory).unwrap();
        let operation_id = uuid::Uuid::new_v4().to_string();
        let staging = base.join(&operation_id);
        crate::windows_protection::new_private_directory(&staging).unwrap();
        let request = {
            let source =
                Source::open(root.to_str().unwrap(), &root_identity, "original.bin", None).unwrap();
            Request {
                version: 1,
                operation_id,
                root: root.to_str().unwrap().into(),
                root_identity,
                source_stamp: source.version.stamp(),
                relative: "original.bin".into(),
                staging: staging.to_str().unwrap().into(),
                bytes: source.version.bytes,
            }
        };
        let mut writer = None;
        let result = copy(&request, &mut |event| {
            if matches!(event, Event::Progress { bytes, .. } if bytes == CHUNK_BYTES) {
                let path = path.clone();
                let (started, ready) = std::sync::mpsc::sync_channel(0);
                writer = Some(std::thread::spawn(move || {
                    started.send(()).unwrap();
                    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
                    file.write_all(&[0x59])?;
                    file.set_modified(modified)?;
                    file.sync_all()
                }));
                ready.recv_timeout(Duration::from_secs(5)).unwrap();
                // Give the competing open time to queue its break while this chunk still owns a reference.
                std::thread::sleep(Duration::from_millis(100));
                assert!(!writer.as_ref().unwrap().is_finished());
            }
            Ok(())
        });
        let writer = writer.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !writer.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !writer.is_finished() {
            std::process::exit(2);
        }
        writer.join().unwrap().unwrap();
        assert!(result
            .err()
            .is_some_and(|code| code.starts_with("source_item_changed:")));
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            modified
        );
        assert_eq!(
            Source::open(
                &request.root,
                &request.root_identity,
                &request.relative,
                Some(request.bytes)
            )
            .unwrap()
            .version
            .stamp(),
            request.source_stamp
        );
        drop(directory);
        std::fs::remove_dir_all(base).unwrap();
    }
}
