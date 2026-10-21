//! Real CfApi qualification confined to a disposable hosted Windows runner.
use super::*;
use std::{
    mem::{offset_of, size_of},
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, AtomicI32, AtomicU64},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_NOT_FOUND,
        ERROR_OPERATION_ABORTED,
    },
    Storage::{
        CloudFilters::*,
        FileSystem::{
            GetFinalPathNameByHandleW, FILE_ATTRIBUTE_NORMAL, FILE_BASIC_INFO,
            FILE_FLAG_OPEN_NO_RECALL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            VOLUME_NAME_DOS, VOLUME_NAME_GUID,
        },
    },
    System::{
        Threading::{CreateEventW, WaitForSingleObject},
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};

static DATA: [u8; 65_553] = [0x5a; 65_553];
const FILE_IDENTITY: [u8; 4] = *b"FL01";
const FILE_NAME: &str = "旅行-original.jpg";

fn wide(value: &Path) -> Vec<u16> {
    value.as_os_str().encode_wide().chain(Some(0)).collect()
}
fn success(code: i32) -> Result<(), String> {
    if code >= 0 {
        Ok(())
    } else {
        Err(format!("CfApi HRESULT {code:#010x}"))
    }
}
fn require_disposable_runner() {
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_eq!(
        std::env::var("RUNNER_ENVIRONMENT").as_deref(),
        Ok("github-hosted")
    );
}
#[derive(Default)]
struct Context {
    hold: AtomicBool,
    fail: AtomicBool,
    cancellations: AtomicU64,
    fetches: AtomicU64,
    delivered: AtomicU64,
    failure: AtomicI32,
}
unsafe extern "system" fn fetch(
    info: *const CF_CALLBACK_INFO,
    parameters: *const CF_CALLBACK_PARAMETERS,
) {
    if info.is_null() || parameters.is_null() {
        return;
    }
    let info = unsafe { &*info };
    if info.CallbackContext.is_null() {
        return;
    }
    let context = unsafe { &*(info.CallbackContext.cast::<Context>()) };
    context.fetches.fetch_add(1, Ordering::AcqRel);
    if context.hold.load(Ordering::Acquire) {
        return;
    }
    let request = unsafe { (*parameters).Anonymous.FetchData };
    let offset = usize::try_from(request.RequiredFileOffset).ok();
    let length = usize::try_from(request.RequiredLength).ok();
    let bytes = offset.zip(length).and_then(|(start, count)| {
        start
            .checked_add(count)
            .and_then(|end| DATA.get(start..end))
    });
    let identity_matches = info.FileIdentityLength == FILE_IDENTITY.len() as u32
        && !info.FileIdentity.is_null()
        && unsafe {
            std::slice::from_raw_parts(info.FileIdentity.cast::<u8>(), FILE_IDENTITY.len())
        } == FILE_IDENTITY;
    let valid = identity_matches
        && bytes.is_some_and(|data| !data.is_empty())
        && !context.fail.load(Ordering::Acquire);
    let operation = CF_OPERATION_INFO {
        StructSize: size_of::<CF_OPERATION_INFO>() as u32,
        Type: CF_OPERATION_TYPE_TRANSFER_DATA,
        ConnectionKey: info.ConnectionKey,
        TransferKey: info.TransferKey,
        RequestKey: info.RequestKey,
        ..Default::default()
    };
    let mut parameters = CF_OPERATION_PARAMETERS {
        ParamSize: (offset_of!(CF_OPERATION_PARAMETERS, Anonymous)
            + size_of::<CF_OPERATION_PARAMETERS_0_0>()) as u32,
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            TransferData: CF_OPERATION_PARAMETERS_0_0 {
                Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                CompletionStatus: if valid { 0 } else { 0xc000000du32 as i32 },
                Buffer: if valid {
                    bytes.unwrap().as_ptr().cast()
                } else {
                    std::ptr::null()
                },
                Offset: request.RequiredFileOffset,
                Length: request.RequiredLength,
            },
        },
    };
    let result = unsafe { CfExecute(&operation, &mut parameters) };
    if result < 0 || !valid {
        context
            .failure
            .store(if result < 0 { result } else { -1 }, Ordering::Release);
    } else {
        context
            .delivered
            .fetch_add(request.RequiredLength as u64, Ordering::AcqRel);
    }
}
unsafe extern "system" fn cancel_fetch(
    info: *const CF_CALLBACK_INFO,
    _: *const CF_CALLBACK_PARAMETERS,
) {
    if info.is_null() {
        return;
    }
    let info = unsafe { &*info };
    if !info.CallbackContext.is_null() {
        let context = unsafe { &*(info.CallbackContext.cast::<Context>()) };
        context.cancellations.fetch_add(1, Ordering::AcqRel);
    }
}
struct Provider {
    root: Vec<u16>,
    context: Option<Box<Context>>,
    connection: Option<CF_CONNECTION_KEY>,
    registered: bool,
}
impl Provider {
    fn create(root: &Path) -> Result<Self, String> {
        require_disposable_runner();
        crate::windows_protection::new_private_directory(root)?;
        let mut provider = Self {
            root: wide(root),
            context: Some(Box::default()),
            connection: None,
            registered: false,
        };
        let name: Vec<u16> = "Frameleaf disposable CfApi test"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let version: Vec<u16> = "1".encode_utf16().chain(Some(0)).collect();
        let registration = CF_SYNC_REGISTRATION {
            StructSize: size_of::<CF_SYNC_REGISTRATION>() as u32,
            ProviderName: name.as_ptr(),
            ProviderVersion: version.as_ptr(),
            ..Default::default()
        };
        let policies = CF_SYNC_POLICIES {
            StructSize: size_of::<CF_SYNC_POLICIES>() as u32,
            Hydration: CF_HYDRATION_POLICY {
                Primary: CF_HYDRATION_POLICY_PARTIAL,
                Modifier: CF_HYDRATION_POLICY_MODIFIER_NONE,
            },
            Population: CF_POPULATION_POLICY {
                Primary: CF_POPULATION_POLICY_FULL,
                Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
            },
            ..Default::default()
        };
        success(unsafe {
            CfRegisterSyncRoot(
                provider.root.as_ptr(),
                &registration,
                &policies,
                CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT,
            )
        })?;
        provider.registered = true;
        let callbacks = [
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_FETCH_DATA,
                Callback: Some(fetch),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
                Callback: Some(cancel_fetch),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NONE,
                Callback: None,
            },
        ];
        let mut connection = CF_CONNECTION_KEY::default();
        success(unsafe {
            CfConnectSyncRoot(
                provider.root.as_ptr(),
                callbacks.as_ptr(),
                (&**provider.context.as_ref().unwrap() as *const Context).cast(),
                CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION,
                &mut connection,
            )
        })?;
        provider.connection = Some(connection);
        let filename = wide(Path::new(FILE_NAME));
        let mut placeholder = CF_PLACEHOLDER_CREATE_INFO {
            RelativeFileName: filename.as_ptr(),
            FsMetadata: CF_FS_METADATA {
                BasicInfo: FILE_BASIC_INFO {
                    FileAttributes: FILE_ATTRIBUTE_NORMAL,
                    ..Default::default()
                },
                FileSize: DATA.len() as i64,
            },
            FileIdentity: FILE_IDENTITY.as_ptr().cast(),
            FileIdentityLength: FILE_IDENTITY.len() as u32,
            Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
            ..Default::default()
        };
        let mut processed = 0;
        success(unsafe {
            CfCreatePlaceholders(
                provider.root.as_ptr(),
                &mut placeholder,
                1,
                CF_CREATE_FLAG_NONE,
                &mut processed,
            )
        })?;
        success(placeholder.Result)?;
        if processed != 1 {
            return Err("placeholder was not created".into());
        }
        Ok(provider)
    }
    fn close(&mut self) -> Result<(), String> {
        if let Some(connection) = self.connection {
            success(unsafe { CfDisconnectSyncRoot(connection) })?;
            self.connection = None;
        }
        if self.registered {
            success(unsafe { CfUnregisterSyncRoot(self.root.as_ptr()) })?;
            self.registered = false;
        }
        Ok(())
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        if self.close().is_err() && self.connection.is_some() {
            // Keep callback state alive until this isolated test process exits if disconnect failed.
            if let Some(context) = self.context.take() {
                let _ = Box::leak(context);
            }
        }
    }
}
fn hydrate_explicit_range(path: &Path) -> Result<(), String> {
    let path = wide(path);
    let mut protected = std::ptr::null_mut();
    success(unsafe {
        CfOpenFileWithOplock(path.as_ptr(), CF_OPEN_FILE_FLAG_EXCLUSIVE, &mut protected)
    })?;
    if protected.is_null() {
        return Err("missing protected handle".into());
    }
    if !unsafe { CfReferenceProtectedHandle(protected) } {
        unsafe { CfCloseHandle(protected) };
        return Err("protected handle reference failed".into());
    }
    let borrowed = unsafe { CfGetWin32HandleFromProtectedHandle(protected) };
    let result = unsafe {
        CfHydratePlaceholder(
            borrowed,
            0,
            DATA.len() as i64,
            CF_HYDRATE_FLAG_NONE,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        CfReleaseProtectedHandle(protected);
        CfCloseHandle(protected);
    }
    success(result)
}

fn qualify_path_spellings(dir: &Dir, path: &Path) {
    use cap_std::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(1)
        .custom_flags(FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_OPEN_REPARSE_POINT);
    let metadata = dir.open_with(FILE_NAME, &options).unwrap();
    let expected = windows_file_id(metadata.as_raw_handle()).unwrap();
    let mut paths = vec![("ordinary", wide(path))];
    for (label, flags) in [
        ("extended-dos", VOLUME_NAME_DOS),
        ("volume-guid", VOLUME_NAME_GUID),
    ] {
        let mut name = vec![0u16; 32_768];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                metadata.as_raw_handle(),
                name.as_mut_ptr(),
                name.len() as u32,
                flags,
            )
        } as usize;
        assert!(length > 0 && length < name.len());
        name.truncate(length + 1);
        name[length] = 0;
        if flags == VOLUME_NAME_DOS {
            assert!(name.starts_with(&[92, 92, 63, 92]));
            paths.push(("handle-dos-without-prefix", name[4..].to_vec()));
        }
        paths.push((label, name));
    }
    for (label, path) in paths {
        let mut protected = std::ptr::null_mut();
        let result = unsafe {
            CfOpenFileWithOplock(path.as_ptr(), CF_OPEN_FILE_FLAG_EXCLUSIVE, &mut protected)
        };
        println!("CfApi path spelling {label}: hresult={result:08x}");
        if result >= 0 {
            assert!(!protected.is_null());
            assert!(unsafe { CfReferenceProtectedHandle(protected) });
            let actual =
                windows_file_id(unsafe { CfGetWin32HandleFromProtectedHandle(protected) }).unwrap();
            unsafe {
                CfReleaseProtectedHandle(protected);
                CfCloseHandle(protected);
            }
            assert_eq!(actual.VolumeSerialNumber, expected.VolumeSerialNumber);
            assert_eq!(actual.FileId.Identifier, expected.FileId.Identifier);
        } else {
            assert!(protected.is_null());
            assert_ne!(label, "ordinary", "the known-working path must open");
        }
    }
}

fn cancel_pending_hydration(path: &Path, context: &Context) -> Result<(), String> {
    let path = wide(path);
    let mut protected = std::ptr::null_mut();
    success(unsafe {
        CfOpenFileWithOplock(path.as_ptr(), CF_OPEN_FILE_FLAG_EXCLUSIVE, &mut protected)
    })?;
    if protected.is_null() {
        return Err("missing protected handle".into());
    }
    let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        unsafe {
            CfCloseHandle(protected);
        }
        return Err("could not create the hydration event".into());
    }
    if !unsafe { CfReferenceProtectedHandle(protected) } {
        unsafe {
            CloseHandle(event);
            CfCloseHandle(protected);
        }
        return Err("protected handle reference failed".into());
    }
    let borrowed = unsafe { CfGetWin32HandleFromProtectedHandle(protected) };
    let mut overlapped = OVERLAPPED {
        hEvent: event,
        ..Default::default()
    };
    let started = unsafe {
        CfHydratePlaceholder(
            borrowed,
            0,
            DATA.len() as i64,
            CF_HYDRATE_FLAG_NONE,
            &mut overlapped,
        )
    };
    let pending = (0x80070000u32 | ERROR_IO_PENDING) as i32;
    if started != pending {
        unsafe {
            CfReleaseProtectedHandle(protected);
            CfCloseHandle(protected);
            CloseHandle(event);
        }
        return Err(format!("expected pending hydration, got {started:#010x}"));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while context.fetches.load(Ordering::Acquire) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let fetched = context.fetches.load(Ordering::Acquire) > 0;
    let cancelled = unsafe { CancelIoEx(borrowed, &overlapped) } != 0;
    let cancel_error = if cancelled {
        0
    } else {
        unsafe { GetLastError() }
    };
    let mut transferred = 0;
    let aborted = loop {
        if unsafe { GetOverlappedResult(borrowed, &overlapped, &mut transferred, 0) } != 0 {
            break false;
        }
        match unsafe { GetLastError() } {
            ERROR_OPERATION_ABORTED => break true,
            ERROR_IO_INCOMPLETE => unsafe {
                WaitForSingleObject(event, 100);
            },
            _ => {
                // Do not unwind while the kernel might still own OVERLAPPED; the parent joins this process.
                std::process::exit(2);
            }
        }
    };
    // Cancellation is only a request; borrowed handle, event and OVERLAPPED live through terminal readback.
    unsafe {
        CfReleaseProtectedHandle(protected);
        CfCloseHandle(protected);
        CloseHandle(event);
    }
    if !fetched || !aborted || (!cancelled && cancel_error != ERROR_NOT_FOUND) {
        return Err("pending provider hydration did not confirm cancellation".into());
    }
    // Provider callbacks are asynchronous; observe cancellation before disconnecting the provider.
    let deadline = Instant::now() + Duration::from_secs(5);
    while context.cancellations.load(Ordering::Acquire) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if context.cancellations.load(Ordering::Acquire) == 0 {
        return Err("provider cancellation notification timed out".into());
    }
    Ok(())
}

#[cfg(feature = "windows-cloud-copy")]
fn foreground_writer_breaks_idle_protected_handle(path: &Path) {
    let mut protected = std::ptr::null_mut();
    success(unsafe {
        CfOpenFileWithOplock(
            wide(path).as_ptr(),
            CF_OPEN_FILE_FLAG_EXCLUSIVE,
            &mut protected,
        )
    })
    .unwrap();
    assert!(!protected.is_null());
    let path = path.to_owned();
    let writer = std::thread::spawn(move || {
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        file.write_all(&[0x59])?;
        file.sync_all()
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !writer.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !writer.is_finished() {
        // The isolated parent owns fixture cleanup; never leave a blocked writer in this process.
        std::process::exit(2);
    }
    let result = writer.join();
    let still_valid = unsafe { CfReferenceProtectedHandle(protected) };
    if still_valid {
        unsafe { CfReleaseProtectedHandle(protected) };
    }
    unsafe { CfCloseHandle(protected) };
    result.unwrap().unwrap();
    assert!(
        !still_valid,
        "foreground writer did not invalidate the old protected handle"
    );
}

#[cfg(feature = "windows-cloud-copy")]
fn qualify_staged_copy(base: &Path) {
    let saved = SavedConnection {
        server: "https://nas.test/".into(),
        server_id: "nas".into(),
        account_id: "owner".into(),
        name: "Synthetic".into(),
        token: "synthetic-session".into(),
        device_name: "Synthetic".into(),
        mode: "client-worker".into(),
        device_id: Some("device".into()),
    };
    let identity = DeviceIdentity::generate();
    let staging = base.join("staging");
    crate::windows_protection::new_private_directory(&staging).unwrap();
    let root = base.join("copy-source");
    let mut provider = Provider::create(&root).unwrap();
    let context = provider.context.as_ref().unwrap();
    let approval =
        CopyApproval::approve(&saved, &identity, &root, DATA.len() as u64, true).unwrap();
    assert_eq!(
        context.fetches.load(Ordering::Acquire),
        0,
        "approval recalled an original"
    );
    let stopped = AtomicBool::new(false);
    let replacement = base.join("replacement-root");
    fs::create_dir(&replacement).unwrap();
    fs::write(replacement.join(FILE_NAME), DATA).unwrap();
    let replaced_approval =
        CopyApproval::approve(&saved, &identity, &replacement, DATA.len() as u64, true).unwrap();
    fs::rename(&replacement, base.join("retained-old-root")).unwrap();
    fs::create_dir(&replacement).unwrap();
    fs::write(replacement.join(FILE_NAME), DATA).unwrap();
    let rejected_id = Uuid::new_v4().to_string();
    assert_eq!(
        replaced_approval
            .stage_to(
                &saved,
                &identity,
                FILE_NAME,
                &staging,
                &rejected_id,
                Some(DATA.len() as u64),
                &stopped,
                &|| Ok(())
            )
            .err()
            .as_deref(),
        Some("source_root_changed")
    );
    assert!(!staging.join(&rejected_id).exists());
    let alias = root.join("outside-link.jpg");
    std::os::windows::fs::symlink_file(replacement.join(FILE_NAME), &alias).unwrap();
    assert!(matches!(
        approval
            .stage_to(
                &saved,
                &identity,
                "outside-link.jpg",
                &staging,
                &rejected_id,
                Some(DATA.len() as u64),
                &stopped,
                &|| Ok(())
            )
            .err()
            .as_deref(),
        Some("source_item_excluded" | "source_item_invalid")
    ));
    fs::remove_file(alias).unwrap();
    assert_eq!(context.fetches.load(Ordering::Acquire), 0);
    assert!(!staging.join(&rejected_id).exists());
    let id = Uuid::new_v4().to_string();
    assert_eq!(
        approval
            .stage_to(
                &saved,
                &identity,
                FILE_NAME,
                &staging,
                &id,
                Some(DATA.len() as u64),
                &stopped,
                &|| Err("metered_network".into())
            )
            .err()
            .as_deref(),
        Some("metered_network")
    );
    assert_eq!(context.fetches.load(Ordering::Acquire), 0);
    assert!(!staging.join(&id).exists());
    let denied = CopyApproval::approve(&saved, &identity, &root, DATA.len() as u64, false).unwrap();
    assert_eq!(
        denied
            .stage_to(
                &saved,
                &identity,
                FILE_NAME,
                &staging,
                &id,
                Some(DATA.len() as u64),
                &stopped,
                &|| Ok(())
            )
            .err()
            .as_deref(),
        Some("source_download_permission_required")
    );
    assert_eq!(context.fetches.load(Ordering::Acquire), 0);
    let copy = approval
        .stage_to(
            &saved,
            &identity,
            FILE_NAME,
            &staging,
            &id,
            Some(DATA.len() as u64),
            &stopped,
            &|| Ok(()),
        )
        .unwrap();
    assert_eq!(copy.bytes, DATA.len() as u64);
    assert_eq!(copy.sha256, format!("{:x}", Sha256::digest(DATA)));
    let mut file = copy.verify(&saved, &identity, &staging).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, DATA);
    drop(file);
    let fetches = context.fetches.load(Ordering::Acquire);
    assert!(fetches > 0);
    let cached_id = Uuid::new_v4().to_string();
    let cached = approval
        .stage_to(
            &saved,
            &identity,
            FILE_NAME,
            &staging,
            &cached_id,
            Some(DATA.len() as u64),
            &stopped,
            &|| Ok(()),
        )
        .unwrap();
    assert_eq!(cached.sha256, copy.sha256);
    assert_eq!(
        context.fetches.load(Ordering::Acquire),
        fetches,
        "cached copy recalled original data again"
    );
    assert!(copy.source_stamp.starts_with("cloud-file-v1:"));
    foreground_writer_breaks_idle_protected_handle(&root.join(FILE_NAME));
    let changed_id = Uuid::new_v4().to_string();
    let changed = approval
        .stage_to(
            &saved,
            &identity,
            FILE_NAME,
            &staging,
            &changed_id,
            Some(DATA.len() as u64),
            &stopped,
            &|| Ok(()),
        )
        .unwrap();
    let mut changed_data = DATA.to_vec();
    changed_data[0] = 0x59;
    assert_ne!(changed.source_stamp, copy.source_stamp);
    assert_eq!(
        changed.sha256,
        format!("{:x}", Sha256::digest(&changed_data))
    );
    assert_eq!(context.fetches.load(Ordering::Acquire), fetches);
    assert!(copy.verify(&saved, &identity, &staging).is_ok());
    println!("real CfApi foreground writer: idle protected handle broke; new copy bound the changed version; old independent copy retained");
    provider.close().unwrap();
    fs::remove_file(root.join(FILE_NAME)).unwrap();
    let restored = StagedCopy::restore(&saved, &identity, &staging, &id).unwrap();
    let mut file = restored.verify(&saved, &identity, &staging).unwrap();
    let mut recovered = Vec::new();
    file.read_to_end(&mut recovered).unwrap();
    assert_eq!(recovered, DATA);
    drop(file);
    println!("integrated stage_to: denied reads0fetch; unaligned Unicode copy and cached retry verified; signed recovery works after source removal");
    let cancel_root = base.join("copy-cancel-source");
    let mut provider = Provider::create(&cancel_root).unwrap();
    let context = provider.context.as_ref().unwrap();
    context.hold.store(true, Ordering::Release);
    let approval =
        CopyApproval::approve(&saved, &identity, &cancel_root, DATA.len() as u64, true).unwrap();
    let id = Uuid::new_v4().to_string();
    let gate = || {
        if context.fetches.load(Ordering::Acquire) > 0 {
            Err("metered_network".into())
        } else {
            Ok(())
        }
    };
    assert_eq!(
        approval
            .stage_to(
                &saved,
                &identity,
                FILE_NAME,
                &staging,
                &id,
                Some(DATA.len() as u64),
                &stopped,
                &gate
            )
            .err()
            .as_deref(),
        Some("metered_network")
    );
    assert!(!staging.join(&id).exists());
    assert!(context.fetches.load(Ordering::Acquire) > 0);
    assert_eq!(context.delivered.load(Ordering::Acquire), 0);
    provider.close().unwrap();
    println!("integrated stage_to: policy revocation joined the reader Job and removed only its incomplete stage");
    let failure_root = base.join("copy-failure-source");
    let mut provider = Provider::create(&failure_root).unwrap();
    let context = provider.context.as_ref().unwrap();
    context.fail.store(true, Ordering::Release);
    let approval =
        CopyApproval::approve(&saved, &identity, &failure_root, DATA.len() as u64, true).unwrap();
    let id = Uuid::new_v4().to_string();
    assert!(approval
        .stage_to(
            &saved,
            &identity,
            FILE_NAME,
            &staging,
            &id,
            Some(DATA.len() as u64),
            &stopped,
            &|| Ok(())
        )
        .is_err());
    assert!(!staging.join(&id).exists());
    assert!(context.fetches.load(Ordering::Acquire) > 0);
    assert_eq!(context.delivered.load(Ordering::Acquire), 0);
    provider.close().unwrap();
    assert!(StagedCopy::restore(&saved, &identity, &staging, &copy.id).is_ok());
    assert!(StagedCopy::restore(&saved, &identity, &staging, &cached.id).is_ok());
    println!("integrated stage_to: failed provider published no receipt and retained earlier verified copies");
}

#[test]
#[ignore = "registers a synthetic cloud provider only on a disposable hosted Windows runner"]
fn cloud_provider_child() {
    require_disposable_runner();
    let base = PathBuf::from(
        std::env::var_os("FRAMELEAF_CFAPI_CHILD_ROOT").expect("parent-owned fixture"),
    );
    assert!(base.starts_with(std::env::temp_dir()));
    assert!(base
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("frameleaf-cfapi-"));
    let root = base.join("source");
    let mut provider = Provider::create(&root).unwrap();
    let dir = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
    let before = dir.symlink_metadata(FILE_NAME).unwrap();
    let observation = crate::source_metadata::probe(&dir, Path::new(FILE_NAME), &before).unwrap();
    assert_eq!(before.len(), DATA.len() as u64);
    assert!(!observation.excluded && !observation.unsupported_reparse);
    assert_ne!(
        observation.availability,
        crate::source_metadata::Availability::Available
    );
    assert_eq!(
        provider
            .context
            .as_ref()
            .unwrap()
            .fetches
            .load(Ordering::Acquire),
        0,
        "metadata triggered hydration"
    );
    qualify_path_spellings(&dir, &root.join(FILE_NAME));
    assert_eq!(
        provider
            .context
            .as_ref()
            .unwrap()
            .fetches
            .load(Ordering::Acquire),
        0
    );
    hydrate_explicit_range(&root.join(FILE_NAME)).unwrap();
    assert_eq!(fs::read(root.join(FILE_NAME)).unwrap(), DATA);
    drop(dir);
    provider.close().unwrap();
    let context = provider.context.as_ref().unwrap();
    assert!(context.fetches.load(Ordering::Acquire) > 0);
    assert!(context.delivered.load(Ordering::Acquire) >= DATA.len() as u64);
    assert_eq!(context.failure.load(Ordering::Acquire), 0);
    println!("real CfApi placeholder: metadata fetched no originals; explicit hydration delivered verified bytes");
    let cancel_root = base.join("cancel-source");
    let mut provider = Provider::create(&cancel_root).unwrap();
    provider
        .context
        .as_ref()
        .unwrap()
        .hold
        .store(true, Ordering::Release);
    cancel_pending_hydration(
        &cancel_root.join(FILE_NAME),
        provider.context.as_ref().unwrap(),
    )
    .unwrap();
    provider.close().unwrap();
    let context = provider.context.as_ref().unwrap();
    assert!(context.cancellations.load(Ordering::Acquire) > 0);
    assert_eq!(context.delivered.load(Ordering::Acquire), 0);
    println!("real CfApi pending hydration: CancelIoEx confirmed terminal cancellation without delivering bytes");
    #[cfg(feature = "windows-cloud-copy")]
    qualify_staged_copy(&base);
}

#[test]
#[ignore = "isolated real CfApi provider qualification; requires disposable hosted Windows"]
fn disposable_cloud_provider_qualification() {
    require_disposable_runner();
    let base = std::env::temp_dir().join(format!("frameleaf-cfapi-{}", Uuid::new_v4()));
    crate::windows_protection::new_private_directory(&base).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "copy_source::windows_cloud_tests::cloud_provider_child",
            "--ignored",
            "--nocapture",
        ])
        .env("FRAMELEAF_CFAPI_CHILD_ROOT", &base)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(90);
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break (status, false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break (child.wait().unwrap(), true);
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    // The child has exited, so its provider callbacks cannot retain fixture memory or handles.
    for name in [
        "source",
        "cancel-source",
        "copy-source",
        "copy-cancel-source",
        "copy-failure-source",
    ] {
        unsafe {
            CfUnregisterSyncRoot(wide(&base.join(name)).as_ptr());
        }
    }
    fs::remove_dir_all(&base).unwrap();
    assert!(
        !timed_out,
        "CfApi child exceeded90seconds and was terminated"
    );
    assert!(status.success(), "CfApi child failed: {status}");
}
