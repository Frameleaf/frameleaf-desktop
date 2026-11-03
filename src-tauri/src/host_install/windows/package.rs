//! Installer-only machine directories and verified receipts; user setup stays in LocalAppData.
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, TokenElevation,
        WinBuiltinAdministratorsSid, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, MoveFileExW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
        FILE_FLAG_OPEN_REPARSE_POINT, MOVEFILE_WRITE_THROUGH,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

const AUTHORITY: &str = "host_install_administrator_required";
const DIRECTORY: &str = "host_install_directory_failed";
const MACHINE_ACL: &str = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";

fn wide(path: &Path) -> Result<Vec<u16>, String> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.is_empty() || value.len() >= 32767 || value.contains(&0) {
        return Err("host_install_path_invalid".into());
    }
    value.push(0);
    Ok(value)
}

fn process_token(access: u32) -> Result<OwnedHandle, String> {
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut raw) } == 0 || raw.is_null() {
        return Err(AUTHORITY.into());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
fn administrators() -> Result<[u32; 17], String> {
    let mut sid = [0; 17];
    let mut size = std::mem::size_of_val(&sid) as u32;
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
        || size > std::mem::size_of_val(&sid) as u32
    {
        return Err(AUTHORITY.into());
    }
    Ok(sid)
}
/// Require both primary-process elevation and the effective token’s administrator authority.
fn require_administrator() -> Result<(), String> {
    let token = process_token(TOKEN_QUERY)?;
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&elevation) as u32,
            &mut length,
        )
    } == 0
        || length != std::mem::size_of_val(&elevation) as u32
        || elevation.TokenIsElevated != 1
    {
        return Err(AUTHORITY.into());
    }
    let sid = administrators()?;
    let mut enabled = 0;
    // NULL checks the effective thread token too, including deny-only/restricted membership.
    if unsafe {
        CheckTokenMembership(
            std::ptr::null_mut(),
            sid.as_ptr().cast_mut().cast(),
            &mut enabled,
        )
    } == 0
        || enabled == 0
    {
        return Err(AUTHORITY.into());
    }
    Ok(())
}

struct Descriptor(*mut core::ffi::c_void);
impl Descriptor {
    fn new(sddl: &str) -> Result<Self, String> {
        let value: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = Self(std::ptr::null_mut());
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                value.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor.0,
                std::ptr::null_mut(),
            )
        } == 0
            || descriptor.0.is_null()
        {
            return Err(DIRECTORY.into());
        }
        Ok(descriptor)
    }
    fn create(&self, path: &Path) -> Result<(), String> {
        let wide = wide(path)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        };
        if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
            return Err(DIRECTORY.into());
        }
        Ok(())
    }
}
fn new_machine_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > 4096 {
        return Err("host_install_record_invalid".into());
    }
    crate::windows_protection::protect(
        path.parent().ok_or("host_install_path_invalid")?,
        &mut BTreeSet::new(),
    )?;
    let descriptor = Descriptor::new(MACHINE_ACL)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let name = wide(path)?;
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err("host_install_record_failed".into());
    }
    {
        let mut file = unsafe { File::from_raw_handle(raw) };
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "host_install_record_failed")?;
    }
    crate::windows_protection::protect(path, &mut BTreeSet::new())
}

fn seed_lease(root: &Path) -> Result<(), String> {
    let path = root.join(".runtime-lease");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => new_machine_file(&path, &[])?,
        Ok(_) => crate::windows_protection::protect(&path, &mut BTreeSet::new())?,
        Err(_) => return Err("host_package_state_invalid".into()),
    }
    Ok(())
}

fn publish_record(root: &Path, expected: &crate::host_install::Installation) -> Result<(), String> {
    let destination = root.join("installation.json");
    let read_existing = || {
        crate::windows_protection::protect(&destination, &mut BTreeSet::new())?;
        let record = crate::host_install::Installation::decode(
            &crate::runtime_store::read_bounded(&destination, 4096)?,
        )?;
        if record != *expected {
            return Err("host_install_record_invalid".into());
        }
        Ok(())
    };
    if crate::host_install::receipt_present(&destination)? {
        return read_existing();
    }
    let temporary = root.join(format!(".installation-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        new_machine_file(
            &temporary,
            &serde_json::to_vec(expected).map_err(|_| "host_install_record_failed")?,
        )?;
        let source = wide(&temporary)?;
        let target = wide(&destination)?;
        // No REPLACE_EXISTING or cross-volume copy: a competing receipt is never overwritten.
        if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
            return Err("host_install_record_failed".into());
        }
        read_existing()
    })();
    let cleanup = fs::remove_file(&temporary);
    result?;
    if cleanup.is_err_and(|error| error.kind() != std::io::ErrorKind::NotFound) {
        return Err("host_install_record_failed".into());
    }
    Ok(())
}

pub(in crate::host_install) fn finalize(
    manifest: &str,
    controller: &str,
) -> Result<serde_json::Value, String> {
    require_administrator()?;
    let layout = crate::host_install::Layout::new(manifest, controller)?;
    crate::windows_protection::protect(&layout.runtime, &mut BTreeSet::new())?;
    seed_lease(&layout.runtime)?;
    let _guard = crate::host_install::finalization_guard(&layout.runtime, false, || {
        crate::host_install::verify_resources(&layout, manifest, controller)
    })?;
    crate::windows_protection::protect(&layout.profiles, &mut BTreeSet::new())?;
    if fs::read_dir(&layout.profiles)
        .map_err(|_| "host_install_profile_changed")?
        .next()
        .is_some()
    {
        return Err("host_install_profile_changed".into());
    }
    publish_record(
        &layout.runtime,
        &crate::host_install::Installation {
            schema_version: 1,
            manifest_sha256: manifest.into(),
            controller_sha256: controller.into(),
        },
    )?;
    Ok(
        serde_json::json!({"protocolVersion":1,"state":"resources-installed","profileReady":false,"manifestSha256":manifest,"controllerSha256":controller,"serverStarted":false,"runtimeQualified":false,"redistributable":false}),
    )
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
/// Create only beneath protected ancestry; refuse unsafe existing objects without repairing ACLs.
fn directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::windows_protection::protect(
                path.parent().ok_or("host_install_path_invalid")?,
                &mut BTreeSet::new(),
            )?;
            Descriptor::new(MACHINE_ACL)?.create(path)?;
        }
        _ => return Err("host_install_directory_invalid".into()),
    }
    crate::windows_protection::protect(path, &mut BTreeSet::new())
}

/// Prepare fixed machine containers only; existing versions require a separate maintenance path.
pub(in crate::host_install) fn prepare(
    manifest: &str,
    controller: &str,
) -> Result<serde_json::Value, String> {
    require_administrator()?;
    let layout = crate::host_install::Layout::new(manifest, controller)?;
    // Existing versions need verified maintenance/recovery, never fresh-directory preparation.
    crate::host_install::admit_versions(&layout, || Err("host_install_version_exists".into()))?;
    let root = layout
        .profiles
        .parent()
        .ok_or("host_install_path_invalid")?
        .to_owned();
    for path in [
        &root,
        &root.join("Runtimes"),
        &root.join("Controllers"),
        &root.join("Controllers").join(manifest),
        &layout.profiles,
    ] {
        directory(path)?;
    }
    Ok(serde_json::json!({"protocolVersion":1,"state":"install-prepared","serverStarted":false}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, ImpersonateLoggedOnUser, RevertToSelf, DISABLE_MAX_PRIVILEGE,
        SID_AND_ATTRIBUTES, TOKEN_DUPLICATE,
    };
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    #[test]
    /// A restricted thread must not borrow the primary process’s elevated authority.
    fn restricted_effective_token_refuses_valid_package_request_before_filesystem_work() {
        let token = process_token(TOKEN_QUERY | TOKEN_DUPLICATE).unwrap();
        let sid = administrators().unwrap();
        let disabled = SID_AND_ATTRIBUTES {
            Sid: sid.as_ptr().cast_mut().cast(),
            Attributes: 0,
        };
        let mut raw = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                CreateRestrictedToken(
                    token.as_raw_handle(),
                    DISABLE_MAX_PRIVILEGE,
                    1,
                    &disabled,
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    &mut raw,
                )
            },
            0
        );
        let restricted = unsafe { OwnedHandle::from_raw_handle(raw) };
        assert_ne!(
            unsafe { ImpersonateLoggedOnUser(restricted.as_raw_handle()) },
            0
        );
        let _revert = Revert;
        for operation in [
            crate::host_install::prepare_windows_package,
            crate::host_install::finalize_windows_package,
        ] {
            assert_eq!(
                operation(&"a".repeat(64), &"b".repeat(64)).unwrap_err(),
                AUTHORITY
            );
        }
    }

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
            assert_eq!(
                std::env::var("RUNNER_ENVIRONMENT").as_deref(),
                Ok("github-hosted")
            );
            require_administrator().unwrap();
            let base = super::super::base().unwrap();
            let root = base
                .parent()
                .unwrap()
                .join(format!("Frameleaf-test-{}", uuid::Uuid::new_v4()));
            assert!(!root.exists());
            let fixture = Self(root);
            directory(&fixture.0).unwrap();
            fixture
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for name in [
                "installation.json",
                "proposal",
                ".runtime-lease",
                ".package-maintenance",
            ] {
                let _ = fs::remove_file(self.0.join(name));
            }
            let _ = fs::remove_file(self.0.join("file"));
            let _ = fs::remove_dir(self.0.join("unsafe"));
            let _ = fs::remove_dir(self.0.join("incorrect"));
            let _ = fs::remove_dir(self.0.join("safe"));
            let _ = fs::remove_dir(&self.0);
        }
    }

    /// Read the actual file object; safety alone does not establish the intended machine policy.
    fn assert_machine_descriptor(path: &Path) {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::{
            Security::{
                Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
                EqualSid, GetAce, GetSecurityDescriptorControl, IsValidAcl, IsValidSid,
                WinBuiltinUsersSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACL,
                CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
                OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
            },
            Storage::FileSystem::{
                FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
                FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, READ_CONTROL,
            },
        };
        let file = fs::OpenOptions::new()
            .access_mode(READ_CONTROL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap();
        let mut descriptor = Descriptor(std::ptr::null_mut());
        let mut owner = std::ptr::null_mut();
        let mut acl: *mut ACL = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    &mut owner,
                    std::ptr::null_mut(),
                    &mut acl,
                    std::ptr::null_mut(),
                    &mut descriptor.0,
                )
            },
            0
        );
        assert!(!descriptor.0.is_null());
        assert!(!owner.is_null());
        let administrator = administrators().unwrap();
        assert_ne!(unsafe { IsValidSid(owner) }, 0);
        assert_ne!(
            unsafe { EqualSid(owner, administrator.as_ptr().cast_mut().cast()) },
            0
        );
        let mut control = 0;
        let mut revision = 0;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) },
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        assert!(!acl.is_null());
        assert_ne!(unsafe { IsValidAcl(acl) }, 0);
        assert_eq!(unsafe { (*acl).AceCount }, 3);
        // File creation maps generic rights to these file-specific access masks.
        for (index, (kind, rights)) in [
            (WinLocalSystemSid, FILE_ALL_ACCESS),
            (WinBuiltinAdministratorsSid, FILE_ALL_ACCESS),
            (WinBuiltinUsersSid, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE),
        ]
        .into_iter()
        .enumerate()
        {
            let mut sid = [0u32; 17];
            let mut length = std::mem::size_of_val(&sid) as u32;
            assert_ne!(
                unsafe {
                    CreateWellKnownSid(
                        kind,
                        std::ptr::null_mut(),
                        sid.as_mut_ptr().cast(),
                        &mut length,
                    )
                },
                0
            );
            let mut raw = std::ptr::null_mut();
            assert_ne!(unsafe { GetAce(acl, index as u32, &mut raw) }, 0);
            assert!(!raw.is_null());
            let ace = raw.cast::<ACCESS_ALLOWED_ACE>();
            assert!(
                unsafe { (*ace).Header.AceSize } as usize
                    >= std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            );
            assert_eq!(u32::from(unsafe { (*ace).Header.AceSize }), 8 + length);
            assert_eq!(unsafe { (*ace).Header.AceType }, 0);
            assert_eq!(
                unsafe { (*ace).Header.AceFlags },
                (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
            );
            assert_eq!(unsafe { (*ace).Mask }, rights);
            let actual_sid = unsafe { std::ptr::addr_of!((*ace).SidStart).cast_mut().cast() };
            assert_ne!(unsafe { IsValidSid(actual_sid) }, 0);
            assert_ne!(unsafe { EqualSid(actual_sid, sid.as_mut_ptr().cast()) }, 0);
        }
    }
    #[test]
    #[ignore = "requires an elevated disposable GitHub-hosted Windows runner; never creates a real Frameleaf installation"]
    /// Exercise real ACLs in a unique sibling directory while preserving unsafe fixture objects.
    fn disposable_runner_creates_protected_directories_and_refuses_existing_unsafe_objects() {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(
            std::env::var("RUNNER_ENVIRONMENT").as_deref(),
            Ok("github-hosted")
        );
        require_administrator().unwrap();
        let base = super::super::base().unwrap();
        let root = base
            .parent()
            .unwrap()
            .join(format!("Frameleaf-test-{}", uuid::Uuid::new_v4()));
        assert!(!root.exists());
        let fixture = Fixture(root);
        directory(&fixture.0).unwrap();
        let safe = fixture.0.join("safe");
        directory(&safe).unwrap();
        directory(&safe).unwrap();
        crate::windows_protection::protect(&safe, &mut BTreeSet::new()).unwrap();
        assert_machine_descriptor(&safe);
        let incorrect = fixture.0.join("incorrect");
        Descriptor::new(&MACHINE_ACL.replace("GRGX", "GR"))
            .unwrap()
            .create(&incorrect)
            .unwrap();
        crate::windows_protection::protect(&incorrect, &mut BTreeSet::new()).unwrap();
        assert!(std::panic::catch_unwind(|| assert_machine_descriptor(&incorrect)).is_err());
        let untrusted = fixture.0.join("unsafe");
        Descriptor::new("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
            .unwrap()
            .create(&untrusted)
            .unwrap();
        assert!(directory(&untrusted).is_err());
        assert!(untrusted.is_dir());
        assert!(crate::windows_protection::protect(&untrusted, &mut BTreeSet::new()).is_err());
        let file = fixture.0.join("file");
        fs::write(&file, b"keep fixture bytes").unwrap();
        assert!(directory(&file).is_err());
        assert_eq!(fs::read(file).unwrap(), b"keep fixture bytes");
        let layout = crate::host_install::Layout {
            runtime: safe.clone(),
            controller: untrusted.join("frameleaf-native-host.exe"),
            profiles: fixture.0.join("Profiles"),
        };
        assert!(crate::host_install::admit_versions(&layout, || Err(
            "host_install_version_exists".into()
        ))
        .is_err());
    }
    #[test]
    #[ignore = "requires an elevated disposable GitHub-hosted Windows runner; synthetic receipt only"]
    fn disposable_runner_publishes_receipts_without_replacing_existing_authority() {
        let fixture = Fixture::new();
        let record = crate::host_install::Installation {
            schema_version: 1,
            manifest_sha256: "a".repeat(64),
            controller_sha256: "b".repeat(64),
        };
        seed_lease(&fixture.0).unwrap();
        let reader = crate::package_lease::CodeLease::acquire(&fixture.0).unwrap();
        assert!(crate::package_lease::Maintenance::acquire(&fixture.0).is_err());
        drop(reader);
        let guard = crate::host_install::finalization_guard(&fixture.0, false, || {
            assert!(crate::package_lease::CodeLease::acquire(&fixture.0).is_err());
            Ok(())
        })
        .unwrap();
        publish_record(&fixture.0, &record).unwrap();
        let path = fixture.0.join("installation.json");
        let original = serde_json::to_vec(&record).unwrap();
        assert_eq!(fs::read(&path).unwrap(), original);
        publish_record(&fixture.0, &record).unwrap();
        let changed = crate::host_install::Installation {
            controller_sha256: "c".repeat(64),
            ..record.clone()
        };
        assert!(publish_record(&fixture.0, &changed).is_err());
        assert!(new_machine_file(&path, b"must not overwrite").is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        let proposal = fixture.0.join("proposal");
        new_machine_file(&proposal, b"other authority").unwrap();
        assert_eq!(
            unsafe {
                MoveFileExW(
                    wide(&proposal).unwrap().as_ptr(),
                    wide(&path).unwrap().as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                )
            },
            0
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::write(&path, b"malformed fixture").unwrap();
        assert!(publish_record(&fixture.0, &record).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"malformed fixture");
        assert!(!fs::read_dir(&fixture.0).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".installation-")));
        drop(guard);
        new_machine_file(&fixture.0.join(".package-maintenance"), &[]).unwrap();
        assert!(
            crate::host_install::finalization_guard(&fixture.0, false, || panic!(
                "fenced package must refuse before verification"
            ))
            .is_err()
        );
        assert!(fixture.0.join(".package-maintenance").is_file());
    }
}
