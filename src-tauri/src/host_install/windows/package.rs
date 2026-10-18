//! Installer-only machine directories; no runtime, receipt or user-profile publication.
use std::{
    collections::BTreeSet,
    fs,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, TokenElevation,
        WinBuiltinAdministratorsSid, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
    },
    Storage::FileSystem::CreateDirectoryW,
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

const AUTHORITY: &str = "host_install_administrator_required";
const DIRECTORY: &str = "host_install_directory_failed";
const MACHINE_ACL: &str = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";

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
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.is_empty() || wide.len() >= 32767 || wide.contains(&0) {
            return Err("host_install_path_invalid".into());
        }
        wide.push(0);
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
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
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
        assert_eq!(
            crate::host_install::prepare_windows_package(&"a".repeat(64), &"b".repeat(64))
                .unwrap_err(),
            AUTHORITY
        );
    }

    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.0.join("file"));
            let _ = fs::remove_dir(self.0.join("unsafe"));
            let _ = fs::remove_dir(self.0.join("safe"));
            let _ = fs::remove_dir(&self.0);
        }
    }
    #[test]
    #[ignore = "requires an elevated disposable GitHub-hosted Windows runner; never creates a real Frameleaf installation"]
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
}
