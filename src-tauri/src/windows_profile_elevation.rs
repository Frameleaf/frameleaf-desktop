fn parameters(manifest: &str, controller: &str, sid: &str) -> Result<String, String> {
    if !crate::native_runtime::digest_valid(manifest, 64)
        || !crate::native_runtime::digest_valid(controller, 64)
        || sid.len() > 184
        || !sid.starts_with("S-1-")
        || !sid[2..].split('-').all(|part| {
            part.parse::<u64>()
                .is_ok_and(|number| number.to_string() == part)
        })
    {
        return Err("host_install_profile_user_invalid".into());
    }
    Ok(format!(
        "--provision-windows-profile {manifest} {controller} {sid}"
    ))
}
fn authorization_error(code: u32) -> String {
    if code == 1223 {
        "host_profile_authorization_cancelled".into()
    } else {
        "host_profile_authorization_unavailable".into()
    }
}
fn process_result(code: u32) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err("host_profile_prepare_failed".into())
    }
}

#[cfg(windows)]
mod native {
    use std::{
        fs::{File, OpenOptions},
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        path::Path,
    };
    use windows_sys::Win32::{
        Foundation::{GetLastError, WAIT_OBJECT_0},
        Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ},
        System::{
            Com::{
                CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
            },
            SystemInformation::GetSystemDirectoryW,
            Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE},
        },
        UI::Shell::{
            ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
            SHELLEXECUTEINFOW,
        },
    };
    const UNAVAILABLE: &str = "host_profile_authorization_unavailable";
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }
    pub(super) fn pin(path: &Path) -> Result<File, String> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| UNAVAILABLE)?;
        let info = file.metadata().map_err(|_| UNAVAILABLE)?;
        if !info.is_file() || info.file_attributes() & 0x400 != 0 {
            return Err(UNAVAILABLE.into());
        }
        Ok(file)
    }
    pub(super) fn execute(path: &Path, parameters: &str, elevate: bool) -> Result<u32, String> {
        let result = unsafe {
            CoInitializeEx(
                std::ptr::null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            )
        };
        if result < 0 {
            #[cfg(debug_assertions)]
            eprintln!("host_profile_com: hresult={result}");
            return Err(UNAVAILABLE.into());
        }
        let _apartment = Apartment;
        let file: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let args: Vec<u16> = parameters.encode_utf16().chain(Some(0)).collect();
        let verb: Vec<u16> = if elevate { "runas\0" } else { "open\0" }
            .encode_utf16()
            .collect();
        if file.len() > 32767
            || file[..file.len() - 1].contains(&0)
            || args.len() > 32767
            || args[..args.len() - 1].contains(&0)
        {
            return Err(UNAVAILABLE.into());
        }
        let mut directory = vec![0u16; 32768];
        let size =
            unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
        if size == 0 || size >= directory.len() {
            return Err(UNAVAILABLE.into());
        }
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
            lpVerb: verb.as_ptr(),
            lpFile: file.as_ptr(),
            lpParameters: args.as_ptr(),
            lpDirectory: directory.as_ptr(),
            nShow: 0,
            ..Default::default()
        };
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            let code = unsafe { GetLastError() };
            #[cfg(debug_assertions)]
            eprintln!("host_profile_shell: win32={code}");
            return Err(super::authorization_error(code));
        }
        if info.hProcess.is_null() {
            return Err(UNAVAILABLE.into());
        }
        let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
        // Keep setup active until the privileged helper exits; never retry beside a still-running helper.
        if unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
            return Err("host_profile_prepare_failed".into());
        }
        let mut code = 0;
        if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
            return Err("host_profile_prepare_failed".into());
        }
        Ok(code)
    }
}

#[cfg(windows)]
pub(crate) fn provision(record: &crate::host_install::Installation) -> Result<(), String> {
    let sid = crate::windows_protection::process_user_sid()?;
    let parameters = parameters(&record.manifest_sha256, &record.controller_sha256, &sid)?;
    let layout = record.layout()?;
    let _controller = native::pin(&layout.controller)?;
    crate::host_install::verify_for_profile(record)?;
    // The preflight lease has been released: the elevated helper takes an exclusive runtime lease.
    process_result(native::execute(&layout.controller, &parameters, true)?)?;
    if crate::host_install::Installation::read(&record.manifest_sha256)? != *record
        || crate::windows_protection::process_user_sid()? != sid
    {
        return Err("host_install_record_invalid".into());
    }
    for name in ["state", "manager"] {
        let path = layout.profiles.join(&sid).join(name);
        crate::host_setup::require_leaf(&path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parameters_allow_only_two_digests_and_a_canonical_sid_spelling() {
        let manifest = "a".repeat(64);
        let controller = "b".repeat(64);
        let sid = "S-1-5-21-1-2-3-1001";
        assert_eq!(
            parameters(&manifest, &controller, sid).unwrap(),
            format!("--provision-windows-profile {manifest} {controller} {sid}")
        );
        for value in ["", "../escape", "a;whoami", &"A".repeat(64)] {
            assert!(parameters(value, &controller, sid).is_err());
            assert!(parameters(&manifest, value, sid).is_err());
        }
        for value in [
            "",
            "S-1-5--21",
            "S-1-05-21",
            "S-1-5-21 0",
            "S-1-5-21\"",
            "S-1-5-21\n",
            "S-1-5-",
            "s-1-5-21",
        ] {
            assert!(
                parameters(&manifest, &controller, value).is_err(),
                "{value:?}"
            );
        }
    }
    #[test]
    fn consent_dismissal_and_helper_failure_never_report_success() {
        assert_eq!(
            authorization_error(1223),
            "host_profile_authorization_cancelled"
        );
        for code in [0, 2, 5, 32, 1155] {
            assert_eq!(
                authorization_error(code),
                "host_profile_authorization_unavailable"
            );
        }
        process_result(0).unwrap();
        for code in [1, 1223, 259, u32::MAX] {
            assert_eq!(
                process_result(code).unwrap_err(),
                "host_profile_prepare_failed"
            );
        }
    }
    #[cfg(windows)]
    #[test]
    fn shell_launch_uses_the_captured_device_path_and_waits_for_the_child() {
        let path =
            crate::windows_protection::stable_path(&std::env::current_exe().unwrap()).unwrap();
        let _pin = native::pin(&path).unwrap();
        assert_eq!(
            native::execute(
                &path,
                "--exact windows_profile_elevation::tests::shell_launch_child --ignored",
                false
            )
            .unwrap(),
            73
        );
    }
    #[cfg(windows)]
    #[test]
    #[ignore = "child-only ShellExecute probe; never prompts for elevation"]
    fn shell_launch_child() {
        let sid = crate::windows_protection::process_user_sid().unwrap();
        assert!(parameters(&"a".repeat(64), &"b".repeat(64), &sid)
            .unwrap()
            .ends_with(&sid));
        std::process::exit(73);
    }
    #[cfg(windows)]
    #[test]
    fn pinned_controller_refuses_concurrent_write_and_rename() {
        let root =
            std::env::temp_dir().join(format!("frameleaf-controller-pin-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("synthetic-controller.exe");
        std::fs::write(&path, b"synthetic only").unwrap();
        let pin = native::pin(&path).unwrap();
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, root.join("changed.exe")).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"synthetic only");
        drop(pin);
        std::fs::remove_dir_all(root).unwrap();
    }
}
