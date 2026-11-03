//! OS-owned machine anchor; installer-only directory writes live in the package submodule.
pub(super) mod package;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    os::windows::{
        ffi::OsStringExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::PathBuf,
};
use windows_sys::Win32::{
    Foundation::{HANDLE, RPC_E_CHANGED_MODE},
    Security::{TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY},
    System::{
        Com::{CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_MULTITHREADED},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
    UI::Shell::{FOLDERID_LocalAppData, FOLDERID_ProgramFilesX64, SHGetKnownFolderPath},
};
const ERROR: &str = "host_install_location_unavailable";
struct Com(bool);
impl Com {
    fn initialize() -> Result<Self, String> {
        let result = unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
        if result < 0 && result != RPC_E_CHANGED_MODE {
            return Err(ERROR.into());
        }
        Ok(Self(result >= 0))
    }
}
impl Drop for Com {
    fn drop(&mut self) {
        // S_FALSE acquires a reference too; an existing different apartment does not.
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}
struct Folder(*mut u16);
impl Drop for Folder {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(self.0.cast()) };
    }
}
pub(super) fn local_app_data() -> Result<PathBuf, String> {
    let mut raw = std::ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
            &mut raw,
        )
    } == 0
        || raw.is_null()
    {
        return Err(ERROR.into());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    // An explicit process token expands the user's registered folder independently of inherited variables.
    known_folder(&FOLDERID_LocalAppData, token.as_raw_handle())
}
fn known_folder(id: &windows_sys::core::GUID, token: HANDLE) -> Result<PathBuf, String> {
    let _initialization = Com::initialize()?;
    let mut folder = Folder(std::ptr::null_mut());
    let result = unsafe { SHGetKnownFolderPath(id, 0, token, &mut folder.0) };
    if result != 0 || folder.0.is_null() {
        #[cfg(test)]
        eprintln!(
            "native known-folder probe HRESULT: {result:#010x} explicit_user={}",
            !token.is_null()
        );
        return Err(ERROR.into());
    }
    let mut length = 0;
    // The OS returns a terminated allocation; reject paths beyond the native path bound.
    while length < 32768 && unsafe { *folder.0.add(length) } != 0 {
        length += 1;
    }
    if length == 0 || length == 32768 {
        return Err(ERROR.into());
    }
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(folder.0, length)
    }));
    crate::windows_protection::stable_path(&path).map_err(|_| ERROR.into())
}
pub(super) fn base() -> Result<PathBuf, String> {
    let physical = known_folder(&FOLDERID_ProgramFilesX64, std::ptr::null_mut())?;
    crate::windows_protection::protect(&physical, &mut BTreeSet::new()).map_err(|_| ERROR)?;
    Ok(physical.join("Frameleaf"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn folder_lookup_balances_com_without_changing_existing_apartments() {
        if std::env::var_os("FRAMELEAF_COM_STATE_CHILD").is_none() {
            // Another test's MTA can implicitly initialize otherwise fresh threads.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "host_install::windows::tests::folder_lookup_balances_com_without_changing_existing_apartments", "--nocapture", "--test-threads=1"])
                .env("FRAMELEAF_COM_STATE_CHILD", "1")
                .output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        use windows_sys::Win32::{
            Foundation::{CO_E_NOTINITIALIZED, S_OK},
            System::Com::{
                CoGetContextToken, CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED,
                COINIT_MULTITHREADED,
            },
        };
        for existing in [
            None,
            Some(COINIT_MULTITHREADED),
            Some(COINIT_APARTMENTTHREADED),
        ] {
            std::thread::spawn(move || unsafe {
                let mut context = 0;
                assert_eq!(CoGetContextToken(&mut context), CO_E_NOTINITIALIZED);
                if let Some(model) = existing {
                    assert_eq!(CoInitializeEx(std::ptr::null(), model as u32), S_OK);
                }
                {
                    let _initialization = Com::initialize().unwrap();
                    assert_eq!(CoGetContextToken(&mut context), S_OK);
                    base().unwrap();
                    local_app_data().unwrap();
                }
                if existing.is_some() {
                    assert_eq!(CoGetContextToken(&mut context), S_OK);
                    CoUninitialize();
                }
                assert_eq!(CoGetContextToken(&mut context), CO_E_NOTINITIALIZED);
            })
            .join()
            .unwrap();
        }
    }
    #[test]
    fn machine_layout_has_a_protected_physical_anchor_and_windows_controller_name() {
        let root = base().unwrap();
        assert!(root
            .to_str()
            .unwrap()
            .starts_with(r"\\.\GLOBALROOT\Device\HarddiskVolume"));
        assert_eq!(root.file_name().unwrap(), "Frameleaf");
        let parent = root.parent().unwrap();
        assert!(parent.is_dir());
        crate::windows_protection::protect(parent, &mut BTreeSet::new()).unwrap();
        let layout = super::super::Layout::new(&"a".repeat(64), &"b".repeat(64)).unwrap();
        assert_eq!(layout.runtime, root.join("Runtimes").join("a".repeat(64)));
        assert_eq!(layout.profiles, root.join("Profiles"));
        assert_eq!(
            layout.controller,
            root.join("Controllers")
                .join("a".repeat(64))
                .join("b".repeat(64))
                .join("frameleaf-native-host.exe")
        );
    }
    #[test]
    /// Invalid alternate inventory makes accidental environment-based redirection observable.
    fn caller_environment_and_working_directory_cannot_redirect_the_machine_anchor() {
        let root = base().unwrap();
        let inventory = serde_json::to_string(&super::super::installed().unwrap()).unwrap();
        if std::env::var_os("FRAMELEAF_LAYOUT_CHILD").is_some() {
            println!("physical-installation={}", root.display());
            println!("installed-versions={inventory}");
            return;
        }
        let temporary = std::env::temp_dir();
        let untrusted = temporary.join(format!("frameleaf-untrusted-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(untrusted.join("Frameleaf/Runtimes/not-a-manifest")).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "host_install::windows::tests::caller_environment_and_working_directory_cannot_redirect_the_machine_anchor", "--nocapture"])
            .env("FRAMELEAF_LAYOUT_CHILD", "1")
            .env("ProgramFiles", &untrusted)
            .env("ProgramW6432", &untrusted)
            .env("ProgramFiles(x86)", &untrusted)
            .current_dir(temporary)
            .output();
        std::fs::remove_dir_all(&untrusted).unwrap();
        let output = output.unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains(&format!("physical-installation={}", root.display())));
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains(&format!("installed-versions={inventory}")));
    }
}
