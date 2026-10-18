//! Read-only machine installation anchor; no directory creation or caller-selected root.
use std::{collections::BTreeSet, ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};
use windows_sys::Win32::{
    System::Com::CoTaskMemFree,
    UI::Shell::{FOLDERID_ProgramFilesX64, SHGetKnownFolderPath},
};
const ERROR: &str = "host_install_location_unavailable";
struct Folder(*mut u16);
impl Drop for Folder {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(self.0.cast()) };
    }
}
pub(super) fn base() -> Result<PathBuf, String> {
    let mut folder = Folder(std::ptr::null_mut());
    let result = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramFilesX64,
            0,
            std::ptr::null_mut(),
            &mut folder.0,
        )
    };
    if result != 0 || folder.0.is_null() {
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
    let physical = crate::windows_protection::stable_path(&path).map_err(|_| ERROR)?;
    crate::windows_protection::protect(&physical, &mut BTreeSet::new()).map_err(|_| ERROR)?;
    Ok(physical.join("Frameleaf"))
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "host_install::windows::tests::caller_environment_and_working_directory_cannot_redirect_the_machine_anchor", "--nocapture"])
            .env("FRAMELEAF_LAYOUT_CHILD", "1")
            .env("ProgramFiles", &untrusted)
            .env("ProgramW6432", &untrusted)
            .env("ProgramFiles(x86)", &untrusted)
            .current_dir(temporary)
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains(&format!("physical-installation={}", root.display())));
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains(&format!("installed-versions={inventory}")));
    }
}
