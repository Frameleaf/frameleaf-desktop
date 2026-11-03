//! User-owned server state is separate from the installer's immutable machine layout.
use std::{
    fs,
    path::{Path, PathBuf},
};

const REQUIRED: &str = "host_install_windows_profile_required";
struct Profile {
    root: PathBuf,
    legacy: PathBuf,
}
impl Profile {
    fn paths(&self) -> (PathBuf, PathBuf) {
        (self.root.join("state"), self.root.join("manager"))
    }
    fn no_legacy(&self) -> Result<(), String> {
        match fs::symlink_metadata(&self.legacy) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err("host_profile_legacy_migration_required".into()),
            Err(_) => Err("host_profile_legacy_state_unavailable".into()),
        }
    }
    fn prepare(&self) -> Result<(), String> {
        self.no_legacy()?;
        crate::windows_protection::private_directory(&self.root)?;
        let mut pins = crate::windows_protection::pin_private_directory(&self.root)?;
        crate::host_storage::check(&self.root)?;
        let (state, data) = self.paths();
        for path in [state, data] {
            crate::windows_protection::private_directory(&path)?;
            pins.extend(crate::windows_protection::pin_private_directory(&path)?);
            crate::host_storage::check(&path)?;
        }
        Ok(())
    }
    fn admit(&self, state: &Path, data: &Path) -> Result<Vec<fs::File>, String> {
        self.no_legacy()?;
        if self.paths() != (state.to_owned(), data.to_owned()) {
            return Err(REQUIRED.into());
        }
        let mut pins = crate::windows_protection::pin_private_directory(&self.root)?;
        pins.extend(crate::windows_protection::pin_private_directory(state)?);
        pins.extend(crate::windows_protection::pin_private_directory(data)?);
        for path in [self.root.as_path(), state, data] {
            crate::host_storage::check(path)?;
        }
        Ok(pins)
    }
}
fn known_folder() -> Result<PathBuf, String> {
    crate::windows_protection::process_user_sid()?;
    crate::host_install::windows_local_app_data().map_err(|_| REQUIRED.into())
}
fn discover() -> Result<Profile, String> {
    let base = known_folder()?;
    let sid = crate::windows_protection::process_user_sid()?;
    let profile = Profile {
        root: base.join("Frameleaf Desktop Host"),
        legacy: crate::host_install::windows_profiles_root()?.join(sid),
    };
    profile.no_legacy()?;
    crate::host_storage::check(&base)?;
    Ok(profile)
}
pub(crate) fn prepare(_record: &crate::host_install::Installation) -> Result<(), String> {
    discover()?.prepare()
}
pub(crate) fn paths() -> Result<(PathBuf, PathBuf), String> {
    let profile = discover()?;
    profile.no_legacy()?;
    Ok(profile.paths())
}
pub(crate) fn admit(state: &Path, data: &Path) -> Result<Vec<fs::File>, String> {
    discover()?.admit(state, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> (Fixture, Profile) {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-user-host-{}", uuid::Uuid::new_v4()));
        crate::windows_protection::new_private_directory(&root).unwrap();
        let profile = Profile {
            root: root.join("host"),
            legacy: root.join("legacy"),
        };
        (Fixture(root), profile)
    }
    #[test]
    fn preparation_is_explicit_and_admission_keeps_both_private_leaves_pinned() {
        let (_fixture, profile) = fixture();
        let (state, data) = profile.paths();
        assert!(profile.admit(&state, &data).is_err());
        assert!(!profile.root.exists());
        profile.prepare().unwrap();
        let pins = profile.admit(&state, &data).unwrap();
        assert!(fs::rename(&profile.root, profile.root.with_extension("moved")).is_err());
        assert!(profile.admit(&data, &state).is_err());
        assert!(profile.admit(&state, &data.join("other")).is_err());
        fs::write(data.join("sentinel"), b"retained").unwrap();
        drop(pins);
        profile.prepare().unwrap();
        assert_eq!(fs::read(data.join("sentinel")).unwrap(), b"retained");
    }
    #[test]
    fn any_legacy_object_blocks_all_new_writes_and_is_preserved() {
        let (_fixture, profile) = fixture();
        fs::write(&profile.legacy, b"legacy").unwrap();
        assert_eq!(
            profile.prepare().unwrap_err(),
            "host_profile_legacy_migration_required"
        );
        assert!(!profile.root.exists());
        assert_eq!(fs::read(&profile.legacy).unwrap(), b"legacy");
        assert!(profile
            .admit(&profile.paths().0, &profile.paths().1)
            .is_err());
    }
    #[test]
    fn os_location_ignores_environment_and_working_directory() {
        let base = known_folder().unwrap();
        if std::env::var_os("FRAMELEAF_PROFILE_LOCATOR_CHILD").is_some() {
            println!("profile-location={}", base.display());
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows_host_profile::tests::os_location_ignores_environment_and_working_directory", "--nocapture"])
            .env("FRAMELEAF_PROFILE_LOCATOR_CHILD", "1")
            .env("LOCALAPPDATA", r"Z:\untrusted")
            .env("APPDATA", r"Z:\untrusted")
            .env("USERPROFILE", r"Z:\untrusted")
            .current_dir(std::env::temp_dir()).output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains(&format!("profile-location={}", base.display())));
    }
    #[test]
    #[ignore = "requires a fresh disposable hosted Windows profile with explicit opt-in"]
    fn disposable_runner_prepares_only_a_fresh_os_selected_profile() {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(
            std::env::var("RUNNER_ENVIRONMENT").as_deref(),
            Ok("github-hosted")
        );
        assert_eq!(
            std::env::var("FRAMELEAF_TEST_DISPOSABLE_HOST_PROFILE").as_deref(),
            Ok("1")
        );
        let profile = discover().unwrap();
        crate::windows_protection::new_private_directory(&profile.root).unwrap();
        struct EmptyProfile(PathBuf);
        impl Drop for EmptyProfile {
            fn drop(&mut self) {
                for name in ["state", "manager"] {
                    let _ = fs::remove_dir(self.0.join(name));
                }
                let _ = fs::remove_dir(&self.0);
            }
        }
        let owned = EmptyProfile(profile.root.clone());
        profile.prepare().unwrap();
        let (state, data) = profile.paths();
        let pins = profile.admit(&state, &data).unwrap();
        assert!(fs::read_dir(&state).unwrap().next().is_none());
        assert!(fs::read_dir(&data).unwrap().next().is_none());
        drop(pins);
        drop(owned);
        assert!(!profile.root.exists());
    }
}
