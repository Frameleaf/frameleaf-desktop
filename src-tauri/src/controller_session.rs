//! The controller locates the logged-in user's bus independently of its parent environment.

use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
};
const ERROR: &str = "credential_store_locked_or_unavailable";

fn admit_directory(path: &Path, user: u32, private: bool) -> Result<(), String> {
    let info = fs::symlink_metadata(path).map_err(|_| ERROR)?;
    if !info.is_dir()
        || info.uid() != user
        || if private {
            info.mode() & 0o7777 != 0o700
        } else {
            info.mode() & 0o022 != 0
        }
    {
        return Err(ERROR.into());
    }
    Ok(())
}
fn admit_runtime(path: &Path, user: u32) -> Result<(), String> {
    admit_directory(path, user, true)?;
    let bus = fs::symlink_metadata(path.join("bus")).map_err(|_| ERROR)?;
    if !bus.file_type().is_socket() || bus.uid() != user || bus.nlink() != 1 {
        return Err(ERROR.into());
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn directory() -> Result<std::path::PathBuf, String> {
    let user = unsafe { libc::getuid() };
    if user == 0 || user == u32::MAX || unsafe { libc::geteuid() } != user {
        return Err(ERROR.into());
    }
    for parent in ["/", "/run", "/run/user"] {
        admit_directory(Path::new(parent), 0, false)?;
    }
    let path = Path::new("/run/user").join(user.to_string());
    admit_runtime(&path, user)?;
    Ok(path)
}
#[cfg(target_os = "linux")]
pub fn directory_for_mode(
    arguments: &[std::ffi::OsString],
) -> Result<Option<std::path::PathBuf>, String> {
    let owner = matches!(arguments, [mode] if mode == "--owner-pipe");
    let qualification = cfg!(debug_assertions)
        && matches!(arguments, [mode, _] if mode == "--qualify-credential-access")
        && std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
        && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted")
        && std::env::var("FRAMELEAF_TEST_DISPOSABLE_KEYSTORE").as_deref() == Ok("1");
    if owner || qualification {
        directory().map(Some)
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, net::UnixListener},
        path::PathBuf,
    };
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> Fixture {
        let path = PathBuf::from("/tmp").join(format!("fl-session-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Fixture(path)
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn installer_and_inspection_modes_never_require_a_user_session() {
        for arguments in [
            vec!["--inspect-owner"],
            vec!["--prepare-install", "manifest", "controller"],
            vec!["--provision-profile", "manifest", "controller", "1000"],
            vec!["--owner-pipe", "unexpected"],
            vec![],
        ] {
            let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
            assert!(directory_for_mode(&arguments).unwrap().is_none());
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "read-only check requiring a preconfigured disposable /run/user/<uid>/bus"]
    fn os_runtime_location_ignores_parent_session_environment() {
        let expected =
            std::path::Path::new("/run/user").join(unsafe { libc::getuid() }.to_string());
        assert_eq!(directory().unwrap(), expected);
        assert_eq!(
            directory_for_mode(&["--owner-pipe".into()]).unwrap(),
            Some(expected)
        );
    }
    #[test]
    fn current_user_private_runtime_requires_an_existing_owned_socket() {
        let root = fixture();
        let uid = unsafe { libc::geteuid() };
        assert!(admit_runtime(&root.0, uid).is_err());
        fs::write(root.0.join("bus"), b"preserve").unwrap();
        assert!(admit_runtime(&root.0, uid).is_err());
        assert_eq!(fs::read(root.0.join("bus")).unwrap(), b"preserve");
        fs::remove_file(root.0.join("bus")).unwrap();
        let _bus = UnixListener::bind(root.0.join("bus")).unwrap();
        admit_runtime(&root.0, uid).unwrap();
        assert!(admit_runtime(&root.0, uid + 1).is_err());
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(admit_runtime(&root.0, uid).is_err());
    }
    #[test]
    fn linked_runtime_or_socket_cannot_select_another_session() {
        let root = fixture();
        let uid = unsafe { libc::geteuid() };
        let _bus = UnixListener::bind(root.0.join("real-bus")).unwrap();
        std::os::unix::fs::symlink(root.0.join("real-bus"), root.0.join("bus")).unwrap();
        assert!(admit_runtime(&root.0, uid).is_err());
        let alias = root.0.with_extension("alias");
        std::os::unix::fs::symlink(&root.0, &alias).unwrap();
        assert!(admit_runtime(&alias, uid).is_err());
        fs::remove_file(alias).unwrap();
        assert!(root.0.join("real-bus").exists());
    }
    #[test]
    fn trusted_parent_refuses_wrong_owner_write_permissions_and_links() {
        let root = fixture();
        let uid = unsafe { libc::geteuid() };
        admit_directory(&root.0, uid, false).unwrap();
        assert!(admit_directory(&root.0, uid + 1, false).is_err());
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(admit_directory(&root.0, uid, false).is_err());
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755)).unwrap();
        admit_directory(&root.0, uid, false).unwrap();
        let alias = root.0.with_extension("alias");
        std::os::unix::fs::symlink(&root.0, &alias).unwrap();
        assert!(admit_directory(&alias, uid, false).is_err());
        fs::remove_file(alias).unwrap();
    }
}
