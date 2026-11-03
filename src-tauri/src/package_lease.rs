//! Package changes require exclusive ownership; a fence survives interrupted maintenance.
#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
use std::path::PathBuf;
use std::{
    fs::{self, File, OpenOptions},
    path::Path,
    process::Command,
};
const LEASE: &str = ".runtime-lease";
const FENCE: &str = ".package-maintenance";
fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    crate::host_storage::directory(path)?
        .sync_all()
        .map_err(|_| "host_package_state_unavailable")?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn metadata(candidate: &Path, name: &str, file: &File) -> Result<(), String> {
    let root = fs::symlink_metadata(candidate).map_err(|_| "host_package_state_invalid")?;
    let info = file.metadata().map_err(|_| "host_package_state_invalid")?;
    if !root.is_dir() || !info.is_file() || info.len() != 0 {
        return Err("host_package_state_invalid".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let named =
            fs::symlink_metadata(candidate.join(name)).map_err(|_| "host_package_state_invalid")?;
        if unsafe { libc::getuid() } != unsafe { libc::geteuid() }
            || ![0, unsafe { libc::geteuid() }].contains(&root.uid())
            || root.mode() & 0o022 != 0
            || info.uid() != root.uid()
            || info.mode() & 0o022 != 0
            || info.nlink() != 1
            || !named.is_file()
            || named.dev() != info.dev()
            || named.ino() != info.ino()
        {
            return Err("host_package_state_invalid".into());
        }
    }
    #[cfg(target_os = "macos")]
    crate::manager_host::no_acl(&candidate.join(name))?;
    #[cfg(windows)]
    {
        let _ = name;
        crate::host_state::valid_file(file)?;
    }
    Ok(())
}
fn open(candidate: &Path, name: &str, initialize: bool) -> Result<File, String> {
    crate::native_runtime::absolute_directory(candidate)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let root = fs::symlink_metadata(candidate).map_err(|_| "host_package_state_invalid")?;
        if unsafe { libc::getuid() } != unsafe { libc::geteuid() }
            || root.mode() & 0o022 != 0
            || ![0, unsafe { libc::geteuid() }].contains(&root.uid())
        {
            return Err("host_package_state_invalid".into());
        }
    }
    let options = |create| {
        let mut value = OpenOptions::new();
        // Windows requires write access to flush an existing maintenance fence on retry.
        value
            .read(true)
            .write(create || (initialize && name == FENCE))
            .create_new(create);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            value
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            value.share_mode(3).custom_flags(0x00200000);
        }
        value
    };
    let path = candidate.join(name);
    let file = match options(false).open(&path) {
        Ok(file) => file,
        Err(error) if initialize && error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if fs::symlink_metadata(candidate)
                    .map_err(|_| "host_package_state_invalid")?
                    .uid()
                    != unsafe { libc::geteuid() }
                {
                    return Err("host_package_not_initialized".into());
                }
            }
            match options(true).open(&path) {
                Ok(file) => {
                    file.sync_all()
                        .map_err(|_| "host_package_state_unavailable")?;
                    sync_directory(candidate)?;
                    file
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => options(false)
                    .open(&path)
                    .map_err(|_| "host_package_state_unavailable")?,
                Err(_) => return Err("host_package_state_unavailable".into()),
            }
        }
        Err(_) => return Err("host_package_state_unavailable".into()),
    };
    metadata(candidate, name, &file)?;
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        if file.as_raw_fd() <= 2 {
            let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd == -1 {
                return Err("host_package_state_unavailable".into());
            }
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
    }
    Ok(file)
}
pub(crate) struct CodeLease {
    file: File,
    #[cfg(unix)]
    inherited: std::sync::atomic::AtomicBool,
}
impl Drop for CodeLease {
    fn drop(&mut self) {
        #[cfg(unix)]
        if !self.inherited.load(std::sync::atomic::Ordering::Relaxed) {
            // Unrelated forks must not retain a reader that was never handed to a child.
            let _ = self.file.unlock();
        }
    }
}
impl CodeLease {
    pub(crate) fn acquire(candidate: &Path) -> Result<Self, String> {
        let file = open(candidate, LEASE, true)?;
        file.try_lock_shared().map_err(|_| "host_package_busy")?;
        let lease = Self {
            file,
            #[cfg(unix)]
            inherited: std::sync::atomic::AtomicBool::new(false),
        };
        match fs::symlink_metadata(candidate.join(FENCE)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(lease),
            _ => Err("host_package_maintenance".into()),
        }
    }
    pub(crate) fn spawn(&self, command: &mut Command) -> std::io::Result<std::process::Child> {
        #[cfg(unix)]
        {
            use std::os::{fd::AsRawFd, unix::process::CommandExt};
            let fd = self.file.as_raw_fd();
            command.env("FRAMELEAF_CODE_LEASE_FD", fd.to_string());
            // Preserve this already-open inode in Node, including after the desktop owner crashes.
            unsafe {
                command.pre_exec(move || {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags == -1
                        || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        #[cfg(not(unix))]
        let _ = &self.file; // Windows process owners retain the lease through Job Object cleanup.
        let child = command.spawn()?;
        #[cfg(unix)]
        self.inherited
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(child)
    }
}
#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
pub(crate) struct Maintenance {
    candidate: PathBuf,
    _lease: File,
}
#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
impl Drop for Maintenance {
    fn drop(&mut self) {
        // A concurrent fork may retain this open file description until exec closes CLOEXEC copies.
        let _ = self._lease.unlock();
    }
}
#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
impl Maintenance {
    pub(crate) fn acquire(candidate: &Path) -> Result<Self, String> {
        let file = open(candidate, LEASE, true)?;
        file.try_lock().map_err(|_| "host_package_busy")?;
        Ok(Self {
            candidate: candidate.into(),
            _lease: file,
        })
    }
    #[cfg(any(target_os = "macos", target_os = "linux", test))]
    pub(crate) fn fence(&self) -> Result<(), String> {
        let file = open(&self.candidate, FENCE, true)?;
        file.sync_all()
            .map_err(|_| "host_package_state_unavailable")?;
        sync_directory(&self.candidate)
    }
    pub(crate) fn require_unfenced(&self) -> Result<(), String> {
        match fs::symlink_metadata(self.candidate.join(FENCE)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err("host_package_maintenance".into()),
        }
    }
    #[cfg(any(target_os = "macos", target_os = "linux", test))]
    pub(crate) fn finish(&self) -> Result<(), String> {
        match fs::symlink_metadata(self.candidate.join(FENCE)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err("host_package_state_unavailable".into()),
            Ok(_) => {}
        }
        let file = open(&self.candidate, FENCE, false)?;
        metadata(&self.candidate, FENCE, &file)?;
        drop(file);
        fs::remove_file(self.candidate.join(FENCE))
            .map_err(|_| "host_package_state_unavailable")?;
        sync_directory(&self.candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-code-lease-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn readers_exclude_maintenance_and_persistent_fence_excludes_new_readers() {
        let f = Fixture::new();
        let reader = CodeLease::acquire(&f.0).unwrap();
        assert!(Maintenance::acquire(&f.0).is_err());
        drop(reader);
        let writer = Maintenance::acquire(&f.0).unwrap();
        writer.fence().unwrap();
        writer.fence().unwrap();
        drop(writer);
        assert!(CodeLease::acquire(&f.0).is_err());
        Maintenance::acquire(&f.0).unwrap().finish().unwrap();
        CodeLease::acquire(&f.0).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn unhanded_reader_releases_a_lock_even_with_a_fork_style_descriptor_copy() {
        let f = Fixture::new();
        let reader = CodeLease::acquire(&f.0).unwrap();
        let inherited = reader.file.try_clone().unwrap();
        let other_reader = CodeLease::acquire(&f.0).unwrap();
        drop(reader);
        assert!(Maintenance::acquire(&f.0).is_err());
        drop(other_reader);
        let writer = Maintenance::acquire(&f.0).unwrap();
        writer.require_unfenced().unwrap();
        drop(writer);
        drop(inherited);
    }
    #[cfg(unix)]
    #[test]
    fn failed_spawn_releases_the_reader_despite_a_fork_style_descriptor_copy() {
        let f = Fixture::new();
        let reader = CodeLease::acquire(&f.0).unwrap();
        let inherited = reader.file.try_clone().unwrap();
        let mut command = Command::new(f.0.join("missing-native-program"));
        assert!(reader.spawn(&mut command).is_err());
        drop(reader);
        Maintenance::acquire(&f.0)
            .unwrap()
            .require_unfenced()
            .unwrap();
        drop(inherited);
    }
    #[cfg(unix)]
    #[test]
    fn linked_or_write_shared_metadata_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        drop(CodeLease::acquire(&f.0).unwrap());
        let path = f.0.join(LEASE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(CodeLease::acquire(&f.0).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::hard_link(&path, f.0.join("alias")).unwrap();
        assert!(CodeLease::acquire(&f.0).is_err());
        std::fs::remove_file(f.0.join("alias")).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(f.0.join("foreign"), &path).unwrap();
        assert!(CodeLease::acquire(&f.0).is_err());
        assert!(!f.0.join("foreign").exists());
    }
    #[cfg(unix)]
    #[test]
    fn node_retains_the_open_code_lease_after_the_desktop_copy_is_closed() {
        use std::io::{BufRead, BufReader};
        use std::process::Stdio;
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let f = Fixture::new();
        let lease = CodeLease::acquire(&f.0).unwrap();
        let mut command = Command::new("node");
        command.args(["-e", "require('node:fs').fstatSync(Number(process.env.FRAMELEAF_CODE_LEASE_FD)); console.log('lease-ready'); process.stdin.resume();"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child = Child(lease.spawn(&mut command).unwrap());
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "lease-ready\n");
        drop(lease);
        assert!(Maintenance::acquire(&f.0).is_err());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        Maintenance::acquire(&f.0).unwrap();
    }
    #[test]
    fn profile_provisioning_never_clears_an_installers_persistent_fence() {
        let f = Fixture::new();
        let writer = Maintenance::acquire(&f.0).unwrap();
        writer.require_unfenced().unwrap();
        writer.fence().unwrap();
        assert_eq!(
            writer.require_unfenced().unwrap_err(),
            "host_package_maintenance"
        );
        drop(writer);
        let writer = Maintenance::acquire(&f.0).unwrap();
        assert!(writer.require_unfenced().is_err());
        drop(writer);
        assert!(f.0.join(FENCE).exists());
        assert!(CodeLease::acquire(&f.0).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn maintenance_drop_releases_a_lock_even_with_a_fork_style_descriptor_copy() {
        let f = Fixture::new();
        let writer = Maintenance::acquire(&f.0).unwrap();
        writer.fence().unwrap();
        let inherited = writer._lease.try_clone().unwrap();
        drop(writer);
        let replacement = Maintenance::acquire(&f.0).unwrap();
        assert!(replacement.require_unfenced().is_err());
        drop(replacement);
        drop(inherited);
        assert!(f.0.join(FENCE).exists());
    }
    #[test]
    fn malformed_fences_stay_closed_instead_of_being_discarded() {
        let f = Fixture::new();
        let writer = Maintenance::acquire(&f.0).unwrap();
        writer.fence().unwrap();
        std::fs::write(f.0.join(FENCE), b"not a valid maintenance inode").unwrap();
        assert!(writer.finish().is_err());
        drop(writer);
        assert!(CodeLease::acquire(&f.0).is_err());
        assert!(f.0.join(FENCE).exists());
    }
}
