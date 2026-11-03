//! Fixed-path installer phases only; never starts a host or reads a user's library.
use std::path::PathBuf;
#[cfg(windows)]
mod windows;
#[cfg(target_os = "linux")]
const BASE: &str = "/opt/frameleaf";
#[cfg(all(not(target_os = "linux"), not(windows)))]
const BASE: &str = "/Library/Application Support/Frameleaf";
pub struct Layout {
    pub runtime: PathBuf,
    pub controller: PathBuf,
    pub profiles: PathBuf,
}
#[cfg(windows)]
pub(crate) fn windows_local_app_data() -> Result<PathBuf, String> {
    windows::local_app_data()
}
#[cfg(windows)]
pub(crate) fn windows_profiles_root() -> Result<PathBuf, String> {
    Ok(windows::base()?.join("Profiles"))
}
impl Layout {
    pub fn new(manifest: &str, controller: &str) -> Result<Self, String> {
        if !crate::native_runtime::digest_valid(manifest, 64)
            || !crate::native_runtime::digest_valid(controller, 64)
        {
            return Err("host_install_identity_invalid".into());
        }
        #[cfg(windows)]
        let base = windows::base()?;
        #[cfg(not(windows))]
        let base = PathBuf::from(BASE);
        Ok(Self {
            runtime: base.join("Runtimes").join(manifest),
            controller: base
                .join("Controllers")
                .join(manifest)
                .join(controller)
                .join(if cfg!(windows) {
                    "frameleaf-native-host.exe"
                } else {
                    "frameleaf-native-host"
                }),
            profiles: base.join("Profiles"),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Installation {
    schema_version: u32,
    pub manifest_sha256: String,
    pub controller_sha256: String,
}
impl Installation {
    fn decode(raw: &[u8]) -> Result<Self, String> {
        let record: Self =
            serde_json::from_slice(raw).map_err(|_| "host_install_record_invalid")?;
        if record.schema_version != 1 {
            return Err("host_install_record_invalid".into());
        }
        record.layout()?;
        Ok(record)
    }
    pub(crate) fn layout(&self) -> Result<Layout, String> {
        Layout::new(&self.manifest_sha256, &self.controller_sha256)
    }
    pub(crate) fn read(manifest: &str) -> Result<Self, String> {
        let candidate = Layout::new(manifest, &"0".repeat(64))?.runtime;
        let path = candidate.join("installation.json");
        crate::manager_host::protect(&path, &mut std::collections::BTreeSet::new())?;
        let record = Self::decode(&crate::runtime_store::read_bounded(&path, 4096)?)?;
        if record.manifest_sha256 != manifest {
            return Err("host_install_record_invalid".into());
        }
        crate::manager_host::protect(
            &record.layout()?.controller,
            &mut std::collections::BTreeSet::new(),
        )?;
        Ok(record)
    }
}
/// Read existing protected machine installations without creating or starting a runtime.
pub(crate) fn installed() -> Result<Vec<Installation>, String> {
    if !cfg!(any(target_os = "macos", target_os = "linux", windows)) {
        return Err("host_install_platform_unsupported".into());
    }
    #[cfg(windows)]
    let root = windows::base()?.join("Runtimes");
    #[cfg(not(windows))]
    let root = PathBuf::from(BASE).join("Runtimes");
    installed_records(
        &root,
        |path| crate::manager_host::protect(path, &mut std::collections::BTreeSet::new()),
        Installation::read,
    )
}

/// Protect each bounded inventory entry before reading its receipt; omit unfinished versions.
fn installed_records(
    root: &std::path::Path,
    mut protect: impl FnMut(&std::path::Path) -> Result<(), String>,
    mut read: impl FnMut(&str) -> Result<Installation, String>,
) -> Result<Vec<Installation>, String> {
    match std::fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("host_install_record_invalid".into()),
        Ok(_) => {}
    }
    protect(root)?;
    let mut records = Vec::new();
    for (index, entry) in std::fs::read_dir(root)
        .map_err(|_| "host_install_record_invalid")?
        .enumerate()
    {
        if index >= 64 {
            return Err("host_install_inventory_limit".into());
        }
        let entry = entry.map_err(|_| "host_install_record_invalid")?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("host_install_record_invalid")?;
        if !crate::native_runtime::digest_valid(name, 64) {
            return Err("host_install_identity_invalid".into());
        }
        let candidate = root.join(name);
        protect(&candidate)?;
        if !std::fs::symlink_metadata(&candidate)
            .map_err(|_| "host_install_record_invalid")?
            .is_dir()
        {
            return Err("host_install_record_invalid".into());
        }
        if receipt_present(&candidate.join("installation.json"))? {
            records.push(read(name)?);
        }
    }
    records.sort_by(|a, b| a.manifest_sha256.cmp(&b.manifest_sha256));
    Ok(records)
}

fn receipt_present(path: &std::path::Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Ok(_) => Ok(true),
        Err(_) => Err("host_install_record_invalid".into()),
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
fn finalization_guard(
    candidate: &std::path::Path,
    finish_maintenance: bool,
    verify: impl FnOnce() -> Result<(), String>,
) -> Result<crate::package_lease::Maintenance, String> {
    let guard = crate::package_lease::Maintenance::acquire(candidate)?;
    if !finish_maintenance {
        guard.require_unfenced()?;
    }
    verify()?;
    Ok(guard)
}

fn admit_versions(
    layout: &Layout,
    verify: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let paths = [
        &layout.runtime,
        layout
            .controller
            .parent()
            .ok_or("host_install_path_invalid")?,
    ];
    let mut present = 0;
    for path in paths {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(metadata) if metadata.is_dir() => present += 1,
            _ => return Err("host_install_version_exists".into()),
        }
    }
    match present {
        0 => Ok(()),
        2 => verify(),
        _ => Err("host_install_version_exists".into()),
    }
}

fn verify_resources(layout: &Layout, manifest: &str, controller: &str) -> Result<(), String> {
    use crate::manager_host::protect;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    protect(&layout.runtime, &mut BTreeSet::new())?;
    protect(&layout.controller, &mut BTreeSet::new())?;
    let binary = crate::runtime_store::read_bounded(&layout.controller, 256 * 1024 * 1024)?;
    if format!("{:x}", Sha256::digest(binary)) != controller {
        return Err("host_install_controller_changed".into());
    }
    let raw = crate::runtime_store::read_bounded(
        &layout.runtime.join("manifest.json"),
        16 * 1024 * 1024,
    )?;
    let signature: [u8; 64] =
        crate::runtime_store::read_bounded(&layout.runtime.join("manifest.sig"), 64)?
            .try_into()
            .map_err(|_| "host_signature_invalid")?;
    let runtime = crate::release_policy::verify_host_runtime(
        &layout.runtime.join("payload"),
        &raw,
        &signature,
    )?;
    if runtime.manifest_sha256() != manifest {
        return Err("host_install_runtime_changed".into());
    }
    runtime.manager_programs()?;
    if receipt_present(&layout.runtime.join("installation.json"))?
        && Installation::read(manifest)?.controller_sha256 != controller
    {
        return Err("host_install_record_invalid".into());
    }
    Ok(())
}
/// Installer-only fresh Windows package preparation; never starts or replaces a runtime.
pub fn prepare_windows_package(
    manifest: &str,
    controller: &str,
) -> Result<serde_json::Value, String> {
    #[cfg(windows)]
    {
        windows::package::prepare(manifest, controller)
    }
    #[cfg(not(windows))]
    {
        let _ = (manifest, controller);
        Err("host_install_platform_unsupported".into())
    }
}

/// Fresh Windows installer finalization; no profile provisioning or host startup.
pub fn finalize_windows_package(
    manifest: &str,
    controller: &str,
) -> Result<serde_json::Value, String> {
    #[cfg(windows)]
    {
        windows::package::finalize(manifest, controller)
    }
    #[cfg(not(windows))]
    {
        let _ = (manifest, controller);
        Err("host_install_platform_unsupported".into())
    }
}

pub fn prepare(manifest: &str, controller: &str) -> Result<serde_json::Value, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        posix::root()?;
        posix::prepare(&Layout::new(manifest, controller)?, manifest, controller)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (manifest, controller);
        Err("host_install_platform_unsupported".into())
    }
}
pub fn finalize(manifest: &str, controller: &str) -> Result<serde_json::Value, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        posix::root()?;
        #[cfg(target_os = "macos")]
        let user = posix::console_user();
        #[cfg(target_os = "linux")]
        let user = None;
        posix::finalize(
            &Layout::new(manifest, controller)?,
            manifest,
            controller,
            user,
            true,
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (manifest, controller);
        Err("host_install_platform_unsupported".into())
    }
}
/// Installer-only fencing; no arbitrary destination, credentials, process IDs or command cross this API.
pub fn prepare_maintenance(manifest: &str, controller: &str) -> Result<serde_json::Value, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        posix::root()?;
        let layout = Layout::new(manifest, controller)?;
        verify_resources(&layout, manifest, controller)?;
        posix::fence(&layout)?;
        Ok(
            serde_json::json!({"protocolVersion":1,"state":"maintenance-prepared","serverStarted":false}),
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (manifest, controller);
        Err("host_install_platform_unsupported".into())
    }
}
/// Fence a damaged component for replacement without executing or trusting its payload.
pub fn prepare_repair(manifest: &str, controller: &str) -> Result<serde_json::Value, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        posix::root()?;
        let layout = Layout::new(manifest, controller)?;
        posix::repair(&layout, manifest, controller)?;
        Ok(
            serde_json::json!({"protocolVersion":1,"state":"repair-prepared","serverStarted":false,"runtimeQualified":false}),
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (manifest, controller);
        Err("host_install_platform_unsupported".into())
    }
}
/// Debian's trusted bootstrap prepares replacement even if the versioned controller is missing.
pub fn prepare_linux_package(
    manifest: &str,
    controller: &str,
) -> Result<serde_json::Value, String> {
    #[cfg(target_os = "linux")]
    {
        posix::root()?;
        posix::prepare_linux_package(&Layout::new(manifest, controller)?, manifest, controller)?;
        Ok(
            serde_json::json!({"protocolVersion":1,"state":"package-prepared","serverStarted":false,"runtimeQualified":false}),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (manifest, controller);
        Err("host_install_platform_unsupported".into())
    }
}
#[cfg(any(target_os = "linux", all(test, unix)))]
fn package_bootstrap(
    path: &std::path::Path,
    digest: &str,
    protect: impl FnOnce(&std::path::Path) -> Result<(), String>,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    protect(path)?;
    let info = std::fs::symlink_metadata(path).map_err(|_| "host_install_controller_changed")?;
    if !info.is_file() || info.nlink() != 1 || info.mode() & 0o022 != 0 || info.mode() & 0o111 == 0
    {
        return Err("host_install_controller_changed".into());
    }
    let binary = crate::runtime_store::read_bounded(path, 256 * 1024 * 1024)?;
    if binary.is_empty() || format!("{:x}", Sha256::digest(binary)) != digest {
        return Err("host_install_controller_changed".into());
    }
    Ok(())
}
#[cfg(any(target_os = "linux", all(test, unix)))]
fn package_tree(
    layout: &Layout,
    manifest: &str,
    controller: &str,
    mut protect: impl FnMut(&std::path::Path) -> Result<(), String>,
) -> Result<(), String> {
    use std::{fs, io::ErrorKind};
    repair_tree(&layout.runtime, 100_000, &mut protect)?;
    let directory = layout
        .controller
        .parent()
        .ok_or("host_install_path_invalid")?;
    match fs::symlink_metadata(directory) {
        Ok(info) if info.is_dir() => {
            repair_tree(directory, 100_000, &mut protect)?;
            match fs::symlink_metadata(&layout.controller) {
                Ok(info) if info.is_file() => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                _ => return Err("host_install_repair_path_invalid".into()),
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        _ => return Err("host_install_repair_path_invalid".into()),
    }
    let path = layout.runtime.join("installation.json");
    if receipt_present(&path)? {
        // The installed controller may be gone; the protected receipt still must name this identity.
        let record = Installation::decode(&crate::runtime_store::read_bounded(&path, 4096)?)?;
        if record.manifest_sha256 != manifest || record.controller_sha256 != controller {
            return Err("host_install_record_invalid".into());
        }
    }
    Ok(())
}
#[cfg(any(target_os = "macos", target_os = "linux", all(test, unix)))]
fn repair_guard(
    candidate: &std::path::Path,
    verify: impl FnOnce() -> Result<(), String>,
    profiles_idle: impl FnOnce() -> Result<(), String>,
) -> Result<crate::package_lease::Maintenance, String> {
    let guard = crate::package_lease::Maintenance::acquire(candidate)?;
    verify()?;
    profiles_idle()?;
    guard.fence()?;
    Ok(guard)
}
#[cfg(any(target_os = "macos", target_os = "linux", all(test, unix)))]
fn repair_tree(
    root: &std::path::Path,
    limit: usize,
    mut protect: impl FnMut(&std::path::Path) -> Result<(), String>,
) -> Result<(), String> {
    use std::{fs, os::unix::fs::MetadataExt};
    let mut pending = vec![root.to_owned()];
    let mut entries = 1;
    if limit == 0 {
        return Err("host_install_inventory_limit".into());
    }
    while let Some(path) = pending.pop() {
        let info = fs::symlink_metadata(&path).map_err(|_| "host_install_repair_path_invalid")?;
        if (!info.is_dir() && !info.is_file())
            || info.mode() & 0o022 != 0
            || (info.is_file() && info.nlink() != 1)
        {
            return Err("host_install_repair_path_invalid".into());
        }
        protect(&path)?;
        if info.is_dir() {
            for entry in fs::read_dir(&path).map_err(|_| "host_install_repair_path_invalid")? {
                if entries >= limit {
                    return Err("host_install_inventory_limit".into());
                }
                entries += 1;
                pending.push(
                    entry
                        .map_err(|_| "host_install_repair_path_invalid")?
                        .path(),
                );
            }
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
pub(crate) fn verify_for_profile(record: &Installation) -> Result<(), String> {
    let layout = record.layout()?;
    let _lease = crate::package_lease::CodeLease::acquire(&layout.runtime)?;
    verify_resources(&layout, &record.manifest_sha256, &record.controller_sha256)
}
/// Linux installers explicitly select the account; a package-manager process has no console user.
pub fn provision(manifest: &str, controller: &str, uid: &str) -> Result<serde_json::Value, String> {
    #[cfg(target_os = "linux")]
    {
        posix::root()?;
        let uid = parse_linux_profile_uid(uid)?;
        let record = Installation::read(manifest)?;
        if record.controller_sha256 != controller {
            return Err("host_install_controller_changed".into());
        }
        let user = posix::linux_user(uid)?;
        posix::finalize(&record.layout()?, manifest, controller, Some(user), false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (manifest, controller, uid);
        Err("host_install_platform_unsupported".into())
    }
}
#[cfg(any(target_os = "linux", test))]
fn parse_linux_profile_uid(value: &str) -> Result<u32, String> {
    let uid: u32 = value
        .parse()
        .map_err(|_| "host_install_profile_user_invalid")?;
    if uid == 0 || uid == u32::MAX || value != uid.to_string() {
        return Err("host_install_profile_user_invalid".into());
    }
    Ok(uid)
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod posix {
    use super::*;
    use crate::manager_host::protect;
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeSet,
        fs,
        os::{
            fd::AsRawFd,
            unix::fs::{DirBuilderExt, MetadataExt},
        },
        path::Path,
    };
    pub(super) fn root() -> Result<(), String> {
        if unsafe { libc::geteuid() } != 0 || unsafe { libc::getuid() } != 0 {
            return Err("host_install_root_required".into());
        }
        Ok(())
    }
    fn root_directory(path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                protect(
                    path.parent().ok_or("host_install_path_invalid")?,
                    &mut BTreeSet::new(),
                )?;
                fs::DirBuilder::new()
                    .mode(0o755)
                    .create(path)
                    .map_err(|_| "host_install_directory_failed")?;
                let directory = crate::host_storage::directory(path)?;
                if unsafe { libc::fchmod(directory.as_raw_fd(), 0o755) } != 0 {
                    return Err("host_install_directory_failed".into());
                }
            }
            _ => return Err("host_install_directory_invalid".into()),
        }
        protect(path, &mut BTreeSet::new())?;
        if fs::symlink_metadata(path)
            .map_err(|_| "host_install_directory_failed")?
            .mode()
            & 0o005
            != 0o005
        {
            return Err("host_install_directory_inaccessible".into());
        }
        Ok(())
    }
    pub(super) fn prepare(
        layout: &Layout,
        manifest: &str,
        controller: &str,
    ) -> Result<serde_json::Value, String> {
        protect(
            Path::new(BASE)
                .parent()
                .ok_or("host_install_path_invalid")?,
            &mut BTreeSet::new(),
        )?;
        for path in [
            Path::new(BASE),
            &PathBuf::from(BASE).join("Runtimes"),
            &PathBuf::from(BASE).join("Controllers"),
            &PathBuf::from(BASE).join("Controllers").join(manifest),
            &layout.profiles,
        ] {
            root_directory(path)?;
        }
        // Byte-identical reinstall can provision a missing console-user profile.
        admit_versions(layout, || verify_resources(layout, manifest, controller))?;
        if layout.runtime.exists() {
            fence(layout)?;
        }
        Ok(
            serde_json::json!({"protocolVersion":1,"state":"install-prepared","serverStarted":false}),
        )
    }
    #[cfg(target_os = "macos")]
    pub(super) fn console_user() -> Option<(u32, u32)> {
        #[link(name = "SystemConfiguration", kind = "framework")]
        unsafe extern "C" {
            fn SCDynamicStoreCopyConsoleUser(
                store: *const libc::c_void,
                uid: *mut libc::uid_t,
                gid: *mut libc::gid_t,
            ) -> *const libc::c_void;
        }
        let mut uid = 0;
        let mut gid = 0;
        let user = unsafe { SCDynamicStoreCopyConsoleUser(std::ptr::null(), &mut uid, &mut gid) };
        if user.is_null() {
            return None;
        }
        unsafe {
            core_foundation::base::CFRelease(user);
        }
        if uid < 501 || uid == u32::MAX || gid == u32::MAX {
            None
        } else {
            Some((uid, gid))
        }
    }
    #[cfg(target_os = "linux")]
    pub(super) fn linux_user(uid: u32) -> Result<(u32, u32), String> {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status != 0 || result.is_null() {
            return Err("host_install_profile_user_invalid".into());
        }
        let entry = unsafe { entry.assume_init() };
        if entry.pw_uid != uid || entry.pw_gid == u32::MAX {
            return Err("host_install_profile_user_invalid".into());
        }
        Ok((uid, entry.pw_gid))
    }
    fn private_leaf(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
        protect(
            path.parent().ok_or("host_install_path_invalid")?,
            &mut BTreeSet::new(),
        )?;
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o7777 != 0o700 {
                    return Err("host_install_profile_changed".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(path)
                    .map_err(|_| "host_install_profile_failed")?;
                let file = crate::host_storage::directory(path)?;
                if unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } != 0
                    || unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0
                {
                    return Err("host_install_profile_failed".into());
                }
            }
            Err(_) => return Err("host_install_profile_failed".into()),
        }
        #[cfg(target_os = "macos")]
        crate::manager_host::no_acl(path)?;
        Ok(())
    }
    fn write_record(layout: &Layout, manifest: &str, controller: &str) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let record = Installation {
            schema_version: 1,
            manifest_sha256: manifest.into(),
            controller_sha256: controller.into(),
        };
        let path = layout.runtime.join("installation.json");
        if receipt_present(&path)? {
            if Installation::read(manifest)? != record {
                return Err("host_install_record_invalid".into());
            }
            return Ok(());
        }
        let temp = format!(".installation-{}.tmp", uuid::Uuid::new_v4());
        let temp_path = layout.runtime.join(&temp);
        let result = (|| -> Result<(), String> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temp_path)
                .map_err(|_| "host_install_record_failed")?;
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0 {
                return Err("host_install_record_failed".into());
            }
            file.write_all(&serde_json::to_vec(&record).map_err(|_| "host_install_record_failed")?)
                .and_then(|_| file.sync_all())
                .map_err(|_| "host_install_record_failed")?;
            let directory = crate::host_storage::directory(&layout.runtime)?;
            let source =
                std::ffi::CString::new(temp.as_str()).map_err(|_| "host_install_record_failed")?;
            // A receipt becomes discoverable only after all its bytes are durable.
            #[cfg(target_os = "macos")]
            let published = unsafe {
                libc::renameatx_np(
                    directory.as_raw_fd(),
                    source.as_ptr(),
                    directory.as_raw_fd(),
                    c"installation.json".as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            #[cfg(target_os = "linux")]
            let published = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    directory.as_raw_fd(),
                    source.as_ptr(),
                    directory.as_raw_fd(),
                    c"installation.json".as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if published != 0 {
                return Err("host_install_record_failed".into());
            }
            directory
                .sync_all()
                .map_err(|_| "host_install_record_failed")?;
            protect(&path, &mut BTreeSet::new())
        })();
        let cleanup = fs::remove_file(&temp_path);
        result?;
        if cleanup.is_err_and(|error| error.kind() != std::io::ErrorKind::NotFound) {
            return Err("host_install_record_failed".into());
        }
        Ok(())
    }
    fn profiles_idle(layout: &Layout) -> Result<(), String> {
        protect(&layout.profiles, &mut BTreeSet::new())?;
        for (index, entry) in fs::read_dir(&layout.profiles)
            .map_err(|_| "host_install_profile_changed")?
            .enumerate()
        {
            if index >= 1024 {
                return Err("host_install_profile_limit".into());
            }
            let entry = entry.map_err(|_| "host_install_profile_changed")?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("host_install_profile_changed")?;
            let uid: u32 = name.parse().map_err(|_| "host_install_profile_changed")?;
            if uid == 0 || name != uid.to_string() {
                return Err("host_install_profile_changed".into());
            }
            protect(&entry.path(), &mut BTreeSet::new())?;
            let state = entry.path().join("state");
            match fs::symlink_metadata(&state) {
                Ok(info) => {
                    if !info.is_dir() || info.uid() != uid || info.mode() & 0o7777 != 0o700 {
                        return Err("host_install_profile_changed".into());
                    }
                    #[cfg(target_os = "macos")]
                    crate::manager_host::no_acl(&state)?;
                    crate::host_state::Owner::package_idle(&state)?;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && fs::read_dir(entry.path())
                            .map_err(|_| "host_install_profile_changed")?
                            .next()
                            .is_none() => {}
                _ => return Err("host_install_profile_changed".into()),
            }
        }
        Ok(())
    }
    pub(super) fn fence(layout: &Layout) -> Result<(), String> {
        let writer = crate::package_lease::Maintenance::acquire(&layout.runtime)?;
        profiles_idle(layout)?;
        writer.fence()
    }
    pub(super) fn repair(layout: &Layout, manifest: &str, controller: &str) -> Result<(), String> {
        protect(&layout.runtime, &mut BTreeSet::new())?;
        let _guard = repair_guard(
            &layout.runtime,
            || {
                let mut checked = BTreeSet::new();
                protect(&layout.controller, &mut checked)?;
                let binary =
                    crate::runtime_store::read_bounded(&layout.controller, 256 * 1024 * 1024)?;
                if format!("{:x}", Sha256::digest(binary)) != controller {
                    return Err("host_install_controller_changed".into());
                }
                repair_tree(&layout.runtime, 100_000, |path| protect(path, &mut checked))?;
                if receipt_present(&layout.runtime.join("installation.json"))?
                    && Installation::read(manifest)?.controller_sha256 != controller
                {
                    return Err("host_install_record_invalid".into());
                }
                Ok(())
            },
            || profiles_idle(layout),
        )?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub(super) fn prepare_linux_package(
        layout: &Layout,
        manifest: &str,
        controller: &str,
    ) -> Result<(), String> {
        let bootstrap = PathBuf::from(BASE)
            .join("Bootstrap")
            .join(controller)
            .join("frameleaf-native-host");
        let verify = || {
            package_bootstrap(&bootstrap, controller, |path| {
                protect(path, &mut BTreeSet::new())
            })
        };
        verify()?;
        root_directory(&PathBuf::from(BASE).join("Runtimes"))?;
        root_directory(&layout.runtime)?;
        let _guard = repair_guard(
            &layout.runtime,
            || {
                verify()?;
                for path in [
                    PathBuf::from(BASE).join("Controllers"),
                    PathBuf::from(BASE).join("Controllers").join(manifest),
                    layout.profiles.clone(),
                ] {
                    root_directory(&path)?;
                }
                let mut checked = BTreeSet::new();
                package_tree(layout, manifest, controller, |path| {
                    protect(path, &mut checked)
                })
            },
            || profiles_idle(layout),
        )?;
        Ok(())
    }
    pub(super) fn finalize(
        layout: &Layout,
        manifest: &str,
        controller: &str,
        user: Option<(u32, u32)>,
        finish_maintenance: bool,
    ) -> Result<serde_json::Value, String> {
        protect(&layout.runtime, &mut BTreeSet::new())?;
        let writer = finalization_guard(&layout.runtime, finish_maintenance, || {
            verify_resources(layout, manifest, controller)
        })?;
        root_directory(&layout.profiles)?;
        if let Some((uid, gid)) = user {
            let parent = layout.profiles.join(uid.to_string());
            root_directory(&parent)?;
            private_leaf(&parent.join("state"), uid, gid)?;
            private_leaf(&parent.join("manager"), uid, gid)?;
        }
        write_record(layout, manifest, controller)?;
        if layout
            .runtime
            .join(".package-maintenance")
            .try_exists()
            .map_err(|_| "host_package_state_unavailable")?
        {
            profiles_idle(layout)?;
        }
        if finish_maintenance {
            writer.finish()?;
        }
        Ok(
            serde_json::json!({"protocolVersion":1,"state":"resources-installed","profileReady":user.is_some(),"manifestSha256":manifest,"controllerSha256":controller,"serverStarted":false,"runtimeQualified":false,"redistributable":false}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct InventoryFixture(PathBuf);
    impl InventoryFixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("frameleaf-inventory-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for InventoryFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    /// Missing and unfinished versions stay untouched; receipt reads require protected ancestry.
    fn inventory_is_read_only_bounded_and_reads_only_protected_complete_versions() {
        use std::{cell::RefCell, collections::BTreeSet};
        let fixture = InventoryFixture::new();
        let root = fixture.0.join("Runtimes");
        assert!(installed_records(
            &root,
            |_| panic!("absent root must not be inspected"),
            |_| panic!("absent root has no receipts")
        )
        .unwrap()
        .is_empty());
        assert!(!root.exists());
        std::fs::create_dir(&root).unwrap();
        for name in ["c".repeat(64), "b".repeat(64), "a".repeat(64)] {
            let directory = root.join(&name);
            std::fs::create_dir(&directory).unwrap();
            if !name.starts_with('b') {
                std::fs::write(directory.join("installation.json"), serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"manifestSha256":name,"controllerSha256":"d".repeat(64)})).unwrap()).unwrap();
            }
        }
        let visited = RefCell::new(BTreeSet::new());
        let records = installed_records(
            &root,
            |path| {
                visited.borrow_mut().insert(path.to_owned());
                Ok(())
            },
            |name| {
                assert!(visited.borrow().contains(&root));
                assert!(visited.borrow().contains(&root.join(name)));
                Installation::decode(
                    &std::fs::read(root.join(name).join("installation.json")).unwrap(),
                )
            },
        )
        .unwrap();
        assert_eq!(
            records
                .iter()
                .map(|r| r.manifest_sha256.as_str())
                .collect::<Vec<_>>(),
            [&"a".repeat(64), &"c".repeat(64)]
        );
        assert_eq!(visited.borrow().len(), 4);
        assert_eq!(
            installed_records(
                &root,
                |_| Err("trust_refused".into()),
                |_| panic!("must protect before reading")
            )
            .unwrap_err(),
            "trust_refused"
        );
        std::fs::write(
            root.join("c".repeat(64)).join("installation.json"),
            b"malformed",
        )
        .unwrap();
        assert!(installed_records(
            &root,
            |_| Ok(()),
            |name| Installation::decode(
                &std::fs::read(root.join(name).join("installation.json")).unwrap()
            )
        )
        .is_err());
    }
    #[test]
    /// Malformed inventories must fail rather than return a partial installation list.
    fn inventory_refuses_invalid_names_files_and_more_than_64_versions() {
        let fixture = InventoryFixture::new();
        let root = &fixture.0;
        let forbidden = root.join("not-a-manifest");
        std::fs::create_dir(&forbidden).unwrap();
        assert!(installed_records(
            root,
            |_| Ok(()),
            |_| panic!("invalid name has no authority")
        )
        .is_err());
        std::fs::remove_dir(forbidden).unwrap();
        let file = root.join("a".repeat(64));
        std::fs::write(&file, b"not a directory").unwrap();
        assert!(installed_records(
            root,
            |_| Ok(()),
            |_| panic!("file is not an installed version")
        )
        .is_err());
        std::fs::remove_file(&file).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root, &file).unwrap();
            assert!(
                installed_records(root, |_| Ok(()), |_| panic!("linked version must refuse"))
                    .is_err()
            );
            std::fs::remove_file(file).unwrap();
        }
        for index in 0..65 {
            std::fs::create_dir(root.join(format!("{index:064x}"))).unwrap();
        }
        assert_eq!(
            installed_records(
                root,
                |_| Ok(()),
                |_| panic!("unfinished versions have no receipts")
            )
            .unwrap_err(),
            "host_install_inventory_limit"
        );
    }
    #[cfg(unix)]
    struct RepairFixture(PathBuf);
    #[cfg(unix)]
    impl RepairFixture {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-repair-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    #[cfg(unix)]
    impl Drop for RepairFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[cfg(unix)]
    #[test]
    fn repair_admission_owns_code_before_validation_and_preserves_fences() {
        let f = RepairFixture::new();
        let calls = std::cell::Cell::new(0);
        let reader = crate::package_lease::CodeLease::acquire(&f.0).unwrap();
        assert!(repair_guard(
            &f.0,
            || {
                calls.set(1);
                Ok(())
            },
            || Ok(())
        )
        .is_err());
        assert_eq!(calls.get(), 0);
        drop(reader);
        let guard = repair_guard(
            &f.0,
            || {
                assert!(crate::package_lease::CodeLease::acquire(&f.0).is_err());
                calls.set(1);
                Ok(())
            },
            || {
                assert_eq!(calls.get(), 1);
                calls.set(2);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 2);
        assert!(f.0.join(".package-maintenance").is_file());
        drop(guard);
        assert!(crate::package_lease::CodeLease::acquire(&f.0).is_err());
        assert!(repair_guard(
            &f.0,
            || Err("controller_changed".into()),
            || panic!("must not inspect profiles")
        )
        .is_err());
        assert!(repair_guard(&f.0, || Ok(()), || Err("profile_active".into())).is_err());
        assert!(f.0.join(".package-maintenance").is_file());
        drop(repair_guard(&f.0, || Ok(()), || Ok(())).unwrap());
        assert!(f.0.join(".package-maintenance").is_file());
    }
    #[cfg(unix)]
    #[test]
    fn package_recovery_accepts_missing_or_damaged_controller_only_with_exact_receipt() {
        use std::os::unix::fs::symlink;
        let f = RepairFixture::new();
        let layout = Layout {
            runtime: f.0.join("runtime"),
            controller: f.0.join("controller/frameleaf-native-host"),
            profiles: f.0.join("profiles"),
        };
        std::fs::create_dir(&layout.runtime).unwrap();
        let m = "a".repeat(64);
        let h = "b".repeat(64);
        let receipt = serde_json::to_vec(
            &serde_json::json!({"schemaVersion":1,"manifestSha256":m,"controllerSha256":h}),
        )
        .unwrap();
        std::fs::write(layout.runtime.join("installation.json"), &receipt).unwrap();
        package_tree(&layout, &m, &h, |_| Ok(())).unwrap();
        std::fs::create_dir(layout.controller.parent().unwrap()).unwrap();
        std::fs::write(&layout.controller, b"corrupt bytes must not execute").unwrap();
        let guard = repair_guard(
            &layout.runtime,
            || package_tree(&layout, &m, &h, |_| Ok(())),
            || Ok(()),
        )
        .unwrap();
        drop(guard);
        assert!(layout.runtime.join(".package-maintenance").exists());
        assert!(crate::package_lease::CodeLease::acquire(&layout.runtime).is_err());
        assert!(package_tree(&layout, &m, &"c".repeat(64), |_| Ok(())).is_err());
        assert!(package_tree(&layout, &"c".repeat(64), &h, |_| Ok(())).is_err());
        std::fs::write(layout.runtime.join("installation.json"), b"broken receipt").unwrap();
        assert!(package_tree(&layout, &m, &h, |_| Ok(())).is_err());
        std::fs::write(layout.runtime.join("installation.json"), receipt).unwrap();
        std::fs::remove_file(&layout.controller).unwrap();
        std::fs::create_dir(&layout.controller).unwrap();
        assert!(package_tree(&layout, &m, &h, |_| Ok(())).is_err());
        std::fs::remove_dir(&layout.controller).unwrap();
        symlink(layout.runtime.join("installation.json"), &layout.controller).unwrap();
        assert!(package_tree(&layout, &m, &h, |_| Ok(())).is_err());
        std::fs::remove_file(&layout.controller).unwrap();
        std::fs::remove_file(layout.runtime.join("installation.json")).unwrap();
        package_tree(&layout, &m, &h, |_| Ok(())).unwrap();
        assert!(layout.runtime.join(".package-maintenance").exists());
    }
    #[cfg(unix)]
    #[test]
    fn package_bootstrap_requires_immutable_regular_matching_executable() {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::{symlink, PermissionsExt};
        let f = RepairFixture::new();
        let binary = f.0.join("bootstrap");
        std::fs::write(&binary, b"verified bootstrap").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let digest = format!("{:x}", Sha256::digest(b"verified bootstrap"));
        package_bootstrap(&binary, &digest, |_| Ok(())).unwrap();
        assert!(package_bootstrap(&binary, &digest, |_| Err("unprotected".into())).is_err());
        std::fs::write(&binary, b"tampered").unwrap();
        assert!(package_bootstrap(&binary, &digest, |_| Ok(())).is_err());
        std::fs::write(&binary, b"verified bootstrap").unwrap();
        std::fs::hard_link(&binary, f.0.join("alias")).unwrap();
        assert!(package_bootstrap(&binary, &digest, |_| Ok(())).is_err());
        std::fs::remove_file(f.0.join("alias")).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(package_bootstrap(&binary, &digest, |_| Ok(())).is_err());
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(package_bootstrap(&binary, &digest, |_| Ok(())).is_err());
        std::fs::remove_file(&binary).unwrap();
        symlink(f.0.join("missing"), &binary).unwrap();
        assert!(package_bootstrap(&binary, &digest, |_| Ok(())).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn repair_tree_accepts_corrupt_or_missing_bytes_but_refuses_unsafe_destinations() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let f = RepairFixture::new();
        std::fs::create_dir(f.0.join("payload")).unwrap();
        let data = f.0.join("payload/corrupt");
        std::fs::write(&data, b"damaged binary, never execute").unwrap();
        let visits = std::cell::Cell::new(0);
        repair_tree(&f.0, 4, |_| {
            visits.set(visits.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(visits.get(), 3);
        assert!(repair_tree(&f.0, 2, |_| Ok(())).is_err());
        assert!(repair_tree(&f.0, 4, |_| Err("not_root_protected".into())).is_err());
        symlink(&data, f.0.join("link")).unwrap();
        assert!(repair_tree(&f.0, 4, |_| Ok(())).is_err());
        std::fs::remove_file(f.0.join("link")).unwrap();
        std::fs::hard_link(&data, f.0.join("alias")).unwrap();
        assert!(repair_tree(&f.0, 4, |_| Ok(())).is_err());
        std::fs::remove_file(f.0.join("alias")).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(repair_tree(&f.0, 4, |_| Ok(())).is_err());
        std::fs::remove_file(data).unwrap();
        repair_tree(&f.0, 4, |_| Ok(())).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let fifo = std::ffi::CString::new(f.0.join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(repair_tree(&f.0, 4, |_| Ok(())).is_err());
    }
    #[test]
    fn finalization_verifies_while_exclusive_and_refuses_fenced_profile_admission() {
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-finalization-{}", uuid::Uuid::new_v4()));
        let _cleanup = Cleanup(root.clone());
        std::fs::create_dir(&root).unwrap();
        let guard = finalization_guard(&root, false, || {
            assert!(
                crate::package_lease::CodeLease::acquire(&root).is_err(),
                "verification_must_hold_exclusive_package_lease"
            );
            Ok(())
        })
        .unwrap();
        guard.fence().unwrap();
        drop(guard);
        let checked = std::cell::Cell::new(false);
        assert!(finalization_guard(&root, false, || {
            checked.set(true);
            Ok(())
        })
        .is_err());
        assert!(
            !checked.get(),
            "a fenced profile must refuse before verification or writes"
        );
        assert!(root.join(".package-maintenance").exists());
        let guard = finalization_guard(&root, true, || {
            assert!(crate::package_lease::CodeLease::acquire(&root).is_err());
            Ok(())
        })
        .unwrap();
        guard.finish().unwrap();
        drop(guard);
        assert!(crate::package_lease::CodeLease::acquire(&root).is_ok());
    }
    #[test]
    fn identical_install_can_reprovision_missing_profile_only_after_verification() {
        let root =
            std::env::temp_dir().join(format!("frameleaf-reinstall-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let layout = Layout {
            runtime: root.join("runtime"),
            controller: root.join("controller/frameleaf-native-host"),
            profiles: root.join("profiles"),
        };
        admit_versions(&layout, || {
            panic!("fresh install has no installed resources to verify")
        })
        .unwrap();
        std::fs::create_dir(&layout.runtime).unwrap();
        assert_eq!(
            admit_versions(&layout, || panic!("partial install must refuse")).unwrap_err(),
            "host_install_version_exists"
        );
        std::fs::create_dir(layout.controller.parent().unwrap()).unwrap();
        std::fs::write(&layout.controller, b"known helper").unwrap();
        let calls = std::cell::Cell::new(0);
        admit_versions(&layout, || {
            calls.set(calls.get() + 1);
            assert_eq!(std::fs::read(&layout.controller).unwrap(), b"known helper");
            Ok(())
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert!(
            !layout.profiles.exists(),
            "admission must not mutate profiles"
        );
        std::fs::create_dir(&layout.profiles).unwrap();
        let sentinel = layout.profiles.join("existing-user-state");
        std::fs::write(&sentinel, b"keep library").unwrap();
        assert_eq!(
            admit_versions(&layout, || Err("host_install_runtime_changed".into())).unwrap_err(),
            "host_install_runtime_changed"
        );
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep library");
        #[cfg(unix)]
        {
            std::fs::remove_file(&layout.controller).unwrap();
            std::fs::remove_dir(layout.controller.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&layout.runtime, layout.controller.parent().unwrap())
                .unwrap();
            assert!(admit_versions(&layout, || panic!(
                "linked resources must refuse before verification"
            ))
            .is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn installer_layout_uses_only_fixed_versioned_system_paths() {
        let layout = Layout::new(&"a".repeat(64), &"b".repeat(64)).unwrap();
        #[cfg(windows)]
        let base = windows::base().unwrap();
        #[cfg(not(windows))]
        let base = PathBuf::from(if cfg!(target_os = "linux") {
            "/opt/frameleaf"
        } else {
            "/Library/Application Support/Frameleaf"
        });
        assert_eq!(layout.runtime, base.join("Runtimes").join("a".repeat(64)));
        assert_eq!(
            layout.controller,
            base.join("Controllers")
                .join("a".repeat(64))
                .join("b".repeat(64))
                .join(if cfg!(windows) {
                    "frameleaf-native-host.exe"
                } else {
                    "frameleaf-native-host"
                })
        );
        for value in ["", "../escape", "/tmp", &"A".repeat(64)] {
            assert!(Layout::new(value, &"b".repeat(64)).is_err());
        }
    }
    #[test]
    fn linux_profile_uid_is_explicit_and_rejects_root_and_path_values() {
        assert_eq!(parse_linux_profile_uid("1000").unwrap(), 1000);
        assert_eq!(parse_linux_profile_uid("2001").unwrap(), 2001);
        assert_eq!(parse_linux_profile_uid("501").unwrap(), 501);
        assert_eq!(parse_linux_profile_uid("999").unwrap(), 999);
        for value in [
            "",
            "0",
            "01000",
            "+1000",
            " 1000",
            "1000\n",
            "../1000",
            "4294967295",
            "4294967296",
        ] {
            assert!(parse_linux_profile_uid(value).is_err(), "{value:?}");
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_profile_uses_the_system_account_database() {
        let uid = unsafe { libc::getuid() };
        let account = posix::linux_user(uid).unwrap();
        assert_eq!(account.0, uid);
        assert_ne!(account.1, u32::MAX);
        assert!(posix::linux_user(u32::MAX - 1).is_err());
    }
    #[test]
    fn profile_provisioning_requires_root_before_any_system_write() {
        #[cfg(unix)]
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        assert!(provision(&"a".repeat(64), &"b".repeat(64), "1000").is_err());
    }
    #[test]
    fn nonroot_or_unsupported_installer_phase_refuses_before_any_system_write() {
        #[cfg(unix)]
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        assert!(prepare_maintenance(&"a".repeat(64), &"b".repeat(64)).is_err());
        assert!(prepare(&"a".repeat(64), &"b".repeat(64)).is_err());
        assert!(finalize(&"a".repeat(64), &"b".repeat(64)).is_err());
    }
    #[test]
    fn installed_record_is_strict_and_bound_to_its_version_directory() {
        let raw = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)})).unwrap();
        let record = Installation::decode(&raw).unwrap();
        assert_eq!(
            record.layout().unwrap().runtime.file_name().unwrap(),
            "a".repeat(64).as_str()
        );
        for value in [
            serde_json::json!({"schemaVersion":2,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)}),
            serde_json::json!({"schemaVersion":1,"manifestSha256":"../escape","controllerSha256":"b".repeat(64)}),
            serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64),"command":"arbitrary"}),
        ] {
            assert!(Installation::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
    #[test]
    fn unfinished_installation_is_absent_but_malformed_or_linked_receipt_is_not_silently_skipped() {
        let root = std::env::temp_dir().join(format!(
            "frameleaf-install-receipt-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).unwrap();
        let record = root.join("installation.json");
        assert!(!receipt_present(&record).unwrap());
        std::fs::write(&record, b"incomplete").unwrap();
        assert!(receipt_present(&record).unwrap());
        assert!(Installation::decode(&std::fs::read(&record).unwrap()).is_err());
        #[cfg(unix)]
        {
            std::fs::remove_file(&record).unwrap();
            std::os::unix::fs::symlink(root.join("missing"), &record).unwrap();
            assert!(receipt_present(&record).unwrap());
        }
        std::fs::remove_dir_all(&root).unwrap();
    }
}
