//! Fixed-path installer phases only; never starts a host or reads a user's library.
use std::path::PathBuf;
const BASE: &str = "/Library/Application Support/Frameleaf";
pub struct Layout {
    pub runtime: PathBuf,
    pub controller: PathBuf,
    pub profiles: PathBuf,
}
impl Layout {
    pub fn new(manifest: &str, controller: &str) -> Result<Self, String> {
        if !crate::native_runtime::digest_valid(manifest, 64)
            || !crate::native_runtime::digest_valid(controller, 64)
        {
            return Err("host_install_identity_invalid".into());
        }
        let base = PathBuf::from(BASE);
        Ok(Self {
            runtime: base.join("Runtimes").join(manifest),
            controller: base
                .join("Controllers")
                .join(controller)
                .join("frameleaf-native-host"),
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
pub(crate) fn installed() -> Result<Vec<Installation>, String> {
    if !cfg!(target_os = "macos") {
        return Err("host_install_platform_unsupported".into());
    }
    let root = PathBuf::from(BASE).join("Runtimes");
    match std::fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("host_install_record_invalid".into()),
        Ok(_) => {}
    }
    crate::manager_host::protect(&root, &mut std::collections::BTreeSet::new())?;
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
        let candidate = Layout::new(name, &"0".repeat(64))?.runtime;
        crate::manager_host::protect(&candidate, &mut std::collections::BTreeSet::new())?;
        if !std::fs::symlink_metadata(&candidate)
            .map_err(|_| "host_install_record_invalid")?
            .is_dir()
        {
            return Err("host_install_record_invalid".into());
        }
        if receipt_present(&candidate.join("installation.json"))? {
            records.push(Installation::read(name)?);
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

#[cfg(any(target_os = "macos", test))]
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

pub fn prepare(manifest: &str, controller: &str) -> Result<serde_json::Value, String> {
    #[cfg(target_os = "macos")]
    {
        macos::root()?;
        macos::prepare(&Layout::new(manifest, controller)?, manifest, controller)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (manifest, controller);
        Err("host_install_platform_unsupported".into())
    }
}
pub fn finalize(manifest: &str, controller: &str) -> Result<serde_json::Value, String> {
    #[cfg(target_os = "macos")]
    {
        macos::root()?;
        macos::finalize(&Layout::new(manifest, controller)?, manifest, controller)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (manifest, controller);
        Err("host_install_platform_unsupported".into())
    }
}
#[cfg(target_os = "macos")]
mod macos {
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
            Path::new("/Library/Application Support"),
            &mut BTreeSet::new(),
        )?;
        for path in [
            Path::new(BASE),
            &PathBuf::from(BASE).join("Runtimes"),
            &PathBuf::from(BASE).join("Controllers"),
            &layout.profiles,
        ] {
            root_directory(path)?;
        }
        // Byte-identical reinstall can provision a missing console-user profile.
        admit_versions(layout, || verify_resources(layout, manifest, controller))?;
        Ok(
            serde_json::json!({"protocolVersion":1,"state":"install-prepared","serverStarted":false}),
        )
    }
    fn console_user() -> Option<(u32, u32)> {
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
        crate::manager_host::no_acl(path)
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
            if unsafe {
                libc::renameatx_np(
                    directory.as_raw_fd(),
                    source.as_ptr(),
                    directory.as_raw_fd(),
                    c"installation.json".as_ptr(),
                    libc::RENAME_EXCL,
                )
            } != 0
            {
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
    fn verify_resources(layout: &Layout, manifest: &str, controller: &str) -> Result<(), String> {
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
    pub(super) fn finalize(
        layout: &Layout,
        manifest: &str,
        controller: &str,
    ) -> Result<serde_json::Value, String> {
        verify_resources(layout, manifest, controller)?;
        root_directory(&layout.profiles)?;
        let user = console_user();
        if let Some((uid, gid)) = user {
            let parent = layout.profiles.join(uid.to_string());
            root_directory(&parent)?;
            private_leaf(&parent.join("state"), uid, gid)?;
            private_leaf(&parent.join("manager"), uid, gid)?;
        }
        write_record(layout, manifest, controller)?;
        Ok(
            serde_json::json!({"protocolVersion":1,"state":"resources-installed","profileReady":user.is_some(),"manifestSha256":manifest,"controllerSha256":controller,"serverStarted":false,"runtimeQualified":false,"redistributable":false}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(
            layout.runtime.to_str().unwrap(),
            format!(
                "/Library/Application Support/Frameleaf/Runtimes/{}",
                "a".repeat(64)
            )
        );
        assert_eq!(
            layout.controller.to_str().unwrap(),
            format!(
                "/Library/Application Support/Frameleaf/Controllers/{}/frameleaf-native-host",
                "b".repeat(64)
            )
        );
        for value in ["", "../escape", "/tmp", &"A".repeat(64)] {
            assert!(Layout::new(value, &"b".repeat(64)).is_err());
        }
    }
    #[test]
    fn nonroot_or_unsupported_installer_phase_refuses_before_any_system_write() {
        #[cfg(unix)]
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
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
