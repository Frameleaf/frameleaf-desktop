//! NSIS delegates all machine writes here; the maintenance lock spans the entire transaction.
use super::*;
use sha2::{Digest, Sha256};

fn own_identity(controller: &str) -> Result<std::path::PathBuf, String> {
    let path = std::env::current_exe().map_err(|_| "host_install_controller_changed")?;
    let bytes = crate::runtime_store::read_bounded(&path, 256 * 1024 * 1024)?;
    if format!("{:x}", Sha256::digest(bytes)) != controller {
        return Err("host_install_controller_changed".into());
    }
    Ok(path)
}
fn protect(path: &Path) -> Result<(), String> {
    crate::windows_protection::protect(path, &mut BTreeSet::new())
}

// Enumerate protected machine code only. Never recurse into Profiles or any user-selected path.
fn code_tree(
    path: &Path,
    files: &mut Vec<std::path::PathBuf>,
    dirs: &mut Vec<std::path::PathBuf>,
) -> Result<(), String> {
    if path.components().count() > 64 {
        return Err("host_install_inventory_limit".into());
    }
    protect(path)?;
    let info = fs::symlink_metadata(path).map_err(|_| "host_install_inventory_invalid")?;
    if info.is_file() {
        files.push(path.into());
    } else if info.is_dir() {
        for entry in fs::read_dir(path).map_err(|_| "host_install_inventory_invalid")? {
            let entry = entry.map_err(|_| "host_install_inventory_invalid")?;
            if files.len() + dirs.len() >= 100_000 {
                return Err("host_install_inventory_limit".into());
            }
            code_tree(&entry.path(), files, dirs)?;
        }
        dirs.push(path.into());
    } else {
        return Err("host_install_inventory_invalid".into());
    }
    Ok(())
}
fn bound_receipt(
    layout: &crate::host_install::Layout,
    manifest: &str,
    controller: &str,
) -> Result<(), String> {
    let path = layout.runtime.join("installation.json");
    if crate::host_install::receipt_present(&path)? {
        protect(&path)?;
        // A missing/damaged code file must not prevent an installer from repairing its bound version.
        let record = crate::host_install::Installation::decode(
            &crate::runtime_store::read_bounded(&path, 4096)?,
        )?;
        if record.manifest_sha256 != manifest || record.controller_sha256 != controller {
            return Err("host_install_record_invalid".into());
        }
    }
    Ok(())
}
fn clear_code(layout: &crate::host_install::Layout) -> Result<(), String> {
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    for name in [
        "payload",
        "manifest.json",
        "manifest.sig",
        "installation.json",
    ] {
        let path = layout.runtime.join(name);
        if crate::host_install::receipt_present(&path)? {
            code_tree(&path, &mut files, &mut dirs)?;
        }
    }
    let controller_root = layout
        .controller
        .parent()
        .ok_or("host_install_path_invalid")?;
    if crate::host_install::receipt_present(controller_root)? {
        code_tree(controller_root, &mut files, &mut dirs)?;
    }
    // Remove admission first; any subsequent failure leaves the persistent fence and lease intact.
    let receipt = layout.runtime.join("installation.json");
    if crate::host_install::receipt_present(&receipt)? {
        fs::remove_file(&receipt).map_err(|_| "host_install_remove_failed")?;
    }
    for path in files.into_iter().filter(|path| path != &receipt) {
        fs::remove_file(path).map_err(|_| "host_install_remove_failed")?;
    }
    for path in dirs {
        fs::remove_dir(path).map_err(|_| "host_install_remove_failed")?;
    }
    Ok(())
}
fn copy_file(source: &Path, destination: &Path) -> Result<(), String> {
    // No existing file is replaced; inherited machine ACLs are checked again before admission.
    let mut input = File::open(source).map_err(|_| "host_install_source_invalid")?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|_| "host_install_copy_failed")?;
    std::io::copy(&mut input, &mut output).map_err(|_| "host_install_copy_failed")?;
    output.sync_all().map_err(|_| "host_install_copy_failed")?;
    protect(destination)
}

pub(in crate::host_install) fn install(
    source: &Path,
    manifest: &str,
    controller: &str,
) -> Result<serde_json::Value, String> {
    require_administrator()?;
    let layout = crate::host_install::Layout::new(manifest, controller)?;
    let own = own_identity(controller)?;
    let source = crate::windows_protection::stable_path(source)?;
    let root = layout
        .profiles
        .parent()
        .ok_or("host_install_path_invalid")?;
    let own_physical = crate::windows_protection::stable_path(&own)?;
    if source.starts_with(root) || root.starts_with(&source) || own_physical.starts_with(root) {
        return Err("host_install_source_invalid".into());
    }
    crate::native_runtime::absolute_directory(&source)?;
    let raw = crate::runtime_store::read_bounded(&source.join("manifest.json"), 16 * 1024 * 1024)?;
    let signature: [u8; 64] = crate::runtime_store::read_bounded(&source.join("manifest.sig"), 64)?
        .try_into()
        .map_err(|_| "host_signature_invalid")?;
    let runtime =
        crate::release_policy::verify_host_runtime(&source.join("payload"), &raw, &signature)?;
    if runtime.manifest_sha256() != manifest {
        return Err("host_install_runtime_changed".into());
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| "host_manifest_invalid")?;
    if metadata["platform"] != "windows" || metadata["architecture"] != "x86_64" {
        return Err("host_install_runtime_target_mismatch".into());
    }
    let files = metadata["files"]
        .as_object()
        .ok_or("host_manifest_invalid")?;
    // Source admission completes before any machine state is changed.
    let root = layout
        .profiles
        .parent()
        .ok_or("host_install_path_invalid")?;
    for path in [
        root.to_path_buf(),
        root.join("Runtimes"),
        root.join("Controllers"),
        root.join("Controllers").join(manifest),
        layout.profiles.clone(),
        layout.runtime.clone(),
    ] {
        directory(&path)?;
    }
    seed_lease(&layout.runtime)?;
    let guard = crate::package_lease::Maintenance::acquire(&layout.runtime)?;
    bound_receipt(&layout, manifest, controller)?;
    guard.fence()?;
    clear_code(&layout)?;
    let controller_root = layout
        .controller
        .parent()
        .ok_or("host_install_path_invalid")?;
    directory(controller_root)?;
    directory(&layout.runtime.join("payload"))?;
    for name in files.keys() {
        let relative = crate::native_runtime::relative(name)?;
        let destination = layout.runtime.join("payload").join(&relative);
        let mut pending = Vec::new();
        let mut parent = destination.parent().ok_or("host_install_path_invalid")?;
        while parent != layout.runtime.join("payload") {
            pending.push(parent.to_path_buf());
            parent = parent.parent().ok_or("host_install_path_invalid")?;
        }
        for parent in pending.into_iter().rev() {
            directory(&parent)?;
        }
        copy_file(&source.join("payload").join(relative), &destination)?;
    }
    copy_file(
        &source.join("manifest.json"),
        &layout.runtime.join("manifest.json"),
    )?;
    copy_file(
        &source.join("manifest.sig"),
        &layout.runtime.join("manifest.sig"),
    )?;
    copy_file(&own, &layout.controller)?;
    crate::host_install::verify_resources(&layout, manifest, controller)?;
    publish_record(
        &layout.runtime,
        &crate::host_install::Installation {
            schema_version: 1,
            manifest_sha256: manifest.into(),
            controller_sha256: controller.into(),
        },
    )?;
    guard.finish()?;
    Ok(
        serde_json::json!({"protocolVersion":1,"state":"resources-installed","profileReady":false,"manifestSha256":manifest,"controllerSha256":controller,"serverStarted":false,"runtimeQualified":false,"redistributable":false}),
    )
}

pub(in crate::host_install) fn remove(
    manifest: &str,
    controller: &str,
) -> Result<serde_json::Value, String> {
    require_administrator()?;
    let layout = crate::host_install::Layout::new(manifest, controller)?;
    own_identity(controller)?;
    protect(&layout.runtime)?;
    seed_lease(&layout.runtime)?;
    let guard = crate::package_lease::Maintenance::acquire(&layout.runtime)?;
    bound_receipt(&layout, manifest, controller)?;
    guard.fence()?;
    clear_code(&layout)?;
    // Retain the fence and lease inode so an old reader can never recreate unfenced admission.
    Ok(
        serde_json::json!({"protocolVersion":1,"state":"code-removed","userDataRetained":true,"serverStarted":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires an elevated disposable GitHub-hosted Windows runner; synthetic machine code only"]
    fn disposable_runner_removal_refuses_readers_and_links_retains_data_and_persistent_fence() {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(
            std::env::var("RUNNER_ENVIRONMENT").as_deref(),
            Ok("github-hosted")
        );
        require_administrator().unwrap();
        let base = crate::host_install::windows::base().unwrap();
        let root = base
            .parent()
            .unwrap()
            .join(format!("Frameleaf-test-{}", uuid::Uuid::new_v4()));
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                // Remove the synthetic link separately; the fixture contains no real user data.
                let _ = fs::remove_file(self.0.join("runtime/payload/link"));
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        directory(&root).unwrap();
        let _fixture = Fixture(root.clone());
        let layout = crate::host_install::Layout {
            runtime: root.join("runtime"),
            controller: root.join("controller/frameleaf-native-host.exe"),
            profiles: root.join("Profiles"),
        };
        for path in [
            &layout.runtime,
            &layout.runtime.join("payload"),
            layout.controller.parent().unwrap(),
            &layout.profiles,
        ] {
            directory(path).unwrap();
        }
        new_machine_file(
            &layout.profiles.join("synthetic-library"),
            b"user data survives",
        )
        .unwrap();
        new_machine_file(&layout.controller, b"synthetic controller").unwrap();
        new_machine_file(&layout.runtime.join("manifest.json"), b"synthetic manifest").unwrap();
        new_machine_file(
            &layout.runtime.join("installation.json"),
            &serde_json::to_vec(&crate::host_install::Installation {
                schema_version: 1,
                manifest_sha256: "a".repeat(64),
                controller_sha256: "b".repeat(64),
            })
            .unwrap(),
        )
        .unwrap();
        new_machine_file(&layout.runtime.join("payload/code"), b"synthetic code").unwrap();
        fs::remove_file(&layout.controller).unwrap();
        bound_receipt(&layout, &"a".repeat(64), &"b".repeat(64)).unwrap();
        assert!(bound_receipt(&layout, &"a".repeat(64), &"c".repeat(64)).is_err());
        new_machine_file(&layout.controller, b"synthetic controller").unwrap();
        seed_lease(&layout.runtime).unwrap();
        let reader = crate::package_lease::CodeLease::acquire(&layout.runtime).unwrap();
        assert!(crate::package_lease::Maintenance::acquire(&layout.runtime).is_err());
        assert!(layout.runtime.join("installation.json").is_file());
        drop(reader);
        let writer = crate::package_lease::Maintenance::acquire(&layout.runtime).unwrap();
        writer.fence().unwrap();
        let link = layout.runtime.join("payload/link");
        std::os::windows::fs::symlink_file(layout.profiles.join("synthetic-library"), &link)
            .unwrap();
        assert!(clear_code(&layout).is_err());
        assert!(layout.runtime.join("installation.json").is_file());
        fs::remove_file(link).unwrap();
        clear_code(&layout).unwrap();
        clear_code(&layout).unwrap(); // Interrupted/complete removal can be safely retried.
        drop(writer);
        assert!(!layout.controller.exists());
        assert!(!layout.runtime.join("payload").exists());
        assert!(!layout.runtime.join("installation.json").exists());
        assert_eq!(
            fs::read(layout.profiles.join("synthetic-library")).unwrap(),
            b"user data survives"
        );
        assert!(layout.runtime.join(".runtime-lease").is_file());
        assert!(layout.runtime.join(".package-maintenance").is_file());
        assert!(crate::package_lease::CodeLease::acquire(&layout.runtime).is_err());
        let retry = crate::package_lease::Maintenance::acquire(&layout.runtime).unwrap();
        assert!(retry.require_unfenced().is_err());
    }
}
