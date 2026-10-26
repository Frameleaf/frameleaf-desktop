//! Closed controller bundles: legacy unsigned receipts and sealed new installations.
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

pub(super) fn info(version: &str) -> Result<Vec<u8>, String> {
    if version.len() > 32
        || version.split('.').count() != 3
        || version
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err("host_controller_bundle_version_invalid".into());
    }
    Ok(include_str!("../../../runtime/macos-host-Info.plist.in")
        .replace("@VERSION@", version)
        .into_bytes())
}

pub(super) fn verify(
    controller: &Path,
    digest: &str,
    version: &str,
    signature_required: bool,
    mut protect: impl FnMut(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let invalid = "host_controller_bundle_invalid";
    let metadata = info(version)?;
    if !controller.is_absolute()
        || !controller.ends_with("Frameleaf Native Host.app/Contents/MacOS/frameleaf-native-host")
        || !crate::native_runtime::digest_valid(digest, 64)
    {
        return Err(invalid.into());
    }
    let bundle = controller.ancestors().nth(3).ok_or(invalid)?;
    let mut expected = vec![
        ("", true, 0o755),
        ("Contents", true, 0o755),
        ("Contents/MacOS", true, 0o755),
        ("Contents/Info.plist", false, 0o644),
        ("Contents/MacOS/frameleaf-native-host", false, 0o755),
    ];
    if signature_required {
        expected.extend([
            ("Contents/_CodeSignature", true, 0o755),
            ("Contents/_CodeSignature/CodeResources", false, 0o644),
        ]);
    }
    for &(name, directory, mode) in &expected {
        let path = if name.is_empty() {
            bundle.to_owned()
        } else {
            bundle.join(name)
        };
        protect(&path)?;
        let entry = fs::symlink_metadata(&path).map_err(|_| invalid)?;
        if entry.is_dir() != directory
            || entry.mode() & 0o7777 != mode
            || (!directory && (!entry.is_file() || entry.nlink() != 1))
        {
            return Err(invalid.into());
        }
        if directory {
            for (index, child) in fs::read_dir(&path).map_err(|_| invalid)?.enumerate() {
                let child = child.map_err(|_| invalid)?.path();
                if index >= 3
                    || !expected
                        .iter()
                        .any(|(name, _, _)| bundle.join(name) == child)
                {
                    return Err(invalid.into());
                }
            }
        }
    }
    if crate::runtime_store::read_bounded(
        &bundle.join("Contents/Info.plist"),
        metadata.len() as u64,
    )? != metadata
    {
        return Err(invalid.into());
    }
    let bytes = crate::runtime_store::read_bounded(controller, 256 * 1024 * 1024)?;
    if bytes.is_empty() || format!("{:x}", Sha256::digest(bytes)) != digest {
        return Err("host_install_controller_changed".into());
    }
    if signature_required {
        let seal = crate::runtime_store::read_bounded(
            &bundle.join("Contents/_CodeSignature/CodeResources"),
            256 * 1024,
        )?;
        verify_seal_paths(&seal)?;
        verify_signature(bundle)?;
    }
    Ok(())
}

fn verify_seal_paths(raw: &[u8]) -> Result<(), String> {
    use core_foundation::{
        base::{CFType, TCFType},
        data::CFData,
        dictionary::CFDictionary,
        propertylist,
        string::CFString,
    };
    let invalid = "host_controller_bundle_signature_invalid";
    let (value, _) =
        propertylist::create_with_data(CFData::from_buffer(raw), 0).map_err(|_| invalid)?;
    // The create-rule reference is owned here; dictionary children remain retained by it.
    let dictionary = unsafe { CFType::wrap_under_create_rule(value) }
        .downcast::<CFDictionary>()
        .ok_or(invalid)?;
    if dictionary.len() > 4 {
        return Err(invalid.into());
    }
    let (keys, values) = dictionary.get_keys_and_values();
    for (key, value) in keys.into_iter().zip(values) {
        let key = unsafe { CFType::wrap_under_get_rule(key) }
            .downcast::<CFString>()
            .ok_or(invalid)?
            .to_string();
        if !matches!(key.as_str(), "files" | "files2" | "rules" | "rules2") {
            return Err(invalid.into());
        }
        let entries = unsafe { CFType::wrap_under_get_rule(value) }
            .downcast::<CFDictionary>()
            .ok_or(invalid)?;
        if entries.len() > 64 {
            return Err(invalid.into());
        }
        for path in entries.get_keys_and_values().0 {
            let path = unsafe { CFType::wrap_under_get_rule(path) }
                .downcast::<CFString>()
                .ok_or(invalid)?
                .to_string();
            if path.len() > 4096
                || (matches!(key.as_str(), "files" | "files2")
                    && !matches!(path.as_str(), "Info.plist" | "MacOS/frameleaf-native-host"))
            {
                return Err(invalid.into());
            }
        }
    }
    Ok(())
}

fn verify_signature(bundle: &Path) -> Result<(), String> {
    use core_foundation::{
        base::{CFRelease, TCFType},
        url::CFURL,
    };
    use std::ffi::c_void;
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecStaticCodeCreateWithPath(
            path: *const c_void,
            flags: u32,
            code: *mut *const c_void,
        ) -> i32;
        fn SecStaticCodeCheckValidity(
            code: *const c_void,
            flags: u32,
            requirement: *const c_void,
        ) -> i32;
    }
    let invalid = "host_controller_bundle_signature_invalid";
    let url = CFURL::from_path(bundle, true).ok_or(invalid)?;
    let mut code = std::ptr::null();
    let status =
        unsafe { SecStaticCodeCreateWithPath(url.as_concrete_TypeRef().cast(), 0, &mut code) };
    if status != 0 || code.is_null() {
        return Err(invalid.into());
    }
    // Strict, all architectures, no symlinks and no network. Digest/ownership remain authoritative.
    let status = unsafe {
        SecStaticCodeCheckValidity(code, (1 << 4) | 1 | (1 << 7) | (1 << 29), std::ptr::null())
    };
    unsafe { CFRelease(code) };
    if status != 0 {
        return Err(invalid.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn signed_bundle_admits_a_real_seal_and_refuses_tampering() {
        let root =
            std::env::temp_dir().join(format!("frameleaf-signed-bundle-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let _cleanup = Cleanup(root.clone());
        let bundle = root.join("Frameleaf Native Host.app");
        let controller = bundle.join("Contents/MacOS/frameleaf-native-host");
        fs::create_dir_all(controller.parent().unwrap()).unwrap();
        let code = root.join("fixture.c");
        fs::write(&code, b"int main(void) { return 0; }\n").unwrap();
        assert!(std::process::Command::new("/usr/bin/xcrun")
            .args(["clang"])
            .arg(&code)
            .arg("-o")
            .arg(&controller)
            .output()
            .unwrap()
            .status
            .success());
        fs::write(bundle.join("Contents/Info.plist"), info("0.1.0").unwrap()).unwrap();
        for path in [
            &bundle,
            &bundle.join("Contents"),
            &bundle.join("Contents/MacOS"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert!(std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&bundle)
            .output()
            .unwrap()
            .status
            .success());
        let digest = format!("{:x}", Sha256::digest(fs::read(&controller).unwrap()));
        let accepted = verify(&controller, &digest, "0.1.0", true, |_| Ok(()));
        assert!(verify(&controller, &digest, "0.1.0", false, |_| Ok(())).is_err());
        assert!(verify(&controller, &digest, "0.1.0", true, |_| Err(
            "unprotected".into()
        ))
        .is_err());
        let seal = bundle.join("Contents/_CodeSignature/CodeResources");
        let original = fs::read(&seal).unwrap();
        fs::set_permissions(&seal, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(verify(&controller, &digest, "0.1.0", true, |_| Ok(())).is_err());
        fs::set_permissions(&seal, fs::Permissions::from_mode(0o644)).unwrap();
        let alias = root.join("seal-alias");
        // macOS forbids hard-linking its cached seal inode; replace it with aliased bytes.
        let link_source = root.join("unsealed-resource");
        fs::write(&link_source, &original).unwrap();
        fs::set_permissions(&link_source, fs::Permissions::from_mode(0o644)).unwrap();
        fs::hard_link(&link_source, &alias).unwrap();
        fs::rename(&link_source, &seal).unwrap();
        assert!(verify(&controller, &digest, "0.1.0", true, |_| Ok(())).is_err());
        fs::remove_file(&alias).unwrap();
        let outside = root.join("outside-seal");
        fs::rename(&seal, &outside).unwrap();
        symlink(&outside, &seal).unwrap();
        assert!(verify(&controller, &digest, "0.1.0", true, |_| Ok(())).is_err());
        fs::remove_file(&seal).unwrap();
        fs::rename(&outside, &seal).unwrap();
        fs::write(&seal, b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>files2</key><dict><key>../outside</key><dict/></dict></dict></plist>").unwrap();
        assert!(verify(&controller, &digest, "0.1.0", true, |_| Ok(())).is_err());
        fs::write(
            &seal,
            b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>",
        )
        .unwrap();
        assert!(verify(&controller, &digest, "0.1.0", true, |_| Ok(())).is_err());
        fs::write(&seal, &original).unwrap();
        let original_code = fs::read(&controller).unwrap();
        let mut changed = original_code.clone();
        changed[0] ^= 1;
        fs::write(&controller, &changed).unwrap();
        let changed_digest = format!("{:x}", Sha256::digest(&changed));
        assert!(verify(&controller, &changed_digest, "0.1.0", true, |_| Ok(())).is_err());
        fs::write(&controller, original_code).unwrap();
        fs::remove_dir_all(bundle.join("Contents/_CodeSignature")).unwrap();
        assert!(verify(&controller, &digest, "0.1.0", true, |_| Ok(())).is_err());
        assert!(
            accepted.is_ok(),
            "a valid sealed controller must be admitted: {accepted:?}"
        );
    }

    #[test]
    fn unsigned_bundle_refuses_metadata_resources_links_modes_and_changed_controller() {
        let root = std::env::temp_dir().join(format!("frameleaf-bundle-{}", uuid::Uuid::new_v4()));
        let bundle = root.join("Frameleaf Native Host.app");
        let controller = bundle.join("Contents/MacOS/frameleaf-native-host");
        fs::create_dir_all(controller.parent().unwrap()).unwrap();
        let metadata = bundle.join("Contents/Info.plist");
        fs::write(&metadata, info("0.1.0").unwrap()).unwrap();
        fs::write(&controller, b"synthetic controller").unwrap();
        for (path, mode) in [
            (&bundle, 0o755),
            (&bundle.join("Contents"), 0o755),
            (&bundle.join("Contents/MacOS"), 0o755),
            (&metadata, 0o644),
            (&controller, 0o755),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        let digest = format!("{:x}", Sha256::digest(b"synthetic controller"));
        let check = || verify(&controller, &digest, "0.1.0", false, |_| Ok(()));
        check().unwrap();
        assert!(verify(&controller, &digest, "0.1.0", false, |_| Err(
            "unprotected".into()
        ))
        .is_err());
        fs::write(&metadata, info("0.2.0").unwrap()).unwrap();
        assert!(check().is_err());
        fs::write(&metadata, info("0.1.0").unwrap()).unwrap();
        let extra = bundle.join("Contents/extra");
        fs::create_dir(&extra).unwrap();
        assert!(check().is_err());
        fs::remove_dir(&extra).unwrap();
        fs::set_permissions(&controller, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(check().is_err());
        fs::set_permissions(&controller, fs::Permissions::from_mode(0o755)).unwrap();
        let alias = root.join("alias");
        fs::hard_link(&controller, &alias).unwrap();
        assert!(check().is_err());
        fs::remove_file(&alias).unwrap();
        fs::rename(&metadata, &alias).unwrap();
        symlink(&alias, &metadata).unwrap();
        assert!(check().is_err());
        fs::remove_file(&metadata).unwrap();
        fs::rename(&alias, &metadata).unwrap();
        fs::write(&controller, b"changed controller").unwrap();
        assert_eq!(check().unwrap_err(), "host_install_controller_changed");
        fs::write(&controller, b"synthetic controller").unwrap();
        check().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
