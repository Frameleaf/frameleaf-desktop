//! Exact unsigned development bundle admission; signed/profile resources require separate qualification.
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
    let expected = [
        ("", true, 0o755),
        ("Contents", true, 0o755),
        ("Contents/MacOS", true, 0o755),
        ("Contents/Info.plist", false, 0o644),
        ("Contents/MacOS/frameleaf-native-host", false, 0o755),
    ];
    for (name, directory, mode) in expected {
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
                if index >= 2
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

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
        let check = || verify(&controller, &digest, "0.1.0", |_| Ok(()));
        check().unwrap();
        assert!(verify(&controller, &digest, "0.1.0", |_| Err("unprotected".into())).is_err());
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
