//! Read-only Windows package admission; never edits an ACL.
fn stable_volume_root(path: &str) -> Option<&str> {
    const PREFIX: &str = r"\\?\GLOBALROOT\Device\HarddiskVolume";
    let rest = path.strip_prefix(PREFIX)?;
    let end = rest.find('\\')?;
    let number = &rest[..end];
    if number.is_empty()
        || number.len() > 10
        || !number.bytes().all(|b| b.is_ascii_digit())
        || number.parse::<u32>().ok()? == 0
    {
        return None;
    }
    let root_end = PREFIX.len() + end + 1;
    let tail = &path[root_end..];
    if !tail.is_empty()
        && tail.split('\\').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.contains([':', '/', '\0'])
                || part.ends_with(['.', ' '])
        })
    {
        return None;
    }
    Some(&path[..root_end])
}
pub(crate) fn filesystem_components(path: &str) -> Option<Vec<&str>> {
    let root = stable_volume_root(path)?;
    let mut paths = vec![root];
    if path.len() > root.len() {
        for (index, _) in path[root.len()..].match_indices('\\') {
            paths.push(&path[..root.len() + index]);
        }
        paths.push(path);
    }
    Some(paths)
}
/// Metadata only: volume GUID names are never execution authority.
pub(crate) fn volume_guid_name(value: &str) -> Option<String> {
    let rest = value.strip_prefix(r"\\?\Volume{")?;
    let (guid, tail) = rest.split_once("}\\")?;
    if guid.len() != 36 {
        return None;
    }
    let guid = uuid::Uuid::parse_str(guid).ok()?;
    if guid.is_nil()
        || (!tail.is_empty()
            && tail.split('\\').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains([':', '/', '\0'])
                    || part.ends_with(['.', ' '])
            }))
    {
        return None;
    }
    Some(format!(r"\\?\Volume{{{guid}}}\{tail}"))
}
fn sid_valid(sid: &[u8]) -> bool {
    sid.len() >= 8 && sid[0] == 1 && sid[1] <= 15 && sid.len() == 8 + 4 * usize::from(sid[1])
}
fn safe_acl(owner: &[u8], acl: &[u8], trusted: &[Vec<u8>], ancestor: bool) -> bool {
    if !sid_valid(owner)
        || !trusted.iter().any(|sid| sid == owner)
        || acl.len() < 8
        || ![2, 4].contains(&acl[0])
        || usize::from(u16::from_le_bytes([acl[2], acl[3]])) != acl.len()
    {
        return false;
    }
    let count = usize::from(u16::from_le_bytes([acl[4], acl[5]]));
    if count > 4096 {
        return false;
    }
    let mut cursor = 8;
    for _ in 0..count {
        let Some(header) = acl.get(cursor..cursor + 8) else {
            return false;
        };
        let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if size < 16 || size % 4 != 0 || header[0] > 1 || header[1] & !0x1f != 0 {
            return false;
        }
        let Some(ace) = acl.get(cursor..cursor + size) else {
            return false;
        };
        let sid = &ace[8..];
        if !sid_valid(sid) {
            return false;
        }
        let mask = u32::from_le_bytes(header[4..8].try_into().unwrap());
        // Deny ACEs never excuse an unsafe allow; inherit-only ACEs do not govern this inode.
        // Generic write/all, maximum-allowed, delete/owner/DACL, data/append/EA/attribute writes and delete-child.
        let mutation = 0x520d0156 & if ancestor { !4 } else { u32::MAX };
        if header[0] == 0
            && header[1] & 8 == 0
            && mask & mutation != 0
            && !trusted.iter().any(|known| known == sid)
        {
            return false;
        }
        cursor += size;
    }
    true
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        collections::BTreeSet,
        fs::{File, OpenOptions},
        os::windows::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        path::{Path, PathBuf},
        sync::OnceLock,
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            GetLengthSid, IsValidAcl, IsValidSid, LookupAccountNameW, ACL,
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSID,
        },
        Storage::FileSystem::{
            GetFinalPathNameByHandleW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_READ_ATTRIBUTES, READ_CONTROL, VOLUME_NAME_GUID, VOLUME_NAME_NT,
        },
    };
    const ERROR: &str = "native_manager_unprotected";
    struct Descriptor(*mut core::ffi::c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    unsafe fn sid_bytes(sid: PSID) -> Result<Vec<u8>, String> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(ERROR.into());
        }
        let size = unsafe { GetLengthSid(sid) } as usize;
        if !(8..=68).contains(&size) {
            return Err(ERROR.into());
        }
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), size) }.to_vec())
    }
    fn trusted_sids() -> Result<&'static Vec<Vec<u8>>, String> {
        static SIDS: OnceLock<Option<Vec<Vec<u8>>>> = OnceLock::new();
        SIDS.get_or_init(|| {
            let name: Vec<u16> = "NT SERVICE\\TrustedInstaller\0".encode_utf16().collect();
            let mut sid = [0u32; 17];
            let mut bytes = 68;
            let mut domain = [0u16; 256];
            let mut domain_size = 256;
            let mut kind = 0;
            if unsafe {
                LookupAccountNameW(
                    std::ptr::null(),
                    name.as_ptr(),
                    sid.as_mut_ptr().cast(),
                    &mut bytes,
                    domain.as_mut_ptr(),
                    &mut domain_size,
                    &mut kind,
                )
            } == 0
            {
                return None;
            }
            let installer = unsafe { sid_bytes(sid.as_mut_ptr().cast()) }.ok()?;
            Some(vec![
                vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
                vec![1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0],
                installer,
            ])
        })
        .as_ref()
        .ok_or_else(|| ERROR.into())
    }
    fn descriptor(file: &File, ancestor: bool) -> Result<bool, String> {
        let mut owner = std::ptr::null_mut();
        let mut acl: *mut ACL = std::ptr::null_mut();
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut acl,
                std::ptr::null_mut(),
                &mut raw,
            )
        };
        let _descriptor = Descriptor(raw);
        if status != 0 || raw.is_null() {
            return Err(ERROR.into());
        }
        if acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
            return Err(ERROR.into());
        }
        let owner = unsafe { sid_bytes(owner) }?;
        let size = usize::from(unsafe { (*acl).AclSize });
        if size < 8 {
            return Err(ERROR.into());
        }
        let acl = unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), size) };
        let trusted = trusted_sids()?;
        if !safe_acl(&owner, acl, trusted, ancestor) {
            return Err(ERROR.into());
        }
        Ok(safe_acl(&owner, acl, trusted, false))
    }
    /// Resolves one opened code object; callers must verify and use only the returned spelling.
    pub(crate) fn stable_path(path: &Path) -> Result<PathBuf, String> {
        if !path.is_absolute() {
            return Err(ERROR.into());
        }
        let file = OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(3)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| ERROR)?;
        let meta = file.metadata().map_err(|_| ERROR)?;
        if meta.file_attributes() & 0x400 != 0 || (!meta.is_file() && !meta.is_dir()) {
            return Err(ERROR.into());
        }
        let mut buffer = vec![0u16; 32768];
        let size = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                VOLUME_NAME_NT,
            )
        } as usize;
        if size == 0 || size >= buffer.len() {
            return Err(ERROR.into());
        }
        let nt = String::from_utf16(&buffer[..size]).map_err(|_| ERROR)?;
        let value = format!(r"\\?\GLOBALROOT{nt}");
        stable_volume_root(&value).ok_or(ERROR)?;
        Ok(PathBuf::from(value))
    }
    /// Capture identity metadata from an already-open object, never resolve a GUID alias for execution.
    pub(crate) fn durable_name(handle: &impl AsRawHandle) -> Result<String, String> {
        let mut buffer = vec![0u16; 32768];
        let size = unsafe {
            GetFinalPathNameByHandleW(
                handle.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                VOLUME_NAME_GUID,
            )
        } as usize;
        if size == 0 || size >= buffer.len() {
            return Err(ERROR.into());
        }
        let value = String::from_utf16(&buffer[..size]).map_err(|_| ERROR)?;
        volume_guid_name(&value).ok_or_else(|| ERROR.into())
    }
    pub(crate) fn protect(
        path: &Path,
        checked: &mut BTreeSet<std::path::PathBuf>,
    ) -> Result<(), String> {
        let text = path.to_str().ok_or(ERROR)?;
        let pending: Vec<_> = filesystem_components(text)
            .ok_or(ERROR)?
            .into_iter()
            .map(PathBuf::from)
            .collect();
        // The device name is valid only for this operation, never a durable installation identity.
        let start = pending
            .iter()
            .rposition(|p| checked.contains(p))
            .map_or(0, |i| i + 1);
        for current in &pending[start..] {
            let file = OpenOptions::new()
                .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
                .share_mode(3)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(current)
                .map_err(|_| ERROR)?;
            let info = file.metadata().map_err(|_| ERROR)?;
            if info.file_attributes() & 0x400 != 0
                || (!info.is_file() && !info.is_dir())
                || (current.as_path() != path && !info.is_dir())
            {
                return Err(ERROR.into());
            }
            if descriptor(&file, current.as_path() != path)? {
                checked.insert(current.clone());
            }
        }
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        struct DriveAlias {
            name: Vec<u16>,
            targets: Vec<Vec<u16>>,
        }
        impl DriveAlias {
            fn create(target: &str) -> Self {
                let name: Vec<u16> = format!("FrameleafNativeTest-{}\0", uuid::Uuid::new_v4())
                    .encode_utf16()
                    .collect();
                let mut alias = Self {
                    name,
                    targets: vec![],
                };
                alias.redirect(target);
                alias
            }
            fn path(&self) -> PathBuf {
                let name = String::from_utf16(&self.name[..self.name.len() - 1]).unwrap();
                PathBuf::from(format!(r"\\.\{name}\cmd.exe"))
            }
            fn redirect(&mut self, target: &str) {
                use windows_sys::Win32::Storage::FileSystem::{
                    DefineDosDeviceW, DDD_NO_BROADCAST_SYSTEM, DDD_RAW_TARGET_PATH,
                };
                let value: Vec<u16> = target.encode_utf16().chain(Some(0)).collect();
                assert_ne!(
                    unsafe {
                        DefineDosDeviceW(
                            DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
                            self.name.as_ptr(),
                            value.as_ptr(),
                        )
                    },
                    0
                );
                self.targets.push(value);
            }
            fn cleanup(&mut self) -> bool {
                use windows_sys::Win32::Storage::FileSystem::{
                    DefineDosDeviceW, DDD_EXACT_MATCH_ON_REMOVE, DDD_NO_BROADCAST_SYSTEM,
                    DDD_RAW_TARGET_PATH, DDD_REMOVE_DEFINITION,
                };
                while let Some(target) = self.targets.last() {
                    if unsafe {
                        DefineDosDeviceW(
                            DDD_EXACT_MATCH_ON_REMOVE
                                | DDD_REMOVE_DEFINITION
                                | DDD_RAW_TARGET_PATH
                                | DDD_NO_BROADCAST_SYSTEM,
                            self.name.as_ptr(),
                            target.as_ptr(),
                        )
                    } == 0
                    {
                        return false;
                    }
                    self.targets.pop();
                }
                true
            }
        }
        impl Drop for DriveAlias {
            fn drop(&mut self) {
                let _ = self.cleanup();
            }
        }
        #[test]
        fn verified_kernel_code_is_hashed_and_spawned_after_its_dos_alias_is_rebound() {
            use sha2::{Digest, Sha256};
            let system_root = std::env::var_os("SystemRoot").unwrap();
            let system = stable_path(&Path::new(&system_root).join("System32")).unwrap();
            let scratch =
                std::env::temp_dir().join(format!("frameleaf-drive-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&scratch).unwrap();
            std::fs::write(
                scratch.join("cmd.exe"),
                b"synthetic replacement is never executed",
            )
            .unwrap();
            let malicious = stable_path(&scratch).unwrap();
            let mut alias = DriveAlias::create(
                system
                    .to_str()
                    .unwrap()
                    .strip_prefix(r"\\?\GLOBALROOT")
                    .unwrap(),
            );
            let requested = alias.path();
            let code = stable_path(&requested).unwrap();
            let mut checked = BTreeSet::new();
            protect(&code, &mut checked).unwrap();
            let original = Sha256::digest(std::fs::read(&code).unwrap());
            let persistent_name = durable_name(&File::open(&code).unwrap()).unwrap();
            alias.redirect(
                malicious
                    .to_str()
                    .unwrap()
                    .strip_prefix(r"\\?\GLOBALROOT")
                    .unwrap(),
            );
            assert_eq!(
                std::fs::read(&requested).unwrap(),
                b"synthetic replacement is never executed"
            );
            assert!(protect(&requested, &mut checked).is_err());
            assert_eq!(Sha256::digest(std::fs::read(&code).unwrap()), original);
            assert_eq!(
                durable_name(&File::open(&code).unwrap()).unwrap(),
                persistent_name
            );
            let output = std::process::Command::new(&code)
                .args(["/d", "/c", "exit", "0"])
                .env_clear()
                .env("SystemRoot", &system_root)
                .output()
                .unwrap();
            assert!(output.status.success());
            assert!(alias.cleanup(), "owned DOS alias cleanup failed");
            std::fs::remove_dir_all(scratch).unwrap();
        }
        #[test]
        fn relative_code_path_never_uses_the_process_working_directory() {
            assert!(stable_path(Path::new("relative-code")).is_err());
        }
        #[test]
        fn actual_windows_security_descriptor_refuses_user_writable_temp_file() {
            let path = std::env::temp_dir().join(format!("frameleaf-acl-{}", uuid::Uuid::new_v4()));
            std::fs::write(&path, b"synthetic").unwrap();
            let file = File::open(&path).unwrap();
            let stable = stable_path(&path).unwrap();
            let direct = descriptor(&file, false);
            drop(file);
            let result = protect(&stable, &mut BTreeSet::new());
            std::fs::remove_file(&path).unwrap();
            assert!(direct.is_err());
            assert!(result.is_err());
        }
        #[test]
        fn actual_windows_security_descriptor_accepts_readonly_system_executable() {
            let path =
                Path::new(&std::env::var_os("SystemRoot").unwrap()).join("System32/notepad.exe");
            assert!(protect(&path, &mut BTreeSet::new()).is_err());
            let stable = stable_path(&path).unwrap();
            protect(&stable, &mut BTreeSet::new()).unwrap();
        }
    }
}
#[cfg(windows)]
pub(crate) use native::{durable_name, protect, stable_path};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persistent_names_normalize_only_the_guid_and_refuse_unsafe_metadata() {
        let guid = "ABCDEFAB-2222-3333-4444-555555555555";
        assert_eq!(
            volume_guid_name(&format!(r"\\?\Volume{{{guid}}}\CaseSensitive\Profile")),
            Some(r"\\?\Volume{abcdefab-2222-3333-4444-555555555555}\CaseSensitive\Profile".into())
        );
        for guid in ["invalid", "00000000-0000-0000-0000-000000000000"] {
            assert!(volume_guid_name(&format!(r"\\?\Volume{{{guid}}}\profile")).is_none());
        }
        for tail in [
            r"..\profile",
            r"a\..\profile",
            r".\profile",
            r"a\\profile",
            "profile:stream",
            "profile.",
            "profile ",
            "a/profile",
        ] {
            assert!(
                volume_guid_name(&format!(
                    r"\\?\Volume{{abcdefab-2222-3333-4444-555555555555}}\{tail}"
                ))
                .is_none(),
                "{tail}"
            );
        }
    }
    #[test]
    fn stable_paths_reject_drive_network_device_and_component_aliases() {
        let root = r"\\?\GLOBALROOT\Device\HarddiskVolume12\";
        assert_eq!(stable_volume_root(root), Some(root));
        assert_eq!(
            stable_volume_root(&format!("{root}Windows\\System32\\notepad.exe")),
            Some(root)
        );
        for path in [
            r"C:\Windows\notepad.exe",
            r"\\?\C:\Windows\notepad.exe",
            r"\\server\share\file",
            r"\\?\UNC\server\share\file",
            r"\\?\Volume{11111111-1111-1111-1111-111111111111}\file",
            r"\\.\C:\file",
            r"\\?\GLOBALROOT\Device\Mup\share\file",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1x\file",
            r"\\?\GLOBALROOT\Device\HarddiskVolume12",
            r"\\?\GLOBALROOT\Device\HarddiskVolume0\file",
        ] {
            assert_eq!(stable_volume_root(path), None, "{path}");
        }
        for tail in [
            r"..\file",
            r"a\..\file",
            r".\file",
            r"a\\file",
            "file:stream",
            "file.",
            "file ",
            "a/file",
        ] {
            assert_eq!(stable_volume_root(&format!("{root}{tail}")), None, "{tail}");
        }
    }
    #[test]
    fn filesystem_walk_starts_at_the_volume_not_the_object_manager_namespace() {
        let root = r"\\?\GLOBALROOT\Device\HarddiskVolume12\";
        let folder = format!("{root}Windows");
        let file = format!("{folder}\\System32\\cmd.exe");
        assert_eq!(filesystem_components(root), Some(vec![root]));
        assert_eq!(
            filesystem_components(&file),
            Some(vec![
                root,
                folder.as_str(),
                &file[..file.len() - 8],
                file.as_str()
            ])
        );
        for value in [
            r"C:\Windows",
            r"\\?\GLOBALROOT\Device\HarddiskVolume12\..\outside",
        ] {
            assert!(filesystem_components(value).is_none());
        }
    }
    fn sid(parts: &[u32]) -> Vec<u8> {
        let mut value = vec![1, parts.len() as u8, 0, 0, 0, 0, 0, 5];
        for part in parts {
            value.extend(part.to_le_bytes());
        }
        value
    }
    fn acl(entries: &[(u8, u8, u32, Vec<u8>)]) -> Vec<u8> {
        let mut value = vec![2, 0, 0, 0, entries.len() as u8, 0, 0, 0];
        for (kind, flags, mask, sid) in entries {
            value.extend([*kind, *flags]);
            value.extend(((8 + sid.len()) as u16).to_le_bytes());
            value.extend(mask.to_le_bytes());
            value.extend(sid);
        }
        let size = value.len() as u16;
        value[2..4].copy_from_slice(&size.to_le_bytes());
        value
    }
    #[test]
    fn acl_allows_privileged_writers_and_public_readers_only() {
        let system = sid(&[18]);
        let admins = sid(&[32, 544]);
        let users = sid(&[32, 545]);
        let trusted = vec![system.clone(), admins.clone()];
        let good = acl(&[
            (0, 0, 0x001f01ff, system.clone()),
            (0, 0x10, 0x001f01ff, admins),
            (0, 0, 0x001200a9, users.clone()),
        ]);
        assert!(safe_acl(&system, &good, &trusted, false));
        assert!(!safe_acl(&users, &good, &trusted, false));
        for mask in [
            2, 4, 16, 64, 256, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000, 0x02000000,
        ] {
            assert!(
                !safe_acl(
                    &system,
                    &acl(&[(0, 0, mask, users.clone())]),
                    &trusted,
                    false
                ),
                "mask {mask:x}"
            );
        }
    }
    #[test]
    fn acl_inheritance_deny_and_ancestor_rules_never_relax_an_effective_mutation() {
        let system = sid(&[18]);
        let users = sid(&[32, 545]);
        let trusted = vec![system.clone()];
        assert!(safe_acl(
            &system,
            &acl(&[(0, 8, 0x10000000, users.clone())]),
            &trusted,
            false
        ));
        assert!(!safe_acl(
            &system,
            &acl(&[(1, 0, 2, users.clone()), (0, 0, 2, users.clone())]),
            &trusted,
            false
        ));
        let append = acl(&[(0, 0, 4, users.clone())]);
        assert!(safe_acl(&system, &append, &trusted, true));
        assert!(!safe_acl(&system, &append, &trusted, false));
        for mask in [
            2, 16, 64, 256, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000,
        ] {
            assert!(!safe_acl(
                &system,
                &acl(&[(0, 0, mask, users.clone())]),
                &trusted,
                true
            ));
        }
    }
    #[test]
    fn acl_refuses_unknown_aces_and_malformed_lengths_or_sids() {
        let system = sid(&[18]);
        let trusted = vec![system.clone()];
        let good = acl(&[(0, 0, 0x001200a9, system.clone())]);
        for kind in [2, 5, 9, 11, 17, 255] {
            assert!(!safe_acl(
                &system,
                &acl(&[(kind, 0, 0, system.clone())]),
                &trusted,
                false
            ));
        }
        for end in 0..good.len() {
            assert!(!safe_acl(&system, &good[..end], &trusted, false));
        }
        for (offset, value) in [
            (0, 0),
            (2, 0),
            (4, 2),
            (8, 255),
            (9, 0x80),
            (10, 0),
            (16, 2),
            (17, 16),
        ] {
            let mut bad = good.clone();
            bad[offset] = value;
            assert!(!safe_acl(&system, &bad, &trusted, false), "offset {offset}");
        }
    }
}
