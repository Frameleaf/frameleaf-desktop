//! Private mutable state belongs to the process user, never an environment-selected account.
use std::{
    fs::{self, File, OpenOptions},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree, ERROR_NO_TOKEN},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateDirectoryW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, READ_CONTROL,
    },
    System::Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
};
const ERROR: &str = "runtime_store_directory_not_private";
struct Local(*mut core::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
/// Refuse thread impersonation rather than creating state for an ambiguous effective identity.
fn current_user() -> Result<Vec<u8>, String> {
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } != 0 {
        let _token = unsafe { OwnedHandle::from_raw_handle(raw) };
        return Err(ERROR.into());
    }
    if unsafe { GetLastError() } != ERROR_NO_TOKEN {
        return Err(ERROR.into());
    }
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 || raw.is_null()
    {
        return Err(ERROR.into());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut buffer = [0usize; 128];
    let mut size = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            std::mem::size_of_val(&buffer) as u32,
            &mut size,
        )
    } == 0
        || size as usize > std::mem::size_of_val(&buffer)
        || (size as usize) < std::mem::size_of::<TOKEN_USER>()
    {
        return Err(ERROR.into());
    }
    let sid = unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let start = buffer.as_ptr() as usize;
    let offset = (sid as usize).checked_sub(start).ok_or(ERROR)?;
    if offset.checked_add(8).is_none_or(|end| end > size as usize) {
        return Err(ERROR.into());
    }
    let sid_size = 8 + 4 * usize::from(unsafe { *sid.cast::<u8>().add(1) });
    if offset
        .checked_add(sid_size)
        .is_none_or(|end| end > size as usize)
    {
        return Err(ERROR.into());
    }
    unsafe { super::native::sid_bytes(sid) }.map_err(|_| ERROR.into())
}
/// Pin ownership to the process SID and stop parent ACL changes from adding foreign grants.
fn descriptor(user: &[u8]) -> Result<Local, String> {
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.as_ptr().cast_mut().cast(), &mut text) } == 0
        || text.is_null()
    {
        return Err(ERROR.into());
    }
    let _text = Local(text.cast());
    let length = (0..256)
        .find(|i| unsafe { *text.add(*i) == 0 })
        .ok_or(ERROR)?;
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| ERROR)?;
    let sddl: Vec<u16> = format!("O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})\0")
        .encode_utf16()
        .collect();
    let mut value = Local(std::ptr::null_mut());
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut value.0,
            std::ptr::null_mut(),
        )
    } == 0
        || value.0.is_null()
    {
        return Err(ERROR.into());
    }
    Ok(value)
}
/// Refuse reparses and withhold delete sharing while an admitted object is inspected.
fn open(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(3)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| ERROR)?;
    let info = file.metadata().map_err(|_| ERROR)?;
    if (!info.is_dir() && !info.is_file()) || info.file_attributes() & 0x400 != 0 {
        return Err(ERROR.into());
    }
    Ok(file)
}
/// Hold protected ancestry during admission; inspect existing descendants without changing ACLs.
fn directory(path: &Path, create_new: bool) -> Result<(), String> {
    crate::native_runtime::absolute_directory(path.parent().ok_or(ERROR)?)?;
    let user = current_user()?;
    let private_trusted = vec![
        user.clone(),
        vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
        vec![1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0],
    ];
    let mut trusted = super::native::trusted_sids()?.clone();
    trusted.push(user.clone());
    let physical = super::stable_path(path.parent().ok_or(ERROR)?)?;
    // Native directory APIs need the extended spelling; process launches keep their captured spelling.
    let parent = PathBuf::from(format!(
        r"\\?\GLOBALROOT{}",
        physical
            .to_str()
            .ok_or(ERROR)?
            .strip_prefix(r"\\.\GLOBALROOT")
            .ok_or(ERROR)?
    ));
    let text = parent.to_str().ok_or(ERROR)?;
    // Hold the physical parent chain against deletion until creation and admission finish.
    let mut parents = Vec::new();
    for part in super::filesystem_components(text).ok_or(ERROR)? {
        let file = open(Path::new(part))?;
        let (owner, acl, _) = super::native::security(&file)?;
        if !super::safe_acl(&owner, &acl, &trusted, true) {
            #[cfg(test)]
            eprintln!("private directory refused unsafe ancestry: {part}");
            return Err(ERROR.into());
        }
        parents.push(file);
    }
    let path: PathBuf = parent.join(path.file_name().ok_or(ERROR)?);
    super::filesystem_components(path.to_str().ok_or(ERROR)?).ok_or(ERROR)?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let security = descriptor(&user)?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: security.0,
                bInheritHandle: 0,
            };
            let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            if name.len() > 32767
                || name[..name.len() - 1].contains(&0)
                || unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0
            {
                #[cfg(test)]
                eprintln!("private directory creation at {path:?}: os={}", unsafe {
                    GetLastError()
                });
                return Err(ERROR.into());
            }
            if create_new {
                return Ok(());
            }
        }
        Ok(_) if create_new => return Err("runtime_store_directory_exists".into()),
        Ok(_) => {}
        Err(_) => return Err(ERROR.into()),
    }
    let file = open(&path)?;
    let (owner, acl, control) = super::native::security(&file)?;
    // Protected DACLs prevent later parent inheritance from widening this private boundary.
    if !file.metadata().map_err(|_| ERROR)?.is_dir()
        || control & 0x1000 == 0
        || !super::private_acl(&owner, &acl, &user, &private_trusted)
    {
        #[cfg(test)]
        eprintln!(
            "private directory root policy refused: {path:?}, protected={}, user_owner={}",
            control & 0x1000 != 0,
            owner == user
        );
        return Err(ERROR.into());
    }
    // Each frame pins its directory and ancestors until all children have been inspected.
    let mut pending = vec![scan(&path, file)?];
    let mut visited = 0;
    while let Some((_, entries)) = pending.last_mut() {
        let Some(entry) = entries.next() else {
            pending.pop();
            continue;
        };
        visited += 1;
        if visited > 100_000 {
            return Err("runtime_store_privacy_inventory_limit".into());
        }
        let path = entry.map_err(|_| ERROR)?.path();
        let file = open(&path)?;
        let (owner, acl, _) = super::native::security(&file)?;
        // Elevated writes may use a trusted SYSTEM/Administrators owner; foreign grants still fail.
        if !super::private_acl(&owner, &acl, &owner, &private_trusted) {
            #[cfg(test)]
            eprintln!("private directory descendant policy refused: {path:?}");
            return Err(ERROR.into());
        }
        if file.metadata().map_err(|_| ERROR)?.is_dir() {
            pending.push(scan(&path, file)?);
        }
    }
    Ok(())
}

/// Enumeration keeps the checked object open without delete sharing until its frame is exhausted.
fn scan(path: &Path, pin: File) -> Result<(File, fs::ReadDir), String> {
    #[cfg(test)]
    BEFORE_SCAN.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook(path);
        }
    });
    let entries = fs::read_dir(path).map_err(|_| ERROR)?;
    Ok((pin, entries))
}

/// Admission may reuse an existing private directory; it never repairs permissions.
pub(crate) fn private_directory(path: &Path) -> Result<(), String> {
    let result = directory(path, false);
    #[cfg(test)]
    if let Err(error) = &result {
        eprintln!("private directory admission at {path:?}: {error}");
    }
    result
}

/// Return ownership only for a newly created protected directory, never an existing stage.
pub(crate) fn create_private_directory(path: &Path) -> Result<(), String> {
    directory(path, true)
}

#[cfg(test)]
thread_local! {
    static BEFORE_SCAN: std::cell::RefCell<Option<Box<dyn FnMut(&Path)>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{
        AddAccessAllowedAce,
        Authorization::{SetSecurityInfo, SE_FILE_OBJECT},
        InitializeAcl, ACL, ACL_REVISION, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_GENERIC_READ, WRITE_DAC};
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn checked_descendant_cannot_be_replaced_before_enumeration() {
        use std::{cell::Cell, rc::Rc};
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                BEFORE_SCAN.with(|hook| *hook.borrow_mut() = None);
            }
        }
        let root = Fixture(
            std::env::temp_dir().join(format!("frameleaf-scan-pin-{}", uuid::Uuid::new_v4())),
        );
        private_directory(&root.0).unwrap();
        let child = root.0.join("checked");
        private_directory(&child).unwrap();
        let foreign = Fixture(
            std::env::temp_dir().join(format!("frameleaf-scan-public-{}", uuid::Uuid::new_v4())),
        );
        fs::create_dir(&foreign.0).unwrap();
        let replacement = foreign.0.clone();
        let parked = root.0.join("parked");
        let attempted = Rc::new(Cell::new(false));
        let replaced = Rc::new(Cell::new(false));
        let flags = (attempted.clone(), replaced.clone());
        BEFORE_SCAN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |path| {
                if path.file_name() == Some(std::ffi::OsStr::new("checked")) {
                    flags.0.set(true);
                    if fs::rename(&child, &parked).is_ok() {
                        fs::rename(&replacement, &child).unwrap();
                        flags.1.set(true);
                    }
                }
            }))
        });
        let _reset = Reset;
        let result = private_directory(&root.0);
        assert!(
            attempted.get(),
            "the replacement must target the checked child before enumeration"
        );
        assert!(
            !replaced.get() || result.is_err(),
            "an unchecked replacement must not be admitted"
        );
        if !replaced.get() {
            result.unwrap();
        }
    }

    #[test]
    fn captured_parent_remains_pinned_until_child_admission_finishes() {
        use std::{cell::Cell, rc::Rc};
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                BEFORE_SCAN.with(|hook| *hook.borrow_mut() = None);
            }
        }
        let root = Fixture(
            std::env::temp_dir().join(format!("frameleaf-parent-pin-{}", uuid::Uuid::new_v4())),
        );
        private_directory(&root.0).unwrap();
        let parent = root.0.join("parent");
        private_directory(&parent).unwrap();
        let child = parent.join("new-child");
        let parked = root.0.join("parked");
        let attempted = Rc::new(Cell::new(false));
        let replaced = Rc::new(Cell::new(false));
        let flags = (attempted.clone(), replaced.clone());
        let rename = (parent.clone(), parked.clone());
        BEFORE_SCAN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |path| {
                if path.file_name() == Some(std::ffi::OsStr::new("new-child")) {
                    flags.0.set(true);
                    flags.1.set(fs::rename(&rename.0, &rename.1).is_ok());
                }
            }))
        });
        let reset = Reset;
        private_directory(&child).unwrap();
        drop(reset);
        assert!(attempted.get());
        assert!(
            !replaced.get(),
            "the captured ancestor must stay pinned throughout admission"
        );
        fs::rename(parent, parked).unwrap();
    }

    #[test]
    fn private_creation_refuses_alias_components_without_creating_a_normalized_sibling() {
        let root = Fixture(
            std::env::temp_dir().join(format!("frameleaf-private-names-{}", uuid::Uuid::new_v4())),
        );
        private_directory(&root.0).unwrap();
        for name in ["aliased.", "aliased ", "aliased:stream"] {
            assert!(private_directory(&root.0.join(name)).is_err());
            assert!(!root.0.join(name).exists());
            assert!(!root.0.join("aliased").exists());
        }
    }

    #[test]
    fn private_creation_supports_long_captured_paths() {
        let root = Fixture(
            std::env::temp_dir().join(format!("frameleaf-long-private-{}", uuid::Uuid::new_v4())),
        );
        private_directory(&root.0).unwrap();
        let mut path = root.0.clone();
        for _ in 0..6 {
            path.push("private-state-component-with-unicode-旅行");
            private_directory(&path).unwrap();
        }
        assert!(path.as_os_str().encode_wide().count() > 260);
        fs::write(path.join("owned"), b"long private path").unwrap();
        private_directory(&root.0).unwrap();
    }

    #[test]
    fn impersonated_threads_refuse_private_storage_before_creation() {
        use windows_sys::Win32::Security::{
            CreateRestrictedToken, ImpersonateLoggedOnUser, RevertToSelf, DISABLE_MAX_PRIVILEGE,
            TOKEN_DUPLICATE,
        };
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                if unsafe { RevertToSelf() } == 0 {
                    std::process::abort();
                }
            }
        }
        let fixture = Fixture(std::env::temp_dir().join(format!(
            "frameleaf-private-impersonation-{}",
            uuid::Uuid::new_v4()
        )));
        assert!(!fixture.0.exists());
        let mut raw = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw)
            },
            0
        );
        let primary = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut raw = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                CreateRestrictedToken(
                    primary.as_raw_handle(),
                    DISABLE_MAX_PRIVILEGE,
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    &mut raw,
                )
            },
            0
        );
        let restricted = unsafe { OwnedHandle::from_raw_handle(raw) };
        assert_ne!(
            unsafe { ImpersonateLoggedOnUser(restricted.as_raw_handle()) },
            0
        );
        let _revert = Revert;
        assert_eq!(current_user().unwrap_err(), ERROR);
        assert!(private_directory(&fixture.0).is_err());
        assert!(!fixture.0.exists());
    }
    #[test]
    /// A private root cannot hide a readable child, and refusal must preserve its ACL and contents.
    fn private_directory_creates_user_acl_and_refuses_publicly_readable_existing_children() {
        let root =
            std::env::temp_dir().join(format!("frameleaf-private-acl-{}", uuid::Uuid::new_v4()));
        assert!(!root.exists());
        private_directory(&root).unwrap();
        let fixture = Fixture(root);
        let child = fixture.0.join("nested");
        private_directory(&child).unwrap();
        let path = child.join("synthetic-state");
        fs::write(&path, b"synthetic only").unwrap();
        private_directory(&fixture.0).unwrap();
        let file = OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(3)
            .open(&path)
            .unwrap();
        let user = current_user().unwrap();
        let users = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0];
        let mut storage = [0u32; 128];
        let acl = storage.as_mut_ptr().cast::<ACL>();
        unsafe {
            assert_ne!(
                InitializeAcl(acl, std::mem::size_of_val(&storage) as u32, ACL_REVISION),
                0
            );
            assert_ne!(
                AddAccessAllowedAce(
                    acl,
                    ACL_REVISION,
                    FILE_ALL_ACCESS,
                    user.as_ptr().cast_mut().cast()
                ),
                0
            );
            assert_ne!(
                AddAccessAllowedAce(
                    acl,
                    ACL_REVISION,
                    FILE_GENERIC_READ,
                    users.as_ptr().cast_mut().cast()
                ),
                0
            );
            assert_eq!(
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    acl,
                    std::ptr::null()
                ),
                0
            );
        }
        let before = super::super::native::security(&file).unwrap();
        assert!(private_directory(&fixture.0).is_err());
        assert_eq!(
            super::super::native::security(&file).unwrap(),
            before,
            "refusal must not repair the child's ACL"
        );
        drop(file);
        assert_eq!(fs::read(&path).unwrap(), b"synthetic only");
    }
}
