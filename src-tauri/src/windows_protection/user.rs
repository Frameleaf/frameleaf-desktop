//! Private mutable state belongs to the process user, never an environment-selected account.
use std::{
    fs::{self, File, OpenOptions},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
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
        CreateDirectoryW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_NO_RECALL,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, READ_CONTROL,
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
fn sid_name(user: &[u8]) -> Result<String, String> {
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
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| ERROR.into())
}
pub(crate) fn process_user_sid() -> Result<String, String> {
    sid_name(&current_user()?)
}
/// Pin ownership to the process SID and stop parent ACL changes from adding foreign grants.
fn descriptor(user: &[u8]) -> Result<Local, String> {
    let sid = sid_name(user)?;
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
/// Only directories need data/list access for effective pins; files need metadata/security access.
fn open(path: &Path) -> Result<File, String> {
    let metadata_access = READ_CONTROL | FILE_READ_ATTRIBUTES;
    let acquire = |access| {
        OpenOptions::new()
            .access_mode(access)
            .share_mode(3)
            .custom_flags(
                FILE_FLAG_BACKUP_SEMANTICS
                    | FILE_FLAG_OPEN_REPARSE_POINT
                    | FILE_FLAG_OPEN_NO_RECALL,
            )
            .open(path)
            .map_err(|_| ERROR)
    };
    let mut file = acquire(metadata_access)?;
    let info = file.metadata().map_err(|_| ERROR)?;
    if (!info.is_dir() && !info.is_file()) || info.file_attributes() & 0x400 != 0 {
        return Err(ERROR.into());
    }
    if info.is_dir() {
        file = acquire(metadata_access | FILE_LIST_DIRECTORY)?;
        let info = file.metadata().map_err(|_| ERROR)?;
        if !info.is_dir() || info.file_attributes() & 0x400 != 0 {
            return Err(ERROR.into());
        }
    }
    Ok(file)
}
/// Hold protected ancestry during admission; inspect existing descendants without changing ACLs.
fn directory(path: &Path, user: &[u8], mode: DirectoryMode) -> Result<Vec<File>, String> {
    if !super::sid_valid(user) {
        return Err(ERROR.into());
    }
    current_user()?;
    crate::native_runtime::absolute_directory(path.parent().ok_or(ERROR)?)?;
    let private_trusted = vec![
        user.to_vec(),
        vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
        vec![1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0],
    ];
    let mut trusted = super::native::trusted_sids()?.clone();
    trusted.push(user.to_vec());
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
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && !matches!(mode, DirectoryMode::ExistingOnly) =>
        {
            let security = descriptor(user)?;
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
            if matches!(mode, DirectoryMode::CreateNew) {
                return Ok(parents);
            }
        }
        Ok(_) if matches!(mode, DirectoryMode::CreateNew) => {
            return Err("runtime_store_directory_exists".into())
        }
        Ok(_) => {}
        Err(_) => return Err(ERROR.into()),
    }
    let file = open(&path)?;
    let (owner, acl, control) = super::native::security(&file)?;
    // Protected DACLs prevent later parent inheritance from widening this private boundary.
    if !file.metadata().map_err(|_| ERROR)?.is_dir()
        || control & 0x1000 == 0
        || !super::private_acl(&owner, &acl, user, &private_trusted)
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
    parents.push(file.try_clone().map_err(|_| ERROR)?);
    let mut pending = vec![scan(&path, file, false)?];
    // Entries seen outside and inside library directories, when a library passed the limit,
    // and whether the rest of the library is being left to the verified root.
    let (mut state, mut library, mut over, mut left) = (0usize, 0usize, None::<Instant>, false);
    while let Some((_, entries, inside)) = pending.last_mut() {
        let inside = *inside;
        let Some(entry) = entries.next() else {
            pending.pop();
            continue;
        };
        let count = if inside {
            library += 1;
            library
        } else {
            state += 1;
            state
        };
        match super::walk_step(inside, count, || {
            overtime(*over.get_or_insert_with(Instant::now))
        }) {
            super::Walk::Inspect => {}
            super::Walk::Refuse => return Err("runtime_store_privacy_inventory_limit".into()),
            super::Walk::LeaveLibrary => {
                left = true;
                while pending.last().is_some_and(|frame| frame.2) {
                    pending.pop();
                }
                continue;
            }
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
            // The library directory itself was just inspected like any other entry.
            let inside = inside || super::library_directory(path.file_name());
            if !(inside && left) {
                pending.push(scan(&path, file, inside)?);
            }
        }
    }
    Ok(parents)
}

/// How long a library has been past the inventory limit.
fn overtime(since: Instant) -> Duration {
    #[cfg(test)]
    if let Some(fixed) = OVERTIME.with(std::cell::Cell::get) {
        return fixed;
    }
    since.elapsed()
}

/// Enumeration keeps the checked object open without delete sharing until its frame is exhausted.
/// `library` says whether the directory is, or is inside, a library directory.
fn scan(path: &Path, pin: File, library: bool) -> Result<(File, fs::ReadDir, bool), String> {
    #[cfg(test)]
    BEFORE_SCAN.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook(path);
        }
    });
    let entries = fs::read_dir(path).map_err(|_| ERROR)?;
    Ok((pin, entries, library))
}

/// Admission may reuse an existing private directory; it never repairs permissions.
pub(crate) fn private_directory(path: &Path) -> Result<(), String> {
    let result = directory(path, &current_user()?, DirectoryMode::CreateOrReuse).map(|_| ());
    #[cfg(test)]
    if let Err(error) = &result {
        eprintln!("private directory admission at {path:?}: {error}");
    }
    result
}

/// Return ownership only for a newly created protected directory, never an existing stage.
pub(crate) fn create_private_directory(path: &Path) -> Result<(), String> {
    directory(path, &current_user()?, DirectoryMode::CreateNew).map(|_| ())
}

pub(crate) fn require_private_directory(path: &Path) -> Result<(), String> {
    let user = current_user()?;
    directory(path, &user, DirectoryMode::ExistingOnly).map(|_| ())
}
pub(crate) fn pin_private_directory(path: &Path) -> Result<Vec<File>, String> {
    let user = current_user()?;
    directory(path, &user, DirectoryMode::ExistingOnly)
}
enum DirectoryMode {
    CreateOrReuse,
    CreateNew,
    ExistingOnly,
}

#[cfg(test)]
type ScanHook = Box<dyn FnMut(&Path)>;
#[cfg(test)]
thread_local! {
    static BEFORE_SCAN: std::cell::RefCell<Option<ScanHook>> = const { std::cell::RefCell::new(None) };
    /// A fixed answer for how long a library has been past the inventory limit.
    static OVERTIME: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
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
    /// Add a read grant for the built-in Users group, as a careless `icacls` would.
    fn grant_users_read(path: &Path) {
        let file = OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(3)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
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
    }
    fn junction(link: &Path, target: &Path) {
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink: {made:?}");
    }
    /// A private profile root with an empty private `state` inside it.
    fn profile(name: &str) -> (Fixture, PathBuf) {
        let root = Fixture(
            std::env::temp_dir().join(format!("frameleaf-{name}-{}", uuid::Uuid::new_v4())),
        );
        private_directory(&root.0).unwrap();
        let state = root.0.join("state");
        private_directory(&state).unwrap();
        (root, state)
    }
    struct ResetOvertime;
    impl Drop for ResetOvertime {
        fn drop(&mut self) {
            OVERTIME.with(|fixed| fixed.set(None));
        }
    }

    #[test]
    fn a_library_past_the_inventory_limit_starts_and_everything_else_is_still_inspected() {
        let (root, state) = profile("large-library");
        let _reset = ResetOvertime;
        // Eleven directories of 9,100 empty files: 100,111 entries, more than the limit.
        let bulk = state.join("bulk");
        fs::create_dir(&bulk).unwrap();
        for directory in 0..11 {
            let directory = bulk.join(format!("{directory:02}"));
            fs::create_dir(&directory).unwrap();
            for file in 0..9_100 {
                File::create(directory.join(file.to_string())).unwrap();
            }
        }
        assert_eq!(
            private_directory(&state).unwrap_err(),
            "runtime_store_privacy_inventory_limit",
            "negative control: this much state outside a library is still refused"
        );
        let media = state.join("media");
        fs::rename(&bulk, &media).unwrap();
        // The same tree as a photo library is admitted, through the profile root too, with
        // time left to inspect all of it.
        OVERTIME.with(|fixed| fixed.set(Some(Duration::ZERO)));
        private_directory(&state).unwrap();
        pin_private_directory(&root.0).unwrap();
        // An exposed file that sorts after the first 100,000 entries.
        fs::create_dir(media.join("zz")).unwrap();
        fs::write(media.join("zz").join("exposed"), b"synthetic").unwrap();
        grant_users_read(&media.join("zz").join("exposed"));
        assert_eq!(
            private_directory(&state).unwrap_err(),
            ERROR,
            "while time allows, entries past the limit are still inspected"
        );
        // Out of time: what was not reached neither passes inspection nor refuses the start.
        OVERTIME.with(|fixed| fixed.set(Some(super::super::LIBRARY_OVERTIME)));
        private_directory(&state).unwrap();
        // State outside the library that sorts after it is inspected all the same.
        let secrets = state.join("secrets");
        fs::create_dir(&secrets).unwrap();
        fs::write(secrets.join("key"), b"synthetic").unwrap();
        private_directory(&state).unwrap();
        grant_users_read(&secrets.join("key"));
        assert_eq!(private_directory(&state).unwrap_err(), ERROR);
        fs::remove_dir_all(&secrets).unwrap();
        private_directory(&state).unwrap();
        // And so are the library's first 100,000 entries, as they always were.
        grant_users_read(&media.join("00").join("0"));
        assert_eq!(private_directory(&state).unwrap_err(), ERROR);
    }

    #[test]
    fn a_junction_leaving_the_tree_is_refused_in_fixed_state_as_the_library_and_inside_it() {
        let outside = Fixture(
            std::env::temp_dir().join(format!("frameleaf-junction-to-{}", uuid::Uuid::new_v4())),
        );
        fs::create_dir(&outside.0).unwrap();
        fs::write(outside.0.join("elsewhere"), b"outside").unwrap();
        for place in ["secrets/link", "media", "media/2026/link"] {
            let (root, state) = profile("junction");
            let link = state.join(place);
            fs::create_dir_all(link.parent().unwrap()).unwrap();
            private_directory(&state).unwrap();
            junction(&link, &outside.0);
            assert!(
                link.join("elsewhere").exists(),
                "negative control: the junction leaves the tree"
            );
            assert_eq!(private_directory(&state).unwrap_err(), ERROR, "{place}");
            assert_eq!(private_directory(&root.0).unwrap_err(), ERROR, "{place}");
            assert!(pin_private_directory(&state).is_err(), "{place}");
            // Removing the junction, not its target, is what admits the tree again.
            fs::remove_dir(&link).unwrap();
            private_directory(&state).unwrap();
            assert_eq!(fs::read(outside.0.join("elsewhere")).unwrap(), b"outside");
        }
    }

    #[test]
    fn a_foreign_grant_is_refused_on_fixed_state_on_the_library_and_inside_it() {
        for place in [
            "secrets",
            "database",
            "database/base/1",
            "media",
            "media/2026",
            "media/2026/photo.jpg",
        ] {
            let (root, state) = profile("foreign-grant");
            let target = state.join(place);
            if target.extension().is_some() {
                fs::create_dir_all(target.parent().unwrap()).unwrap();
                fs::write(&target, b"synthetic").unwrap();
            } else {
                fs::create_dir_all(&target).unwrap();
            }
            private_directory(&state).unwrap();
            grant_users_read(&target);
            assert_eq!(private_directory(&state).unwrap_err(), ERROR, "{place}");
            assert_eq!(private_directory(&root.0).unwrap_err(), ERROR, "{place}");
            assert!(require_private_directory(&state).is_err(), "{place}");
        }
    }

    #[test]
    fn private_file_with_a_writer_that_denies_read_sharing_is_admitted_without_reading_data() {
        use std::io::Write;
        let root = Fixture(std::env::temp_dir().join(format!(
            "frameleaf-private-file-share-{}",
            uuid::Uuid::new_v4()
        )));
        private_directory(&root.0).unwrap();
        let path = root.0.join("private-journal");
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(2 | 4)
            .open(&path)
            .unwrap();
        writer.write_all(b"private journal bytes").unwrap();
        writer.flush().unwrap();
        let before = super::super::native::security(&writer).unwrap();
        let read_data = OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY)
            .share_mode(3)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL)
            .open(&path);
        assert!(
            read_data.is_err(),
            "negative control: the existing writer must actually deny read-data sharing"
        );
        private_directory(&root.0).unwrap();
        assert_eq!(
            super::super::native::security(&writer).unwrap(),
            before,
            "admission must not alter the file ACL"
        );
        drop(writer);
        assert_eq!(fs::read(path).unwrap(), b"private journal bytes");
    }

    #[test]
    fn directory_pin_enforces_delete_sharing_unlike_a_metadata_only_handle() {
        let root = Fixture(
            std::env::temp_dir().join(format!("frameleaf-share-pin-{}", uuid::Uuid::new_v4())),
        );
        private_directory(&root.0).unwrap();
        let parked = root.0.with_extension("parked");
        let _parked_cleanup = Fixture(parked.clone());
        let metadata_only = OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(3)
            .custom_flags(
                FILE_FLAG_BACKUP_SEMANTICS
                    | FILE_FLAG_OPEN_REPARSE_POINT
                    | FILE_FLAG_OPEN_NO_RECALL,
            )
            .open(&root.0)
            .unwrap();
        fs::rename(&root.0, &parked)
            .expect("negative control: metadata-only handles do not pin the directory name");
        fs::rename(&parked, &root.0).unwrap();
        drop(metadata_only);
        let pin = open(&root.0).unwrap();
        assert!(
            fs::rename(&root.0, &parked).is_err(),
            "the admission handle must prevent replacement"
        );
        drop(pin);
        fs::rename(&root.0, &parked).expect("the pin must release delete sharing after admission");
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
    #[test]
    fn retained_private_admission_pins_the_leaf_and_its_ancestors() {
        let root =
            std::env::temp_dir().join(format!("frameleaf-ancestry-pin-{}", uuid::Uuid::new_v4()));
        create_private_directory(&root).unwrap();
        let fixture = Fixture(root);
        let leaf = fixture.0.join("state");
        create_private_directory(&leaf).unwrap();
        let pins = pin_private_directory(&leaf).unwrap();
        assert!(fs::rename(&fixture.0, fixture.0.with_extension("moved")).is_err());
        assert!(fs::rename(&leaf, leaf.with_extension("moved")).is_err());
        assert!(fs::remove_dir(&leaf).is_err());
        fs::write(leaf.join("allowed"), b"synthetic state").unwrap();
        fs::remove_file(leaf.join("allowed")).unwrap();
        drop(pins);
        let moved = fixture.0.join("moved");
        fs::rename(&leaf, &moved).unwrap();
        fs::rename(&moved, &leaf).unwrap();
        let moved = fixture.0.with_extension("moved");
        fs::rename(&fixture.0, &moved).unwrap();
        fs::rename(&moved, &fixture.0).unwrap();
    }
    #[test]
    fn existing_private_admission_never_recreates_a_directory_removed_after_inspection() {
        let root = std::env::temp_dir().join(format!(
            "frameleaf-existing-private-{}",
            uuid::Uuid::new_v4()
        ));
        create_private_directory(&root).unwrap();
        crate::native_runtime::absolute_directory(&root).unwrap();
        fs::remove_dir(&root).unwrap();
        assert!(require_private_directory(&root).is_err());
        assert!(!root.exists());
    }
    #[test]
    fn exclusive_private_creation_refuses_existing_state_without_repair_or_deletion() {
        let root =
            std::env::temp_dir().join(format!("frameleaf-new-private-{}", uuid::Uuid::new_v4()));
        create_private_directory(&root).unwrap();
        let fixture = Fixture(root);
        let path = fixture.0.join("synthetic-state");
        fs::write(&path, b"retain").unwrap();
        let before = super::super::native::security(&open(&fixture.0).unwrap()).unwrap();
        assert!(create_private_directory(&fixture.0).is_err());
        assert_eq!(
            super::super::native::security(&open(&fixture.0).unwrap()).unwrap(),
            before
        );
        assert_eq!(fs::read(&path).unwrap(), b"retain");
        private_directory(&fixture.0).unwrap();
    }
}
