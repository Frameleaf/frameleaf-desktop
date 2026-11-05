//! Keep the foreground agent owned while removing administrator permissions from its token.
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, GetLastError, LocalFree, DUPLICATE_SAME_ACCESS, ERROR_INSUFFICIENT_BUFFER,
        GENERIC_ALL, WAIT_OBJECT_0,
    },
    Security::{
        Authorization::{
            ConvertStringSidToSidW, SetEntriesInAclW, EXPLICIT_ACCESS_W, GRANT_ACCESS,
            TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
        },
        CreateRestrictedToken, CreateWellKnownSid, GetTokenInformation, SetTokenInformation,
        TokenDefaultDacl, WinBuiltinAdministratorsSid, WinBuiltinPowerUsersSid, ACL,
        DISABLE_MAX_PRIVILEGE, OBJECT_INHERIT_ACE, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_QUERY,
    },
    System::Threading::{
        CreateProcessAsUserW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
        InitializeProcThreadAttributeList, OpenProcessToken, ResumeThread, TerminateProcess,
        UpdateProcThreadAttribute, WaitForSingleObject, BELOW_NORMAL_PRIORITY_CLASS,
        CREATE_NO_WINDOW, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
        PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, STARTUPINFOW,
    },
};

const ERROR: &str = "host_agent_restricted_launch_failed";
struct Local(*mut core::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct Attributes(Vec<usize>);
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.0.as_mut_ptr().cast());
        }
    }
}
impl Attributes {
    /// Restrict inheritance to these pipes even if another thread opens an inheritable handle.
    fn pipes(handles: &[windows_sys::Win32::Foundation::HANDLE]) -> Result<Self, String> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 || bytes > 1_048_576 {
            return Err(ERROR.into());
        }
        let mut storage = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 1, 0, &mut bytes)
        } == 0
        {
            return Err(ERROR.into());
        }
        let mut list = Self(storage);
        if unsafe {
            UpdateProcThreadAttribute(
                list.0.as_mut_ptr().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(ERROR.into());
        }
        Ok(list)
    }
}

/// Retain an aligned, bounded copy of the ACL used for objects created by this token.
fn default_dacl(token: &OwnedHandle) -> Result<Vec<usize>, String> {
    let mut bytes = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenDefaultDacl,
            std::ptr::null_mut(),
            0,
            &mut bytes,
        )
    } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || bytes < std::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32
        || bytes > 1_048_576
    {
        return Err(ERROR.into());
    }
    let mut buffer = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
    let capacity = std::mem::size_of_val(buffer.as_slice());
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenDefaultDacl,
            buffer.as_mut_ptr().cast(),
            capacity as u32,
            &mut bytes,
        )
    } == 0
        || bytes as usize > capacity
        || (bytes as usize) < std::mem::size_of::<TOKEN_DEFAULT_DACL>()
    {
        return Err(ERROR.into());
    }
    let acl = unsafe { (*buffer.as_ptr().cast::<TOKEN_DEFAULT_DACL>()).DefaultDacl };
    let offset = (acl as usize)
        .checked_sub(buffer.as_ptr() as usize)
        .ok_or(ERROR)?;
    if acl.is_null()
        || !(acl as usize).is_multiple_of(std::mem::align_of::<ACL>())
        || offset
            .checked_add(std::mem::size_of::<ACL>())
            .is_none_or(|end| end > bytes as usize)
    {
        return Err(ERROR.into());
    }
    let size = usize::from(unsafe { (*acl).AclSize });
    if size < std::mem::size_of::<ACL>()
        || offset
            .checked_add(size)
            .is_none_or(|end| end > bytes as usize)
    {
        return Err(ERROR.into());
    }
    Ok(buffer)
}

/// Preserve default object grants and keep new objects accessible after administrator groups are denied.
fn grant_token_user(token: &OwnedHandle) -> Result<(), String> {
    let name: Vec<u16> = crate::windows_protection::process_user_sid()?
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let defaults = default_dacl(token)?;
    let previous = unsafe { (*defaults.as_ptr().cast::<TOKEN_DEFAULT_DACL>()).DefaultDacl };
    let mut sid = Local(std::ptr::null_mut());
    let mut acl = Local(std::ptr::null_mut());
    unsafe {
        if ConvertStringSidToSidW(name.as_ptr(), &mut sid.0) == 0 {
            return Err(ERROR.into());
        }
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: OBJECT_INHERIT_ACE,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: sid.0.cast(),
                ..Default::default()
            },
        };
        let mut updated = std::ptr::null_mut();
        let result = SetEntriesInAclW(1, &entry, previous, &mut updated);
        acl.0 = updated.cast();
        if result != 0 {
            return Err(ERROR.into());
        }
        let defaults = TOKEN_DEFAULT_DACL {
            DefaultDacl: updated,
        };
        if SetTokenInformation(
            token.as_raw_handle(),
            TokenDefaultDacl,
            (&defaults as *const TOKEN_DEFAULT_DACL).cast(),
            std::mem::size_of_val(&defaults) as u32,
        ) == 0
        {
            return Err(ERROR.into());
        }
    }
    Ok(())
}

/// Start only a protected agent executable; the existing bootstrap still gates payload execution on stdin.
pub fn run(node: &OsStr) -> Result<u32, String> {
    let node = crate::windows_protection::stable_path(Path::new(node)).map_err(|_| ERROR)?;
    crate::windows_protection::protect(&node, &mut BTreeSet::new()).map_err(|_| ERROR)?;
    run_command(
        &node,
        &[
            OsStr::new("--input-type=module"),
            OsStr::new("--eval"),
            OsStr::new(super::AGENT_BOOTSTRAP),
        ],
    )
}

/// Quote UTF-16 arguments using Windows' backslash-before-quote rules.
fn command_line(arguments: &[&OsStr]) -> Result<Vec<u16>, String> {
    let mut line = Vec::new();
    for argument in arguments {
        if !line.is_empty() {
            line.push(b' ' as u16);
        }
        line.push(b'"' as u16);
        let mut slashes = 0;
        for value in argument.encode_wide() {
            if value == 0 {
                return Err(ERROR.into());
            }
            if value == b'\\' as u16 {
                slashes += 1;
                continue;
            }
            line.extend(std::iter::repeat_n(
                b'\\' as u16,
                if value == b'"' as u16 {
                    slashes * 2 + 1
                } else {
                    slashes
                },
            ));
            line.push(value);
            slashes = 0;
        }
        line.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
        line.push(b'"' as u16);
    }
    if line.len() >= 32767 {
        return Err(ERROR.into());
    }
    line.push(0);
    Ok(line)
}

/// Remove privileged groups and privileges without changing the profile user.
fn restricted_token() -> Result<OwnedHandle, String> {
    unsafe {
        let mut raw = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            &mut raw,
        ) == 0
        {
            return Err(ERROR.into());
        }
        let original = OwnedHandle::from_raw_handle(raw);
        let mut administrators = [0u32; 17];
        let mut power_users = [0u32; 17];
        for (kind, buffer) in [
            (WinBuiltinAdministratorsSid, &mut administrators),
            (WinBuiltinPowerUsersSid, &mut power_users),
        ] {
            let mut size = std::mem::size_of_val(buffer) as u32;
            if CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            ) == 0
            {
                return Err(ERROR.into());
            }
        }
        let groups = [
            SID_AND_ATTRIBUTES {
                Sid: administrators.as_mut_ptr().cast(),
                Attributes: 0,
            },
            SID_AND_ATTRIBUTES {
                Sid: power_users.as_mut_ptr().cast(),
                Attributes: 0,
            },
        ];
        let mut raw = std::ptr::null_mut();
        if CreateRestrictedToken(
            original.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            groups.len() as u32,
            groups.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut raw,
        ) == 0
        {
            return Err(ERROR.into());
        }
        let token = OwnedHandle::from_raw_handle(raw);
        grant_token_user(&token)?;
        Ok(token)
    }
}

/// Retain pipes and a kill-on-close job while supervising a restricted foreground child.
fn run_command(program: &Path, arguments: &[&OsStr]) -> Result<u32, String> {
    let program_name = program.as_os_str();
    let mut all = vec![program_name];
    all.extend_from_slice(arguments);
    let mut line = command_line(&all)?;
    let executable: Vec<u16> = program_name.encode_wide().chain(Some(0)).collect();
    let token = restricted_token()?;
    unsafe {
        let mut pipes = Vec::new();
        for handle in [
            std::io::stdin().as_raw_handle(),
            std::io::stdout().as_raw_handle(),
            std::io::stderr().as_raw_handle(),
        ] {
            let mut duplicate = std::ptr::null_mut();
            if DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            ) == 0
            {
                return Err(ERROR.into());
            }
            pipes.push(OwnedHandle::from_raw_handle(duplicate));
        }
        let inherited: Vec<_> = pipes.iter().map(AsRawHandle::as_raw_handle).collect();
        let mut attributes = Attributes::pipes(&inherited)?;
        let startup = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: pipes[0].as_raw_handle(),
                hStdOutput: pipes[1].as_raw_handle(),
                hStdError: pipes[2].as_raw_handle(),
                ..Default::default()
            },
            lpAttributeList: attributes.0.as_mut_ptr().cast(),
        };
        let mut process = PROCESS_INFORMATION::default();
        if CreateProcessAsUserW(
            token.as_raw_handle(),
            executable.as_ptr(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | BELOW_NORMAL_PRIORITY_CLASS
                | EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null(),
            std::ptr::null(),
            &startup.StartupInfo,
            &mut process,
        ) == 0
        {
            return Err(ERROR.into());
        }
        let child = OwnedHandle::from_raw_handle(process.hProcess);
        let thread = OwnedHandle::from_raw_handle(process.hThread);
        let tree = match crate::process_tree::ProcessTree::attach_handle(child.as_handle()) {
            Ok(tree) => tree,
            Err(error) => {
                TerminateProcess(child.as_raw_handle(), 1);
                WaitForSingleObject(child.as_raw_handle(), 5000);
                return Err(error);
            }
        };
        #[cfg(test)]
        tests::assert_child_token(child.as_raw_handle());
        // The child cannot run before its kill-on-close owner is installed.
        if ResumeThread(thread.as_raw_handle()) == u32::MAX
            || WaitForSingleObject(child.as_raw_handle(), INFINITE) != WAIT_OBJECT_0
        {
            tree.terminate_confirmed(Duration::from_secs(5))?;
            return Err(ERROR.into());
        }
        let mut code = 0;
        if GetExitCodeProcess(child.as_raw_handle(), &mut code) == 0 {
            return Err(ERROR.into());
        }
        tree.terminate_confirmed(Duration::from_secs(5))?;
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inspect native privilege entries so flag wording cannot substitute for token-state proof.
    fn privileges(token: &OwnedHandle) -> Vec<windows_sys::Win32::Security::LUID_AND_ATTRIBUTES> {
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenPrivileges, TOKEN_PRIVILEGES,
        };
        let mut buffer = [0usize; 128];
        let mut bytes = 0;
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenPrivileges,
                    buffer.as_mut_ptr().cast(),
                    std::mem::size_of_val(&buffer) as u32,
                    &mut bytes,
                )
            },
            0
        );
        assert!(bytes as usize <= std::mem::size_of_val(&buffer));
        let value = unsafe { &*buffer.as_ptr().cast::<TOKEN_PRIVILEGES>() };
        let count = value.PrivilegeCount as usize;
        assert!(
            std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges)
                + count * std::mem::size_of::<windows_sys::Win32::Security::LUID_AND_ATTRIBUTES>()
                <= bytes as usize
        );
        unsafe { std::slice::from_raw_parts(value.Privileges.as_ptr(), count) }.to_vec()
    }

    /// Inspect the created child's token before it can execute any fixture code.
    pub(super) fn assert_child_token(child: windows_sys::Win32::Foundation::HANDLE) {
        use windows_sys::Win32::Security::{
            Authorization::{ConvertSidToStringSidW, GetExplicitEntriesFromAclW},
            CheckTokenMembership, DuplicateTokenEx, EqualSid, GetTokenInformation,
            LookupPrivilegeValueW, SecurityImpersonation, TokenImpersonation, TokenUser,
            TOKEN_USER,
        };
        let mut raw = std::ptr::null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(child, TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) },
            0
        );
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut buffer = [0usize; 128];
        let mut bytes = 0;
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    std::mem::size_of_val(&buffer) as u32,
                    &mut bytes,
                )
            },
            0
        );
        assert!(bytes as usize <= std::mem::size_of_val(&buffer));
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut text = std::ptr::null_mut();
        assert_ne!(
            unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) },
            0
        );
        let allocation = Local(text.cast());
        let length = (0..256)
            .find(|index| unsafe { *text.add(*index) == 0 })
            .unwrap();
        let actual =
            String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).unwrap();
        assert_eq!(
            actual,
            crate::windows_protection::process_user_sid().unwrap()
        );
        drop(allocation);
        let defaults = default_dacl(&token).unwrap();
        let default = unsafe { (*defaults.as_ptr().cast::<TOKEN_DEFAULT_DACL>()).DefaultDacl };
        let mut count = 0;
        let mut entries = std::ptr::null_mut();
        assert_eq!(
            unsafe { GetExplicitEntriesFromAclW(default, &mut count, &mut entries) },
            0
        );
        let allocation = Local(entries.cast());
        assert!(count > 0 && count <= 65536 && !entries.is_null());
        let entries = unsafe { std::slice::from_raw_parts(entries, count as usize) };
        assert!(
            entries
                .iter()
                .any(|entry| entry.grfAccessMode == GRANT_ACCESS
                    && entry.grfAccessPermissions & GENERIC_ALL != 0
                    && entry.Trustee.TrusteeForm == TRUSTEE_IS_SID
                    && unsafe { EqualSid(entry.Trustee.ptstrName.cast(), user.User.Sid) } != 0),
            "the actual child's default object ACL must explicitly grant its user full access"
        );
        drop(allocation);
        let mut raw = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                DuplicateTokenEx(
                    token.as_raw_handle(),
                    TOKEN_QUERY,
                    std::ptr::null(),
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut raw,
                )
            },
            0
        );
        let membership = unsafe { OwnedHandle::from_raw_handle(raw) };
        for kind in [WinBuiltinAdministratorsSid, WinBuiltinPowerUsersSid] {
            let mut sid = [0u32; 17];
            let mut size = std::mem::size_of_val(&sid) as u32;
            assert_ne!(
                unsafe {
                    CreateWellKnownSid(
                        kind,
                        std::ptr::null_mut(),
                        sid.as_mut_ptr().cast(),
                        &mut size,
                    )
                },
                0
            );
            let mut member = 1;
            assert_ne!(
                unsafe {
                    CheckTokenMembership(
                        membership.as_raw_handle(),
                        sid.as_mut_ptr().cast(),
                        &mut member,
                    )
                },
                0
            );
            assert_eq!(member, 0);
        }
        let name: Vec<u16> = "SeChangeNotifyPrivilege"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut notify = windows_sys::Win32::Foundation::LUID::default();
        assert_ne!(
            unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut notify) },
            0
        );
        assert!(privileges(&token)
            .iter()
            .all(|entry| entry.Luid.HighPart == notify.HighPart
                && entry.Luid.LowPart == notify.LowPart));
    }

    #[test]
    /// Prove filtering removes privileges, including when the child can adjust its own token.
    fn administrative_privileges_are_removed_and_cannot_be_enabled_again() {
        use windows_sys::Win32::{
            Foundation::{GetLastError, ERROR_NOT_ALL_ASSIGNED, LUID},
            Security::{
                AdjustTokenPrivileges, DuplicateTokenEx, LookupPrivilegeValueW,
                SecurityImpersonation, TokenPrimary, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
                TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
            },
        };
        let lookup = |name: &str| {
            let text: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let mut value = LUID::default();
            assert_ne!(
                unsafe { LookupPrivilegeValueW(std::ptr::null(), text.as_ptr(), &mut value) },
                0
            );
            value
        };
        let shutdown = lookup("SeShutdownPrivilege");
        let notify = lookup("SeChangeNotifyPrivilege");
        let key = |luid: LUID| (luid.HighPart, luid.LowPart);
        let mut raw = std::ptr::null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) },
            0
        );
        let original = unsafe { OwnedHandle::from_raw_handle(raw) };
        if std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted") {
            assert!(
                privileges(&original)
                    .iter()
                    .any(|entry| key(entry.Luid) == key(shutdown)),
                "the elevated CI token must hold the tested privilege"
            );
        }
        let restricted = restricted_token().unwrap();
        assert!(privileges(&restricted)
            .iter()
            .all(|entry| key(entry.Luid) == key(notify)));
        let mut raw = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                DuplicateTokenEx(
                    restricted.as_raw_handle(),
                    TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                    std::ptr::null(),
                    SecurityImpersonation,
                    TokenPrimary,
                    &mut raw,
                )
            },
            0
        );
        let adjustable = unsafe { OwnedHandle::from_raw_handle(raw) };
        let desired = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: shutdown,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        assert_ne!(
            unsafe {
                AdjustTokenPrivileges(
                    adjustable.as_raw_handle(),
                    0,
                    &desired,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_NOT_ALL_ASSIGNED);
    }

    #[test]
    /// Calibrate quoting against the OS parser, including the complete embedded bootstrap.
    fn windows_command_line_preserves_quotes_unicode_and_trailing_slashes() {
        use std::os::windows::ffi::OsStringExt;
        let values = [
            OsStr::new("test.exe"),
            OsStr::new("a b"),
            OsStr::new("é\\\"x\\"),
            OsStr::new(""),
            OsStr::new(super::super::AGENT_BOOTSTRAP),
        ];
        let line = command_line(&values).unwrap();
        let mut count = 0;
        let raw =
            unsafe { windows_sys::Win32::UI::Shell::CommandLineToArgvW(line.as_ptr(), &mut count) };
        assert!(!raw.is_null());
        let allocation = Local(raw.cast());
        let decoded = unsafe { std::slice::from_raw_parts(raw, count as usize) }
            .iter()
            .map(|argument| {
                let length = (0..32768)
                    .find(|index| unsafe { *argument.add(*index) == 0 })
                    .unwrap();
                std::ffi::OsString::from_wide(unsafe {
                    std::slice::from_raw_parts(*argument, length)
                })
            })
            .collect::<Vec<_>>();
        drop(allocation);
        assert_eq!(decoded, values);
        assert!(command_line(&[OsStr::new("bad\0argument")]).is_err());
    }

    #[test]
    /// Calibrate the supervisor with the shipped Node loader and the actual child's restricted token.
    fn actual_node_child_has_restricted_token_and_preserves_exit_status() {
        use sha2::{Digest, Sha256};
        let output = std::process::Command::new("node")
            .args(["-p", "process.execPath"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let node = crate::windows_protection::stable_path(Path::new(
            String::from_utf8(output.stdout).unwrap().trim(),
        ))
        .unwrap();
        // Match the executable pin in tools/build_host_windows_support.py.
        assert_eq!(
            format!("{:x}", Sha256::digest(std::fs::read(&node).unwrap())),
            "a619e2e09eb0d50ef4c733d678b4d22689d2afef138cd67fd3fa107b535f8819"
        );
        let code = run_command(
            &node,
            &[OsStr::new("--eval"), OsStr::new("process.exit(37)")],
        )
        .unwrap();
        assert_eq!(code, 37);
    }
}
