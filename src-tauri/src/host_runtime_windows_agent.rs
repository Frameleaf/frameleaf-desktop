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
    Foundation::{DuplicateHandle, LocalFree, DUPLICATE_SAME_ACCESS, WAIT_OBJECT_0},
    Security::{
        Authorization::{
            ConvertStringSidToSidW, GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo,
            EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_KERNEL_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
            TRUSTEE_W,
        },
        CreateRestrictedToken, CreateWellKnownSid, WinBuiltinAdministratorsSid,
        WinBuiltinPowerUsersSid, DACL_SECURITY_INFORMATION, DISABLE_MAX_PRIVILEGE, NO_INHERITANCE,
        SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY,
    },
    System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
        ResumeThread, TerminateProcess, WaitForSingleObject, BELOW_NORMAL_PRIORITY_CLASS,
        CREATE_NO_WINDOW, CREATE_SUSPENDED, INFINITE, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOW,
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

/// Preserve existing token grants and let the process user access its token after administrator groups are denied.
fn grant_token_user(token: &OwnedHandle) -> Result<(), String> {
    let name: Vec<u16> = crate::windows_protection::process_user_sid()?
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut sid = Local(std::ptr::null_mut());
    let mut descriptor = Local(std::ptr::null_mut());
    let mut acl = Local(std::ptr::null_mut());
    let mut previous = std::ptr::null_mut();
    unsafe {
        if ConvertStringSidToSidW(name.as_ptr(), &mut sid.0) == 0
            || GetSecurityInfo(
                token.as_raw_handle(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut previous,
                std::ptr::null_mut(),
                &mut descriptor.0,
            ) != 0
        {
            return Err(ERROR.into());
        }
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: TOKEN_ALL_ACCESS,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
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
        if result != 0
            || SetSecurityInfo(
                token.as_raw_handle(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                updated,
                std::ptr::null_mut(),
            ) != 0
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

/// Retain pipes and a kill-on-close job while supervising a restricted foreground child.
fn run_command(program: &Path, arguments: &[&OsStr]) -> Result<u32, String> {
    let program_name = program.as_os_str();
    let mut all = vec![program_name];
    all.extend_from_slice(arguments);
    let mut line = command_line(&all)?;
    let executable: Vec<u16> = program_name.encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut raw = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut raw) == 0 {
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
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: pipes[0].as_raw_handle(),
            hStdOutput: pipes[1].as_raw_handle(),
            hStdError: pipes[2].as_raw_handle(),
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        if CreateProcessAsUserW(
            token.as_raw_handle(),
            executable.as_ptr(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS,
            std::ptr::null(),
            std::ptr::null(),
            &startup,
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
    /// Restriction must preserve the profile's user identity while removing administrator membership.
    fn actual_child_has_no_administrator_role_and_preserves_exit_status() {
        let shell = crate::windows_protection::system_root()
            .unwrap()
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let expected = crate::windows_protection::process_user_sid().unwrap();
        let script = format!("$i=[Security.Principal.WindowsIdentity]::GetCurrent(); if ($i.User.Value -ne '{expected}' -or ([Security.Principal.WindowsPrincipal]$i).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ exit 91 }}; exit 37");
        let code = run_command(
            &shell,
            &[
                OsStr::new("-NoProfile"),
                OsStr::new("-NonInteractive"),
                OsStr::new("-Command"),
                OsStr::new(&script),
            ],
        )
        .unwrap();
        assert_eq!(code, 37);
    }
}
