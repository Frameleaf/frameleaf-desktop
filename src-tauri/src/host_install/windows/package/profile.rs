//! Explicit installer-selected accounts; UAC account selection never determines the photo owner.
use super::*;
use windows_sys::Win32::Security::{
    Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW},
    GetLengthSid, IsValidSid, LookupAccountSidW, SidTypeUser,
};
const ACCOUNT: &str = "host_install_profile_user_invalid";

pub(super) struct Ownership {
    token: OwnedHandle,
    previous: windows_sys::Win32::Security::TOKEN_PRIVILEGES,
}
impl Ownership {
    pub(super) fn enable() -> Result<Self, String> {
        use windows_sys::Win32::{
            Foundation::{GetLastError, SetLastError, ERROR_NO_TOKEN, LUID},
            Security::{
                AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
                SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
            },
            System::Threading::{GetCurrentThread, OpenThreadToken},
        };
        let mut thread = std::ptr::null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread) } != 0 {
            let _thread = unsafe { OwnedHandle::from_raw_handle(thread) };
            return Err(AUTHORITY.into());
        }
        if unsafe { GetLastError() } != ERROR_NO_TOKEN {
            return Err(AUTHORITY.into());
        }
        let mut value = Self {
            token: process_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)?,
            previous: TOKEN_PRIVILEGES::default(),
        };
        let name: Vec<u16> = "SeRestorePrivilege\0".encode_utf16().collect();
        let mut luid = LUID::default();
        if unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) } == 0 {
            return Err(AUTHORITY.into());
        }
        let requested = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut size = 0;
        unsafe {
            SetLastError(0);
        }
        let result = unsafe {
            AdjustTokenPrivileges(
                value.token.as_raw_handle(),
                0,
                &requested,
                std::mem::size_of_val(&value.previous) as u32,
                &mut value.previous,
                &mut size,
            )
        };
        if result == 0 || unsafe { GetLastError() } != 0 {
            return Err(AUTHORITY.into());
        }
        Ok(value)
    }
}
impl Drop for Ownership {
    fn drop(&mut self) {
        use windows_sys::Win32::{
            Foundation::{GetLastError, SetLastError},
            Security::AdjustTokenPrivileges,
        };
        if self.previous.PrivilegeCount == 0 {
            return;
        }
        unsafe {
            SetLastError(0);
        }
        let result = unsafe {
            AdjustTokenPrivileges(
                self.token.as_raw_handle(),
                0,
                &self.previous,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if result == 0 || unsafe { GetLastError() } != 0 {
            std::process::abort();
        }
    }
}

pub(super) struct Account {
    pub(super) name: String,
    sid: Vec<u8>,
}

impl Account {
    pub(super) fn lookup(value: &str) -> Result<Self, String> {
        if value.len() > 184
            || !value.starts_with("S-1-")
            || !value[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-')
        {
            return Err(ACCOUNT.into());
        }
        let text: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
        let mut sid = Descriptor(std::ptr::null_mut());
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid.0) } == 0
            || sid.0.is_null()
            || unsafe { IsValidSid(sid.0) } == 0
        {
            return Err(ACCOUNT.into());
        }
        let mut canonical = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid.0, &mut canonical) } == 0 || canonical.is_null() {
            return Err(ACCOUNT.into());
        }
        let _canonical = Descriptor(canonical.cast());
        let length = (0..185)
            .find(|i| unsafe { *canonical.add(*i) == 0 })
            .ok_or(ACCOUNT)?;
        let canonical =
            String::from_utf16(unsafe { std::slice::from_raw_parts(canonical, length) })
                .map_err(|_| ACCOUNT)?;
        if canonical != value {
            return Err(ACCOUNT.into());
        }
        let mut name = [0u16; 256];
        let mut domain = [0u16; 256];
        let mut name_length = name.len() as u32;
        let mut domain_length = domain.len() as u32;
        let mut kind = 0;
        if unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid.0,
                name.as_mut_ptr(),
                &mut name_length,
                domain.as_mut_ptr(),
                &mut domain_length,
                &mut kind,
            )
        } == 0
            || kind != SidTypeUser
            || name_length == 0
            || name_length as usize >= name.len()
            || domain_length as usize >= domain.len()
        {
            return Err(ACCOUNT.into());
        }
        let length = unsafe { GetLengthSid(sid.0) } as usize;
        if !(8..=68).contains(&length) {
            return Err(ACCOUNT.into());
        }
        Ok(Self {
            name: canonical,
            sid: unsafe { std::slice::from_raw_parts(sid.0.cast::<u8>(), length) }.to_vec(),
        })
    }
}

pub(super) fn prepare(profiles: &Path, user: &Account) -> Result<(), String> {
    directory(profiles)?;
    let parent = profiles.join(&user.name);
    directory(&parent)?;
    for entry in fs::read_dir(&parent).map_err(|_| "host_install_profile_changed")? {
        let entry = entry.map_err(|_| "host_install_profile_changed")?;
        if entry.file_name() != "state" && entry.file_name() != "manager" {
            return Err("host_install_profile_changed".into());
        }
    }
    for name in ["state", "manager"] {
        crate::windows_protection::account_directory(&parent.join(name), &user.sid)?;
    }
    Ok(())
}

pub(in crate::host_install) fn provision(
    manifest: &str,
    controller: &str,
    sid: &str,
) -> Result<serde_json::Value, String> {
    require_administrator()?;
    let layout = crate::host_install::Layout::new(manifest, controller)?;
    let record = crate::host_install::Installation::read(manifest)?;
    if record.controller_sha256 != controller {
        return Err("host_install_record_invalid".into());
    }
    let user = Account::lookup(sid)?;
    crate::windows_protection::protect(
        &layout.runtime.join(".runtime-lease"),
        &mut BTreeSet::new(),
    )?;
    let _guard = crate::host_install::finalization_guard(&layout.runtime, false, || {
        crate::host_install::verify_resources(&layout, manifest, controller)
    })?;
    {
        let _ownership = Ownership::enable()?;
        prepare(&layout.profiles, &user)?;
    }
    Ok(
        serde_json::json!({"protocolVersion":1,"state":"resources-installed","profileReady":true,
        "manifestSha256":manifest,"controllerSha256":controller,"serverStarted":false,
        "runtimeQualified":false,"redistributable":false}),
    )
}

#[cfg(test)]
pub(super) fn ownership_enabled() -> bool {
    use windows_sys::Win32::{
        Foundation::LUID,
        Security::{
            LookupPrivilegeValueW, TokenPrivileges, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
            TOKEN_PRIVILEGES,
        },
    };
    let token = process_token(TOKEN_QUERY).unwrap();
    let name: Vec<u16> = "SeRestorePrivilege\0".encode_utf16().collect();
    let mut luid = LUID::default();
    assert_ne!(
        unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) },
        0
    );
    let mut buffer = [0usize; 1024];
    let mut size = 0;
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenPrivileges,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                &mut size,
            )
        },
        0
    );
    let offset = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    assert!((offset..=std::mem::size_of_val(&buffer)).contains(&(size as usize)));
    let privileges = buffer.as_ptr().cast::<TOKEN_PRIVILEGES>();
    let count = unsafe { (*privileges).PrivilegeCount } as usize;
    assert!(count <= (size as usize - offset) / std::mem::size_of::<LUID_AND_ATTRIBUTES>());
    let entries = unsafe { std::slice::from_raw_parts((*privileges).Privileges.as_ptr(), count) };
    entries.iter().any(|entry| {
        entry.Luid.LowPart == luid.LowPart
            && entry.Luid.HighPart == luid.HighPart
            && entry.Attributes & SE_PRIVILEGE_ENABLED != 0
    })
}

#[cfg(test)]
pub(super) fn current_account() -> Account {
    use windows_sys::Win32::Security::{TokenUser, TOKEN_USER};
    let token = process_token(TOKEN_QUERY).unwrap();
    let mut buffer = [0usize; 128];
    let mut size = 0;
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                &mut size,
            )
        },
        0
    );
    assert!(size as usize <= std::mem::size_of_val(&buffer));
    let sid = unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let mut text = std::ptr::null_mut();
    assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut text) }, 0);
    let _text = Descriptor(text.cast());
    let length = (0..185).find(|i| unsafe { *text.add(*i) == 0 }).unwrap();
    Account::lookup(
        &String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).unwrap(),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_selection_requires_canonical_resolved_user_and_never_accepts_groups_or_services() {
        current_account();
        for value in [
            "",
            "BA",
            "S-1-5-18",
            "S-1-5-32-545",
            "S-1-05-18",
            "s-1-5-18",
            "S-1-5-21-0-0-0-4294967295",
            "../profile",
            "S-1-5-18\0",
            "S-1-5-18/other",
        ] {
            assert!(Account::lookup(value).is_err(), "invalid account admitted");
        }
    }
}
