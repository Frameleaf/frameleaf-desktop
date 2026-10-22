//! Check the effective token against a metadata handle; never open or recall media data.
use cap_std::fs::{Dir, File, OpenOptions, OpenOptionsExt};
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree, ERROR_NO_TOKEN},
    Security::{
        AccessCheck,
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        DuplicateToken, SecurityImpersonation, DACL_SECURITY_INFORMATION, GENERIC_MAPPING,
        GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, TOKEN_DUPLICATE, TOKEN_QUERY,
    },
    Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_FLAG_OPEN_NO_RECALL, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, READ_CONTROL,
    },
    System::Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
};
const ERROR: &str = "source_item_unavailable";
struct Descriptor(*mut core::ffi::c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
pub(super) fn open_current(dir: &Dir, name: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL)
        .share_mode(7)
        .custom_flags(FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = dir.open_with(name, &options).map_err(|_| ERROR)?;
    let mut descriptor = Descriptor(std::ptr::null_mut());
    if unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor.0,
        )
    } != 0
        || descriptor.0.is_null()
    {
        return Err(ERROR.into());
    }
    let mut raw = std::ptr::null_mut();
    if unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            1,
            &mut raw,
        )
    } == 0
    {
        if unsafe { GetLastError() } != ERROR_NO_TOKEN
            || unsafe {
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw)
            } == 0
        {
            return Err(ERROR.into());
        }
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut impersonation = std::ptr::null_mut();
    if unsafe {
        DuplicateToken(
            token.as_raw_handle(),
            SecurityImpersonation,
            &mut impersonation,
        )
    } == 0
    {
        return Err(ERROR.into());
    }
    let impersonation = unsafe { OwnedHandle::from_raw_handle(impersonation) };
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    let mut privileges = [0usize; 512];
    let mut size = std::mem::size_of_val(&privileges) as u32;
    let mut granted = 0;
    let mut allowed = 0;
    if unsafe {
        AccessCheck(
            descriptor.0,
            impersonation.as_raw_handle(),
            FILE_READ_DATA,
            &mapping,
            privileges.as_mut_ptr().cast(),
            &mut size,
            &mut granted,
            &mut allowed,
        )
    } == 0
        || allowed == 0
        || granted & FILE_READ_DATA == 0
    {
        return Err(ERROR.into());
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denied_data_reads_cannot_use_unchanged_metadata() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SetFileSecurityW, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        let base =
            std::env::temp_dir().join(format!("frameleaf-read-acl-{}", uuid::Uuid::new_v4()));
        crate::windows_protection::new_private_directory(&base).unwrap();
        let _cleanup = super::super::Partial(Some(base.clone()));
        let path = base.join("original.jpg");
        std::fs::write(&path, b"synthetic original").unwrap();
        let dir = Dir::open_ambient_dir(&base, cap_std::ambient_authority()).unwrap();
        let before =
            super::super::opened_stamp(&open_current(&dir, Path::new("original.jpg")).unwrap())
                .unwrap();
        let sid = crate::windows_protection::process_user_sid().unwrap();
        let sddl: Vec<u16> = format!("D:P(D;;0x1;;;{sid})(A;;FA;;;{sid})\0")
            .encode_utf16()
            .collect();
        let mut denied = Descriptor(std::ptr::null_mut());
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut denied.0,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        assert_ne!(
            unsafe {
                SetFileSecurityW(
                    path.as_ptr(),
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    denied.0,
                )
            },
            0
        );
        let mut options = OpenOptions::new();
        options
            .read(true)
            .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL)
            .share_mode(7)
            .custom_flags(FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_OPEN_REPARSE_POINT);
        let metadata = dir.open_with("original.jpg", &options).unwrap();
        assert_eq!(super::super::opened_stamp(&metadata).unwrap(), before);
        assert_eq!(
            open_current(&dir, Path::new("original.jpg"))
                .err()
                .as_deref(),
            Some(ERROR)
        );
    }
}
