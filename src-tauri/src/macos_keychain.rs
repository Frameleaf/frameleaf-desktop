use super::Prompt;
use core_foundation::{
    base::TCFType,
    data::{CFData, CFDataRef},
};
use serde::de::DeserializeOwned;
use std::{ffi::CString, ptr};

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Read,
    Write,
    Delete,
    Confirm,
}

extern "C" {
    fn frameleaf_keychain(
        operation: Operation,
        name: *const std::ffi::c_char,
        presence: bool,
        prompt: u32,
        bytes: *const u8,
        size: usize,
        output: *mut CFDataRef,
    ) -> i32;
}

fn user_presence(account: &str) -> bool {
    matches!(account, "connection" | "cloud-account" | "manager-grant")
}

fn operation(
    op: Operation,
    account: &str,
    prompt: u32,
    bytes: &[u8],
) -> Result<Option<CFData>, String> {
    let name = CString::new(account).map_err(|_| "credential_record_invalid")?;
    let mut output = ptr::null();
    // The synchronous native call borrows its input and returns only a create-rule CFData.
    let status = unsafe {
        frameleaf_keychain(
            op,
            name.as_ptr(),
            user_presence(account),
            prompt,
            bytes.as_ptr(),
            bytes.len(),
            &mut output,
        )
    };
    match status {
        0 => Ok((!output.is_null()).then(|| unsafe { CFData::wrap_under_create_rule(output) })),
        -25300 if op != Operation::Write => Ok(None), // errSecItemNotFound
        -128 | -25293 | -25308 => Err("credential_unlock_required".into()),
        _ => Err("credential_store_locked_or_unavailable".into()),
    }
}

pub(super) fn read<T: DeserializeOwned>(
    account: &str,
    prompt: Prompt,
) -> Result<Option<T>, String> {
    operation(Operation::Read, account, prompt as u32, &[])?
        .map(|data| {
            serde_json::from_slice(data.bytes()).map_err(|_| "credential_record_invalid".into())
        })
        .transpose()
}
pub(super) fn confirm(account: &str, expected: &[u8], prompt: Prompt) -> Result<(), String> {
    let data = operation(Operation::Confirm, account, prompt as u32, &[])
        .map_err(|error| {
            if error == "credential_unlock_required" {
                error
            } else {
                "credential_confirmation_unavailable".into()
            }
        })?
        .ok_or("credential_confirmation_changed")?;
    if data.bytes() != expected {
        return Err("credential_confirmation_changed".into());
    }
    Ok(())
}
pub(super) fn write(account: &str, bytes: &[u8]) -> Result<(), String> {
    operation(Operation::Write, account, 0, bytes).map(|_| ())
}
pub(super) fn delete(account: &str) -> Result<(), String> {
    operation(Operation::Delete, account, 0, &[]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_accounts_cannot_reach_any_native_keychain_operation() {
        let name = "bad\0account";
        assert!(read::<String>(name, Prompt::Silent).is_err());
        assert!(confirm(name, b"fixture", Prompt::Silent).is_err());
        assert!(write(name, b"fixture").is_err());
        assert!(delete(name).is_err());
    }

    #[test]
    fn foreground_sign_ins_require_presence_and_worker_state_remains_unattended() {
        for account in ["connection", "cloud-account", "manager-grant"] {
            assert!(user_presence(account));
        }
        for account in [
            "installation",
            "worker-session",
            "photo-source-copy",
            "manager-pairing-check",
        ] {
            assert!(!user_presence(account));
        }
    }
}
