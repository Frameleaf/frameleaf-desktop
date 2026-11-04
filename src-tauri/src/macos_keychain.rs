use super::Prompt;
use core_foundation::{
    base::TCFType,
    data::{CFData, CFDataRef},
};
use serde::de::DeserializeOwned;
use std::{ffi::CString, ptr};

extern "C" {
    fn frameleaf_keychain(
        operation: u32,
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

fn operation(op: u32, account: &str, prompt: u32, bytes: &[u8]) -> Result<Option<CFData>, String> {
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
        -25300 if op != 1 => Ok(None), // errSecItemNotFound
        -128 | -25293 | -25308 => Err("credential_unlock_required".into()),
        _ => Err("credential_store_locked_or_unavailable".into()),
    }
}

pub(super) fn read<T: DeserializeOwned>(
    account: &str,
    prompt: Prompt,
) -> Result<Option<T>, String> {
    operation(0, account, prompt as u32, &[])?
        .map(|data| {
            serde_json::from_slice(data.bytes()).map_err(|_| "credential_record_invalid".into())
        })
        .transpose()
}
pub(super) fn write(account: &str, bytes: &[u8]) -> Result<(), String> {
    operation(1, account, 0, bytes).map(|_| ())
}
pub(super) fn delete(account: &str) -> Result<(), String> {
    operation(2, account, 0, &[]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_accounts_cannot_reach_any_native_keychain_operation() {
        let name = "bad\0account";
        assert!(read::<String>(name, Prompt::Silent).is_err());
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
