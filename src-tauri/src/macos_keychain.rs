use super::Prompt;
use core_foundation::{
    base::TCFType,
    data::{CFData, CFDataRef},
};
use serde::de::DeserializeOwned;
use std::{collections::BTreeMap, ffi::CString, ptr, sync::Mutex};
use zeroize::Zeroizing;

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

const INTERACTION_NOT_ALLOWED: i32 = -25308; // errSecInteractionNotAllowed: the screen is locked

// The process reads user-presence items silently once its context is authorised. macOS can still refuse
// that context while the screen is locked, so keep the last bytes this process read or wrote.
// ponytail: process memory only, cleared on delete; same reach the authorised context already has.
type Kept = BTreeMap<String, Zeroizing<Vec<u8>>>;
static UNLOCKED: Mutex<Kept> = Mutex::new(BTreeMap::new());
fn keep(kept: &mut Kept, account: &str, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) if user_presence(account) => {
            kept.insert(account.into(), Zeroizing::new(bytes.to_vec()));
        }
        _ => {
            kept.remove(account);
        }
    }
}
fn kept(kept: &Kept, account: &str) -> Option<CFData> {
    kept.get(account).map(|bytes| CFData::from_buffer(bytes))
}

fn user_presence(account: &str) -> bool {
    matches!(account, "connection" | "cloud-account" | "manager-grant")
        || account.starts_with("approved-library-")
}

fn operation(
    op: Operation,
    account: &str,
    prompt: u32,
    bytes: &[u8],
) -> Result<Option<CFData>, String> {
    let name = CString::new(account).map_err(|_| "credential_record_invalid")?;
    let mut output = ptr::null();
    // Held across the native call (already serialized natively) so a slower read can never replace
    // bytes a newer write cached.
    let mut cache = UNLOCKED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let data = (status == 0 && !output.is_null())
        .then(|| unsafe { CFData::wrap_under_create_rule(output) });
    match (op, status) {
        (Operation::Write, 0) => keep(&mut cache, account, Some(bytes)),
        (Operation::Delete, _) => keep(&mut cache, account, None),
        (_, 0) => {
            if let Some(data) = &data {
                keep(&mut cache, account, Some(data.bytes()));
            }
        }
        (Operation::Read, INTERACTION_NOT_ALLOWED) => {
            if let Some(data) = kept(&cache, account) {
                return Ok(Some(data));
            }
        }
        _ => {}
    }
    match status {
        0 => Ok(data),
        -25300 if op != Operation::Write => Ok(None), // errSecItemNotFound
        -128 | -25293 | INTERACTION_NOT_ALLOWED => Err("credential_unlock_required".into()),
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
    fn items_stay_readable_while_the_screen_is_locked() {
        extern "C" {
            fn frameleaf_keychain_accessible() -> core_foundation::string::CFStringRef;
            static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly:
                core_foundation::string::CFStringRef;
        }
        let used = unsafe { frameleaf_keychain_accessible() };
        // kSecAttrAccessibleWhenUnlocked* stops every background read the moment the Mac locks.
        assert_eq!(used, unsafe {
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        });
    }

    #[test]
    fn a_locked_screen_reuses_only_the_presence_sign_in_this_process_already_has() {
        let mut cache = Kept::new();
        keep(&mut cache, "connection", Some(b"session"));
        assert_eq!(kept(&cache, "connection").unwrap().bytes(), b"session");
        keep(&mut cache, "connection", None);
        assert!(
            kept(&cache, "connection").is_none(),
            "sign-out forgets the copy"
        );
        keep(&mut cache, "worker-session", Some(b"worker"));
        assert!(
            kept(&cache, "worker-session").is_none(),
            "unattended items are read from the keychain itself"
        );
    }

    #[test]
    fn foreground_sign_ins_require_presence_and_worker_state_remains_unattended() {
        for account in [
            "connection",
            "cloud-account",
            "manager-grant",
            "approved-library-fixture",
        ] {
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
