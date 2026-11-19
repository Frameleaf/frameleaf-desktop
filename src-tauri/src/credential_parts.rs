//! Records too long for one Windows credential. Windows Credential Manager refuses a credential
//! over 2,560 bytes, and a record is stored as UTF-16, so 1,280 characters is all one holds: a
//! sign-in carrying a signed OAuth access token does not fit. Such a record is stored in parts,
//! and the account's own credential names them.
//!
//! The parts of a record live in one of two slots. A longer record is written to the slot not in
//! use, then the account's credential is pointed at it, then the old slot is emptied: a write cut
//! short leaves the earlier record readable. Parts are written upwards and removed downwards, so
//! what is left of a slot is always its first parts and can be found again to be removed.
// Only Windows has the limit; other systems use the trait alone.
#![cfg_attr(not(any(windows, test)), allow(dead_code))]

use sha2::{Digest, Sha256};
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

/// UTF-16 units in one stored value, under the 1,280 Windows accepts.
pub(crate) const LIMIT: usize = 1200;
/// More parts than this is not a record this app writes.
const MAX_PARTS: usize = 64;
const SLOTS: [char; 2] = ['a', 'b'];
/// No record is JSON that starts like this, so a pointer is never mistaken for one.
const POINTER: &str = "frameleaf-parts:1:";
const INVALID: &str = "credential_record_invalid";
const UNAVAILABLE: &str = "credential_store_locked_or_unavailable";

/// Named values in the operating system's credential store.
pub(crate) trait Slots {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<String>>, String>;
    fn set(&self, name: &str, value: &str) -> Result<(), String>;
    fn delete(&self, name: &str) -> Result<(), String>;
}

static LOCK: Mutex<()> = Mutex::new(());
fn lock() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn part(account: &str, slot: char, index: usize) -> String {
    format!("{account}#part-{slot}-{index}")
}

struct Pointer {
    slot: char,
    count: usize,
    digest: String,
}

fn pointer(value: &str) -> Option<Result<Pointer, String>> {
    let fields = value.strip_prefix(POINTER)?;
    let mut fields = fields.split(':');
    let parsed = (|| {
        let slot = fields.next()?.parse::<char>().ok()?;
        let count = fields.next()?.parse::<usize>().ok()?;
        let digest = fields.next()?;
        (SLOTS.contains(&slot)
            && (1..=MAX_PARTS).contains(&count)
            && digest.len() == 64
            && fields.next().is_none())
        .then(|| Pointer {
            slot,
            count,
            digest: digest.into(),
        })
    })();
    Some(parsed.ok_or_else(|| INVALID.into()))
}

fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn split(value: &str, limit: usize) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut units) = (0, 0);
    for (at, character) in value.char_indices() {
        if units + character.len_utf16() > limit {
            parts.push(&value[start..at]);
            (start, units) = (at, 0);
        }
        units += character.len_utf16();
    }
    parts.push(&value[start..]);
    parts
}

/// Removes what is left of a slot, last part first.
fn empty(store: &impl Slots, account: &str, slot: char) -> Result<(), String> {
    let mut count = 0;
    while count < MAX_PARTS && store.get(&part(account, slot, count))?.is_some() {
        count += 1;
    }
    for index in (0..count).rev() {
        store.delete(&part(account, slot, index))?;
    }
    Ok(())
}

pub(crate) fn read(store: &impl Slots, account: &str) -> Result<Option<Zeroizing<String>>, String> {
    let _lock = lock();
    let Some(head) = store.get(account)? else {
        return Ok(None);
    };
    let Some(pointer) = pointer(&head) else {
        return Ok(Some(head));
    };
    let pointer = pointer?;
    let mut value = Zeroizing::new(String::new());
    for index in 0..pointer.count {
        value.push_str(
            &store
                .get(&part(account, pointer.slot, index))?
                .ok_or(INVALID)?,
        );
    }
    if digest(&value) != pointer.digest {
        return Err(INVALID.into());
    }
    Ok(Some(value))
}

pub(crate) fn write(
    store: &impl Slots,
    account: &str,
    value: &str,
    limit: usize,
) -> Result<(), String> {
    let _lock = lock();
    if value.encode_utf16().count() <= limit && !value.starts_with(POINTER) {
        store.set(account, value)?;
        // The record no longer needs its parts. One that cannot be removed now is removed by the
        // next write or delete.
        for slot in SLOTS {
            let _ = empty(store, account, slot);
        }
        return Ok(());
    }
    let parts = split(value, limit);
    if parts.len() > MAX_PARTS {
        return Err(UNAVAILABLE.into());
    }
    let head = store.get(account)?;
    let used = match head.as_ref().and_then(|head| pointer(head)) {
        Some(Ok(pointer)) => Some(pointer.slot),
        _ => None,
    };
    let slot = if used == Some(SLOTS[0]) {
        SLOTS[1]
    } else {
        SLOTS[0]
    };
    empty(store, account, slot)?;
    for (index, part_value) in parts.iter().enumerate() {
        store.set(&part(account, slot, index), part_value)?;
    }
    store.set(
        account,
        &format!("{POINTER}{slot}:{}:{}", parts.len(), digest(value)),
    )?;
    if let Some(used) = used {
        let _ = empty(store, account, used);
    }
    Ok(())
}

/// Removes the record and every part of it. The parts go first: a removal cut short leaves a
/// record that reads as invalid and can be removed again, never parts that nothing names.
pub(crate) fn delete(store: &impl Slots, account: &str) -> Result<(), String> {
    let _lock = lock();
    for slot in SLOTS {
        empty(store, account, slot)?;
    }
    store.delete(account)
}

/// A store with the Windows size limit, for tests on every system.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct Memory {
    pub values: std::rc::Rc<std::cell::RefCell<std::collections::BTreeMap<String, String>>>,
    /// Refuses every write and removal after this many more, as a store that locks would.
    pub writes_left: std::rc::Rc<std::cell::Cell<Option<usize>>>,
}

#[cfg(test)]
impl Memory {
    /// What Windows accepts in one credential, in UTF-16 units.
    pub const WINDOWS: usize = 1280;
    fn spend(&self) -> Result<(), String> {
        match self.writes_left.get() {
            Some(0) => Err(UNAVAILABLE.into()),
            Some(left) => {
                self.writes_left.set(Some(left - 1));
                Ok(())
            }
            None => Ok(()),
        }
    }
}

#[cfg(test)]
impl Slots for Memory {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<String>>, String> {
        Ok(self.values.borrow().get(name).cloned().map(Zeroizing::new))
    }
    fn set(&self, name: &str, value: &str) -> Result<(), String> {
        if value.encode_utf16().count() > Self::WINDOWS {
            return Err(UNAVAILABLE.into());
        }
        self.spend()?;
        self.values.borrow_mut().insert(name.into(), value.into());
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<(), String> {
        self.spend()?;
        self.values.borrow_mut().remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(units: usize) -> String {
        // Two-unit characters at the front put a surrogate pair on a part boundary.
        format!(
            "{{\"name\":\"{}\",\"token\":\"{}\"}}",
            "𝒜".repeat(40),
            "t".repeat(units)
        )
    }

    fn names(store: &Memory) -> Vec<String> {
        store.values.borrow().keys().cloned().collect()
    }

    #[test]
    fn windows_refuses_a_long_record_in_one_credential_and_parts_carry_it() {
        let store = Memory::default();
        let long = record(6000);
        assert!(long.encode_utf16().count() > Memory::WINDOWS);
        assert!(
            store.set("connection", &long).is_err(),
            "the limit this guards"
        );

        write(&store, "connection", &long, LIMIT).unwrap();
        assert_eq!(
            read(&store, "connection").unwrap().unwrap().as_str(),
            long.as_str()
        );
        for value in store.values.borrow().values() {
            assert!(value.encode_utf16().count() <= LIMIT);
        }
        assert!(names(&store).len() > 5);

        delete(&store, "connection").unwrap();
        assert!(names(&store).is_empty(), "no part of a secret is left");
        assert!(read(&store, "connection").unwrap().is_none());
    }

    #[test]
    fn a_short_record_stays_one_credential_as_before() {
        let store = Memory::default();
        let short = record(100);
        write(&store, "connection", &short, LIMIT).unwrap();
        assert_eq!(names(&store), ["connection"]);
        assert_eq!(store.values.borrow()["connection"], short);
        // A record written by an earlier version reads unchanged.
        assert_eq!(*read(&store, "connection").unwrap().unwrap(), short);
    }

    #[test]
    fn rewriting_alternates_slots_and_leaves_no_old_parts() {
        let store = Memory::default();
        write(&store, "c", &record(6000), LIMIT).unwrap();
        let first = names(&store);
        assert!(first.iter().any(|name| name.starts_with("c#part-a-")));
        write(&store, "c", &record(3000), LIMIT).unwrap();
        assert!(names(&store)
            .iter()
            .all(|name| name == "c" || name.starts_with("c#part-b-")));
        assert_eq!(*read(&store, "c").unwrap().unwrap(), record(3000));
        // Growing shorter than the limit drops the parts altogether.
        write(&store, "c", &record(10), LIMIT).unwrap();
        assert_eq!(names(&store), ["c"]);
    }

    #[test]
    fn a_write_cut_short_at_any_point_keeps_the_earlier_record() {
        let earlier = record(4000);
        let later = record(5000);
        let mut interrupted = 0;
        for allowed in 0..40 {
            let store = Memory::default();
            write(&store, "c", &earlier, LIMIT).unwrap();
            store.writes_left.set(Some(allowed));
            let result = write(&store, "c", &later, LIMIT);
            store.writes_left.set(None);
            let stored = read(&store, "c").unwrap().unwrap();
            if result.is_err() {
                interrupted += 1;
                assert_eq!(*stored, earlier, "after {allowed} writes");
            } else {
                assert_eq!(*stored, later);
            }
            // Whatever was left behind, the next write and a delete clear all of it.
            write(&store, "c", &later, LIMIT).unwrap();
            assert_eq!(*read(&store, "c").unwrap().unwrap(), later);
            delete(&store, "c").unwrap();
            assert!(names(&store).is_empty(), "after {allowed} writes");
        }
        assert!(interrupted > 3);
    }

    #[test]
    fn a_delete_cut_short_is_reported_and_can_be_finished() {
        for allowed in 0..8 {
            let store = Memory::default();
            write(&store, "c", &record(4000), LIMIT).unwrap();
            store.writes_left.set(Some(allowed));
            let result = delete(&store, "c");
            store.writes_left.set(None);
            if result.is_err() {
                // Never the whole secret under a name nothing points at.
                assert!(names(&store).contains(&"c".to_string()));
                assert!(read(&store, "c").is_err() || allowed == 0);
            }
            delete(&store, "c").unwrap();
            assert!(names(&store).is_empty());
        }
    }

    #[test]
    fn missing_or_altered_parts_are_an_invalid_record_not_a_shorter_one() {
        let store = Memory::default();
        write(&store, "c", &record(4000), LIMIT).unwrap();
        store
            .values
            .borrow_mut()
            .insert("c#part-a-1".into(), "x".into());
        assert_eq!(read(&store, "c").unwrap_err(), INVALID);
        store.values.borrow_mut().remove("c#part-a-1");
        assert_eq!(read(&store, "c").unwrap_err(), INVALID);
        for pointer in [
            "frameleaf-parts:1:c:2:00",
            "frameleaf-parts:1:a:0:",
            "frameleaf-parts:1:a:999:x",
        ] {
            store.values.borrow_mut().insert("c".into(), pointer.into());
            assert_eq!(read(&store, "c").unwrap_err(), INVALID, "{pointer}");
        }
    }

    #[test]
    fn a_record_past_every_part_is_refused_before_anything_is_written() {
        let store = Memory::default();
        assert!(write(&store, "c", &"x".repeat(LIMIT * MAX_PARTS + 1), LIMIT).is_err());
        assert!(names(&store).is_empty());
    }
}
