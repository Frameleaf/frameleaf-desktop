//! A library's move to another companion package, until Manager has run with either side of it.
//!
//! The move is committed on disk before Manager is started with the new package, and Manager
//! may still refuse it. This record says which move is unconfirmed, so that the package the
//! library last ran with can be chosen again and the same move can be tried again. Manager
//! becoming ready, with either package, is the only thing that settles it.
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::Path,
};

const RECORD: &str = "desktop-package-move.json";
const UNAVAILABLE: &str = "host_upgrade_move_unavailable";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Move {
    schema_version: u32,
    /// The package Manager last ran this library with.
    pub from: String,
    /// The package the library was moved to.
    pub to: String,
}
impl Move {
    pub(crate) fn new(from: &str, to: &str) -> Self {
        Self {
            schema_version: 1,
            from: from.into(),
            to: to.into(),
        }
    }
    fn valid(&self) -> bool {
        self.schema_version == 1
            && self.from != self.to
            && [&self.from, &self.to]
                .into_iter()
                .all(|manifest| crate::native_runtime::digest_valid(manifest, 64))
    }
}
/// What the record says. `Unreadable` is its own answer and is never read as `Absent`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Stored {
    Absent,
    Present(Move),
    Unreadable,
}
/// What starting a library with `selected` does when its journal names `journal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// The library last ran with this package: nothing moves.
    Start,
    /// Move to the selected package. `resume` says this same move was made before and Manager
    /// has not been seen ready since, so the transition it may already have accepted is sent
    /// again rather than a new one.
    Forward {
        resume: bool,
    },
    /// The selected package is the one an unconfirmed move left: go back to it.
    Return,
    Refuse(&'static str),
}
pub(crate) fn plan(journal: &str, selected: &str, record: &Stored) -> Plan {
    if journal == selected {
        return Plan::Start;
    }
    match record {
        Stored::Absent => Plan::Forward { resume: false },
        // Whether a move is unconfirmed is not known: nothing is moved in either direction.
        Stored::Unreadable => Plan::Refuse(UNAVAILABLE),
        Stored::Present(pending) if pending.from == journal && pending.to == selected => {
            Plan::Forward { resume: true }
        }
        Stored::Present(pending) if pending.to == journal && pending.from == selected => {
            Plan::Return
        }
        // A third package: Manager's own record is of one of the two sides of the
        // unconfirmed move, and only starting with one of them settles which.
        Stored::Present(_) => Plan::Refuse("host_upgrade_move_unconfirmed"),
    }
}

pub(crate) fn stored(data: &Path) -> Stored {
    let Ok(directory) = crate::host_storage::directory(data) else {
        return Stored::Unreadable;
    };
    let directory = cap_std::fs::Dir::from_std_file(directory);
    let file = match directory.open_with(RECORD, &crate::host_state::options(false)) {
        Ok(file) => file.into_std(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Stored::Absent,
        Err(_) => return Stored::Unreadable,
    };
    let mut bytes = Vec::new();
    if crate::host_state::valid_file(&file).is_err()
        || file.take(1025).read_to_end(&mut bytes).is_err()
        || bytes.len() > 1024
    {
        return Stored::Unreadable;
    }
    match serde_json::from_slice::<Move>(&bytes) {
        Ok(pending) if pending.valid() => Stored::Present(pending),
        _ => Stored::Unreadable,
    }
}
/// Record the move before its first change. Recording the same move again changes nothing.
pub(crate) fn save(data: &Path, pending: &Move) -> Result<(), String> {
    const TEMPORARY: &str = ".desktop-package-move.json.tmp";
    let failed = |_: std::io::Error| UNAVAILABLE.to_string();
    if !pending.valid() {
        return Err(UNAVAILABLE.into());
    }
    match stored(data) {
        Stored::Present(saved) if &saved == pending => return Ok(()),
        Stored::Absent => {}
        _ => return Err(UNAVAILABLE.into()),
    }
    let bytes = serde_json::to_vec(pending).map_err(|_| UNAVAILABLE)?;
    let directory = cap_std::fs::Dir::from_std_file(
        crate::host_storage::directory(data).map_err(|_| UNAVAILABLE)?,
    );
    match directory.remove_file(TEMPORARY) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(failed(error)),
        _ => {}
    }
    let mut options = crate::host_state::options(true);
    options.create_new(true);
    let mut file = directory
        .open_with(TEMPORARY, &options)
        .map_err(failed)?
        .into_std();
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(failed)?;
    drop(file);
    directory
        .rename(TEMPORARY, &directory, RECORD)
        .map_err(failed)?;
    // A directory handle cannot be flushed on Windows; the profile's own marker does the same.
    #[cfg(unix)]
    crate::host_storage::directory(data)
        .map_err(|_| UNAVAILABLE.to_string())?
        .sync_all()
        .map_err(failed)?;
    if stored(data) != Stored::Present(pending.clone()) {
        return Err(UNAVAILABLE.into());
    }
    Ok(())
}
/// Manager is ready with the package the journal names, so its own record agrees with it and
/// no move is unconfirmed. A record that cannot be removed stays, and keeps saying so.
pub(crate) fn settled(data: &Path) {
    if let Ok(directory) = crate::host_storage::directory(data) {
        let _ = cap_std::fs::Dir::from_std_file(directory).remove_file(RECORD);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-package-move-{}", uuid::Uuid::new_v4()));
            crate::runtime_store::private_directory(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn packages() -> (String, String, String) {
        ("a".repeat(64), "b".repeat(64), "c".repeat(64))
    }
    #[test]
    fn an_unconfirmed_move_can_be_tried_again_or_taken_back_and_nothing_else() {
        let (a, b, c) = packages();
        for record in [
            Stored::Absent,
            Stored::Unreadable,
            Stored::Present(Move::new(&a, &b)),
        ] {
            assert_eq!(plan(&a, &a, &record), Plan::Start);
        }
        assert_eq!(
            plan(&a, &b, &Stored::Absent),
            Plan::Forward { resume: false }
        );
        let pending = Stored::Present(Move::new(&a, &b));
        // Interrupted, or taken back: the journal names the package moved from.
        assert_eq!(plan(&a, &b, &pending), Plan::Forward { resume: true });
        // Committed and Manager not seen ready: the package moved from may be chosen again.
        assert_eq!(plan(&b, &a, &pending), Plan::Return);
        for (journal, selected) in [(&a, &c), (&b, &c), (&c, &a), (&c, &b)] {
            assert_eq!(
                plan(journal, selected, &pending),
                Plan::Refuse("host_upgrade_move_unconfirmed")
            );
        }
        // Unknown never moves anything, in either direction.
        for (journal, selected) in [(&a, &b), (&b, &a)] {
            assert_eq!(
                plan(journal, selected, &Stored::Unreadable),
                Plan::Refuse("host_upgrade_move_unavailable")
            );
        }
    }
    #[test]
    fn the_record_is_kept_until_settled_and_never_replaced_by_another_move() {
        let fixture = Fixture::new();
        let (a, b, c) = packages();
        assert_eq!(stored(&fixture.0), Stored::Absent);
        assert!(save(&fixture.0, &Move::new(&a, &a)).is_err());
        assert!(save(&fixture.0, &Move::new(&a, "short")).is_err());
        assert_eq!(stored(&fixture.0), Stored::Absent);
        let pending = Move::new(&a, &b);
        save(&fixture.0, &pending).unwrap();
        save(&fixture.0, &pending).unwrap();
        assert_eq!(stored(&fixture.0), Stored::Present(pending.clone()));
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
        assert_eq!(
            save(&fixture.0, &Move::new(&b, &c)).unwrap_err(),
            "host_upgrade_move_unavailable"
        );
        assert_eq!(stored(&fixture.0), Stored::Present(pending.clone()));
        // Anything but a whole record of one move is unknown, not absent.
        let path = fixture.0.join(RECORD);
        for bytes in [
            &b""[..],
            b"{}",
            br#"{"schemaVersion":2,"from":"a","to":"b"}"#,
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert_eq!(stored(&fixture.0), Stored::Unreadable);
            assert!(save(&fixture.0, &pending).is_err());
        }
        settled(&fixture.0);
        assert_eq!(stored(&fixture.0), Stored::Absent);
        settled(&fixture.0);
        assert_eq!(
            stored(&fixture.0.join("missing")),
            Stored::Unreadable,
            "a Manager folder that cannot be opened is unknown"
        );
    }
}
