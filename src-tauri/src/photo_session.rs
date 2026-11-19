//! The web data the Photos window leaves behind: the session cookie and the photo site's own
//! storage. Sign-out owes it a wipe whether or not the Photos window is open, and the debt is
//! written down first so a crash or a failed wipe is made good the next time the app can.

use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager, WebviewWindow};

const MARKER: &str = "photos-clear-pending";

/// Records that the web data must be wiped. Best effort: the wipe is attempted either way.
fn owe(directory: &Path) {
    let _ = std::fs::create_dir_all(directory);
    let _ = std::fs::write(directory.join(MARKER), b"");
}

/// A marker that cannot be read is not known to be absent, so the wipe is still owed.
fn owed(directory: &Path) -> bool {
    !matches!(directory.join(MARKER).try_exists(), Ok(false))
}

/// Wipes, and only then forgets the debt. True only when the data was wiped.
fn settle(directory: Option<&Path>, wipe: impl FnOnce() -> bool) -> bool {
    if !wipe() {
        return false;
    }
    if let Some(directory) = directory {
        match std::fs::remove_file(directory.join(MARKER)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                eprintln!("photo data marker not removed: {error}");
            }
            _ => {}
        }
    }
    true
}

fn directory(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_local_data_dir().ok()
}

/// Sign-out is about to remove the saved sign-in: the Photos web data must go with it.
pub(crate) fn mark(app: &AppHandle) {
    if let Some(directory) = directory(app) {
        owe(&directory);
    }
}

/// Wipes the Photos web data through `window`. The main, Photos and local Photos windows share
/// one web data store, so any of them wipes it, with the Photos window open or closed.
pub(crate) fn clear(app: &AppHandle, window: &WebviewWindow) -> bool {
    settle(directory(app).as_deref(), || {
        window.clear_all_browsing_data().is_ok()
    })
}

/// Makes good a wipe that an earlier sign-out still owes, before the Photos window is used again.
pub(crate) fn clear_if_owed(app: &AppHandle) {
    if directory(app).is_some_and(|directory| owed(&directory)) {
        if let Some(main) = app.get_webview_window("main") {
            clear(app, &main);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("frameleaf-photo-session-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn a_failed_wipe_is_not_reported_and_stays_owed_until_one_succeeds() {
        let directory = scratch();
        assert!(!owed(&directory));
        owe(&directory);
        assert!(owed(&directory));

        assert!(!settle(Some(&directory), || false));
        assert!(owed(&directory), "a failed wipe is tried again");

        assert!(settle(Some(&directory), || true));
        assert!(!owed(&directory));
        // Nothing owed and nowhere to write it down: the answer is still the wipe's own.
        assert!(settle(Some(&directory), || true));
        assert!(settle(None, || true));
        assert!(!settle(None, || false));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_debt_survives_a_restart_and_an_unreadable_marker_counts_as_owed() {
        let directory = scratch();
        owe(&directory);
        // A new process sees only the file.
        assert!(directory.join(MARKER).is_file());
        assert!(owed(&directory));
        std::fs::remove_dir_all(&directory).unwrap();
        assert!(!owed(&directory));
        // A path that cannot be examined at all is not proof that nothing is owed.
        let unreadable = directory.join("a\0b");
        assert!(owed(&unreadable));
    }
}
