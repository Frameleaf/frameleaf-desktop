//! What closing the main window does while background work is running.

use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{AppHandle, Manager, Window};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_notification::NotificationExt;

/// The id of the macOS app-menu Quit item that goes through the exit guard.
#[cfg(target_os = "macos")]
const APP_QUIT: &str = "app-quit";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Activity {
    pub worker: bool,
    pub import: bool,
    pub watch: bool,
    pub local_host: bool,
    pub media_copy: bool,
}

impl Activity {
    fn any(self) -> bool {
        self.worker || self.import || self.watch || self.local_host || self.media_copy
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CloseAction {
    /// Let the window close; with no other window open the app exits.
    Close,
    /// Keep running: hide the window, reachable again from the tray (or the Dock on macOS).
    Hide,
    /// Nothing would bring a hidden window back: keep it open and ask before quitting.
    ConfirmQuit,
}

pub(crate) fn close_action(macos: bool, tray: bool, activity: Activity) -> CloseAction {
    if macos {
        // The Dock reopens the window, so closing never quits on macOS.
        CloseAction::Hide
    } else if !activity.any() {
        CloseAction::Close
    } else if tray {
        CloseAction::Hide
    } else {
        CloseAction::ConfirmQuit
    }
}

/// The worker holds or does work that ends if the app quits. A person's own Pause or Stop,
/// and a setup that gave up, leave nothing running.
pub(crate) fn worker_active(status: &crate::worker_setup::SetupStatus) -> bool {
    status.control == crate::worker_control::WorkerControl::Running
        && !matches!(
            status.state.as_str(),
            "" | "stopped" | "setup-needs-attention" | "model-download-required"
        )
}

fn activity(app: &AppHandle) -> Activity {
    let imports = app.state::<crate::source_import::SourceJobs>();
    let drops = app.state::<crate::drop_import::DropImport>();
    Activity {
        worker: worker_active(&app.state::<crate::worker_setup::WorkerSetup>().status()),
        import: imports.copying() || drops.jobs.copying(),
        watch: imports.watching(),
        local_host: app
            .state::<crate::host_setup::HostSetup>()
            .background_active(),
        media_copy: app.state::<crate::media_copy::MediaCopy>().is_active(),
    }
}

/// A tray icon was built and something on this desktop shows it.
fn tray_available(app: &AppHandle) -> bool {
    app.tray_by_id("frameleaf").is_some() && tray_host_present()
}

/// A Linux session without a status-notifier host (stock GNOME) accepts the icon but never shows it.
#[cfg(target_os = "linux")]
fn tray_host_present() -> bool {
    use dbus::blocking::Connection;
    use std::time::Duration;
    let Ok(bus) = Connection::new_session() else {
        return false;
    };
    let owned: Result<(bool,), dbus::Error> = bus
        .with_proxy(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            Duration::from_millis(500),
        )
        .method_call(
            "org.freedesktop.DBus",
            "NameHasOwner",
            ("org.kde.StatusNotifierWatcher",),
        );
    owned.is_ok_and(|(present,)| present)
}

#[cfg(not(target_os = "linux"))]
fn tray_host_present() -> bool {
    true
}

/// Handles a close request for the main window. Returns whether the close was prevented.
pub(crate) fn on_close_requested(window: &Window) -> bool {
    let app = window.app_handle();
    let tray = tray_available(app);
    match close_action(cfg!(target_os = "macos"), tray, activity(app)) {
        CloseAction::Close => false,
        CloseAction::Hide => {
            let _ = window.hide();
            if tray {
                tell_once(app);
            }
            true
        }
        CloseAction::ConfirmQuit => {
            confirm_quit(app);
            true
        }
    }
}

/// The first time the window hides, say where Frameleaf went. The marker survives restarts.
fn tell_once(app: &AppHandle) {
    let Ok(marker) = app
        .path()
        .app_local_data_dir()
        .map(|base| base.join("tray-notice-v1"))
    else {
        return;
    };
    if marker.exists() {
        return;
    }
    let place = if cfg!(target_os = "macos") {
        "menu bar"
    } else {
        "system tray"
    };
    let told = app
        .notification()
        .builder()
        .title("Frameleaf is still running")
        .body(format!(
            "AI processing and photo imports continue in the background. Open or quit Frameleaf from its icon in the {place}."
        ))
        .show();
    if told.is_ok() {
        if let Some(parent) = marker.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(marker, b"");
    }
}

fn confirm_quit(app: &AppHandle) {
    static ASKING: AtomicBool = AtomicBool::new(false);
    if ASKING.swap(true, Ordering::AcqRel) {
        return;
    }
    let handle = app.clone();
    app.dialog()
        .message("AI processing, photo imports or folder watching are still running, and this desktop has no system tray to keep Frameleaf in. Quitting stops them until you open Frameleaf again.")
        .title("Quit Frameleaf?")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Quit".into(),
            "Keep Running".into(),
        ))
        .show(move |quit| {
            ASKING.store(false, Ordering::Release);
            if quit {
                // Through the exit guard: a media copy or the local server still blocks it.
                handle.exit(0);
            }
        });
}

/// Cmd+Q in the default macOS menu terminates the process without asking the exit guard.
/// Replace it with an item that requests an ordinary, preventable exit.
#[cfg(target_os = "macos")]
pub(crate) fn guard_app_quit(app: &AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, MenuItemKind};
    let menu = Menu::default(app)?;
    let Some(MenuItemKind::Submenu(app_menu)) = menu.items()?.into_iter().next() else {
        return Ok(());
    };
    // The predefined Quit is the last item of the app menu.
    let last = app_menu.items()?.len().saturating_sub(1);
    app_menu.remove_at(last)?;
    app_menu.append(&MenuItem::with_id(
        app,
        APP_QUIT,
        format!("Quit {}", app.package_info().name),
        true,
        Some("Cmd+Q"),
    )?)?;
    app.on_menu_event(|app, event| {
        if event.id().as_ref() == APP_QUIT {
            app.exit(0);
        }
    });
    app.set_menu(menu)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker_control::WorkerControl;
    use crate::worker_setup::SetupStatus;

    const IDLE: Activity = Activity {
        worker: false,
        import: false,
        watch: false,
        local_host: false,
        media_copy: false,
    };

    fn each_activity() -> [Activity; 5] {
        [
            Activity {
                worker: true,
                ..IDLE
            },
            Activity {
                import: true,
                ..IDLE
            },
            Activity {
                watch: true,
                ..IDLE
            },
            Activity {
                local_host: true,
                ..IDLE
            },
            Activity {
                media_copy: true,
                ..IDLE
            },
        ]
    }

    #[test]
    fn windows_and_linux_hide_to_the_tray_while_work_is_running() {
        for activity in each_activity() {
            assert_eq!(
                close_action(false, true, activity),
                CloseAction::Hide,
                "{activity:?}"
            );
        }
    }

    #[test]
    fn windows_and_linux_close_when_idle() {
        assert_eq!(close_action(false, true, IDLE), CloseAction::Close);
        assert_eq!(close_action(false, false, IDLE), CloseAction::Close);
    }

    #[test]
    fn without_a_tray_running_work_asks_before_quitting_and_never_hides() {
        for activity in each_activity() {
            assert_eq!(
                close_action(false, false, activity),
                CloseAction::ConfirmQuit,
                "{activity:?}"
            );
        }
    }

    #[test]
    fn macos_always_hides_because_the_dock_reopens_the_window() {
        for tray in [true, false] {
            assert_eq!(close_action(true, tray, IDLE), CloseAction::Hide);
            for activity in each_activity() {
                assert_eq!(close_action(true, tray, activity), CloseAction::Hide);
            }
        }
    }

    #[test]
    fn worker_counts_as_running_until_the_person_or_setup_ends_it() {
        let status = |state: &str, control| SetupStatus {
            state: state.into(),
            control,
            ..SetupStatus::default()
        };
        for state in [
            "working",
            "waiting-for-work",
            "reconnecting",
            "downloading-models",
            "starting-worker",
            "no-eligible-work",
            // Waiting for power or an unmetered network resumes by itself.
            "paused",
        ] {
            assert!(
                worker_active(&status(state, WorkerControl::Running)),
                "{state}"
            );
        }
        for state in [
            "",
            "stopped",
            "setup-needs-attention",
            "model-download-required",
        ] {
            assert!(
                !worker_active(&status(state, WorkerControl::Running)),
                "{state}"
            );
        }
        assert!(!worker_active(&status("paused", WorkerControl::Paused)));
        assert!(!worker_active(&status("stopped", WorkerControl::Stopped)));
    }
}
