//! The menu bar / system tray entry: where the app is connected, what AI processing is doing, and
//! the few actions that make sense without opening the window.

use crate::connection::{normalize_server, SavedConnection};
use crate::worker_control::WorkerControl;
use crate::worker_setup::SetupStatus;
use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager, WebviewWindow, Wry,
};

const NOT_CONNECTED: &str = "Not connected";

struct Items {
    server: MenuItem<Wry>,
    worker: MenuItem<Wry>,
    photos: MenuItem<Wry>,
    toggle: MenuItem<Wry>,
    stop: MenuItem<Wry>,
}

#[derive(Default)]
pub(crate) struct TrayState(Mutex<Option<Items>>);

/// What the tray shows for one setup status.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Labels {
    pub worker: String,
    pub toggle: String,
    pub can_toggle: bool,
    pub can_stop: bool,
}

pub(crate) fn server_label(saved: Option<&SavedConnection>) -> String {
    saved
        .and_then(|saved| normalize_server(&saved.server).ok())
        .and_then(|base| base.host_str().map(str::to_owned))
        .unwrap_or_else(|| NOT_CONNECTED.into())
}

pub(crate) fn labels(status: &SetupStatus, connected: bool) -> Labels {
    let state = if !connected {
        "AI processing: not connected".to_string()
    } else {
        let word = match status.state.as_str() {
            "working" => "working",
            "waiting-for-work" | "reconnecting" => "running",
            "downloading-models" | "preparing-runtime" | "preparing-models" | "qualifying"
            | "qualified" | "starting-worker" => "getting ready",
            "pausing" => "pausing",
            "paused" => "paused",
            "stopped" => "stopped",
            "no-eligible-work" => "no work assigned",
            "" => "not set up",
            _ if status.code.is_some() => "needs attention",
            other => other,
        };
        format!("AI processing: {word}")
    };
    let paused = status.control != WorkerControl::Running;
    Labels {
        worker: state,
        toggle: if paused {
            "Resume AI processing".into()
        } else {
            "Pause AI processing".into()
        },
        can_toggle: connected,
        can_stop: connected && status.control != WorkerControl::Stopped,
    }
}

pub(crate) fn build(app: &AppHandle) -> tauri::Result<()> {
    let server = MenuItem::with_id(app, "server", NOT_CONNECTED, false, None::<&str>)?;
    let worker = MenuItem::with_id(
        app,
        "worker",
        "AI processing: not connected",
        false,
        None::<&str>,
    )?;
    let photos = MenuItem::with_id(app, "open-photos", "Open Photos", false, None::<&str>)?;
    let open = MenuItem::with_id(
        app,
        "open-desktop",
        "Open Frameleaf Desktop",
        true,
        None::<&str>,
    )?;
    let toggle = MenuItem::with_id(
        app,
        "toggle-worker",
        "Pause AI processing",
        false,
        None::<&str>,
    )?;
    let stop = MenuItem::with_id(
        app,
        "stop-worker",
        "Stop AI processing now",
        false,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quit", "Quit Frameleaf", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &server,
            &worker,
            &PredefinedMenuItem::separator(app)?,
            &photos,
            &open,
            &PredefinedMenuItem::separator(app)?,
            &toggle,
            &stop,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;
    let mut builder = TrayIconBuilder::with_id("frameleaf")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .tooltip("Frameleaf")
        .on_menu_event(|app, event| on_menu(app, event.id().as_ref()));
    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }
    builder.build(app)?;
    if let Ok(mut slot) = app.state::<TrayState>().0.lock() {
        *slot = Some(Items {
            server,
            worker,
            photos,
            toggle,
            stop,
        });
    }
    Ok(())
}

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn on_menu(app: &AppHandle, id: &str) {
    match id {
        "open-desktop" => show_main(app),
        "quit" => app.exit(0),
        "open-photos" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let state = app.state::<crate::DesktopState>();
                let current = state.0.lock().await;
                if let Some(Err(code)) = current
                    .as_ref()
                    .map(|saved| crate::open_photos_window(&app, saved))
                {
                    let _ = app.emit_to("main", "tray-action-failed", code);
                    show_main(&app);
                }
            });
        }
        "toggle-worker" | "stop-worker" => {
            let app = app.clone();
            let control = if id == "stop-worker" {
                WorkerControl::Stopped
            } else if app
                .state::<crate::worker_setup::WorkerSetup>()
                .status()
                .control
                != WorkerControl::Running
            {
                WorkerControl::Running
            } else {
                WorkerControl::Paused
            };
            tauri::async_runtime::spawn(async move {
                match crate::apply_worker_control(&app, control).await {
                    Ok(status) => {
                        let _ = app.emit_to("main", "worker-setup", status);
                    }
                    Err(code) => {
                        let _ = app.emit_to("main", "tray-action-failed", code);
                        show_main(&app);
                    }
                }
                refresh(&app).await;
            });
        }
        _ => {}
    }
}

fn apply(items: &Items, server: &str, labels: &Labels, connected: bool) {
    let _ = items.server.set_text(server);
    let _ = items.worker.set_text(&labels.worker);
    let _ = items.toggle.set_text(&labels.toggle);
    let _ = items.toggle.set_enabled(labels.can_toggle);
    let _ = items.stop.set_enabled(labels.can_stop);
    let _ = items.photos.set_enabled(connected);
}

/// The worker line only: called wherever a `worker-setup` status leaves for the window, so the
/// tray never lags behind it.
pub(crate) fn set_worker_status(app: &AppHandle, status: &SetupStatus) {
    let Some(state) = app.try_state::<TrayState>() else {
        return;
    };
    let Ok(slot) = state.0.lock() else {
        return;
    };
    if let Some(items) = slot.as_ref() {
        let labels = labels(status, true);
        let _ = items.worker.set_text(&labels.worker);
        let _ = items.toggle.set_text(&labels.toggle);
        let _ = items.toggle.set_enabled(labels.can_toggle);
        let _ = items.stop.set_enabled(labels.can_stop);
    }
}

/// Every line, from the signed-in connection and the worker status.
pub(crate) async fn refresh(app: &AppHandle) {
    let Some(state) = app.try_state::<TrayState>() else {
        return;
    };
    let (server, connected) = {
        let desktop = app.state::<crate::DesktopState>();
        let current = desktop.0.lock().await;
        (server_label(current.as_ref()), current.is_some())
    };
    let status = app.state::<crate::worker_setup::WorkerSetup>().status();
    let labels = labels(&status, connected);
    let slot = state.0.lock();
    if let Ok(slot) = slot {
        if let Some(items) = slot.as_ref() {
            apply(items, &server, &labels, connected);
        }
    }
}

#[tauri::command]
pub(crate) async fn tray_refresh(window: WebviewWindow, app: AppHandle) -> Result<(), String> {
    crate::require_local(&window)?;
    refresh(&app).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(state: &str, control: WorkerControl, code: Option<&str>) -> SetupStatus {
        SetupStatus {
            state: state.into(),
            code: code.map(Into::into),
            control,
            workloads: Vec::new(),
        }
    }

    #[test]
    fn server_line_is_the_host_of_the_signed_in_server_or_not_connected() {
        assert_eq!(server_label(None), "Not connected");
        let saved = SavedConnection {
            server: "https://nas.home.arpa:2283/".into(),
            server_id: "s".into(),
            account_id: "a".into(),
            name: "Ada".into(),
            token: "t".into(),
            device_name: "Laptop".into(),
            mode: "client-worker".into(),
            device_id: None,
        };
        assert_eq!(server_label(Some(&saved)), "nas.home.arpa");
    }

    #[test]
    fn worker_line_and_toggle_follow_the_setup_status() {
        let running = labels(&status("working", WorkerControl::Running, None), true);
        assert_eq!(running.worker, "AI processing: working");
        assert_eq!(running.toggle, "Pause AI processing");
        assert!(running.can_toggle && running.can_stop);

        let paused = labels(
            &status("paused", WorkerControl::Paused, Some("user_paused")),
            true,
        );
        assert_eq!(paused.worker, "AI processing: paused");
        assert_eq!(paused.toggle, "Resume AI processing");
        assert!(paused.can_stop);

        let stopped = labels(&status("stopped", WorkerControl::Stopped, None), true);
        assert_eq!(stopped.worker, "AI processing: stopped");
        assert_eq!(stopped.toggle, "Resume AI processing");
        assert!(stopped.can_toggle && !stopped.can_stop);

        let failed = labels(
            &status(
                "failed",
                WorkerControl::Running,
                Some("worker_runtime_unavailable"),
            ),
            true,
        );
        assert_eq!(failed.worker, "AI processing: needs attention");
        assert_eq!(
            labels(&status("qualifying", WorkerControl::Running, None), true).worker,
            "AI processing: getting ready"
        );
        assert_eq!(
            labels(&SetupStatus::default(), true).worker,
            "AI processing: not set up"
        );

        let offline = labels(&status("working", WorkerControl::Running, None), false);
        assert_eq!(offline.worker, "AI processing: not connected");
        assert!(!offline.can_toggle && !offline.can_stop);
    }
}
