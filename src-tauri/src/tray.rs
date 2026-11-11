//! Background activity and controls in the menu bar or system tray.

use crate::connection::{normalize_server, SavedConnection};
use crate::source_import::ImportView;
use crate::worker_control::{self, Preference, WorkerControl};
use crate::worker_setup::SetupStatus;
use std::{sync::Mutex, time::Duration};
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager, WebviewWindow, Wry,
};
use tauri_plugin_notification::NotificationExt;

const NOT_CONNECTED: &str = "Not connected";

struct Items {
    server: MenuItem<Wry>,
    worker: MenuItem<Wry>,
    import: MenuItem<Wry>,
    last_import: Option<(String, String)>,
    photos: MenuItem<Wry>,
    toggle: MenuItem<Wry>,
    pause_hour: MenuItem<Wry>,
    stop: MenuItem<Wry>,
}

#[derive(Default)]
pub(crate) struct TrayState {
    items: Mutex<Option<Items>>,
    resume: Mutex<Option<(String, u64)>>,
}

/// What the tray shows for one setup status.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Labels {
    pub worker: String,
    pub toggle: String,
    pub can_toggle: bool,
    pub can_pause_hour: bool,
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
            "waiting-for-work" => "waiting for work",
            "reconnecting" => "reconnecting",
            "downloading-models" | "preparing-runtime" | "preparing-models" | "qualifying"
            | "qualified" | "starting-worker" => "getting ready",
            "pausing" => "pausing",
            "paused" if status.control == WorkerControl::Paused => "paused",
            "paused" => match status.code.as_deref() {
                Some("on_battery") => "waiting for power",
                Some("power_unknown") => "checking power",
                Some("metered_network") => "waiting for unmetered network",
                Some("network_unknown") => "checking network",
                Some("memory_low") => "waiting for memory",
                Some("memory_unknown") => "checking memory",
                _ => "paused",
            },
            "stopped" => "stopped",
            "no-eligible-work" => "no work assigned",
            "" => "not set up",
            _ => "needs attention",
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
        can_pause_hour: connected && !paused,
        can_stop: connected && status.control != WorkerControl::Stopped,
    }
}

fn import_label(status: Option<&ImportView>) -> String {
    let Some(status) = status else {
        return "Photo imports: no active copy".into();
    };
    let label = match (status.state.as_str(), status.code.as_deref()) {
        ("copying", _) => "copying",
        ("complete", _) => "finished",
        ("cancelled", _) => "cancelled",
        ("needs-attention" | "watching", Some("metered_network")) => {
            "waiting for unmetered network"
        }
        ("needs-attention" | "watching", Some("network_unknown")) => "checking network",
        ("needs-attention" | "watching", Some("source_server_processing")) => {
            "waiting for the server"
        }
        ("watching", _) => "watching for new photos",
        ("paused" | "watch-paused", _) => "paused",
        (
            "needs-attention",
            Some("source_upload_budget_exhausted" | "source_upload_budget_required"),
        ) => "needs upload approval",
        ("needs-attention", _) => "needs attention",
        _ => "ready",
    };
    if status.total == 0 {
        format!("Photo imports: {label}")
    } else {
        format!(
            "Photo imports: {label} · {} of {} verified",
            status.completed, status.total
        )
    }
}

fn import_notice(
    previous: Option<&(String, String)>,
    status: &ImportView,
) -> Option<(&'static str, String)> {
    let (source, state) = previous?;
    if source != &status.source_id {
        return None;
    }
    match status.state.as_str() {
        "complete" if state == "copying" && status.completed > 0 => Some((
            "Photo import finished",
            format!("{} files verified in your library.", status.completed),
        )),
        "needs-attention" if matches!(state.as_str(), "copying" | "watching") => Some((
            "Photo import needs attention",
            "Open Photo Sources in Frameleaf for details.".into(),
        )),
        _ => None,
    }
}

/// Reflect import progress even when the app window is hidden, and notify on terminal changes.
pub(crate) fn set_import_status(app: &AppHandle, status: Option<&ImportView>) {
    let Some(state) = app.try_state::<TrayState>() else {
        return;
    };
    let notice = {
        let Ok(mut slot) = state.items.lock() else {
            return;
        };
        let Some(items) = slot.as_mut() else {
            return;
        };
        let notice = status.and_then(|status| import_notice(items.last_import.as_ref(), status));
        items.last_import = status.map(|status| (status.source_id.clone(), status.state.clone()));
        let _ = items.import.set_text(import_label(status));
        notice
    };
    if let Some((title, body)) = notice {
        let _ = app.notification().builder().title(title).body(body).show();
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
    let import = MenuItem::with_id(
        app,
        "photo-imports",
        import_label(None),
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
    let pause_hour = MenuItem::with_id(
        app,
        "pause-worker-hour",
        "Pause AI processing for one hour",
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
            &import,
            &PredefinedMenuItem::separator(app)?,
            &photos,
            &open,
            &PredefinedMenuItem::separator(app)?,
            &toggle,
            &pause_hour,
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
    if let Ok(mut slot) = app.state::<TrayState>().items.lock() {
        *slot = Some(Items {
            server,
            worker,
            import,
            last_import: None,
            photos,
            toggle,
            pause_hour,
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
        "pause-worker-hour" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(code) = pause_worker_for_hour(&app).await {
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

async fn pause_worker_for_hour(app: &AppHandle) -> Result<(), String> {
    let desktop = app.state::<crate::DesktopState>();
    let current = desktop.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let now = worker_control::now();
    if worker_control::load(saved)?.effective(now) != WorkerControl::Running {
        return Ok(());
    }
    let scope = worker_control::key(saved)?;
    let until = now.saturating_add(3_600_000);
    worker_control::save_preference(saved, Preference::Timed { until })?;
    let status = app.state::<crate::worker_setup::WorkerSetup>().pause();
    crate::publish_worker_status(app, status);
    schedule_worker_resume(app, scope, until);
    Ok(())
}

/// Only the same connection and still-current preference can resume automatically.
pub(crate) fn schedule_worker_resume(app: &AppHandle, scope: String, until: u64) {
    let Some(tray) = app.try_state::<TrayState>() else {
        return;
    };
    let Ok(mut scheduled) = tray.resume.lock() else {
        return;
    };
    let identity = (scope, until);
    if scheduled.as_ref() == Some(&identity) {
        return;
    }
    *scheduled = Some(identity.clone());
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let remaining = until.saturating_sub(worker_control::now());
            if remaining == 0 {
                break;
            }
            // Recheck wall time after sleep, and drop timers superseded by another pause.
            tokio::time::sleep(Duration::from_millis(remaining.min(60_000))).await;
            if !app
                .state::<TrayState>()
                .resume
                .lock()
                .is_ok_and(|scheduled| scheduled.as_ref() == Some(&identity))
            {
                return;
            }
        }
        loop {
            let desktop = app.state::<crate::DesktopState>();
            let mut current = desktop.0.lock().await;
            let Some(saved) = current.as_mut() else {
                return;
            };
            if worker_control::key(saved).as_ref() != Ok(&identity.0)
                || !worker_control::load(saved)
                    .is_ok_and(|preference| preference.resume_due(until, worker_control::now()))
            {
                return;
            }
            match crate::apply_connected_worker_control(&app, saved, WorkerControl::Running).await {
                Ok(status) => {
                    crate::publish_worker_status(&app, status);
                    return;
                }
                Err(code)
                    if matches!(
                        code.as_str(),
                        "server_unreachable_or_certificate_invalid"
                            | "server_response_interrupted"
                            | "worker_resume_offline"
                    ) =>
                {
                    drop(current);
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                Err(code) => {
                    let mut status = app.state::<crate::worker_setup::WorkerSetup>().status();
                    status.state = "failed".into();
                    status.code = Some(code.clone());
                    crate::publish_worker_status(&app, status);
                    let _ = app.emit_to("main", "tray-action-failed", code);
                    return;
                }
            }
        }
    });
}

fn apply(items: &Items, server: &str, labels: &Labels, connected: bool) {
    let _ = items.server.set_text(server);
    let _ = items.worker.set_text(&labels.worker);
    let _ = items.toggle.set_text(&labels.toggle);
    let _ = items.toggle.set_enabled(labels.can_toggle);
    let _ = items.pause_hour.set_enabled(labels.can_pause_hour);
    let _ = items.stop.set_enabled(labels.can_stop);
    let _ = items.photos.set_enabled(connected);
}

/// The worker line only: called wherever a `worker-setup` status leaves for the window, so the
/// tray never lags behind it.
pub(crate) fn set_worker_status(app: &AppHandle, status: &SetupStatus) {
    let Some(state) = app.try_state::<TrayState>() else {
        return;
    };
    let Ok(slot) = state.items.lock() else {
        return;
    };
    if let Some(items) = slot.as_ref() {
        let labels = labels(status, true);
        let _ = items.worker.set_text(&labels.worker);
        let _ = items.toggle.set_text(&labels.toggle);
        let _ = items.toggle.set_enabled(labels.can_toggle);
        let _ = items.pause_hour.set_enabled(labels.can_pause_hour);
        let _ = items.stop.set_enabled(labels.can_stop);
    }
}

/// Every line, from the signed-in connection and the worker status.
pub(crate) async fn refresh(app: &AppHandle) {
    let Some(state) = app.try_state::<TrayState>() else {
        return;
    };
    let desktop = app.state::<crate::DesktopState>();
    let current = desktop.0.lock().await;
    let (server, connected) = (server_label(current.as_ref()), current.is_some());
    if !connected {
        set_import_status(app, None);
    } else if state.items.lock().is_ok_and(|slot| {
        slot.as_ref()
            .is_some_and(|items| items.last_import.is_none())
    }) {
        if let Some(import) = current.as_ref().and_then(|saved| {
            let base = app.path().app_local_data_dir().ok()?;
            app.state::<crate::source_import::SourceJobs>()
                .status(&base, saved)
                .ok()?
        }) {
            let _ = state.items.lock().map(|mut slot| {
                if let Some(items) = slot.as_mut().filter(|items| items.last_import.is_none()) {
                    items.last_import = Some((import.source_id.clone(), import.state.clone()));
                    let _ = items.import.set_text(import_label(Some(&import)));
                }
            });
        }
    }
    let status = app.state::<crate::worker_setup::WorkerSetup>().status();
    let labels = labels(&status, connected);
    let slot = state.items.lock();
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
            ..SetupStatus::default()
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
    fn import_line_shows_progress_and_notifies_only_on_matching_state_changes() {
        let copying = ImportView {
            source_id: "current".into(),
            state: "copying".into(),
            total: 12,
            completed: 8,
            ..ImportView::default()
        };
        assert_eq!(
            import_label(Some(&copying)),
            "Photo imports: copying · 8 of 12 verified"
        );
        let needs_attention = ImportView {
            state: "needs-attention".into(),
            code: Some("metered_network".into()),
            ..copying.clone()
        };
        assert_eq!(
            import_label(Some(&needs_attention)),
            "Photo imports: waiting for unmetered network · 8 of 12 verified"
        );
        assert_eq!(
            import_notice(
                Some(&("current".into(), "copying".into())),
                &needs_attention
            )
            .map(|notice| notice.0),
            Some("Photo import needs attention")
        );
        assert!(import_notice(
            Some(&("current".into(), "watching".into())),
            &needs_attention
        )
        .is_some());
        assert!(import_notice(Some(&("old".into(), "copying".into())), &needs_attention).is_none());
        assert!(import_notice(
            Some(&("current".into(), "needs-attention".into())),
            &needs_attention
        )
        .is_none());
        let complete = ImportView {
            state: "complete".into(),
            completed: 12,
            ..copying
        };
        assert_eq!(
            import_notice(Some(&("current".into(), "copying".into())), &complete),
            Some((
                "Photo import finished",
                "12 files verified in your library.".into()
            ))
        );
        let empty = ImportView {
            completed: 0,
            ..complete
        };
        assert!(import_notice(Some(&("current".into(), "copying".into())), &empty).is_none());
    }

    #[test]
    fn worker_line_and_toggle_follow_the_setup_status() {
        let running = labels(&status("working", WorkerControl::Running, None), true);
        assert_eq!(running.worker, "AI processing: working");
        assert_eq!(running.toggle, "Pause AI processing");
        assert!(running.can_toggle && running.can_stop && running.can_pause_hour);

        let paused = labels(
            &status("paused", WorkerControl::Paused, Some("user_paused")),
            true,
        );
        assert_eq!(paused.worker, "AI processing: paused");
        assert_eq!(paused.toggle, "Resume AI processing");
        assert!(paused.can_stop && !paused.can_pause_hour);
        let battery = labels(
            &status("paused", WorkerControl::Running, Some("on_battery")),
            true,
        );
        assert_eq!(battery.worker, "AI processing: waiting for power");
        assert!(battery.can_pause_hour);

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
        assert!(!offline.can_toggle && !offline.can_stop && !offline.can_pause_hour);
    }
}
