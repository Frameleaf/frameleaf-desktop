use crate::{
    host_install,
    host_setup::{Compatibility, HostSetup, View},
    require_local,
};
use tauri::{Manager, State, WebviewWindow};
/// Display-only details that let a person tell installed packages apart before a one-way move.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstalledPackage {
    #[serde(flatten)]
    installation: host_install::Installation,
    version: Option<String>,
    library: bool,
}
#[tauri::command]
pub(crate) async fn installed_local_hosts(
    window: WebviewWindow,
) -> Result<Vec<InstalledPackage>, String> {
    require_local(&window)?;
    tauri::async_runtime::spawn_blocking(|| {
        let records = host_install::installed()?;
        let current = crate::host_setup::library_package(&records);
        Ok(records
            .into_iter()
            .map(|installation| InstalledPackage {
                version: crate::host_setup::package_version(&installation),
                library: current.as_deref() == Some(installation.manifest_sha256.as_str()),
                installation,
            })
            .collect())
    })
    .await
    .map_err(|_| "native_host_setup_failed".to_string())?
}
#[tauri::command]
pub(crate) async fn check_local_host_package(
    window: WebviewWindow,
    setup: State<'_, HostSetup>,
    manifest_sha256: String,
    controller_sha256: String,
) -> Result<Compatibility, String> {
    require_local(&window)?;
    Ok(setup
        .compatibility(manifest_sha256, controller_sha256)
        .await)
}

#[tauri::command]
pub(crate) async fn local_host_status(
    window: WebviewWindow,
    setup: State<'_, HostSetup>,
) -> Result<View, String> {
    require_local(&window)?;
    setup.status().await
}
#[tauri::command]
pub(crate) async fn prepare_local_host(
    window: WebviewWindow,
    setup: State<'_, HostSetup>,
    app: tauri::AppHandle,
    manifest_sha256: String,
) -> Result<View, String> {
    require_local(&window)?;
    let state = app.state::<crate::DesktopState>();
    let current = state.0.lock().await;
    if current.is_some()
        || crate::credentials::load::<crate::connection::SavedConnection>("connection")?.is_some()
    {
        return Err("sign_out_before_switching_servers".into());
    }
    setup.start(manifest_sha256).await
}
#[tauri::command]
pub(crate) async fn provision_local_host_profile(
    window: WebviewWindow,
    setup: State<'_, HostSetup>,
    app: tauri::AppHandle,
    manifest_sha256: String,
) -> Result<View, String> {
    require_local(&window)?;
    let state = app.state::<crate::DesktopState>();
    let current = state.0.lock().await;
    if current.is_some()
        || crate::credentials::load::<crate::connection::SavedConnection>("connection")?.is_some()
    {
        return Err("sign_out_before_switching_servers".into());
    }
    setup.provision(manifest_sha256).await
}
#[tauri::command]
pub(crate) fn cancel_local_host_start(
    window: WebviewWindow,
    setup: State<'_, HostSetup>,
) -> Result<(), String> {
    require_local(&window)?;
    setup.cancel();
    Ok(())
}
#[tauri::command]
pub(crate) async fn stop_local_host_manager(
    window: WebviewWindow,
    setup: State<'_, HostSetup>,
) -> Result<View, String> {
    require_local(&window)?;
    setup.stop().await
}

/// The quit path offered after a blocked exit: stop local management, then leave the app.
/// `leave_running` is the fallback once that stop has failed: quit and let the next launch
/// stop the recorded Manager.
#[tauri::command]
pub(crate) async fn quit_local_host(
    window: WebviewWindow,
    app: tauri::AppHandle,
    setup: State<'_, HostSetup>,
    leave_running: bool,
) -> Result<(), String> {
    require_local(&window)?;
    if leave_running {
        // Only give up exit protection when nothing else would then refuse the exit.
        if app.state::<crate::media_copy::MediaCopy>().is_active() {
            return Err("media_copy_exit_blocked".into());
        }
        setup.leave_for_exit(true)?;
    } else {
        setup.stop_for_exit().await?;
    }
    app.exit(0);
    Ok(())
}

#[tauri::command]
pub(crate) async fn authorize_local_manager(
    window: WebviewWindow,
    app: tauri::AppHandle,
    setup: State<'_, HostSetup>,
    password: String,
    allow_management: bool,
    allow_recovery: bool,
) -> Result<crate::manager::View, String> {
    let password = zeroize::Zeroizing::new(password);
    require_local(&window)?;
    if !allow_management {
        return Err("manager_approval_required".into());
    }
    let state = app.state::<crate::DesktopState>();
    let _lock = state.0.lock().await;
    setup.authorize(password, allow_recovery).await
}

#[tauri::command]
pub(crate) async fn open_local_photos(
    window: WebviewWindow,
    app: tauri::AppHandle,
    setup: State<'_, HostSetup>,
) -> Result<(), String> {
    require_local(&window)?;
    let state = app.state::<crate::DesktopState>();
    let current = state.0.lock().await;
    if current.is_some() {
        return Err("sign_out_before_switching_servers".into());
    }
    let base = setup.photos_url().await?;
    if let Some(photos) = app.get_webview_window("local-photos") {
        photos.show().map_err(|_| "photo_window_unavailable")?;
        photos.set_focus().map_err(|_| "photo_window_unavailable")?;
        return Ok(());
    }
    let origin = base.origin();
    // No NAS session injection or native capabilities; the existing photo UI owns signup/login.
    tauri::WebviewWindowBuilder::new(&app, "local-photos", tauri::WebviewUrl::External(base))
        .title("Frameleaf Photos — This computer")
        .inner_size(1280.0, 850.0)
        .on_navigation(move |url| url.origin() == origin)
        .build()
        .map_err(|_| "photo_window_unavailable")?;
    Ok(())
}
