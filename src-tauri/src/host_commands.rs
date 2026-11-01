use crate::{
    host_install,
    host_setup::{HostSetup, View},
    require_local,
};
use tauri::{Manager, State, WebviewWindow};
#[tauri::command]
pub(crate) async fn installed_local_hosts(
    window: WebviewWindow,
) -> Result<Vec<host_install::Installation>, String> {
    require_local(&window)?;
    tauri::async_runtime::spawn_blocking(host_install::installed)
        .await
        .map_err(|_| "native_host_setup_failed".to_string())?
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

#[tauri::command]
pub(crate) async fn authorize_local_manager(
    window: WebviewWindow,
    app: tauri::AppHandle,
    setup: State<'_, HostSetup>,
    password: String,
    allow_management: bool,
) -> Result<crate::manager::View, String> {
    let password = zeroize::Zeroizing::new(password);
    require_local(&window)?;
    if !allow_management {
        return Err("manager_approval_required".into());
    }
    let state = app.state::<crate::DesktopState>();
    let _lock = state.0.lock().await;
    setup.authorize(password).await
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
