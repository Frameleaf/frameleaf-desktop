use crate::{
    host_setup::{HostSetup, View},
    require_local,
};
use tauri::{Manager, State, WebviewWindow};
#[tauri::command]
pub(crate) async fn installed_local_hosts(
    window: WebviewWindow,
) -> Result<Vec<crate::host_setup::InstalledPackage>, String> {
    require_local(&window)?;
    tauri::async_runtime::spawn_blocking(crate::host_setup::installed_packages)
        .await
        .map_err(|_| "native_host_setup_failed".to_string())?
}
#[tauri::command]
pub(crate) async fn local_host_status(
    window: WebviewWindow,
    setup: State<'_, HostSetup>,
) -> Result<View, String> {
    require_local(&window)?;
    let view = setup.status().await?;
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    {
        tauri::async_runtime::spawn_blocking(move || crate::host_setup::discover_status(view))
            .await
            .map_err(|_| "native_host_setup_failed".to_string())?
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Ok(view)
    }
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

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Explicit optional account creation stays distinct from sign-in.
pub(crate) async fn authorize_local_manager(
    window: WebviewWindow,
    app: tauri::AppHandle,
    setup: State<'_, HostSetup>,
    password: String,
    administrator_name: Option<String>,
    allow_management: bool,
    allow_recovery: bool,
    allow_updates: Option<bool>,
) -> Result<crate::manager::View, String> {
    let password = zeroize::Zeroizing::new(password);
    require_local(&window)?;
    if !allow_management {
        return Err("manager_approval_required".into());
    }
    let state = app.state::<crate::DesktopState>();
    let _lock = state.0.lock().await;
    setup
        .authorize(
            password,
            administrator_name,
            allow_recovery,
            allow_updates.unwrap_or(false),
        )
        .await
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

#[tauri::command]
pub(crate) async fn update_local_host(
    window: WebviewWindow,
    app: tauri::AppHandle,
    manifest_sha256: String,
    backup_operation_id: uuid::Uuid,
    migrations_approved: bool,
) -> Result<View, String> {
    require_local(&window)?;
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    {
        crate::host_setup::validate_update_request(
            &manifest_sha256,
            backup_operation_id,
            migrations_approved,
        )?;
        // This task owns the app and lifecycle lock if the invoking webview disconnects.
        tauri::async_runtime::spawn(async move {
            let state = app.state::<crate::DesktopState>();
            let current = state.0.lock().await;
            if current.is_some()
                || crate::credentials::load::<crate::connection::SavedConnection>("connection")?
                    .is_some()
            {
                return Err("sign_out_before_switching_servers".into());
            }
            let updated = app
                .state::<HostSetup>()
                .update(manifest_sha256, backup_operation_id, migrations_approved)
                .await?;
            // Retire old Photos assets after commit; a window failure cannot undo the update.
            if let Some(photos) = app.get_webview_window("local-photos") {
                let _ = photos.close();
            }
            Ok(updated)
        })
        .await
        .map_err(|_| "native_host_update_failed".to_string())?
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (
            app,
            manifest_sha256,
            backup_operation_id,
            migrations_approved,
        );
        Err("host_install_platform_unsupported".into())
    }
}

#[tauri::command]
pub(crate) async fn recover_local_host_update(
    window: WebviewWindow,
    app: tauri::AppHandle,
    manifest_sha256: String,
    cancel_update: bool,
) -> Result<View, String> {
    require_local(&window)?;
    if !crate::native_runtime::digest_valid(&manifest_sha256, 64) {
        return Err("host_install_identity_invalid".into());
    }
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    {
        tauri::async_runtime::spawn(async move {
            let state = app.state::<crate::DesktopState>();
            let current = state.0.lock().await;
            if current.is_some()
                || crate::credentials::load::<crate::connection::SavedConnection>("connection")?
                    .is_some()
            {
                return Err("sign_out_before_switching_servers".into());
            }
            let updated = app
                .state::<HostSetup>()
                .recover_update(manifest_sha256, cancel_update)
                .await?;
            // Retire old Photos assets after commit; a window failure cannot undo the update.
            if let Some(photos) = app.get_webview_window("local-photos") {
                let _ = photos.close();
            }
            Ok(updated)
        })
        .await
        .map_err(|_| "native_host_update_failed".to_string())?
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (app, cancel_update);
        Err("host_install_platform_unsupported".into())
    }
}
