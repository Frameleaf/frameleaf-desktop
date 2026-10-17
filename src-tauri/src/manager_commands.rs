use crate::{credentials, manager, require_local, DesktopState};
use tauri::{Manager, WebviewWindow};

#[tauri::command]
pub(crate) async fn manager_view(
    window: WebviewWindow,
    app: tauri::AppHandle,
) -> Result<Option<manager::View>, String> {
    require_local(&window)?;
    let state = app.state::<DesktopState>();
    let _lock = state.0.lock().await;
    let Some(saved) = credentials::load::<manager::SavedManager>(manager::CREDENTIAL)? else {
        return Ok(None);
    };
    // Public pairing metadata remains visible when a device key needs recovery.
    Ok(Some(saved.view()))
}
#[tauri::command]
pub(crate) fn manager_certificate_fingerprint(
    window: WebviewWindow,
    pem: String,
) -> Result<String, String> {
    require_local(&window)?;
    manager::certificate_fingerprint(&pem)
}
#[tauri::command]
pub(crate) async fn pair_manager(
    window: WebviewWindow,
    app: tauri::AppHandle,
    origin: String,
    password: String,
    certificate: Option<manager::CertificateTrust>,
    allow_management: bool,
) -> Result<manager::View, String> {
    require_local(&window)?;
    if !allow_management {
        return Err("manager_approval_required".into());
    }
    let state = app.state::<DesktopState>();
    let _lock = state.0.lock().await;
    if credentials::load::<manager::SavedManager>(manager::CREDENTIAL)?.is_some() {
        return Err("manager_already_paired".into());
    }
    let origin = crate::connection::normalize_server(&origin)?
        .origin()
        .ascii_serialization();
    let identity = credentials::identity()?;
    // Confirm secure writes before sending a Manager password; no plaintext fallback.
    credentials::save("manager-pairing-check", &true)?;
    credentials::delete("manager-pairing-check")?;
    manager::pair(&identity, &origin, password, certificate, |saved| {
        credentials::save(manager::CREDENTIAL, saved)
    })
    .await
}
#[tauri::command]
pub(crate) async fn manager_request(
    window: WebviewWindow,
    app: tauri::AppHandle,
    command: manager::Command,
) -> Result<serde_json::Value, String> {
    require_local(&window)?;
    let state = app.state::<DesktopState>();
    let _lock = state.0.lock().await;
    let saved = credentials::load::<manager::SavedManager>(manager::CREDENTIAL)?
        .ok_or("manager_pairing_required")?;
    app.state::<crate::host_setup::HostSetup>()
        .require_management_origin(&saved.view().origin)?;
    manager::send(&saved, &credentials::identity()?, command).await
}
#[tauri::command]
pub(crate) async fn reauthenticate_manager(
    window: WebviewWindow,
    app: tauri::AppHandle,
    password: String,
) -> Result<(), String> {
    require_local(&window)?;
    let state = app.state::<DesktopState>();
    let _lock = state.0.lock().await;
    let saved = credentials::load::<manager::SavedManager>(manager::CREDENTIAL)?
        .ok_or("manager_pairing_required")?;
    saved.require_device(&credentials::identity()?)?;
    manager::reauthenticate(&saved, password).await
}
#[tauri::command]
pub(crate) async fn disconnect_manager(
    window: WebviewWindow,
    app: tauri::AppHandle,
    password: String,
) -> Result<(), String> {
    require_local(&window)?;
    let state = app.state::<DesktopState>();
    let _lock = state.0.lock().await;
    let saved = credentials::load::<manager::SavedManager>(manager::CREDENTIAL)?
        .ok_or("manager_pairing_required")?;
    // Revocation requires the Manager password, not possession of the old device key.
    manager::disconnect(&saved, password).await?;
    credentials::delete(manager::CREDENTIAL)
}
