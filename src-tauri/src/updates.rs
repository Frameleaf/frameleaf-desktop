use std::time::Duration;

use tauri::{AppHandle, Manager, WebviewWindow};
use tauri_plugin_updater::{Error, Update, UpdaterExt};

use crate::{host_setup::HostSetup, require_local};

async fn latest(app: &AppHandle) -> Result<Option<Update>, String> {
    if cfg!(debug_assertions) || tauri::utils::platform::bundle_type().is_none() {
        return Ok(None);
    }
    let updater = app
        .updater_builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "update_check_failed")?;
    match updater.check().await {
        Ok(update) => Ok(update),
        Err(Error::ReleaseNotFound | Error::TargetsNotFound(_)) => Ok(None),
        Err(error) => {
            eprintln!("Desktop update check failed: {error}");
            Err("update_check_failed".into())
        }
    }
}

#[tauri::command]
pub(crate) async fn check_desktop_update(
    window: WebviewWindow,
    app: AppHandle,
) -> Result<Option<String>, String> {
    require_local(&window)?;
    Ok(latest(&app).await?.map(|update| update.version))
}

#[tauri::command]
pub(crate) async fn install_desktop_update(
    window: WebviewWindow,
    app: AppHandle,
    version: String,
) -> Result<(), String> {
    require_local(&window)?;
    let host = app.state::<HostSetup>();
    let _owner = host.lock_for_update()?;
    let media_copy = app
        .state::<crate::media_copy::MediaCopy>()
        .lock_for_update()?;
    let mut update = latest(&app)
        .await?
        .filter(|update| update.version == version)
        .ok_or("update_changed")?;
    let url = &update.download_url;
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.port().is_some()
        || !url
            .path()
            .starts_with("/Frameleaf/frameleaf-desktop/releases/download/")
    {
        return Err("update_install_failed".into());
    }
    update.timeout = Some(Duration::from_secs(60 * 60));
    let bytes = update.download(|_, _| {}, || {}).await.map_err(|error| {
        eprintln!("Desktop update download failed: {error}");
        "update_install_failed"
    })?;
    let restart = app.clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        let _media_copy = media_copy;
        update.install(bytes).map_err(|error| {
            eprintln!("Desktop update installation failed: {error}");
            "update_install_failed"
        })?;
        // Keep the local host locked until the app has exited.
        restart.restart();
    })
    .await
    .map_err(|_| "update_install_failed")?
}
