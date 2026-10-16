pub mod connection;
mod credentials;
pub mod lifecycle;
pub mod ml_transport;
mod model_cache;
pub mod model_catalogue;
pub mod native_predictor;
pub mod native_runtime;
pub mod photo_sources;
mod process_tree;
pub mod release_policy;
mod resource_policy;
pub mod runtime_store;
mod transport;
pub mod worker;
mod worker_control;
mod worker_setup;

use connection::{normalize_server, ConnectionView, Features, SavedConnection};
use serde::Deserialize;
use tauri::{Emitter, Manager, State, WebviewUrl, WebviewWindow};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

#[derive(Default)]
struct DesktopState(Mutex<Option<SavedConnection>>);

fn require_local(window: &WebviewWindow) -> Result<(), String> {
    let url = window.url().map_err(|_| "window_origin_invalid")?;
    if !connection::native_origin_allowed(window.label(), &url, cfg!(debug_assertions)) {
        return Err("native_access_denied".into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    access_token: String,
    user_id: String,
    name: String,
}

async fn prepare(saved: &mut SavedConnection) -> ConnectionView {
    let unavailable = Features {
        enrollment: false,
        worker: false,
        worker_session: false,
        sources: false,
        native_host: false,
    };
    let client = match transport::client() {
        Ok(c) => c,
        Err(_) => return ConnectionView::new(saved, "offline".into(), unavailable),
    };
    prepare_with_client(&client, saved).await
}

async fn prepare_with_client(
    client: &reqwest::Client,
    saved: &mut SavedConnection,
) -> ConnectionView {
    let unavailable = Features {
        enrollment: false,
        worker: false,
        worker_session: false,
        sources: false,
        native_host: false,
    };
    match transport::capabilities(client, saved).await {
        Ok(Some(caps)) => {
            if connection::persist_server_identity(saved, &caps.server_id, |value| {
                credentials::save("connection", value)
            })
            .is_err()
            {
                return ConnectionView::new(
                    saved,
                    "credential-store-unavailable".into(),
                    caps.features,
                );
            }
            if !caps.features.enrollment {
                return ConnectionView::new(saved, "unsupported-server".into(), caps.features);
            }
            match transport::enroll(client, saved).await {
                Ok(enrollment) => {
                    saved.device_id = Some(enrollment.id);
                    if credentials::save("connection", saved).is_err() {
                        return ConnectionView::new(
                            saved,
                            "credential-store-unavailable".into(),
                            caps.features,
                        );
                    }
                    if caps.features.worker_session && enrollment.state == "preparing" {
                        // A new photo association must never reuse an earlier worker grant.
                        if credentials::delete("worker-session").is_err() {
                            return ConnectionView::new(
                                saved,
                                "credential-store-unavailable".into(),
                                caps.features,
                            );
                        }
                        let issued = transport::issue_worker_session(client, saved).await;
                        if issued
                            .and_then(|worker| credentials::save("worker-session", &worker))
                            .is_err()
                        {
                            return ConnectionView::new(
                                saved,
                                "worker-setup-failed".into(),
                                caps.features,
                            );
                        }
                    }
                    ConnectionView::new(saved, enrollment.state, caps.features)
                }
                Err(_) => ConnectionView::new(saved, "enrollment-failed".into(), caps.features),
            }
        }
        Ok(None) => ConnectionView::new(saved, "unsupported-server".into(), unavailable),
        Err(code) => ConnectionView::new(
            saved,
            if code == "server_identity_changed" {
                "identity-changed"
            } else {
                "offline"
            }
            .into(),
            unavailable,
        ),
    }
}

#[tauri::command]
async fn connect_server(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    server: String,
    email: String,
    password: String,
    device_name: String,
) -> Result<ConnectionView, String> {
    require_local(&window)?;
    let mut current = state.0.lock().await;
    if current.is_some() || credentials::load::<SavedConnection>("connection")?.is_some() {
        return Err("sign_out_before_switching_servers".into());
    }
    let client = transport::client()?;
    let (saved, mut view) = sign_in(&client, &server, &email, password, &device_name).await?;
    if view.state == "preparing"
        && view.features.worker_session
        && start_worker_setup(&app, &saved, false).await.is_err()
    {
        view.state = "worker-setup-failed".into();
    }
    *current = Some(saved);
    Ok(view)
}

async fn sign_in(
    client: &reqwest::Client,
    server: &str,
    email: &str,
    password: String,
    device_name: &str,
) -> Result<(SavedConnection, ConnectionView), String> {
    let base = normalize_server(server)?;
    let password = Zeroizing::new(password);
    if email.is_empty() || email.len() > 320 || password.is_empty() || password.len() > 4096 {
        return Err("login_details_invalid".into());
    }
    // Check secure persistence and the device identity before sending a password.
    let identity = credentials::identity()?;
    identity.enrollment("validation", "validation", device_name, "client-worker")?;
    let response = client.post(base.join("api/auth/login").unwrap())
        .json(&serde_json::json!({ "email": email.trim(), "password": password.as_str(), "rememberMe": true }))
        .send().await.map_err(|_| "server_unreachable_or_certificate_invalid")?;
    let login: LoginResponse = transport::json(response).await?;
    let mut saved = SavedConnection {
        server: base.to_string(),
        server_id: String::new(),
        account_id: login.user_id,
        name: login.name,
        token: login.access_token,
        device_name: device_name.into(),
        mode: "client-worker".into(),
        device_id: None,
    };
    if let Err(error) = credentials::save("connection", &saved) {
        let _ = client
            .post(base.join("api/auth/logout").unwrap())
            .bearer_auth(&saved.token)
            .send()
            .await;
        return Err(error);
    }
    let view = prepare_with_client(client, &mut saved).await;
    Ok((saved, view))
}

#[tauri::command]
async fn restore_connection(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<Option<ConnectionView>, String> {
    require_local(&window)?;
    let mut current = state.0.lock().await;
    app.state::<worker_setup::WorkerSetup>().stop().await;
    let Some(mut saved) = credentials::load::<SavedConnection>("connection")? else {
        return Ok(None);
    };
    if saved.server_id.is_empty() {
        return Err("server_identity_not_confirmed".into());
    }
    let base = normalize_server(&saved.server)?;
    let client = transport::client()?;
    #[derive(Deserialize)]
    struct User {
        id: String,
    }
    let response = client
        .get(base.join("api/users/me").unwrap())
        .bearer_auth(&saved.token)
        .send()
        .await
        .map_err(|_| "server_unreachable_or_certificate_invalid")?;
    let user: User = transport::json(response).await?;
    if user.id != saved.account_id {
        return Err("account_identity_changed".into());
    }
    let mut view = prepare(&mut saved).await;
    if view.state == "preparing"
        && view.features.worker_session
        && start_worker_setup(&app, &saved, false).await.is_err()
    {
        view.state = "worker-setup-failed".into();
    }
    *current = Some(saved);
    Ok(Some(view))
}

#[tauri::command]
async fn sign_out(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<lifecycle::SignOutResult, String> {
    require_local(&window)?;
    let mut current = state.0.lock().await;
    app.state::<worker_setup::WorkerSetup>().stop().await;
    let saved = current
        .clone()
        .or(credentials::load::<SavedConnection>("connection")?);
    *current = None;
    Ok(lifecycle::finish_sign_out(
        async {
            let worker = credentials::delete("worker-session").is_ok();
            let connection = credentials::delete("connection").is_ok();
            worker && connection
        },
        async {
            if let Some(photos) = app.get_webview_window("photos") {
                let cleared = photos.clear_all_browsing_data().is_ok();
                let closed = photos.close().is_ok();
                cleared && closed
            } else {
                true
            }
        },
        async {
            let Some(saved) = saved else {
                return false;
            };
            let Ok(base) = normalize_server(&saved.server) else {
                return false;
            };
            let Ok(client) = transport::client() else {
                return false;
            };
            let mut revoked = true;
            if let Some(device) = &saved.device_id {
                let Ok(url) = base.join(&format!("api/desktop/devices/{device}/session")) else {
                    return false;
                };
                revoked &= client
                    .delete(url)
                    .bearer_auth(&saved.token)
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false);
            }
            revoked &= client
                .post(base.join("api/auth/logout").unwrap())
                .bearer_auth(&saved.token)
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            revoked
        },
    )
    .await)
}

#[tauri::command]
async fn open_photos(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<(), String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let base = normalize_server(&saved.server)?;
    if let Some(photos) = app.get_webview_window("photos") {
        photos.show().map_err(|_| "photo_window_unavailable")?;
        photos.set_focus().map_err(|_| "photo_window_unavailable")?;
        return Ok(());
    }
    let origin = base.origin();
    let photos =
        tauri::WebviewWindowBuilder::new(&app, "photos", WebviewUrl::External(base.clone()))
            .title("Frameleaf Photos")
            .inner_size(1280.0, 850.0)
            .on_navigation(move |url| url.origin() == origin)
            .build()
            .map_err(|_| "photo_window_unavailable")?;
    let domain = base.host_str().ok_or("server_address_invalid")?;
    let token = tauri::webview::Cookie::build(("immich_access_token", saved.token.clone()))
        .domain(domain)
        .path("/")
        .secure(true)
        .http_only(true)
        .build();
    photos
        .set_cookie(token)
        .map_err(|_| "photo_session_unavailable")?;
    for (key, value) in [
        ("immich_is_authenticated", "true"),
        ("immich_auth_type", "password"),
    ] {
        photos
            .set_cookie(
                tauri::webview::Cookie::build((key, value))
                    .domain(domain)
                    .path("/")
                    .secure(true)
                    .build(),
            )
            .map_err(|_| "photo_session_unavailable")?;
    }
    photos
        .navigate(base.join("photos").unwrap())
        .map_err(|_| "photo_window_unavailable")?;
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .manage(DesktopState::default())
        .manage(worker_setup::WorkerSetup::default())
        .invoke_handler(tauri::generate_handler![
            connect_server,
            restore_connection,
            sign_out,
            open_photos,
            worker_setup_status,
            prepare_models,
            control_worker,
            discover_onedrive,
            choose_photo_folder
        ])
        .run(tauri::generate_context!())
        .expect("Frameleaf desktop failed to start");
}

async fn start_worker_setup(
    app: &tauri::AppHandle,
    saved: &SavedConnection,
    allow_download: bool,
) -> Result<(), String> {
    let control = worker_control::load(saved)?;
    if control != worker_control::WorkerControl::Running {
        let status = app.state::<worker_setup::WorkerSetup>().hold(control).await;
        let _ = app.emit_to("main", "worker-setup", status);
        return Ok(());
    }
    let paths = worker_setup::SetupPaths {
        data: app
            .path()
            .app_local_data_dir()
            .map_err(|_| "app_data_directory_unavailable")?
            .join("worker"),
        bundle: app
            .path()
            .resource_dir()
            .map_err(|_| "app_resources_unavailable")?
            .join("native-runtime"),
    };
    let handle = app.clone();
    app.state::<worker_setup::WorkerSetup>()
        .start(
            saved.clone(),
            paths,
            allow_download,
            std::sync::Arc::new(move |status| {
                let _ = handle.emit_to("main", "worker-setup", status);
            }),
        )
        .await;
    Ok(())
}

#[tauri::command]
async fn worker_setup_status(
    window: WebviewWindow,
    app: tauri::AppHandle,
) -> Result<worker_setup::SetupStatus, String> {
    require_local(&window)?;
    Ok(app.state::<worker_setup::WorkerSetup>().status())
}

#[tauri::command]
async fn prepare_models(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    allow_download: bool,
) -> Result<(), String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    if saved.mode != "client-worker" || saved.server_id.is_empty() || saved.device_id.is_none() {
        return Err("desktop_enrollment_required".into());
    }
    start_worker_setup(&app, saved, allow_download).await
}

#[tauri::command]
async fn control_worker(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    control: worker_control::WorkerControl,
) -> Result<worker_setup::SetupStatus, String> {
    require_local(&window)?;
    let mut current = state.0.lock().await;
    let saved = current.as_mut().ok_or("sign_in_required")?;
    let setup = app.state::<worker_setup::WorkerSetup>();
    match control {
        worker_control::WorkerControl::Paused => {
            let status = setup.pause();
            worker_control::save(saved, control)?;
            Ok(status)
        }
        worker_control::WorkerControl::Stopped => {
            let status = setup.hold(control).await;
            worker_control::save(saved, control)?;
            Ok(status)
        }
        worker_control::WorkerControl::Running => {
            let previous = worker_control::load(saved)?;
            setup.stop().await;
            let view = prepare(saved).await;
            if view.state != "preparing" || !view.features.worker_session {
                setup.hold(previous).await;
                return Err("worker_setup_unavailable".into());
            }
            if let Err(error) = worker_control::save(saved, control) {
                setup.hold(previous).await;
                return Err(error);
            }
            start_worker_setup(&app, saved, false).await?;
            Ok(setup.status())
        }
    }
}

fn source_hints(app: &tauri::AppHandle) -> Result<Vec<photo_sources::RootHint>, String> {
    let home = app
        .path()
        .home_dir()
        .map_err(|_| "source_home_unavailable")?;
    let supplied: Vec<_> = if cfg!(target_os = "windows") {
        ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"]
            .iter()
            .filter_map(std::env::var_os)
            .map(std::path::PathBuf::from)
            .collect()
    } else {
        Vec::new()
    };
    Ok(photo_sources::known_onedrive_roots(&home, &supplied))
}
#[tauri::command]
async fn discover_onedrive(
    window: WebviewWindow,
    app: tauri::AppHandle,
) -> Result<Vec<photo_sources::RootHint>, String> {
    require_local(&window)?;
    tauri::async_runtime::spawn_blocking(move || source_hints(&app))
        .await
        .map_err(|_| "source_discovery_failed")?
}
#[tauri::command]
async fn choose_photo_folder(
    window: WebviewWindow,
    app: tauri::AppHandle,
    one_drive: Option<usize>,
) -> Result<Option<photo_sources::FolderInventory>, String> {
    use tauri_plugin_dialog::DialogExt;
    require_local(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut picker = app.dialog().file().set_title("Choose a photo folder");
        if let Some(index) = one_drive {
            let hints = source_hints(&app)?;
            let hint = hints.get(index).ok_or("source_account_unavailable")?;
            picker = picker.set_directory(&hint.path);
        }
        let Some(folder) = picker.blocking_pick_folder() else {
            return Ok(None);
        };
        let path = folder.into_path().map_err(|_| "source_folder_invalid")?;
        photo_sources::inventory(&path, 10_000).map(Some)
    })
    .await
    .map_err(|_| "source_inventory_failed")?
}
