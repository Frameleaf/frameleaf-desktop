mod camera_sources;
pub mod cloud_account;
pub mod connection;
pub mod copy_source;
pub mod copy_upload;
mod credential_lock;
mod credentials;
mod discovery;
mod drop_import;
mod file_manager_import;
mod host_commands;
pub mod host_control;
mod host_database;
pub mod host_install;
pub mod host_runtime;
mod host_setup;
mod host_state;
mod host_storage;
mod identity_anchor;
mod import_album;
pub mod lifecycle;
pub mod manager;
mod manager_commands;
pub mod manager_host;
mod manager_profile;
pub mod manager_tls;
pub mod ml_transport;
mod model_cache;
pub mod model_catalogue;
pub mod native_predictor;
pub mod native_runtime;
mod package_lease;
pub mod photo_sources;
mod process_tree;
#[cfg(any(target_os = "linux", test))]
mod profile_elevation;
pub mod release_policy;
mod resource_policy;
pub mod runtime_epochs;
pub mod runtime_store;
mod server_admin;
mod server_identity;
mod server_login;
mod source_consent;
mod source_import;
mod source_metadata;
mod transport;
mod tray;
mod updates;
mod upload_budget;
mod upload_parts;
mod window_placement;
#[cfg(windows)]
mod windows_host_profile;
#[cfg(any(windows, test))]
mod windows_protection;
pub mod worker;
mod worker_control;
mod worker_setup;

use connection::{normalize_server, ConnectionView, Features, SavedConnection};
use serde::Deserialize;
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindow};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct DesktopState(pub(crate) Mutex<Option<SavedConnection>>);

pub(crate) fn require_local(window: &WebviewWindow) -> Result<(), String> {
    let url = window.url().map_err(|_| "window_origin_invalid")?;
    if !connection::native_origin_allowed(window.label(), &url, cfg!(debug_assertions)) {
        return Err("native_access_denied".into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginResponse {
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

pub(crate) async fn prepare_with_client(
    client: &reqwest::Client,
    saved: &mut SavedConnection,
) -> ConnectionView {
    let capabilities = transport::capabilities(client, saved).await;
    prepare_with_capabilities(client, saved, capabilities).await
}

async fn prepare_with_capabilities(
    client: &reqwest::Client,
    saved: &mut SavedConnection,
    capabilities: Result<Option<connection::Capabilities>, String>,
) -> ConnectionView {
    let unavailable = Features {
        enrollment: false,
        worker: false,
        worker_session: false,
        sources: false,
        native_host: false,
    };
    match capabilities {
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
    if app.state::<host_setup::HostSetup>().background_active() {
        return Err("local_host_active".into());
    }
    if current.is_some() || credentials::load::<SavedConnection>("connection")?.is_some() {
        return Err("sign_out_before_switching_servers".into());
    }
    let client = transport::client()?;
    let (saved, mut view) = sign_in(
        &client,
        &server,
        &email,
        password,
        &device_name,
        || credentials::foreground_identity(&window),
        |saved| credentials::confirm_new_sign_in("connection", saved, &window),
    )
    .await?;
    if view.state == "preparing"
        && view.features.worker_session
        && start_worker_setup(&app, &saved, false).await.is_err()
    {
        view.state = "worker-setup-failed".into();
    }
    *current = Some(saved);
    drop(current);
    tray::refresh(&app).await;
    Ok(view)
}

async fn sign_in(
    client: &reqwest::Client,
    server: &str,
    email: &str,
    password: String,
    device_name: &str,
    identity: impl FnOnce() -> Result<connection::DeviceIdentity, String>,
    confirm: impl FnOnce(&SavedConnection) -> Result<(), String>,
) -> Result<(SavedConnection, ConnectionView), String> {
    let base = normalize_server(server)?;
    let password = Zeroizing::new(password);
    let email = email.trim();
    if email.is_empty() || email.len() > 320 || password.is_empty() || password.len() > 4096 {
        return Err("login_details_invalid".into());
    }
    // Check secure persistence and the device identity before sending a password.
    let identity = identity()?;
    identity.enrollment("validation", "validation", device_name, "client-worker")?;
    let response = client.post(base.join("api/auth/login").unwrap())
        .json(&serde_json::json!({ "email": email, "password": password.as_str(), "rememberMe": true }))
        .send().await.map_err(|_| "server_unreachable_or_certificate_invalid")?;
    let login: LoginResponse = transport::json(response).await?;
    keep_login(client, &base, login, device_name, confirm).await
}

/// A server session from any sign-in method becomes this computer's saved connection.
pub(crate) async fn keep_login(
    client: &reqwest::Client,
    base: &url::Url,
    login: LoginResponse,
    device_name: &str,
    confirm: impl FnOnce(&SavedConnection) -> Result<(), String>,
) -> Result<(SavedConnection, ConnectionView), String> {
    let mut saved = SavedConnection {
        server: base.to_string(),
        server_id: String::new(),
        account_id: login.user_id,
        name: login.name,
        token: login.access_token,
        device_name: device_name.trim().into(),
        mode: "client-worker".into(),
        device_id: None,
    };
    let view = finish_new_connection(client, &mut saved, confirm).await?;
    Ok((saved, view))
}

// Persist the verified identity with the very first credential so cancellation is restart-safe.
async fn finish_new_connection(
    client: &reqwest::Client,
    saved: &mut SavedConnection,
    confirm: impl FnOnce(&SavedConnection) -> Result<(), String>,
) -> Result<ConnectionView, String> {
    let capabilities = transport::capabilities(client, saved).await;
    if let Ok(Some(caps)) = &capabilities {
        saved.server_id.clone_from(&caps.server_id);
    }
    let result = match credentials::save("connection", saved) {
        Err(error) => Err(error),
        Ok(()) => match confirm(saved) {
            Ok(()) => return Ok(prepare_with_capabilities(client, saved, capabilities).await),
            // A changed item may belong to another writer. Revoke our minted token only.
            Err(error) if error == "credential_confirmation_changed" => Err(error),
            Err(error)
                if !saved.server_id.is_empty()
                    && matches!(
                        error.as_str(),
                        "credential_unlock_required" | "credential_confirmation_unavailable"
                    ) =>
            {
                return Err(error)
            }
            Err(_) => {
                credentials::delete("connection").and(Err("server_sign_in_retry_required".into()))
            }
        },
    };
    let base = normalize_server(&saved.server)?;
    let _ = client
        .post(base.join("api/auth/logout").unwrap())
        .bearer_auth(&saved.token)
        .send()
        .await;
    result
}

#[tauri::command]
async fn restore_connection(
    retry: Option<bool>,
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<Option<ConnectionView>, String> {
    require_local(&window)?;
    let mut current = state.0.lock().await;
    if app.state::<host_setup::HostSetup>().background_active() {
        return Ok(None);
    }
    app.state::<source_import::SourceJobs>().stop().await;
    app.state::<drop_import::DropImport>()
        .reset_for_restore()
        .await;
    app.state::<worker_setup::WorkerSetup>().stop().await;
    let Some(mut saved) = credentials::load_interactive::<SavedConnection>(
        "connection",
        &window,
        retry.unwrap_or(false),
    )?
    else {
        // The saved sign-in is gone: drop any connection still held so the window and the
        // background agree (the jobs above already stopped).
        let held = current.take().is_some();
        drop(current);
        if held {
            tray::refresh(&app).await;
        }
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
    if retry.unwrap_or(false) {
        credentials::unlock_existing_identity(&window)?;
    }
    let mut view = prepare(&mut saved).await;
    if view.state == "preparing"
        && view.features.worker_session
        && start_worker_setup(&app, &saved, false).await.is_err()
    {
        view.state = "worker-setup-failed".into();
    }
    if let Ok(Some(consent)) =
        credentials::load::<source_consent::Consent>(source_consent::CREDENTIAL)
    {
        if consent.watch && consent.registered && !consent.watch_paused {
            if let Ok(base) = import_base(&app) {
                let _ = app
                    .state::<source_import::SourceJobs>()
                    .start(app.clone(), base, saved.clone())
                    .await;
            }
        }
    }
    *current = Some(saved);
    drop(current);
    tray::refresh(&app).await;
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
    app.state::<source_import::SourceJobs>().stop().await;
    app.state::<drop_import::DropImport>().stop().await;
    app.state::<source_consent::SourceConsent>().clear()?;
    app.state::<worker_setup::WorkerSetup>().stop().await;
    let saved = match current.as_ref() {
        Some(saved) => Some(saved.clone()),
        None => match credentials::load_interactive::<SavedConnection>("connection", &window, true)
        {
            // The explicit clear action already authorized access; malformed bytes cannot revoke remotely.
            Err(code) if code == "credential_record_invalid" => None,
            result => result?,
        },
    };
    *current = None;
    drop(current);
    tray::refresh(&app).await;
    Ok(lifecycle::finish_sign_out(
        async {
            let worker = credentials::delete("worker-session").is_ok();
            let connection = credentials::delete("connection").is_ok();
            let sources = credentials::delete(source_consent::CREDENTIAL).is_ok();
            let drops = credentials::delete(drop_import::CREDENTIAL).is_ok();
            worker && connection && sources && drops
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
    open_photos_window(&app, saved)
}

/// Shows the photo window for the signed-in connection, from the window or the tray alike.
pub(crate) fn open_photos_window(app: &AppHandle, saved: &SavedConnection) -> Result<(), String> {
    let base = normalize_server(&saved.server)?;
    if let Some(photos) = app.get_webview_window("photos") {
        photos.show().map_err(|_| "photo_window_unavailable")?;
        photos.set_focus().map_err(|_| "photo_window_unavailable")?;
        return Ok(());
    }
    let origin = base.origin();
    let photos =
        tauri::WebviewWindowBuilder::new(app, "photos", WebviewUrl::External(base.clone()))
            .title("Frameleaf Photos")
            .inner_size(1280.0, 850.0)
            .on_navigation(move |url| url.origin() == origin)
            .build()
            .map_err(|_| "photo_window_unavailable")?;
    let domain = base.host_str().ok_or("server_address_invalid")?;
    let secure = base.scheme() == "https";
    let token = tauri::webview::Cookie::build(("immich_access_token", saved.token.clone()))
        .domain(domain)
        .path("/")
        .secure(secure)
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
                    .secure(secure)
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
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_single_instance::init(|app, args, _| {
            #[cfg(windows)]
            if let Some(selection) =
                file_manager_import::windows_selection(args.into_iter().map(Into::into))
            {
                drop_import::launch_event(app, selection);
                return;
            }
            #[cfg(not(windows))]
            let _ = args;
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .manage(DesktopState::default())
        .manage(window_placement::WindowPlacement::default())
        .manage(host_setup::HostSetup::default())
        .manage(worker_setup::WorkerSetup::default())
        .manage(source_consent::SourceConsent::default())
        .manage(source_import::SourceJobs::default())
        .manage(source_import::ImportTransfer::default())
        .manage(drop_import::DropImport::default())
        .manage(tray::TrayState::default())
        .manage(cloud_account::email::EmailAttempt::default())
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                let placement = app.state::<window_placement::WindowPlacement>();
                placement.restore(&window);
                let _ = window.show();
                placement.remember(&window);
            }
            file_manager_import::setup(app.handle());
            // A desktop without a tray (some Linux sessions) still gets the window.
            if let Err(error) = tray::build(app.handle()) {
                eprintln!("tray unavailable: {error}");
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            updates::check_desktop_update,
            updates::install_desktop_update,
            host_commands::open_local_photos,
            host_commands::authorize_local_manager,
            host_commands::installed_local_hosts,
            host_commands::check_local_host_package,
            host_commands::local_host_status,
            host_commands::prepare_local_host,
            host_commands::provision_local_host_profile,
            host_commands::cancel_local_host_start,
            host_commands::stop_local_host_manager,
            connect_server,
            restore_connection,
            sign_out,
            open_photos,
            worker_setup_status,
            prepare_models,
            control_worker,
            discover_camera_folders,
            discover_onedrive,
            choose_photo_folder,
            approve_photo_folder,
            import_album::list_photo_import_albums,
            photo_source_status,
            revoke_photo_source,
            photo_import_status,
            prepare_photo_import,
            control_photo_import,
            drop_import::preview_photo_drop,
            drop_import::photo_drop_status,
            drop_import::approve_photo_drop,
            drop_import::control_photo_drop,
            file_manager_import::explorer_import_shortcut,
            manager_commands::manager_view,
            manager_commands::manager_certificate_fingerprint,
            manager_commands::pair_manager,
            manager_commands::manager_request,
            manager_commands::reauthenticate_manager,
            manager_commands::disconnect_manager,
            discovery::discover_servers,
            server_admin::server_summary,
            server_admin::server_ai_processing,
            server_admin::cloud_status,
            server_admin::wallet_status,
            server_admin::update_wallet,
            server_admin::remote_status,
            server_admin::update_remote,
            server_admin::test_remote_access,
            server_admin::open_external,
            tray::tray_refresh,
            cloud_account::cloud_sign_in,
            cloud_account::cloud_account,
            cloud_account::cloud_sign_out,
            cloud_account::cloud_servers,
            server_login::server_sign_in_options,
            server_login::server_oauth_sign_in,
            cloud_account::email::cloud_email_consents,
            cloud_account::email::cloud_email_start,
            cloud_account::email::cloud_email_complete,
            cloud_account::connect_cloud_server
        ])
        .on_webview_event(|webview, event| {
            if webview.label() == "main" {
                if let tauri::WebviewEvent::DragDrop(event) = event {
                    if let Some(window) = webview.app_handle().get_webview_window("main") {
                        drop_import::native_event(&window, event);
                    }
                }
            }
        })
        .on_window_event(|window, event| {
            if window.label() != "main" {
                return;
            }
            let placement = window.state::<window_placement::WindowPlacement>();
            match event {
                tauri::WindowEvent::DragDrop(event) => {
                    if let Some(main) = window.get_webview_window("main") {
                        drop_import::native_event(&main, event);
                    }
                }
                tauri::WindowEvent::Moved(_)
                | tauri::WindowEvent::Resized(_)
                | tauri::WindowEvent::ScaleFactorChanged { .. } => {
                    if let Some(main) = window.get_webview_window("main") {
                        placement.remember(&main);
                    }
                }
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    placement.save(window.app_handle());
                    if cfg!(target_os = "macos")
                        || window.state::<host_setup::HostSetup>().background_active()
                        || window.state::<source_import::SourceJobs>().watching()
                    {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                }
                _ => {}
            }
        })
        .build(tauri::generate_context!())
        .expect("Frameleaf desktop failed to start")
        .run(|app, event| {
            #[cfg(target_os = "macos")]
            if matches!(event, tauri::RunEvent::Reopen { .. }) {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                app.state::<window_placement::WindowPlacement>().save(app);
                if app.state::<host_setup::HostSetup>().background_active() {
                    api.prevent_exit();
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                        let _ = window.emit("native-host-exit-blocked", ());
                    }
                }
            }
        });
}

pub(crate) async fn start_worker_setup(
    app: &tauri::AppHandle,
    saved: &SavedConnection,
    allow_download: bool,
) -> Result<(), String> {
    let preference = worker_control::load(saved)?;
    let control = preference.effective(worker_control::now());
    if control != worker_control::WorkerControl::Running {
        if let worker_control::Preference::Timed { until } = preference {
            tray::schedule_worker_resume(app, worker_control::key(saved)?, until);
        }
        let status = app.state::<worker_setup::WorkerSetup>().hold(control).await;
        publish_worker_status(app, status);
        return Ok(());
    }
    let paths = worker_setup::SetupPaths {
        data: app
            .path()
            .app_local_data_dir()
            .map_err(|_| "app_data_directory_unavailable")?
            .join("worker"),
        bundle: worker_setup::bundled_runtime(
            &app.path()
                .resource_dir()
                .map_err(|_| "app_resources_unavailable")?,
        ),
    };
    let handle = app.clone();
    app.state::<worker_setup::WorkerSetup>()
        .start(
            saved.clone(),
            paths,
            allow_download,
            std::sync::Arc::new(move |status| publish_worker_status(&handle, status)),
        )
        .await;
    Ok(())
}

/// Every worker status the window hears about, the tray hears about too.
pub(crate) fn publish_worker_status(app: &AppHandle, status: worker_setup::SetupStatus) {
    tray::set_worker_status(app, &status);
    let _ = app.emit_to("main", "worker-setup", status);
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
    control: worker_control::WorkerControl,
) -> Result<worker_setup::SetupStatus, String> {
    require_local(&window)?;
    let status = apply_worker_control(&app, control).await?;
    tray::refresh(&app).await;
    Ok(status)
}

/// Pause, stop or resume the worker for the signed-in connection, from the window or the tray.
pub(crate) async fn apply_worker_control(
    app: &AppHandle,
    control: worker_control::WorkerControl,
) -> Result<worker_setup::SetupStatus, String> {
    let state = app.state::<DesktopState>();
    let mut current = state.0.lock().await;
    let saved = current.as_mut().ok_or("sign_in_required")?;
    apply_connected_worker_control(app, saved, control).await
}

pub(crate) async fn apply_connected_worker_control(
    app: &AppHandle,
    saved: &mut SavedConnection,
    control: worker_control::WorkerControl,
) -> Result<worker_setup::SetupStatus, String> {
    let setup = app.state::<worker_setup::WorkerSetup>();
    match control {
        worker_control::WorkerControl::Paused => {
            // Persist first: a pause that cannot be saved would silently resume after a restart.
            worker_control::save(saved, control)?;
            let status = setup.pause();
            tray::set_worker_status(app, &status);
            Ok(status)
        }
        worker_control::WorkerControl::Stopped => {
            // Persist first, as for Pause: a stop that cannot be saved must not stop the worker.
            worker_control::save(saved, control)?;
            let status = setup.hold(control).await;
            tray::set_worker_status(app, &status);
            Ok(status)
        }
        worker_control::WorkerControl::Running => {
            let previous = worker_control::load(saved)?;
            setup.stop().await;
            let client = match transport::client() {
                Ok(client) => client,
                Err(error) => {
                    setup.hold(previous.held()).await;
                    return Err(error);
                }
            };
            // Say why Resume failed: an expired sign-in or an unanswered server must not read as
            // a permissions problem.
            let capabilities = transport::capabilities(&client, saved).await;
            if let Err(error) = &capabilities {
                setup.hold(previous.held()).await;
                return Err(error.clone());
            }
            let view = prepare_with_capabilities(&client, saved, capabilities).await;
            if let Some(error) = resume_refusal(&view.state, view.features.worker_session) {
                setup.hold(previous.held()).await;
                return Err(error);
            }
            if let Err(error) = worker_control::save(saved, control) {
                setup.hold(previous.held()).await;
                return Err(error);
            }
            if let Err(error) = start_worker_setup(app, saved, false).await {
                // Put the saved control back too, so a restart does not resume what failed here.
                let rolled_back = worker_control::save_preference(saved, previous);
                setup.hold(previous.held()).await;
                // If the old setting can't be saved back, say so: a restart would resume the worker.
                return Err(match rolled_back {
                    Ok(()) => error,
                    Err(_) => "worker_control_unsaved".into(),
                });
            }
            Ok(setup.status())
        }
    }
}

/// The error Resume returns when the server did not hand back a worker session, by connection state.
fn resume_refusal(state: &str, worker_session: bool) -> Option<String> {
    match state {
        "preparing" if worker_session => None,
        "preparing" | "unsupported-server" => Some("worker_resume_unsupported_server".into()),
        "awaiting-approval"
        | "enrollment-failed"
        | "worker-setup-failed"
        | "credential-store-unavailable"
        | "identity-changed"
        | "offline" => Some(format!("worker_resume_{}", state.replace('-', "_"))),
        _ => Some("worker_setup_unavailable".into()),
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
async fn discover_camera_folders(
    window: WebviewWindow,
    app: tauri::AppHandle,
) -> Result<Vec<photo_sources::RootHint>, String> {
    require_local(&window)?;
    tauri::async_runtime::spawn_blocking(move || camera_hints(&app))
        .await
        .map_err(|_| "source_discovery_failed")?
}

fn camera_hints(app: &tauri::AppHandle) -> Result<Vec<photo_sources::RootHint>, String> {
    let home = app
        .path()
        .home_dir()
        .map_err(|_| "source_home_unavailable")?;
    Ok(camera_sources::discover(&home))
}

#[tauri::command]
async fn choose_photo_folder(
    window: WebviewWindow,
    app: tauri::AppHandle,
    one_drive: Option<usize>,
    camera: Option<String>,
) -> Result<Option<source_consent::SelectedFolder>, String> {
    use tauri_plugin_dialog::DialogExt;
    require_local(&window)?;
    if one_drive.is_some() && camera.is_some() {
        return Err("source_folder_invalid".into());
    }
    let generation = app.state::<source_consent::SourceConsent>().generation()?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut picker = app.dialog().file().set_title("Choose a photo folder");
        let from_camera = camera.is_some();
        if let Some(index) = one_drive {
            let hints = source_hints(&app)?;
            let hint = hints.get(index).ok_or("source_account_unavailable")?;
            picker = picker.set_directory(&hint.path);
        }
        if let Some(path) = camera {
            let hint = camera_hints(&app)?
                .into_iter()
                .find(|hint| hint.path == path)
                .ok_or("source_camera_unavailable")?;
            picker = picker
                .set_title("Choose photos from camera storage")
                .set_directory(hint.path);
        }
        let Some(folder) = picker.blocking_pick_folder() else {
            return Ok(None);
        };
        let path = folder.into_path().map_err(|_| "source_folder_invalid")?;
        let consent = app.state::<source_consent::SourceConsent>();
        if from_camera {
            consent.select_camera(generation, path)
        } else {
            consent.select(generation, path)
        }
        .map(Some)
    })
    .await
    .map_err(|_| "source_inventory_failed")?
}

#[tauri::command]
async fn photo_source_status(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<Option<source_consent::ConsentView>, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let Some(consent) = credentials::load::<source_consent::Consent>(source_consent::CREDENTIAL)?
    else {
        return Ok(None);
    };
    consent.require(saved, &credentials::identity()?)?;
    Ok(Some(consent.view()))
}
#[tauri::command]
async fn approve_photo_folder(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    selection_id: Option<String>,
    allow_download: bool,
    watch: Option<bool>,
    album: Option<import_album::Destination>,
) -> Result<source_consent::ConsentView, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let identity = credentials::identity()?;
    let mut consent = if let Some(selection) = selection_id {
        if credentials::load::<source_consent::Consent>(source_consent::CREDENTIAL)?.is_some() {
            return Err("source_remove_previous_approval".into());
        }
        let destination = import_album::approve(saved, album).await?;
        app.state::<source_consent::SourceConsent>().approve(
            saved,
            &identity,
            &selection,
            allow_download,
            watch.unwrap_or(false),
            destination,
            |value| credentials::save(source_consent::CREDENTIAL, value),
        )?
    } else {
        if album.is_some() {
            return Err("source_album_selection_changed".into());
        }
        credentials::load::<source_consent::Consent>(source_consent::CREDENTIAL)?
            .ok_or("source_approval_required")?
    };
    consent.register(saved, &identity).await?;
    credentials::save(source_consent::CREDENTIAL, &consent)?;
    if consent.watch && !consent.watch_paused {
        app.state::<source_import::SourceJobs>()
            .start(app.clone(), import_base(&app)?, saved.clone())
            .await?;
    }
    Ok(consent.view())
}
#[tauri::command]
async fn revoke_photo_source(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<bool, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    app.state::<source_import::SourceJobs>().stop().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let consent = credentials::load::<source_consent::Consent>(source_consent::CREDENTIAL);
    // Local authority ends before waiting on the NAS; offline revocation cannot leave it enabled here.
    credentials::delete(source_consent::CREDENTIAL)?;
    tray::set_import_status(&app, None);
    app.state::<source_consent::SourceConsent>().clear()?;
    match consent {
        Ok(Some(consent)) => {
            let Ok(identity) = credentials::identity() else {
                return Ok(false);
            };
            Ok(consent.revoke(saved, &identity).await.is_ok())
        }
        Ok(None) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn import_base(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    let base = app
        .path()
        .app_local_data_dir()
        .map_err(|_| "source_storage_unavailable")?;
    if !base.exists() {
        runtime_store::private_directory(&base)?;
    }
    native_runtime::absolute_directory(&base)?;
    Ok(base)
}
#[tauri::command]
async fn photo_import_status(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<Option<source_import::ImportView>, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    if credentials::load::<source_consent::Consent>(source_consent::CREDENTIAL)?.is_none() {
        return Ok(None);
    }
    app.state::<source_import::SourceJobs>()
        .status(&import_base(&app)?, saved)
}
#[tauri::command]
async fn prepare_photo_import(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<source_import::ImportView, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let status = app
        .state::<source_import::SourceJobs>()
        .prepare(&import_base(&app)?, saved)
        .await?;
    tray::set_import_status(&app, Some(&status));
    Ok(status)
}
#[tauri::command]
async fn control_photo_import(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    action: String,
) -> Result<source_import::ImportView, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let base = import_base(&app)?;
    let status = match action.as_str() {
        "watch-resume" => {
            return app
                .state::<source_import::SourceJobs>()
                .resume_watch(app.clone(), base, saved.clone())
                .await;
        }
        "watch-pause" => {
            app.state::<source_import::SourceJobs>()
                .pause_watch(&base, saved)
                .await
        }
        "resume" => {
            return app
                .state::<source_import::SourceJobs>()
                .start(app.clone(), base, saved.clone())
                .await;
        }
        "approve-upload" => {
            app.state::<source_import::SourceJobs>()
                .approve_upload(&base, saved)
                .await
        }
        "pause" | "cancel" => {
            app.state::<source_import::SourceJobs>()
                .control(&base, saved, action == "cancel")
                .await
        }
        _ => Err("source_control_invalid".into()),
    }?;
    tray::set_import_status(&app, Some(&status));
    Ok(status)
}

#[cfg(test)]
mod resume_tests {
    #[test]
    fn resume_names_why_the_server_refused() {
        assert_eq!(super::resume_refusal("preparing", true), None);
        assert_eq!(
            super::resume_refusal("preparing", false).as_deref(),
            Some("worker_resume_unsupported_server")
        );
        assert_eq!(
            super::resume_refusal("awaiting-approval", true).as_deref(),
            Some("worker_resume_awaiting_approval")
        );
        assert_eq!(
            super::resume_refusal("worker-setup-failed", true).as_deref(),
            Some("worker_resume_worker_setup_failed")
        );
        assert_eq!(
            super::resume_refusal("paused", true).as_deref(),
            Some("worker_setup_unavailable")
        );
    }
}
