pub mod connection;
mod credentials;
pub mod lifecycle;
pub mod ml_transport;
pub mod model_catalogue;
pub mod native_predictor;
pub mod native_runtime;
mod process_tree;
pub mod release_policy;
pub mod runtime_store;
mod transport;
pub mod worker;

use connection::{normalize_server, ConnectionView, Features, SavedConnection};
use serde::Deserialize;
use tauri::{Manager, State, WebviewUrl, WebviewWindow};
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
    match transport::capabilities(&client, saved).await {
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
            match transport::enroll(&client, saved).await {
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
                        let issued = transport::issue_worker_session(&client, saved).await;
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
    let base = normalize_server(&server)?;
    let password = Zeroizing::new(password);
    if email.is_empty() || email.len() > 320 || password.is_empty() || password.len() > 4096 {
        return Err("login_details_invalid".into());
    }
    // Check secure persistence and the device identity before sending a password.
    let identity = credentials::identity()?;
    identity.enrollment("validation", "validation", &device_name, "client-worker")?;
    let client = transport::client()?;
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
        device_name,
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
    let view = prepare(&mut saved).await;
    *current = Some(saved);
    Ok(view)
}

#[tauri::command]
async fn restore_connection(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<Option<ConnectionView>, String> {
    require_local(&window)?;
    let mut current = state.0.lock().await;
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
    let view = prepare(&mut saved).await;
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
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .manage(DesktopState::default())
        .invoke_handler(tauri::generate_handler![
            connect_server,
            restore_connection,
            sign_out,
            open_photos
        ])
        .run(tauri::generate_context!())
        .expect("Frameleaf desktop failed to start");
}
