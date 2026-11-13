mod accelerated_pack;
mod camera_identity;
mod camera_sources;
pub mod cloud_account;
pub mod connection;
pub mod copy_source;
pub mod copy_upload;
mod credential_lock;
#[cfg(any(not(target_os = "macos"), test))]
mod credential_parts;
mod credentials;
mod discovery;
mod drop_import;
mod file_manager_import;
mod host_carry;
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
mod macos_quit;
pub mod manager;
mod manager_commands;
pub mod manager_host;
mod manager_local;
mod manager_profile;
pub mod manager_tls;
mod media_copy;
pub mod ml_transport;
mod model_cache;
pub mod model_catalogue;
pub mod native_predictor;
pub mod native_runtime;
mod offline_albums;
mod package_lease;
mod photo_session;
pub mod photo_sources;
mod process_tree;
#[cfg(any(target_os = "linux", test))]
mod profile_elevation;
mod provider_selection;
mod reconnect;
pub mod release_policy;
mod resource_policy;
pub mod runtime_epochs;
pub mod runtime_store;
mod saved_sign_in;
mod server_admin;
mod server_identity;
mod server_login;
mod server_steps;
mod source_consent;
mod source_import;
mod source_metadata;
mod transport;
mod tray;
mod updates;
mod upload_budget;
mod upload_parts;
mod window_close;
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

/// `keep_worker_session`: this is a check of the connection in use and its worker is running.
/// Answers the view, and whether that worker's session was kept instead of a new one issued.
async fn prepare(saved: &mut SavedConnection, keep_worker_session: bool) -> (ConnectionView, bool) {
    let unavailable = Features {
        enrollment: false,
        worker: false,
        worker_session: false,
        sources: false,
        native_host: false,
    };
    let client = match transport::client() {
        Ok(c) => c,
        Err(_) => {
            return (
                ConnectionView::new(saved, "offline".into(), unavailable),
                false,
            )
        }
    };
    let capabilities = transport::capabilities(&client, saved).await;
    prepare_checked(&client, saved, capabilities, keep_worker_session).await
}

/// Whether a connection check may leave the running worker's session in place: it is the session
/// of this server, account and device, has proofs left and has not expired. A session that is
/// missing or can't be read is not known to be valid, so a new one is issued, as before.
fn worker_session_reusable(
    saved: &SavedConnection,
    worker: &Result<Option<worker::SavedWorker>, String>,
    now: time::OffsetDateTime,
) -> bool {
    let Ok(Some(worker)) = worker else {
        return false;
    };
    let Ok(expires) = time::OffsetDateTime::parse(
        &worker.expires_at,
        &time::format_description::well_known::Rfc3339,
    ) else {
        return false;
    };
    worker.server_id == saved.server_id
        && worker.account_id == saved.account_id
        && Some(&worker.device_id) == saved.device_id.as_ref()
        && (1..=2_147_483_647).contains(&worker.next_sequence)
        // The worker renews its own session; one about to lapse is replaced now instead.
        && expires > now + time::Duration::minutes(1)
}

#[cfg(test)]
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
    prepare_checked(client, saved, capabilities, false).await.0
}

async fn prepare_checked(
    client: &reqwest::Client,
    saved: &mut SavedConnection,
    capabilities: Result<Option<connection::Capabilities>, String>,
    keep_worker_session: bool,
) -> (ConnectionView, bool) {
    let mut kept = false;
    let view = prepare_view(client, saved, capabilities, keep_worker_session, &mut kept).await;
    (view, kept)
}

async fn prepare_view(
    client: &reqwest::Client,
    saved: &mut SavedConnection,
    capabilities: Result<Option<connection::Capabilities>, String>,
    keep_worker_session: bool,
    kept: &mut bool,
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
                    // A check of the connection in use keeps the running worker's own session
                    // while it is still valid: a new one would only restart the worker.
                    *kept = keep_worker_session
                        && caps.features.worker_session
                        && enrollment.state == "preparing"
                        && worker_session_reusable(
                            saved,
                            &credentials::load("worker-session"),
                            time::OffsetDateTime::now_utc(),
                        );
                    if caps.features.worker_session && enrollment.state == "preparing" && !*kept {
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
) -> Result<SignInOutcome, String> {
    let step = SignInStep::Password {
        email: &email,
        password: Zeroizing::new(password),
    };
    connect_with(window, app, state, &server, step, &device_name).await
}

/// The second step of `connect_server`: one proof for the transaction it returned.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn connect_server_step(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    server: String,
    transaction: String,
    method: String,
    proof: String,
    device_name: String,
) -> Result<SignInOutcome, String> {
    let step = SignInStep::Proof {
        transaction: Zeroizing::new(transaction),
        method: &method,
        proof: Zeroizing::new(proof),
    };
    connect_with(window, app, state, &server, step, &device_name).await
}

/// What a sign-in command answers: the connection, or the step that would complete the sign-in.
#[derive(serde::Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub(crate) enum SignInOutcome {
    Done {
        connection: ConnectionView,
    },
    #[serde(rename_all = "camelCase")]
    Next {
        transaction: String,
        methods: Vec<String>,
        sent_to: Option<String>,
        /// Sign in with Frameleaf only: the address of the server that asked for the step.
        #[serde(skip_serializing_if = "Option::is_none")]
        server: Option<String>,
    },
}

/// What one sign-in call sends: the password, or a proof for the step the password opened.
enum SignInStep<'a> {
    Password {
        email: &'a str,
        password: Zeroizing<String>,
    },
    Proof {
        transaction: Zeroizing<String>,
        method: &'a str,
        proof: Zeroizing<String>,
    },
}

pub(crate) enum SignIn {
    Done(Box<SavedConnection>, ConnectionView),
    Next(server_steps::Pending),
}

async fn connect_with(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    server: &str,
    step: SignInStep<'_>,
    device_name: &str,
) -> Result<SignInOutcome, String> {
    require_local(&window)?;
    let mut current = state.0.lock().await;
    if app.state::<host_setup::HostSetup>().background_active() {
        return Err("local_host_active".into());
    }
    if current.is_some() || credentials::load::<SavedConnection>("connection")?.is_some() {
        return Err("sign_out_before_switching_servers".into());
    }
    let client = transport::client()?;
    let signed_in = sign_in_step(
        &client,
        server,
        step,
        device_name,
        || credentials::foreground_identity(&window),
        |saved| credentials::confirm_new_sign_in("connection", saved, &window),
    )
    .await?;
    let (saved, mut view) = match signed_in {
        SignIn::Done(saved, view) => (*saved, view),
        SignIn::Next(pending) => {
            return Ok(SignInOutcome::Next {
                transaction: pending.transaction.as_str().to_owned(),
                methods: pending.methods,
                sent_to: pending.sent_to,
                server: None,
            })
        }
    };
    if view.state == "preparing"
        && view.features.worker_session
        && start_worker_setup(&app, &saved, false).await.is_err()
    {
        view.state = "worker-setup-failed".into();
    }
    *current = Some(saved);
    drop(current);
    tray::refresh(&app).await;
    Ok(SignInOutcome::Done { connection: view })
}

/// The password step alone, as the sign-in fixtures call it.
#[cfg(test)]
async fn sign_in(
    client: &reqwest::Client,
    server: &str,
    email: &str,
    password: String,
    device_name: &str,
    identity: impl FnOnce() -> Result<connection::DeviceIdentity, String>,
    confirm: impl FnOnce(&SavedConnection) -> Result<(), String>,
) -> Result<SignIn, String> {
    let password = Zeroizing::new(password);
    let step = SignInStep::Password { email, password };
    sign_in_step(client, server, step, device_name, identity, confirm).await
}

async fn sign_in_step(
    client: &reqwest::Client,
    server: &str,
    step: SignInStep<'_>,
    device_name: &str,
    identity: impl FnOnce() -> Result<connection::DeviceIdentity, String>,
    confirm: impl FnOnce(&SavedConnection) -> Result<(), String>,
) -> Result<SignIn, String> {
    let base = normalize_server(server)?;
    if let SignInStep::Password { email, password } = &step {
        let email = email.trim();
        if email.is_empty() || email.len() > 320 || password.is_empty() || password.len() > 4096 {
            return Err("login_details_invalid".into());
        }
    }
    // Check secure persistence and the device identity before sending a password or a code.
    let identity = identity()?;
    identity.enrollment("validation", "validation", device_name, "client-worker")?;
    let answer = match &step {
        SignInStep::Password { email, password } => {
            server_steps::password(client, &base, email.trim(), password).await?
        }
        SignInStep::Proof {
            transaction,
            method,
            proof,
        } => server_steps::proof(client, &base, transaction, method, proof).await?,
    };
    match answer {
        server_steps::Step::Done(login) => keep_login(client, &base, login, device_name, confirm)
            .await
            .map(|(saved, view)| SignIn::Done(Box::new(saved), view)),
        server_steps::Step::Next(pending) => Ok(SignIn::Next(pending)),
    }
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
    let result = if saved.server_id.is_empty() {
        // The server did not say which server it is, so there is nothing a restart could check
        // this sign-in against. It is not saved; the session just minted is ended below.
        Err("server_sign_in_retry_required".into())
    } else {
        match credentials::save("connection", saved) {
            Err(error) => Err(error),
            Ok(()) => match confirm(saved) {
                Ok(()) => return Ok(prepare_with_capabilities(client, saved, capabilities).await),
                // A changed item may belong to another writer. Revoke our minted token only.
                Err(error) if error == "credential_confirmation_changed" => Err(error),
                Err(error)
                    if matches!(
                        error.as_str(),
                        "credential_unlock_required" | "credential_confirmation_unavailable"
                    ) =>
                {
                    return Err(error)
                }
                Err(_) => credentials::delete("connection")
                    .and(Err("server_sign_in_retry_required".into())),
            },
        }
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
) -> Result<Option<ConnectionView>, String> {
    require_local(&window)?;
    let result = restore_saved(&app, Some(&window), retry.unwrap_or(false)).await;
    // A server that did not answer is tried again from here, with backoff, window shown or not.
    app.state::<reconnect::Reconnect>()
        .after_restore(&app, &result);
    result
}

/// Restores the saved sign-in and resumes its worker and folder watch. `window`: the window that
/// asked, which may be prompted to unlock the credential store; the backend's own reconnect
/// attempts have none and never prompt.
pub(crate) async fn restore_saved(
    app: &AppHandle,
    window: Option<&WebviewWindow>,
    retry: bool,
) -> Result<Option<ConnectionView>, String> {
    let state = app.state::<DesktopState>();
    let mut current = state.0.lock().await;
    if app.state::<host_setup::HostSetup>().background_active() {
        app.state::<media_copy::MediaCopy>().cancel();
        return Ok(None);
    }
    let loaded = match window {
        Some(window) => {
            credentials::load_interactive::<SavedConnection>("connection", window, retry)
        }
        None => credentials::load::<SavedConnection>("connection"),
    };
    let Some(mut saved) = loaded? else {
        // The saved sign-in is gone: drop any connection still held so the window and the
        // background agree.
        stop_connection_work(app).await;
        let held = current.take().is_some();
        app.state::<offline_albums::OfflineAlbums>()
            .clear(app)
            .await;
        drop(current);
        if held {
            tray::refresh(app).await;
        }
        return Ok(None);
    };
    // Restoring the connection already in use is only a check: it must not interrupt its work.
    let checking = current
        .as_ref()
        .is_some_and(|held| saved_sign_in::same_session(held, &saved));
    let plan = saved_sign_in::check(&transport::client()?, &saved)
        .await
        .plan();
    if !checking || plan.stop_work {
        stop_connection_work(app).await;
    }
    if plan.purge_albums {
        app.state::<offline_albums::OfflineAlbums>()
            .clear(app)
            .await;
    }
    plan.resume_work?;
    if let Some(window) = window.filter(|_| retry) {
        credentials::unlock_existing_identity(window)?;
    }
    let setup = app.state::<worker_setup::WorkerSetup>();
    let (mut view, worker_kept) = prepare(&mut saved, checking && setup.running().await).await;
    // A sign-in saved before its server was identified learns and saves the identity in
    // `prepare`, from the server its session was just checked against. Until then it is not used.
    saved_sign_in::identified(&saved)?;
    if view.state == "identity-changed" {
        app.state::<offline_albums::OfflineAlbums>()
            .clear(app)
            .await;
    }
    if view.state == "preparing" && view.features.worker_session {
        // Starting replaces a running worker with one that holds the session just issued. A
        // check that kept the session leaves the worker alone, unless it ended meanwhile.
        if !(worker_kept && setup.running().await)
            && start_worker_setup(app, &saved, false).await.is_err()
        {
            view.state = "worker-setup-failed".into();
        }
    } else if checking && !matches!(view.state.as_str(), "offline" | "enrollment-failed") {
        // The server answered that this computer has no AI work now; a lost reply says nothing.
        app.state::<worker_setup::WorkerSetup>().stop().await;
    }
    let jobs = app.state::<source_import::SourceJobs>();
    if !(checking && (jobs.watching() || jobs.copying())) {
        if let Ok(Some(consent)) =
            credentials::load::<source_consent::Consent>(source_consent::CREDENTIAL)
        {
            if consent.watch && consent.registered && !consent.watch_paused {
                if let Ok(base) = import_base(app) {
                    let _ = jobs.start(app.clone(), base, saved.clone()).await;
                }
            }
        }
    }
    *current = Some(saved);
    drop(current);
    tray::refresh(app).await;
    Ok(Some(view))
}

/// Ends the imports, media copy and worker that belong to a connection no longer in use.
async fn stop_connection_work(app: &AppHandle) {
    app.state::<media_copy::MediaCopy>().cancel();
    app.state::<source_import::SourceJobs>().stop().await;
    app.state::<drop_import::DropImport>()
        .reset_for_restore()
        .await;
    app.state::<worker_setup::WorkerSetup>().stop().await;
}

#[tauri::command]
async fn sign_out(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<lifecycle::SignOutResult, String> {
    require_local(&window)?;
    app.state::<reconnect::Reconnect>().cancel();
    let mut current = state.0.lock().await;
    app.state::<media_copy::MediaCopy>().cancel();
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
    let offline = app
        .state::<offline_albums::OfflineAlbums>()
        .clear(&app)
        .await;
    // Written down before the sign-in goes, so a crash from here on still wipes the Photos data.
    photo_session::mark(&app);
    // The saved sign-in is removed while the connection is still locked: a restore waiting on the
    // lock would otherwise find it, sign in again and leave a live session behind a signed-out
    // window. Every sign-in saves under this lock too, so nothing can bring it back in between.
    let local = {
        let worker = credentials::delete("worker-session").is_ok();
        let connection = credentials::delete("connection").is_ok();
        let sources = credentials::delete(source_consent::CREDENTIAL).is_ok();
        let drops = credentials::delete(drop_import::CREDENTIAL).is_ok();
        worker && connection && sources && drops && offline
    };
    drop(current);
    tray::refresh(&app).await;
    Ok(lifecycle::finish_sign_out(
        async { local },
        async {
            // The Photos session lives in the web data store, not in its window: it is wiped
            // through the window that asked, with the Photos window open or closed.
            let closed = app
                .get_webview_window("photos")
                .is_none_or(|photos| photos.close().is_ok());
            let cleared = photo_session::clear(&app, &window);
            cleared && closed
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
        if photos.url().is_ok_and(|url| url.origin() == base.origin()) {
            photos.show().map_err(|_| "photo_window_unavailable")?;
            photos.set_focus().map_err(|_| "photo_window_unavailable")?;
            return Ok(());
        }
    }
    // An earlier sign-out that could not wipe its Photos data is made good before a new session.
    photo_session::clear_if_owed(app);
    let photos = photo_window(app, &base, base.clone())?;
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
    photos.show().map_err(|_| "photo_window_unavailable")?;
    photos.set_focus().map_err(|_| "photo_window_unavailable")?;
    Ok(())
}

pub(crate) fn photo_window(
    app: &AppHandle,
    base: &url::Url,
    initial: url::Url,
) -> Result<WebviewWindow, String> {
    if connection::native_origin_allowed("main", base, cfg!(debug_assertions)) {
        return Err("photo_window_unavailable".into());
    }
    if let Some(window) = app.get_webview_window("photos") {
        return Ok(window);
    }
    let origin = base.origin();
    let web_origin = serde_json::to_string(&origin.ascii_serialization())
        .map_err(|_| "photo_window_unavailable")?;
    let handle = app.clone();
    tauri::WebviewWindowBuilder::new(app, "photos", WebviewUrl::External(initial))
        .title("Frameleaf Photos")
        .inner_size(1280.0, 850.0)
        .initialization_script(format!("if (window.top === window && location.origin === {web_origin}) window.__FRAMELEAF_DESKTOP_OFFLINE_ALBUMS__ = true;"))
        .on_navigation(move |url| {
            offline_albums::local_url(url)
                || (url.origin() == origin && !offline_albums::intercept(&handle, url))
        })
        .build()
        .map_err(|_| "photo_window_unavailable".into())
}

pub fn run() {
    tauri::Builder::default()
        .register_asynchronous_uri_scheme_protocol("offline-media", offline_albums::serve)
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
        .manage(offline_albums::OfflineAlbums::default())
        .manage(host_setup::HostSetup::default())
        .manage(worker_setup::WorkerSetup::default())
        .manage(accelerated_pack::AcceleratedPack::default())
        .manage(source_consent::SourceConsent::default())
        .manage(source_import::SourceJobs::default())
        .manage(source_import::ImportTransfer::default())
        .manage(drop_import::DropImport::default())
        .manage(media_copy::MediaCopy::default())
        .manage(tray::TrayState::default())
        .manage(cloud_account::email::EmailAttempt::default())
        .manage(cloud_account::ServerStep::default())
        .manage(reconnect::Reconnect::default())
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                let placement = app.state::<window_placement::WindowPlacement>();
                placement.restore(&window);
                let _ = window.show();
                placement.remember(&window);
            }
            // A sign-out that was cut short before it wiped the Photos data finishes here.
            photo_session::clear_if_owed(app.handle());
            file_manager_import::setup(app.handle());
            // A desktop without a tray (some Linux sessions) still gets the window.
            if let Err(error) = tray::build(app.handle()) {
                eprintln!("tray unavailable: {error}");
            }
            updates::observe_restart(app.handle());
            #[cfg(target_os = "macos")]
            if let Err(error) = window_close::guard_app_quit(app.handle()) {
                eprintln!("app menu unavailable: {error}");
            }
            // Dock Quit and a logout, restart or shutdown go through the exit guard too.
            #[cfg(target_os = "macos")]
            if let Err(error) = macos_quit::install(app.handle()) {
                eprintln!("quit guard unavailable: {error}");
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
            host_commands::local_host_carry_status,
            host_commands::carry_local_host_library,
            host_commands::confirm_local_host_carry,
            host_commands::cancel_local_host_start,
            host_commands::stop_local_host_manager,
            host_commands::quit_local_host,
            connect_server,
            connect_server_step,
            restore_connection,
            sign_out,
            open_photos,
            offline_albums::open_offline_photos,
            offline_albums::offline_album_status,
            offline_albums::offline_album_original,
            offline_albums::offline_album_save_original,
            offline_albums::offline_album_close_media,
            offline_albums::offline_album_remove,
            offline_albums::offline_album_cancel,
            offline_albums::offline_album_browse_library,
            worker_setup_status,
            accelerated_pack_status,
            download_accelerated_pack,
            decline_accelerated_pack,
            cancel_accelerated_pack_download,
            retry_accelerated_provider,
            prepare_models,
            control_worker,
            discover_camera_folders,
            reconnect_photo_camera,
            discover_onedrive,
            media_copy::preservation_copy_packages,
            media_copy::save_preservation_copy,
            media_copy::cancel_preservation_copy,
            choose_photo_folder,
            approve_photo_folder,
            import_album::list_photo_import_albums,
            photo_source_status,
            revoke_photo_source,
            photo_import_status,
            source_import::history::photo_import_history,
            source_import::history::retry_photo_import,
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
            server_admin::server_step_up,
            server_admin::saved_sign_in_verification,
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
            cloud_account::connect_cloud_server,
            cloud_account::connect_cloud_server_step
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
                    if window_close::on_close_requested(window) {
                        api.prevent_close();
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
            // Windows ends a session by exiting this app without asking first.
            #[cfg(windows)]
            if matches!(event, tauri::RunEvent::Exit) {
                host_commands::session_ending(app);
            }
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                app.state::<window_placement::WindowPlacement>().save(app);
                if app.state::<media_copy::MediaCopy>().is_active() {
                    api.prevent_exit();
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                        let _ = window.emit("tray-action-failed", "media_copy_exit_blocked");
                    }
                } else if app.state::<host_setup::HostSetup>().background_active() {
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

fn worker_paths(app: &tauri::AppHandle) -> Result<worker_setup::SetupPaths, String> {
    Ok(worker_setup::SetupPaths {
        app_version: app.package_info().version.to_string(),
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
    })
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
    let paths = worker_paths(app)?;
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

/// FD-60: the GPU runtime pack this computer could download, and where that download stands.
#[tauri::command]
async fn accelerated_pack_status(
    window: WebviewWindow,
    app: tauri::AppHandle,
) -> Result<accelerated_pack::PackStatus, String> {
    require_local(&window)?;
    let paths = worker_paths(&app)?;
    let mut status = app.state::<accelerated_pack::AcceleratedPack>().status(
        &paths.bundle,
        &paths.data,
        &provider_selection::Host,
    );
    if status.state == "available" {
        status.metered = tauri::async_runtime::spawn_blocking(resource_policy::sample)
            .await
            .is_ok_and(|network| network.unmetered == Some(false));
    }
    Ok(status)
}

/// The person chose Download: nothing else ever starts this transfer. The worker is restarted
/// once the pack is ready, so it is installed and qualified without reopening the app.
#[tauri::command]
async fn download_accelerated_pack(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<accelerated_pack::PackStatus, String> {
    require_local(&window)?;
    let paths = worker_paths(&app)?;
    let handle = app.clone();
    let status = app
        .state::<accelerated_pack::AcceleratedPack>()
        .download(paths.bundle, paths.data, move |status| {
            let _ = handle.emit_to("main", "accelerated-pack", status);
        })
        .await?;
    if status.state == "ready" {
        restart_running_worker(&app, &state).await;
    }
    Ok(status)
}

#[tauri::command]
async fn decline_accelerated_pack(
    window: WebviewWindow,
    app: tauri::AppHandle,
) -> Result<accelerated_pack::PackStatus, String> {
    require_local(&window)?;
    let paths = worker_paths(&app)?;
    Ok(app.state::<accelerated_pack::AcceleratedPack>().decline(
        &paths.bundle,
        &paths.data,
        &provider_selection::Host,
    ))
}

#[tauri::command]
async fn cancel_accelerated_pack_download(
    window: WebviewWindow,
    app: tauri::AppHandle,
) -> Result<(), String> {
    require_local(&window)?;
    app.state::<accelerated_pack::AcceleratedPack>().cancel();
    Ok(())
}

/// Try the GPU again after it failed its check or measured slower: forget what was remembered
/// about this runtime and let the worker qualify it again.
#[tauri::command]
async fn retry_accelerated_provider(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<(), String> {
    require_local(&window)?;
    let paths = worker_paths(&app)?;
    provider_selection::forget(&paths.data);
    restart_running_worker(&app, &state).await;
    Ok(())
}

/// Start the worker again when it is running, so a change to its runtimes takes effect. A worker
/// the person paused or stopped stays as they left it.
async fn restart_running_worker(app: &tauri::AppHandle, state: &State<'_, DesktopState>) {
    let setup = app.state::<worker_setup::WorkerSetup>();
    if setup.status().control != worker_control::WorkerControl::Running || !setup.running().await {
        return;
    }
    let current = state.0.lock().await;
    if let Some(saved) = current
        .as_ref()
        .filter(|saved| saved.mode == "client-worker" && saved.device_id.is_some())
    {
        let _ = start_worker_setup(app, saved, false).await;
    }
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
async fn reconnect_photo_camera(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<Option<source_import::ImportView>, String> {
    use tauri_plugin_dialog::DialogExt;
    require_local(&window)?;
    let (source_id, original) = {
        let current = state.0.lock().await;
        let saved = current.as_ref().ok_or("sign_in_required")?;
        let consent = credentials::load::<source_consent::Consent>(source_consent::CREDENTIAL)?
            .ok_or("source_approval_required")?;
        let identity = credentials::identity()?;
        let approval = consent.approval(saved, &identity)?;
        if !consent.camera() || approval.media().is_none() {
            return Err("source_camera_identity_unavailable".into());
        }
        (
            consent.source_id().to_string(),
            approval.root().to_path_buf(),
        )
    };
    let picker_app = app.clone();
    let selected = tauri::async_runtime::spawn_blocking(move || {
        let mut picker = picker_app
            .dialog()
            .file()
            .set_title("Choose the same camera folder to resume");
        if original.is_dir() {
            picker = picker.set_directory(original);
        }
        picker
            .blocking_pick_folder()
            .map(|folder| folder.into_path().map_err(|_| "source_folder_invalid"))
            .transpose()
    })
    .await
    .map_err(|_| "source_inventory_failed")??;
    let Some(path) = selected else {
        return Ok(None);
    };
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let base = import_base(&app)?;
    let jobs = app.state::<source_import::SourceJobs>();
    jobs.reconnect_camera(base.clone(), saved.clone(), source_id, path)
        .await?;
    jobs.start(app.clone(), base, saved.clone()).await.map(Some)
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
    if let Ok(base) = import_base(&app) {
        source_import::history::retire(&base, saved, &app.state::<source_import::SourceJobs>());
    }
    // Local authority ends before waiting on the NAS; offline revocation cannot leave it enabled here.
    credentials::delete(source_consent::CREDENTIAL)?;
    let _ = app.emit_to("main", "photo-import-history", ());
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
    // The inventory scan of a large folder must not hold the connection lock.
    let current = state.0.lock().await.clone();
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let status = app
        .state::<source_import::SourceJobs>()
        .prepare(&import_base(&app)?, saved)
        .await?;
    tray::set_import_status(&app, Some(&status));
    let _ = app.emit_to("main", "photo-import-history", ());
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
    let _ = app.emit_to("main", "photo-import-history", ());
    Ok(status)
}

#[cfg(test)]
mod session_tests;

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

#[cfg(test)]
mod worker_session_tests {
    use super::*;
    use time::{format_description::well_known::Rfc3339, OffsetDateTime};

    fn saved() -> SavedConnection {
        SavedConnection {
            server: "http://192.168.1.20:2283/".into(),
            server_id: "server".into(),
            account_id: "account".into(),
            name: "Ada".into(),
            token: "session".into(),
            device_name: "Desk".into(),
            mode: "client-worker".into(),
            device_id: Some("device".into()),
        }
    }
    fn worker() -> worker::SavedWorker {
        worker::SavedWorker {
            server_id: "server".into(),
            account_id: "account".into(),
            device_id: "device".into(),
            session_id: "worker-session".into(),
            authorization_epoch: 1,
            worker_token: "token".into(),
            expires_at: "2026-11-12T11:00:00Z".into(),
            next_sequence: 7,
        }
    }

    #[test]
    fn a_connection_check_keeps_a_valid_worker_session() {
        let now = OffsetDateTime::parse("2026-11-12T10:00:00Z", &Rfc3339).unwrap();
        assert!(worker_session_reusable(&saved(), &Ok(Some(worker())), now));
    }

    #[test]
    fn a_session_that_is_not_known_to_be_valid_is_replaced() {
        let now = OffsetDateTime::parse("2026-11-12T10:00:00Z", &Rfc3339).unwrap();
        let reusable = |change: fn(&mut worker::SavedWorker, &mut SavedConnection)| {
            let (mut worker, mut saved) = (worker(), saved());
            change(&mut worker, &mut saved);
            worker_session_reusable(&saved, &Ok(Some(worker)), now)
        };
        // Expired, or about to; an expiry that can't be read says nothing.
        assert!(!reusable(
            |worker, _| worker.expires_at = "2020-01-01T00:00:00Z".into()
        ));
        assert!(!reusable(|worker, _| worker.expires_at = "soon".into()));
        // Another server, account or device, or one this computer is no longer enrolled as.
        assert!(!reusable(|worker, _| worker.server_id = "other".into()));
        assert!(!reusable(|worker, _| worker.account_id = "other".into()));
        assert!(!reusable(|worker, _| worker.device_id = "other".into()));
        assert!(!reusable(|_, saved| saved.device_id = None));
        // No proofs left.
        assert!(!reusable(|worker, _| worker.next_sequence = 0));
        // Missing or unreadable: unknown, so a new session is issued.
        assert!(!worker_session_reusable(&saved(), &Ok(None), now));
        assert!(!worker_session_reusable(
            &saved(),
            &Err("credential_store_unavailable".into()),
            now
        ));
        let lapsing = {
            let mut worker = worker();
            worker.expires_at = "2026-11-12T10:00:20Z".into();
            worker
        };
        assert!(!worker_session_reusable(&saved(), &Ok(Some(lapsing)), now));
    }
}
