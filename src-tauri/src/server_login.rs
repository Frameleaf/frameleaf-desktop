//! How one can sign in to a server at an address, before any credential is sent: its ping
//! (identity, linked, setup) and its public config (password login, its own OAuth, Sign in with
//! Frameleaf). The same lookup the mobile apps make (Android `ServerLookup`, iOS `ServerLoginOptions`).
use crate::connection::{is_local_network, normalize_server};
use crate::transport;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tauri::WebviewWindow;
use url::Url;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Deserialize)]
struct Ping {
    res: String,
    id: String,
    #[serde(default)]
    linked: bool,
    #[serde(default)]
    name: String,
    #[serde(default)]
    setup: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct PublicConfig {
    password_login: Option<Enabled>,
    oauth: Option<OAuth>,
    frameleaf: Option<FrameleafConfig>,
    server: Option<ServerConfig>,
}
#[derive(Deserialize)]
struct Enabled {
    enabled: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OAuth {
    enabled: bool,
    #[serde(default)]
    button_text: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FrameleafConfig {
    sign_in_available: bool,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ServerConfig {
    name: String,
    login_page_message: String,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignInOptions {
    pub server: String,
    pub id: String,
    pub name: String,
    pub linked: bool,
    pub local: bool,
    pub needs_setup: bool,
    pub password_login: bool,
    pub frameleaf_sign_in: bool,
    pub oauth: bool,
    pub oauth_button_text: String,
    pub login_message: Option<String>,
}

fn options(base: &Url, ping: Ping, config: Option<PublicConfig>) -> Result<SignInOptions, String> {
    if ping.res != "pong" || ping.id.is_empty() || ping.id.len() > 128 {
        return Err("server_not_frameleaf".into());
    }
    let config = config.unwrap_or_default();
    let server = config.server.unwrap_or_default();
    let name = [server.name.trim(), ping.name.trim()]
        .into_iter()
        .find(|name| !name.is_empty())
        .or(base.host_str())
        .unwrap_or_default()
        .chars()
        .take(128)
        .collect();
    let message = server
        .login_page_message
        .trim()
        .chars()
        .take(1000)
        .collect::<String>();
    Ok(SignInOptions {
        server: base.to_string(),
        local: base.host().is_some_and(is_local_network),
        // A linked server is joined with Sign in with Frameleaf, never set up again.
        needs_setup: !ping.linked && ping.setup == "needed",
        // An older server without these fields still takes a password; a linked one also Frameleaf.
        password_login: config.password_login.is_none_or(|value| value.enabled),
        frameleaf_sign_in: config
            .frameleaf
            .map_or(ping.linked, |value| value.sign_in_available)
            && ping.linked,
        oauth: config.oauth.as_ref().is_some_and(|value| value.enabled),
        oauth_button_text: config
            .oauth
            .map(|value| value.button_text.trim().chars().take(64).collect())
            .unwrap_or_default(),
        login_message: (!message.is_empty()).then_some(message),
        id: ping.id,
        name,
        linked: ping.linked,
    })
}

async fn get<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    base: &Url,
    path: &str,
) -> Result<T, String> {
    let url = base.join(path).map_err(|_| "server_address_invalid")?;
    tokio::time::timeout(LOOKUP_TIMEOUT, async {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|_| "server_unreachable_or_certificate_invalid")?;
        transport::json(response).await
    })
    .await
    .map_err(|_| "server_unreachable_or_certificate_invalid")?
}

/// The ways to sign in to the server at `server`. Nothing secret is sent.
#[tauri::command]
pub(crate) async fn server_sign_in_options(
    window: WebviewWindow,
    server: String,
) -> Result<SignInOptions, String> {
    crate::require_local(&window)?;
    // The one place an address is typed: every later step is given the origin this returns.
    let base = crate::connection::typed_server(&server)?;
    let client = transport::client()?;
    let ping: Ping = get(&client, &base, "api/server/ping")
        .await
        .map_err(|code| {
            if code.starts_with("server_http_") || code == "server_response_invalid" {
                "server_not_frameleaf".into()
            } else {
                code
            }
        })?;
    // The ping proves who answered; a missing or older config only narrows to the defaults.
    let config = get(&client, &base, "api/public/config").await.ok();
    options(&base, ping, config)
}

/// The callback the identity provider sends back: the server's own web login page, which the
/// administrator already registered with the provider for browser sign-in.
fn oauth_redirect(base: &Url) -> Result<Url, String> {
    base.join("auth/login")
        .map_err(|_| "server_address_invalid".into())
}

/// Whether `url` is the provider coming back to this server's login page.
fn is_oauth_return(base: &Url, url: &Url) -> bool {
    url.origin() == base.origin() && url.path().trim_end_matches('/') == "/auth/login"
}

/// What came back: the full callback for `/api/oauth/callback`, or why there is none.
fn oauth_outcome(callback: &Url, state: &str) -> Result<(), String> {
    let mut code = None;
    let mut returned = None;
    let mut error = None;
    for (key, value) in callback.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => returned = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }
    match error.as_deref() {
        Some("access_denied") => return Err("server_oauth_cancelled".into()),
        Some(_) => return Err("server_oauth_failed".into()),
        None => {}
    }
    if returned.as_deref() != Some(state) || code.is_none_or(|code| code.is_empty()) {
        return Err("server_oauth_failed".into());
    }
    Ok(())
}

/// Where the provider's page may be opened from: https, or plain http only on this network.
fn provider_page_allowed(url: &Url) -> bool {
    url.username().is_empty()
        && url.password().is_none()
        && match url.scheme() {
            "https" => url.host().is_some(),
            "http" => url.host().is_some_and(is_local_network),
            _ => false,
        }
}

/// Signs in with the server's own OAuth provider (its "Sign in with …" button). The provider's
/// page opens in a private window of this app with no access to the app; when the provider sends
/// the person back to the server's login page, that address is handed to the server instead.
#[tauri::command]
pub(crate) async fn server_oauth_sign_in(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::DesktopState>,
    server: String,
    device_name: String,
) -> Result<crate::connection::ConnectionView, String> {
    use tauri::Manager;
    crate::require_local(&window)?;
    let base = normalize_server(&server)?;
    let ready = |current: &Option<crate::connection::SavedConnection>| -> Result<(), String> {
        if app
            .state::<crate::host_setup::HostSetup>()
            .background_active()
        {
            return Err("local_host_active".into());
        }
        if current.is_some()
            || crate::credentials::load::<crate::connection::SavedConnection>("connection")?
                .is_some()
        {
            return Err("sign_out_before_switching_servers".into());
        }
        Ok(())
    };
    ready(&*state.0.lock().await)?;
    // Check secure persistence and the device identity before the provider is opened.
    let identity = crate::credentials::foreground_identity(&window)?;
    identity.enrollment("validation", "validation", &device_name, "client-worker")?;
    let client = transport::client()?;

    let verifier = zeroize::Zeroizing::new(crate::cloud_account::random_token(48));
    let oauth_state = crate::cloud_account::random_token(24);
    let redirect = oauth_redirect(&base)?;
    #[derive(Deserialize)]
    struct Authorize {
        url: String,
    }
    let response = client
        .post(
            base.join("api/oauth/authorize")
                .map_err(|_| "server_address_invalid")?,
        )
        .json(&serde_json::json!({
            "redirectUri": redirect.as_str(),
            "state": oauth_state,
            "codeChallenge": crate::cloud_account::pkce_challenge(&verifier),
        }))
        .send()
        .await
        .map_err(|_| "server_unreachable_or_certificate_invalid")?;
    if response.status() == reqwest::StatusCode::BAD_REQUEST {
        return Err("server_oauth_unavailable".into());
    }
    let authorize: Authorize = transport::json(response).await?;
    let page = Url::parse(&authorize.url).map_err(|_| "server_oauth_failed")?;
    if !provider_page_allowed(&page) {
        return Err("server_oauth_failed".into());
    }

    let callback = provider_window(&app, &base, page).await?;
    oauth_outcome(&callback, &oauth_state)?;
    let login = oauth_session(&client, &base, &callback, &oauth_state, &verifier).await?;

    let mut current = state.0.lock().await;
    ready(&current)?;
    let (saved, mut view) = crate::keep_login(&client, &base, login, &device_name, |saved| {
        crate::credentials::confirm_new_sign_in("connection", saved, &window)
    })
    .await?;
    if view.state == "preparing"
        && view.features.worker_session
        && crate::start_worker_setup(&app, &saved, false)
            .await
            .is_err()
    {
        view.state = "worker-setup-failed".into();
    }
    *current = Some(saved);
    drop(current);
    crate::tray::refresh(&app).await;
    Ok(view)
}

/// Hands the provider's callback to the server for a session. The session is declared as one
/// that can answer `verification_required`, like the Password sign-in; a server older than
/// unified sign-in ignores that and answers as it always did.
async fn oauth_session(
    client: &reqwest::Client,
    base: &Url,
    callback: &Url,
    state: &str,
    verifier: &str,
) -> Result<crate::LoginResponse, String> {
    let response = client
        .post(
            base.join("api/oauth/callback")
                .map_err(|_| "server_address_invalid")?,
        )
        .json(&serde_json::json!({
            "url": callback.as_str(),
            "state": state,
            "codeVerifier": verifier,
            "rememberMe": true,
            "capabilities": crate::server_steps::CAPABILITIES,
        }))
        .send()
        .await
        .map_err(|_| "server_unreachable_or_certificate_invalid")?;
    if matches!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::UNAUTHORIZED
    ) {
        return Err("server_oauth_failed".into());
    }
    transport::json(response).await
}

const PROVIDER_WINDOW: &str = "server-sign-in";
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(600);

/// Opens the provider's page and waits for it to send the person back to the server's login page.
async fn provider_window(app: &tauri::AppHandle, base: &Url, page: Url) -> Result<Url, String> {
    use tauri::Manager;
    if let Some(open) = app.get_webview_window(PROVIDER_WINDOW) {
        let _ = open.destroy();
    }
    let (sender, mut receiver) =
        tokio::sync::mpsc::unbounded_channel::<Result<Url, &'static str>>();
    let returned = sender.clone();
    let server = base.clone();
    let opened =
        tauri::WebviewWindowBuilder::new(app, PROVIDER_WINDOW, tauri::WebviewUrl::External(page))
            .title("Sign in")
            .inner_size(520.0, 720.0)
            // Nothing the provider stores outlives this sign-in, and nothing of the person's other sign-ins is in it.
            .incognito(true)
            .on_navigation(move |url| {
                if is_oauth_return(&server, url) {
                    let _ = returned.send(Ok(url.clone()));
                    return false;
                }
                // The provider's pages only: https anywhere, plain http only on this network. A blocked
                // page ends the sign-in with an error rather than leaving a stuck window.
                let allowed = provider_page_allowed(url);
                if !allowed {
                    let _ = returned.send(Err("server_oauth_failed"));
                }
                allowed
            })
            .build()
            .map_err(|_| "server_oauth_failed")?;
    opened.on_window_event(move |event| {
        if matches!(event, tauri::WindowEvent::Destroyed) {
            let _ = sender.send(Err("server_oauth_cancelled"));
        }
    });
    let outcome = tokio::time::timeout(PROVIDER_TIMEOUT, receiver.recv()).await;
    let _ = opened.destroy();
    match outcome {
        Ok(Some(Ok(callback))) => Ok(callback),
        Ok(Some(Err(code))) => Err(code.into()),
        Ok(None) => Err("server_oauth_cancelled".into()),
        Err(_) => Err("server_oauth_failed".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ping(linked: bool, setup: &str) -> Ping {
        Ping {
            res: "pong".into(),
            id: "inst-1".into(),
            linked,
            name: "Home Server".into(),
            setup: setup.into(),
        }
    }
    fn config(json: &str) -> Option<PublicConfig> {
        Some(serde_json::from_str(json).unwrap())
    }

    #[test]
    fn a_linked_server_offers_frameleaf_and_its_own_login() {
        let base = Url::parse("http://192.168.1.20:2283/").unwrap();
        let found = options(
            &base,
            ping(true, "complete"),
            config(r#"{"passwordLogin":{"enabled":true},"oauth":{"enabled":false,"buttonText":""},
                "frameleaf":{"signInAvailable":true},"server":{"name":"Tower","loginPageMessage":" "}}"#),
        )
        .unwrap();
        assert!(found.frameleaf_sign_in && found.password_login && !found.oauth);
        assert!(found.local && !found.needs_setup);
        assert_eq!(found.name, "Tower");
        assert_eq!(found.login_message, None);
    }

    #[test]
    fn an_unlinked_server_never_offers_frameleaf_even_if_config_claims_it() {
        let base = Url::parse("https://photos.example.com/").unwrap();
        let found = options(
            &base,
            ping(false, "complete"),
            config(r#"{"passwordLogin":{"enabled":false},"oauth":{"enabled":true,"buttonText":"Sign in with Authentik"},
                "frameleaf":{"signInAvailable":true}}"#),
        )
        .unwrap();
        assert!(!found.frameleaf_sign_in && !found.password_login && found.oauth && !found.local);
        assert_eq!(found.oauth_button_text, "Sign in with Authentik");
        assert_eq!(found.name, "Home Server");
    }

    #[test]
    fn a_missing_config_keeps_password_and_follows_the_ping() {
        let base = Url::parse("http://tower.local/").unwrap();
        let found = options(&base, ping(true, "needed"), None).unwrap();
        assert!(found.password_login && found.frameleaf_sign_in && !found.needs_setup);
        let unlinked = options(&base, ping(false, "needed"), None).unwrap();
        assert!(unlinked.needs_setup && !unlinked.frameleaf_sign_in);
    }

    #[test]
    fn a_non_frameleaf_answer_is_refused() {
        let base = Url::parse("https://photos.example.com/").unwrap();
        let mut answer = ping(false, "complete");
        answer.res = "ok".into();
        assert_eq!(
            options(&base, answer, None).unwrap_err(),
            "server_not_frameleaf"
        );
    }

    #[test]
    fn the_provider_comes_back_only_to_this_servers_login_page() {
        let base = Url::parse("https://photos.example.com/").unwrap();
        let back = |u: &str| is_oauth_return(&base, &Url::parse(u).unwrap());
        assert_eq!(
            oauth_redirect(&base).unwrap().as_str(),
            "https://photos.example.com/auth/login"
        );
        assert!(back("https://photos.example.com/auth/login?code=1&state=s"));
        assert!(!back("https://photos.example.com/auth/logins?code=1"));
        assert!(!back("https://evil.example.com/auth/login?code=1"));
        assert!(!back("http://photos.example.com/auth/login?code=1"));
    }

    #[test]
    fn a_callback_needs_its_state_and_a_code() {
        let url = |q: &str| Url::parse(&format!("https://p.example/auth/login?{q}")).unwrap();
        assert!(oauth_outcome(&url("code=abc&state=s1"), "s1").is_ok());
        assert_eq!(
            oauth_outcome(&url("code=abc&state=s2"), "s1").unwrap_err(),
            "server_oauth_failed"
        );
        assert_eq!(
            oauth_outcome(&url("state=s1"), "s1").unwrap_err(),
            "server_oauth_failed"
        );
        assert_eq!(
            oauth_outcome(&url("error=access_denied&state=s1"), "s1").unwrap_err(),
            "server_oauth_cancelled"
        );
        assert_eq!(
            oauth_outcome(&url("error=server_error&state=s1"), "s1").unwrap_err(),
            "server_oauth_failed"
        );
    }

    #[test]
    fn the_provider_page_is_https_or_on_this_network() {
        let ok = |u: &str| provider_page_allowed(&Url::parse(u).unwrap());
        assert!(ok("https://auth.example.com/authorize?x=1"));
        assert!(ok("http://192.168.1.5:9000/authorize"));
        assert!(!ok("http://auth.example.com/authorize"));
        assert!(!ok("https://user:pw@auth.example.com/"));
        assert!(!ok("javascript:alert(1)"));
    }
}

#[cfg(test)]
mod oauth_session_tests {
    use super::*;
    use crate::server_steps::fixture::{client, server};
    use serde_json::json;

    #[tokio::test]
    async fn the_callback_declares_the_capability_and_any_server_signs_in() {
        // The fixture is a plain-http server on this computer; an older server ignores the field.
        let (base, seen) = server(|request| match request.path.as_str() {
            "/api/oauth/callback" => (
                200,
                json!({"accessToken": "session", "userId": "user", "name": "Ada"}),
            ),
            _ => (404, json!({})),
        });
        let callback = base.join("auth/login?code=c0de&state=st").unwrap();
        let login = oauth_session(&client(), &base, &callback, "st", "verifier")
            .await
            .unwrap();
        assert_eq!(login.access_token, "session");
        assert_eq!(
            seen.lock().unwrap()[0].body,
            json!({
                "url": callback.as_str(), "state": "st", "codeVerifier": "verifier",
                "rememberMe": true, "capabilities": ["verification"],
            })
        );
    }

    #[tokio::test]
    async fn a_refused_callback_is_a_failed_sign_in() {
        for (status, expected) in [
            (400, "server_oauth_failed"),
            (401, "server_oauth_failed"),
            (500, "server_http_500"),
        ] {
            let (base, _) = server(move |_| (status, json!({"message": "private"})));
            let callback = base.join("auth/login?code=c0de&state=st").unwrap();
            let refused = oauth_session(&client(), &base, &callback, "st", "verifier").await;
            assert_eq!(refused.err().unwrap(), expected);
        }
    }
}
