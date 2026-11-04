//! A Frameleaf Cloud account on this computer (docs/native-apps.md, FC-85/FC-86 with the
//! `frameleaf-desktop` client): an authorization-code + PKCE sign-in through the system browser
//! and a loopback redirect, the account's servers, and a server session minted by RFC 8693 token
//! exchange instead of a second password.

use crate::connection::{normalize_server, ConnectionView, SavedConnection};
use crate::{credentials, transport};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State, WebviewWindow};
use url::Url;
use zeroize::ZeroizeOnDrop;

pub(crate) const CLIENT_ID: &str = "frameleaf-desktop";
pub(crate) const SCOPE: &str = "openid email profile offline_access account";
const CLOUD_ORIGIN: &str = "https://api.frameleaf.cloud";
const CREDENTIAL: &str = "cloud-account";
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const ID_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";
/// How long the browser may take to come back to the loopback listener.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);
/// How long one candidate address may take to answer the ping.
const PROBE_TIMEOUT: Duration = Duration::from_secs(6);
/// An access token this close to expiry is refreshed first.
const REFRESH_MARGIN: u64 = 60;
const CLOUD_LIMIT: usize = 256 * 1024;

#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CloudCredential {
    pub cloud_url: String,
    pub issuer: String,
    pub api: String,
    pub refresh_token: String,
    pub access_token: String,
    /// Unix seconds.
    pub expires_at: u64,
}

#[derive(Clone, Serialize, Debug, PartialEq)]
pub(crate) struct CloudAccount {
    pub email: String,
    pub name: String,
}

#[derive(Clone, Serialize, Debug, PartialEq)]
pub(crate) struct CloudConnection {
    pub kind: String,
    pub uri: String,
    pub verified: bool,
}

#[derive(Clone, Serialize, Debug, PartialEq)]
pub(crate) struct CloudServer {
    pub instance_id: String,
    pub name: String,
    pub version: String,
    pub status: String,
    pub role: String,
    pub presence: String,
    pub last_seen_at: Option<String>,
    pub connections: Vec<CloudConnection>,
    pub remote_entitled: bool,
}

/// One entry of the cloud's `Connection` contract, the fields this app reads.
#[derive(Clone, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Candidate {
    pub kind: String,
    pub uri: String,
    #[serde(default)]
    pub custom: bool,
    #[serde(default)]
    pub verified: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstanceSummary {
    instance_id: String,
    name: String,
    #[serde(default)]
    version: String,
    status: String,
    role: String,
    #[serde(default)]
    presence: Option<String>,
    #[serde(default)]
    last_seen_at: Option<String>,
    #[serde(default)]
    connections: Vec<Candidate>,
    #[serde(default)]
    remote_access: Option<RemoteEntitlement>,
}
#[derive(Deserialize)]
struct RemoteEntitlement {
    #[serde(default)]
    entitled: bool,
}

/// The cloud's two origins: the identity provider (sign-in, tokens, the account's servers) and the
/// API (the `resource` of the app token, discovery).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CloudHosts {
    pub issuer: Url,
    pub api: Url,
}

fn origin(url: &Url) -> Url {
    let mut origin = url.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    origin
}

/// Cloud discovery requires a bare HTTPS origin, except for local development servers.
pub(crate) fn parse_cloud_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value.trim()).map_err(|_| "cloud_address_invalid")?;
    let host = url.host_str().ok_or("cloud_address_invalid")?;
    let local = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    if !(url.scheme() == "https" || (url.scheme() == "http" && local))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err("cloud_address_invalid".into());
    }
    Ok(origin(&url))
}

/// The hosts derived from the cloud address alone: `api.frameleaf.cloud` has its issuer on
/// `id.frameleaf.cloud`; any other cloud serves both from the one address.
pub(crate) fn derive_hosts(cloud: &Url) -> CloudHosts {
    let host = cloud.host_str().unwrap_or_default().to_ascii_lowercase();
    let issuer = host
        .strip_prefix("api.")
        .filter(|rest| *rest == "frameleaf.cloud" || rest.ends_with(".frameleaf.cloud"))
        .and_then(|rest| {
            let mut issuer = cloud.clone();
            issuer.set_host(Some(&format!("id.{rest}"))).ok()?;
            Some(issuer)
        })
        .unwrap_or_else(|| cloud.clone());
    CloudHosts {
        issuer: origin(&issuer),
        api: origin(cloud),
    }
}

/// The server's own rule for an address the cloud hands over (`cloudAddressProblem`): the
/// configured host or a subdomain of it, or (on `frameleaf.cloud` only) a sibling under that
/// domain, the same scheme rule and port, no credentials.
pub(crate) fn cloud_address_allowed(configured: &Url, candidate: &Url) -> bool {
    let (Some(host), Some(other)) = (configured.host_str(), candidate.host_str()) else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let other = other.to_ascii_lowercase();
    if candidate.scheme() != "https"
        && !(configured.scheme() == "http" && candidate.scheme() == "http")
    {
        return false;
    }
    let domain = host
        .strip_suffix(".frameleaf.cloud")
        .map(|_| "frameleaf.cloud");
    let on_cloud = other == host
        || other.ends_with(&format!(".{host}"))
        || domain.is_some_and(|domain| other == domain || other.ends_with(&format!(".{domain}")));
    on_cloud
        && candidate.port_or_known_default() == configured.port_or_known_default()
        && candidate.username().is_empty()
        && candidate.password().is_none()
}

/// The hosts, with the cloud's own services document applied when it names acceptable ones.
pub(crate) fn hosts_from_discovery(cloud: &Url, document: Option<&Value>) -> CloudHosts {
    let mut hosts = derive_hosts(cloud);
    let Some(document) = document else {
        return hosts;
    };
    let named = |key: &str| {
        document
            .get(key)?
            .as_str()
            .and_then(|value| Url::parse(value).ok())
            .filter(|url| cloud_address_allowed(cloud, url))
            .map(|url| origin(&url))
    };
    if let Some(issuer) = named("issuer") {
        hosts.issuer = issuer;
    }
    if let Some(api) = named("api") {
        hosts.api = api;
    }
    hosts
}

async fn discover_hosts(client: &Client, cloud: &Url) -> CloudHosts {
    let document = match cloud.join(".well-known/frameleaf-services") {
        Ok(url) => match client.get(url).send().await {
            Ok(response) => transport::json_limit::<Value>(response, CLOUD_LIMIT)
                .await
                .ok(),
            Err(_) => None,
        },
        Err(_) => None,
    };
    hosts_from_discovery(cloud, document.as_ref())
}

fn random_token(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buffer);
    URL_SAFE_NO_PAD.encode(buffer)
}

/// PKCE (RFC 7636): the verifier stays here, S256 of it goes to the browser.
pub(crate) fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub(crate) fn authorize_url(
    hosts: &CloudHosts,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
) -> Result<Url, String> {
    let mut url = hosts
        .issuer
        .join("authorize")
        .map_err(|_| "cloud_address_invalid")?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", SCOPE)
        .append_pair("resource", hosts.api.as_str().trim_end_matches('/'))
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state)
        .append_pair("prompt", "consent");
    Ok(url)
}

/// What one request to the loopback listener means.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Callback {
    /// Not the redirect (a favicon, a stray tab): answer and keep waiting.
    Ignored,
    /// The redirect, with the authorization code.
    Code(String),
    /// The redirect refusing the sign-in, or one that does not belong to this attempt.
    Refused(String),
}

pub(crate) fn parse_callback(target: &str, expected_state: &str) -> Callback {
    let Ok(url) = Url::parse("http://127.0.0.1").and_then(|base| base.join(target)) else {
        return Callback::Ignored;
    };
    if url.host_str() != Some("127.0.0.1") || url.path() != "/callback" {
        return Callback::Ignored;
    }
    let mut code = None;
    let mut error = None;
    let mut state = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            _ => {}
        }
    }
    if state.as_deref() != Some(expected_state) {
        return Callback::Refused("cloud_sign_in_state_mismatch".into());
    }
    if let Some(error) = error {
        let safe: String = error
            .chars()
            .take(40)
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        return Callback::Refused(format!("cloud_sign_in_{safe}"));
    }
    match code {
        Some(code) if !code.is_empty() && code.len() <= 2048 => Callback::Code(code),
        _ => Callback::Refused("cloud_sign_in_invalid".into()),
    }
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn page(title: &str, text: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title><style>body{{font:15px -apple-system,\"Segoe UI\",system-ui,sans-serif;background:#101416;color:#e5e7eb;display:grid;place-items:center;height:100vh;margin:0}}main{{text-align:center;max-width:28em;padding:24px}}h1{{font-size:18px;margin:0 0 8px}}p{{color:#a1adb8;margin:0}}</style></head><body><main><h1>{title}</h1><p>{text}</p></main></body></html>"
    )
}

/// One request's target (`GET /callback?… HTTP/1.1`), read with a bound and a read timeout.
fn request_target(stream: &mut TcpStream) -> Option<String> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let mut request = Vec::new();
    let mut byte = [0u8];
    while !request.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => request.push(byte[0]),
            _ => return None,
        }
        if request.len() > 8192 {
            return None;
        }
        if request.ends_with(b"\r\n") && !request.contains(&b'\n') {
            break;
        }
    }
    let line = request.split(|b| *b == b'\n').next()?;
    let line = String::from_utf8_lossy(line);
    let mut parts = line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    parts.next().map(str::to_owned)
}

/// Waits for the browser to come back with the code, answering what else arrives on the port.
fn wait_for_callback(
    listener: TcpListener,
    expected_state: &str,
    deadline: Instant,
) -> Result<String, String> {
    listener
        .set_nonblocking(true)
        .map_err(|_| "cloud_sign_in_listener_unavailable")?;
    loop {
        if Instant::now() >= deadline {
            return Err("cloud_sign_in_timed_out".into());
        }
        let (mut stream, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(_) => return Err("cloud_sign_in_listener_unavailable".into()),
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let _ = stream.set_nonblocking(false);
        let Some(target) = request_target(&mut stream) else {
            respond(
                &mut stream,
                "400 Bad Request",
                &page("Frameleaf", "That request was not understood."),
            );
            continue;
        };
        match parse_callback(&target, expected_state) {
            Callback::Ignored => respond(
                &mut stream,
                "404 Not Found",
                &page("Frameleaf", "Nothing here."),
            ),
            Callback::Code(code) => {
                respond(
                    &mut stream,
                    "200 OK",
                    &page(
                        "Signed in to Frameleaf",
                        "You can close this window and go back to Frameleaf Desktop.",
                    ),
                );
                return Ok(code);
            }
            Callback::Refused(reason) => {
                respond(
                    &mut stream,
                    "400 Bad Request",
                    &page(
                        "Sign-in not completed",
                        "Go back to Frameleaf Desktop and try again.",
                    ),
                );
                if reason != "cloud_sign_in_state_mismatch" {
                    return Err(reason);
                }
            }
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
}
#[derive(Deserialize)]
struct TokenError {
    error: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `POST {issuer}/token`; a refusal names the OAuth error (`cloud_token_invalid_grant`).
async fn token_request(
    client: &Client,
    issuer: &Url,
    form: &[(&str, &str)],
) -> Result<TokenResponse, String> {
    let url = issuer.join("token").map_err(|_| "cloud_address_invalid")?;
    let response = client
        .post(url)
        .form(form)
        .send()
        .await
        .map_err(|_| "cloud_unreachable")?;
    let status = response.status();
    if status.is_success() {
        return transport::json_limit(response, CLOUD_LIMIT).await;
    }
    let body = response.bytes().await.unwrap_or_default();
    let error = (body.len() <= 65_536)
        .then(|| serde_json::from_slice::<TokenError>(&body).ok())
        .flatten()
        .map(|e| e.error)
        .filter(|e| {
            !e.is_empty()
                && e.len() <= 64
                && e.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
    Err(match error {
        Some(error) => format!("cloud_token_{error}"),
        None => format!("cloud_http_{}", status.as_u16()),
    })
}

fn store(credential: &CloudCredential) -> Result<(), String> {
    credentials::save(CREDENTIAL, credential)
}

/// A usable app access token, refreshed (and the rotated refresh token saved) when it is about to
/// expire. A refresh the cloud refuses ends the sign-in here.
async fn access_token(client: &Client, credential: &mut CloudCredential) -> Result<String, String> {
    if credential.expires_at > now() + REFRESH_MARGIN && !credential.access_token.is_empty() {
        return Ok(credential.access_token.clone());
    }
    let issuer = Url::parse(&credential.issuer).map_err(|_| "cloud_address_invalid")?;
    let refreshed = token_request(
        client,
        &issuer,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", credential.refresh_token.as_str()),
            ("client_id", CLIENT_ID),
        ],
    )
    .await;
    let token = match refreshed {
        Ok(token) => token,
        Err(code) if code == "cloud_token_invalid_grant" => {
            let _ = credentials::delete(CREDENTIAL);
            return Err("cloud_sign_in_required".into());
        }
        Err(code) => return Err(code),
    };
    credential.access_token = token.access_token.clone();
    credential.expires_at = now() + token.expires_in.unwrap_or(600);
    if let Some(refresh) = token.refresh_token {
        credential.refresh_token = refresh;
    }
    store(credential)?;
    Ok(token.access_token)
}

async fn cloud_get(client: &Client, base: &Url, path: &str, token: &str) -> Result<Value, String> {
    let url = base.join(path).map_err(|_| "cloud_address_invalid")?;
    let response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| "cloud_unreachable")?;
    match response.status().as_u16() {
        401 => Err("cloud_sign_in_required".into()),
        _ => transport::json_limit(response, CLOUD_LIMIT).await,
    }
}

async fn profile(
    client: &Client,
    credential: &CloudCredential,
    token: &str,
) -> Result<CloudAccount, String> {
    let issuer = Url::parse(&credential.issuer).map_err(|_| "cloud_address_invalid")?;
    let value = cloud_get(client, &issuer, "v1/account/app-profile", token).await?;
    let email = value
        .get("email")
        .and_then(Value::as_str)
        .ok_or("cloud_response_invalid")?
        .to_string();
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| email.clone());
    Ok(CloudAccount { email, name })
}

/// Held from loading the credential through its refresh and save, and through sign-out's delete,
/// so a refresh in flight can never write back a credential sign-out removed (nor two refreshes
/// spend the same rotating refresh token).
static LIFECYCLE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The stored credential with a usable access token, or `None` when signed out.
async fn current(
    client: &Client,
    prompt: Option<(&WebviewWindow, bool)>,
) -> Result<Option<(CloudCredential, String)>, String> {
    let _held = LIFECYCLE.lock().await;
    let credential = if let Some((window, retry)) = prompt {
        credentials::load_interactive(CREDENTIAL, window, retry)?
    } else {
        load()?
    };
    let Some(mut credential) = credential else {
        return Ok(None);
    };
    let token = access_token(client, &mut credential).await?;
    Ok(Some((credential, token)))
}

fn load() -> Result<Option<CloudCredential>, String> {
    credentials::load::<CloudCredential>(CREDENTIAL)
}

#[tauri::command]
pub(crate) async fn cloud_sign_in(
    window: WebviewWindow,
    app: tauri::AppHandle,
) -> Result<CloudAccount, String> {
    use tauri_plugin_opener::OpenerExt;
    crate::require_local(&window)?;
    let cloud = parse_cloud_url(CLOUD_ORIGIN)?;
    // The credential store must work before the browser opens; nothing to keep is worth a round trip.
    if load()?.is_some() {
        return Err("cloud_sign_out_before_switching_accounts".into());
    }
    let client = transport::client()?;
    let hosts = discover_hosts(&client, &cloud).await;
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|_| "cloud_sign_in_listener_unavailable")?;
    let port = listener
        .local_addr()
        .map_err(|_| "cloud_sign_in_listener_unavailable")?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let verifier = random_token(48);
    let state = random_token(24);
    let url = authorize_url(&hosts, &redirect_uri, &state, &pkce_challenge(&verifier))?;
    app.opener()
        .open_url(url.as_str(), None::<&str>)
        .map_err(|_| "external_open_failed")?;
    let expected = state.clone();
    let code = tauri::async_runtime::spawn_blocking(move || {
        wait_for_callback(listener, &expected, Instant::now() + CALLBACK_TIMEOUT)
    })
    .await
    .map_err(|_| "cloud_sign_in_failed")??;
    let token = token_request(
        &client,
        &hosts.issuer,
        &[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", CLIENT_ID),
            ("code_verifier", verifier.as_str()),
        ],
    )
    .await?;
    let refresh_token = token
        .refresh_token
        .ok_or("cloud_sign_in_no_refresh_token")?;
    let credential = CloudCredential {
        cloud_url: cloud.to_string(),
        issuer: hosts.issuer.to_string(),
        api: hosts.api.to_string(),
        refresh_token,
        access_token: token.access_token.clone(),
        expires_at: now() + token.expires_in.unwrap_or(600),
    };
    store(&credential)?;
    credentials::confirm_new_sign_in(CREDENTIAL, &credential, &window)?;
    match profile(&client, &credential, &token.access_token).await {
        Ok(account) => Ok(account),
        Err(error) => {
            let _ = revoke(&client, &credential).await;
            let _ = credentials::delete(CREDENTIAL);
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) async fn cloud_account(
    window: WebviewWindow,
    retry: Option<bool>,
) -> Result<Option<CloudAccount>, String> {
    crate::require_local(&window)?;
    let client = transport::client()?;
    let (credential, token) = match current(&client, Some((&window, retry.unwrap_or(false)))).await
    {
        Ok(Some(found)) => found,
        Ok(None) => return Ok(None),
        Err(code) if code == "cloud_sign_in_required" => return Ok(None),
        Err(code) => return Err(code),
    };
    match profile(&client, &credential, &token).await {
        Ok(account) => Ok(Some(account)),
        Err(code) if code == "cloud_sign_in_required" => {
            credentials::delete(CREDENTIAL)?;
            Ok(None)
        }
        Err(code) => Err(code),
    }
}

async fn revoke(client: &Client, credential: &CloudCredential) -> Result<(), String> {
    let issuer = Url::parse(&credential.issuer).map_err(|_| "cloud_address_invalid")?;
    let url = issuer
        .join("token/revocation")
        .map_err(|_| "cloud_address_invalid")?;
    client
        .post(url)
        .form(&[
            ("token", credential.refresh_token.as_str()),
            ("token_type_hint", "refresh_token"),
            ("client_id", CLIENT_ID),
        ])
        .send()
        .await
        .map_err(|_| "cloud_unreachable")?;
    Ok(())
}

#[tauri::command]
pub(crate) async fn cloud_sign_out(window: WebviewWindow) -> Result<(), String> {
    crate::require_local(&window)?;
    let credential = {
        let _held = LIFECYCLE.lock().await;
        let Some(credential) = credentials::load_interactive(CREDENTIAL, &window, true)? else {
            return Ok(());
        };
        // Local authority ends first; the cloud is told best-effort.
        credentials::delete(CREDENTIAL)?;
        credential
    };
    if let Ok(client) = transport::client() {
        let _ = revoke(&client, &credential).await;
    }
    Ok(())
}

fn to_server(summary: InstanceSummary) -> CloudServer {
    CloudServer {
        instance_id: summary.instance_id,
        name: summary.name,
        version: summary.version,
        status: summary.status,
        role: summary.role,
        presence: summary.presence.unwrap_or_else(|| "offline".into()),
        last_seen_at: summary.last_seen_at,
        connections: summary
            .connections
            .into_iter()
            .map(|c| CloudConnection {
                kind: c.kind,
                uri: c.uri,
                verified: c.verified,
            })
            .collect(),
        remote_entitled: summary.remote_access.is_some_and(|r| r.entitled),
    }
}

/// `GET /v1/instances` answers a list; a wrapping object is read the same way.
pub(crate) fn parse_instances(value: Value) -> Result<Vec<CloudServer>, String> {
    let items = match value {
        Value::Array(items) => items,
        Value::Object(mut object) => match object.remove("instances") {
            Some(Value::Array(items)) => items,
            _ => return Err("cloud_response_invalid".into()),
        },
        _ => return Err("cloud_response_invalid".into()),
    };
    Ok(items
        .into_iter()
        .filter_map(|item| serde_json::from_value::<InstanceSummary>(item).ok())
        .map(to_server)
        .collect())
}

async fn signed_in(client: &Client) -> Result<(CloudCredential, String), String> {
    current(client, None)
        .await?
        .ok_or_else(|| "cloud_sign_in_required".into())
}

#[tauri::command]
pub(crate) async fn cloud_servers(window: WebviewWindow) -> Result<Vec<CloudServer>, String> {
    crate::require_local(&window)?;
    let client = transport::client()?;
    let (credential, token) = signed_in(&client).await?;
    let issuer = Url::parse(&credential.issuer).map_err(|_| "cloud_address_invalid")?;
    parse_instances(cloud_get(&client, &issuer, "v1/instances", &token).await?)
}

fn rank(candidate: &Candidate) -> u8 {
    match (candidate.kind.as_str(), candidate.custom) {
        ("local", _) => 0,
        ("wan", false) => 1,
        ("ipv6", _) => 2,
        ("wan", true) => 3,
        ("relay", _) => 4,
        _ => 5,
    }
}

/// The candidates this app can use (https, or http on the local network), in the order to prefer them: local, wan,
/// ipv6, custom hostname, relay; the cloud's own order within a kind.
pub(crate) fn order_candidates(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut usable: Vec<Candidate> = Vec::new();
    for candidate in candidates {
        let Ok(base) = normalize_server(&candidate.uri) else {
            continue;
        };
        let candidate = Candidate {
            uri: base.to_string(),
            ..candidate
        };
        if !usable.iter().any(|known| known.uri == candidate.uri) {
            usable.push(candidate);
        }
    }
    usable.sort_by_key(|candidate| (rank(candidate), !candidate.uri.starts_with("https://")));
    usable
}

/// The first candidate, in preference order, whose probe answered for this server.
pub(crate) fn select_candidate<'a>(
    ordered: &'a [Candidate],
    results: &[(String, Result<String, String>)],
    instance_id: &str,
) -> Option<&'a Candidate> {
    ordered.iter().find(|candidate| {
        results
            .iter()
            .any(|(uri, result)| uri == &candidate.uri && result.as_deref() == Ok(instance_id))
    })
}

#[derive(Deserialize)]
struct Ping {
    id: String,
}

/// `GET /api/server/ping` on one candidate: the id it answers with.
async fn probe(client: Client, base: Url) -> Result<String, String> {
    let url = base
        .join("api/server/ping")
        .map_err(|_| "server_address_invalid")?;
    let ping: Ping = tokio::time::timeout(PROBE_TIMEOUT, async {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|_| "server_unreachable_or_certificate_invalid")?;
        transport::json(response).await
    })
    .await
    .map_err(|_| "server_unreachable_or_certificate_invalid")??;
    Ok(ping.id)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeResponse {
    access_token: Option<String>,
    user_id: Option<String>,
    name: Option<String>,
}

#[tauri::command]
pub(crate) async fn connect_cloud_server(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, crate::DesktopState>,
    instance_id: String,
    device_name: String,
) -> Result<ConnectionView, String> {
    crate::require_local(&window)?;
    let instance = uuid::Uuid::parse_str(instance_id.trim())
        .map_err(|_| "cloud_server_invalid")?
        .to_string();
    let mut current = state.0.lock().await;
    if app
        .state::<crate::host_setup::HostSetup>()
        .background_active()
    {
        return Err("local_host_active".into());
    }
    if current.is_some() || credentials::load::<SavedConnection>("connection")?.is_some() {
        return Err("sign_out_before_switching_servers".into());
    }
    // Check secure persistence and the device identity before any token is minted.
    let identity = credentials::identity()?;
    identity.enrollment("validation", "validation", &device_name, "client-worker")?;
    let client = transport::client()?;
    let (credential, app_token) = signed_in(&client).await?;
    let issuer = Url::parse(&credential.issuer).map_err(|_| "cloud_address_invalid")?;

    // 1. Where the server answers: every usable candidate is asked at once, the best one wins.
    let listed = cloud_get(
        &client,
        &issuer,
        &format!("v1/instances/{instance}/connections"),
        &app_token,
    )
    .await?;
    let candidates: Vec<Candidate> = listed
        .get("connections")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .ok_or("cloud_response_invalid")?;
    let ordered = order_candidates(candidates);
    if ordered.is_empty() {
        return Err("cloud_server_has_no_https_address".into());
    }
    let probes: Vec<_> = ordered
        .iter()
        .map(|candidate| {
            let uri = candidate.uri.clone();
            let base = normalize_server(&uri);
            let client = client.clone();
            tauri::async_runtime::spawn(async move {
                let result = match base {
                    Ok(base) => probe(client, base).await,
                    Err(error) => Err(error),
                };
                (uri, result)
            })
        })
        .collect();
    let mut results = Vec::new();
    for handle in probes {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }
    let chosen =
        select_candidate(&ordered, &results, &instance).ok_or("cloud_server_unreachable")?;
    let base = normalize_server(&chosen.uri)?;

    // 2. A 120-second server-audience token, minted only now that the server is known to answer.
    let exchange = token_request(
        &client,
        &issuer,
        &[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("client_id", CLIENT_ID),
            ("subject_token", app_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("audience", instance.as_str()),
            ("requested_token_type", ID_TOKEN_TYPE),
        ],
    )
    .await
    .map_err(|code| code.replacen("cloud_token_", "cloud_exchange_", 1))?;

    // 3. The server turns it into a session of its own.
    let response = client
        .post(base.join("api/oauth/frameleaf/exchange").unwrap())
        .json(&serde_json::json!({ "token": exchange.access_token, "rememberMe": true }))
        .send()
        .await
        .map_err(|_| "server_unreachable_or_certificate_invalid")?;
    let status = response.status();
    if !status.is_success() {
        let body = response.bytes().await.unwrap_or_default();
        let code = (body.len() <= 65_536)
            .then(|| serde_json::from_slice::<Value>(&body).ok())
            .flatten()
            .and_then(|value| value.get("code")?.as_str().map(str::to_owned));
        return Err(crate::server_admin::refusal(
            status.as_u16(),
            code.as_deref(),
        ));
    }
    let login: ExchangeResponse = transport::json(response).await?;
    let (Some(token), Some(account_id)) = (login.access_token, login.user_id) else {
        return Err("cloud_exchange_unsupported".into());
    };
    let name = match login.name {
        Some(name) if !name.trim().is_empty() => name,
        _ => {
            #[derive(Deserialize)]
            struct User {
                name: String,
            }
            let me = client
                .get(base.join("api/users/me").unwrap())
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|_| "server_unreachable_or_certificate_invalid")?;
            transport::json::<User>(me).await?.name
        }
    };
    let mut saved = SavedConnection {
        server: base.to_string(),
        server_id: String::new(),
        account_id,
        name,
        token,
        device_name: device_name.trim().into(),
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
    credentials::confirm_new_sign_in("connection", &saved, &window)?;
    let mut view = crate::prepare_with_client(&client, &mut saved).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn candidate(kind: &str, uri: &str, custom: bool) -> Candidate {
        Candidate {
            kind: kind.into(),
            uri: uri.into(),
            custom,
            verified: true,
        }
    }

    #[test]
    fn cloud_addresses_are_origins_and_the_production_api_has_its_issuer_on_id() {
        let cloud = parse_cloud_url(" https://api.frameleaf.cloud ").unwrap();
        assert_eq!(cloud.as_str(), "https://api.frameleaf.cloud/");
        let hosts = derive_hosts(&cloud);
        assert_eq!(hosts.issuer.as_str(), "https://id.frameleaf.cloud/");
        assert_eq!(hosts.api.as_str(), "https://api.frameleaf.cloud/");

        let staging =
            derive_hosts(&parse_cloud_url("https://api.staging.frameleaf.cloud").unwrap());
        assert_eq!(
            staging.issuer.as_str(),
            "https://id.staging.frameleaf.cloud/"
        );

        let other = derive_hosts(&parse_cloud_url("https://api.cloud.example:8443/").unwrap());
        assert_eq!(other.issuer.as_str(), "https://api.cloud.example:8443/");
        assert_eq!(other.api.as_str(), "https://api.cloud.example:8443/");

        assert_eq!(
            parse_cloud_url("http://localhost:3000").unwrap().as_str(),
            "http://localhost:3000/"
        );
        for invalid in [
            "http://api.frameleaf.cloud",
            "https://api.frameleaf.cloud/path",
            "https://api.frameleaf.cloud/?x=1",
            "https://user:pw@api.frameleaf.cloud",
            "api.frameleaf.cloud",
            "",
        ] {
            assert_eq!(
                parse_cloud_url(invalid).unwrap_err(),
                "cloud_address_invalid",
                "{invalid}"
            );
        }
    }

    #[test]
    fn discovery_may_move_the_hosts_only_within_the_cloud_domain() {
        let cloud = parse_cloud_url("https://api.frameleaf.cloud").unwrap();
        let moved = hosts_from_discovery(
            &cloud,
            Some(
                &json!({"issuer": "https://login.frameleaf.cloud/", "api": "https://api2.frameleaf.cloud"}),
            ),
        );
        assert_eq!(moved.issuer.as_str(), "https://login.frameleaf.cloud/");
        assert_eq!(moved.api.as_str(), "https://api2.frameleaf.cloud/");
        let refused = hosts_from_discovery(
            &cloud,
            Some(
                &json!({"issuer": "https://evil.example/", "api": "http://api.frameleaf.cloud", "ml": {}}),
            ),
        );
        assert_eq!(refused, derive_hosts(&cloud));
        assert_eq!(hosts_from_discovery(&cloud, None), derive_hosts(&cloud));

        let dev = parse_cloud_url("https://cloud.example:8443").unwrap();
        assert!(cloud_address_allowed(
            &dev,
            &Url::parse("https://id.cloud.example:8443/").unwrap()
        ));
        assert!(!cloud_address_allowed(
            &dev,
            &Url::parse("https://id.cloud.example/").unwrap()
        ));
        assert!(!cloud_address_allowed(
            &dev,
            &Url::parse("https://id.example:8443/").unwrap()
        ));
        assert!(!cloud_address_allowed(
            &cloud,
            &Url::parse("https://frameleaf.cloud.evil.example/").unwrap()
        ));
        assert!(cloud_address_allowed(
            &cloud,
            &Url::parse("https://frameleaf.cloud/").unwrap()
        ));
    }

    #[test]
    fn authorization_request_carries_pkce_the_resource_and_the_loopback_redirect() {
        let hosts = derive_hosts(&parse_cloud_url("https://api.frameleaf.cloud").unwrap());
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_challenge(verifier);
        // RFC 7636 appendix B.
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        let url = authorize_url(
            &hosts,
            "http://127.0.0.1:4921/callback",
            "st4te",
            &challenge,
        )
        .unwrap();
        assert_eq!(
            url.origin().unicode_serialization(),
            "https://id.frameleaf.cloud"
        );
        assert_eq!(url.path(), "/authorize");
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let get = |key: &str| {
            pairs
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("response_type"), Some("code"));
        assert_eq!(get("client_id"), Some("frameleaf-desktop"));
        assert_eq!(get("redirect_uri"), Some("http://127.0.0.1:4921/callback"));
        assert_eq!(
            get("scope"),
            Some("openid email profile offline_access account")
        );
        assert_eq!(get("resource"), Some("https://api.frameleaf.cloud"));
        assert_eq!(get("code_challenge"), Some(challenge.as_str()));
        assert_eq!(get("code_challenge_method"), Some("S256"));
        assert_eq!(get("state"), Some("st4te"));
        assert_eq!(get("prompt"), Some("consent"));
    }

    #[test]
    fn loopback_requests_are_read_as_the_code_a_refusal_or_noise() {
        assert_eq!(
            parse_callback("/callback?code=abc&state=xyz", "xyz"),
            Callback::Code("abc".into())
        );
        assert_eq!(
            parse_callback(
                "/callback?state=xyz&error=access_denied&error_description=no",
                "xyz"
            ),
            Callback::Refused("cloud_sign_in_access_denied".into())
        );
        assert_eq!(
            parse_callback("/callback?code=abc&state=other", "xyz"),
            Callback::Refused("cloud_sign_in_state_mismatch".into())
        );
        assert_eq!(
            parse_callback("/callback?code=abc", "xyz"),
            Callback::Refused("cloud_sign_in_state_mismatch".into())
        );
        assert_eq!(
            parse_callback("/callback?state=xyz", "xyz"),
            Callback::Refused("cloud_sign_in_invalid".into())
        );
        assert_eq!(parse_callback("/favicon.ico", "xyz"), Callback::Ignored);
        assert_eq!(parse_callback("/", "xyz"), Callback::Ignored);
        assert_eq!(
            parse_callback("http://evil.example/callback?code=a&state=xyz", "xyz"),
            Callback::Ignored
        );
    }

    #[test]
    fn loopback_listener_answers_the_browser_and_hands_back_the_code() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let browser = std::thread::spawn(move || {
            let mut replies = Vec::new();
            for target in ["/favicon.ico", "/callback?code=c0de&state=s"] {
                let mut stream = loop {
                    if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
                        break stream;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                stream
                    .write_all(
                        format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes(),
                    )
                    .unwrap();
                let mut reply = String::new();
                stream.read_to_string(&mut reply).unwrap();
                replies.push(reply);
            }
            replies
        });
        let code =
            wait_for_callback(listener, "s", Instant::now() + Duration::from_secs(10)).unwrap();
        assert_eq!(code, "c0de");
        let replies = browser.join().unwrap();
        assert!(replies[0].starts_with("HTTP/1.1 404"));
        assert!(replies[1].starts_with("HTTP/1.1 200"));
        assert!(replies[1].contains("Signed in to Frameleaf"));
    }

    #[test]
    fn loopback_listener_gives_up_at_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            wait_for_callback(listener, "s", Instant::now() + Duration::from_millis(120))
                .unwrap_err(),
            "cloud_sign_in_timed_out"
        );
    }

    #[test]
    fn candidates_are_ordered_local_wan_ipv6_custom_relay_https_first() {
        let ordered = order_candidates(vec![
            candidate("relay", "https://r.abc.frameleaf.net/", false),
            candidate("wan", "https://photos.example.com/", true),
            candidate("ipv6", "https://[2001:db8::1]:2283/", false),
            candidate("wan", "https://abc.frameleaf.net:44443/", false),
            candidate("local", "http://192.168.1.20:2283/", false),
            candidate(
                "local",
                "https://192-168-1-20.abc.frameleaf.net:2283",
                false,
            ),
            candidate(
                "local",
                "https://192-168-1-20.abc.frameleaf.net:2283/",
                false,
            ),
            candidate("wan", "https://user:pw@abc.frameleaf.net/", false),
        ]);
        let uris: Vec<&str> = ordered.iter().map(|c| c.uri.as_str()).collect();
        assert_eq!(
            uris,
            [
                "https://192-168-1-20.abc.frameleaf.net:2283/",
                "http://192.168.1.20:2283/",
                "https://abc.frameleaf.net:44443/",
                "https://[2001:db8::1]:2283/",
                "https://photos.example.com/",
                "https://r.abc.frameleaf.net/",
            ]
        );
    }

    #[test]
    fn the_best_candidate_that_answered_for_this_server_is_chosen() {
        let ordered = order_candidates(vec![
            candidate("local", "https://home.abc.frameleaf.net:2283/", false),
            candidate("wan", "https://abc.frameleaf.net:44443/", false),
            candidate("relay", "https://r.abc.frameleaf.net/", false),
        ]);
        let id = "018f5e7a-6b1e-7f6e-9c2e-1a2b3c4d5e6f";
        let results = vec![
            (
                "https://home.abc.frameleaf.net:2283/".to_string(),
                Err("server_unreachable_or_certificate_invalid".to_string()),
            ),
            (
                "https://abc.frameleaf.net:44443/".to_string(),
                Ok("another-server".to_string()),
            ),
            (
                "https://r.abc.frameleaf.net/".to_string(),
                Ok(id.to_string()),
            ),
        ];
        assert_eq!(
            select_candidate(&ordered, &results, id).unwrap().kind,
            "relay"
        );
        let results = vec![
            (
                "https://r.abc.frameleaf.net/".to_string(),
                Ok(id.to_string()),
            ),
            (
                "https://home.abc.frameleaf.net:2283/".to_string(),
                Ok(id.to_string()),
            ),
        ];
        assert_eq!(
            select_candidate(&ordered, &results, id).unwrap().kind,
            "local"
        );
        assert!(select_candidate(&ordered, &[], id).is_none());
    }

    #[test]
    fn instance_summaries_map_to_the_server_list_shape() {
        let servers = parse_instances(json!([{
            "instanceId": "018f5e7a-6b1e-7f6e-9c2e-1a2b3c4d5e6f",
            "id": "018f5e7a-6b1e-7f6e-9c2e-1a2b3c4d5e6f",
            "name": "Family photos",
            "version": "3.2.0",
            "status": "linked",
            "role": "owner",
            "lastSeenAt": "2026-11-03T10:00:00.000Z",
            "presence": "online",
            "region": "eu",
            "services": {"relay": "active", "backup": "none", "ml": "none"},
            "connections": [{"kind": "relay", "uri": "https://r.abc.frameleaf.net", "protocol": "https", "address": "r.abc.frameleaf.net", "port": 443, "local": false, "relay": true, "ipv6": false, "custom": false, "dnsRebindingProtection": true, "httpsRequired": true, "verified": true}],
            "identityKeys": [],
            "remoteAccess": {"entitled": true},
            "remoteEnabled": true
        }, {"not": "a server"}]))
        .unwrap();
        assert_eq!(servers.len(), 1);
        let server = &servers[0];
        assert_eq!(server.instance_id, "018f5e7a-6b1e-7f6e-9c2e-1a2b3c4d5e6f");
        assert_eq!(server.presence, "online");
        assert_eq!(
            server.last_seen_at.as_deref(),
            Some("2026-11-03T10:00:00.000Z")
        );
        assert!(server.remote_entitled);
        assert_eq!(
            server.connections,
            [CloudConnection {
                kind: "relay".into(),
                uri: "https://r.abc.frameleaf.net".into(),
                verified: true
            }]
        );
        assert_eq!(
            serde_json::to_value(server).unwrap()["last_seen_at"],
            json!("2026-11-03T10:00:00.000Z")
        );
        assert_eq!(
            parse_instances(json!({"instances": []})).unwrap(),
            Vec::<CloudServer>::new()
        );
        assert_eq!(
            parse_instances(json!("x")).unwrap_err(),
            "cloud_response_invalid"
        );
    }
}
