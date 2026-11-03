//! The native pages that read and change the signed-in server: overview, Frameleaf Cloud account,
//! AI credit and remote access. Server replies pass through as bounded JSON; only the keys this app
//! sends are validated here, the server validates their values.

use crate::connection::{normalize_server, SavedConnection};
use crate::{transport, DesktopState};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::Mutex;
use tauri::{State, WebviewWindow};
use url::Url;

/// The largest reply any of these pages reads (attention lists and settlements included).
const PASSTHROUGH_LIMIT: usize = 256 * 1024;

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Me {
    pub id: String,
    pub name: String,
    pub email: String,
    #[serde(default)]
    pub is_admin: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerSummary {
    pub me: Me,
    pub connections: Option<Value>,
    pub storage: Option<Value>,
    pub version: Option<Value>,
    pub attention: Option<Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CloudStatus {
    pub cloud: Value,
    pub license: Option<Value>,
    pub backup: Option<Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletStatus {
    pub ml: Value,
    pub wallet: Option<Value>,
    pub settlements: Option<Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteStatus {
    pub remote: Value,
    pub usage: Option<Value>,
}

/// Hosts the last cloud status named (the account site and the sign-in issuer), which the browser
/// may be sent to beside the server and the Frameleaf domains.
#[derive(Default)]
pub(crate) struct ExternalHosts(pub(crate) Mutex<Vec<String>>);

struct Session {
    client: Client,
    base: Url,
    token: String,
}
impl Session {
    fn open(saved: &SavedConnection) -> Result<Self, String> {
        Ok(Self {
            client: transport::client()?,
            base: normalize_server(&saved.server)?,
            token: saved.token.clone(),
        })
    }
    async fn get(&self, path: &str) -> Result<Value, String> {
        let url = self.base.join(path).map_err(|_| "server_address_invalid")?;
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| "server_unreachable_or_certificate_invalid")?;
        transport::json_limit(response, PASSTHROUGH_LIMIT).await
    }
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, String> {
        let url = self.base.join(path).map_err(|_| "server_address_invalid")?;
        let mut request = self.client.request(method, url).bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| "server_unreachable_or_certificate_invalid")?;
        let status = response.status();
        if status.is_success() {
            return transport::json_limit(response, PASSTHROUGH_LIMIT).await;
        }
        // A refusal's `code` tells the page what to do; nothing else of the body is kept.
        let body = response.bytes().await.unwrap_or_default();
        let code = if body.len() <= 65_536 {
            serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|value| value.get("code")?.as_str().map(str::to_owned))
        } else {
            None
        };
        Err(refusal(status.as_u16(), code.as_deref()))
    }
    async fn me(&self) -> Result<Me, String> {
        serde_json::from_value(self.get("api/users/me").await?)
            .map_err(|_| "server_response_invalid".into())
    }
    async fn require_admin(&self) -> Result<Me, String> {
        let me = self.me().await?;
        if !me.is_admin {
            return Err("admin_required".into());
        }
        Ok(me)
    }
}

/// The error code for a refused change: the server's own `code` when it sent one.
pub(crate) fn refusal(status: u16, code: Option<&str>) -> String {
    match (status, code) {
        (403, Some("step-up-required")) => "wallet_step_up_required".into(),
        (_, Some(code)) if is_code(code) => format!("server_refused_{}", code.replace('-', "_")),
        _ => format!("server_http_{status}"),
    }
}
fn is_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

async fn session(state: &State<'_, DesktopState>) -> Result<Session, String> {
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    Session::open(saved)
}

#[tauri::command]
pub(crate) async fn server_summary(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<ServerSummary, String> {
    crate::require_local(&window)?;
    let session = session(&state).await?;
    let me = session.me().await?;
    let (connections, storage, version) = tokio::join!(
        session.get("api/server/connections"),
        session.get("api/server/storage"),
        session.get("api/server/version-check"),
    );
    let attention = if me.is_admin {
        session.get("api/admin/attention").await.ok()
    } else {
        None
    };
    Ok(ServerSummary {
        me,
        connections: connections.ok(),
        storage: storage.ok(),
        version: version.ok(),
        attention,
    })
}

/// Every https host a cloud status names, lowercase: `manageUrl` and `signInIssuer` today.
pub(crate) fn cloud_hosts(status: &Value) -> Vec<String> {
    let mut hosts = Vec::new();
    for key in ["manageUrl", "signInIssuer"] {
        if let Some(url) = status.get(key).and_then(Value::as_str) {
            if let Ok(url) = Url::parse(url) {
                if url.scheme() == "https" {
                    if let Some(host) = url.host_str() {
                        let host = host.to_ascii_lowercase();
                        if !hosts.contains(&host) {
                            hosts.push(host);
                        }
                    }
                }
            }
        }
    }
    hosts
}

#[tauri::command]
pub(crate) async fn cloud_status(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    hosts: State<'_, ExternalHosts>,
) -> Result<CloudStatus, String> {
    crate::require_local(&window)?;
    let session = session(&state).await?;
    session.require_admin().await?;
    let (cloud, license, backup) = tokio::join!(
        session.get("api/admin/cloud/status"),
        session.get("api/admin/license"),
        session.get("api/admin/cloud/backup"),
    );
    let cloud = cloud?;
    *hosts.0.lock().map_err(|_| "state_unavailable")? = cloud_hosts(&cloud);
    Ok(CloudStatus {
        cloud,
        license: license.ok(),
        backup: backup.ok(),
    })
}

#[tauri::command]
pub(crate) async fn wallet_status(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<WalletStatus, String> {
    crate::require_local(&window)?;
    let session = session(&state).await?;
    session.require_admin().await?;
    let (ml, wallet, settlements) = tokio::join!(
        session.get("api/admin/cloud/ml"),
        session.get("api/admin/cloud/ml/wallet"),
        session.get("api/admin/cloud/ml/settlements"),
    );
    Ok(WalletStatus {
        ml: ml?,
        wallet: wallet.ok(),
        settlements: settlements.ok(),
    })
}

/// The `CloudMlWalletUpdateDto` body, or none when there is nothing to change.
pub(crate) fn wallet_update(
    daily_cap_usd: Option<f64>,
    auto_top_up: Option<bool>,
) -> Result<Value, String> {
    let mut body = Map::new();
    if let Some(cap) = daily_cap_usd {
        if !cap.is_finite() || !(1.0..=1000.0).contains(&cap) {
            return Err("wallet_daily_cap_invalid".into());
        }
        body.insert("dailyCapUsd".into(), Value::from(cap));
    }
    if let Some(auto) = auto_top_up {
        body.insert("autoTopUp".into(), Value::from(auto));
    }
    if body.is_empty() {
        return Err("wallet_nothing_to_change".into());
    }
    Ok(Value::Object(body))
}

#[tauri::command]
pub(crate) async fn update_wallet(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    daily_cap_usd: Option<f64>,
    auto_top_up: Option<bool>,
) -> Result<Value, String> {
    crate::require_local(&window)?;
    let body = wallet_update(daily_cap_usd, auto_top_up)?;
    let session = session(&state).await?;
    session
        .send(
            reqwest::Method::PUT,
            "api/admin/cloud/ml/wallet",
            Some(&body),
        )
        .await
}

#[tauri::command]
pub(crate) async fn remote_status(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<RemoteStatus, String> {
    crate::require_local(&window)?;
    let session = session(&state).await?;
    session.require_admin().await?;
    let (remote, usage) = tokio::join!(
        session.get("api/admin/cloud/remote"),
        session.get("api/admin/cloud/remote/usage"),
    );
    Ok(RemoteStatus {
        remote: remote?,
        usage: usage.ok(),
    })
}

/// `RemoteAccessUpdateDto` (PUT admin/cloud/remote) and `CloudRemoteAccessUpdateDto`
/// (PUT admin/cloud/remote-access), split from one settings object. Only these keys, with the
/// server's types, are ever sent.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct RemoteUpdate {
    pub remote: Option<Value>,
    pub relay: Option<Value>,
}
pub(crate) fn split_remote_settings(settings: &Value) -> Result<RemoteUpdate, String> {
    let object = settings.as_object().ok_or("remote_settings_invalid")?;
    let mut remote = Map::new();
    let mut relay = Map::new();
    for (key, value) in object {
        let valid = match key.as_str() {
            "enabled" | "portMapping" => value.is_boolean(),
            "mode" => matches!(value.as_str(), Some("relay" | "relay-and-direct")),
            "directPort" => value
                .as_u64()
                .is_some_and(|port| (1024..=65_535).contains(&port)),
            "publicUrl" => matches!(value.as_str(), Some("frameleaf" | "custom")),
            "allowOriginalsOverRelay" | "allowPasswordOverRelay" => value.is_boolean(),
            _ => return Err("remote_settings_invalid".into()),
        };
        if !valid {
            return Err("remote_settings_invalid".into());
        }
        if key.starts_with("allow") {
            relay.insert(key.clone(), value.clone());
        } else {
            remote.insert(key.clone(), value.clone());
        }
    }
    if remote.is_empty() && relay.is_empty() {
        return Err("remote_settings_invalid".into());
    }
    Ok(RemoteUpdate {
        remote: (!remote.is_empty()).then_some(Value::Object(remote)),
        relay: (!relay.is_empty()).then_some(Value::Object(relay)),
    })
}

#[tauri::command]
pub(crate) async fn update_remote(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    settings: Value,
) -> Result<Value, String> {
    crate::require_local(&window)?;
    let update = split_remote_settings(&settings)?;
    let session = session(&state).await?;
    if let Some(relay) = &update.relay {
        session
            .send(
                reqwest::Method::PUT,
                "api/admin/cloud/remote-access",
                Some(relay),
            )
            .await?;
    }
    match &update.remote {
        Some(remote) => {
            session
                .send(reqwest::Method::PUT, "api/admin/cloud/remote", Some(remote))
                .await
        }
        None => session.get("api/admin/cloud/remote").await,
    }
}

#[tauri::command]
pub(crate) async fn test_remote_access(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<Value, String> {
    crate::require_local(&window)?;
    let session = session(&state).await?;
    session
        .send(reqwest::Method::POST, "api/admin/cloud/remote/test", None)
        .await
}

/// Only https, and only the signed-in server, a host the last cloud status named, or Frameleaf's
/// own domains: the browser never opens an address a server reply could choose freely.
pub(crate) fn external_url_allowed(
    url: &Url,
    server_host: Option<&str>,
    cloud_hosts: &[String],
) -> bool {
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    if server_host.is_some_and(|server| server.eq_ignore_ascii_case(&host)) {
        return true;
    }
    if cloud_hosts
        .iter()
        .any(|cloud| cloud.eq_ignore_ascii_case(&host))
    {
        return true;
    }
    host == "frameleaf.cloud"
        || host.ends_with(".frameleaf.cloud")
        || host == "frameleaf.net"
        || host.ends_with(".frameleaf.net")
}

#[tauri::command]
pub(crate) async fn open_external(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    hosts: State<'_, ExternalHosts>,
    url: String,
) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    crate::require_local(&window)?;
    if url.len() > 2048 {
        return Err("external_url_not_allowed".into());
    }
    let parsed = Url::parse(&url).map_err(|_| "external_url_not_allowed")?;
    let server_host = {
        let current = state.0.lock().await;
        current
            .as_ref()
            .and_then(|saved| normalize_server(&saved.server).ok())
            .and_then(|base| base.host_str().map(str::to_owned))
    };
    let cloud = hosts.0.lock().map_err(|_| "state_unavailable")?.clone();
    if !external_url_allowed(&parsed, server_host.as_deref(), &cloud) {
        return Err("external_url_not_allowed".into());
    }
    app.opener()
        .open_url(parsed.as_str(), None::<&str>)
        .map_err(|_| "external_open_failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn external_urls_are_limited_to_the_server_the_cloud_and_frameleaf_domains() {
        let cloud = vec!["frameleaf.example".to_string()];
        let allowed = |url: &str| {
            external_url_allowed(&Url::parse(url).unwrap(), Some("nas.home.arpa"), &cloud)
        };
        assert!(allowed("https://nas.home.arpa/admin"));
        assert!(allowed("https://NAS.home.arpa/"));
        assert!(allowed("https://frameleaf.example/servers/1"));
        assert!(allowed("https://frameleaf.cloud/store"));
        assert!(allowed("https://id.frameleaf.cloud/session/end"));
        assert!(allowed("https://frameleaf.net/"));
        assert!(allowed("https://abc.frameleaf.net/"));
        assert!(!allowed("http://frameleaf.cloud/store"));
        assert!(!allowed("https://evil.example/"));
        assert!(!allowed("https://notframeleaf.cloud/"));
        assert!(!allowed("https://frameleaf.cloud.evil.example/"));
        assert!(!allowed("https://user:pw@frameleaf.cloud/"));
        assert!(!allowed("javascript:alert(1)"));
        assert!(!allowed("file:///etc/passwd"));
        assert!(!external_url_allowed(
            &Url::parse("https://nas.home.arpa/").unwrap(),
            None,
            &[]
        ));
    }

    #[test]
    fn cloud_status_hosts_come_from_its_https_links_only() {
        let hosts = cloud_hosts(&json!({
            "manageUrl": "https://Frameleaf.Example/servers/abc",
            "signInIssuer": "https://id.frameleaf.example",
            "other": "https://ignored.example"
        }));
        assert_eq!(hosts, ["frameleaf.example", "id.frameleaf.example"]);
        assert!(
            cloud_hosts(&json!({"manageUrl": "http://plain.example", "signInIssuer": null}))
                .is_empty()
        );
        assert!(cloud_hosts(&json!(null)).is_empty());
    }

    #[test]
    fn remote_settings_split_into_the_two_server_bodies_and_refuse_anything_else() {
        let update = split_remote_settings(&json!({
            "enabled": true,
            "mode": "relay-and-direct",
            "directPort": 44_443,
            "portMapping": false,
            "publicUrl": "custom",
            "allowOriginalsOverRelay": true,
            "allowPasswordOverRelay": false
        }))
        .unwrap();
        assert_eq!(
            update.remote.unwrap(),
            json!({"enabled": true, "mode": "relay-and-direct", "directPort": 44_443, "portMapping": false, "publicUrl": "custom"})
        );
        assert_eq!(
            update.relay.unwrap(),
            json!({"allowOriginalsOverRelay": true, "allowPasswordOverRelay": false})
        );
        let only_relay = split_remote_settings(&json!({"allowOriginalsOverRelay": false})).unwrap();
        assert!(only_relay.remote.is_none());
        assert!(only_relay.relay.is_some());
        for invalid in [
            json!({}),
            json!([]),
            json!("relay"),
            json!({"hostname": "photos.example.com"}),
            json!({"mode": "direct"}),
            json!({"directPort": 80}),
            json!({"directPort": "8443"}),
            json!({"publicUrl": "https://x"}),
            json!({"enabled": "yes"}),
            json!({"allowPasswordOverRelay": 1}),
        ] {
            assert_eq!(
                split_remote_settings(&invalid).unwrap_err(),
                "remote_settings_invalid",
                "{invalid}"
            );
        }
    }

    #[test]
    fn wallet_updates_send_only_what_changes_within_the_server_limits() {
        assert_eq!(
            wallet_update(Some(25.0), None).unwrap(),
            json!({"dailyCapUsd": 25.0})
        );
        assert_eq!(
            wallet_update(None, Some(false)).unwrap(),
            json!({"autoTopUp": false})
        );
        assert_eq!(
            wallet_update(Some(1000.0), Some(true)).unwrap(),
            json!({"dailyCapUsd": 1000.0, "autoTopUp": true})
        );
        assert_eq!(
            wallet_update(None, None).unwrap_err(),
            "wallet_nothing_to_change"
        );
        for cap in [0.5, 1000.5, f64::NAN, f64::INFINITY, -3.0] {
            assert_eq!(
                wallet_update(Some(cap), None).unwrap_err(),
                "wallet_daily_cap_invalid"
            );
        }
    }

    #[test]
    fn refusals_keep_the_servers_code_and_name_the_wallet_step_up() {
        assert_eq!(
            refusal(403, Some("step-up-required")),
            "wallet_step_up_required"
        );
        assert_eq!(
            refusal(403, Some("frameleaf_exchange_no_access")),
            "server_refused_frameleaf_exchange_no_access"
        );
        assert_eq!(refusal(400, Some("Bad Request!")), "server_http_400");
        assert_eq!(refusal(500, None), "server_http_500");
        assert_eq!(refusal(401, Some(&"a".repeat(65))), "server_http_401");
    }
}
