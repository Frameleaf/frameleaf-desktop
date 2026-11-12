//! The native pages that read and change the signed-in server: overview, Frameleaf Cloud account,
//! AI credit and remote access. Server replies pass through as bounded JSON; only the keys this app
//! sends are validated here, the server validates their values.

use crate::connection::{normalize_server, SavedConnection};
use crate::{transport, DesktopState};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
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

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AiQueue {
    name: String,
    state: Option<String>,
    unavailable: Option<bool>,
    is_paused: bool,
    held_for_night: Option<bool>,
    resumes_at: Option<String>,
    active: u64,
    waiting: u64,
    processed: u64,
    total: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunningJobs {
    can_manage_queues: bool,
    queues: Vec<AiQueue>,
}
#[derive(Deserialize, Serialize)]
struct ProcessingOrder {
    order: Vec<String>,
    workloads: Vec<WorkloadOrder>,
}
#[derive(Deserialize, Serialize)]
struct WorkloadOrder {
    workload: String,
    sources: Vec<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiProcessing {
    queues: Option<Vec<AiQueue>>,
    processing_order: Option<ProcessingOrder>,
}

fn ai_queues(value: Value) -> Option<Vec<AiQueue>> {
    let jobs: RunningJobs = serde_json::from_value(value).ok()?;
    jobs.can_manage_queues.then(|| {
        jobs.queues
            .into_iter()
            .filter(|queue| {
                matches!(
                    queue.name.as_str(),
                    "faceDetection"
                        | "facialRecognition"
                        | "smartSearch"
                        | "ocr"
                        | "imageEnrichment"
                        | "imageDescription"
                        | "nsfwDetection"
                )
            })
            .collect()
    })
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
    async fn get(&self, path: &str) -> Result<Value, Refused> {
        self.send(reqwest::Method::GET, path, None).await
    }
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, Refused> {
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
            return Ok(transport::json_limit(response, PASSTHROUGH_LIMIT).await?);
        }
        // A refusal's `code` tells the page what to do; nothing else of the body is kept, apart
        // from what answers a request for Two-Step Verification.
        let body = crate::server_steps::refusal_body(response).await;
        if let Some(needed) = body
            .as_ref()
            .and_then(|body| verification_required(status, body))
        {
            return Err(needed);
        }
        let code = body.as_ref().and_then(|value| value.get("code")?.as_str());
        Err(refusal(status.as_u16(), code).into())
    }
    async fn me(&self) -> Result<Me, Refused> {
        serde_json::from_value(self.get("api/users/me").await?)
            .map_err(|_| "server_response_invalid".into())
    }
    async fn require_admin(&self) -> Result<Me, Refused> {
        let me = self.me().await?;
        if !me.is_admin {
            return Err("admin_required".into());
        }
        Ok(me)
    }
}

/// Why a page's request failed: an error code, or the server asking for Two-Step Verification
/// first (403 `verification_required`). The page answers that with `server_step_up`, then retries.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum Refused {
    Code(String),
    Verification {
        code: &'static str,
        methods: Vec<String>,
        transaction: String,
    },
}
impl From<String> for Refused {
    fn from(code: String) -> Self {
        Self::Code(code)
    }
}
impl From<&str> for Refused {
    fn from(code: &str) -> Self {
        Self::Code(code.into())
    }
}

fn verification_required(status: reqwest::StatusCode, body: &Value) -> Option<Refused> {
    if status != reqwest::StatusCode::FORBIDDEN || body.get("code")? != "verification_required" {
        return None;
    }
    let transaction = body.get("transaction")?.as_str()?;
    if transaction.is_empty() || transaction.len() > 4000 {
        return None;
    }
    let methods = body.get("methods").and_then(Value::as_array);
    Some(Refused::Verification {
        code: "verification_required",
        methods: crate::server_steps::known_methods(
            methods
                .into_iter()
                .flatten()
                .filter_map(|method| method.as_str().map(str::to_owned))
                .collect(),
        ),
        transaction: transaction.to_owned(),
    })
}

/// An optional part of a page: its absence is fine, a request for Two-Step Verification is not.
fn optional(part: Result<Value, Refused>) -> Result<Option<Value>, Refused> {
    match part {
        Err(needed @ Refused::Verification { .. }) => Err(needed),
        part => Ok(part.ok()),
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
) -> Result<ServerSummary, Refused> {
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

#[tauri::command]
pub(crate) async fn server_ai_processing(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<AiProcessing, Refused> {
    crate::require_local(&window)?;
    let session = session(&state).await?;
    session.require_admin().await?;
    let (jobs, order) = tokio::join!(
        session.get("api/jobs/running"),
        session.get("api/ml-destinations/processing-order"),
    );
    Ok(AiProcessing {
        queues: optional(jobs)?.and_then(ai_queues),
        processing_order: optional(order)?.and_then(|value| serde_json::from_value(value).ok()),
    })
}

#[tauri::command]
pub(crate) async fn cloud_status(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<CloudStatus, Refused> {
    crate::require_local(&window)?;
    let session = session(&state).await?;
    session.require_admin().await?;
    let (cloud, license, backup) = tokio::join!(
        session.get("api/admin/cloud/status"),
        session.get("api/admin/license"),
        session.get("api/admin/cloud/backup"),
    );
    Ok(CloudStatus {
        cloud: cloud?,
        license: license.ok(),
        backup: backup.ok(),
    })
}

#[tauri::command]
pub(crate) async fn wallet_status(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<WalletStatus, Refused> {
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
) -> Result<Value, Refused> {
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
) -> Result<RemoteStatus, Refused> {
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
) -> Result<Value, Refused> {
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
) -> Result<Value, Refused> {
    crate::require_local(&window)?;
    let session = session(&state).await?;
    session
        .send(reqwest::Method::POST, "api/admin/cloud/remote/test", None)
        .await
}

/// Answers a `verification_required` with one proof, so the refused request can be retried.
#[tauri::command]
pub(crate) async fn server_step_up(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    transaction: String,
    method: String,
    proof: String,
) -> Result<(), String> {
    crate::require_local(&window)?;
    let transaction = zeroize::Zeroizing::new(transaction);
    let proof = zeroize::Zeroizing::new(proof);
    let session = session(&state).await?;
    crate::server_steps::step_up(
        &session.client,
        &session.base,
        &session.token,
        &transaction,
        &method,
        &proof,
    )
    .await
}

/// Allow the signed-in server origin, HTTPS Frameleaf service domains and the fixed downloads page.
pub(crate) fn external_url_allowed(url: &Url, server: Option<&Url>) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    if url.as_str() == "https://github.com/Frameleaf/frameleaf-desktop/releases"
        || server.is_some_and(|server| server.origin() == url.origin())
    {
        return true;
    }
    let Some(host) = url.host_str().filter(|_| url.scheme() == "https") else {
        return false;
    };
    let host = host.to_ascii_lowercase();
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
    url: String,
) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    crate::require_local(&window)?;
    if url.len() > 2048 {
        return Err("external_url_not_allowed".into());
    }
    let parsed = Url::parse(&url).map_err(|_| "external_url_not_allowed")?;
    let server = {
        let current = state.0.lock().await;
        current
            .as_ref()
            .and_then(|saved| normalize_server(&saved.server).ok())
    };
    if !external_url_allowed(&parsed, server.as_ref()) {
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
    fn external_urls_are_limited_to_the_server_and_frameleaf_domains() {
        let server = Url::parse("https://nas.home.arpa").unwrap();
        let allowed = |url: &str| external_url_allowed(&Url::parse(url).unwrap(), Some(&server));
        assert!(allowed("https://nas.home.arpa/admin"));
        assert!(allowed("https://NAS.home.arpa/"));
        assert!(!allowed("http://nas.home.arpa/"));
        let local = Url::parse("http://192.168.1.20:2283").unwrap();
        let on_local = |url: &str| external_url_allowed(&Url::parse(url).unwrap(), Some(&local));
        assert!(on_local("http://192.168.1.20:2283/admin"));
        assert!(!on_local("http://192.168.1.20/"));
        assert!(!on_local("http://192.168.1.21:2283/"));
        assert!(!allowed("https://frameleaf.example/servers/1"));
        assert!(allowed("https://frameleaf.cloud/store"));
        assert!(allowed(
            "https://github.com/Frameleaf/frameleaf-desktop/releases"
        ));
        assert!(!allowed(
            "https://github.com/Frameleaf/frameleaf-desktop/releases?redirect=other"
        ));
        assert!(!allowed("https://github.com/other/repo/releases"));
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
            None
        ));
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

#[cfg(test)]
mod verification_tests {
    use super::*;
    use crate::server_steps::fixture::{client, server};
    use serde_json::json;

    #[tokio::test]
    async fn admin_request_needing_two_step_verification_keeps_its_methods_and_transaction() {
        let (base, _) = server(|request| match request.path.as_str() {
            "/api/admin/cloud/status" => (
                403,
                json!({
                    "message": "private", "error": "Forbidden", "statusCode": 403,
                    "code": "verification_required", "acr": "urn:frameleaf:acr:verified",
                    "maxAge": null, "methods": ["frameleaf", "totp", "recovery_code", "sms"],
                    "transaction": "txn",
                }),
            ),
            "/api/admin/license" => (403, json!({"code": "verification_required"})),
            "/api/admin/cloud/remote" => (403, json!({"code": "frameleaf_sign_in_required"})),
            _ => (403, json!({"message": "private"})),
        });
        let session = Session {
            client: client(),
            base,
            token: "session".into(),
        };
        // A read and a change take the same path.
        for refused in [
            session.get("api/admin/cloud/status").await,
            session
                .send(reqwest::Method::PUT, "api/admin/cloud/status", None)
                .await,
        ] {
            let Err(refused) = refused else {
                panic!("the request should be refused");
            };
            let Refused::Verification {
                methods,
                transaction,
                ..
            } = &refused
            else {
                panic!("Two-Step Verification should be asked for");
            };
            assert_eq!(methods, &["frameleaf", "totp", "recovery_code"]);
            assert_eq!(transaction, "txn");
            assert_eq!(
                serde_json::to_value(&refused).unwrap(),
                json!({
                    "code": "verification_required",
                    "methods": ["frameleaf", "totp", "recovery_code"],
                    "transaction": "txn",
                })
            );
            // An optional part of a page does not hide it.
            assert!(matches!(
                optional(Err(refused)),
                Err(Refused::Verification { .. })
            ));
        }
        // Other refusals stay plain codes, as the page already reads them.
        for (path, code) in [
            ("api/admin/license", "server_refused_verification_required"),
            (
                "api/admin/cloud/remote",
                "server_refused_frameleaf_sign_in_required",
            ),
            ("api/admin/attention", "server_http_403"),
        ] {
            let Err(refused) = session.get(path).await else {
                panic!("the request should be refused");
            };
            assert_eq!(serde_json::to_value(&refused).unwrap(), json!(code));
            assert!(matches!(optional(Err(refused)), Ok(None)));
        }
    }
}

#[cfg(test)]
mod ai_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn library_ai_queue_summary_filters_other_queues_and_refuses_ungranted_counts() {
        let queue = |name| {
            json!({
                "name": name, "isPaused": false, "active": 1, "waiting": 4, "processed": 5, "total": 10
            })
        };
        let result = ai_queues(json!({
            "canManageQueues": true, "queues": [queue("smartSearch"), queue("videoConversion")],
            "operations": [{ "private": "omitted" }]
        }))
        .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "smartSearch");
        assert_eq!(result[0].total, 10);
        assert!(
            ai_queues(json!({ "canManageQueues": false, "queues": [queue("smartSearch")] }))
                .is_none()
        );
        assert!(ai_queues(json!({ "queues": [] })).is_none());
        assert!(ai_queues(json!({ "canManageQueues": true, "queues": [] }))
            .unwrap()
            .is_empty());
    }
}
