use crate::connection::DeviceIdentity;
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{Client, Response};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::{ZeroizeOnDrop, Zeroizing};

pub const CREDENTIAL: &str = "manager-grant";
const RECENT: u64 = 300_000;
const LIFETIME: u64 = 30 * 86_400_000;
const WINDOW: u64 = 60_000;
const SCOPES: [Scope; 5] = [
    Scope::Status,
    Scope::Start,
    Scope::Stop,
    Scope::Restart,
    Scope::Backup,
];
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    Status,
    Start,
    Stop,
    Restart,
    Backup,
    Update,
    Restore,
    MoveLibrary,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Start,
    Stop,
    Restart,
    Backup,
}
impl Action {
    fn scope(self) -> Scope {
        match self {
            Self::Start => Scope::Start,
            Self::Stop => Scope::Stop,
            Self::Restart => Scope::Restart,
            Self::Backup => Scope::Backup,
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Status {},
    Backups {},
    ReviewRestore {
        snapshot: String,
        key: Uuid,
    },
    RestoreReview {
        id: Uuid,
        snapshot: String,
    },
    #[serde(rename_all = "camelCase")]
    Restore {
        review_id: Uuid,
        key: Uuid,
    },
    RestoreOperation {
        id: Uuid,
    },
    ResumeRestore {
        id: Uuid,
    },
    Control {
        action: Action,
        key: Uuid,
    },
    Operation {
        id: Uuid,
    },
    Resume {
        action: Action,
        id: Uuid,
    },
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateTrust {
    pub pem: String,
    pub sha256: String,
}
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedManager {
    origin: String,
    manager_id: String,
    device_id: String,
    installation_id: String,
    public_key: String,
    id: String,
    token: String,
    expires_at: u64,
    recent_until: u64,
    #[zeroize(skip)]
    scopes: Vec<Scope>,
    certificate_pem: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub origin: String,
    pub manager_id: String,
    pub device_id: String,
    pub installation_id: String,
    pub expires_at: u64,
    pub scopes: Vec<Scope>,
    pub certificate_sha256: Option<String>,
}
impl SavedManager {
    pub fn require_device(&self, identity: &DeviceIdentity) -> Result<(), String> {
        if self.device_id != identity.installation_id || self.public_key != identity.public_key() {
            return Err("manager_device_changed".into());
        }
        Ok(())
    }

    pub fn view(&self) -> View {
        View {
            origin: self.origin.clone(),
            manager_id: self.manager_id.clone(),
            device_id: self.device_id.clone(),
            installation_id: self.installation_id.clone(),
            expires_at: self.expires_at,
            scopes: self.scopes.clone(),
            certificate_sha256: self
                .certificate_pem
                .as_deref()
                .and_then(|pem| certificate_fingerprint(pem).ok()),
        }
    }
}
#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pairing {
    pairing_id: String,
    manager_id: String,
    origin: String,
    device_id: String,
    installation_id: String,
    public_key: String,
    #[zeroize(skip)]
    scopes: Vec<Scope>,
    secret: String,
    approved_at: u64,
    expires_at: u64,
}
#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Issued {
    id: String,
    manager_id: String,
    origin: String,
    device_id: String,
    installation_id: String,
    token: String,
    expires_at: u64,
    recent_until: u64,
    #[zeroize(skip)]
    scopes: Vec<Scope>,
}
#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Login {
    csrf: String,
}
#[derive(ZeroizeOnDrop)]
struct Session {
    credential: String,
    csrf: String,
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn identifier(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}
pub(crate) fn clock() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or_else(|| "clock_invalid".into())
}
pub fn normalize_manager(value: &str) -> Result<url::Url, String> {
    if value.contains('\\') {
        return Err("manager_origin_invalid".into());
    }
    let url = url::Url::parse(value.trim()).map_err(|_| "manager_origin_invalid")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err("manager_origin_invalid".into());
    }
    Ok(url)
}
fn canonical_origin(value: &str) -> Result<String, String> {
    let url = normalize_manager(value)?;
    let origin = url.origin().ascii_serialization();
    if value != origin {
        return Err("manager_origin_invalid".into());
    }
    Ok(origin)
}
fn certificate_der(pem: &str) -> Result<Vec<u8>, String> {
    if pem.len() > 16_384 {
        return Err("manager_certificate_invalid".into());
    }
    let content = pem
        .trim()
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|value| value.strip_suffix("-----END CERTIFICATE-----"))
        .ok_or("manager_certificate_invalid")?;
    let encoded: String = content
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    let der = STANDARD
        .decode(&encoded)
        .map_err(|_| "manager_certificate_invalid")?;
    if STANDARD.encode(&der) != encoded {
        return Err("manager_certificate_invalid".into());
    }
    reqwest::Certificate::from_der(&der).map_err(|_| "manager_certificate_invalid")?;
    Ok(der)
}
pub fn certificate_fingerprint(pem: &str) -> Result<String, String> {
    Ok(format!("{:x}", Sha256::digest(certificate_der(pem)?)))
}
pub fn manager_client(
    origin: &str,
    pem: Option<&str>,
    approved: Option<&str>,
) -> Result<Client, String> {
    if normalize_manager(origin)?.scheme() == "http" && (pem.is_some() || approved.is_some()) {
        return Err("manager_http_certificate_invalid".into());
    }
    let mut builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("FrameleafDesktop/", env!("CARGO_PKG_VERSION")));
    match (pem, approved) {
        (None, None) => {}
        (Some(pem), Some(approved)) => {
            let der = certificate_der(pem)?;
            if !hex(approved, 64) || format!("{:x}", Sha256::digest(&der)) != approved {
                return Err("manager_certificate_approval_changed".into());
            }
            builder = builder.tls_built_in_root_certs(false).add_root_certificate(
                reqwest::Certificate::from_der(&der).map_err(|_| "manager_certificate_invalid")?,
            );
        }
        _ => return Err("manager_certificate_approval_required".into()),
    }
    builder
        .build()
        .map_err(|_| "network_client_unavailable".into())
}
async fn reply<T: DeserializeOwned>(mut response: Response) -> Result<T, String> {
    let status = response.status();
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "manager_response_interrupted")?
    {
        if bytes.len() + chunk.len() > 65_536 {
            return Err("manager_response_too_large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let value = serde_json::from_slice::<Value>(&bytes).ok();
        let code = value
            .as_ref()
            .and_then(|value| value.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("");
        return Err(match code {
            "desktop_recent_auth_required" => "manager_recent_auth_required",
            "desktop_grant_invalid" => "manager_pair_again",
            "desktop_grant_scope_denied" => "manager_scope_denied",
            "desktop_grant_installation_changed" => "manager_installation_changed",
            "desktop_request_replayed" => "manager_request_replayed",
            "operation_in_progress" => "manager_operation_in_progress",
            "request_key_reused" => "manager_request_key_reused",
            "operation_not_recoverable" => "manager_operation_not_recoverable",
            "no_installation" => "manager_no_installation",
            "rate_limited" => "manager_rate_limited",
            "invalid_credentials" => "manager_invalid_credentials",
            "already_claimed" => "manager_already_claimed",
            "invalid_claim_proof" => "manager_claim_proof_changed",
            "native_recovery_unavailable" | "desktop_route_unavailable" => {
                "manager_recovery_unavailable"
            }
            "native_restore_review_busy" => "manager_review_busy",
            "native_restore_review_changed" => "manager_review_changed",
            "native_restore_verification_failed" => "manager_review_failed",
            "native_backup_unavailable" => "manager_backup_unavailable",
            "native_restore_review_expired"
            | "native_restore_review_not_ready"
            | "native_restore_runtime_change_required" => code,
            _ => "manager_request_failed",
        }
        .into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "manager_response_invalid".into())
}
async fn login(client: &Client, origin: &str, password: &str) -> Result<Session, String> {
    let response = client
        .post(format!("{origin}/manager-api/login"))
        .header("origin", origin)
        .json(&json!({"password":password}))
        .send()
        .await
        .map_err(|_| "manager_unreachable_or_certificate_invalid")?;
    session_response(response, origin).await
}
async fn session_response(response: Response, origin: &str) -> Result<Session, String> {
    let http = normalize_manager(origin)?.scheme() == "http";
    let prefix = if http {
        ""
    } else {
        "__Host-frameleaf-manager="
    };
    let credentials: Vec<_> = response
        .headers()
        .get_all(if http {
            "x-frameleaf-manager-session"
        } else {
            "set-cookie"
        })
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| {
            if http {
                Some(value)
            } else {
                value.split(';').next()
            }
        })
        .filter(|value| value.starts_with(prefix))
        .collect();
    let credential = if credentials.len() == 1 && hex(credentials[0].trim_start_matches(prefix), 64)
    {
        Some(credentials[0].to_string())
    } else {
        None
    };
    let value: Login = reply(response).await?;
    if !hex(&value.csrf, 64) {
        return Err("manager_response_invalid".into());
    }
    Ok(Session {
        credential: credential.ok_or("manager_response_invalid")?,
        csrf: value.csrf.clone(),
    })
}
pub(crate) async fn claim_local(
    client: &Client,
    origin: &str,
    name: &str,
    password: &str,
    proof: &str,
) -> Result<(), String> {
    #[derive(Serialize)]
    struct Claim<'a> {
        name: &'a str,
        password: &'a str,
        proof: &'a str,
    }
    let response = client
        .post(format!("{origin}/manager-api/claim"))
        .header("origin", origin)
        .json(&Claim {
            name,
            password,
            proof,
        })
        .send()
        .await
        .map_err(|_| "manager_claim_interrupted")?;
    let session = session_response(response, origin).await?;
    let _ = browser::<Value>(client, origin, &session, "logout", json!({})).await;
    Ok(())
}
async fn browser<T: DeserializeOwned>(
    client: &Client,
    origin: &str,
    session: &Session,
    path: &str,
    body: Value,
) -> Result<T, String> {
    reply(
        client
            .post(format!("{origin}/manager-api/{path}"))
            .header("origin", origin)
            .header(
                if origin.starts_with("http://") {
                    "x-frameleaf-manager-session"
                } else {
                    "cookie"
                },
                &session.credential,
            )
            .header("x-csrf-token", &session.csrf)
            .json(&body)
            .send()
            .await
            .map_err(|_| "manager_unreachable_or_certificate_invalid")?,
    )
    .await
}
fn pairing_message(value: &Pairing) -> String {
    json!([
        "frameleaf-manager/pair/v1",
        value.manager_id,
        value.origin,
        value.pairing_id,
        value.device_id,
        value.installation_id,
        value.public_key,
        value.scopes,
        value.secret,
        value.approved_at,
        value.expires_at
    ])
    .to_string()
}
fn validate_pairing(
    value: &Pairing,
    identity: &DeviceIdentity,
    origin: &str,
    now: u64,
    scopes: &[Scope],
) -> Result<(), String> {
    if value.origin != origin
        || value.device_id != identity.installation_id
        || value.public_key != identity.public_key()
        || value.scopes != scopes
        || !identifier(&value.manager_id)
        || !identifier(&value.pairing_id)
        || !hex(&value.installation_id, 12)
        || !hex(&value.secret, 64)
        || value.approved_at > now.saturating_add(WINDOW)
        || value.expires_at <= now
        || value.expires_at.checked_sub(value.approved_at) != Some(RECENT)
    {
        return Err("manager_pairing_binding_changed".into());
    }
    Ok(())
}
pub async fn pair(
    identity: &DeviceIdentity,
    origin: &str,
    password: String,
    certificate: Option<CertificateTrust>,
    allow_recovery: bool,
    persist: impl FnOnce(&SavedManager) -> Result<(), String>,
) -> Result<View, String> {
    let mut scopes = SCOPES.to_vec();
    if allow_recovery {
        scopes.push(Scope::Restore);
    }
    pair_with_scopes(identity, origin, password, certificate, scopes, persist).await
}

#[cfg(all(windows, feature = "qualify-windows-media-move"))]
pub(crate) async fn pair_qualification_move(
    identity: &DeviceIdentity,
    origin: &str,
    password: String,
    certificate: CertificateTrust,
) -> Result<SavedManager, String> {
    let mut scopes = SCOPES.to_vec();
    scopes.push(Scope::MoveLibrary);
    let mut grant = None;
    pair_with_scopes(
        identity,
        origin,
        password,
        Some(certificate),
        scopes,
        |saved| {
            let raw = Zeroizing::new(
                serde_json::to_vec(saved).map_err(|_| "manager_credential_invalid")?,
            );
            grant = Some(serde_json::from_slice(&raw).map_err(|_| "manager_credential_invalid")?);
            Ok(())
        },
    )
    .await?;
    grant.ok_or_else(|| "manager_credential_invalid".into())
}

async fn pair_with_scopes(
    identity: &DeviceIdentity,
    origin: &str,
    password: String,
    certificate: Option<CertificateTrust>,
    scopes: Vec<Scope>,
    persist: impl FnOnce(&SavedManager) -> Result<(), String>,
) -> Result<View, String> {
    canonical_origin(origin)?;
    let password = Zeroizing::new(password);
    if password.is_empty() || password.len() > 256 {
        return Err("manager_login_details_invalid".into());
    }
    let client = manager_client(
        origin,
        certificate.as_ref().map(|value| value.pem.as_str()),
        certificate.as_ref().map(|value| value.sha256.as_str()),
    )?;
    let session = login(&client, origin, &password).await?;
    let result=async{
        let approval:Pairing=browser(&client,origin,&session,"desktop-grants/approve",json!({"password":password.as_str(),"deviceId":identity.installation_id,"publicKey":identity.public_key(),"scopes":scopes})).await?;
        validate_pairing(&approval,identity,origin,clock()?,&scopes)?;
        let issued:Issued=reply(client.post(format!("{origin}/manager-api/desktop/redeem")).json(&json!({"pairingId":approval.pairing_id,"secret":approval.secret,"signature":identity.sign(&pairing_message(&approval))})).send().await.map_err(|_|"manager_pairing_interrupted")?).await?;
        let now=clock()?;
        if !identifier(&issued.id)||issued.manager_id!=approval.manager_id||issued.origin!=origin||issued.device_id!=identity.installation_id||issued.installation_id!=approval.installation_id||issued.scopes!=scopes||!hex(&issued.token,64)||issued.expires_at<=now||issued.expires_at>now.saturating_add(LIFETIME+WINDOW)||issued.recent_until!=approval.approved_at+RECENT{return Err("manager_pairing_binding_changed".into());}
        let saved=SavedManager{origin:origin.into(),manager_id:issued.manager_id.clone(),device_id:issued.device_id.clone(),installation_id:issued.installation_id.clone(),public_key:identity.public_key(),id:issued.id.clone(),token:issued.token.clone(),expires_at:issued.expires_at,recent_until:issued.recent_until,scopes:issued.scopes.clone(),certificate_pem:certificate.map(|value|value.pem)};
        if let Err(error)=persist(&saved){
            let revoked=browser::<Value>(&client,origin,&session,"desktop-grants/revoke",json!({"id":saved.id,"password":password.as_str()})).await;
            return Err(if revoked.is_ok_and(|value| value == json!({"revoked": true})){error}else{"manager_grant_not_saved_revoke_in_manager".into()});
        }
        Ok(saved.view())
    }.await;
    let _ = browser::<Value>(&client, origin, &session, "logout", json!({})).await;
    result
}
struct Prepared {
    path: &'static str,
    body: Vec<u8>,
    proof: String,
}
fn request_message(
    saved: &SavedManager,
    proof: &Value,
    scope: &str,
    path: &str,
    body: &[u8],
) -> Result<String, String> {
    if !proof["timestamp"].is_u64() || !proof["nonce"].as_str().is_some_and(identifier) {
        return Err("manager_request_invalid".into());
    }
    Ok(json!([
        "frameleaf-manager/request/v1",
        saved.manager_id,
        saved.origin,
        saved.id,
        saved.device_id,
        saved.installation_id,
        scope,
        "POST",
        path,
        format!("{:x}", Sha256::digest(body)),
        proof["timestamp"],
        proof["nonce"],
        saved.token
    ])
    .to_string())
}
fn prepare(
    saved: &SavedManager,
    identity: &DeviceIdentity,
    command: &Command,
    now: u64,
    nonce: &str,
) -> Result<Prepared, String> {
    let (scope, path, body) = match command {
        Command::Status {} => (Scope::Status, "/manager-api/desktop/status", json!({})),
        Command::Backups {} => (Scope::Restore, "/manager-api/desktop/backups", json!({})),
        Command::Restore { review_id, key } => {
            if review_id.is_nil() || key.is_nil() {
                return Err("manager_request_invalid".into());
            }
            (
                Scope::Restore,
                "/manager-api/desktop/restore",
                json!({"reviewId":review_id,"key":key}),
            )
        }
        Command::RestoreOperation { id } | Command::ResumeRestore { id } => {
            if id.is_nil() {
                return Err("manager_request_invalid".into());
            }
            let path = if matches!(command, Command::RestoreOperation { .. }) {
                "/manager-api/desktop/restore-operation"
            } else {
                "/manager-api/desktop/resume-restore"
            };
            (Scope::Restore, path, json!({"id":id}))
        }
        Command::ReviewRestore { snapshot, key } => {
            if !hex(snapshot, 64) || key.is_nil() {
                return Err("manager_request_invalid".into());
            }
            (
                Scope::Restore,
                "/manager-api/desktop/review-restore",
                json!({"snapshot":snapshot,"key":key}),
            )
        }
        Command::RestoreReview { id, snapshot } => {
            if !hex(snapshot, 64) || id.is_nil() {
                return Err("manager_request_invalid".into());
            }
            (
                Scope::Restore,
                "/manager-api/desktop/restore-review",
                json!({"id":id}),
            )
        }
        Command::Control { action, key } => (
            action.scope(),
            "/manager-api/desktop/control",
            json!({"action":action,"key":key}),
        ),
        Command::Operation { id } => (
            Scope::Status,
            "/manager-api/desktop/operation",
            json!({"id":id}),
        ),
        Command::Resume { action, id } => (
            action.scope(),
            "/manager-api/desktop/resume",
            json!({"action":action,"id":id}),
        ),
    };
    prepare_scoped(saved, identity, (scope, path, body), now, nonce)
}

fn prepare_scoped(
    saved: &SavedManager,
    identity: &DeviceIdentity,
    (scope, path, body): (Scope, &'static str, Value),
    now: u64,
    nonce: &str,
) -> Result<Prepared, String> {
    canonical_origin(&saved.origin)?;
    saved.require_device(identity)?;
    if saved.expires_at <= now {
        return Err("manager_pairing_expired".into());
    }
    if !identifier(&saved.id)
        || !identifier(&saved.manager_id)
        || !hex(&saved.installation_id, 12)
        || !hex(&saved.token, 64)
        || !identifier(nonce)
        || now > 9_007_199_254_740_991
        || saved.expires_at > now.saturating_add(LIFETIME + WINDOW)
    {
        return Err("manager_credential_invalid".into());
    }
    if !saved.scopes.contains(&scope) {
        return Err("manager_scope_denied".into());
    }
    let body = body.to_string().into_bytes();
    let mut proof = json!({"protocolVersion":1,"managerId":saved.manager_id,"grantId":saved.id,"deviceId":saved.device_id,"token":saved.token,"timestamp":now,"nonce":nonce});
    let scope = serde_json::to_value(scope).map_err(|_| "manager_request_invalid")?;
    proof["signature"] = json!(identity.sign(&request_message(
        saved,
        &proof,
        scope.as_str().ok_or("manager_request_invalid")?,
        path,
        &body
    )?));
    Ok(Prepared {
        path,
        body,
        proof: STANDARD.encode(proof.to_string()),
    })
}
fn saved_client(saved: &SavedManager) -> Result<Client, String> {
    let fingerprint = saved
        .certificate_pem
        .as_deref()
        .map(certificate_fingerprint)
        .transpose()?;
    manager_client(
        &saved.origin,
        saved.certificate_pem.as_deref(),
        fingerprint.as_deref(),
    )
}
pub async fn send(
    saved: &SavedManager,
    identity: &DeviceIdentity,
    command: Command,
) -> Result<Value, String> {
    let request = prepare(
        saved,
        identity,
        &command,
        clock()?,
        &Uuid::new_v4().to_string(),
    )?;
    let value = send_prepared(saved, request).await?;
    validate_reply(saved, &command, value)
}

async fn send_prepared(saved: &SavedManager, request: Prepared) -> Result<Value, String> {
    reply(
        saved_client(saved)?
            .post(format!("{}{}", saved.origin, request.path))
            .header("content-type", "application/json")
            .header("x-frameleaf-manager-proof", request.proof)
            .body(request.body)
            .send()
            .await
            .map_err(|_| "manager_unreachable_or_certificate_invalid")?,
    )
    .await
}

#[cfg(all(windows, feature = "qualify-windows-media-move"))]
pub(crate) async fn send_qualification_move(
    saved: &SavedManager,
    identity: &DeviceIdentity,
    scope: Scope,
    path: &str,
    body: Value,
) -> Result<Value, String> {
    let path = match (scope, path) {
        (Scope::Status, "/manager-api/desktop/operation") => "/manager-api/desktop/operation",
        (
            Scope::Start | Scope::Stop | Scope::Restart | Scope::Backup,
            "/manager-api/desktop/control",
        ) => {
            let action: Action = serde_json::from_value(body["action"].clone())
                .map_err(|_| "manager_request_invalid")?;
            if action.scope() != scope {
                return Err("manager_scope_denied".into());
            }
            "/manager-api/desktop/control"
        }
        (Scope::MoveLibrary, "/manager-api/desktop/media-move-safety") => {
            "/manager-api/desktop/media-move-safety"
        }
        (Scope::MoveLibrary, "/manager-api/desktop/review-media-move") => {
            "/manager-api/desktop/review-media-move"
        }
        (Scope::MoveLibrary, "/manager-api/desktop/confirm-media-move") => {
            "/manager-api/desktop/confirm-media-move"
        }
        (Scope::MoveLibrary, "/manager-api/desktop/media-move-operation") => {
            "/manager-api/desktop/media-move-operation"
        }
        (Scope::MoveLibrary, "/manager-api/desktop/resume-media-move") => {
            "/manager-api/desktop/resume-media-move"
        }
        _ => return Err("manager_scope_denied".into()),
    };
    let request = prepare_scoped(
        saved,
        identity,
        (scope, path, body),
        clock()?,
        &Uuid::new_v4().to_string(),
    )?;
    send_prepared(saved, request).await
}

async fn grant_action(
    saved: &SavedManager,
    password: String,
    path: &str,
    field: &str,
) -> Result<(), String> {
    canonical_origin(&saved.origin)?;
    let password = Zeroizing::new(password);
    if password.is_empty() || password.len() > 256 {
        return Err("manager_login_details_invalid".into());
    }
    let client = saved_client(saved)?;
    let session = login(&client, &saved.origin, &password).await?;
    let result = browser::<Value>(
        &client,
        &saved.origin,
        &session,
        path,
        json!({"id":saved.id,"password":password.as_str()}),
    )
    .await;
    let _ = browser::<Value>(&client, &saved.origin, &session, "logout", json!({})).await;
    if result? == json!({field:true}) {
        Ok(())
    } else {
        Err("manager_response_invalid".into())
    }
}
pub async fn reauthenticate(saved: &SavedManager, password: String) -> Result<(), String> {
    grant_action(
        saved,
        password,
        "desktop-grants/reauthenticate",
        "authenticated",
    )
    .await
}
pub async fn disconnect(saved: &SavedManager, password: String) -> Result<(), String> {
    grant_action(saved, password, "desktop-grants/revoke", "revoked").await
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Operation<K = Action, const MAX: usize = 32> {
    id: String,
    kind: K,
    state: String,
    step: Option<String>,
    completed: Vec<String>,
    error: Option<String>,
    created_at: u64,
    updated_at: u64,
}
impl<K, const MAX: usize> Operation<K, MAX> {
    fn valid(&self) -> bool {
        let label = |value: &str| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'
                        || byte == b'_'
                })
        };
        identifier(&self.id)
            && matches!(
                self.state.as_str(),
                "running" | "interrupted" | "failed" | "complete"
            )
            && self.completed.len() <= MAX
            && self.completed.iter().all(|value| label(value))
            && self.step.as_deref().is_none_or(label)
            && self.error.as_deref().is_none_or(label)
            && self.created_at <= self.updated_at
            && self.updated_at <= 9_007_199_254_740_991
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RestoreKind {
    Restore,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagerIdentity {
    id: String,
    origin: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Installation {
    id: String,
    name: Option<String>,
    release: String,
    port: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    manager: ManagerIdentity,
    installation: Installation,
    operations: Vec<Operation>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Accepted {
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupEntry {
    id: String,
    time: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewAccepted {
    id: String,
    snapshot: String,
    installation_id: String,
    state: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewState {
    id: String,
    snapshot: String,
    installation_id: String,
    state: String,
    expires: u64,
    library_id: Option<String>,
    release: Option<String>,
    target_release: Option<String>,
    created_at: Option<u64>,
    media_included: Option<bool>,
    requires_runtime_change: Option<bool>,
}
fn public_error(operation: &mut Value) {
    if let Some(error) = operation["error"].as_str() {
        if !matches!(
            error,
            "operation_failed"
                | "operation_interrupted"
                | "no_installation"
                | "installation_changed"
                | "other_media_writer_detected"
                | "source_not_fenced"
                | "source_changed_review_again"
                | "previous_installation_not_fenced"
                | "previous_autostart_enabled"
                | "recovery_key_required"
                | "backup_incomplete"
                | "invalid_database_path"
                | "database_path_not_mounted"
        ) {
            operation["error"] = json!("manager_operation_failed");
        }
    }
}
fn validate_reply(
    saved: &SavedManager,
    command: &Command,
    mut value: Value,
) -> Result<Value, String> {
    let invalid = || "manager_response_invalid".to_string();
    match command {
        Command::RestoreOperation { id } => {
            let operation: Operation<RestoreKind, 64> =
                serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            if operation.id != id.to_string() || !operation.valid() {
                return Err(invalid());
            }
            public_error(&mut value);
        }
        Command::Restore { .. } | Command::ResumeRestore { .. } => {
            let accepted: Accepted =
                serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            if Uuid::parse_str(&accepted.id).is_err()
                || accepted.id == Uuid::nil().to_string()
                || matches!(command, Command::ResumeRestore {id} if accepted.id != id.to_string())
            {
                return Err(invalid());
            }
        }
        Command::Backups {} => {
            let entries: Vec<BackupEntry> =
                serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            if entries.len() > 1000
                || entries.iter().any(|entry| {
                    !hex(&entry.id, 64)
                        || entry.time.len() > 64
                        || time::OffsetDateTime::parse(
                            &entry.time,
                            &time::format_description::well_known::Rfc3339,
                        )
                        .is_err()
                })
            {
                return Err(invalid());
            }
        }
        Command::ReviewRestore { snapshot, key } => {
            let accepted: ReviewAccepted =
                serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            if accepted.id != key.to_string()
                || accepted.snapshot != *snapshot
                || accepted.installation_id != saved.installation_id
                || accepted.state != "preparing"
            {
                return Err(invalid());
            }
        }
        Command::RestoreReview { id, snapshot } => {
            let status: ReviewState =
                serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            if status.id != id.to_string()
                || status.snapshot != *snapshot
                || status.installation_id != saved.installation_id
                || status.expires > 9_007_199_254_740_991
            {
                return Err(invalid());
            }
            let release = |value: &str| {
                value.starts_with("frameleaf-v")
                    && value.len() <= 128
                    && value
                        .bytes()
                        .all(|v| v.is_ascii_alphanumeric() || b"._-".contains(&v))
            };
            if status.state == "prepared" {
                if !status.library_id.as_deref().is_some_and(|v| hex(v, 12))
                    || !status.release.as_deref().is_some_and(release)
                    || !status.target_release.as_deref().is_some_and(release)
                    || status.created_at.is_none_or(|v| v > 9_007_199_254_740_991)
                    || status.media_included != Some(false)
                    || status.requires_runtime_change.is_none()
                {
                    return Err(invalid());
                }
            } else if !matches!(
                status.state.as_str(),
                "preparing" | "failed" | "expired" | "interrupted"
            ) || value.as_object().is_none_or(|v| v.len() != 5)
            {
                return Err(invalid());
            }
        }
        Command::Status {} => {
            let status: Status = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            if status.manager.id != saved.manager_id
                || status.manager.origin != saved.origin
                || status.installation.id != saved.installation_id
            {
                return Err("manager_installation_changed".into());
            }
            if status.installation.port == 0
                || status
                    .installation
                    .name
                    .as_ref()
                    .is_some_and(|value| value.len() > 480)
                || status.installation.release.len() > 128
                || status.operations.len() > 100
                || !status.operations.iter().all(Operation::valid)
            {
                return Err(invalid());
            }
            for operation in value["operations"].as_array_mut().ok_or_else(invalid)? {
                public_error(operation);
            }
        }
        Command::Operation { id } => {
            let operation: Operation =
                serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            if operation.id != id.to_string() || !operation.valid() {
                return Err(invalid());
            }
            let _ = operation.kind;
            public_error(&mut value);
        }
        Command::Control { .. } | Command::Resume { .. } => {
            let accepted: Accepted =
                serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            if !identifier(&accepted.id)
                || matches!(command,Command::Resume{id,..}if accepted.id!=id.to_string())
            {
                return Err(invalid());
            }
        }
    }
    if value.to_string().contains(&saved.token) {
        return Err(invalid());
    }
    Ok(value)
}
#[cfg(test)]
#[path = "manager_tests.rs"]
mod tests;
