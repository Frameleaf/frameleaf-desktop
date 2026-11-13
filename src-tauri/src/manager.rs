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
const REPLY_LIMIT: usize = 65_536;
/// Manager counts every paired request from one address, whatever it asks, against one
/// allowance: this many in a window that opens with the first of them. Past it Manager answers
/// `rate_limited` to all of them, status and start included, until the window closes.
const PAIRED_REQUESTS: u64 = 120;
const PAIRED_WINDOW: Duration = Duration::from_secs(600);
/// The first wait between two looks at something Manager is still doing; each later one is
/// twice the one before, up to `POLL_STEADY`.
const POLL_FIRST: Duration = Duration::from_millis(250);
/// The longest wait between two looks: polling that never ends spends half the allowance.
const POLL_STEADY: Duration =
    Duration::from_millis(PAIRED_WINDOW.as_millis() as u64 * 2 / PAIRED_REQUESTS);
/// How long to wait after the look numbered `asked` (from 0) found Manager still at it.
fn poll_delay(asked: u32) -> Duration {
    POLL_FIRST
        .saturating_mul(1 << asked.min(16))
        .min(POLL_STEADY)
}
/// A refused request, with how long Manager asked this app to wait when it said so.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refused {
    pub(crate) code: String,
    pub(crate) retry_after: Option<Duration>,
}
impl<T: Into<String>> From<T> for Refused {
    fn from(code: T) -> Self {
        Self {
            code: code.into(),
            retry_after: None,
        }
    }
}
/// Ask Manager on a paired route until it answers, inside its request allowance. Every loop
/// that waits on a paired route goes through here. `Ok(None)` from `ask` is "not yet" and is
/// asked again after a growing wait. `manager_rate_limited` says nothing about what was
/// asked: it is waited out, for as long as Manager said or else the steady wait, and asked
/// again. Any other refusal ends it. When `deadline` passes without an answer the result is
/// `unanswered`, never an answer; a wait Manager asked for that ends after it is not begun.
pub(crate) async fn paced<T, E, F>(
    deadline: tokio::time::Instant,
    unanswered: &str,
    ask: impl Fn() -> F,
) -> Result<T, String>
where
    E: Into<Refused>,
    F: std::future::Future<Output = Result<Option<T>, E>>,
{
    let mut asked = 0;
    loop {
        let reply = ask().await.map_err(Into::into);
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let wait = match reply {
            Ok(Some(answer)) => return Ok(answer),
            Ok(None) => poll_delay(asked),
            Err(Refused { code, retry_after }) if code == "manager_rate_limited" => {
                if retry_after.is_some_and(|wait| wait > remaining) {
                    return Err(unanswered.into());
                }
                retry_after.unwrap_or(POLL_STEADY).max(poll_delay(asked))
            }
            Err(refused) => return Err(refused.code),
        };
        if remaining.is_zero() {
            return Err(unanswered.into());
        }
        asked += 1;
        tokio::time::sleep(wait.min(remaining)).await;
    }
}
/// Status and backup lists grow with history; 1,000 backup entries alone exceed 64 KiB.
const LIST_LIMIT: usize = 1024 * 1024;
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
    /// What Manager's controller is doing now. Only for a Manager that declares
    /// `runtime-status`, and never from the interface.
    #[serde(skip_deserializing)]
    Runtime {
        nonce: Uuid,
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

    /// This computer's grant for the Manager it hosts follows that Manager to another loopback
    /// port and to the certificate that replaced the one the grant pins. Only a grant for this
    /// installation that pins `certificate` or the certificate it `replaced` is touched, and
    /// only between loopback origins on the same host. Returns whether anything changed.
    pub(crate) fn follow_local(
        &mut self,
        installation_id: &str,
        origin: &str,
        certificate: &str,
        replaced: Option<&str>,
    ) -> bool {
        let fingerprint = |pem: &str| certificate_fingerprint(pem).ok();
        let Some(pinned) = self.certificate_pem.as_deref().and_then(fingerprint) else {
            return false;
        };
        let loopback = |value: &str| {
            url::Url::parse(value).ok().filter(|url| {
                url.scheme() == "https"
                    && url.origin().ascii_serialization() == value
                    && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
            })
        };
        let same_host = match (loopback(&self.origin), loopback(origin)) {
            (Some(from), Some(to)) => from.host_str() == to.host_str(),
            _ => false,
        };
        let (Some(current), true, true) = (
            fingerprint(certificate),
            self.installation_id == installation_id,
            same_host,
        ) else {
            return false;
        };
        if pinned != current && replaced.and_then(fingerprint).as_ref() != Some(&pinned) {
            return false;
        }
        if self.origin == origin && pinned == current {
            return false;
        }
        self.origin = origin.into();
        self.certificate_pem = Some(certificate.into());
        true
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
/// A Manager on this computer or the home network is reached over plain HTTP: nobody can get a
/// certificate for a local host. Only a Manager reached over the internet must use HTTPS, because
/// HTTP would carry its password across networks the owner does not control.
pub fn require_encrypted(origin: &str) -> Result<(), String> {
    let url = normalize_manager(origin)?;
    let local = url.host().is_some_and(crate::connection::is_local_network);
    if url.scheme() == "http" && !local {
        return Err("manager_https_required".into());
    }
    Ok(())
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
        // System trust: the operating system's trust store, plus the bundled public roots.
        (None, None) => {}
        (Some(pem), Some(approved)) => {
            let der = certificate_der(pem)?;
            if !hex(approved, 64) || format!("{:x}", Sha256::digest(&der)) != approved {
                return Err("manager_certificate_approval_changed".into());
            }
            // A pinned Manager trusts only its approved certificate: no bundled or system roots.
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
/// A short lowercase code Manager may show to people; never a path, sentence or secret.
fn public_code(value: &str) -> bool {
    value.len() <= 64
        && value.starts_with(|first: char| first.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
        && !(value.len() >= 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}
/// Whether Manager's clock, from its `Date` header, is too far from ours for signed requests.
fn clock_skewed(date: Option<&str>, now: u64) -> bool {
    date.and_then(|value| {
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc2822).ok()
    })
    .is_some_and(|server| {
        // `Date` has one-second resolution, so allow a margin inside Manager's window.
        (server.unix_timestamp_nanos() / 1_000_000 - i128::from(now)).unsigned_abs()
            > u128::from(WINDOW - 5_000)
    })
}
async fn reply<T: DeserializeOwned>(response: Response) -> Result<T, String> {
    reply_limit(response, REPLY_LIMIT).await
}
async fn reply_limit<T: DeserializeOwned>(
    mut response: Response,
    limit: usize,
) -> Result<T, String> {
    let status = response.status();
    let skewed = clock().is_ok_and(|now| {
        let date = response.headers().get(reqwest::header::DATE);
        clock_skewed(date.and_then(|value| value.to_str().ok()), now)
    });
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "manager_response_interrupted")?
    {
        if bytes.len() + chunk.len() > limit {
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
            // Manager refuses a request signed outside its time window with the same code as a
            // revoked grant; its own clock tells the two apart.
            "desktop_grant_invalid" if skewed => "manager_clock_skew",
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
            // Manager's own code says more than a generic failure; Desktop's namespace stays ours.
            _ if public_code(code) && !code.starts_with("manager_") => code,
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
        || value.expires_at.checked_sub(value.approved_at) != Some(RECENT)
    {
        return Err("manager_pairing_binding_changed".into());
    }
    // Manager approved this moments ago, so a time outside the window means the clocks disagree.
    if value.approved_at > now.saturating_add(WINDOW) || value.expires_at <= now {
        return Err("manager_clock_skew".into());
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
    canonical_origin(origin)?;
    require_encrypted(origin)?;
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
    let mut scopes = SCOPES.to_vec();
    if allow_recovery {
        scopes.push(Scope::Restore);
    }
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
        Command::Runtime { nonce } => {
            if nonce.is_nil() {
                return Err("manager_request_invalid".into());
            }
            (
                Scope::Status,
                "/manager-api/desktop/runtime",
                json!({"nonce":nonce}),
            )
        }
    };
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
    send_paced(saved, identity, command)
        .await
        .map_err(|refused| refused.code)
}
/// Manager's `Retry-After`, in whole seconds, on the reply that refused a request.
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    value.trim().parse().ok().map(Duration::from_secs)
}
/// `send` for a caller that waits on Manager with `paced`: a refusal keeps how long Manager
/// asked this app to wait.
pub(crate) async fn send_paced(
    saved: &SavedManager,
    identity: &DeviceIdentity,
    command: Command,
) -> Result<Value, Refused> {
    let mut wait = None;
    let sent = async {
        let request = prepare(
            saved,
            identity,
            &command,
            clock()?,
            &Uuid::new_v4().to_string(),
        )?;
        let limit = if matches!(command, Command::Status {} | Command::Backups {}) {
            LIST_LIMIT
        } else {
            REPLY_LIMIT
        };
        let response = saved_client(saved)?
            .post(format!("{}{}", saved.origin, request.path))
            .header("content-type", "application/json")
            .header("x-frameleaf-manager-proof", request.proof)
            .body(request.body)
            .send()
            .await
            .map_err(|_| "manager_unreachable_or_certificate_invalid")?;
        wait = retry_after(response.headers());
        let value = reply_limit(response, limit).await?;
        validate_reply(saved, &command, value)
    }
    .await;
    sent.map_err(|code: String| Refused {
        code,
        retry_after: wait,
    })
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
/// Remove a pairing from this computer first, then try to revoke its grant in Manager.
/// An unreachable Manager is not an error; the result says whether Manager confirmed the revoke.
pub async fn remove(
    saved: Option<SavedManager>,
    password: String,
    forget: impl FnOnce() -> Result<(), String>,
) -> Result<bool, String> {
    forget()?;
    match saved {
        Some(saved) if !password.is_empty() => Ok(disconnect(&saved, password).await.is_ok()),
        _ => Ok(false),
    }
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
/// Operation kinds in a status list; a kind this Desktop does not know stays visible as `other`.
#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum StatusKind {
    Start,
    Stop,
    Restart,
    Backup,
    #[serde(other)]
    Other,
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
    operations: Vec<Operation<StatusKind>>,
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
    // Manager's own code passes through; anything that is not a plain code stays private.
    if operation["error"]
        .as_str()
        .is_some_and(|error| !public_code(error))
    {
        operation["error"] = json!("manager_operation_failed");
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Runtime {
    protocol_version: u32,
    nonce: String,
    installation_id: String,
    capabilities: Vec<String>,
    ports: RuntimePorts,
    photo_server: RuntimePhotoServer,
}
#[derive(Deserialize)]
struct RuntimePorts {
    manager: u16,
    api: u16,
    database: u16,
}
#[derive(Deserialize)]
struct RuntimePhotoServer {
    state: String,
    #[serde(default)]
    code: Option<String>,
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
            let shown = value["operations"].as_array_mut().ok_or_else(invalid)?;
            for (operation, parsed) in shown.iter_mut().zip(&status.operations) {
                if parsed.kind == StatusKind::Other {
                    operation["kind"] = json!("other");
                }
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
        Command::Runtime { nonce } => {
            // A later Manager may add fields here; what is read must be exactly as expected.
            let runtime: Runtime = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            if runtime.protocol_version != 1
                || runtime.nonce != nonce.to_string()
                || runtime.installation_id != saved.installation_id
                || [
                    runtime.ports.manager,
                    runtime.ports.api,
                    runtime.ports.database,
                ]
                .contains(&0)
                || !matches!(
                    runtime.photo_server.state.as_str(),
                    "running" | "starting" | "stopping" | "stopped" | "unknown"
                )
                || runtime
                    .photo_server
                    .code
                    .as_deref()
                    .is_some_and(|code| !public_code(code))
                || runtime.capabilities.len() > 64
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
