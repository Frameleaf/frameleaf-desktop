//! FD-77: this computer's own link to Frameleaf Cloud (FC-288). A computer links as a backup machine with
//! `computer: true`: the device flow (`frameleaf-link`, approved in the browser), `POST /v1/instances` with
//! its own Ed25519 key, then `private_key_jwt` instance tokens and DPoP on every call. The person's own
//! sign-in (`cloud_account`) is not used: the computer's backup identity is the instance the link creates.
//!
//! Everything here is blocking: the backup engine is synchronous, and runs on its own thread or process.
//! Errors are short codes the page explains (`computer_backup_*`, or Cloud's own envelope code).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use frameleaf_backup_core::snapshot_record::{public_jwk, Ed25519Jwk};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;

pub(crate) const LINK_CLIENT: &str = "frameleaf-link";
pub(crate) const OBJECT_FORMAT: &str = "frameleaf-repository/1";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
pub(crate) const UNREACHABLE: &str = "computer_backup_cloud_unreachable";

/// The Cloud this build talks to. A development build may name a local stand-in in `FRAMELEAF_CLOUD_URL`;
/// a release build always uses Frameleaf Cloud.
pub(crate) fn cloud_url() -> Result<Url, String> {
    let configured = std::env::var("FRAMELEAF_CLOUD_URL")
        .ok()
        .filter(|_| cfg!(debug_assertions));
    crate::cloud_account::parse_cloud_url(
        configured
            .as_deref()
            .unwrap_or("https://api.frameleaf.cloud"),
    )
}

/// What is saved (in the credential store) once the computer is linked.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Link {
    pub cloud: String,
    pub issuer: String,
    pub api: String,
    pub instance_id: String,
    /// The Ed25519 seed, unpadded base64url. Never leaves this computer.
    pub key: String,
}

pub(crate) fn new_key() -> SigningKey {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    SigningKey::from_bytes(&seed)
}

pub(crate) fn key_of(link: &Link) -> Result<SigningKey, String> {
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&link.key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("computer_backup_key_damaged")?;
    Ok(SigningKey::from_bytes(&seed))
}

pub(crate) fn encode_key(key: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(key.to_bytes())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn b64(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("JSON"))
}

fn jws(key: &SigningKey, header: Value, payload: Value) -> String {
    let input = format!("{}.{}", b64(&header), b64(&payload));
    let signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

/// RFC 9449 proof: `htu` is the URL without query or fragment.
fn dpop_proof(
    key: &SigningKey,
    method: &str,
    url: &Url,
    nonce: Option<&str>,
    token: Option<&str>,
) -> String {
    let jwk = public_jwk(&key.verifying_key());
    let mut htu = url.clone();
    htu.set_query(None);
    htu.set_fragment(None);
    let mut payload = json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": method,
        "htu": htu.as_str(),
        "iat": now(),
    });
    if let Some(nonce) = nonce {
        payload["nonce"] = json!(nonce);
    }
    if let Some(token) = token {
        payload["ath"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())));
    }
    jws(
        key,
        json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": {"kty": "OKP", "crv": "Ed25519", "x": jwk.x}}),
        payload,
    )
}

fn client() -> Client {
    Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .build()
        .expect("HTTP client")
}

/// Cloud's refusal, as its error envelope (`code`) or the token endpoint's OAuth `error`.
#[derive(Debug, Clone)]
pub(crate) struct Refusal {
    pub status: u16,
    pub code: String,
}

impl Refusal {
    pub(crate) fn code(&self) -> String {
        self.code.clone()
    }
}

fn refusal(status: u16, body: &Value) -> Refusal {
    let code = body
        .get("code")
        .or_else(|| body.get("error"))
        .and_then(Value::as_str)
        .filter(|code| {
            code.len() <= 64
                && code
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
        .unwrap_or("computer_backup_cloud_refused")
        .to_string();
    Refusal { status, code }
}

pub(crate) type Answer<T> = Result<T, Refusal>;

fn unreachable() -> Refusal {
    Refusal {
        status: 0,
        code: UNREACHABLE.into(),
    }
}

fn send(request: RequestBuilder) -> Answer<(u16, reqwest::header::HeaderMap, Value)> {
    let response = request.send().map_err(|_| unreachable())?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = response.bytes().map_err(|_| unreachable())?;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    Ok((status, headers, body))
}

/// Discovery names the issuer and api; without an answer the address alone decides them.
pub(crate) fn discover(cloud: &Url) -> (Url, Url) {
    let document = cloud
        .join(".well-known/frameleaf-services")
        .ok()
        .and_then(|url| client().get(url).send().ok())
        .filter(|response| response.status().is_success())
        .and_then(|response| response.json::<Value>().ok());
    let hosts = crate::cloud_account::hosts_from_discovery(cloud, document.as_ref());
    (hosts.issuer, hosts.api)
}

fn join(base: &str, path: &str) -> Result<Url, Refusal> {
    Url::parse(&format!("{}{path}", base.trim_end_matches('/'))).map_err(|_| unreachable())
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct DeviceStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri_complete: String,
    #[serde(default = "five")]
    pub interval: u64,
    pub expires_in: u64,
}
fn five() -> u64 {
    5
}

/// Step 1 of the device flow: the code the person approves in the browser.
pub(crate) fn device_start(
    issuer: &Url,
    name: &str,
    key: &SigningKey,
    platform: &str,
) -> Answer<DeviceStart> {
    let jkt = public_jwk(&key.verifying_key()).kid;
    let (status, _, body) = send(
        client()
            .post(join(issuer.as_str(), "/device/auth")?)
            .form(&[
                ("client_id", LINK_CLIENT),
                ("instance_name", name),
                ("version", env!("CARGO_PKG_VERSION")),
                ("jkt", &jkt),
                ("platform", platform),
            ]),
    )?;
    if status != 200 {
        return Err(refusal(status, &body));
    }
    serde_json::from_value(body).map_err(|_| unreachable())
}

pub(crate) enum Poll {
    Pending,
    SlowDown,
    Approved(String),
}

/// Step 3: asks once whether the person approved. `expired_token` and `access_denied` are refusals.
pub(crate) fn device_poll(issuer: &Url, device_code: &str) -> Answer<Poll> {
    let (status, _, body) = send(client().post(join(issuer.as_str(), "/token")?).form(&[
        ("grant_type", DEVICE_GRANT),
        ("device_code", device_code),
        ("client_id", LINK_CLIENT),
    ]))?;
    if status == 200 {
        return body["access_token"]
            .as_str()
            .map(|token| Poll::Approved(token.to_string()))
            .ok_or_else(unreachable);
    }
    match body["error"].as_str() {
        Some("authorization_pending") => Ok(Poll::Pending),
        Some("slow_down") => Ok(Poll::SlowDown),
        _ => Err(refusal(status, &body)),
    }
}

/// Step 4: links the computer. The answer must say it is a computer: an older Cloud drops the field and
/// links a Manager backup machine (which needs a licence), so that link is undone at once.
#[allow(clippy::too_many_arguments)]
pub(crate) fn register(
    issuer: &Url,
    api: &Url,
    cloud: &Url,
    link_token: &str,
    key: &SigningKey,
    instance_id: &str,
    name: &str,
    platform: &str,
) -> Result<Link, String> {
    let url = join(api.as_str(), "/v1/instances").map_err(|r| r.code())?;
    let jwk = public_jwk(&key.verifying_key());
    let body = json!({
        "instanceId": instance_id,
        "kind": "backup-machine",
        "computer": true,
        "name": name,
        "version": env!("CARGO_PKG_VERSION"),
        "platform": platform,
        "jwk": jwk,
        "bootId": uuid::Uuid::new_v4().to_string(),
        "capabilities": ["dpop"],
        "permissions": {"allowRemoteEnable": false, "allowBackupTrigger": true, "allowEntitlementRefresh": true},
    });
    let mut nonce: Option<String> = None;
    for _ in 0..2 {
        let proof = dpop_proof(key, "POST", &url, nonce.as_deref(), None);
        let (status, headers, answer) = send(
            client()
                .post(url.clone())
                .bearer_auth(link_token)
                .header("DPoP", proof)
                .json(&body),
        )
        .map_err(|r| r.code())?;
        if let Some(next) = headers.get("dpop-nonce").and_then(|v| v.to_str().ok()) {
            if answer["code"] == "use_dpop_nonce" && nonce.as_deref() != Some(next) {
                nonce = Some(next.to_string());
                continue;
            }
        }
        if status != 201 && status != 200 {
            return Err(refusal(status, &answer).code());
        }
        let link = Link {
            cloud: cloud.to_string(),
            issuer: issuer.to_string(),
            api: api.to_string(),
            instance_id: answer["instanceId"]
                .as_str()
                .unwrap_or(instance_id)
                .to_string(),
            key: encode_key(key),
        };
        if answer["kind"] != "backup-machine" || answer["computer"] != true {
            let _ = Cloud::new(link).call(Method::DELETE, "/v1/instance", None);
            return Err("computer_backup_cloud_too_old".into());
        }
        return Ok(link);
    }
    Err("use_dpop_nonce".into())
}

/// A linked computer talking to Cloud with its instance token.
pub(crate) struct Cloud {
    pub link: Link,
    key: SigningKey,
    client: Client,
    nonces: Mutex<HashMap<String, String>>,
    token: Mutex<Option<(String, Instant)>>,
}

impl Cloud {
    pub(crate) fn new(link: Link) -> Self {
        let key = key_of(&link).unwrap_or_else(|_| new_key());
        Cloud {
            link,
            key,
            client: client(),
            nonces: Mutex::default(),
            token: Mutex::default(),
        }
    }

    pub(crate) fn jwk(&self) -> Ed25519Jwk {
        public_jwk(&self.key.verifying_key())
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    fn nonce(&self, url: &Url) -> Option<String> {
        self.nonces
            .lock()
            .ok()?
            .get(&url.origin().ascii_serialization())
            .cloned()
    }

    fn keep_nonce(&self, url: &Url, headers: &reqwest::header::HeaderMap) {
        if let (Some(value), Ok(mut nonces)) = (
            headers.get("dpop-nonce").and_then(|v| v.to_str().ok()),
            self.nonces.lock(),
        ) {
            nonces.insert(url.origin().ascii_serialization(), value.to_string());
        }
    }

    /// A 10-minute instance token for `api`, renewed a minute early.
    fn token(&self) -> Answer<String> {
        if let Some((token, until)) = self.token.lock().map_err(|_| unreachable())?.clone() {
            if Instant::now() < until {
                return Ok(token);
            }
        }
        let url = join(&self.link.issuer, "/token")?;
        let kid = self.jwk().kid;
        let resource = self.link.api.trim_end_matches('/').to_string();
        for _ in 0..2 {
            let assertion = jws(
                &self.key,
                json!({"alg": "EdDSA", "typ": "JWT", "kid": kid}),
                json!({
                    "iss": self.link.instance_id, "sub": self.link.instance_id,
                    "aud": url.as_str(), "jti": uuid::Uuid::new_v4().to_string(),
                    "iat": now(), "exp": now() + 240,
                }),
            );
            let proof = dpop_proof(&self.key, "POST", &url, self.nonce(&url).as_deref(), None);
            let (status, headers, body) =
                send(self.client.post(url.clone()).header("DPoP", proof).form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", &self.link.instance_id),
                    ("client_assertion_type", ASSERTION_TYPE),
                    ("client_assertion", &assertion),
                    ("resource", &resource),
                    ("scope", "instance"),
                ]))?;
            let before = self.nonce(&url);
            self.keep_nonce(&url, &headers);
            if status == 400 && body["error"] == "use_dpop_nonce" && self.nonce(&url) != before {
                continue;
            }
            if status != 200 {
                return Err(refusal(status, &body));
            }
            let token = body["access_token"]
                .as_str()
                .ok_or_else(unreachable)?
                .to_string();
            let life = body["expires_in"]
                .as_u64()
                .unwrap_or(600)
                .saturating_sub(60)
                .max(30);
            *self.token.lock().map_err(|_| unreachable())? =
                Some((token.clone(), Instant::now() + Duration::from_secs(life)));
            return Ok(token);
        }
        Err(refusal(400, &json!({"error": "use_dpop_nonce"})))
    }

    /// One API call with `Authorization: DPoP` and a fresh proof; a nonce challenge or an expired token
    /// is retried once. Returns the status and body of any 2xx answer.
    pub(crate) fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Answer<(u16, Value)> {
        let url = join(&self.link.api, path)?;
        let mut retried = false;
        loop {
            let token = self.token()?;
            let proof = dpop_proof(
                &self.key,
                method.as_str(),
                &url,
                self.nonce(&url).as_deref(),
                Some(&token),
            );
            let mut request = self
                .client
                .request(method.clone(), url.clone())
                .header("Authorization", format!("DPoP {token}"))
                .header("DPoP", proof);
            if let Some(body) = &body {
                request = request.json(body);
            }
            let (status, headers, answer) = send(request)?;
            self.keep_nonce(&url, &headers);
            if (200..300).contains(&status) {
                return Ok((status, answer));
            }
            if status == 401 && !retried {
                retried = true;
                if answer["code"] != "use_dpop_nonce" {
                    if let Ok(mut token) = self.token.lock() {
                        *token = None;
                    }
                }
                continue;
            }
            return Err(refusal(status, &answer));
        }
    }

    pub(crate) fn get(&self, path: &str) -> Answer<Value> {
        self.call(Method::GET, path, None).map(|(_, body)| body)
    }

    pub(crate) fn post(&self, path: &str, body: Value) -> Answer<Value> {
        self.call(Method::POST, path, Some(body))
            .map(|(_, body)| body)
    }
}

/// The repository grant's storage and a capability credential (`BackupRepositoryGrantResponse`).
#[derive(Clone, Debug)]
pub(crate) struct Grant {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub read_only: bool,
    pub refresh_after: Duration,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

fn grant_of(body: &Value) -> Answer<Grant> {
    let text = |value: &Value| value.as_str().map(str::to_string).ok_or_else(unreachable);
    let credentials = &body["capability"]["credentials"];
    // BAK-001: storage the computer can trust keeps versions and can't delete them.
    let denies = body["policy"]["denies"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if body["versioning"] != true || !denies.iter().any(|d| d == "s3:DeleteObjectVersion") {
        return Err(Refusal {
            status: 0,
            code: "computer_backup_storage_unsafe".into(),
        });
    }
    Ok(Grant {
        endpoint: text(&body["endpoint"])?,
        region: text(&body["region"])?,
        bucket: text(&body["bucket"])?,
        read_only: body["readOnly"] == true,
        refresh_after: Duration::from_secs(
            body["capability"]["refreshAfterSec"]
                .as_u64()
                .unwrap_or(300),
        ),
        access_key_id: text(&credentials["accessKeyId"])?,
        secret_access_key: text(&credentials["secretAccessKey"])?,
        session_token: text(&credentials["sessionToken"])?,
    })
}

impl Cloud {
    /// The first enabled location, unless the grant already exists somewhere (then its own).
    fn location(&self) -> Answer<String> {
        if let Ok(meta) = self.get(&format!(
            "/v4/backup/grant?objectFormat={}",
            OBJECT_FORMAT.replace('/', "%2F")
        )) {
            if let Some(id) = meta["location"]["locationId"].as_str() {
                return Ok(id.to_string());
            }
        }
        self.get("/v4/backup/locations")?["locations"][0]["locationId"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Refusal {
                status: 0,
                code: "region-unavailable".into(),
            })
    }

    /// `upload` and `prune` name the run lease; `restore` names none.
    pub(crate) fn grant(&self, operation: &str, lease: Option<&str>) -> Answer<Grant> {
        let mut body = json!({"operation": operation, "objectFormat": OBJECT_FORMAT, "locationId": self.location()?});
        if let Some(lease) = lease {
            body["leaseId"] = json!(lease);
        }
        grant_of(&self.post("/v4/backup/grant", body)?)
    }

    pub(crate) fn rotate(&self, operation: &str, lease: Option<&str>) -> Answer<Grant> {
        let mut body = json!({"operation": operation, "objectFormat": OBJECT_FORMAT});
        if let Some(lease) = lease {
            body["leaseId"] = json!(lease);
        }
        grant_of(&self.post("/v4/backup/grant/rotate", body)?)
    }

    pub(crate) fn take_lease(&self, lease: &str, operation: &str) -> Answer<()> {
        self.post(
            "/v4/backup/lease",
            json!({"leaseId": lease, "operation": operation}),
        )
        .map(drop)
    }

    pub(crate) fn renew_lease(&self, lease: &str) -> Answer<()> {
        self.post("/v4/backup/lease/heartbeat", json!({"leaseId": lease}))
            .map(drop)
    }

    pub(crate) fn release_lease(&self, lease: &str) {
        let _ = self.call(
            Method::DELETE,
            &format!("/v4/backup/lease?leaseId={lease}"),
            None,
        );
    }
}
