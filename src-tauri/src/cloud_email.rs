//! Frameleaf account sign-in and sign-up in the app. Sign-in is Cloud's sign-in in steps
//! (`/v1/app/sign-in/start` and `/verify`, then the token endpoint's sign-in grant with PKCE): an
//! emailed Verification Code, then a second step when the account has one. Sign-up, and sign-in
//! on a Cloud without those routes, is the phones' older flow (`/v1/app/email-auth/consents`,
//! `/start`, then the email-code grant). The PKCE verifier, the transaction and every proof stay
//! in this process's memory and are never written or logged; the window only sees each outcome.
use super::{
    discover_hosts, keep_sign_in, load, parse_cloud_url, pkce_challenge, random_token,
    token_request, CloudAccount, CloudHosts, TokenResponse, CLIENT_ID, CLOUD_LIMIT, CLOUD_ORIGIN,
};
use crate::transport;
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Mutex;
use tauri::{State, WebviewWindow};
use url::Url;
use zeroize::Zeroizing;

const EMAIL_CODE_GRANT: &str = "urn:frameleaf:params:oauth:grant-type:email-code";
const SIGN_IN_GRANT: &str = "urn:frameleaf:params:oauth:grant-type:sign-in";
/// The second steps this window can show. A passkey is finished in the browser.
const SECOND_STEPS: [&str; 3] = ["totp", "recovery_code", "password"];

enum Flow {
    /// The older routes: one emailed code, redeemed by the email-code grant.
    Legacy { attempt_id: String },
    /// Sign-in in steps: the transaction, and what completes its current step.
    Steps {
        transaction: Zeroizing<String>,
        methods: Vec<String>,
    },
}

struct Pending {
    flow: Flow,
    verifier: Zeroizing<String>,
    sign_up: bool,
    cloud: Url,
    hosts: CloudHosts,
}

/// The one sign-in under way, if any. A new start replaces it.
#[derive(Default)]
pub(crate) struct EmailAttempt(Mutex<Option<Pending>>);

#[derive(Serialize, Deserialize)]
pub(crate) struct Consent {
    version: String,
    text: String,
    content: String,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Consents {
    tos: Consent,
    privacy: Consent,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Registration {
    country: String,
    #[serde(default)]
    name: String,
    terms_version: String,
    privacy_version: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Started {
    disclosure: Option<String>,
    /// The masked address Cloud sent the Verification Code to, when it says.
    sent_to: Option<String>,
}

/// What a proof led to: signed in, another step, or a step only the browser can finish.
/// `recovery`: Cloud says the person may have none of the methods to hand, so the step also
/// offers account recovery.
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub(crate) enum Completed {
    Done {
        account: CloudAccount,
    },
    Next {
        methods: Vec<String>,
        recovery: bool,
    },
    Browser {
        recovery: bool,
    },
}

enum Advanced {
    Token(TokenResponse),
    Next {
        methods: Vec<String>,
        recovery: bool,
    },
    Browser {
        recovery: bool,
    },
}

/// One answer of the sign-in in steps (Cloud's `AppSignInAnswer`).
#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum Answer {
    Next {
        transaction: String,
        methods: Vec<String>,
        #[serde(default, rename = "sentTo")]
        sent_to: Option<String>,
        #[serde(default)]
        exists: Option<bool>,
        /// The person can't complete this step with what is offered: recovery is the way on.
        #[serde(default)]
        recovery: bool,
    },
    Done {
        code: String,
    },
}

/// Cloud's error envelope, as far as this flow reads it.
#[derive(Deserialize, Default)]
struct Refusal {
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    data: Option<RefusalData>,
}
#[derive(Deserialize, Default)]
struct RefusalData {
    #[serde(default)]
    recovery: bool,
}

async fn refusal(response: Response) -> Refusal {
    response
        .bytes()
        .await
        .ok()
        .filter(|body| body.len() <= 65_536)
        .and_then(|body| serde_json::from_slice(&body).ok())
        .unwrap_or_default()
}

async fn post(
    client: &Client,
    hosts: &CloudHosts,
    path: &str,
    body: &Value,
) -> Result<Response, String> {
    let url = hosts
        .issuer
        .join(path)
        .map_err(|_| "cloud_address_invalid")?;
    client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|_| "cloud_unreachable".into())
}

/// One call of the sign-in in steps: its answer, or the refusal's status and envelope.
async fn step(
    client: &Client,
    hosts: &CloudHosts,
    path: &str,
    body: &Value,
) -> Result<Result<Answer, (u16, Refusal)>, String> {
    let response = post(client, hosts, path, body).await?;
    let status = response.status();
    if !status.is_success() {
        return Ok(Err((status.as_u16(), refusal(response).await)));
    }
    transport::json_limit(response, CLOUD_LIMIT)
        .await
        .map(Ok)
        .map_err(|_| "cloud_email_unavailable".into())
}

/// A transaction or sign-in code as Cloud mints them.
fn opaque(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn wrong_proof(method: &str) -> &'static str {
    match method {
        "password" => "cloud_email_wrong_password",
        "recovery_code" => "cloud_email_wrong_recovery_code",
        _ => "cloud_email_wrong_code",
    }
}

/// The proof as Cloud takes it, when it has the method's shape.
fn proof_for(method: &str, proof: &str) -> Option<Zeroizing<String>> {
    let trimmed = proof.trim();
    let (value, ok) = match method {
        "email_code" | "totp" => (
            trimmed,
            trimmed.len() == 6 && trimmed.chars().all(|c| c.is_ascii_digit()),
        ),
        "recovery_code" => (
            trimmed,
            (1..=64).contains(&trimmed.len())
                && !trimmed.chars().any(|c| c.is_whitespace() || c.is_control()),
        ),
        // A password is sent as typed.
        "password" => (proof, (1..=256).contains(&proof.chars().count())),
        _ => (trimmed, false),
    };
    ok.then(|| Zeroizing::new(value.to_string()))
}

/// The error for a refused `/verify` (`ApiError` envelope) by status and detail.
fn verify_refusal(status: u16, detail: Option<&str>, method: &str) -> String {
    match (status, detail) {
        (_, Some("signup-required")) => "cloud_email_no_account",
        (_, Some("second-factor-locked")) => "cloud_email_second_step_locked",
        (401 | 422, _) => wrong_proof(method),
        // The transaction ended, or the step it was at changed: a new start is the way on.
        (404 | 409, _) => "cloud_email_expired_code",
        (429, _) => "cloud_email_rate_limited",
        (403, _) => "cloud_email_account_blocked",
        _ => "cloud_email_unavailable",
    }
    .into()
}

/// Whether the same sign-in can take another proof after this error.
fn can_retry(error: &str) -> bool {
    matches!(
        error,
        "cloud_email_wrong_code"
            | "cloud_email_wrong_recovery_code"
            | "cloud_email_wrong_password"
            | "cloud_email_rate_limited"
            | "cloud_email_second_step_locked"
            | "cloud_unreachable"
    )
}

/// The error for a refused `/start` (`ApiError` envelope) by status and detail.
fn start_refusal(status: u16, detail: Option<&str>, sign_up: bool) -> String {
    match (status, detail) {
        (_, Some("signup-consent-changed")) => "cloud_email_consent_changed",
        (409, _) if sign_up => "cloud_email_consent_changed",
        (429, _) => "cloud_email_rate_limited",
        (422, _) => "cloud_email_invalid",
        _ => "cloud_email_unavailable",
    }
    .into()
}

/// The error for a refused code: the token endpoint's OAuth `error`, then the HTTP status.
fn code_refusal(code: &str, sign_up: bool) -> String {
    match code.strip_prefix("cloud_token_").unwrap_or(code) {
        "invalid_otp" => "cloud_email_wrong_code",
        "expired_otp" => "cloud_email_expired_code",
        "invalid_grant" => "cloud_email_expired_code",
        "signup_required" => "cloud_email_no_account",
        "signup_consent_changed" => "cloud_email_consent_changed",
        "signup_paused" => "cloud_email_signup_paused",
        "slow_down" | "cloud_http_429" => "cloud_email_rate_limited",
        "email_unverified" => "cloud_email_unverified",
        "cloud_http_409" if sign_up => "cloud_email_consent_changed",
        _ => "cloud_email_unavailable",
    }
    .into()
}

fn valid_email(email: &str) -> bool {
    email.len() <= 254
        && email
            .split_once('@')
            .is_some_and(|(user, domain)| !user.is_empty() && domain.contains('.'))
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// The terms and privacy notice a new account accepts, with their versions.
#[tauri::command]
pub(crate) async fn cloud_email_consents(window: WebviewWindow) -> Result<Consents, String> {
    crate::require_local(&window)?;
    let client = transport::client()?;
    let hosts = discover_hosts(&client, &parse_cloud_url(CLOUD_ORIGIN)?).await;
    let url = hosts
        .issuer
        .join("v1/app/email-auth/consents")
        .map_err(|_| "cloud_address_invalid")?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "cloud_unreachable")?;
    transport::json_limit(response, CLOUD_LIMIT)
        .await
        .map_err(|_| "cloud_email_unavailable".into())
}

/// Starts a sign-in in steps and asks for the emailed Verification Code. `None`: this Cloud has
/// only the older routes.
async fn start_steps(
    client: &Client,
    hosts: &CloudHosts,
    email: &str,
    verifier: &str,
) -> Result<Option<(Flow, Started)>, String> {
    let body = json!({
        "email": email,
        "clientId": CLIENT_ID,
        "codeChallenge": pkce_challenge(verifier),
    });
    let transaction = match step(client, hosts, "v1/app/sign-in/start", &body).await? {
        Ok(Answer::Next {
            exists: Some(false),
            ..
        }) => return Err("cloud_email_no_account".into()),
        Ok(Answer::Next {
            transaction,
            methods,
            ..
        }) if opaque(&transaction) && methods.iter().any(|m| m == "email_code") => {
            Zeroizing::new(transaction)
        }
        Ok(_) => return Err("cloud_email_unavailable".into()),
        Err((404 | 405 | 501, _)) => return Ok(None),
        Err((status, _)) => return Err(start_refusal(status, None, false)),
    };
    // `email_code` without a proof sends the code.
    let body = json!({ "transaction": transaction.as_str(), "method": "email_code" });
    match step(client, hosts, "v1/app/sign-in/verify", &body).await? {
        Ok(Answer::Next {
            transaction,
            methods,
            sent_to,
            ..
        }) if opaque(&transaction) => Ok(Some((
            Flow::Steps {
                transaction: Zeroizing::new(transaction),
                methods,
            },
            Started {
                disclosure: None,
                sent_to: sent_to.filter(|address| address.len() <= 254),
            },
        ))),
        Ok(_) => Err("cloud_email_unavailable".into()),
        Err((status, refused)) => Err(verify_refusal(
            status,
            refused.detail.as_deref(),
            "email_code",
        )),
    }
}

/// The older start: a sign-up, or a sign-in on a Cloud without sign-in in steps.
async fn start_legacy(
    client: &Client,
    hosts: &CloudHosts,
    email: &str,
    registration: Option<&Registration>,
    verifier: &str,
) -> Result<(Flow, Started), String> {
    let mut body = json!({
        "purpose": if registration.is_some() { "sign-up" } else { "sign-in" },
        "email": email,
        "codeChallenge": pkce_challenge(verifier),
    });
    if let Some(r) = registration {
        body["country"] = r.country.clone().into();
        if !r.name.trim().is_empty() {
            body["name"] = r.name.trim().into();
        }
        body["consent"] = json!({ "tos": r.terms_version, "privacy": r.privacy_version });
    }
    let response = post(client, hosts, "v1/app/email-auth/start", &body).await?;
    let status = response.status();
    if !status.is_success() {
        let detail = refusal(response).await.detail;
        return Err(start_refusal(
            status.as_u16(),
            detail.as_deref(),
            registration.is_some(),
        ));
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Answer {
        attempt_id: String,
        disclosure: Option<String>,
    }
    let answer: Answer = transport::json_limit(response, CLOUD_LIMIT)
        .await
        .map_err(|_| "cloud_email_unavailable")?;
    if answer.attempt_id.is_empty() || answer.attempt_id.len() > 256 {
        return Err("cloud_email_unavailable".into());
    }
    Ok((
        Flow::Legacy {
            attempt_id: answer.attempt_id,
        },
        Started {
            disclosure: answer.disclosure,
            sent_to: None,
        },
    ))
}

/// Sends the Verification Code: in steps for a sign-in when Cloud has them, else the older way.
async fn begin(
    client: &Client,
    hosts: &CloudHosts,
    email: &str,
    registration: Option<&Registration>,
    verifier: &str,
) -> Result<(Flow, Started), String> {
    if registration.is_none() {
        if let Some(started) = start_steps(client, hosts, email, verifier).await? {
            return Ok(started);
        }
    }
    start_legacy(client, hosts, email, registration, verifier).await
}

fn redeemed(result: Result<TokenResponse, String>, sign_up: bool) -> Result<Advanced, String> {
    match result {
        Ok(token) => Ok(Advanced::Token(token)),
        // The account has a passkey or an authenticator this grant can't ask for.
        Err(error) if error == "cloud_token_second_step_required" => {
            Ok(Advanced::Browser { recovery: false })
        }
        Err(error) => Err(code_refusal(&error, sign_up)),
    }
}

/// Gives Cloud one proof for the sign-in under way.
async fn advance(
    client: &Client,
    pending: &mut Pending,
    method: &str,
    proof: &str,
) -> Result<Advanced, String> {
    let (transaction, methods) = match &mut pending.flow {
        Flow::Legacy { attempt_id } => {
            if method != "email_code" {
                return Err(wrong_proof(method).into());
            }
            let result = token_request(
                client,
                &pending.hosts.issuer,
                &[
                    ("grant_type", EMAIL_CODE_GRANT),
                    ("client_id", CLIENT_ID),
                    ("attempt_id", attempt_id.as_str()),
                    ("otp", proof),
                    ("code_verifier", pending.verifier.as_str()),
                ],
            )
            .await;
            return redeemed(result, pending.sign_up);
        }
        Flow::Steps {
            transaction,
            methods,
        } => (transaction, methods),
    };
    if !methods.iter().any(|offered| offered == method) {
        return Err(wrong_proof(method).into());
    }
    let body = json!({ "transaction": transaction.as_str(), "method": method, "proof": proof });
    match step(client, &pending.hosts, "v1/app/sign-in/verify", &body).await? {
        Ok(Answer::Done { code }) if opaque(&code) => {
            let code = Zeroizing::new(code);
            let result = token_request(
                client,
                &pending.hosts.issuer,
                &[
                    ("grant_type", SIGN_IN_GRANT),
                    ("client_id", CLIENT_ID),
                    ("code", code.as_str()),
                    ("code_verifier", pending.verifier.as_str()),
                ],
            )
            .await;
            redeemed(result, false)
        }
        Ok(Answer::Next {
            transaction: next,
            methods: offered,
            recovery,
            ..
        }) if opaque(&next) => {
            let shown: Vec<String> = offered
                .into_iter()
                .filter(|offered| SECOND_STEPS.contains(&offered.as_str()))
                .collect();
            // Only a passkey completes this step.
            if shown.is_empty() {
                return Ok(Advanced::Browser { recovery });
            }
            *transaction = Zeroizing::new(next);
            *methods = shown.clone();
            Ok(Advanced::Next {
                methods: shown,
                recovery,
            })
        }
        Ok(_) => Err("cloud_email_unavailable".into()),
        Err((409, refused)) if refused.detail.as_deref() == Some("second-step-unavailable") => {
            Ok(Advanced::Browser {
                recovery: refused.data.is_some_and(|data| data.recovery),
            })
        }
        Err((status, refused)) => Err(verify_refusal(status, refused.detail.as_deref(), method)),
    }
}

/// Sends a Verification Code to `email`: a sign-in, or a sign-up when `registration` is given.
#[tauri::command]
pub(crate) async fn cloud_email_start(
    window: WebviewWindow,
    attempt: State<'_, EmailAttempt>,
    email: String,
    registration: Option<Registration>,
) -> Result<Started, String> {
    crate::require_local(&window)?;
    let email = email.trim().to_string();
    if !valid_email(&email) {
        return Err("cloud_email_invalid".into());
    }
    if let Some(r) = &registration {
        if r.country.len() != 2
            || !r.country.chars().all(|c| c.is_ascii_uppercase())
            || r.name.chars().count() > 100
            || r.terms_version.len() > 32
            || r.privacy_version.len() > 32
        {
            return Err("cloud_email_invalid".into());
        }
    }
    // Same rule as the browser sign-in: one Frameleaf account at a time.
    if load()?.is_some() {
        return Err("cloud_sign_out_before_switching_accounts".into());
    }
    let cloud = parse_cloud_url(CLOUD_ORIGIN)?;
    let client = transport::client()?;
    let hosts = discover_hosts(&client, &cloud).await;
    let verifier = Zeroizing::new(random_token(48));
    let (flow, started) = begin(&client, &hosts, &email, registration.as_ref(), &verifier).await?;
    *attempt.0.lock().map_err(|_| "cloud_email_unavailable")? = Some(Pending {
        flow,
        verifier,
        sign_up: registration.is_some(),
        cloud,
        hosts,
    });
    Ok(started)
}

/// Gives one proof (`method`: `email_code`, `totp`, `recovery_code` or `password`) for the sign-in
/// `cloud_email_start` began, and keeps the sign-in once Cloud says it is done.
#[tauri::command]
pub(crate) async fn cloud_email_complete(
    window: WebviewWindow,
    attempt: State<'_, EmailAttempt>,
    method: String,
    proof: String,
) -> Result<Completed, String> {
    crate::require_local(&window)?;
    let proof = Zeroizing::new(proof);
    let proof = proof_for(&method, &proof).ok_or_else(|| wrong_proof(&method))?;
    let client = transport::client()?;
    let mut pending = attempt
        .0
        .lock()
        .map_err(|_| "cloud_email_unavailable")?
        .take()
        .ok_or("cloud_email_expired_code")?;
    let keep = |pending: Pending| {
        if let Ok(mut slot) = attempt.0.lock() {
            slot.get_or_insert(pending);
        }
    };
    match advance(&client, &mut pending, &method, &proof).await {
        Ok(Advanced::Token(token)) => {
            keep_sign_in(&client, &window, &pending.cloud, &pending.hosts, token)
                .await
                .map(|account| Completed::Done { account })
        }
        Ok(Advanced::Next { methods, recovery }) => {
            keep(pending);
            Ok(Completed::Next { methods, recovery })
        }
        Ok(Advanced::Browser { recovery }) => Ok(Completed::Browser { recovery }),
        Err(error) => {
            // A mistyped proof can be corrected; anything else needs a new start.
            if can_retry(&error) {
                keep(pending);
            }
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::Arc,
    };

    type Asked = Arc<Mutex<Vec<(String, String)>>>;

    /// A fake Cloud on loopback: `answer` gets each request's path and body; all are recorded.
    fn fake_cloud(
        answer: impl Fn(&str, &str) -> (u16, Value) + Send + 'static,
    ) -> (CloudHosts, Asked) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let asked = Asked::default();
        let seen = asked.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut head = Vec::new();
                let mut byte = [0];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                if head.is_empty() {
                    continue;
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let length = head
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                let path = head.split_whitespace().nth(1).unwrap().to_string();
                let body = String::from_utf8(body).unwrap();
                let (status, reply) = answer(&path, &body);
                seen.lock().unwrap().push((path, body));
                let reply = reply.to_string();
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{reply}",
                        reply.len()
                    )
                    .as_bytes(),
                );
            }
        });
        (
            CloudHosts {
                issuer: url.clone(),
                api: url,
            },
            asked,
        )
    }

    fn tokens() -> (u16, Value) {
        (
            200,
            json!({ "access_token": "access", "refresh_token": "refresh", "expires_in": 600 }),
        )
    }
    fn done() -> (u16, Value) {
        (
            200,
            json!({ "status": "done", "code": "done-code", "grantType": SIGN_IN_GRANT, "methods": ["email_code"], "acr": "urn:frameleaf:acr:basic" }),
        )
    }
    fn refused(status: u16, code: &str, detail: Option<&str>) -> (u16, Value) {
        (
            status,
            json!({ "code": code, "message": "No.", "retryable": false, "detail": detail }),
        )
    }

    /// A Cloud with sign-in in steps; `proved` answers each `/verify` that carries a proof.
    fn stepped_cloud(
        proved: impl Fn(&Value) -> (u16, Value) + Send + 'static,
    ) -> (CloudHosts, Asked) {
        fake_cloud(move |path, body| match path {
            "/v1/app/sign-in/start" => (
                200,
                json!({ "status": "next", "transaction": "tx-start", "methods": ["email_code"], "exists": true }),
            ),
            "/v1/app/sign-in/verify" => {
                let body: Value = serde_json::from_str(body).unwrap();
                if body.get("proof").is_none() {
                    assert_eq!(body["transaction"], "tx-start");
                    return (
                        200,
                        json!({ "status": "next", "transaction": "tx-sent", "methods": ["email_code"], "sentTo": "a•••@example.com" }),
                    );
                }
                proved(&body)
            }
            "/token" => tokens(),
            _ => refused(404, "not-found", None),
        })
    }

    /// An account with an authenticator: the emailed code, then 654321 or the Recovery Code.
    fn two_step(body: &Value) -> (u16, Value) {
        let field = |name: &str| body[name].as_str().unwrap().to_string();
        match (
            field("transaction").as_str(),
            field("method").as_str(),
            field("proof").as_str(),
        ) {
            ("tx-sent", "email_code", "123456") => (
                200,
                json!({ "status": "next", "transaction": "tx-second", "methods": ["totp", "recovery_code", "passkey"], "recovery": true }),
            ),
            ("tx-second", "totp", "654321") | ("tx-second", "recovery_code", "ABCDE-FGHJK") => {
                done()
            }
            _ => refused(401, "code-invalid", None),
        }
    }

    async fn start(hosts: &CloudHosts) -> (Pending, Started) {
        let client = transport::client().unwrap();
        let verifier = Zeroizing::new(random_token(48));
        let (flow, started) = begin(&client, hosts, "ada@example.com", None, &verifier)
            .await
            .unwrap();
        let pending = Pending {
            flow,
            verifier,
            sign_up: false,
            cloud: hosts.api.clone(),
            hosts: hosts.clone(),
        };
        (pending, started)
    }
    async fn give(pending: &mut Pending, method: &str, proof: &str) -> Result<Advanced, String> {
        advance(&transport::client().unwrap(), pending, method, proof).await
    }
    fn paths(asked: &Asked) -> Vec<String> {
        asked
            .lock()
            .unwrap()
            .iter()
            .map(|(path, _)| path.clone())
            .collect()
    }

    #[tokio::test]
    async fn an_emailed_code_alone_signs_in_through_the_steps() {
        let (hosts, asked) = stepped_cloud(|_| done());
        let (mut pending, started) = start(&hosts).await;
        assert_eq!(started.sent_to.as_deref(), Some("a•••@example.com"));
        let token = match give(&mut pending, "email_code", "123456").await {
            Ok(Advanced::Token(token)) => token,
            _ => panic!("the code should finish the sign-in"),
        };
        assert_eq!(token.refresh_token.as_deref(), Some("refresh"));
        let asked = asked.lock().unwrap();
        assert_eq!(
            asked
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            [
                "/v1/app/sign-in/start",
                "/v1/app/sign-in/verify",
                "/v1/app/sign-in/verify",
                "/token"
            ]
        );
        let started: Value = serde_json::from_str(&asked[0].1).unwrap();
        assert_eq!(started["clientId"], "frameleaf-desktop");
        assert_eq!(started["codeChallenge"], pkce_challenge(&pending.verifier));
        let proof: Value = serde_json::from_str(&asked[2].1).unwrap();
        assert_eq!(
            proof,
            json!({ "transaction": "tx-sent", "method": "email_code", "proof": "123456" })
        );
        let form = &asked[3].1;
        assert!(form.contains("grant_type=urn%3Aframeleaf%3Aparams%3Aoauth%3Agrant-type%3Asign-in"));
        assert!(form.contains("code=done-code"));
        assert!(form.contains(&format!("code_verifier={}", pending.verifier.as_str())));
    }

    #[tokio::test]
    async fn an_authenticator_code_completes_the_second_step() {
        let (hosts, asked) = stepped_cloud(two_step);
        let (mut pending, _) = start(&hosts).await;
        // The passkey Cloud also offers is not something this window can do.
        match give(&mut pending, "email_code", "123456").await {
            Ok(Advanced::Next { methods, recovery }) => {
                assert_eq!(methods, ["totp", "recovery_code"]);
                // Cloud said the person may have none of these: the step offers recovery too.
                assert!(recovery);
                let shown = serde_json::to_value(Completed::Next { methods, recovery }).unwrap();
                assert_eq!(
                    shown,
                    json!({ "status": "next", "methods": ["totp", "recovery_code"], "recovery": true })
                );
            }
            _ => panic!("a second step should be asked for"),
        }
        // A wrong code can be corrected in the same sign-in.
        let wrong = give(&mut pending, "totp", "000000").await.err().unwrap();
        assert_eq!(wrong, "cloud_email_wrong_code");
        assert!(can_retry(&wrong));
        assert!(matches!(
            give(&mut pending, "totp", "654321").await,
            Ok(Advanced::Token(_))
        ));
        assert_eq!(paths(&asked).last().unwrap(), "/token");
    }

    #[tokio::test]
    async fn a_recovery_code_completes_the_second_step() {
        let (hosts, _) = stepped_cloud(two_step);
        let (mut pending, _) = start(&hosts).await;
        assert!(matches!(
            give(&mut pending, "email_code", "123456").await,
            Ok(Advanced::Next { .. })
        ));
        let wrong = give(&mut pending, "recovery_code", "NOPE").await;
        assert_eq!(wrong.err().unwrap(), "cloud_email_wrong_recovery_code");
        assert!(matches!(
            give(&mut pending, "recovery_code", "ABCDE-FGHJK").await,
            Ok(Advanced::Token(_))
        ));
        // A method Cloud did not offer for this step is never sent.
        let (hosts, asked) = stepped_cloud(two_step);
        let (mut pending, _) = start(&hosts).await;
        assert!(give(&mut pending, "password", "hunter2").await.is_err());
        assert_eq!(paths(&asked).len(), 2);
    }

    #[tokio::test]
    async fn a_step_only_a_passkey_completes_hands_off_to_the_browser() {
        // Cloud's answer for a passkey-only account on the desktop app.
        let (hosts, asked) = stepped_cloud(|_| {
            let mut answer = refused(409, "forbidden", Some("second-step-unavailable"));
            answer.1["data"] = json!({ "recovery": true });
            answer
        });
        let (mut pending, _) = start(&hosts).await;
        assert!(matches!(
            give(&mut pending, "email_code", "123456").await,
            Ok(Advanced::Browser { recovery: true })
        ));
        assert!(!paths(&asked).contains(&"/token".to_string()));
        // And a `next` that offers nothing but the passkey.
        let (hosts, _) = stepped_cloud(|_| {
            (
                200,
                json!({ "status": "next", "transaction": "tx-second", "methods": ["passkey"], "recovery": true }),
            )
        });
        let (mut pending, _) = start(&hosts).await;
        assert!(matches!(
            give(&mut pending, "email_code", "123456").await,
            Ok(Advanced::Browser { recovery: true })
        ));
        // After a Password, Cloud offers no recovery: none is shown.
        let (hosts, _) = stepped_cloud(|_| {
            (
                200,
                json!({ "status": "next", "transaction": "tx-second", "methods": ["totp"] }),
            )
        });
        let (mut pending, _) = start(&hosts).await;
        assert!(matches!(
            give(&mut pending, "email_code", "123456").await,
            Ok(Advanced::Next {
                recovery: false,
                ..
            })
        ));
        assert_eq!(
            serde_json::to_value(Completed::Browser { recovery: false }).unwrap(),
            json!({ "status": "browser", "recovery": false })
        );
    }

    /// A Cloud from before sign-in in steps; `token` answers its email-code grant.
    fn legacy_cloud(token: fn() -> (u16, Value)) -> (CloudHosts, Asked) {
        fake_cloud(move |path, _| match path {
            "/v1/app/email-auth/start" => (
                200,
                json!({ "attemptId": "attempt-1", "expiresAt": "2026-11-12T00:00:00Z", "disclosure": null }),
            ),
            "/token" => token(),
            _ => refused(404, "not-found", None),
        })
    }

    #[tokio::test]
    async fn a_cloud_with_only_the_older_routes_still_signs_in() {
        let (hosts, asked) = legacy_cloud(tokens);
        let (mut pending, _) = start(&hosts).await;
        assert!(matches!(pending.flow, Flow::Legacy { .. }));
        assert!(matches!(
            give(&mut pending, "email_code", "123456").await,
            Ok(Advanced::Token(_))
        ));
        let asked = asked.lock().unwrap();
        assert_eq!(
            asked
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            [
                "/v1/app/sign-in/start",
                "/v1/app/email-auth/start",
                "/token"
            ]
        );
        let started: Value = serde_json::from_str(&asked[1].1).unwrap();
        assert_eq!(started["purpose"], "sign-in");
        let form = &asked[2].1;
        assert!(form.contains("grant-type%3Aemail-code"));
        assert!(form.contains("attempt_id=attempt-1") && form.contains("otp=123456"));
    }

    #[tokio::test]
    async fn a_second_step_the_grant_cannot_ask_for_is_never_the_generic_failure() {
        fn second_step_required() -> (u16, Value) {
            (400, json!({ "error": "second_step_required" }))
        }
        // The older email-code grant, for an account with a passkey or an authenticator.
        let (hosts, _) = legacy_cloud(second_step_required);
        let (mut pending, _) = start(&hosts).await;
        assert!(matches!(
            give(&mut pending, "email_code", "123456").await,
            Ok(Advanced::Browser { recovery: false })
        ));
        // The sign-in grant, when a factor was added after the last step.
        let (hosts, _) = fake_cloud(|path, body| match path {
            "/token" => second_step_required(),
            "/v1/app/sign-in/verify" if body.contains("proof") => done(),
            "/v1/app/sign-in/verify" => (
                200,
                json!({ "status": "next", "transaction": "tx-sent", "methods": ["email_code"] }),
            ),
            _ => (
                200,
                json!({ "status": "next", "transaction": "tx-start", "methods": ["email_code"], "exists": true }),
            ),
        });
        let (mut pending, _) = start(&hosts).await;
        assert!(matches!(
            give(&mut pending, "email_code", "123456").await,
            Ok(Advanced::Browser { recovery: false })
        ));
    }

    #[tokio::test]
    async fn sign_up_and_unknown_addresses_go_to_account_creation() {
        // No account has the address: no code is asked for.
        let (hosts, asked) = fake_cloud(|_, _| {
            (
                200,
                json!({ "status": "next", "transaction": "tx-start", "methods": ["email_code"], "exists": false }),
            )
        });
        let client = transport::client().unwrap();
        let refusal = begin(&client, &hosts, "new@example.com", None, "verifier").await;
        assert_eq!(refusal.err().unwrap(), "cloud_email_no_account");
        assert_eq!(paths(&asked), ["/v1/app/sign-in/start"]);
        // A sign-up is the email-auth flow, never the steps.
        let (hosts, asked) = legacy_cloud(tokens);
        let registration = Registration {
            country: "CA".into(),
            name: String::new(),
            terms_version: "1".into(),
            privacy_version: "1".into(),
        };
        let started = begin(
            &client,
            &hosts,
            "new@example.com",
            Some(&registration),
            "verifier",
        )
        .await;
        assert!(matches!(started, Ok((Flow::Legacy { .. }, _))));
        assert_eq!(paths(&asked), ["/v1/app/email-auth/start"]);
    }

    #[test]
    fn step_refusals_name_what_the_person_can_do() {
        assert_eq!(
            verify_refusal(401, None, "password"),
            "cloud_email_wrong_password"
        );
        assert_eq!(verify_refusal(401, None, "totp"), "cloud_email_wrong_code");
        assert_eq!(
            verify_refusal(404, Some("sign-in-expired"), "totp"),
            "cloud_email_expired_code"
        );
        assert_eq!(
            verify_refusal(404, Some("signup-required"), "email_code"),
            "cloud_email_no_account"
        );
        assert_eq!(
            verify_refusal(409, Some("sign-in-method-not-offered"), "totp"),
            "cloud_email_expired_code"
        );
        assert_eq!(
            verify_refusal(429, Some("second-factor-locked"), "totp"),
            "cloud_email_second_step_locked"
        );
        assert_eq!(
            verify_refusal(429, None, "email_code"),
            "cloud_email_rate_limited"
        );
        assert_eq!(
            verify_refusal(403, None, "email_code"),
            "cloud_email_account_blocked"
        );
        assert!(!can_retry("cloud_email_expired_code"));
    }

    #[test]
    fn proofs_are_shaped_before_they_are_sent() {
        assert_eq!(
            proof_for("email_code", " 123456 ").unwrap().as_str(),
            "123456"
        );
        assert!(proof_for("totp", "12345").is_none());
        assert!(proof_for("totp", "12345a").is_none());
        assert_eq!(
            proof_for("recovery_code", " ABCDE-FGHJK ")
                .unwrap()
                .as_str(),
            "ABCDE-FGHJK"
        );
        assert!(proof_for("recovery_code", "").is_none());
        assert_eq!(
            proof_for("password", " pass word ").unwrap().as_str(),
            " pass word "
        );
        assert!(proof_for("password", "").is_none());
        assert!(proof_for("passkey", "{}").is_none());
    }

    #[test]
    fn refusals_name_what_the_person_can_do() {
        assert_eq!(
            code_refusal("cloud_token_invalid_otp", false),
            "cloud_email_wrong_code"
        );
        assert_eq!(
            code_refusal("cloud_token_signup_required", false),
            "cloud_email_no_account"
        );
        assert_eq!(
            code_refusal("cloud_http_409", true),
            "cloud_email_consent_changed"
        );
        assert_eq!(
            code_refusal("cloud_http_409", false),
            "cloud_email_unavailable"
        );
        assert_eq!(
            code_refusal("cloud_token_slow_down", false),
            "cloud_email_rate_limited"
        );
        assert_eq!(
            start_refusal(409, Some("signup-consent-changed"), true),
            "cloud_email_consent_changed"
        );
        assert_eq!(start_refusal(429, None, false), "cloud_email_rate_limited");
        assert_eq!(start_refusal(404, None, false), "cloud_email_unavailable");
    }

    #[test]
    fn emails_are_checked_before_anything_is_sent() {
        assert!(valid_email("ada@example.com"));
        assert!(!valid_email("ada@localhost"));
        assert!(!valid_email("@example.com"));
        assert!(!valid_email("ada example@example.com"));
        assert!(!valid_email(&format!("{}@example.com", "a".repeat(250))));
    }
}
