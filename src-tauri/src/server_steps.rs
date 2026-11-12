//! Unified sign-in on a server: its login answered in steps (`POST auth/login` with `steps`, then
//! `POST auth/login/two-factor`), Sign in with Frameleaf (`POST oauth/frameleaf/exchange`, then
//! `POST oauth/frameleaf/step-up` when the server asks for a local proof), and the answer to a
//! later `verification_required` (`POST auth/step-up`). Transactions, passwords and codes pass
//! through memory only; nothing here stores or logs them.
use crate::{transport, LoginResponse};
use reqwest::{Client, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;
use zeroize::Zeroizing;

/// Declared on every request that creates a session: this app can answer `verification_required`.
/// A server older than unified sign-in ignores it and answers as it always did.
pub(crate) const CAPABILITIES: [&str; 1] = ["verification"];
const TRANSACTION_LIMIT: usize = 4000;

/// The second step of a sign-in: what would complete it, most preferred first.
pub(crate) struct Pending {
    pub transaction: Zeroizing<String>,
    pub methods: Vec<String>,
    pub sent_to: Option<String>,
}

pub(crate) enum Step {
    Done(LoginResponse),
    Next(Pending),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Answer {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    name: String,
    status: Option<String>,
    #[serde(default)]
    two_factor_required: bool,
    transaction: Option<String>,
    two_factor_token: Option<String>,
    methods: Option<Vec<String>>,
    sent_to: Option<String>,
}

/// The method names a server may offer; anything else is dropped before it reaches the page.
pub(crate) fn known_methods(methods: Vec<String>) -> Vec<String> {
    methods
        .into_iter()
        .filter(|method| {
            matches!(
                method.as_str(),
                "totp" | "recovery_code" | "email_code" | "password" | "passkey" | "frameleaf"
            )
        })
        .take(8)
        .collect()
}

fn step(answer: Answer) -> Result<Step, String> {
    if answer.status.as_deref() == Some("next") || answer.two_factor_required {
        let transaction = answer
            .transaction
            .or(answer.two_factor_token)
            .filter(|value| !value.is_empty() && value.len() <= TRANSACTION_LIMIT)
            .ok_or("server_response_invalid")?;
        return Ok(Step::Next(Pending {
            transaction: Zeroizing::new(transaction),
            // A server older than sign-in in steps names no methods; its code step takes these two.
            methods: known_methods(
                answer
                    .methods
                    .unwrap_or_else(|| vec!["totp".into(), "recovery_code".into()]),
            ),
            sent_to: answer
                .sent_to
                .map(|value| value.chars().take(320).collect()),
        }));
    }
    if answer.access_token.is_empty() || answer.user_id.is_empty() {
        return Err("server_response_invalid".into());
    }
    Ok(Step::Done(LoginResponse {
        access_token: answer.access_token,
        user_id: answer.user_id,
        name: answer.name,
    }))
}

/// The `code` of a refusal's JSON body; nothing else of the body is kept.
pub(crate) async fn refusal_body(response: Response) -> Option<Value> {
    let body = response.bytes().await.ok()?;
    if body.len() > 65_536 {
        return None;
    }
    serde_json::from_slice(&body).ok()
}

async fn refused(response: Response, wrong_proof: Option<&str>) -> String {
    let status = response.status().as_u16();
    let body = refusal_body(response).await;
    let code = body
        .as_ref()
        .and_then(|value| value.get("code")?.as_str())
        .unwrap_or_default();
    match (status, code, wrong_proof) {
        // The server answers a wrong or expired proof with 401 and no code.
        (401, _, Some(wrong)) => wrong.into(),
        (400, _, Some(_)) => "sign_in_code_invalid".into(),
        (429, _, _) => "sign_in_too_many_attempts".into(),
        (403, "two_factor_required", _) => "sign_in_two_step_unsupported".into(),
        (403, "frameleaf_sign_in_required", _) => {
            "server_refused_frameleaf_sign_in_required".into()
        }
        _ => format!("server_http_{status}"),
    }
}

async fn answer(response: Response, wrong_proof: Option<&str>) -> Result<Step, String> {
    if response.status().is_success() {
        return step(transport::json(response).await?);
    }
    Err(refused(response, wrong_proof).await)
}

/// The password step. `steps` asks for the answer in steps; `twoFactor` gets the same code step
/// from a server older than that, which would otherwise refuse with `two_factor_required`.
pub(crate) async fn password(
    client: &Client,
    base: &Url,
    email: &str,
    password: &str,
) -> Result<Step, String> {
    let response = client
        .post(base.join("api/auth/login").unwrap())
        .json(&json!({
            "email": email,
            "password": password,
            "rememberMe": true,
            "steps": true,
            "twoFactor": true,
            "capabilities": CAPABILITIES,
        }))
        .send()
        .await
        .map_err(|_| "server_unreachable_or_certificate_invalid")?;
    answer(response, None).await
}

/// The body field a proof travels in, and the error a refused one becomes. The server takes a
/// six-digit code or a recovery code; an emailed code has no field of its own.
fn proof_field<'a>(
    method: &str,
    proof: &'a str,
) -> Result<(&'static str, &'a str, &'static str), String> {
    let proof = proof.trim();
    match method {
        "totp" | "email_code" if proof.len() == 6 && proof.bytes().all(|b| b.is_ascii_digit()) => {
            Ok(("code", proof, "sign_in_code_wrong"))
        }
        "recovery_code" if (1..=32).contains(&proof.len()) => {
            Ok(("recoveryCode", proof, "sign_in_recovery_code_wrong"))
        }
        _ => Err("sign_in_code_invalid".into()),
    }
}

fn checked_transaction(transaction: &str) -> Result<&str, String> {
    if transaction.is_empty() || transaction.len() > TRANSACTION_LIMIT {
        return Err("sign_in_code_invalid".into());
    }
    Ok(transaction)
}

/// The second step: one proof for the transaction the password step returned.
pub(crate) async fn proof(
    client: &Client,
    base: &Url,
    transaction: &str,
    method: &str,
    proof: &str,
) -> Result<Step, String> {
    let (field, value, wrong) = proof_field(method, proof)?;
    let response = client
        .post(base.join("api/auth/login/two-factor").unwrap())
        .json(&json!({
            "twoFactorToken": checked_transaction(transaction)?,
            field: value,
            "steps": true,
            "capabilities": CAPABILITIES,
        }))
        .send()
        .await
        .map_err(|_| "server_unreachable_or_certificate_invalid")?;
    answer(response, Some(wrong)).await
}

/// The `verification_required` a sign-in was refused with (403), as the step that completes it.
fn verification_step(status: u16, body: Option<&Value>) -> Option<Pending> {
    let body = body.filter(|_| status == 403)?;
    if body.get("code")?.as_str()? != "verification_required" {
        return None;
    }
    let transaction = body.get("transaction")?.as_str()?;
    if transaction.is_empty() || transaction.len() > TRANSACTION_LIMIT {
        return None;
    }
    let methods = body.get("methods").and_then(Value::as_array);
    Some(Pending {
        transaction: Zeroizing::new(transaction.to_owned()),
        methods: known_methods(
            methods
                .into_iter()
                .flatten()
                .filter_map(|method| method.as_str().map(str::to_owned))
                .collect(),
        ),
        sent_to: None,
    })
}

/// A Sign in with Frameleaf answer: the session, the local proof the server asks for first, or
/// the server's own refusal code.
async fn frameleaf_answer(response: Response, wrong_proof: Option<&str>) -> Result<Step, String> {
    let status = response.status().as_u16();
    if response.status().is_success() {
        // A server that answers without a session does not have this sign-in.
        return step(transport::json(response).await?).map_err(|code| {
            if code == "server_response_invalid" {
                "cloud_exchange_unsupported".into()
            } else {
                code
            }
        });
    }
    let body = refusal_body(response).await;
    if let Some(pending) = verification_step(status, body.as_ref()) {
        return Ok(Step::Next(pending));
    }
    let code = body.as_ref().and_then(|value| value.get("code")?.as_str());
    Err(match (status, wrong_proof) {
        // A wrong proof and an expired transaction are both 401 with no code.
        (401, Some(wrong)) if code.is_none() => wrong.into(),
        (400, Some(_)) if code.is_none() => "sign_in_code_invalid".into(),
        (429, _) => "sign_in_too_many_attempts".into(),
        _ => crate::server_admin::refusal(status, code),
    })
}

/// Sign in with Frameleaf: a server-audience token for a session. A server that wants the local
/// Password (a first link) or authenticator first answers with the step that completes it.
pub(crate) async fn frameleaf_exchange(
    client: &Client,
    base: &Url,
    token: &str,
) -> Result<Step, String> {
    let response = client
        .post(base.join("api/oauth/frameleaf/exchange").unwrap())
        .json(&json!({ "token": token, "rememberMe": true, "capabilities": CAPABILITIES }))
        .send()
        .await
        .map_err(|_| "server_unreachable_or_certificate_invalid")?;
    frameleaf_answer(response, None).await
}

/// Finishes a Sign in with Frameleaf that asked for more: the local Password when the server
/// listed it, and one authenticator proof when it listed those. Both go in the same request.
pub(crate) async fn frameleaf_step_up(
    client: &Client,
    base: &Url,
    transaction: &str,
    password: Option<&str>,
    proof: Option<(&str, &str)>,
) -> Result<Step, String> {
    let mut body = json!({
        "transaction": checked_transaction(transaction)?,
        "rememberMe": true,
        "capabilities": CAPABILITIES,
    });
    if let Some(password) = password {
        if password.is_empty() || password.len() > 1000 {
            return Err("frameleaf_step_refused".into());
        }
        body["password"] = password.into();
    }
    if let Some((method, proof)) = proof {
        // The server has no emailed code of its own for this step.
        if method == "email_code" {
            return Err("sign_in_code_invalid".into());
        }
        let (field, value, _) = proof_field(method, proof)?;
        body[field] = value.into();
    }
    if password.is_none() && proof.is_none() {
        return Err("sign_in_code_invalid".into());
    }
    let response = client
        .post(base.join("api/oauth/frameleaf/step-up").unwrap())
        .json(&body)
        .send()
        .await
        .map_err(|_| "server_unreachable_or_certificate_invalid")?;
    frameleaf_answer(response, Some("frameleaf_step_refused")).await
}

/// Answers a `verification_required` for the signed-in session; it then counts as verified.
pub(crate) async fn step_up(
    client: &Client,
    base: &Url,
    token: &str,
    transaction: &str,
    method: &str,
    proof: &str,
) -> Result<(), String> {
    let (field, value, wrong) = proof_field(method, proof)?;
    let response = client
        .post(base.join("api/auth/step-up").unwrap())
        .bearer_auth(token)
        .json(&json!({ "transaction": checked_transaction(transaction)?, field: value }))
        .send()
        .await
        .map_err(|_| "server_unreachable_or_certificate_invalid")?;
    if response.status().is_success() {
        return Ok(());
    }
    Err(refused(response, Some(wrong)).await)
}

#[cfg(test)]
pub(crate) mod fixture {
    use serde_json::Value;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
        thread,
    };
    use url::Url;

    pub(crate) struct Request {
        pub path: String,
        pub bearer: Option<String>,
        pub body: Value,
    }
    pub(crate) type Seen = Arc<Mutex<Vec<Request>>>;

    /// A local server that answers every request with `answer`, and keeps what it was sent.
    pub(crate) fn server(
        answer: impl Fn(&Request) -> (u16, Value) + Send + 'static,
    ) -> (Url, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let seen = Seen::default();
        let log = seen.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let (head, body) = loop {
                    let read = stream.read(&mut chunk).unwrap();
                    bytes.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    let Some((head, body)) = text.split_once("\r\n\r\n") else {
                        assert!(read > 0 && bytes.len() < 65_536);
                        continue;
                    };
                    let length = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if body.len() >= length || read == 0 {
                        break (head.to_owned(), body.to_owned());
                    }
                };
                let request = Request {
                    path: head.split(' ').nth(1).unwrap().to_owned(),
                    bearer: head.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("authorization")
                            .then(|| value.trim().trim_start_matches("Bearer ").to_owned())
                    }),
                    body: serde_json::from_str(&body).unwrap_or(Value::Null),
                };
                let (status, reply) = answer(&request);
                log.lock().unwrap().push(request);
                let reply = if reply.is_null() {
                    String::new()
                } else {
                    reply.to_string()
                };
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{reply}",
                        reply.len()
                    )
                    .as_bytes(),
                );
            }
        });
        (base, seen)
    }

    pub(crate) fn client() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{client, server, Request};
    use super::*;

    fn session(extra: Value) -> (u16, Value) {
        let mut body = json!({
            "accessToken": "session", "userId": "user", "userEmail": "ada@example.test",
            "name": "Ada", "isAdmin": false,
        });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        (200, body)
    }
    fn unauthorized() -> (u16, Value) {
        (
            401,
            json!({"message": "private", "error": "Unauthorized", "statusCode": 401}),
        )
    }
    /// The server's login for an account with Two-Step Verification, as `auth.service.ts` answers.
    fn two_step(next: Value) -> impl Fn(&Request) -> (u16, Value) + Send + 'static {
        move |request| match request.path.as_str() {
            "/api/auth/login" if request.body["password"] != "right" => unauthorized(),
            "/api/auth/login" if request.body["steps"] == true => {
                let mut body = json!({
                    "accessToken": "", "userId": "user", "name": "Ada",
                    "twoFactorRequired": true, "twoFactorToken": "txn",
                    "status": "next", "transaction": "txn",
                });
                body.as_object_mut()
                    .unwrap()
                    .extend(next.as_object().unwrap().clone());
                (200, body)
            }
            "/api/auth/login/two-factor"
                if request.body["twoFactorToken"] == "txn"
                    && (request.body["code"] == "123456"
                        || request.body["recoveryCode"] == "abcd-efgh") =>
            {
                session(json!({"status": "done"}))
            }
            "/api/auth/login/two-factor" => unauthorized(),
            _ => (404, Value::Null),
        }
    }
    async fn next(client: &Client, base: &Url) -> Pending {
        match password(client, base, "ada@example.test", "right")
            .await
            .unwrap()
        {
            Step::Next(pending) => pending,
            Step::Done(_) => panic!("a second step was expected"),
        }
    }
    fn token(step: Result<Step, String>) -> String {
        match step {
            Ok(Step::Done(login)) => login.access_token,
            Ok(Step::Next(_)) => panic!("the sign-in should be done"),
            Err(code) => panic!("{code}"),
        }
    }
    fn error(step: Result<Step, String>) -> String {
        step.err().expect("a refusal was expected")
    }

    #[tokio::test]
    async fn password_then_authenticator_code_signs_in() {
        let (base, seen) = server(two_step(json!({"methods": ["totp", "recovery_code"]})));
        let client = client();
        let pending = next(&client, &base).await;
        assert_eq!(pending.methods, ["totp", "recovery_code"]);
        assert_eq!(pending.sent_to, None);
        assert_eq!(
            token(proof(&client, &base, &pending.transaction, "totp", "123456").await),
            "session"
        );
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen[0].body,
            json!({
                "email": "ada@example.test", "password": "right", "rememberMe": true,
                "steps": true, "twoFactor": true, "capabilities": ["verification"],
            })
        );
        assert_eq!(
            seen[1].body,
            json!({
                "twoFactorToken": "txn", "code": "123456",
                "steps": true, "capabilities": ["verification"],
            })
        );
    }

    #[tokio::test]
    async fn password_then_emailed_code_reports_where_it_was_sent() {
        let (base, seen) = server(two_step(
            json!({"methods": ["email_code", "recovery_code"], "sentTo": "a•••@example.test"}),
        ));
        let client = client();
        let pending = next(&client, &base).await;
        assert_eq!(pending.methods, ["email_code", "recovery_code"]);
        assert_eq!(pending.sent_to.as_deref(), Some("a•••@example.test"));
        assert_eq!(
            token(proof(&client, &base, &pending.transaction, "email_code", "123456").await),
            "session"
        );
        assert_eq!(seen.lock().unwrap()[1].body["code"], "123456");
    }

    #[tokio::test]
    async fn recovery_code_completes_the_step() {
        let (base, seen) = server(two_step(json!({"methods": ["totp", "recovery_code"]})));
        let client = client();
        let pending = next(&client, &base).await;
        let done = proof(
            &client,
            &base,
            &pending.transaction,
            "recovery_code",
            " abcd-efgh ",
        )
        .await;
        assert_eq!(token(done), "session");
        let seen = seen.lock().unwrap();
        assert_eq!(seen[1].body["recoveryCode"], "abcd-efgh");
        assert!(seen[1].body.get("code").is_none());
    }

    #[tokio::test]
    async fn wrong_code_keeps_the_step_open_with_its_own_error() {
        let (base, seen) = server(two_step(json!({"methods": ["totp", "recovery_code"]})));
        let client = client();
        let pending = next(&client, &base).await;
        let transaction = pending.transaction.as_str();
        assert_eq!(
            error(proof(&client, &base, transaction, "totp", "000000").await),
            "sign_in_code_wrong"
        );
        assert_eq!(
            error(proof(&client, &base, transaction, "recovery_code", "nope").await),
            "sign_in_recovery_code_wrong"
        );
        // A malformed code, an unknown method or a missing transaction never reaches the server.
        let sent = seen.lock().unwrap().len();
        for (transaction, method, code) in [
            (transaction, "totp", "12ab56"),
            (transaction, "totp", "1234567"),
            (transaction, "recovery_code", ""),
            (transaction, "passkey", "123456"),
            ("", "totp", "123456"),
        ] {
            assert_eq!(
                error(proof(&client, &base, transaction, method, code).await),
                "sign_in_code_invalid"
            );
        }
        assert_eq!(seen.lock().unwrap().len(), sent);
        // The same transaction still completes with the right code.
        assert_eq!(
            token(proof(&client, &base, transaction, "totp", "123456").await),
            "session"
        );
    }

    #[tokio::test]
    async fn server_without_steps_still_signs_in() {
        // Older than 1.2.16: `steps` and `capabilities` are ignored and no status is sent.
        let (base, _) = server(|request| match request.path.as_str() {
            "/api/auth/login" => session(json!({})),
            _ => (404, Value::Null),
        });
        assert_eq!(
            token(password(&client(), &base, "ada@example.test", "right").await),
            "session"
        );
    }

    #[tokio::test]
    async fn older_two_step_server_shows_a_code_step_instead_of_a_refusal() {
        // Before sign-in in steps: `two_factor_required` unless the client says it has a code step.
        let (base, _) = server(|request| match request.path.as_str() {
            "/api/auth/login" if request.body["twoFactor"] == true => (
                200,
                json!({
                    "accessToken": "", "userId": "user", "name": "Ada",
                    "twoFactorRequired": true, "twoFactorToken": "legacy",
                }),
            ),
            "/api/auth/login" => (
                403,
                json!({"message": "private", "statusCode": 403, "code": "two_factor_required"}),
            ),
            "/api/auth/login/two-factor"
                if request.body["twoFactorToken"] == "legacy"
                    && request.body["code"] == "123456" =>
            {
                session(json!({}))
            }
            _ => unauthorized(),
        });
        let client = client();
        let pending = next(&client, &base).await;
        assert_eq!(pending.transaction.as_str(), "legacy");
        assert_eq!(pending.methods, ["totp", "recovery_code"]);
        assert_eq!(
            token(proof(&client, &base, &pending.transaction, "totp", "123456").await),
            "session"
        );
    }

    #[tokio::test]
    async fn refusals_and_malformed_answers_have_their_own_codes() {
        for (status, body, expected) in [
            (
                403,
                json!({"code": "two_factor_required"}),
                "sign_in_two_step_unsupported",
            ),
            (
                403,
                json!({"code": "frameleaf_sign_in_required"}),
                "server_refused_frameleaf_sign_in_required",
            ),
            (403, json!({"code": "other"}), "server_http_403"),
            (401, json!({}), "server_http_401"),
            (429, json!({}), "sign_in_too_many_attempts"),
            // No session and no next step is not a sign-in.
            (
                200,
                json!({"accessToken": "", "userId": "user", "name": "Ada"}),
                "server_response_invalid",
            ),
            (
                200,
                json!({"status": "next", "methods": ["totp"]}),
                "server_response_invalid",
            ),
        ] {
            let (base, _) = server(move |_| (status, body.clone()));
            assert_eq!(
                error(password(&client(), &base, "ada@example.test", "right").await),
                expected
            );
        }
    }

    #[tokio::test]
    async fn offered_methods_pass_through_in_the_servers_order_without_unknown_names() {
        let (base, _) = server(two_step(json!({"methods": ["passkey", "sms", "totp"]})));
        assert_eq!(next(&client(), &base).await.methods, ["passkey", "totp"]);
        let (base, _) = server(two_step(json!({"methods": ["passkey"]})));
        assert_eq!(next(&client(), &base).await.methods, ["passkey"]);
    }

    #[tokio::test]
    async fn step_up_sends_the_transaction_with_the_session() {
        let (base, seen) = server(|request| {
            if request.body["code"] == "123456" || request.body["recoveryCode"] == "abcd-efgh" {
                (204, Value::Null)
            } else {
                unauthorized()
            }
        });
        let client = client();
        step_up(&client, &base, "session", "txn", "totp", "123456")
            .await
            .unwrap();
        step_up(
            &client,
            &base,
            "session",
            "txn",
            "recovery_code",
            "abcd-efgh",
        )
        .await
        .unwrap();
        assert_eq!(
            step_up(&client, &base, "session", "txn", "totp", "000000")
                .await
                .unwrap_err(),
            "sign_in_code_wrong"
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].path, "/api/auth/step-up");
        assert_eq!(seen[0].bearer.as_deref(), Some("session"));
        assert_eq!(
            seen[0].body,
            json!({"transaction": "txn", "code": "123456"})
        );
        assert_eq!(
            seen[1].body,
            json!({"transaction": "txn", "recoveryCode": "abcd-efgh"})
        );
    }
}

#[cfg(test)]
mod frameleaf_tests {
    use super::fixture::{client, server, Request};
    use super::*;

    fn session() -> (u16, Value) {
        (
            200,
            json!({"accessToken": "session", "userId": "user", "name": "Ada", "isAdmin": true}),
        )
    }
    fn needs(methods: Value) -> (u16, Value) {
        (
            403,
            json!({
                "message": "private", "error": "Forbidden", "statusCode": 403,
                "code": "verification_required", "acr": "urn:frameleaf:acr:verified",
                "maxAge": null, "methods": methods, "transaction": "pending",
            }),
        )
    }
    /// The server's exchange for a person with a local authenticator and a Basic Frameleaf sign-in,
    /// or (with `password`) an account here that is linked for the first time.
    fn asks(password: bool) -> impl Fn(&Request) -> (u16, Value) + Send + 'static {
        move |request| match request.path.as_str() {
            "/api/oauth/frameleaf/exchange" if password => {
                needs(json!(["frameleaf", "password", "totp", "recovery_code"]))
            }
            "/api/oauth/frameleaf/exchange" => needs(json!(["frameleaf", "totp", "recovery_code"])),
            "/api/oauth/frameleaf/step-up"
                if request.body["transaction"] == "pending"
                    && (!password || request.body["password"] == "right")
                    && (request.body["code"] == "123456"
                        || request.body["recoveryCode"] == "abcd-efgh") =>
            {
                session()
            }
            "/api/oauth/frameleaf/step-up" => (
                401,
                json!({"message": "private", "error": "Unauthorized", "statusCode": 401}),
            ),
            _ => (404, Value::Null),
        }
    }
    fn pending(step: Result<Step, String>) -> Pending {
        match step {
            Ok(Step::Next(pending)) => pending,
            Ok(Step::Done(_)) => panic!("a step was expected"),
            Err(code) => panic!("{code}"),
        }
    }
    fn token(step: Result<Step, String>) -> String {
        match step {
            Ok(Step::Done(login)) => login.access_token,
            Ok(Step::Next(_)) => panic!("the sign-in should be done"),
            Err(code) => panic!("{code}"),
        }
    }

    #[tokio::test]
    async fn exchange_declares_the_capability_and_signs_in_on_any_server() {
        // A server older than unified sign-in ignores `capabilities`; a newer one that needs
        // nothing more answers the same way. Plain http on the home network, as the fixture is.
        let (base, seen) = server(|_| session());
        assert_eq!(base.scheme(), "http");
        assert_eq!(
            token(frameleaf_exchange(&client(), &base, "exchange-token").await),
            "session"
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].path, "/api/oauth/frameleaf/exchange");
        assert_eq!(
            seen[0].body,
            json!({"token": "exchange-token", "rememberMe": true, "capabilities": ["verification"]})
        );
    }

    #[tokio::test]
    async fn exchange_that_needs_the_authenticator_finishes_with_one_code() {
        let (base, seen) = server(asks(false));
        let client = client();
        let step = pending(frameleaf_exchange(&client, &base, "exchange-token").await);
        assert_eq!(step.methods, ["frameleaf", "totp", "recovery_code"]);
        assert_eq!(step.transaction.as_str(), "pending");
        let proof = Some(("totp", "123456"));
        assert_eq!(
            token(frameleaf_step_up(&client, &base, &step.transaction, None, proof).await),
            "session"
        );
        let recovery = Some(("recovery_code", " abcd-efgh "));
        assert_eq!(
            token(frameleaf_step_up(&client, &base, &step.transaction, None, recovery).await),
            "session"
        );
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen[1].body,
            json!({
                "transaction": "pending", "code": "123456",
                "rememberMe": true, "capabilities": ["verification"],
            })
        );
        assert_eq!(seen[2].body["recoveryCode"], "abcd-efgh");
        assert!(seen[2].body.get("code").is_none());
    }

    #[tokio::test]
    async fn first_link_sends_the_password_and_the_code_together() {
        let (base, seen) = server(asks(true));
        let client = client();
        let step = pending(frameleaf_exchange(&client, &base, "exchange-token").await);
        assert_eq!(
            step.methods,
            ["frameleaf", "password", "totp", "recovery_code"]
        );
        let transaction = step.transaction.as_str();
        let code = Some(("totp", "123456"));
        // A wrong Password keeps the step open with its own error.
        assert_eq!(
            frameleaf_step_up(&client, &base, transaction, Some("wrong"), code)
                .await
                .err()
                .unwrap(),
            "frameleaf_step_refused"
        );
        assert_eq!(
            token(frameleaf_step_up(&client, &base, transaction, Some("right"), code).await),
            "session"
        );
        let sent = seen.lock().unwrap().len();
        assert_eq!(seen.lock().unwrap()[2].body["password"], "right");
        // Nothing malformed reaches the server: no proof at all, an emailed code, a bad code.
        for (password, proof) in [
            (None, None),
            (Some(""), code),
            (None, Some(("email_code", "123456"))),
            (None, Some(("totp", "12ab56"))),
        ] {
            assert!(
                frameleaf_step_up(&client, &base, transaction, password, proof)
                    .await
                    .is_err()
            );
        }
        assert_eq!(seen.lock().unwrap().len(), sent);
    }

    #[tokio::test]
    async fn exchange_refusals_keep_the_servers_code() {
        for (status, body, expected) in [
            (
                403,
                json!({"code": "frameleaf_exchange_no_access"}),
                "server_refused_frameleaf_exchange_no_access",
            ),
            // Asked for, but with nothing to answer it with: a plain refusal, never a dead step.
            (
                403,
                json!({"code": "verification_required", "methods": ["frameleaf"]}),
                "server_refused_verification_required",
            ),
            (401, json!({"code": "frameleaf_exchange_expired"}), "server_refused_frameleaf_exchange_expired"),
            (404, json!({}), "server_http_404"),
            (429, json!({}), "sign_in_too_many_attempts"),
            (200, json!({"userId": "user"}), "cloud_exchange_unsupported"),
        ] {
            let (base, _) = server(move |_| (status, body.clone()));
            assert_eq!(
                frameleaf_exchange(&client(), &base, "exchange-token")
                    .await
                    .err()
                    .unwrap(),
                expected
            );
        }
    }
}
