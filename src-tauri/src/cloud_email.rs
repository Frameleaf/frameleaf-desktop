//! Frameleaf account sign-in and sign-up with an emailed code, in the app (the phones' flow:
//! `/v1/app/email-auth/consents`, `/start`, then the token endpoint's email-code grant with PKCE).
//! The PKCE verifier never leaves this process; the window only sees the attempt's outcome.
use super::{
    discover_hosts, keep_sign_in, load, parse_cloud_url, pkce_challenge, random_token,
    token_request, CloudAccount, CloudHosts, CLIENT_ID, CLOUD_LIMIT, CLOUD_ORIGIN,
};
use crate::transport;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::{State, WebviewWindow};
use url::Url;
use zeroize::Zeroizing;

const EMAIL_CODE_GRANT: &str = "urn:frameleaf:params:oauth:grant-type:email-code";

struct Pending {
    attempt_id: String,
    verifier: Zeroizing<String>,
    sign_up: bool,
    cloud: Url,
    hosts: CloudHosts,
}

/// The one code on its way, if any. A new start replaces it.
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
pub(crate) struct Started {
    disclosure: Option<String>,
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

/// Sends a code to `email`: a sign-in, or a sign-up when `registration` is given.
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
    let mut body = serde_json::json!({
        "purpose": if registration.is_some() { "sign-up" } else { "sign-in" },
        "email": email,
        "codeChallenge": pkce_challenge(&verifier),
    });
    if let Some(r) = &registration {
        body["country"] = r.country.clone().into();
        if !r.name.trim().is_empty() {
            body["name"] = r.name.trim().into();
        }
        body["consent"] =
            serde_json::json!({ "tos": r.terms_version, "privacy": r.privacy_version });
    }
    let url = hosts
        .issuer
        .join("v1/app/email-auth/start")
        .map_err(|_| "cloud_address_invalid")?;
    let response = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|_| "cloud_unreachable")?;
    let status = response.status();
    if !status.is_success() {
        #[derive(Deserialize)]
        struct Envelope {
            detail: Option<String>,
        }
        let detail = response
            .bytes()
            .await
            .ok()
            .filter(|body| body.len() <= 65_536)
            .and_then(|body| serde_json::from_slice::<Envelope>(&body).ok())
            .and_then(|envelope| envelope.detail);
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
    *attempt.0.lock().map_err(|_| "cloud_email_unavailable")? = Some(Pending {
        attempt_id: answer.attempt_id,
        verifier,
        sign_up: registration.is_some(),
        cloud,
        hosts,
    });
    Ok(Started {
        disclosure: answer.disclosure,
    })
}

/// Redeems the six-digit code for the attempt `cloud_email_start` sent, and keeps the sign-in.
#[tauri::command]
pub(crate) async fn cloud_email_complete(
    window: WebviewWindow,
    attempt: State<'_, EmailAttempt>,
    code: String,
) -> Result<CloudAccount, String> {
    crate::require_local(&window)?;
    let code = code.trim().to_string();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err("cloud_email_wrong_code".into());
    }
    let pending = attempt
        .0
        .lock()
        .map_err(|_| "cloud_email_unavailable")?
        .take()
        .ok_or("cloud_email_expired_code")?;
    let client = transport::client()?;
    let result = token_request(
        &client,
        &pending.hosts.issuer,
        &[
            ("grant_type", EMAIL_CODE_GRANT),
            ("client_id", CLIENT_ID),
            ("attempt_id", pending.attempt_id.as_str()),
            ("otp", code.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ],
    )
    .await;
    match result {
        Ok(token) => keep_sign_in(&client, &window, &pending.cloud, &pending.hosts, token).await,
        Err(error) => {
            let refusal = code_refusal(&error, pending.sign_up);
            // A mistyped code can be corrected; anything else needs a new code.
            if refusal == "cloud_email_wrong_code" {
                if let Ok(mut slot) = attempt.0.lock() {
                    slot.get_or_insert(pending);
                }
            }
            Err(refusal)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
