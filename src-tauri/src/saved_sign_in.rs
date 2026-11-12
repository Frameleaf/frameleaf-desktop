//! Checking the saved sign-in with the server, and what each answer means for this computer.

use crate::connection::{normalize_server, SavedConnection};
use serde::Deserialize;

/// The server did not answer, or answered with a fault of its own. The sign-in is kept.
pub(crate) const UNREACHABLE: &str = "server_unreachable_or_certificate_invalid";
/// The server wants Two-Step Verification before it lets this session continue.
pub(crate) const NEEDS_VERIFICATION: &str = "verification_required";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AccountCheck {
    Verified,
    Unreachable,
    NeedsVerification,
    /// The server definitively refused this sign-in, or it now belongs to another account.
    Rejected(String),
    /// An answer that says nothing about the sign-in either way.
    Failed(String),
}

/// What restoring does after a check.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    pub stop_work: bool,
    pub purge_albums: bool,
    /// `Ok`: carry on and start the worker and the folder watch. `Err`: the code the window shows.
    pub resume_work: Result<(), String>,
}

impl AccountCheck {
    pub(crate) fn plan(self) -> Plan {
        let rejected = matches!(self, Self::Rejected(_));
        Plan {
            // Only a definitive rejection ends running work and removes offline albums.
            stop_work: rejected,
            purge_albums: rejected,
            resume_work: match self {
                Self::Verified => Ok(()),
                Self::Unreachable => Err(UNREACHABLE.into()),
                Self::NeedsVerification => Err(NEEDS_VERIFICATION.into()),
                Self::Rejected(code) | Self::Failed(code) => Err(code),
            },
        }
    }
}

/// The connection in use is the saved one: restoring it is only a check.
pub(crate) fn same_session(held: &SavedConnection, saved: &SavedConnection) -> bool {
    held.server == saved.server && held.account_id == saved.account_id && held.token == saved.token
}

pub(crate) async fn check(client: &reqwest::Client, saved: &SavedConnection) -> AccountCheck {
    #[derive(Deserialize)]
    struct User {
        id: String,
    }
    #[derive(Deserialize)]
    struct Refusal {
        code: String,
    }
    let base = match normalize_server(&saved.server) {
        Ok(base) => base,
        Err(code) => return AccountCheck::Failed(code),
    };
    let Ok(mut response) = client
        .get(base.join("api/users/me").unwrap())
        .bearer_auth(&saved.token)
        .send()
        .await
    else {
        return AccountCheck::Unreachable;
    };
    let status = response.status().as_u16();
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if body.len() + chunk.len() <= 65_536 => {
                body.extend_from_slice(&chunk);
            }
            Ok(Some(_)) => return AccountCheck::Failed("server_response_too_large".into()),
            Ok(None) => break,
            Err(_) => return AccountCheck::Unreachable,
        }
    }
    match status {
        200..=299 => match serde_json::from_slice::<User>(&body) {
            Ok(user) if user.id == saved.account_id => AccountCheck::Verified,
            Ok(_) => AccountCheck::Rejected("account_identity_changed".into()),
            Err(_) => AccountCheck::Failed("server_response_invalid".into()),
        },
        401 => AccountCheck::Rejected("server_http_401".into()),
        403 if serde_json::from_slice::<Refusal>(&body)
            .is_ok_and(|refusal| refusal.code == NEEDS_VERIFICATION) =>
        {
            AccountCheck::NeedsVerification
        }
        403 => AccountCheck::Rejected("server_http_403".into()),
        // A restarting server or its proxy: nothing here says the sign-in ended.
        408 | 429 | 500..=599 => AccountCheck::Unreachable,
        other => AccountCheck::Failed(format!("server_http_{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn saved(server: String) -> SavedConnection {
        SavedConnection {
            server,
            server_id: "server".into(),
            account_id: "account".into(),
            name: "Test".into(),
            token: "fixture".into(),
            device_name: "Fixture".into(),
            mode: "client-worker".into(),
            device_id: None,
        }
    }

    fn reply(status: u16, body: &'static str) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 8192);
            }
            assert!(request.starts_with(b"GET /api/users/me "));
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        (url, handle)
    }

    async fn answer(status: u16, body: &'static str) -> AccountCheck {
        let (url, server) = reply(status, body);
        let check = check(&reqwest::Client::new(), &saved(url)).await;
        server.join().unwrap();
        check
    }

    fn closed_port() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/", listener.local_addr().unwrap())
    }

    #[tokio::test]
    async fn an_unreachable_server_keeps_the_sign_in_albums_and_running_work() {
        let check = check(&reqwest::Client::new(), &saved(closed_port())).await;
        assert_eq!(check, AccountCheck::Unreachable);
        assert_eq!(
            check.plan(),
            Plan {
                stop_work: false,
                purge_albums: false,
                resume_work: Err(UNREACHABLE.into()),
            }
        );
        for status in [408, 429, 500, 502, 503, 504] {
            assert_eq!(answer(status, "{}").await, AccountCheck::Unreachable);
        }
    }

    #[tokio::test]
    async fn a_401_signs_out_and_purges_offline_albums() {
        let check = answer(401, r#"{"message":"Invalid user token","statusCode":401}"#).await;
        assert_eq!(check, AccountCheck::Rejected("server_http_401".into()));
        assert_eq!(
            check.plan(),
            Plan {
                stop_work: true,
                purge_albums: true,
                resume_work: Err("server_http_401".into()),
            }
        );
    }

    #[tokio::test]
    async fn a_403_asking_for_verification_keeps_albums_and_the_sign_in() {
        let check = answer(
            403,
            r#"{"message":"More is needed to sign in here.","error":"Forbidden","statusCode":403,"code":"verification_required","methods":["totp"],"transaction":"t"}"#,
        )
        .await;
        assert_eq!(check, AccountCheck::NeedsVerification);
        assert_eq!(
            check.plan(),
            Plan {
                stop_work: false,
                purge_albums: false,
                resume_work: Err(NEEDS_VERIFICATION.into()),
            }
        );
    }

    #[tokio::test]
    async fn any_other_403_is_a_definitive_rejection() {
        for body in [
            r#"{"message":"Forbidden","statusCode":403}"#,
            r#"{"statusCode":403,"code":"two_factor_setup_required"}"#,
            "not json",
        ] {
            let plan = answer(403, body).await.plan();
            assert!(plan.purge_albums && plan.stop_work, "{body}");
            assert_eq!(plan.resume_work, Err("server_http_403".into()));
        }
    }

    #[tokio::test]
    async fn another_account_behind_the_token_is_rejected() {
        let plan = answer(200, r#"{"id":"someone-else"}"#).await.plan();
        assert!(plan.purge_albums && plan.stop_work);
        assert_eq!(plan.resume_work, Err("account_identity_changed".into()));
    }

    #[tokio::test]
    async fn an_answer_that_says_nothing_about_the_sign_in_changes_nothing() {
        for (status, body, code) in [
            (404, "{}", "server_http_404"),
            (200, "<html>", "server_response_invalid"),
        ] {
            let plan = answer(status, body).await.plan();
            assert!(!plan.purge_albums && !plan.stop_work);
            assert_eq!(plan.resume_work, Err(code.into()));
        }
    }

    #[tokio::test]
    async fn success_after_an_unreachable_attempt_resumes_work() {
        let client = reqwest::Client::new();
        let first = check(&client, &saved(closed_port())).await.plan();
        assert_eq!(first.resume_work, Err(UNREACHABLE.into()));
        assert!(!first.stop_work && !first.purge_albums);

        let retry = answer(200, r#"{"id":"account","name":"Test"}"#).await;
        assert_eq!(retry, AccountCheck::Verified);
        assert_eq!(
            retry.plan(),
            Plan {
                stop_work: false,
                purge_albums: false,
                resume_work: Ok(()),
            }
        );
    }

    #[test]
    fn only_the_connection_in_use_counts_as_a_check() {
        let held = saved("https://photos.example/".into());
        assert!(same_session(
            &held,
            &saved("https://photos.example/".into())
        ));
        let mut other = saved("https://photos.example/".into());
        other.token = "replacement".into();
        assert!(!same_session(&held, &other));
        assert!(!same_session(
            &held,
            &saved("https://other.example/".into())
        ));
    }
}
