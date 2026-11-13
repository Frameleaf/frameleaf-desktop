//! Saving, restoring and ending a sign-in. The credential store here is the calling test's own.
use crate::{connection::SavedConnection, credentials, saved_sign_in};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

fn saved(server: String, server_id: &str) -> SavedConnection {
    SavedConnection {
        server,
        server_id: server_id.into(),
        account_id: "account".into(),
        name: "Ada".into(),
        token: "session".into(),
        device_name: "Desk".into(),
        mode: "client-worker".into(),
        device_id: None,
    }
}

/// A server that answers `capabilities` with `status` and `body`, and anything else with 204.
/// Returns its address and the request lines it saw, with whether each carried the session.
fn server(status: u16, body: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                let mut byte = [0];
                if stream.read_exact(&mut byte).is_err() {
                    break;
                }
                request.push(byte[0]);
            }
            let request = String::from_utf8_lossy(&request).to_string();
            let line = request.lines().next().unwrap_or_default().to_string();
            let authorized = request
                .to_ascii_lowercase()
                .contains("authorization: bearer session");
            let (status, body) = if line.starts_with("GET /api/desktop/capabilities ") {
                (status, body)
            } else {
                (204, "")
            };
            log.lock().unwrap().push(format!("{line} {authorized}"));
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    (url, seen)
}

const IDENTIFIED: &str = r#"{"protocolVersion":1,"serverId":"known-server","features":{"enrollment":false,"worker":false,"sources":false,"nativeHost":false}}"#;

#[tokio::test]
async fn a_sign_in_whose_server_is_not_identified_is_not_saved_and_its_session_is_ended() {
    let store = credentials::use_test_store();
    for (status, body) in [(404, "{}"), (500, "{}"), (200, "<html>")] {
        let (url, seen) = server(status, body);
        let mut connection = saved(url, "");
        let result = crate::finish_new_connection(&reqwest::Client::new(), &mut connection, |_| {
            panic!("nothing was saved to confirm")
        })
        .await;
        assert_eq!(
            result.err().as_deref(),
            Some("server_sign_in_retry_required"),
            "{status}"
        );
        assert!(store.values.borrow().is_empty(), "{status}: nothing saved");
        assert_eq!(
            *seen.lock().unwrap(),
            [
                "GET /api/desktop/capabilities HTTP/1.1 true",
                "POST /api/auth/logout HTTP/1.1 true"
            ],
            "{status}"
        );
    }
}

#[tokio::test]
async fn an_identified_sign_in_is_saved_with_the_identity() {
    let store = credentials::use_test_store();
    let (url, seen) = server(200, IDENTIFIED);
    let mut connection = saved(url, "");
    let view = crate::finish_new_connection(&reqwest::Client::new(), &mut connection, |_| Ok(()))
        .await
        .unwrap();
    assert_eq!(view.state, "unsupported-server");
    let kept: SavedConnection = credentials::load("connection").unwrap().unwrap();
    assert_eq!(kept.server_id, "known-server");
    assert_eq!(store.values.borrow().len(), 1);
    assert!(!seen
        .lock()
        .unwrap()
        .iter()
        .any(|line| line.contains("logout")));
}

#[tokio::test]
async fn a_sign_in_saved_without_an_identity_recovers_once_the_server_says_who_it_is() {
    credentials::use_test_store();
    // What an earlier version saved when `capabilities` failed right after the login.
    let (url, _) = server(404, "{}");
    let mut stuck = saved(url, "");
    credentials::save("connection", &stuck).unwrap();
    crate::prepare_with_client(&reqwest::Client::new(), &mut stuck).await;
    assert_eq!(
        saved_sign_in::identified(&stuck).unwrap_err(),
        "server_identity_not_confirmed",
        "still unidentified: not used"
    );

    let (url, _) = server(200, IDENTIFIED);
    let mut recovering = saved(url, "");
    credentials::save("connection", &recovering).unwrap();
    crate::prepare_with_client(&reqwest::Client::new(), &mut recovering).await;
    assert_eq!(saved_sign_in::identified(&recovering), Ok(()));
    let mut kept: SavedConnection = credentials::load("connection").unwrap().unwrap();
    assert_eq!(kept.server_id, "known-server", "and it stays recovered");

    // A different server answering later is still refused.
    let (url, _) = server(
        200,
        r#"{"protocolVersion":1,"serverId":"another","features":{"enrollment":false,"worker":false,"sources":false,"nativeHost":false}}"#,
    );
    kept.server = url;
    let view = crate::prepare_with_client(&reqwest::Client::new(), &mut kept).await;
    assert_eq!(view.state, "identity-changed");
    assert_eq!(kept.server_id, "known-server");
}

/// The text of one function in `lib.rs`, without whitespace, so rustfmt wrapping does not matter.
fn function(signature: &str) -> String {
    let source = include_str!("lib.rs");
    let start = source.find(signature).expect(signature);
    let end = source[start..].find("\n}\n").unwrap() + start;
    source[start..end].split_whitespace().collect()
}

fn position(text: &str, needle: &str) -> usize {
    let needle: String = needle.split_whitespace().collect();
    text.find(&needle)
        .unwrap_or_else(|| panic!("missing: {needle}"))
}

#[test]
fn sign_out_removes_the_saved_sign_in_before_it_releases_the_connection() {
    let body = function("async fn sign_out(");
    let released = position(&body, "drop(current);");
    for removed in [
        r#"credentials::delete("worker-session")"#,
        r#"credentials::delete("connection")"#,
    ] {
        assert!(
            position(&body, removed) < released,
            "{removed} must run while the connection is locked: a restore waiting on the lock \
             would otherwise sign in again from the saved sign-in"
        );
    }
    assert!(position(&body, "tray::refresh(&app).await") > released);
    // Every path that saves a sign-in does so holding the same lock.
    for signature in [
        "async fn connect_with(",
        "pub(crate) async fn restore_saved(",
    ] {
        let body = function(signature);
        assert!(
            position(&body, "state.0.lock().await") < position(&body, "*current = Some(saved)")
        );
    }
}

#[test]
fn sign_out_wipes_the_photos_data_whether_or_not_its_window_is_open() {
    let body = function("async fn sign_out(");
    // Written down before the sign-in goes, and wiped through the window that asked.
    assert!(
        position(&body, "photo_session::mark(&app)")
            < position(&body, r#"credentials::delete("connection")"#)
    );
    position(&body, "photo_session::clear(&app, &window)");
    assert!(
        !body.contains("else{true}"),
        "a closed Photos window is not a cleared one"
    );
    // A wipe still owed is made good at launch and before the next Photos session.
    position(
        include_str!("lib.rs"),
        "photo_session::clear_if_owed(app.handle())",
    );
    let open = function("pub(crate) fn open_photos_window(");
    assert!(position(&open, "photo_session::clear_if_owed(app)") < position(&open, "set_cookie("));
}

#[test]
fn restoring_checks_the_identity_only_after_the_server_could_supply_it() {
    let body = function("pub(crate) async fn restore_saved(");
    assert!(
        position(&body, "prepare(&mut saved,")
            < position(&body, "saved_sign_in::identified(&saved)?")
    );
    assert!(
        position(&body, "saved_sign_in::identified(&saved)?")
            < position(&body, "*current = Some(saved)")
    );
    assert_eq!(body.matches("server_id.is_empty()").count(), 0);
}

#[test]
fn a_sign_in_longer_than_one_windows_credential_is_saved_read_and_removed() {
    let store = credentials::use_test_store();
    // An RS256 `at+jwt` from a 4096-bit key is about 1,150 characters by itself.
    let mut connection = saved("https://photos.example/".into(), "server");
    connection.token = "t".repeat(1150);
    let record = serde_json::to_string(&connection).unwrap();
    assert!(record.encode_utf16().count() > crate::credential_parts::Memory::WINDOWS);

    credentials::save("connection", &connection).unwrap();
    let kept: SavedConnection = credentials::load("connection").unwrap().unwrap();
    assert_eq!(kept.token, connection.token);
    assert!(store.values.borrow().len() > 1, "stored in parts");

    // Signing in to Frameleaf keeps a refresh token and a signed access token together.
    let cloud = crate::cloud_account::CloudCredential {
        cloud_url: "https://frameleaf.cloud/".into(),
        issuer: "https://id.frameleaf.cloud/".into(),
        api: "https://api.frameleaf.cloud/".into(),
        refresh_token: "r".repeat(43),
        access_token: "a".repeat(1100),
        expires_at: 1_800_000_000,
    };
    credentials::save("cloud-account", &cloud).unwrap();
    let kept: crate::cloud_account::CloudCredential =
        credentials::load("cloud-account").unwrap().unwrap();
    assert_eq!(kept.access_token, cloud.access_token);

    credentials::delete("connection").unwrap();
    credentials::delete("cloud-account").unwrap();
    assert!(
        store.values.borrow().is_empty(),
        "no part of a token is left"
    );
}
