//! Real synthetic-media journey; the fixture authority never enters release trust.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use frameleaf_desktop::host_runtime::VerifiedHostRuntime;
use reqwest::{multipart, Client};
use serde_json::{json, Value};
use std::{fs, net::TcpListener, path::PathBuf, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

#[tokio::test]
#[ignore = "requires measured FRAMELEAF_TEST_HOST_PACK and a new FRAMELEAF_TEST_PHOTO_STATE; no installed/release claim"]
async fn actual_native_photo_upload_thumbnail_and_restart() {
    let pack = PathBuf::from(std::env::var_os("FRAMELEAF_TEST_HOST_PACK").unwrap())
        .canonicalize()
        .unwrap();
    let state = PathBuf::from(std::env::var_os("FRAMELEAF_TEST_PHOTO_STATE").unwrap());
    assert!(
        state.is_absolute() && !state.exists(),
        "never adopt a profile"
    );
    fs::create_dir(&state).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let raw = fs::read(pack.join("manifest.json")).unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let host = VerifiedHostRuntime::verify(
        &pack.join("payload"),
        &raw,
        &key.sign(&raw).to_bytes(),
        &[key.verifying_key()],
        2,
    )
    .unwrap();
    assert!(!host.certified());
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let database_port = a.local_addr().unwrap().port();
    let api_port = b.local_addr().unwrap().port();
    drop((a, b));
    let base = format!("http://127.0.0.1:{api_port}");
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let password = Zeroizing::new(format!("Synthetic-{}!", Uuid::new_v4()));
    let mut process = host
        .start(&state, &password, database_port, api_port)
        .unwrap();
    process.wait_ready(Duration::from_secs(240)).unwrap();
    let web = client.get(&base).send().await.unwrap();
    assert!(web.status().is_success(), "native web entry unavailable");
    assert!(web.text().await.unwrap().contains("<html"));
    let credentials = json!({"email":"native-photo@example.invalid", "password":password.as_str()});
    let signup = client.post(format!("{base}/api/auth/admin-sign-up"))
        .json(&json!({"email":credentials["email"], "password":password.as_str(), "name":"Synthetic native qualification"}))
        .send().await.unwrap();
    assert_eq!(signup.status(), 201, "synthetic signup failed");
    let login = client
        .post(format!("{base}/api/auth/login"))
        .json(&credentials)
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 201, "synthetic login failed");
    let login: Value = login.json().await.unwrap();
    let token = Zeroizing::new(login["accessToken"].as_str().unwrap().to_owned());
    // Generated 32x32 solid PNG, no user media or external fixture download.
    let original = STANDARD.decode("iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAKklEQVR4nGNQaEigKWIYtWDUglELRi0YtWDUglELRi0YtWDUglELhooFAHfgAD2FaRhWAAAAAElFTkSuQmCC").unwrap();
    let form = multipart::Form::new()
        .text("fileCreatedAt", "2026-01-01T00:00:00.000Z")
        .text("fileModifiedAt", "2026-01-01T00:00:00.000Z")
        .part(
            "assetData",
            multipart::Part::bytes(original.clone())
                .file_name("synthetic-native-photo.png")
                .mime_str("image/png")
                .unwrap(),
        );
    let uploaded = client
        .post(format!("{base}/api/assets"))
        .bearer_auth(token.as_str())
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(uploaded.status(), 201, "synthetic upload failed");
    let uploaded: Value = uploaded.json().await.unwrap();
    assert_eq!(uploaded["status"], "created");
    let id = Uuid::parse_str(uploaded["id"].as_str().unwrap()).unwrap();
    let thumbnail = format!("{base}/api/assets/{id}/thumbnail?size=thumbnail");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let thumbnail_bytes = loop {
        let response = client
            .get(&thumbnail)
            .bearer_auth(token.as_str())
            .send()
            .await
            .unwrap();
        if response.status().is_success() {
            assert!(response.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("image/"));
            let bytes = response.bytes().await.unwrap();
            assert!(!bytes.is_empty() && bytes.as_ref() != original);
            break bytes;
        }
        assert_eq!(response.status(), 404, "thumbnail processing failed");
        assert!(
            tokio::time::Instant::now() < deadline,
            "native thumbnail timed out"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    drop(client);
    process.stop().unwrap();
    drop(process);
    let mut restarted = host
        .start(&state, &password, database_port, api_port)
        .unwrap();
    restarted.wait_ready(Duration::from_secs(240)).unwrap();
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let login = client
        .post(format!("{base}/api/auth/login"))
        .json(&credentials)
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 201, "persisted account unavailable");
    let login: Value = login.json().await.unwrap();
    let token = Zeroizing::new(login["accessToken"].as_str().unwrap().to_owned());
    let info = client
        .get(format!("{base}/api/assets/{id}"))
        .bearer_auth(token.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(info.status(), 200, "persisted asset metadata unavailable");
    let info: Value = info.json().await.unwrap();
    assert_eq!(info["id"], id.to_string());
    assert_eq!(info["originalFileName"], "synthetic-native-photo.png");
    let response = client
        .get(format!("{base}/api/assets/{id}/original"))
        .bearer_auth(token.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), original);
    let response = client
        .get(&thumbnail)
        .bearer_auth(token.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap(), thumbnail_bytes);
    restarted.stop().unwrap();
}
