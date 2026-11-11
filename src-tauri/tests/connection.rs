use frameleaf_desktop::connection::{enrollment_message, normalize_server, EnrollmentRequest};

#[test]
fn server_selection_requires_tls_off_the_local_network_and_refuses_credentials_paths_and_fragments()
{
    assert_eq!(
        normalize_server("https://nas.example:2283/")
            .unwrap()
            .as_str(),
        "https://nas.example:2283/"
    );
    assert!(normalize_server("http://nas.local").is_ok());
    for value in [
        "http://nas.example",
        "http://user:pass@nas.local",
        "https://user:pass@nas.local",
        "https://nas.local/api",
        "https://nas.local/?token=secret",
        "https://nas.local/#secret",
        "file:///etc/passwd",
        "https://nas.local\\@evil.example",
    ] {
        assert!(normalize_server(value).is_err(), "accepted {value}");
    }
}

#[test]
fn enrollment_signature_binds_server_account_and_every_device_field() {
    let dto = EnrollmentRequest {
        protocol_version: 1,
        installation_id: "d".into(),
        request_id: "r".into(),
        public_key: "p".into(),
        name: "Mac".into(),
        platform: "macos".into(),
        architecture: "arm64".into(),
        mode: "client-worker".into(),
        timestamp: 100,
        signature: String::new(),
    };
    let message = enrollment_message("server", "account", &dto);
    assert_eq!(message, "frameleaf-desktop/enroll/v1\nserver\naccount\nd\nr\n100\np\nMac\nmacos\narm64\nclient-worker");
    assert_ne!(message, enrollment_message("other", "account", &dto));
    assert_ne!(message, enrollment_message("server", "other", &dto));
}

#[test]
fn remote_pages_and_non_setup_windows_never_receive_native_authority() {
    use frameleaf_desktop::connection::native_origin_allowed;
    use url::Url;
    assert!(native_origin_allowed(
        "main",
        &Url::parse("tauri://localhost/").unwrap(),
        false
    ));
    assert!(!native_origin_allowed(
        "photos",
        &Url::parse("tauri://localhost/").unwrap(),
        false
    ));
    assert!(!native_origin_allowed(
        "main",
        &Url::parse("https://nas.example/").unwrap(),
        true
    ));
    assert!(!native_origin_allowed(
        "main",
        &Url::parse("http://localhost:1420/").unwrap(),
        false
    ));
    assert!(native_origin_allowed(
        "main",
        &Url::parse("http://localhost:1420/").unwrap(),
        true
    ));
    assert!(!native_origin_allowed(
        "main",
        &Url::parse("http://localhost:1421/").unwrap(),
        true
    ));
}

#[test]
fn native_origin_checks_include_port_and_userinfo() {
    use frameleaf_desktop::connection::native_origin_allowed;
    use url::Url;
    for value in [
        "http://tauri.localhost:9999/",
        "https://tauri.localhost:1234/",
        "tauri://user@localhost/",
    ] {
        assert!(
            !native_origin_allowed("main", &Url::parse(value).unwrap(), true),
            "accepted {value}"
        );
    }
}

#[test]
fn navigation_scope_binds_server_origin_identity_and_account_without_using_credentials() {
    use frameleaf_desktop::connection::{ConnectionView, Features, SavedConnection};

    let mut saved = SavedConnection {
        server: "https://nas.example/".into(),
        server_id: "library".into(),
        account_id: "person".into(),
        name: "Pat".into(),
        token: "secret".into(),
        device_name: "Mac".into(),
        mode: "client".into(),
        device_id: None,
    };
    let scope = |saved: &SavedConnection, state: &str| {
        ConnectionView::new(
            saved,
            state.into(),
            Features {
                enrollment: true,
                worker: false,
                worker_session: false,
                sources: false,
                native_host: false,
            },
        )
        .navigation_scope
    };
    let original = scope(&saved, "ready");
    assert_eq!(original.as_ref().unwrap().len(), 64);
    saved.token = "new secret".into();
    assert_eq!(scope(&saved, "ready"), original);
    assert_eq!(scope(&saved, "identity-changed"), None);
    for change in [
        ("https://other.example/", "library", "person"),
        ("https://nas.example/", "other-library", "person"),
        ("https://nas.example/", "library", "other-person"),
    ] {
        saved.server = change.0.into();
        saved.server_id = change.1.into();
        saved.account_id = change.2.into();
        assert_ne!(scope(&saved, "ready"), original);
    }
}
