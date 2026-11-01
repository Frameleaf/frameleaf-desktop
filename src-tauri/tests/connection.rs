use frameleaf_desktop::connection::{enrollment_message, normalize_server, EnrollmentRequest};

#[test]
fn server_selection_requires_tls_and_refuses_credentials_paths_and_fragments() {
    assert_eq!(
        normalize_server("https://nas.example:2283/")
            .unwrap()
            .as_str(),
        "https://nas.example:2283/"
    );
    for value in [
        "http://nas.local",
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
