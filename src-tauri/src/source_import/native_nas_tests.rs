//! Opt-in consuming-client proof against the owned HTTPS/PostgreSQL NAS fixture.
use super::*;
use crate::ml_transport::native_nas_tests::{install_test_keyring, read_fixture_message};
use std::io::{BufReader, Write};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    server: String,
    account_id: String,
    token: String,
    ca_pem: String,
    root: PathBuf,
}
fn report(value: Value) {
    println!("FOLDER_COPY {}", value);
    std::io::stdout().flush().unwrap();
}
#[test]
#[ignore = "requires the owned NAS HTTPS/PostgreSQL fixture; run alone with process-only credentials"]
fn actual_native_folder_copy() {
    install_test_keyring();
    let mut input = BufReader::new(std::io::stdin());
    let configuration: Configuration =
        serde_json::from_value(read_fixture_message(&mut input)).unwrap();
    let base = crate::connection::normalize_server(&configuration.server).unwrap();
    assert_eq!(base.host_str(), Some("tun.eu1.relays.frameleaf.test"));
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .add_root_certificate(
            reqwest::Certificate::from_pem(configuration.ca_pem.as_bytes()).unwrap(),
        )
        .resolve(
            base.host_str().unwrap(),
            ([127, 0, 0, 1], base.port().unwrap()).into(),
        )
        .build()
        .unwrap();
    transport::FIXTURE_CLIENT.set(client.clone()).unwrap();
    tauri::async_runtime::block_on(async {
        let identity = credentials::identity().unwrap();
        let mut saved = SavedConnection {
            server: base.to_string(),
            server_id: String::new(),
            account_id: configuration.account_id,
            token: configuration.token,
            name: "Synthetic photo owner".into(),
            device_name: "Synthetic copy desktop".into(),
            mode: "client-worker".into(),
            device_id: None,
        };
        saved.server_id = transport::capabilities(&client, &saved)
            .await
            .unwrap()
            .unwrap()
            .server_id;
        saved.device_id = Some(transport::enroll(&client, &saved).await.unwrap().id);
        credentials::save("connection", &saved).unwrap();
        for name in ["source", "data"] {
            crate::runtime_store::private_directory(&configuration.root.join(name)).unwrap();
        }
        let source = configuration.root.join("source");
        let data = configuration.root.join("data");
        let original = vec![42u8; 2 * 1024 * 1024 + 7];
        fs::write(source.join("synthetic.jpg"), &original).unwrap();
        let picker = crate::source_consent::SourceConsent::default();
        let chosen = picker
            .select(picker.generation().unwrap(), source.clone())
            .unwrap();
        let mut consent = picker
            .approve(&saved, &identity, &chosen.selection_id, true, |value| {
                credentials::save(CREDENTIAL, value)
            })
            .unwrap();
        consent.register(&saved, &identity).await.unwrap();
        credentials::save(CREDENTIAL, &consent).unwrap();
        let manifest = manifest_for(&consent, &saved, &identity, &data).unwrap();
        let journal = Journal::new(&data, consent.source_id()).unwrap();
        journal
            .write("manifest.json", &manifest, &identity)
            .unwrap();
        journal
            .write("cursor.json", &Cursor::new(&manifest).unwrap(), &identity)
            .unwrap();
        let cancel = AtomicBool::new(false);
        let gate = || current(&saved, &identity, consent.source_id()).map(|_| ());
        let run = || {
            execute(
                &client,
                &base,
                &saved,
                &identity,
                &consent,
                &journal,
                &cancel,
                &gate,
                &|_| {},
            )
        };
        assert_eq!(run().await.err().as_deref(), Some("server_http_503"));
        let cursor: Cursor = journal.read("cursor.json", &identity).unwrap();
        let active = cursor.active.as_ref().unwrap();
        let stage = journal
            .root
            .join("stage")
            .join(&active.stage_id)
            .join("original");
        assert_eq!(fs::read(&stage).unwrap(), original);
        assert!(active.receipt.is_none());
        report(
            json!({"phase":"lost-receipt","sourceId":manifest.source_id,"runId":manifest.id,
            "deviceId":saved.device_id,"itemId":active.item_id,"sha256":active.copy.as_ref().unwrap().sha256,
            "bytes":original.len()}),
        );
        assert_eq!(read_fixture_message(&mut input)["command"], "resume");
        assert_eq!(run().await.err().as_deref(), Some("server_http_409"));
        assert_eq!(fs::read(&stage).unwrap(), original);
        report(json!({"phase":"unhealthy-copy-retained"}));
        assert_eq!(read_fixture_message(&mut input)["command"], "resume");
        run().await.unwrap();
        let cursor: Cursor = journal.read("cursor.json", &identity).unwrap();
        assert_eq!(cursor.state, "complete");
        assert_eq!(cursor.position, 1);
        assert!(cursor.active.is_none());
        assert!(!stage.exists());
        assert_eq!(fs::read(source.join("synthetic.jpg")).unwrap(), original);
        report(json!({"phase":"complete","originalUnchanged":true,"stagingReleased":true}));
    });
}
