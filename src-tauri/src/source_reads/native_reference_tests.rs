//! Opt-in native consumer against the owned HTTPS/PostgreSQL fixture; never the OS credential store.
use super::*;
use crate::ml_transport::native_nas_tests::{install_test_keyring, read_fixture_message};
use crate::{
    credentials,
    source_consent::{SourceConsent, SourceMode, CREDENTIAL},
    transport,
};
use serde_json::{json, Value};
use std::io::{BufReader, Write};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    server: String,
    account_id: String,
    token: String,
    ca_pem: String,
    root: std::path::PathBuf,
}
fn report(value: Value) {
    println!("REFERENCE_PUBLICATION {value}");
    std::io::stdout().flush().unwrap();
}
async fn publish(base: &Path, saved: &SavedConnection, source: &str) -> View {
    let owner = Requests::default();
    let (send, mut receive) = tokio::sync::watch::channel(View::default());
    owner
        .publish_reference(
            base.to_owned(),
            saved.clone(),
            source.into(),
            Arc::new(move |value| {
                send.send_replace(value);
            }),
        )
        .await
        .unwrap();
    let view = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        receive.wait_for(|v| {
            v.source_id == source && matches!(v.state.as_str(), "stopped" | "needs-attention")
        }),
    )
    .await
    .unwrap()
    .unwrap()
    .clone();
    owner.stop().await.unwrap();
    view
}
#[test]
#[ignore = "requires the owned HTTPS/PostgreSQL fixture; run alone with process-only credentials"]
fn actual_native_reference_publication() {
    install_test_keyring();
    let mut input = BufReader::new(std::io::stdin());
    let c: Configuration = serde_json::from_value(read_fixture_message(&mut input)).unwrap();
    let server = crate::connection::normalize_server(&c.server).unwrap();
    assert_eq!(server.host_str(), Some("tun.eu1.relays.frameleaf.test"));
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(std::time::Duration::from_secs(30))
        .add_root_certificate(reqwest::Certificate::from_pem(c.ca_pem.as_bytes()).unwrap())
        .resolve(
            server.host_str().unwrap(),
            ([127, 0, 0, 1], server.port().unwrap()).into(),
        )
        .build()
        .unwrap();
    transport::FIXTURE_CLIENT.set(client.clone()).unwrap();
    tauri::async_runtime::block_on(async {
        let identity = credentials::identity().unwrap();
        let mut saved = SavedConnection {
            server: server.to_string(),
            server_id: String::new(),
            account_id: c.account_id,
            token: c.token,
            name: "Synthetic reference owner".into(),
            device_name: "Synthetic desktop".into(),
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
            crate::runtime_store::private_directory(&c.root.join(name)).unwrap();
        }
        let source_root = c.root.join("source");
        let base = c.root.join("data");
        let original = b"synthetic independent reference original";
        fs::write(source_root.join("original.jpg"), original).unwrap();
        let picker = SourceConsent::default();
        let chosen = picker
            .select(picker.generation().unwrap(), source_root.clone())
            .unwrap();
        let mut consent = picker
            .approve_with_hydration(
                &saved,
                &identity,
                &chosen.selection_id,
                SourceMode::Reference,
                true,
                false,
                |value| credentials::save(CREDENTIAL, value),
            )
            .unwrap();
        consent.register(&saved, &identity).await.unwrap();
        credentials::save(CREDENTIAL, &consent).unwrap();
        let source = consent.source_id().to_owned();
        let mut preparation =
            Preparation::plan(&base, &saved, &identity, &source, "original.jpg").unwrap();
        preparation
            .approve(&saved, &identity, original.len() as u64)
            .unwrap();
        let prepared = preparation
            .stage_and_handoff(&saved, &identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert!(prepared.prepared);
        assert_eq!(prepared.spent, original.len() as u64);
        assert_eq!(prepared.remaining, 0);
        let resources = preparation.prepared_resources(&saved, &identity).unwrap();
        assert_eq!(resources.len(), 1);
        drop(preparation);
        let selected = &resources[0];
        let job = Job::resume(
            &base,
            &saved,
            &identity,
            &source,
            &selected.resource_key,
            &selected.version,
        )
        .unwrap();
        let before = serde_json::to_value(job.state(&saved, &identity).unwrap()).unwrap();
        assert_eq!(before["read"], json!({"used":0,"limit":0}));
        assert_eq!(before["upload"], json!({"used":0,"limit":0}));
        let stage = job
            .journal
            .root
            .join("stage")
            .join(before["stage"].as_str().unwrap())
            .join("original");
        drop(job);
        let first = publish(&base, &saved, &source).await;
        assert_eq!(first.code.as_deref(), Some("server_http_503"));
        report(
            json!({"phase":"lost-receipt","sourceId":source,"resourceKey":selected.resource_key,"sha256":selected.sha256,"bytes":selected.bytes}),
        );
        assert_eq!(read_fixture_message(&mut input)["command"], "resume");
        let second = publish(&base, &saved, &source).await;
        assert_eq!(
            second.code.as_deref(),
            Some("source_reference_receipt_invalid")
        );
        report(json!({"phase":"foreign-receipt-refused"}));
        assert_eq!(read_fixture_message(&mut input)["command"], "resume");
        assert_eq!(publish(&base, &saved, &source).await.state, "stopped");
        // A completed-run replay also keeps the original logical asset and item identity.
        assert_eq!(publish(&base, &saved, &source).await.state, "stopped");
        let journal = Journal {
            root: base.join("photo-reads").join(&source).join("publications"),
        };
        let state: Value = journal
            .read(&format!("{}.json", selected.resource_key), &identity)
            .unwrap();
        assert!(state["pending"].is_null());
        let receipt = &state["current"]["receipt"];
        assert_eq!(receipt["storage"], "reference");
        assert_eq!(receipt["resourceId"], receipt["itemId"]);
        let job = Job::resume(
            &base,
            &saved,
            &identity,
            &source,
            &selected.resource_key,
            &selected.version,
        )
        .unwrap();
        let after = serde_json::to_value(job.state(&saved, &identity).unwrap()).unwrap();
        assert_eq!(before["read"], after["read"]);
        assert_eq!(before["upload"], after["upload"]);
        assert_eq!(fs::read(&stage).unwrap(), original);
        assert_eq!(
            fs::read(source_root.join("original.jpg")).unwrap(),
            original
        );
        report(
            json!({"phase":"complete","receipt":receipt,"independentOriginalUnchanged":true,"cacheRetained":true,"readAndUploadAllowancesUnchanged":true}),
        );
    });
}
