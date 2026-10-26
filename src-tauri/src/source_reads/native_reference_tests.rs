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
async fn action(base: &Path, saved: &SavedConnection, source: &str, recover: Option<&str>) -> View {
    let owner = Requests::default();
    let (send, mut receive) = tokio::sync::watch::channel(View::default());
    let notify: Arc<dyn Fn(View) + Send + Sync> = Arc::new(move |value| {
        send.send_replace(value);
    });
    if let Some(key) = recover {
        owner
            .recover_reference(
                base.to_owned(),
                saved.clone(),
                source.into(),
                key.into(),
                notify,
            )
            .await
            .unwrap();
    } else {
        owner
            .publish_reference(base.to_owned(), saved.clone(), source.into(), notify)
            .await
            .unwrap();
    }
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
                |value| crate::source_consent::persist(value, &saved, &identity),
            )
            .unwrap();
        consent.register(&saved, &identity).await.unwrap();
        crate::source_consent::persist(&consent, &saved, &identity).unwrap();
        let source = consent.source_id().to_owned();
        let mut preparation =
            Preparation::plan(&base, &saved, &identity, &source, "original.jpg").unwrap();
        preparation
            .approve(&saved, &identity, original.len() as u64)
            .unwrap();
        let prepared = preparation
            .stage_and_handoff(&saved, &identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        let first_scan = prepared.scan_id.clone();
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
        let job_record = job.journal.root.join("state.json");
        let job_before = fs::read(&job_record).unwrap();
        drop(job);
        let first = action(&base, &saved, &source, None).await;
        assert_eq!(first.code.as_deref(), Some("server_http_503"));
        report(
            json!({"phase":"lost-receipt","sourceId":source,"resourceKey":selected.resource_key,"sha256":selected.sha256,"bytes":selected.bytes}),
        );
        assert_eq!(read_fixture_message(&mut input)["command"], "resume");
        let edited = b"owner-edited independent original after lost reply";
        fs::write(source_root.join("original.jpg"), edited).unwrap();
        assert!(Job::resume(
            &base,
            &saved,
            &identity,
            &source,
            &selected.resource_key,
            &selected.version
        )
        .is_err());
        assert_eq!(
            action(&base, &saved, &source, None).await.state,
            "needs-attention"
        );
        let journal = Journal {
            root: base.join("photo-reads").join(&source).join("publications"),
        };
        let name = format!("{}.json", selected.resource_key);
        let pending_before = fs::read(journal.root.join(&name)).unwrap();
        let second = action(&base, &saved, &source, Some(&selected.resource_key)).await;
        assert_eq!(
            second.code.as_deref(),
            Some("source_reference_receipt_invalid")
        );
        assert_eq!(fs::read(journal.root.join(&name)).unwrap(), pending_before);
        report(json!({"phase":"foreign-receipt-refused"}));
        assert_eq!(read_fixture_message(&mut input)["command"], "resume");
        assert_eq!(
            action(&base, &saved, &source, Some(&selected.resource_key))
                .await
                .code
                .as_deref(),
            Some("server_http_409")
        );
        assert_eq!(fs::read(journal.root.join(&name)).unwrap(), pending_before);
        report(json!({"phase":"current-binding-refused","pendingAttemptUnchanged":true}));
        assert_eq!(read_fixture_message(&mut input)["command"], "resume");
        assert_eq!(
            action(&base, &saved, &source, Some(&selected.resource_key))
                .await
                .state,
            "stopped"
        );
        // Completed recovery uses GET only; a missing original cannot authorize a read.
        fs::remove_file(source_root.join("original.jpg")).unwrap();
        assert_eq!(
            action(&base, &saved, &source, Some(&selected.resource_key))
                .await
                .state,
            "stopped"
        );
        fs::write(source_root.join("original.jpg"), edited).unwrap();
        let state: Value = journal
            .read(&format!("{}.json", selected.resource_key), &identity)
            .unwrap();
        assert!(state["pending"].is_null());
        let receipt = &state["current"]["receipt"];
        assert_eq!(receipt["storage"], "reference");
        assert_eq!(receipt["resourceId"], receipt["itemId"]);
        assert!(Job::resume(
            &base,
            &saved,
            &identity,
            &source,
            &selected.resource_key,
            &selected.version
        )
        .is_err());
        assert_eq!(fs::read(&job_record).unwrap(), job_before);
        assert_eq!(fs::read(&stage).unwrap(), original);
        assert_eq!(fs::read(source_root.join("original.jpg")).unwrap(), edited);
        report(
            json!({"phase":"complete","receipt":receipt,"editedOriginalRetained":true,"originalValidationStillRequired":true,"cacheRetained":true,"readAndUploadAllowancesUnchanged":true}),
        );
        // Simulate local sign-out; its inactive record must never be usable by an original reader.
        credentials::delete(CREDENTIAL).unwrap();
        credentials::delete("connection").unwrap();
        assert!(crate::source_import::current(&saved, &identity, &source).is_err());
        let command = read_fixture_message(&mut input);
        assert_eq!(command["command"], "reconnect");
        let mut next = saved.clone();
        next.token = command["token"].as_str().unwrap().into();
        credentials::save("connection", &next).unwrap();
        let mut foreign = next.clone();
        foreign.account_id = "66666666-6666-4666-8666-666666666666".into();
        assert!(crate::source_consent::stored(&foreign, &identity)
            .unwrap()
            .is_none());
        let record = crate::source_consent::stored(&next, &identity)
            .unwrap()
            .unwrap();
        assert!(record.require(&saved, &identity).is_err());
        assert!(record.require(&next, &identity).is_err());
        assert_eq!(
            serde_json::to_value(record.session_view(&next, &identity).unwrap()).unwrap()
                ["reconnectRequired"],
            true
        );
        let mut reconnected = record.reconnect_candidate(&next, &identity).unwrap();
        assert!(reconnected.reference_approval(&next, &identity).is_err());
        reconnected.register(&next, &identity).await.unwrap();
        crate::source_consent::persist(&reconnected, &next, &identity).unwrap();
        assert!(reconnected.copy_approval(&next, &identity).is_err());
        assert_eq!(
            action(&base, &next, &source, Some(&selected.resource_key))
                .await
                .state,
            "stopped"
        );
        let current: Value = journal
            .read(&format!("{}.json", selected.resource_key), &identity)
            .unwrap();
        assert_eq!(&current["current"]["receipt"], receipt);
        assert!(Job::resume(
            &base,
            &next,
            &identity,
            &source,
            &selected.resource_key,
            &selected.version
        )
        .is_err());
        assert_eq!(fs::read(&job_record).unwrap(), job_before);
        report(
            json!({"phase":"reconnected","receipt":receipt,"readAndUploadAllowancesUnchanged":true}),
        );
        assert_eq!(read_fixture_message(&mut input)["command"], "rescan");
        let scan_owner = Requests::default();
        let scan = scan_owner
            .prepare_reference(
                base.clone(),
                next.clone(),
                source.clone(),
                PreparationAction::Rescan {
                    relatives: vec!["original.jpg".into()],
                    expected_scan: first_scan.clone(),
                },
                Arc::new(|_| {}),
            )
            .await
            .unwrap();
        scan_owner.stop().await.unwrap();
        assert!(!scan.prepared);
        assert_eq!((scan.spent, scan.remaining), (0, 0));
        assert_ne!(scan.scan_id, first_scan);
        let publication_before = fs::read(journal.root.join(&name)).unwrap();
        fs::remove_file(source_root.join("original.jpg")).unwrap();
        let ended = scan_owner
            .prepare_reference(
                base.clone(),
                next.clone(),
                source.clone(),
                PreparationAction::Abandon {
                    expected_scan: scan.scan_id.clone(),
                },
                Arc::new(|_| {}),
            )
            .await
            .unwrap();
        scan_owner.stop().await.unwrap();
        assert!(ended.abandoned);
        assert!(!ended.prepared);
        assert_eq!((ended.spent, ended.remaining), (0, 0));
        assert_eq!(ended.scan_id, scan.scan_id);
        assert_eq!(fs::read(&job_record).unwrap(), job_before);
        assert_eq!(
            fs::read(journal.root.join(&name)).unwrap(),
            publication_before
        );
        fs::write(source_root.join("original.jpg"), edited).unwrap();
        let restarted = scan_owner
            .prepare_reference(
                base.clone(),
                next.clone(),
                source.clone(),
                PreparationAction::Rescan {
                    relatives: vec!["original.jpg".into()],
                    expected_scan: ended.scan_id.clone(),
                },
                Arc::new(|_| {}),
            )
            .await
            .unwrap();
        scan_owner.stop().await.unwrap();
        assert!(!restarted.abandoned);
        assert_eq!((restarted.spent, restarted.remaining), (0, 0));
        assert_ne!(restarted.scan_id, ended.scan_id);
        assert!(scan_owner
            .prepare_reference(
                base.clone(),
                next.clone(),
                source.clone(),
                PreparationAction::Abandon {
                    expected_scan: ended.scan_id,
                },
                Arc::new(|_| {}),
            )
            .await
            .is_err());
        scan_owner.stop().await.unwrap();
        let mut preparation = Preparation::resume(&base, &next, &identity, &source).unwrap();
        assert!(!preparation.view(&next, &identity).unwrap().abandoned);
        assert!(preparation
            .stage_and_handoff(&next, &identity, &AtomicBool::new(false), &|| Ok(()))
            .is_err());
        preparation
            .approve(&next, &identity, edited.len() as u64)
            .unwrap();
        let prepared = preparation
            .stage_and_handoff(&next, &identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        assert!(prepared.prepared);
        assert_eq!(
            (prepared.spent, prepared.remaining),
            (edited.len() as u64, 0)
        );
        let fresh = preparation.prepared_resources(&next, &identity).unwrap();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].resource_key, selected.resource_key);
        assert_ne!(fresh[0].version, selected.version);
        assert!(preparation
            .journal
            .root
            .join(format!("preparation-plan-{first_scan}.json"))
            .exists());
        drop(preparation);
        assert_eq!(action(&base, &next, &source, None).await.state, "stopped");
        let updated: Value = journal.read(&name, &identity).unwrap();
        let replacement = &updated["current"]["receipt"];
        assert!(updated["pending"].is_null());
        assert_eq!(replacement["assetId"], receipt["assetId"]);
        assert_ne!(replacement["resourceId"], receipt["resourceId"]);
        let job = Job::resume(
            &base,
            &next,
            &identity,
            &source,
            &fresh[0].resource_key,
            &fresh[0].version,
        )
        .unwrap();
        let view = serde_json::to_value(job.state(&next, &identity).unwrap()).unwrap();
        assert_eq!(view["read"], json!({"used":0,"limit":0}));
        assert_eq!(view["upload"], json!({"used":0,"limit":0}));
        assert_eq!(fs::read(&job_record).unwrap(), job_before);
        drop(job);
        report(
            json!({"phase":"rescanned","receipt":replacement,"explicitReadSpent":prepared.spent,"remaining":prepared.remaining,"oldReadAndUploadAllowancesUnchanged":true,"newReadAndUploadAllowancesZero":true}),
        );
        assert_eq!(read_fixture_message(&mut input)["command"], "forget");
        crate::source_consent::forget_reference(&source, &next, &identity).unwrap();
        credentials::delete(CREDENTIAL).unwrap();
        assert!(crate::source_consent::stored(&next, &identity)
            .unwrap()
            .is_none());
        reconnected
            .revocation_candidate(&next, &identity)
            .unwrap()
            .revoke(&next, &identity)
            .await
            .unwrap();
        assert_eq!(fs::read(&stage).unwrap(), original);
        assert_eq!(fs::read(source_root.join("original.jpg")).unwrap(), edited);
        report(json!({"phase":"forgotten","originalAndCacheRetained":true}));
    });
}
