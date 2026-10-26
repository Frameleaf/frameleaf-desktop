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
        let status = owner
            .reference_status(base.to_owned(), saved.clone(), source.into())
            .await
            .unwrap()
            .unwrap();
        owner.stop().await.unwrap();
        let entry = status
            .publications
            .iter()
            .find(|entry| entry.resource_key == key)
            .unwrap();
        let request = RecoveryRequest {
            source_id: source.into(),
            resource_key: key.into(),
            record_id: entry.record_id.clone(),
            request_id: uuid::Uuid::new_v4().to_string(),
        };
        let source = source.to_owned();
        owner
            .start_reference_recovery(
                base.to_owned(),
                saved.clone(),
                request,
                Arc::new(move |value| {
                    notify(View {
                        source_id: source.clone(),
                        state: value.state,
                        code: value.code,
                    })
                }),
            )
            .await
            .unwrap();
    } else {
        let status = owner
            .reference_status(base.to_owned(), saved.clone(), source.into())
            .await
            .unwrap()
            .unwrap();
        owner.stop().await.unwrap();
        let scan = status.scans.iter().find(|scan| scan.current).unwrap();
        let request = PreparationRequest {
            source_id: source.into(),
            scan_id: scan.scan_id.clone(),
            request_id: uuid::Uuid::new_v4().to_string(),
        };
        let source = source.to_owned();
        let publish_notify: Arc<dyn Fn(PreparationWork) + Send + Sync> = Arc::new(move |value| {
            notify(View {
                source_id: source.clone(),
                state: value.state,
                code: value.code,
            })
        });
        owner
            .start_reference_publication(
                base.to_owned(),
                saved.clone(),
                request.clone(),
                publish_notify.clone(),
            )
            .await
            .unwrap();
        owner
            .start_reference_publication(base.to_owned(), saved.clone(), request, publish_notify)
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
static PREPARATION_POLICY_GATE: std::sync::Mutex<
    Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
> = std::sync::Mutex::new(None);
fn allowed_preparation_policy() -> crate::resource_policy::Snapshot {
    if let Some((entered, finish)) = PREPARATION_POLICY_GATE.lock().unwrap().take() {
        entered.send(()).unwrap();
        finish
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
    }
    crate::resource_policy::Snapshot {
        external_power: Some(true),
        unmetered: Some(true),
        available_memory: Some(128 * 1024 * 1024),
    }
}
fn denied_preparation_policy() -> crate::resource_policy::Snapshot {
    crate::resource_policy::Snapshot {
        external_power: Some(false),
        ..allowed_preparation_policy()
    }
}
async fn owned_preparation(
    base: &Path,
    saved: &SavedConnection,
    source: &str,
    scan: &str,
    sample: fn() -> crate::resource_policy::Snapshot,
) -> PreparationWork {
    let owner = Requests::default();
    let request = PreparationRequest {
        source_id: source.into(),
        scan_id: scan.into(),
        request_id: uuid::Uuid::new_v4().to_string(),
    };
    let (send, mut receive) = tokio::sync::watch::channel(None::<PreparationWork>);
    let notify: Arc<dyn Fn(PreparationWork) + Send + Sync> = Arc::new(move |work| {
        send.send_replace(Some(work));
    });
    owner
        .start_reference_preparation_for_test(
            base.to_owned(),
            saved.clone(),
            request.clone(),
            notify.clone(),
            sample,
        )
        .await
        .unwrap();
    owner
        .start_reference_preparation_for_test(
            base.to_owned(),
            saved.clone(),
            request.clone(),
            notify,
            sample,
        )
        .await
        .unwrap();
    let work = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        receive.wait_for(|view| {
            view.as_ref().is_some_and(|view| {
                view.request == request
                    && matches!(view.state.as_str(), "stopped" | "needs-attention")
            })
        }),
    )
    .await
    .unwrap()
    .unwrap()
    .clone()
    .unwrap();
    owner.stop().await.unwrap();
    work
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
        let inspector = Requests::default();
        let local = inspector
            .reference_status(base.clone(), saved.clone(), source.clone())
            .await
            .unwrap()
            .unwrap();
        inspector.stop().await.unwrap();
        assert_eq!(local.publications.len(), 1);
        assert_eq!(local.publications[0].state, "publish");
        assert!(local.publications[0].receipt.is_none());
        assert_eq!(fs::read(journal.root.join(&name)).unwrap(), pending_before);
        let stale_owner = Requests::default();
        let (stale_send, mut stale_receive) = tokio::sync::watch::channel(None::<RecoveryWork>);
        stale_owner
            .start_reference_recovery(
                base.clone(),
                saved.clone(),
                RecoveryRequest {
                    source_id: source.clone(),
                    resource_key: selected.resource_key.clone(),
                    record_id: "f".repeat(64),
                    request_id: uuid::Uuid::new_v4().to_string(),
                },
                Arc::new(move |work| {
                    stale_send.send_replace(Some(work));
                }),
            )
            .await
            .unwrap();
        let refused = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stale_receive.wait_for(|work| {
                work.as_ref()
                    .is_some_and(|work| work.state == "needs-attention")
            }),
        )
        .await
        .unwrap()
        .unwrap()
        .clone()
        .unwrap();
        assert_eq!(refused.code.as_deref(), Some("source_publication_changed"));
        stale_owner.stop().await.unwrap();
        assert_eq!(fs::read(journal.root.join(&name)).unwrap(), pending_before);
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
        // Saved receipt inspection does not open originals, stages, or even require a preparation plan.
        let preparation_root = base.join("photo-preparations").join(&source);
        let detached = base.join("detached-synthetic-preparation");
        let publication_bytes = fs::read(journal.root.join(&name)).unwrap();
        fs::rename(&preparation_root, &detached).unwrap();
        let inspector = Requests::default();
        let local = inspector
            .reference_status(base.clone(), saved.clone(), source.clone())
            .await
            .unwrap()
            .unwrap();
        inspector.stop().await.unwrap();
        assert!(local.scans.is_empty());
        assert_eq!(local.publications.len(), 1);
        assert_eq!(local.publications[0].state, "recorded");
        assert!(local.publications[0].receipt.is_some());
        assert!(!preparation_root.exists());
        assert!(!source_root.join("original.jpg").exists());
        assert_eq!(
            fs::read(journal.root.join(&name)).unwrap(),
            publication_bytes
        );
        assert_eq!(fs::read(&job_record).unwrap(), job_before);
        fs::rename(&detached, &preparation_root).unwrap();
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
        fs::write(
            source_root.join("not-selected.jpg"),
            b"not part of the selected scope",
        )
        .unwrap();
        let scan_owner = Requests::default();
        let scan = scan_owner
            .prepare_reference(
                base.clone(),
                next.clone(),
                source.clone(),
                PreparationAction::RescanSelected {
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
        let capacity_before = crate::private_inputs::InputBudget::open(&base, &identity)
            .unwrap()
            .remaining()
            .unwrap();
        assert_eq!(scan.resources, 1);
        let approved = scan_owner
            .prepare_reference(
                base.clone(),
                next.clone(),
                source.clone(),
                PreparationAction::ApproveRead {
                    expected_scan: scan.scan_id.clone(),
                    additional: edited.len() as u64,
                },
                Arc::new(|_| {}),
            )
            .await
            .unwrap();
        scan_owner.stop().await.unwrap();
        assert_eq!(
            (approved.spent, approved.remaining),
            (0, edited.len() as u64)
        );
        let pending = Preparation::resume(&base, &next, &identity, &source).unwrap();
        let staged = pending
            .stage_with(&next, &identity, &AtomicBool::new(false), &|| Ok(()))
            .unwrap();
        let pending_plan: Value = pending
            .journal
            .read("preparation-plan.json", &identity)
            .unwrap();
        let pending_cache = pending
            .journal
            .root
            .join(format!(
                "stage-{}",
                pending_plan["generation"]["id"].as_str().unwrap()
            ))
            .join(&staged.id);
        let pending_state = pending.journal.root.join(format!(
            "preparation-state-{}.json",
            pending_plan["generation"]["id"].as_str().unwrap()
        ));
        drop(pending);
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
        assert_eq!((ended.spent, ended.remaining), (edited.len() as u64, 0));
        assert_eq!(ended.scan_id, scan.scan_id);
        assert_eq!(fs::read(&job_record).unwrap(), job_before);
        assert_eq!(
            fs::read(journal.root.join(&name)).unwrap(),
            publication_before
        );
        crate::source_reference_commands::require_reference_source(&next, &source).unwrap();
        assert!(crate::source_reference_commands::require_reference_source(
            &next,
            &uuid::Uuid::new_v4().to_string()
        )
        .is_err());
        let mut foreign_session = next.clone();
        foreign_session.token = "unbound-session".into();
        assert!(crate::source_reference_commands::require_reference_source(
            &foreign_session,
            &source
        )
        .is_err());
        let listed = scan_owner
            .reference_status(base.clone(), next.clone(), source.clone())
            .await
            .unwrap()
            .unwrap();
        scan_owner.stop().await.unwrap();
        assert_eq!(listed.source_id, source);
        assert_eq!(listed.scans[0].scan_id, ended.scan_id);
        assert_eq!(
            (listed.scans[0].spent, listed.scans[0].reserved_bytes),
            (edited.len() as u64, edited.len() as u64)
        );
        assert!(listed.scans[0].abandoned && listed.scans[0].discardable);
        let abandoned_before = fs::read(&pending_state).unwrap();
        let discarded = scan_owner
            .prepare_reference(
                base.clone(),
                next.clone(),
                source.clone(),
                PreparationAction::Discard {
                    expected_scan: ended.scan_id.clone(),
                },
                Arc::new(|_| {}),
            )
            .await
            .unwrap();
        scan_owner.stop().await.unwrap();
        assert!(discarded.abandoned);
        assert_eq!(
            (discarded.spent, discarded.remaining),
            (edited.len() as u64, 0)
        );
        assert!(!pending_cache.exists());
        let listed = scan_owner
            .reference_status(base.clone(), next.clone(), source.clone())
            .await
            .unwrap()
            .unwrap();
        scan_owner.stop().await.unwrap();
        assert_eq!(
            (listed.scans[0].spent, listed.scans[0].reserved_bytes),
            (edited.len() as u64, 0)
        );
        assert!(!listed.scans[0].discardable);
        assert_eq!(fs::read(&pending_state).unwrap(), abandoned_before);
        assert_eq!(fs::read(&job_record).unwrap(), job_before);
        assert_eq!(
            fs::read(journal.root.join(&name)).unwrap(),
            publication_before
        );
        assert_eq!(
            crate::private_inputs::InputBudget::open(&base, &identity)
                .unwrap()
                .remaining()
                .unwrap(),
            capacity_before
        );
        fs::write(source_root.join("original.jpg"), edited).unwrap();
        let restarted = scan_owner
            .prepare_reference(
                base.clone(),
                next.clone(),
                source.clone(),
                PreparationAction::RescanSelected {
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
        for (expected, code) in [
            (restarted.scan_id.clone(), "source_preparation_incomplete"),
            ("f".repeat(64), "source_scan_changed"),
        ] {
            let blocked = Requests::default();
            let (send, mut receive) = tokio::sync::watch::channel(None::<PreparationWork>);
            blocked
                .start_reference_publication(
                    base.clone(),
                    next.clone(),
                    PreparationRequest {
                        source_id: source.clone(),
                        scan_id: expected,
                        request_id: uuid::Uuid::new_v4().to_string(),
                    },
                    Arc::new(move |work| {
                        send.send_replace(Some(work));
                    }),
                )
                .await
                .unwrap();
            let refused = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                receive.wait_for(|work| {
                    work.as_ref()
                        .is_some_and(|work| work.state == "needs-attention")
                }),
            )
            .await
            .unwrap()
            .unwrap()
            .clone()
            .unwrap();
            assert_eq!(refused.code.as_deref(), Some(code));
            blocked.stop().await.unwrap();
            assert_eq!(
                fs::read(journal.root.join(&name)).unwrap(),
                publication_before
            );
        }
        let mut preparation = Preparation::resume(&base, &next, &identity, &source).unwrap();
        assert!(!preparation.view(&next, &identity).unwrap().abandoned);
        assert!(preparation
            .stage_and_handoff(&next, &identity, &AtomicBool::new(false), &|| Ok(()))
            .is_err());
        drop(preparation);
        assert_eq!(
            scan_owner
                .prepare_reference(
                    base.clone(),
                    next.clone(),
                    source.clone(),
                    PreparationAction::ApproveRead {
                        expected_scan: scan.scan_id.clone(),
                        additional: edited.len() as u64
                    },
                    Arc::new(|_| {})
                )
                .await
                .err()
                .as_deref(),
            Some("source_scan_changed")
        );
        scan_owner.stop().await.unwrap();
        let approved = scan_owner
            .prepare_reference(
                base.clone(),
                next.clone(),
                source.clone(),
                PreparationAction::ApproveRead {
                    expected_scan: restarted.scan_id.clone(),
                    additional: edited.len() as u64,
                },
                Arc::new(|_| {}),
            )
            .await
            .unwrap();
        scan_owner.stop().await.unwrap();
        assert_eq!(
            (approved.spent, approved.remaining),
            (0, edited.len() as u64)
        );
        assert_eq!(
            scan_owner
                .prepare_reference(
                    base.clone(),
                    next.clone(),
                    source.clone(),
                    PreparationAction::ApproveRead {
                        expected_scan: restarted.scan_id.clone(),
                        additional: edited.len() as u64
                    },
                    Arc::new(|_| {})
                )
                .await
                .err()
                .as_deref(),
            Some("source_read_budget_invalid")
        );
        scan_owner.stop().await.unwrap();
        let owner = Requests::default();
        let request = PreparationRequest {
            source_id: source.clone(),
            scan_id: restarted.scan_id.clone(),
            request_id: uuid::Uuid::new_v4().to_string(),
        };
        let (entered, waiting) = std::sync::mpsc::channel();
        let (release, finish) = std::sync::mpsc::channel();
        *PREPARATION_POLICY_GATE.lock().unwrap() = Some((entered, finish));
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            owner.start_reference_preparation_for_test(
                base.clone(),
                next.clone(),
                request.clone(),
                Arc::new(|_| {}),
                allowed_preparation_policy,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        waiting
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let mut pause = Box::pin(owner.pause_reference_preparation(&next, request));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(15), &mut pause)
                .await
                .is_err()
        );
        release.send(()).unwrap();
        assert_eq!(pause.await.unwrap().state, "paused");
        let policy_denied = owned_preparation(
            &base,
            &next,
            &source,
            &restarted.scan_id,
            denied_preparation_policy,
        )
        .await;
        assert_eq!(policy_denied.code.as_deref(), Some("on_battery"));
        let preparation = Preparation::resume(&base, &next, &identity, &source).unwrap();
        assert_eq!(
            (
                preparation.view(&next, &identity).unwrap().spent,
                preparation.view(&next, &identity).unwrap().remaining
            ),
            (0, edited.len() as u64)
        );
        drop(preparation);
        assert_eq!(
            owned_preparation(
                &base,
                &next,
                &source,
                &restarted.scan_id,
                allowed_preparation_policy
            )
            .await
            .state,
            "stopped"
        );
        let preparation = Preparation::resume(&base, &next, &identity, &source).unwrap();
        let prepared = preparation.view(&next, &identity).unwrap();
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
