use super::*;
use crate::host_epochs::host_fixture;
use crate::host_runtime::VerifiedHostRuntime;
use host_fixture::Fixture;
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};

struct Store {
    id: String,
    raw: RefCell<Option<Value>>,
    anchor: RefCell<Option<String>>,
    saves: Cell<usize>,
    events: RefCell<Vec<&'static str>>,
}
impl Store {
    fn new() -> Self {
        let identity = DeviceIdentity::generate();
        let mut raw = serde_json::to_value(&identity).unwrap();
        let scope = format!(
            "factory-v1/{}/{}/CPUExecutionProvider",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        raw["runtimeEpochs"] =
            json!({"accepted":{scope:{"epoch":999,"manifestSha256":"b".repeat(64)}}});
        Self {
            id: identity.installation_id.clone(),
            raw: RefCell::new(Some(raw)),
            anchor: RefCell::new(Some(identity.installation_id.clone())),
            saves: Cell::new(0),
            events: RefCell::new(Vec::new()),
        }
    }
    fn load(&self) -> Result<Option<DeviceIdentity>, String> {
        self.events.borrow_mut().push("load");
        self.raw
            .borrow()
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| "credential_record_invalid".into())
    }
    fn marker(&self) -> Result<Option<String>, String> {
        self.events.borrow_mut().push("anchor");
        Ok(self.anchor.borrow().clone())
    }
    fn save(&self, identity: &DeviceIdentity) -> Result<(), String> {
        self.events.borrow_mut().push("save");
        self.saves.set(self.saves.get() + 1);
        *self.raw.borrow_mut() = Some(serde_json::to_value(identity).unwrap());
        Ok(())
    }
    fn id(&self) -> String {
        self.id.clone()
    }
    fn activate(
        &self,
        runtime: &VerifiedHostRuntime,
        publish: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        activate_host_with(
            &self.id(),
            runtime,
            || self.load(),
            || self.marker(),
            |identity| self.save(identity),
            publish,
        )
    }
    fn use_current(
        &self,
        runtime: &VerifiedHostRuntime,
        operation: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        with_host_admitted_with(
            &self.id(),
            runtime,
            || self.load(),
            || self.marker(),
            operation,
        )
    }
}

#[test]
fn unknown_identity_metadata_is_refused_before_a_save_can_discard_it() {
    let mut record = serde_json::to_value(DeviceIdentity::generate()).unwrap();
    record["futureCredentialMetadata"] = json!({"mustSurvive":true});
    assert!(serde_json::from_value::<DeviceIdentity>(record).is_err());
}

#[test]
fn confirmed_host_admission_precedes_publish_and_preserves_key_uuid_and_ml_history() {
    let store = Store::new();
    let original = store.raw.borrow().clone().unwrap();
    let original_key = store.load().unwrap().unwrap();
    store.events.borrow_mut().clear();
    let mut fixture = Fixture::new();
    fixture.1["epoch"] = json!(9);
    let runtime = fixture.verify().unwrap();
    store
        .activate(&runtime, &mut || {
            store.events.borrow_mut().push("publish");
            assert_eq!(
                store.raw.borrow().as_ref().unwrap()["hostEpochs"]["accepted"][0]["epoch"],
                9
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(
        *store.events.borrow(),
        ["load", "anchor", "save", "load", "anchor", "publish"]
    );
    let current = store.load().unwrap().unwrap();
    assert_eq!(current.installation_id, original_key.installation_id);
    assert_eq!(current.public_key(), original_key.public_key());
    assert_eq!(current.sign("preserved"), original_key.sign("preserved"));
    assert_eq!(
        store.raw.borrow().as_ref().unwrap()["runtimeEpochs"],
        original["runtimeEpochs"]
    );
    let used = Cell::new(0);
    store
        .use_current(&runtime, &mut || {
            used.set(used.get() + 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(used.get(), 1);
    let old = Fixture::new();
    assert_eq!(
        store
            .use_current(&old.verify().unwrap(), &mut || panic!("old root executed"))
            .unwrap_err(),
        "host_epoch_rollback"
    );
    fixture.1["epoch"] = json!(10);
    assert_eq!(
        store
            .use_current(&fixture.verify().unwrap(), &mut || panic!(
                "unadmitted future executed"
            ))
            .unwrap_err(),
        "host_epoch_not_admitted"
    );
    fixture.1["epoch"] = json!(9);
    fixture.1["sourceRevision"] = json!("c".repeat(40));
    assert_eq!(
        store
            .use_current(&fixture.verify().unwrap(), &mut || panic!(
                "reused epoch executed"
            ))
            .unwrap_err(),
        "host_epoch_reused"
    );
    assert_eq!(store.saves.get(), 1);
}

#[test]
fn missing_changed_legacy_unknown_and_invalid_credentials_never_save_or_publish() {
    let fixture = Fixture::new();
    let runtime = fixture.verify().unwrap();
    for mode in [
        "missing",
        "anchor_missing",
        "anchor_changed",
        "uuid_changed",
        "legacy",
        "unknown",
        "bad_host",
        "bad_ml",
    ] {
        let store = Store::new();
        match mode {
            "missing" => *store.raw.borrow_mut() = None,
            "anchor_missing" => *store.anchor.borrow_mut() = None,
            "anchor_changed" => *store.anchor.borrow_mut() = Some(uuid::Uuid::new_v4().to_string()),
            "uuid_changed" => {
                store.raw.borrow_mut().as_mut().unwrap()["installation_id"] =
                    json!(uuid::Uuid::new_v4().to_string())
            }
            "legacy" => {
                store
                    .raw
                    .borrow_mut()
                    .as_mut()
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove("hostEpochs");
            }
            "unknown" => {
                store.raw.borrow_mut().as_mut().unwrap()["futureMetadata"] = json!("preserve this")
            }
            "bad_host" => {
                store.raw.borrow_mut().as_mut().unwrap()["hostEpochs"] = json!({"accepted":[{"scope":"foreign","epoch":1,"manifestSha256":"a".repeat(64)}]})
            }
            "bad_ml" => {
                store.raw.borrow_mut().as_mut().unwrap()["runtimeEpochs"] =
                    json!({"accepted":{"foreign":{"epoch":1,"manifestSha256":"a".repeat(64)}}})
            }
            _ => unreachable!(),
        }
        let before = store.raw.borrow().clone();
        assert!(
            store
                .activate(&runtime, &mut || panic!("invalid record published"))
                .is_err(),
            "{mode}"
        );
        assert!(
            store
                .use_current(&runtime, &mut || panic!("invalid record executed"))
                .is_err(),
            "{mode}"
        );
        assert_eq!(store.saves.get(), 0, "{mode}");
        assert_eq!(*store.raw.borrow(), before, "{mode}");
    }
    let store = Store::new();
    assert_eq!(
        activate_host_with(
            &store.id(),
            &runtime,
            || Err("locked".into()),
            || store.marker(),
            |value| store.save(value),
            &mut || panic!("locked store published")
        )
        .unwrap_err(),
        "locked"
    );
    assert_eq!(store.saves.get(), 0);
    assert_eq!(
        store
            .use_current(&runtime, &mut || panic!("empty history executed"))
            .unwrap_err(),
        "host_epoch_not_admitted"
    );
    assert!(activate_host_with(
        &uuid::Uuid::new_v4().to_string(),
        &runtime,
        || store.load(),
        || store.marker(),
        |value| store.save(value),
        &mut || panic!("foreign binding published")
    )
    .is_err());
    assert_eq!(store.saves.get(), 0);
}

#[test]
fn failed_save_and_unconfirmed_readback_never_publish_or_restore_an_old_floor() {
    let mut fixture = Fixture::new();
    fixture.1["epoch"] = json!(9);
    let runtime = fixture.verify().unwrap();
    let store = Store::new();
    let original = store.raw.borrow().clone();
    assert_eq!(
        activate_host_with(
            &store.id(),
            &runtime,
            || store.load(),
            || store.marker(),
            |_| Err("save_locked".into()),
            &mut || panic!("failed write published")
        )
        .unwrap_err(),
        "save_locked"
    );
    assert_eq!(*store.raw.borrow(), original);
    let committed = Store::new();
    assert_eq!(
        activate_host_with(
            &committed.id(),
            &runtime,
            || committed.load(),
            || committed.marker(),
            |identity| {
                committed.save(identity)?;
                Err("save_result_ambiguous".into())
            },
            &mut || panic!("ambiguous save published")
        )
        .unwrap_err(),
        "save_result_ambiguous"
    );
    assert_eq!(
        committed.raw.borrow().as_ref().unwrap()["hostEpochs"]["accepted"][0]["epoch"],
        9
    );
    committed.activate(&runtime, &mut || Ok(())).unwrap();
    for mode in [
        "missing", "locked", "key", "history", "ml", "unknown", "anchor",
    ] {
        let store = Store::new();
        assert!(
            activate_host_with(
                &store.id(),
                &runtime,
                || {
                    if store.saves.get() == 0 {
                        return store.load();
                    }
                    let mut value = store.raw.borrow().clone().unwrap();
                    match mode {
                        "missing" => return Ok(None),
                        "locked" => return Err("locked_after_save".into()),
                        "key" => {
                            value["secret"] = serde_json::to_value(DeviceIdentity::generate())
                                .unwrap()["secret"]
                                .clone()
                        }
                        "history" => value["hostEpochs"] = json!({"accepted":[]}),
                        "ml" => value["runtimeEpochs"] = json!({"accepted":{}}),
                        "unknown" => value["futureMetadata"] = json!(true),
                        "anchor" => {}
                        _ => unreachable!(),
                    }
                    serde_json::from_value(value)
                        .map(Some)
                        .map_err(|_| "credential_record_invalid".into())
                },
                || {
                    if mode == "anchor" && store.saves.get() > 0 {
                        return Ok(Some(uuid::Uuid::new_v4().to_string()));
                    }
                    store.marker()
                },
                |identity| store.save(identity),
                &mut || panic!("unconfirmed write published")
            )
            .is_err(),
            "{mode}"
        );
        assert_eq!(store.saves.get(), 1, "{mode}");
        assert_eq!(
            store.raw.borrow().as_ref().unwrap()["hostEpochs"]["accepted"][0]["epoch"],
            9
        );
        store.activate(&runtime, &mut || Ok(())).unwrap();
    }
}

#[test]
fn failed_publication_retains_high_history_and_exact_retry_works_from_another_root() {
    let store = Store::new();
    let mut newer = Fixture::new();
    newer.1["epoch"] = json!(8);
    let runtime = newer.verify().unwrap();
    let publishes = Cell::new(0);
    assert_eq!(
        store
            .activate(&runtime, &mut || {
                publishes.set(publishes.get() + 1);
                Err("journal_write_failed".into())
            })
            .unwrap_err(),
        "journal_write_failed"
    );
    assert_eq!(publishes.get(), 1);
    let old = Fixture::new();
    assert_eq!(
        store
            .activate(&old.verify().unwrap(), &mut || panic!("rollback published"))
            .unwrap_err(),
        "host_epoch_rollback"
    );
    let mut retry = Fixture::new();
    retry.1["epoch"] = json!(8);
    let before = store.raw.borrow().clone();
    store
        .activate(&retry.verify().unwrap(), &mut || {
            publishes.set(publishes.get() + 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(publishes.get(), 2);
    assert_eq!(*store.raw.borrow(), before);
}

#[test]
fn changed_retained_payload_never_advances_or_executes_after_admission() {
    let store = Store::new();
    let fixture = Fixture::new();
    let runtime = fixture.verify().unwrap();
    std::fs::write(fixture.0.join("node"), b"tampered").unwrap();
    assert!(store
        .activate(&runtime, &mut || panic!("tampered candidate published"))
        .is_err());
    assert_eq!(store.saves.get(), 0);
    std::fs::write(fixture.0.join("node"), b"fixture").unwrap();
    store.activate(&runtime, &mut || Ok(())).unwrap();
    std::fs::write(fixture.0.join("node"), b"tampered").unwrap();
    assert!(store
        .use_current(&runtime, &mut || panic!(
            "tampered admitted object executed"
        ))
        .is_err());
    assert_eq!(store.saves.get(), 1);
}

#[test]
fn host_first_enrollment_needs_fresh_proof_and_never_reenrolls_existing_or_legacy_credentials() {
    let record = RefCell::new(None::<String>);
    let marker = RefCell::new(None::<String>);
    assert_eq!(
        enroll_host_identity_with(
            || Ok(None),
            |_| panic!("nonempty profile must not enroll"),
            || Ok(None),
            |_| panic!("must not create anchor"),
            || Err("native_profile_recovery_required".into())
        )
        .err()
        .as_deref(),
        Some("native_profile_recovery_required")
    );
    let fresh = enroll_host_identity_with(
        || Ok(None),
        |identity| {
            *record.borrow_mut() = Some(serde_json::to_string(identity).unwrap());
            Ok(())
        },
        || Ok(None),
        |id| {
            *marker.borrow_mut() = Some(id.into());
            Ok(())
        },
        || Ok(()),
    )
    .unwrap();
    assert_eq!(
        marker.borrow().as_deref(),
        Some(fresh.installation_id.as_str())
    );
    let saved = serde_json::from_str::<DeviceIdentity>(record.borrow().as_ref().unwrap()).unwrap();
    assert_eq!(saved.public_key(), fresh.public_key());
    assert!(saved.host_epochs.is_some());
    let mut legacy = serde_json::to_value(&saved).unwrap();
    legacy.as_object_mut().unwrap().remove("hostEpochs");
    let restored = enroll_host_identity_with(
        || Ok(Some(serde_json::from_value(legacy).unwrap())),
        |_| panic!("must preserve legacy record"),
        || Ok(marker.borrow().clone()),
        |_| panic!("must preserve anchor"),
        || panic!("existing identity does not need empty roots"),
    )
    .unwrap();
    assert!(restored.host_epochs.is_none());
    assert_eq!(restored.public_key(), fresh.public_key());
    assert!(enroll_host_identity_with(
        || Ok(None),
        |_| panic!("deleted credential must not reenroll"),
        || Ok(marker.borrow().clone()),
        |_| panic!("must not replace anchor"),
        || panic!("missing existing record must refuse first")
    )
    .is_err());
}

#[test]
fn host_handover_confirms_target_after_source_prepare_and_preserves_entire_device_identity() {
    let store = Store::new();
    let source_fixture = Fixture::new();
    let source = source_fixture.verify().unwrap();
    let mut target_fixture = Fixture::new();
    target_fixture.1["epoch"] = json!(2);
    let target = target_fixture.verify().unwrap();
    store.activate(&source, &mut || Ok(())).unwrap();
    let original = store.load().unwrap().unwrap();
    let mut before = store.raw.borrow().clone().unwrap();
    before.as_object_mut().unwrap().remove("hostEpochs");
    let saves = store.saves.get();
    let prepared = Cell::new(false);
    transition_host_with(
        &store.id(),
        [&source, &target],
        || store.load(),
        || store.marker(),
        |id| store.save(id),
        &mut || {
            assert_eq!(store.saves.get(), saves);
            store.use_current(&source, &mut || Ok(())).unwrap();
            prepared.set(true);
            Ok(())
        },
        &mut || {
            assert!(prepared.get());
            assert_eq!(store.saves.get(), saves + 1);
            store.use_current(&target, &mut || Ok(())).unwrap();
            assert!(store.use_current(&source, &mut || Ok(())).is_err());
            Ok(())
        },
    )
    .unwrap();
    let current = store.load().unwrap().unwrap();
    assert_eq!(current.installation_id, original.installation_id);
    assert_eq!(current.public_key(), original.public_key());
    assert_eq!(current.sign("handover"), original.sign("handover"));
    let mut after = store.raw.borrow().clone().unwrap();
    after.as_object_mut().unwrap().remove("hostEpochs");
    assert_eq!(after, before);
    assert_eq!(
        store.raw.borrow().as_ref().unwrap()["hostEpochs"]["accepted"][0]["epoch"],
        2
    );
}

#[test]
fn host_handover_failures_never_publish_unconfirmed_target_or_restore_saved_source_floor() {
    for fault in [
        "prepare",
        "same-epoch",
        "stale-source",
        "target-code",
        "source-code",
        "credential-drift",
        "anchor",
        "save",
        "discard",
        "ambiguous-save",
        "readback",
        "target-code-save",
        "publish",
    ] {
        let store = Store::new();
        let source_fixture = Fixture::new();
        let source = source_fixture.verify().unwrap();
        let mut target_fixture = Fixture::new();
        target_fixture.1["epoch"] = json!(2);
        let target = target_fixture.verify().unwrap();
        store.activate(&source, &mut || Ok(())).unwrap();
        if fault == "stale-source" {
            store.activate(&target, &mut || Ok(())).unwrap();
        }
        let published = Cell::new(false);
        let loads = Cell::new(0);
        let prepared = Cell::new(false);
        let result = transition_host_with(
            &store.id(),
            [
                &source,
                if fault == "same-epoch" {
                    &source
                } else {
                    &target
                },
            ],
            || {
                loads.set(loads.get() + 1);
                let value = store.load()?;
                if fault == "readback" && loads.get() == 3 {
                    let mut changed = serde_json::to_value(value.unwrap()).unwrap();
                    changed["secret"] = json!(vec![7; 32]);
                    return serde_json::from_value(changed)
                        .map(Some)
                        .map_err(|_| "bad fixture".into());
                }
                Ok(value)
            },
            || store.marker(),
            |id| {
                if fault == "save" {
                    return Err("save refused".into());
                }
                if fault == "discard" {
                    return Ok(());
                }
                store.save(id)?;
                if fault == "target-code-save" {
                    std::fs::write(target_fixture.0.join("node"), b"changed during save").unwrap();
                }
                if fault == "ambiguous-save" {
                    return Err("saved but reply lost".into());
                }
                Ok(())
            },
            &mut || {
                prepared.set(true);
                match fault {
                    "prepare" => return Err("backup or intent refused".into()),
                    "source-code" => std::fs::write(
                        source_fixture.0.join("node"),
                        b"source changed after preparation",
                    )
                    .unwrap(),
                    "target-code" => {
                        std::fs::write(target_fixture.0.join("node"), b"changed after preparation")
                            .unwrap()
                    }
                    "credential-drift" => {
                        store.raw.borrow_mut().as_mut().unwrap()["secret"] = json!(vec![7; 32])
                    }
                    "anchor" => {
                        *store.anchor.borrow_mut() =
                            Some("22222222-2222-4222-8222-222222222222".into())
                    }
                    _ => {}
                }
                Ok(())
            },
            &mut || {
                published.set(true);
                if fault == "publish" {
                    Err("publication interrupted".into())
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.is_err(), "accepted {fault}");
        assert_eq!(published.get(), fault == "publish", "published {fault}");
        assert_eq!(
            prepared.get(),
            !matches!(fault, "same-epoch" | "stale-source")
        );
        let saved_epoch = if matches!(
            fault,
            "stale-source" | "ambiguous-save" | "readback" | "target-code-save" | "publish"
        ) {
            2
        } else {
            1
        };
        assert_eq!(
            store.raw.borrow().as_ref().unwrap()["hostEpochs"]["accepted"][0]["epoch"],
            saved_epoch,
            "floor changed incorrectly for {fault}"
        );
        if saved_epoch == 2 {
            assert!(store
                .use_current(&source, &mut || panic!("old source executed"))
                .is_err());
        }
    }
}
