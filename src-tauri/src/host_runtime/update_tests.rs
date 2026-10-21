use super::*;
use crate::host_epochs::{
    host_authority::{Authority, ID as SECURE_ID},
    host_fixture::Fixture as HostFixture,
    HostEpochAuthority,
};
use crate::host_runtime::{HostMode, VerifiedHostRuntime};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
const ID: &str = "aaaaaaaaaaaa";
struct Fixture {
    source: HostFixture,
    target: HostFixture,
    current: VerifiedHostRuntime,
    next: VerifiedHostRuntime,
    state: PathBuf,
    authority: Authority,
}
impl Fixture {
    fn new() -> Self {
        Self::with_target(|_| {})
    }
    fn with_target(prepare: impl FnOnce(&mut HostFixture)) -> Self {
        let source = HostFixture::new();
        let mut target = HostFixture::new();
        target.1["epoch"] = json!(2);
        target.1["sourceRevision"] = json!("b".repeat(40));
        prepare(&mut target);
        let current = source.verify().unwrap();
        let next = target.verify().unwrap();
        let state = source.2.with_extension("state");
        let mut owner = crate::host_state::Owner::acquire(&state, true, SECURE_ID).unwrap();
        owner
            .activate(ID, current.manifest_sha256(), HostMode::Server)
            .unwrap();
        owner.clean_stop().unwrap();
        drop(owner);
        crate::runtime_store::private_directory(&state.join("database")).unwrap();
        fs::write(state.join("database/original"), b"untouched original").unwrap();
        fs::write(state.join("host-state.json"),format!("{{\"schemaVersion\":1,\"manifestSha256\":\"{}\",\"sourceRevision\":\"{}\",\"postgresMajor\":\"19\"}}\n",current.manifest_sha256(),current.source_revision())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                state.join("host-state.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let authority = Authority::admitted(&current);
        Self {
            source,
            target,
            current,
            next,
            state,
            authority,
        }
    }
    fn review(&self) -> Result<HostUpdateReview, String> {
        self.current
            .review_update(&self.next, &self.state, ID, &self.authority.execution())
    }
    fn marker(&self) -> Value {
        serde_json::from_slice(&fs::read(self.state.join("controller-state.json")).unwrap())
            .unwrap()
    }
    fn change_marker(&self, change: impl FnOnce(&mut Value)) {
        let mut m = self.marker();
        change(&mut m);
        fs::write(
            self.state.join("controller-state.json"),
            serde_json::to_vec(&m).unwrap(),
        )
        .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.state);
    }
}

#[test]
fn initial_review_returns_facts_without_changing_state_credentials_or_history() {
    let f = Fixture::new();
    let journal = fs::read(f.state.join("controller-state.json")).unwrap();
    let host = fs::read(f.state.join("host-state.json")).unwrap();
    let before = {
        let a = f.authority.0.lock().unwrap();
        (a.0.clone(), serde_json::to_vec(&a.1).unwrap())
    };
    let result = serde_json::to_value(f.review().unwrap()).unwrap();
    assert_eq!(result["state"], "reviewed");
    assert_eq!(result["installationId"], ID);
    assert_eq!(result["secureInstallationId"], SECURE_ID);
    assert_eq!(result["generation"], f.marker()["generation"]);
    assert_eq!(result["fromEpoch"], 1);
    assert_eq!(result["toEpoch"], 2);
    assert_eq!(result["fromManifestSha256"], f.current.manifest_sha256());
    assert_eq!(result["toManifestSha256"], f.next.manifest_sha256());
    assert!(result.get("canApply").is_none());
    assert_eq!(
        fs::read(f.state.join("controller-state.json")).unwrap(),
        journal
    );
    assert_eq!(fs::read(f.state.join("host-state.json")).unwrap(), host);
    assert_eq!(
        fs::read(f.state.join("database/original")).unwrap(),
        b"untouched original"
    );
    let after = f.authority.0.lock().unwrap();
    assert_eq!(after.0, before.0);
    assert_eq!(serde_json::to_vec(&after.1).unwrap(), before.1);
    assert!(!f.state.join("agent.log").exists());
    assert!(!f.state.join("restore-activation.json").exists());
}
#[test]
fn review_rejects_active_unbound_changed_and_restore_fenced_journals_without_rewriting() {
    for change in [
        "active",
        "legacy",
        "uuid",
        "configuration",
        "manifest",
        "physical",
        "nil-generation",
        "restore",
        "intent",
        "torn",
    ] {
        let f = Fixture::new();
        assert!(f.review().is_ok());
        match change {
            "intent" => fs::write(f.state.join("restore-activation.json"), b"pending").unwrap(),
            "torn" => fs::write(f.state.join("controller-state.json"), b"{").unwrap(),
            _ => f.change_marker(|m| match change {
                "active" => m["phase"] = json!("active"),
                "legacy" => {
                    m["schemaVersion"] = json!(1);
                    m.as_object_mut().unwrap().remove("secureInstallationId");
                }
                "uuid" => m["secureInstallationId"] = json!("22222222-2222-4222-8222-222222222222"),
                "configuration" => m["installationId"] = json!("bbbbbbbbbbbb"),
                "manifest" => m["manifestSha256"] = json!("f".repeat(64)),
                "physical" => m["profileIdentity"] = json!("f".repeat(64)),
                "nil-generation" => m["generation"] = json!(uuid::Uuid::nil()),
                "restore" => m["restorePending"] = json!(true),
                _ => unreachable!(),
            }),
        }
        let before = fs::read(f.state.join("controller-state.json")).unwrap();
        assert!(f.review().is_err(), "unexpected acceptance: {change}");
        assert_eq!(
            fs::read(f.state.join("controller-state.json")).unwrap(),
            before
        );
        assert_eq!(
            fs::read(f.state.join("database/original")).unwrap(),
            b"untouched original"
        );
    }
}
#[test]
fn review_requires_exact_source_metadata_and_stopped_database_without_creating_missing_state() {
    for fault in [
        "missing", "extra", "revision", "manifest", "postgres", "torn", "pid", "lease",
    ] {
        let f = Fixture::new();
        assert!(f.review().is_ok());
        let path = f.state.join("host-state.json");
        let mut held = None;
        match fault {
            "missing" => fs::remove_file(&path).unwrap(),
            "torn" => fs::write(&path, b"{").unwrap(),
            "pid" => fs::write(
                f.state.join("database/postmaster.pid"),
                b"not PID authority",
            )
            .unwrap(),
            "lease" => {
                let dir = cap_std::fs::Dir::from_std_file(
                    crate::host_storage::directory(&f.state).unwrap(),
                );
                let file = dir
                    .open_with("lease.lock", &crate::host_state::options(true))
                    .unwrap()
                    .into_std();
                file.try_lock().unwrap();
                held = Some(file);
            }
            _ => {
                let mut m: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                match fault {
                    "extra" => m["ignored"] = json!(true),
                    "revision" => m["sourceRevision"] = json!("c".repeat(40)),
                    "manifest" => m["manifestSha256"] = json!("f".repeat(64)),
                    "postgres" => m["postgresMajor"] = json!("20"),
                    _ => unreachable!(),
                };
                fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
            }
        }
        let marker = fs::read(f.state.join("controller-state.json")).unwrap();
        assert!(f.review().is_err(), "unexpected acceptance: {fault}");
        assert_eq!(
            fs::read(f.state.join("controller-state.json")).unwrap(),
            marker
        );
        drop(held);
    }
    let f = Fixture::new();
    let missing = f.state.with_extension("missing");
    assert!(f
        .current
        .review_update(&f.next, &missing, ID, &f.authority.execution())
        .is_err());
    assert!(!missing.exists());
}
#[test]
fn retained_review_inputs_recheck_authority_files_and_target_compatibility() {
    let f = Fixture::new();
    assert!(f
        .current
        .review_update(&f.current, &f.state, ID, &f.authority.execution())
        .is_err());
    let mut same = HostFixture::new();
    same.1["sourceRevision"] = json!("c".repeat(40));
    let same = same.verify().unwrap();
    assert!(f
        .current
        .review_update(&same, &f.state, ID, &f.authority.execution())
        .is_err());
    let _earlier = f.review().unwrap();
    f.authority
        .activate(SECURE_ID, &f.next, &mut || Ok(()))
        .unwrap();
    assert!(matches!(f.review(),Err(e) if e=="host_epoch_rollback"));
    let f = Fixture::new();
    f.authority.0.lock().unwrap().0 = "22222222-2222-4222-8222-222222222222".into();
    assert!(f.review().is_err());
    for target in [true, false] {
        let f = Fixture::new();
        let runtime = if target { &f.target } else { &f.source };
        fs::write(runtime.0.join("node"), b"changed").unwrap();
        assert!(f.review().is_err());
    }
    let mut f = Fixture::new();
    f.next.manifest.postgres_version = "20".into();
    assert!(f.review().is_err());
    let mut f = Fixture::new();
    f.next.manifest.vector_version = "different".into();
    assert!(f.review().is_err());
}
#[test]
fn selected_database_review_preserves_both_roots_and_rejects_replaced_targets() {
    let f = Fixture::new();
    let op = "33333333-3333-4333-8333-333333333333";
    let attempt = "44444444-4444-4444-8444-444444444444";
    let target = f.state.join("restore-targets").join(op).join(attempt);
    for path in [
        f.state.join("restore-targets"),
        f.state.join("restore-targets").join(op),
        target.clone(),
        target.join("database"),
    ] {
        crate::runtime_store::private_directory(&path).unwrap();
    }
    fs::write(target.join("database/selected"), b"selected retained").unwrap();
    let reference = crate::host_database::Reference::capture(&f.state, op, attempt).unwrap();
    f.change_marker(|m| m["databaseReference"] = serde_json::to_value(reference).unwrap());
    let result = serde_json::to_value(f.review().unwrap()).unwrap();
    let dir = cap_std::fs::Dir::from_std_file(
        crate::host_storage::directory(&target.join("database")).unwrap(),
    );
    let id = crate::copy_source::root_identity(&dir).unwrap();
    assert_eq!(
        result["databaseIdentity"],
        format!("{:x}", Sha256::digest(id.as_bytes()))
    );
    drop(dir);
    assert_eq!(
        fs::read(f.state.join("database/original")).unwrap(),
        b"untouched original"
    );
    assert_eq!(
        fs::read(target.join("database/selected")).unwrap(),
        b"selected retained"
    );
    fs::rename(target.join("database"), target.join("retained")).unwrap();
    crate::runtime_store::private_directory(&target.join("database")).unwrap();
    assert!(f.review().is_err());
    assert_eq!(
        fs::read(target.join("retained/selected")).unwrap(),
        b"selected retained"
    );
}

#[test]
fn unchanged_database_versions_do_not_admit_changed_binaries_roles_or_libraries() {
    for change in ["postgres", "vector", "library", "role"] {
        let mut f = Fixture::new();
        assert!(f.review().is_ok());
        if change == "role" {
            f.target.1["entryPoints"]["postgres"] = json!("pg/initdb");
            f.target.1["entryPoints"]["initdb"] = json!("pg/postgres");
        } else {
            let name = match change {
                "postgres" => "pg/postgres",
                "vector" => "pg/vector",
                _ => "pg/lib/dependency",
            };
            fs::create_dir_all(f.target.0.join(name).parent().unwrap()).unwrap();
            fs::write(f.target.0.join(name), b"changed database component").unwrap();
            f.target.1["files"][name] = json!({"bytes":26,"sha256":format!("{:x}",Sha256::digest(b"changed database component"))});
        }
        f.next = f.target.verify().unwrap();
        assert!(
            matches!(f.review(),Err(e) if e=="host_update_database_component_changed"),
            "accepted same-version component change: {change}"
        );
    }
}

#[cfg(unix)]
#[test]
fn host_metadata_links_never_become_update_proof() {
    use std::os::unix::fs::symlink;
    for symbolic in [true, false] {
        let f = Fixture::new();
        assert!(f.review().is_ok());
        let path = f.state.join("host-state.json");
        let original = f.source.2.with_extension("metadata");
        fs::rename(&path, &original).unwrap();
        if symbolic {
            symlink(&original, &path).unwrap();
        } else {
            fs::hard_link(&original, &path).unwrap();
        }
        let before = fs::read(&original).unwrap();
        assert!(f.review().is_err());
        assert_eq!(fs::read(&original).unwrap(), before);
        fs::remove_file(&path).unwrap();
        fs::rename(&original, &path).unwrap();
        assert!(f.review().is_ok());
    }
}

struct ReservationFixture {
    source: Fixture,
    config: crate::manager_host::Configuration,
}
impl ReservationFixture {
    fn new() -> Self {
        Self::with_source(Fixture::new())
    }
    fn with_source(source: Fixture) -> Self {
        let data = source.state.with_extension("manager");
        crate::runtime_store::private_directory(&data).unwrap();
        let root = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&data).unwrap());
        use std::io::Write;
        root.open_with(".host-profile", &crate::host_state::options(true))
            .unwrap()
            .write_all("c".repeat(64).as_bytes())
            .unwrap();
        let config = crate::manager_host::Configuration {
            installation_id: ID.into(),
            secure_installation_id: SECURE_ID.into(),
            name: "Synthetic reservation".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: if cfg!(windows) {
                std::env::current_exe().unwrap()
            } else {
                "/bin/echo".into()
            },
            state: source.state.clone(),
            data,
            origin: "https://127.0.0.1:9443".into(),
            database_port: 54329,
            api_port: 2283,
        };
        Self { source, config }
    }
    fn reserve(&self) -> Result<super::HostUpdateReservation, String> {
        self.source.current.reserve_update(
            &self.source.next,
            &self.config,
            &self.source.authority.execution(),
        )
    }
    fn cancel(&self) -> Result<(), String> {
        self.source.current.cancel_update_reservation(
            &self.source.next,
            &self.config,
            &self.source.authority.execution(),
        )
    }
    fn record(&self) -> Vec<u8> {
        fs::read(self.source.state.join("host-update.json")).unwrap()
    }
}
impl Drop for ReservationFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.config.data);
    }
}
#[test]
fn update_reservation_is_durable_idempotent_fenced_and_cancellable_without_rebinding() {
    let f = ReservationFixture::new();
    let journal = fs::read(f.source.state.join("controller-state.json")).unwrap();
    let metadata = fs::read(f.source.state.join("host-state.json")).unwrap();
    let authority = serde_json::to_vec(&f.source.authority.0.lock().unwrap().1).unwrap();
    let first = serde_json::to_value(f.reserve().unwrap()).unwrap();
    assert_eq!(first["state"], "reserved");
    let bytes = f.record();
    assert_eq!(serde_json::to_value(f.reserve().unwrap()).unwrap(), first);
    assert_eq!(f.record(), bytes);
    assert!(matches!(f.source.review(), Err(e) if e == "host_update_pending"));
    assert!(first.get("canApply").is_none());
    assert_eq!(
        first["review"]["generation"],
        f.source.marker()["generation"]
    );
    assert_eq!(first["review"]["installationId"], ID);
    f.cancel().unwrap();
    assert!(!f.source.state.join("host-update.json").exists());
    f.source.review().unwrap();
    assert_eq!(
        fs::read(f.source.state.join("controller-state.json")).unwrap(),
        journal
    );
    assert_eq!(
        fs::read(f.source.state.join("host-state.json")).unwrap(),
        metadata
    );
    assert_eq!(
        fs::read(f.source.state.join("database/original")).unwrap(),
        b"untouched original"
    );
    assert_eq!(
        serde_json::to_vec(&f.source.authority.0.lock().unwrap().1).unwrap(),
        authority
    );
}
#[test]
fn reservation_retry_and_cancel_refuse_changed_bindings_and_later_epoch() {
    for change in [
        "configuration",
        "generation",
        "profile",
        "database",
        "floor",
    ] {
        let mut f = ReservationFixture::new();
        f.reserve().unwrap();
        let bytes = f.record();
        match change {
            "configuration" => f.config.name = "Changed".into(),
            "generation" => f
                .source
                .change_marker(|m| m["generation"] = json!(uuid::Uuid::new_v4())),
            "profile" => fs::write(f.config.data.join(".host-profile"), "d".repeat(64)).unwrap(),
            "database" => {
                fs::rename(
                    f.source.state.join("database"),
                    f.source.state.join("retained-database"),
                )
                .unwrap();
                crate::runtime_store::private_directory(&f.source.state.join("database")).unwrap();
            }
            "floor" => f
                .source
                .authority
                .activate(SECURE_ID, &f.source.next, &mut || Ok(()))
                .unwrap(),
            _ => unreachable!(),
        }
        assert!(f.reserve().is_err(), "reserve accepted {change}");
        assert!(f.cancel().is_err(), "cancel accepted {change}");
        assert_eq!(f.record(), bytes);
    }
}
#[test]
fn malformed_or_unknown_reservation_never_becomes_cancellation_authority() {
    for mutation in ["torn", "oversized", "phase", "extra", "operation"] {
        let f = ReservationFixture::new();
        f.reserve().unwrap();
        let mut value: Value = serde_json::from_slice(&f.record()).unwrap();
        let bytes = match mutation {
            "torn" => b"{".to_vec(),
            "oversized" => vec![b'x'; 4097],
            "phase" => {
                value["state"] = json!("applying");
                serde_json::to_vec(&value).unwrap()
            }
            "extra" => {
                value["allowApply"] = json!(true);
                serde_json::to_vec(&value).unwrap()
            }
            "operation" => {
                value["operationId"] = json!(uuid::Uuid::nil());
                serde_json::to_vec(&value).unwrap()
            }
            _ => unreachable!(),
        };
        fs::write(f.source.state.join("host-update.json"), &bytes).unwrap();
        assert!(f.reserve().is_err());
        assert!(f.cancel().is_err());
        assert_eq!(f.record(), bytes);
    }
}
#[test]
fn reservation_never_creates_a_missing_journal_or_manager_profile() {
    for missing in ["journal", "manager"] {
        let f = ReservationFixture::new();
        let path = if missing == "journal" {
            f.source.state.join("controller-state.json")
        } else {
            f.config.data.clone()
        };
        if missing == "journal" {
            fs::remove_file(&path).unwrap();
        } else {
            fs::remove_dir_all(&path).unwrap();
        }
        assert!(f.reserve().is_err());
        assert!(!path.exists(), "reservation recreated {missing}");
        assert!(!f.source.state.join("host-update.json").exists());
    }
}
#[test]
fn reservation_refuses_live_manager_and_controller_ownership() {
    let f = ReservationFixture::new();
    let profile = crate::manager_profile::ProfileGuard::acquire(&f.config).unwrap();
    assert!(f.reserve().is_err());
    drop(profile);
    let controller = crate::host_state::Owner::acquire(&f.source.state, true, SECURE_ID).unwrap();
    assert!(f.reserve().is_err());
    drop(controller);
    assert!(!f.source.state.join("host-update.json").exists());
    f.reserve().unwrap();
    f.cancel().unwrap();
}

#[cfg(unix)]
#[test]
fn linked_nonprivate_or_directory_update_records_are_never_retried_or_cancelled() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for shape in ["symlink", "hardlink", "directory", "public"] {
        let f = ReservationFixture::new();
        f.reserve().unwrap();
        let path = f.source.state.join("host-update.json");
        let saved = f.config.data.join("saved-record");
        fs::rename(&path, &saved).unwrap();
        match shape {
            "symlink" => symlink(&saved, &path).unwrap(),
            "hardlink" => fs::hard_link(&saved, &path).unwrap(),
            "directory" => fs::create_dir(&path).unwrap(),
            "public" => {
                fs::copy(&saved, &path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            _ => unreachable!(),
        }
        let original = fs::read(&saved).unwrap();
        assert!(f.reserve().is_err());
        assert!(f.cancel().is_err());
        assert!(fs::symlink_metadata(&path).is_ok());
        assert_eq!(fs::read(saved).unwrap(), original);
    }
}
#[test]
fn pending_update_blocks_direct_start_even_when_the_controller_journal_is_missing() {
    let f = ReservationFixture::new();
    f.reserve().unwrap();
    fs::remove_file(f.source.state.join("controller-state.json")).unwrap();
    assert!(
        matches!(crate::host_runtime::direct_profile(&f.source.state), Err(e) if e == "host_update_pending")
    );
    assert!(f.cancel().is_err());
    assert!(f.source.state.join("host-update.json").exists());
}

#[test]
fn cancellation_keeps_the_fence_if_target_changes_during_authority_revalidation() {
    struct Tamper<'a>(&'a Authority, PathBuf);
    impl HostEpochAuthority for Tamper<'_> {
        fn installation_id(&self) -> Result<String, String> {
            self.0.installation_id()
        }
        fn with_admitted(
            &self,
            id: &str,
            runtime: &VerifiedHostRuntime,
            operation: &mut dyn FnMut() -> Result<(), String>,
        ) -> Result<(), String> {
            self.0.with_admitted(id, runtime, &mut || {
                fs::write(&self.1, b"changed target during admission").unwrap();
                operation()
            })
        }
        fn activate(
            &self,
            id: &str,
            runtime: &VerifiedHostRuntime,
            publish: &mut dyn FnMut() -> Result<(), String>,
        ) -> Result<(), String> {
            self.0.activate(id, runtime, publish)
        }
    }
    let f = ReservationFixture::new();
    f.reserve().unwrap();
    let bytes = f.record();
    let authority = Tamper(&f.source.authority, f.source.target.0.join("node"));
    let execution = HostExecution::new(&authority, SECURE_ID).unwrap();
    assert!(f
        .source
        .current
        .cancel_update_reservation(&f.source.next, &f.config, &execution)
        .is_err());
    assert!(
        f.source.state.join("host-update.json").exists(),
        "target drift cleared the update fence"
    );
    assert_eq!(f.record(), bytes);
}

struct PreparationStore {
    inner: crate::manager_profile::update::tests::Store,
    state: PathBuf,
    fail_at: Option<usize>,
    ambiguous: bool,
    discard: bool,
    writes: usize,
}
impl crate::manager_profile::UpdateStore for PreparationStore {
    fn load<T: serde::de::DeserializeOwned>(&mut self, account: &str) -> Result<Option<T>, String> {
        crate::manager_profile::UpdateStore::load(&mut self.inner, account)
    }
    fn save<T: serde::Serialize>(&mut self, account: &str, value: &T) -> Result<(), String> {
        let intent: Value =
            serde_json::from_slice(&fs::read(self.state.join("host-update.json")).unwrap())
                .unwrap();
        assert_eq!(
            intent["state"], "preparingCredentials",
            "secret write preceded durable fence"
        );
        self.writes += 1;
        if self.fail_at == Some(self.writes) {
            if self.discard {
                return Ok(());
            }
            if self.ambiguous {
                crate::manager_profile::UpdateStore::save(&mut self.inner, account, value)?;
            }
            return Err("synthetic_store_write_failed".into());
        }
        crate::manager_profile::UpdateStore::save(&mut self.inner, account, value)
    }
}
#[test]
fn credential_preparation_is_fenced_before_writes_and_retries_without_replacing_identity() {
    for (failure, ambiguous, discard) in [
        (None, false, false),
        (Some(1), false, false),
        (Some(2), false, false),
        (Some(1), true, false),
        (Some(2), true, false),
        (Some(1), false, true),
        (Some(2), false, true),
    ] {
        let f = ReservationFixture::new();
        let mut memory = crate::manager_profile::update::tests::Store::default();
        crate::manager_profile::update::tests::seed(
            &f.config,
            &f.source.source.2,
            f.source.current.manifest_sha256(),
            &mut memory,
        );
        let source_records: std::collections::BTreeMap<_, _> = memory
            .0
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        let mut store = PreparationStore {
            inner: memory,
            state: f.config.state.clone(),
            fail_at: failure,
            ambiguous,
            discard,
            writes: 0,
        };
        let destination = crate::manager_host::Configuration {
            installation_id: f.config.installation_id.clone(),
            secure_installation_id: f.config.secure_installation_id.clone(),
            name: f.config.name.clone(),
            release: "frameleaf-v3.0.0-2".into(),
            controller: f.config.controller.clone(),
            state: f.config.state.clone(),
            data: f.config.data.clone(),
            origin: f.config.origin.clone(),
            database_port: f.config.database_port,
            api_port: f.config.api_port,
        };
        let marker = fs::read(f.config.data.join(".host-profile")).unwrap();
        let journal = fs::read(f.config.state.join("controller-state.json")).unwrap();
        let floor = serde_json::to_vec(&f.source.authority.0.lock().unwrap().1).unwrap();
        f.reserve().unwrap();
        let prepare = |store: &mut PreparationStore| {
            f.source.current.update_reservation(
                &f.source.next,
                &f.config,
                &f.source.authority.execution(),
                false,
                Some(&destination),
                store,
            )
        };
        let result = prepare(&mut store);
        if failure.is_some() {
            assert!(result.is_err());
            assert_eq!(
                serde_json::from_slice::<Value>(&f.record()).unwrap()["state"],
                "preparingCredentials"
            );
            assert!(f.cancel().is_err());
            store.fail_at = None;
            let writes = store.writes;
            let pending = f.record();
            for (account, original) in &source_records {
                let mut changed: Value = serde_json::from_str(original).unwrap();
                if account.starts_with("native-manager-tls-") {
                    let tls = crate::manager_tls::TlsIdentity::load_or_create(
                        &f.config.installation_id,
                        &f.config.origin,
                        || Ok(None),
                        |_| Ok(()),
                    )
                    .unwrap();
                    changed = serde_json::to_value(&tls).unwrap();
                } else {
                    changed["databasePassword"] = "another synthetic existing password".into();
                }
                store.inner.0.insert(
                    account.clone(),
                    zeroize::Zeroizing::new(serde_json::to_string(&changed).unwrap()),
                );
                assert!(
                    prepare(&mut store).is_err(),
                    "source identity drift was accepted"
                );
                assert_eq!(store.writes, writes);
                assert_eq!(f.record(), pending);
                store
                    .inner
                    .0
                    .insert(account.clone(), zeroize::Zeroizing::new(original.clone()));
            }
            // A foreign target is refused rather than silently overwritten during retry.
            let target_account = store
                .inner
                .0
                .keys()
                .find(|k| !source_records.contains_key(*k) && k.starts_with("native-host-profile-"))
                .cloned();
            if let Some(account) = target_account {
                let original = store.inner.0[&account].to_string();
                let mut changed: Value = serde_json::from_str(&original).unwrap();
                changed["databasePassword"] = "foreign synthetic target password".into();
                let foreign = serde_json::to_string(&changed).unwrap();
                store
                    .inner
                    .0
                    .insert(account.clone(), zeroize::Zeroizing::new(foreign.clone()));
                assert!(prepare(&mut store).is_err());
                assert_eq!(store.writes, writes);
                assert_eq!(store.inner.0[&account].as_str(), foreign);
                store
                    .inner
                    .0
                    .insert(account, zeroize::Zeroizing::new(original));
            }
        } else {
            result.unwrap();
        }
        prepare(&mut store).unwrap();
        let prepared = f.record();
        let receipt: Value = serde_json::from_slice(&prepared).unwrap();
        assert_eq!(receipt["state"], "credentialsPrepared");
        assert_eq!(receipt["tlsCertificateSha256"].as_str().unwrap().len(), 64);
        let writes = store.writes;
        prepare(&mut store).unwrap();
        assert_eq!(writes, store.writes);
        assert_eq!(prepared, f.record());
        assert!(f.cancel().is_err());
        assert!(f.reserve().is_err());
        assert_eq!(
            fs::read(f.config.data.join(".host-profile")).unwrap(),
            marker
        );
        assert_eq!(
            fs::read(f.config.state.join("controller-state.json")).unwrap(),
            journal
        );
        assert_eq!(
            serde_json::to_vec(&f.source.authority.0.lock().unwrap().1).unwrap(),
            floor
        );
        assert_eq!(
            fs::read(f.config.state.join("database/original")).unwrap(),
            b"untouched original"
        );
        for (k, v) in source_records {
            assert_eq!(store.inner.0[&k].as_str(), v);
            assert!(!String::from_utf8_lossy(&prepared).contains(&v));
        }
    }
}

#[test]
fn signed_backup_approval_requires_fresh_exact_source_owner_and_never_mutates_profile_or_data() {
    use base64::Engine;
    use hmac::Mac;
    for fault in [
        "valid",
        "target",
        "uuid",
        "library",
        "revision",
        "journal",
        "floor",
        "missing-profile",
        "postmaster",
    ] {
        let f = ReservationFixture::new();
        let mut memory = crate::manager_profile::update::tests::Store::default();
        crate::manager_profile::update::tests::seed(
            &f.config,
            &f.source.source.2,
            f.source.current.manifest_sha256(),
            &mut memory,
        );
        let source_accounts: std::collections::BTreeMap<_, _> = memory
            .0
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        let before = fs::read(f.config.state.join("controller-state.json")).unwrap();
        let marker: Value = serde_json::from_slice(&before).unwrap();
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/native-update-approval.json"
        ))
        .unwrap();
        let now = fixture["now"].as_u64().unwrap();
        let mut payload = fixture["payload"].clone();
        payload["secureInstallationId"] = SECURE_ID.into();
        payload["generation"] = marker["generation"].clone();
        payload["sourceManifestSha256"] = f.source.current.manifest_sha256().into();
        payload["sourceRevision"] = f.source.current.source_revision().into();
        payload["targetManifestSha256"] = f.source.next.manifest_sha256().into();
        payload["checkpoint"]["manifestSha256"] = payload["sourceManifestSha256"].clone();
        payload["checkpoint"]["sourceRevision"] = payload["sourceRevision"].clone();
        payload["controllerStateSha256"] = format!("{:x}", Sha256::digest(&before)).into();
        match fault {
            "target" => payload["targetManifestSha256"] = "9".repeat(64).into(),
            "uuid" => {
                payload["secureInstallationId"] = "99999999-9999-4999-8999-999999999999".into()
            }
            "library" => payload["libraryId"] = "9".repeat(12).into(),
            "revision" => {
                payload["sourceRevision"] = "9".repeat(40).into();
                payload["checkpoint"]["sourceRevision"] = payload["sourceRevision"].clone();
            }
            "journal" => {
                let mut changed = before.clone();
                changed.push(b'\n');
                fs::write(f.config.state.join("controller-state.json"), changed).unwrap();
            }
            "floor" => f
                .source
                .authority
                .activate(SECURE_ID, &f.source.next, &mut || Ok(()))
                .unwrap(),
            "missing-profile" => fs::remove_dir_all(&f.config.data).unwrap(),
            "postmaster" => fs::write(
                f.config.state.join("database/postmaster.pid"),
                b"not PID authority",
            )
            .unwrap(),
            _ => {}
        }
        let raw = payload.to_string();
        let mut mac =
            hmac::Hmac::<Sha256>::new_from_slice(b"kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")
                .unwrap();
        mac.update(b"frameleaf-native-update-approval-v1\0");
        mac.update(raw.as_bytes());
        let sealed = format!(
            "{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let journal = fs::read(f.config.state.join("controller-state.json")).unwrap();
        let result = f.source.current.verify_update_approval_with(
            &f.source.next,
            &f.config,
            &f.source.authority.execution(),
            &sealed,
            now,
            &mut memory,
        );
        if fault == "valid" {
            let proof = serde_json::to_value(result.unwrap()).unwrap();
            assert_eq!(proof["state"], "verified");
            assert!(proof.get("canApply").is_none());
            assert!(!proof.to_string().contains(&"k".repeat(43)));
        } else {
            assert!(result.is_err(), "accepted {fault}");
        }
        assert_eq!(
            fs::read(f.config.state.join("controller-state.json")).unwrap(),
            journal
        );
        if fault == "missing-profile" {
            assert!(!f.config.data.exists());
        }
        assert_eq!(
            fs::read(f.config.state.join("database/original")).unwrap(),
            b"untouched original"
        );
        for (k, v) in source_accounts {
            assert_eq!(memory.0[&k].as_str(), v);
        }
    }
}

struct ConsumptionFixture {
    f: ReservationFixture,
    destination: crate::manager_host::Configuration,
    store: crate::manager_profile::update::tests::Store,
    token: String,
    now: u64,
}
impl ConsumptionFixture {
    fn new() -> Self {
        Self::with_reservation(ReservationFixture::new())
    }
    fn with_reservation(f: ReservationFixture) -> Self {
        use base64::Engine;
        use hmac::Mac;
        let mut store = crate::manager_profile::update::tests::Store::default();
        crate::manager_profile::update::tests::seed(
            &f.config,
            &f.source.source.2,
            f.source.current.manifest_sha256(),
            &mut store,
        );
        let destination = crate::manager_host::Configuration {
            installation_id: f.config.installation_id.clone(),
            secure_installation_id: f.config.secure_installation_id.clone(),
            name: f.config.name.clone(),
            release: "frameleaf-v3.0.0-2".into(),
            controller: f.config.controller.clone(),
            state: f.config.state.clone(),
            data: f.config.data.clone(),
            origin: f.config.origin.clone(),
            database_port: f.config.database_port,
            api_port: f.config.api_port,
        };
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/native-update-approval.json"
        ))
        .unwrap();
        let now = fixture["now"].as_u64().unwrap();
        let mut payload = fixture["payload"].clone();
        let journal = fs::read(f.config.state.join("controller-state.json")).unwrap();
        let marker: Value = serde_json::from_slice(&journal).unwrap();
        payload["secureInstallationId"] = SECURE_ID.into();
        payload["generation"] = marker["generation"].clone();
        payload["sourceManifestSha256"] = f.source.current.manifest_sha256().into();
        payload["sourceRevision"] = f.source.current.source_revision().into();
        payload["targetManifestSha256"] = f.source.next.manifest_sha256().into();
        payload["checkpoint"]["manifestSha256"] = payload["sourceManifestSha256"].clone();
        payload["checkpoint"]["sourceRevision"] = payload["sourceRevision"].clone();
        payload["controllerStateSha256"] = format!("{:x}", Sha256::digest(&journal)).into();
        let raw = payload.to_string();
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice("k".repeat(43).as_bytes()).unwrap();
        mac.update(b"frameleaf-native-update-approval-v1\0");
        mac.update(raw.as_bytes());
        let token = format!(
            "{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        f.reserve().unwrap();
        f.source
            .current
            .update_reservation(
                &f.source.next,
                &f.config,
                &f.source.authority.execution(),
                false,
                Some(&destination),
                &mut store,
            )
            .unwrap();
        Self {
            f,
            destination,
            store,
            token,
            now,
        }
    }
    fn consume(
        &mut self,
        token: Option<&str>,
        now: u64,
    ) -> Result<crate::host_runtime::HostUpdateApproval, String> {
        self.f.source.current.consume_update_approval_with(
            &self.f.source.next,
            [&self.f.config, &self.destination],
            &self.f.source.authority.execution(),
            token,
            || Ok(now),
            &mut self.store,
        )
    }
    fn accounts(&self) -> std::collections::BTreeMap<String, String> {
        self.store
            .0
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect()
    }
}
#[test]
fn durable_update_approval_consumption_preserves_first_time_and_authenticates_expired_retry() {
    let mut f = ConsumptionFixture::new();
    let token = f.token.clone();
    let now = f.now;
    let prepared = f.f.record();
    let accounts = f.accounts();
    let journal = fs::read(f.f.config.state.join("controller-state.json")).unwrap();
    let floor = serde_json::to_vec(&f.f.source.authority.0.lock().unwrap().1).unwrap();
    assert!(f.consume(None, now).is_err());
    assert_eq!(f.f.record(), prepared);
    let result = serde_json::to_value(f.consume(Some(&token), now).unwrap()).unwrap();
    assert_eq!(result["state"], "consumed");
    let consumed = f.f.record();
    assert!(consumed.len() <= 4096);
    assert!(!String::from_utf8_lossy(&consumed).contains(&"k".repeat(43)));
    assert_ne!(prepared, consumed);
    for later in [now, now + 600_000] {
        assert!(f.consume(Some(&token), later).is_ok());
        assert!(f.consume(None, later).is_ok());
        assert_eq!(f.f.record(), consumed);
    }
    assert!(f
        .consume(Some(&format!("{token}0")), now + 600_000)
        .is_err());
    assert!(f.f.cancel().is_err());
    assert!(f.f.reserve().is_err());
    assert_eq!(f.accounts(), accounts);
    assert_eq!(
        fs::read(f.f.config.state.join("controller-state.json")).unwrap(),
        journal
    );
    assert_eq!(
        serde_json::to_vec(&f.f.source.authority.0.lock().unwrap().1).unwrap(),
        floor
    );
    assert_eq!(
        fs::read(f.f.config.state.join("database/original")).unwrap(),
        b"untouched original"
    );
}
#[test]
fn durable_update_approval_consumption_refuses_expired_initial_approval_and_late_clock() {
    let mut f = ConsumptionFixture::new();
    let token = f.token.clone();
    let now = f.now;
    let before = f.f.record();
    assert!(f.consume(Some(&token), now + 600_000).is_err());
    assert_eq!(f.f.record(), before);
    let calls = std::cell::Cell::new(0);
    let result = f.f.source.current.consume_update_approval_with(
        &f.f.source.next,
        [&f.f.config, &f.destination],
        &f.f.source.authority.execution(),
        Some(&token),
        || {
            let n = calls.get();
            calls.set(n + 1);
            Ok(if n == 0 { now } else { now + 600_000 })
        },
        &mut f.store,
    );
    assert!(result.is_err());
    assert_eq!(f.f.record(), before);
}
#[test]
fn durable_update_approval_consumption_refuses_tampering_missing_credentials_and_advanced_floor() {
    for fault in [
        "receipt",
        "time",
        "prepared",
        "journal",
        "missing-target",
        "target-password",
        "source-password",
        "floor",
        "unknown-receipt",
        "unknown-record",
        "duplicate",
        "valid-mac-time",
        "valid-mac-operation",
        "valid-mac-database",
        "valid-mac-source",
        "source-key",
        "missing-tls",
    ] {
        let mut f = ConsumptionFixture::new();
        let token = f.token.clone();
        let now = f.now;
        f.consume(Some(&token), now).unwrap();
        match fault {
            "unknown-receipt"
            | "unknown-record"
            | "duplicate"
            | "valid-mac-time"
            | "valid-mac-operation"
            | "valid-mac-database"
            | "valid-mac-source" => {
                use hmac::Mac;
                let mut record: Value = serde_json::from_slice(&f.f.record()).unwrap();
                match fault {
                    "unknown-receipt" => {
                        record["approvalReceipt"]["receipt"]["unknown"] = true.into()
                    }
                    "unknown-record" => record["unknown"] = true.into(),
                    "valid-mac-time" => {
                        record["approvalReceipt"]["receipt"]["consumedAt"] = (now + 600_000).into()
                    }
                    "valid-mac-operation" => {
                        record["approvalReceipt"]["receipt"]["operationId"] =
                            "99999999-9999-4999-8999-999999999999".into()
                    }
                    "valid-mac-database" => {
                        record["approvalReceipt"]["receipt"]["databaseIdentity"] =
                            "0".repeat(64).into()
                    }
                    "valid-mac-source" => {
                        record["approvalReceipt"]["receipt"]["approval"]["sourceRevision"] =
                            "9".repeat(40).into();
                        record["approvalReceipt"]["receipt"]["approval"]["checkpoint"]
                            ["sourceRevision"] = "9".repeat(40).into();
                    }
                    _ => {}
                }
                if fault.starts_with("valid-mac-") {
                    let mut mac =
                        hmac::Hmac::<Sha256>::new_from_slice("k".repeat(43).as_bytes()).unwrap();
                    mac.update(b"frameleaf-native-update-consumption-v1\0");
                    mac.update(
                        &serde_json_canonicalizer::to_vec(&record["approvalReceipt"]["receipt"])
                            .unwrap(),
                    );
                    record["approvalReceipt"]["mac"] = mac
                        .finalize()
                        .into_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                        .into();
                }
                let mut bytes = record.to_string();
                if fault == "duplicate" {
                    bytes = bytes.replace(
                        "\"protocolVersion\":1",
                        "\"protocolVersion\":1,\"protocolVersion\":1",
                    );
                }
                fs::write(f.f.config.state.join("host-update.json"), bytes).unwrap();
            }
            "missing-tls" => {
                let binding =
                    String::from_utf8(fs::read(f.f.config.data.join(".host-profile")).unwrap())
                        .unwrap();
                let name = f
                    .store
                    .0
                    .keys()
                    .find(|k| k.starts_with("native-manager-tls-") && !k.ends_with(&binding))
                    .unwrap()
                    .clone();
                f.store.0.remove(&name);
            }
            "receipt" | "time" | "prepared" => {
                let mut record: Value = serde_json::from_slice(&f.f.record()).unwrap();
                match fault {
                    "receipt" => record["approvalReceipt"]["mac"] = "0".repeat(64).into(),
                    "time" => record["approvalReceipt"]["receipt"]["consumedAt"] = (now + 1).into(),
                    _ => record["credentialsSha256"] = "0".repeat(64).into(),
                }
                fs::write(
                    f.f.config.state.join("host-update.json"),
                    serde_json::to_vec(&record).unwrap(),
                )
                .unwrap();
            }
            "journal" => {
                let path = f.f.config.state.join("controller-state.json");
                let mut value = fs::read(&path).unwrap();
                value.push(b'\n');
                fs::write(path, value).unwrap();
            }
            "missing-target" | "target-password" | "source-password" | "source-key" => {
                let original =
                    String::from_utf8(fs::read(f.f.config.data.join(".host-profile")).unwrap())
                        .unwrap();
                let name = f
                    .store
                    .0
                    .keys()
                    .find(|k| {
                        k.starts_with("native-host-profile-")
                            && (k.ends_with(&original)
                                == matches!(fault, "source-password" | "source-key"))
                    })
                    .unwrap()
                    .clone();
                if fault == "missing-target" {
                    f.store.0.remove(&name);
                } else {
                    let mut value: Value = serde_json::from_str(&f.store.0[&name]).unwrap();
                    if fault == "source-key" {
                        value["backupKey"] = "j".repeat(43).into();
                    } else {
                        value["databasePassword"] = "changed synthetic database password".into();
                    }
                    f.store
                        .0
                        .insert(name, zeroize::Zeroizing::new(value.to_string()));
                }
            }
            "floor" => {
                f.f.source
                    .authority
                    .activate(SECURE_ID, &f.f.source.next, &mut || Ok(()))
                    .unwrap()
            }
            _ => unreachable!(),
        }
        let before = f.f.record();
        let accounts = f.accounts();
        assert!(f.consume(None, now + 600_000).is_err(), "accepted {fault}");
        assert_eq!(f.f.record(), before);
        assert_eq!(f.accounts(), accounts);
    }
}

#[test]
fn durable_update_approval_consumption_never_repairs_credentials_before_first_consumption() {
    for tls in [false, true] {
        let mut f = ConsumptionFixture::new();
        let token = f.token.clone();
        let now = f.now;
        let binding =
            String::from_utf8(fs::read(f.f.config.data.join(".host-profile")).unwrap()).unwrap();
        let prefix = if tls {
            "native-manager-tls-"
        } else {
            "native-host-profile-"
        };
        let name = f
            .store
            .0
            .keys()
            .find(|k| k.starts_with(prefix) && !k.ends_with(&binding))
            .unwrap()
            .clone();
        f.store.0.remove(&name);
        let before = f.f.record();
        let accounts = f.accounts();
        assert!(f.consume(Some(&token), now).is_err());
        assert_eq!(f.f.record(), before);
        assert_eq!(f.accounts(), accounts);
    }
}

#[test]
fn consumed_approval_readback_callback_requires_consumption_and_rechecks_unchanged_context() {
    // Windows Owner forbids external writes to its exclusively locked journal.
    for changed in [false].into_iter().chain(cfg!(unix).then_some(true)) {
        let mut f = ConsumptionFixture::new();
        let now = f.now;
        let calls = std::cell::Cell::new(0);
        let inspect = |_: &super::super::update_approval::Payload, _: &str| {
            calls.set(calls.get() + 1);
            Ok(())
        };
        assert!(f
            .f
            .source
            .current
            .with_update_approval(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                None,
                || Ok(now),
                &mut f.store,
                inspect
            )
            .is_err());
        assert_eq!(calls.get(), 0);
        let token = f.token.clone();
        f.consume(Some(&token), now).unwrap();
        let record = f.f.record();
        let accounts = f.accounts();
        let result = f.f.source.current.with_update_approval(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            None,
            || Ok(now + 600_000),
            &mut f.store,
            |_, key| {
                assert_eq!(key.len(), 43);
                calls.set(calls.get() + 1);
                if changed {
                    let path = f.f.config.state.join("controller-state.json");
                    let mut bytes = fs::read(&path).unwrap();
                    bytes.push(b'\n');
                    fs::write(path, bytes).unwrap();
                }
                Ok(())
            },
        );
        assert_eq!(result.is_err(), changed);
        assert_eq!(calls.get(), 1);
        assert_eq!(f.f.record(), record);
        assert_eq!(f.accounts(), accounts);
    }
}

#[test]
fn prepared_update_abort_releases_only_fence_after_expired_approval_without_touching_source() {
    let mut f = ConsumptionFixture::new();
    let token = f.token.clone();
    assert!(f.consume(Some(&token), f.now + 600_000).is_err());
    assert!(f.f.cancel().is_err());
    let accounts = f.accounts();
    let journal = fs::read(f.f.config.state.join("controller-state.json")).unwrap();
    let host = fs::read(f.f.config.state.join("host-state.json")).unwrap();
    let binding = fs::read(f.f.config.data.join(".host-profile")).unwrap();
    let floor = serde_json::to_vec(&f.f.source.authority.0.lock().unwrap().1).unwrap();
    f.f.source
        .current
        .abort_prepared_update_with(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &mut f.store,
        )
        .unwrap();
    assert!(!f.f.config.state.join("host-update.json").exists());
    assert!(
        f.f.source.review().is_ok(),
        "source remains fenced after safe abort"
    );
    assert_eq!(f.accounts(), accounts);
    assert_eq!(
        fs::read(f.f.config.state.join("controller-state.json")).unwrap(),
        journal
    );
    assert_eq!(
        fs::read(f.f.config.state.join("host-state.json")).unwrap(),
        host
    );
    assert_eq!(
        fs::read(f.f.config.data.join(".host-profile")).unwrap(),
        binding
    );
    assert_eq!(
        serde_json::to_vec(&f.f.source.authority.0.lock().unwrap().1).unwrap(),
        floor
    );
    assert_eq!(
        fs::read(f.f.config.state.join("database/original")).unwrap(),
        b"untouched original"
    );
    assert!(
        f.f.source
            .current
            .abort_prepared_update_with(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &mut f.store,
            )
            .is_err(),
        "absent record cannot claim an abort occurred"
    );
}

#[test]
fn prepared_update_abort_refuses_advanced_replayed_changed_or_missing_bindings_without_repairs() {
    for fault in [
        "consumed",
        "preparing",
        "unknown",
        "duplicate",
        "source-config",
        "target-config",
        "missing-profile",
        "missing-tls",
        "target-password",
        "journal-generation",
        "target-code",
        "floor-replay",
    ] {
        let mut f = ConsumptionFixture::new();
        match fault {
            "consumed" => {
                let token = f.token.clone();
                f.consume(Some(&token), f.now).unwrap();
            }
            "preparing" | "unknown" | "duplicate" => {
                let mut record: Value = serde_json::from_slice(&f.f.record()).unwrap();
                if fault == "preparing" {
                    record["state"] = "preparingCredentials".into();
                }
                if fault == "unknown" {
                    record["unknown"] = true.into();
                }
                let mut raw = record.to_string();
                if fault == "duplicate" {
                    raw = raw.replace(
                        "\"protocolVersion\":1",
                        "\"protocolVersion\":1,\"protocolVersion\":1",
                    );
                }
                fs::write(f.f.config.state.join("host-update.json"), raw).unwrap();
            }
            "source-config" => f.f.config.release = "frameleaf-v3.0.0-9".into(),
            "target-config" => f.destination.release = "frameleaf-v3.0.0-9".into(),
            "missing-profile" | "missing-tls" | "target-password" => {
                let source_binding =
                    String::from_utf8(fs::read(f.f.config.data.join(".host-profile")).unwrap())
                        .unwrap();
                let prefix = if fault == "missing-tls" {
                    "native-manager-tls-"
                } else {
                    "native-host-profile-"
                };
                let account = f
                    .store
                    .0
                    .keys()
                    .find(|k| k.starts_with(prefix) && !k.ends_with(&source_binding))
                    .unwrap()
                    .clone();
                if fault == "target-password" {
                    let mut profile: Value = serde_json::from_str(&f.store.0[&account]).unwrap();
                    profile["databasePassword"] = "foreign synthetic password for abort".into();
                    f.store
                        .0
                        .insert(account, zeroize::Zeroizing::new(profile.to_string()));
                } else {
                    f.store.0.remove(&account);
                }
            }
            "journal-generation" => {
                f.f.source
                    .change_marker(|m| m["generation"] = uuid::Uuid::new_v4().to_string().into())
            }
            "target-code" => {
                fs::write(f.f.source.target.0.join("node"), b"changed target").unwrap()
            }
            "floor-replay" => {
                let prepared = f.f.record();
                let token = f.token.clone();
                f.consume(Some(&token), f.now).unwrap();
                f.f.source
                    .authority
                    .activate(SECURE_ID, &f.f.source.next, &mut || Ok(()))
                    .unwrap();
                fs::write(f.f.config.state.join("host-update.json"), prepared).unwrap();
            }
            _ => unreachable!(),
        }
        let record = f.f.record();
        let accounts = f.accounts();
        assert!(
            f.f.source
                .current
                .abort_prepared_update_with(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &mut f.store,
                )
                .is_err(),
            "accepted {fault}"
        );
        assert_eq!(f.f.record(), record, "lost fence for {fault}");
        assert_eq!(f.accounts(), accounts, "repaired credentials for {fault}");
        assert_eq!(
            fs::read(f.f.config.state.join("database/original")).unwrap(),
            b"untouched original"
        );
    }
}

#[test]
fn prepared_update_abort_rechecks_code_and_journal_after_credential_reads() {
    struct Drift<'a> {
        inner: &'a mut crate::manager_profile::update::tests::Store,
        path: PathBuf,
        bytes: Option<Vec<u8>>,
    }
    impl crate::manager_profile::UpdateStore for Drift<'_> {
        fn load<T: serde::de::DeserializeOwned>(
            &mut self,
            account: &str,
        ) -> Result<Option<T>, String> {
            if let Some(bytes) = self.bytes.take() {
                fs::write(&self.path, bytes).unwrap();
            }
            crate::manager_profile::UpdateStore::load(self.inner, account)
        }
        fn save<T: serde::Serialize>(&mut self, _: &str, _: &T) -> Result<(), String> {
            Err("abort must never write credentials".into())
        }
    }
    // Windows Owner holds an exclusive byte-range lock on the journal.
    for journal in [false].into_iter().chain(cfg!(unix).then_some(true)) {
        let mut f = ConsumptionFixture::new();
        let record = f.f.record();
        let accounts = f.accounts();
        let (path, bytes) = if journal {
            let path = f.f.config.state.join("controller-state.json");
            let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            value["generation"] = uuid::Uuid::new_v4().to_string().into();
            (path, serde_json::to_vec(&value).unwrap())
        } else {
            (
                f.f.source.target.0.join("node"),
                b"changed during credential read".to_vec(),
            )
        };
        let mut store = Drift {
            inner: &mut f.store,
            path,
            bytes: Some(bytes),
        };
        assert!(f
            .f
            .source
            .current
            .abort_prepared_update_with(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &mut store,
            )
            .is_err());
        assert!(
            store.bytes.is_none(),
            "test failed to reach guarded credential read"
        );
        assert_eq!(f.f.record(), record);
        assert_eq!(f.accounts(), accounts);
    }
}

#[test]
fn recovery_intent_is_authenticated_idempotent_and_reviewed_only_by_current_target_after_handover()
{
    let mut f = ConsumptionFixture::new();
    let path = f.f.config.state.join("host-update-recovery.json");
    assert!(f
        .f
        .source
        .current
        .prepare_update_recovery_with(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &mut f.store
        )
        .is_err());
    assert!(!path.exists());
    let token = f.token.clone();
    f.consume(Some(&token), f.now).unwrap();
    let accounts = f.accounts();
    let consumed = f.f.record();
    let journal = fs::read(f.f.config.state.join("controller-state.json")).unwrap();
    let floor = serde_json::to_vec(&f.f.source.authority.0.lock().unwrap().1).unwrap();
    for _ in 0..2 {
        let proof =
            f.f.source
                .current
                .prepare_update_recovery_with(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &mut f.store,
                )
                .unwrap();
        assert_eq!(
            serde_json::to_value(proof).unwrap()["state"],
            "recovery-intent-prepared"
        );
    }
    let intent = fs::read(&path).unwrap();
    assert!(intent.len() <= 4096);
    assert!(!String::from_utf8_lossy(&intent).contains(&"k".repeat(43)));
    assert_eq!(f.accounts(), accounts);
    assert_eq!(f.f.record(), consumed);
    assert_eq!(
        serde_json::to_vec(&f.f.source.authority.0.lock().unwrap().1).unwrap(),
        floor
    );
    assert!(f
        .f
        .source
        .current
        .review_update_recovery_with(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &mut f.store
        )
        .is_err());
    f.f.source
        .authority
        .activate(SECURE_ID, &f.f.source.next, &mut || Ok(()))
        .unwrap();
    let floor = serde_json::to_vec(&f.f.source.authority.0.lock().unwrap().1).unwrap();
    assert!(f
        .f
        .source
        .current
        .prepare_update_recovery_with(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &mut f.store
        )
        .is_err());
    let proof =
        f.f.source
            .current
            .review_update_recovery_with(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &mut f.store,
            )
            .unwrap();
    assert_eq!(
        serde_json::to_value(proof).unwrap()["state"],
        "target-recovery-reviewed"
    );
    assert_eq!(fs::read(path).unwrap(), intent);
    assert_eq!(f.accounts(), accounts);
    assert_eq!(f.f.record(), consumed);
    assert_eq!(
        serde_json::to_vec(&f.f.source.authority.0.lock().unwrap().1).unwrap(),
        floor
    );
    assert_eq!(
        fs::read(f.f.config.state.join("controller-state.json")).unwrap(),
        journal
    );
    assert_eq!(
        fs::read(f.f.config.state.join("database/original")).unwrap(),
        b"untouched original"
    );
}

#[test]
fn recovery_intent_target_review_refuses_tamper_drift_missing_accounts_and_foreign_context_without_repair(
) {
    for fault in [
        "mac",
        "unknown",
        "duplicate",
        "operation",
        "valid-mac-operation",
        "consumption",
        "missing-account",
        "journal",
        "missing-intent",
        "missing-consumed",
        "foreign-target",
    ] {
        let mut f = ConsumptionFixture::new();
        let token = f.token.clone();
        f.consume(Some(&token), f.now).unwrap();
        f.f.source
            .current
            .prepare_update_recovery_with(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &mut f.store,
            )
            .unwrap();
        let path = f.f.config.state.join("host-update-recovery.json");
        match fault {
            "mac"
            | "unknown"
            | "duplicate"
            | "operation"
            | "valid-mac-operation"
            | "consumption" => {
                let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                match fault {
                    "mac" => value["mac"] = "0".repeat(64).into(),
                    "unknown" => value["unknown"] = true.into(),
                    "operation" | "valid-mac-operation" => {
                        value["intent"]["operationId"] =
                            "99999999-9999-4999-8999-999999999999".into()
                    }
                    "consumption" => value["intent"]["consumptionSha256"] = "0".repeat(64).into(),
                    _ => {}
                }
                if fault == "valid-mac-operation" {
                    use hmac::Mac;
                    let mut mac =
                        hmac::Hmac::<Sha256>::new_from_slice("k".repeat(43).as_bytes()).unwrap();
                    mac.update(b"frameleaf-native-update-recovery-v1\0");
                    mac.update(&serde_json_canonicalizer::to_vec(&value["intent"]).unwrap());
                    value["mac"] = mac
                        .finalize()
                        .into_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                        .into();
                }
                let mut raw = value.to_string();
                if fault == "duplicate" {
                    raw = raw.replace(
                        "\"schemaVersion\":1",
                        "\"schemaVersion\":1,\"schemaVersion\":1",
                    );
                }
                fs::write(&path, raw).unwrap();
            }
            "missing-account" => {
                let key = f
                    .store
                    .0
                    .keys()
                    .find(|k| k.starts_with("native-host-profile-"))
                    .unwrap()
                    .clone();
                f.store.0.remove(&key);
            }
            "journal" => {
                f.f.source
                    .change_marker(|m| m["generation"] = uuid::Uuid::new_v4().to_string().into())
            }
            "missing-intent" => fs::remove_file(&path).unwrap(),
            "missing-consumed" => {
                fs::remove_file(f.f.config.state.join("host-update.json")).unwrap()
            }
            "foreign-target" => {
                f.f.source.target.1["sourceRevision"] = "e".repeat(40).into();
                f.f.source.next = f.f.source.target.verify().unwrap();
            }
            _ => unreachable!(),
        }
        f.f.source
            .authority
            .activate(SECURE_ID, &f.f.source.next, &mut || Ok(()))
            .unwrap();
        let before = fs::read(&path).ok();
        let consumed = fs::read(f.f.config.state.join("host-update.json")).ok();
        let accounts = f.accounts();
        assert!(
            f.f.source
                .current
                .review_update_recovery_with(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &mut f.store
                )
                .is_err(),
            "accepted {fault}"
        );
        assert_eq!(fs::read(path).ok(), before);
        assert_eq!(
            fs::read(f.f.config.state.join("host-update.json")).ok(),
            consumed
        );
        assert_eq!(f.accounts(), accounts);
    }
}

#[cfg(unix)]
#[test]
fn recovery_intent_never_follows_links_overwrites_conflicts_or_repairs_nonprivate_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for shape in ["symlink", "hardlink", "public", "oversized", "conflict"] {
        let mut f = ConsumptionFixture::new();
        let token = f.token.clone();
        f.consume(Some(&token), f.now).unwrap();
        f.f.source
            .current
            .prepare_update_recovery_with(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &mut f.store,
            )
            .unwrap();
        let path = f.f.config.state.join("host-update-recovery.json");
        let saved = f.f.config.data.join("saved-intent");
        fs::rename(&path, &saved).unwrap();
        match shape {
            "symlink" => symlink(&saved, &path).unwrap(),
            "hardlink" => fs::hard_link(&saved, &path).unwrap(),
            "public" => {
                fs::copy(&saved, &path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            "oversized" => {
                fs::write(&path, vec![b'x'; 4097]).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            "conflict" => {
                fs::write(&path, b"foreign torn intent").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            _ => unreachable!(),
        }
        let saved_bytes = fs::read(&saved).unwrap();
        let record = f.f.record();
        let accounts = f.accounts();
        assert!(
            f.f.source
                .current
                .prepare_update_recovery_with(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &mut f.store
                )
                .is_err(),
            "accepted {shape}"
        );
        assert_eq!(fs::read(&saved).unwrap(), saved_bytes);
        assert_eq!(f.f.record(), record);
        assert_eq!(f.accounts(), accounts);
    }
}

#[test]
fn recovery_intent_target_cannot_consume_a_prepared_record_or_create_missing_recovery_authority() {
    let mut f = ConsumptionFixture::new();
    let before = f.f.record();
    let accounts = f.accounts();
    f.f.source
        .authority
        .activate(SECURE_ID, &f.f.source.next, &mut || Ok(()))
        .unwrap();
    assert!(f
        .f
        .source
        .current
        .review_update_recovery_with(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &mut f.store
        )
        .is_err());
    assert_eq!(f.f.record(), before);
    assert_eq!(f.accounts(), accounts);
    assert!(!f.f.config.state.join("host-update-recovery.json").exists());
}

struct UpdateTransition<'a> {
    base: &'a Authority,
    mode: &'static str,
    intent: PathBuf,
}
impl HostEpochAuthority for UpdateTransition<'_> {
    fn installation_id(&self) -> Result<String, String> {
        self.base.installation_id()
    }
    fn with_admitted(
        &self,
        id: &str,
        runtime: &VerifiedHostRuntime,
        operation: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let saved = self
            .base
            .0
            .try_lock()
            .map_err(|_| "nested installation admission")?;
        if saved.0 != id {
            return Err("wrong installation".into());
        }
        saved.1.require_admitted(runtime)?;
        operation()
    }
    fn activate(
        &self,
        id: &str,
        runtime: &VerifiedHostRuntime,
        publish: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.base.activate(id, runtime, publish)
    }
    fn transition(
        &self,
        id: &str,
        [source, target]: [&VerifiedHostRuntime; 2],
        prepare: &mut dyn FnMut() -> Result<(), String>,
        publish: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let mut saved = self
            .base
            .0
            .try_lock()
            .map_err(|_| "nested installation transition")?;
        if saved.0 != id {
            return Err("wrong installation".into());
        }
        saved.1.require_admitted(source)?;
        if target.epoch() <= source.epoch() {
            return Err("not newer".into());
        }
        prepare()?;
        assert!(
            self.intent.is_file(),
            "epoch save without durable recovery intent"
        );
        if self.mode == "before-save" {
            return Err("save refused".into());
        }
        saved.1.admit(target)?;
        if self.mode == "after-save" {
            return Err("saved but reply lost".into());
        }
        publish()
    }
}

#[test]
fn guarded_handover_revalidates_backup_on_retry_and_admits_target_only_after_durable_intent() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut f = ConsumptionFixture::new();
    let token = f.token.clone();
    f.consume(Some(&token), f.now).unwrap();
    let accounts = f.accounts();
    let record = f.f.record();
    let journal = fs::read(f.f.config.state.join("controller-state.json")).unwrap();
    let intent = f.f.config.state.join("host-update-recovery.json");
    let cancel = AtomicBool::new(false);
    let calls = std::cell::Cell::new(0);
    for mode in ["before-save", "success"] {
        let provider = UpdateTransition {
            base: &f.f.source.authority,
            mode,
            intent: intent.clone(),
        };
        let execution = HostExecution::new(&provider, SECURE_ID).unwrap();
        let result = f.f.source.current.begin_update_handover_test(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &execution,
            &cancel,
            &mut f.store,
            |payload, key| {
                assert!(
                    provider.base.0.try_lock().is_err(),
                    "backup readback lacks installation ownership"
                );
                assert_eq!(
                    serde_json::to_value(payload).unwrap()["targetManifestSha256"],
                    f.f.source.next.manifest_sha256()
                );
                assert_eq!(key, "k".repeat(43));
                calls.set(calls.get() + 1);
                Ok(())
            },
        );
        assert_eq!(result.is_ok(), mode == "success");
        if let Ok(proof) = result {
            assert_eq!(
                serde_json::to_value(proof).unwrap()["state"],
                "target-admitted"
            );
        }
    }
    assert_eq!(calls.get(), 2, "existing intent bypassed backup readback");
    assert!(intent.is_file());
    assert!(!cancel.load(Ordering::Acquire));
    assert_eq!(f.accounts(), accounts);
    assert_eq!(f.f.record(), record);
    assert_eq!(
        fs::read(f.f.config.state.join("controller-state.json")).unwrap(),
        journal
    );
    assert_eq!(
        fs::read(f.f.config.state.join("database/original")).unwrap(),
        b"untouched original"
    );
    assert!(f.consume(None, f.now + 600_000).is_err());
    assert!(f
        .f
        .source
        .current
        .review_update_recovery_with(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &mut f.store
        )
        .is_ok());
}

#[test]
fn guarded_handover_cancellation_refusal_and_ambiguous_save_never_bypass_fences_or_lower_target() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for fault in [
        "backup",
        "pre-cancel",
        "late-cancel",
        "intent",
        "target-code",
        "after-save",
    ] {
        let mut f = ConsumptionFixture::new();
        let token = f.token.clone();
        f.consume(Some(&token), f.now).unwrap();
        let intent = f.f.config.state.join("host-update-recovery.json");
        if fault == "intent" {
            fs::write(&intent, b"foreign intent").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&intent, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let provider = UpdateTransition {
            base: &f.f.source.authority,
            mode: if fault == "after-save" {
                "after-save"
            } else {
                "success"
            },
            intent: intent.clone(),
        };
        let execution = HostExecution::new(&provider, SECURE_ID).unwrap();
        let cancel = AtomicBool::new(fault == "pre-cancel");
        let calls = std::cell::Cell::new(0);
        let record = f.f.record();
        let accounts = f.accounts();
        let result = f.f.source.current.begin_update_handover_test(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &execution,
            &cancel,
            &mut f.store,
            |_, _| {
                calls.set(calls.get() + 1);
                if fault == "backup" {
                    return Err("decrypted backup mismatch".into());
                }
                if fault == "late-cancel" {
                    cancel.store(true, Ordering::Release);
                }
                if fault == "target-code" {
                    fs::write(
                        f.f.source.target.0.join("node"),
                        b"changed while verifying backup",
                    )
                    .unwrap();
                }
                Ok(())
            },
        );
        assert!(result.is_err(), "accepted {fault}");
        assert_eq!(calls.get(), usize::from(fault != "pre-cancel"));
        let epochs = serde_json::to_value(&f.f.source.authority.0.lock().unwrap().1).unwrap();
        assert_eq!(
            epochs["accepted"][0]["epoch"],
            if fault == "after-save" { 2 } else { 1 }
        );
        assert_eq!(f.f.record(), record);
        assert_eq!(f.accounts(), accounts);
        if fault == "after-save" {
            assert!(f
                .f
                .source
                .current
                .review_update_recovery_with(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &execution,
                    &mut f.store
                )
                .is_ok());
            assert!(f.consume(None, f.now + 600_000).is_err());
        }
        if fault == "intent" {
            assert_eq!(fs::read(intent).unwrap(), b"foreign intent");
        }
    }
}

#[test]
fn guarded_handover_requires_consumption_supported_authority_and_actual_engine_readback() {
    use std::sync::atomic::AtomicBool;
    let mut f = ConsumptionFixture::new();
    let cancel = AtomicBool::new(false);
    let intent = f.f.config.state.join("host-update-recovery.json");
    {
        let provider = UpdateTransition {
            base: &f.f.source.authority,
            mode: "success",
            intent: intent.clone(),
        };
        let execution = HostExecution::new(&provider, SECURE_ID).unwrap();
        assert!(f
            .f
            .source
            .current
            .begin_update_handover_test(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &execution,
                &cancel,
                &mut f.store,
                |_, _| panic!("unconsumed backup use")
            )
            .is_err());
    }
    let token = f.token.clone();
    f.consume(Some(&token), f.now).unwrap();
    assert!(f
        .f
        .source
        .current
        .begin_update_handover_test(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &cancel,
            &mut f.store,
            |_, _| panic!("unsupported authority callback")
        )
        .is_err());
    let provider = UpdateTransition {
        base: &f.f.source.authority,
        mode: "success",
        intent: intent.clone(),
    };
    let execution = HostExecution::new(&provider, SECURE_ID).unwrap();
    // The signed synthetic fixture engine is not a working restic repository/engine.
    assert!(f
        .f
        .source
        .current
        .begin_update_handover_with(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &execution,
            &cancel,
            &mut f.store
        )
        .is_err());
    assert!(!intent.exists());
    assert_eq!(
        serde_json::to_value(&f.f.source.authority.0.lock().unwrap().1).unwrap()["accepted"][0]
            ["epoch"],
        1
    );
}

#[test]
fn update_input_staging_refuses_before_target_admission_or_consumption_without_plaintext() {
    use std::sync::atomic::AtomicBool;
    for consumed in [false, true] {
        let mut f = ConsumptionFixture::new();
        if consumed {
            let token = f.token.clone();
            f.consume(Some(&token), f.now).unwrap();
        }
        let before = f.accounts();
        assert!(f
            .f
            .source
            .current
            .stage_update_input_with(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &AtomicBool::new(false),
                &mut f.store,
            )
            .is_err());
        assert!(!f.f.config.state.join("restore-input").exists());
        assert_eq!(f.accounts(), before);
        assert_eq!(
            fs::read(f.f.config.state.join("database/original")).unwrap(),
            b"untouched original"
        );
    }
}

fn input_staging_fixture() -> (ConsumptionFixture, Vec<u8>, Vec<u8>) {
    input_staging_fixture_with(ConsumptionFixture::new())
}
fn input_staging_fixture_with(mut f: ConsumptionFixture) -> (ConsumptionFixture, Vec<u8>, Vec<u8>) {
    use base64::Engine;
    use hmac::Mac;
    let encoded = f.token.split_once('.').unwrap().0;
    let mut payload: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .unwrap(),
    )
    .unwrap();
    let dump = b"PGDMPsynthetic update staging".to_vec();
    payload["checkpoint"]["dump"] =
        json!({"bytes":dump.len(),"sha256":format!("{:x}",Sha256::digest(&dump))});
    let cp = &payload["checkpoint"];
    // Match the Manager/child's canonical checkpoint and recovery field order.
    let checkpoint = format!(
        r#"{{"protocolVersion":1,"state":"checkpoint","schemaVersion":1,"operationId":{},"manifestSha256":{},"sourceRevision":{},"postgresMajor":"19","databaseFormat":"frameleaf-canonical","dump":{{"bytes":{},"sha256":{}}}}}"#,
        cp["operationId"],
        cp["manifestSha256"],
        cp["sourceRevision"],
        cp["dump"]["bytes"],
        cp["dump"]["sha256"]
    );
    let raw=format!(r#"{{"schemaVersion":1,"runtime":"native","mediaIncluded":false,"databaseFormat":"frameleaf-canonical","libraryId":{},"createdAt":1,"installation":{{"id":{},"name":{},"release":{}}},"checkpoint":{}}}"#,payload["libraryId"],payload["installationId"],json!(f.f.config.name.trim()),json!(f.f.config.release),checkpoint).into_bytes();
    payload["recoverySha256"] = format!("{:x}", Sha256::digest(&raw)).into();
    let bytes = payload.to_string();
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice("k".repeat(43).as_bytes()).unwrap();
    mac.update(b"frameleaf-native-update-approval-v1\0");
    mac.update(bytes.as_bytes());
    f.token = format!(
        "{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let token = f.token.clone();
    f.consume(Some(&token), f.now).unwrap();
    f.f.source
        .current
        .prepare_update_recovery_with(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &mut f.store,
        )
        .unwrap();
    f.f.source
        .authority
        .activate(SECURE_ID, &f.f.source.next, &mut || Ok(()))
        .unwrap();
    (f, dump, raw)
}

#[test]
fn update_input_staging_preserves_source_and_returns_exact_target_binding_with_fresh_retries() {
    use std::{io::Write, sync::atomic::AtomicBool};
    let (mut f, dump, raw) = input_staging_fixture();
    let accounts = f.accounts();
    let originals = [
        "controller-state.json",
        "host-state.json",
        "host-update.json",
        "host-update-recovery.json",
        "database/original",
    ]
    .map(|p| (p, fs::read(f.f.config.state.join(p)).unwrap()));
    let mut operations = std::collections::BTreeSet::new();
    for _ in 0..2 {
        let result =
            f.f.source
                .current
                .stage_update_input_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(false),
                    &mut f.store,
                    |payload, key, mut file| {
                        assert!(f.f.source.authority.0.try_lock().is_err());
                        assert_eq!(key, "k".repeat(43));
                        assert_eq!(
                            serde_json::to_value(payload).unwrap()["targetManifestSha256"],
                            f.f.source.next.manifest_sha256()
                        );
                        file.write_all(&dump).unwrap();
                        file.sync_all().unwrap();
                        Ok(raw.clone())
                    },
                )
                .unwrap();
        let request = serde_json::to_value(result).unwrap();
        let binding = &request["restore"];
        assert_eq!(request["kind"], "native-update");
        assert_eq!(request["sourceEpoch"], 1);
        assert_eq!(request["targetEpoch"], 2);
        assert_eq!(binding["manifestSha256"], f.f.source.next.manifest_sha256());
        assert_eq!(binding["sourceRevision"], f.f.source.next.source_revision());
        assert_eq!(
            request["sourceCheckpoint"],
            serde_json::from_slice::<Value>(&raw).unwrap()["checkpoint"]
        );
        let operation = binding["operationId"].as_str().unwrap();
        assert!(operations.insert(operation.to_owned()));
        let path = f.f.config.state.join("restore-input").join(operation);
        #[cfg(windows)]
        for directory in [
            path.parent().unwrap().to_path_buf(),
            path.clone(),
            path.join("input"),
        ] {
            crate::windows_protection::require_private_directory(&directory).unwrap();
        }
        assert_eq!(fs::read(path.join("input/database.dump")).unwrap(), dump);
        assert_eq!(fs::read(path.join("input/recovery.json")).unwrap(), raw);
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(path.join("restore-intent.json")).unwrap())
                .unwrap(),
            *binding
        );
        assert!(!request.to_string().contains(&"k".repeat(43)));
        for (name, before) in &originals {
            assert_eq!(fs::read(f.f.config.state.join(name)).unwrap(), *before);
        }
    }
    assert_eq!(f.accounts(), accounts);
    assert!(
        f.consume(None, f.now + 600_000).is_err(),
        "old source regained epoch authority"
    );
}

#[test]
fn update_input_staging_refuses_failed_or_changed_inputs_and_retains_uncertain_attempts() {
    use std::{io::Write, sync::atomic::AtomicBool};
    for fault in [
        "missing-intent",
        "cancel",
        "write",
        "dump",
        "recovery",
        "extra-input",
        "extra-operation",
        "source-marker",
        "production-engine",
    ] {
        let (mut f, dump, raw) = input_staging_fixture();
        let accounts = f.accounts();
        let called = std::cell::Cell::new(false);
        let state = f.f.config.state.clone();
        let root = state.join("restore-input");
        if fault == "missing-intent" {
            fs::remove_file(state.join("host-update-recovery.json")).unwrap();
        }
        let cancel = AtomicBool::new(fault == "cancel");
        let result = if fault == "production-engine" {
            f.f.source.current.stage_update_input_with(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &cancel,
                &mut f.store,
            )
        } else {
            f.f.source.current.stage_update_input_test(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &cancel,
                &mut f.store,
                |_, _, mut file| {
                    called.set(true);
                    file.write_all(if fault == "dump" {
                        b"wrong dump"
                    } else {
                        &dump
                    })
                    .unwrap();
                    file.sync_all().unwrap();
                    if fault == "write" {
                        return Err("synthetic interrupted write".into());
                    }
                    if fault == "source-marker" {
                        fs::write(state.join("host-state.json"), b"{}").unwrap();
                    }
                    if fault == "extra-input" || fault == "extra-operation" {
                        let operation =
                            fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
                        fs::write(
                            if fault == "extra-input" {
                                operation.join("input/foreign")
                            } else {
                                operation.join("foreign")
                            },
                            b"keep",
                        )
                        .unwrap();
                    }
                    Ok(if fault == "recovery" {
                        b"{}".to_vec()
                    } else {
                        raw.clone()
                    })
                },
            )
        };
        assert!(result.is_err(), "accepted {fault}");
        assert_eq!(
            called.get(),
            !matches!(fault, "missing-intent" | "cancel" | "production-engine")
        );
        if matches!(fault, "missing-intent" | "cancel") {
            assert!(!root.exists());
        } else {
            let attempts = fs::read_dir(&root)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect::<Vec<_>>();
            assert_eq!(attempts.len(), 1);
            assert!(attempts[0].join("input/database.dump").is_file());
            if fault != "source-marker" {
                assert!(!attempts[0].join("restore-intent.json").exists());
            }
        }
        assert_eq!(f.accounts(), accounts);
        assert_eq!(
            fs::read(state.join("database/original")).unwrap(),
            b"untouched original"
        );
    }
}

#[cfg(unix)]
#[test]
fn update_input_staging_never_follows_or_repairs_an_unsafe_staging_root() {
    use std::{
        os::unix::fs::{symlink, PermissionsExt},
        sync::atomic::AtomicBool,
    };
    for shape in ["link", "public", "file"] {
        let (mut f, _, _) = input_staging_fixture();
        let path = f.f.config.state.join("restore-input");
        let outside = f.f.config.data.join("untouched");
        crate::runtime_store::private_directory(&outside).unwrap();
        fs::write(outside.join("original"), b"keep").unwrap();
        match shape {
            "link" => symlink(&outside, &path).unwrap(),
            "public" => {
                fs::create_dir(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            }
            _ => fs::write(&path, b"keep file").unwrap(),
        }
        let result = f.f.source.current.stage_update_input_test(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &AtomicBool::new(false),
            &mut f.store,
            |_, _, _| panic!("unsafe root reached backup"),
        );
        assert!(result.is_err(), "accepted {shape}");
        assert_eq!(fs::read(outside.join("original")).unwrap(), b"keep");
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
        if shape == "public" {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
    }
}

#[cfg(windows)]
#[test]
fn update_input_staging_refuses_existing_inherited_acl_without_repair() {
    use std::sync::atomic::AtomicBool;
    let (mut f, _, _) = input_staging_fixture();
    let path = f.f.config.state.join("restore-input");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("original"), b"keep").unwrap();
    assert!(crate::windows_protection::require_private_directory(&path).is_err());
    assert!(f
        .f
        .source
        .current
        .stage_update_input_test(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &AtomicBool::new(false),
            &mut f.store,
            |_, _, _| panic!("unsafe root reached backup"),
        )
        .is_err());
    assert!(crate::windows_protection::require_private_directory(&path).is_err());
    assert_eq!(fs::read(path.join("original")).unwrap(), b"keep");
    assert_eq!(fs::read_dir(path).unwrap().count(), 1);
}

#[cfg(unix)]
fn supervised_preparation_fixture(mode: &str) -> (ConsumptionFixture, Vec<u8>, Vec<u8>) {
    use std::os::unix::fs::PermissionsExt;
    let source = Fixture::with_target(|target| {
        let script = format!(
            "#!/usr/bin/python3\nMODE = {mode:?}\n{}",
            include_str!("../../tests/fixtures/update-preparation-agent.py")
        );
        fs::write(target.0.join("node"), script.as_bytes()).unwrap();
        fs::set_permissions(target.0.join("node"), fs::Permissions::from_mode(0o700)).unwrap();
        target.1["files"]["node"] = json!({"bytes":script.len(),"sha256":format!("{:x}",Sha256::digest(script.as_bytes()))});
    });
    input_staging_fixture_with(ConsumptionFixture::with_reservation(
        ReservationFixture::with_source(source),
    ))
}

#[cfg(unix)]
#[test]
fn supervised_update_preparation_uses_held_credentials_and_retains_source_and_target_floor() {
    use std::{io::Write, sync::atomic::AtomicBool};
    let (mut f, dump, raw) = supervised_preparation_fixture("normal");
    let before = f.accounts();
    let journal = f.f.record();
    let marker = fs::read(f.f.config.state.join("host-state.json")).unwrap();
    let candidate =
        f.f.source
            .current
            .prepare_update_candidate_test(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &AtomicBool::new(false),
                &mut f.store,
                |_, key, mut file| {
                    assert_eq!(key, "k".repeat(43));
                    file.write_all(&dump).unwrap();
                    Ok(raw.clone())
                },
            )
            .unwrap();
    let value = serde_json::to_value(candidate).unwrap();
    assert_eq!(value["state"], "candidate-verified");
    assert_eq!(value["offlineChecksums"], true);
    assert_eq!(value["schemaValidated"], true);
    assert_eq!(value["receipt"]["state"], "update-prepared");
    assert_eq!(value["receipt"]["update"]["targetEpoch"], 2);
    assert_eq!(value["receipt"]["update"]["sourceEpoch"], 1);
    assert!(!value
        .to_string()
        .contains("synthetic existing database password"));
    assert!(!value.to_string().contains(&"k".repeat(43)));
    assert_eq!(f.accounts(), before);
    assert_eq!(f.f.record(), journal);
    assert_eq!(
        fs::read(f.f.config.state.join("host-state.json")).unwrap(),
        marker
    );
    assert_eq!(
        fs::read(f.f.config.state.join("database/original")).unwrap(),
        b"untouched original"
    );
    assert!(f
        .f
        .source
        .authority
        .execution()
        .with_admitted(&f.f.source.current, &mut || Ok(()))
        .is_err());
    assert!(crate::manager_profile::ProfileGuard::acquire(&f.f.config).is_ok());
}

#[cfg(unix)]
#[test]
fn supervised_update_preparation_refuses_bad_receipts_or_targets_without_changing_source() {
    use std::{io::Write, sync::atomic::AtomicBool};
    for mode in [
        "nonzero",
        "state",
        "binding",
        "record",
        "pid",
        "extra",
        "source-marker",
        "proof-state",
        "unchecked",
        "unschemed",
        "proof-extra",
        "unverified",
    ] {
        let (mut f, dump, raw) = supervised_preparation_fixture(mode);
        let before = f.accounts();
        let journal = f.f.record();
        assert!(
            f.f.source
                .current
                .prepare_update_candidate_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(false),
                    &mut f.store,
                    |_, _, mut file| {
                        file.write_all(&dump).unwrap();
                        Ok(raw.clone())
                    }
                )
                .is_err(),
            "{mode}"
        );
        assert_eq!(f.accounts(), before);
        assert_eq!(f.f.record(), journal);
        assert_eq!(
            fs::read(f.f.config.state.join("database/original")).unwrap(),
            b"untouched original"
        );
        assert!(f
            .f
            .source
            .authority
            .execution()
            .with_admitted(&f.f.source.current, &mut || Ok(()))
            .is_err());
        assert!(crate::manager_profile::ProfileGuard::acquire(&f.f.config).is_ok());
    }
}

#[test]
fn supervised_update_preparation_refuses_unconsumed_or_unadmitted_requests_before_staging() {
    use std::sync::atomic::AtomicBool;
    for admitted in [false, true] {
        let mut f = ConsumptionFixture::new();
        if admitted {
            f.f.source
                .authority
                .activate(SECURE_ID, &f.f.source.next, &mut || Ok(()))
                .unwrap();
        }
        let before = f.accounts();
        let journal = f.f.record();
        assert!(f
            .f
            .source
            .current
            .prepare_update_candidate_test(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &AtomicBool::new(false),
                &mut f.store,
                |_, _, _| panic!("unapproved update reached backup reader")
            )
            .is_err());
        assert!(!f.f.config.state.join("restore-input").exists());
        assert_eq!(f.accounts(), before);
        assert_eq!(f.f.record(), journal);
    }
}

#[cfg(unix)]
#[test]
fn supervised_update_preparation_drains_the_owned_child_on_cancellation() {
    use std::{
        io::Write,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };
    let (mut f, dump, raw) = supervised_preparation_fixture("hang");
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    let state = f.f.config.state.clone();
    let watcher = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !state.join("update-child-started").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        signal.store(true, Ordering::Release);
    });
    let before = f.accounts();
    let journal = f.f.record();
    assert!(f
        .f
        .source
        .current
        .prepare_update_candidate_test(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &cancel,
            &mut f.store,
            |_, _, mut file| {
                file.write_all(&dump).unwrap();
                Ok(raw.clone())
            }
        )
        .is_err());
    watcher.join().unwrap();
    assert!(f.f.config.state.join("update-stop-received").exists());
    assert_eq!(f.accounts(), before);
    assert_eq!(f.f.record(), journal);
    assert_eq!(
        fs::read(f.f.config.state.join("database/original")).unwrap(),
        b"untouched original"
    );
    assert!(crate::manager_profile::ProfileGuard::acquire(&f.f.config).is_ok());
}

#[test]
fn unconfirmed_update_shutdown_retains_profile_controller_and_both_code_leases() {
    for successful in [false, true] {
        let (mut f, _, _) = input_staging_fixture();
        let before = f.accounts();
        let journal = f.f.record();
        assert!(f
            .f
            .source
            .current
            .fail_update_shutdown_test(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &mut f.store,
                successful,
            )
            .is_err());
        assert!(crate::manager_profile::ProfileGuard::acquire(&f.f.config).is_err());
        assert!(crate::host_state::Owner::acquire_update(&f.f.config.state, SECURE_ID).is_err());
        for runtime in [&f.f.source.current, &f.f.source.next] {
            assert!(
                crate::package_lease::Maintenance::acquire(runtime.root.parent().unwrap()).is_err()
            );
        }
        assert_eq!(f.accounts(), before);
        assert_eq!(f.f.record(), journal);
    }
}

#[cfg(unix)]
#[test]
fn update_selection_persists_authenticated_target_pointer_and_retains_writer_fence_and_original() {
    use std::{io::Write, sync::atomic::AtomicBool};
    let (mut f, dump, raw) = supervised_preparation_fixture("normal");
    let accounts = f.accounts();
    let journal = fs::read(f.f.config.state.join("controller-state.json")).unwrap();
    let host = fs::read(f.f.config.state.join("host-state.json")).unwrap();
    let profile = fs::read(f.f.config.data.join(".host-profile")).unwrap();
    let selected =
        f.f.source
            .current
            .select_update_candidate_test(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &AtomicBool::new(false),
                &mut f.store,
                |_, _, mut file| {
                    file.write_all(&dump).unwrap();
                    Ok(raw.clone())
                },
            )
            .unwrap();
    let value = serde_json::to_value(selected).unwrap();
    assert_eq!(value["state"], "selected-pending-publication");
    assert_eq!(value["offlineChecksums"], true);
    assert_eq!(value["schemaValidated"], true);
    let marker: Value =
        serde_json::from_slice(&fs::read(f.f.config.state.join("controller-state.json")).unwrap())
            .unwrap();
    assert_eq!(marker["manifestSha256"], f.f.source.next.manifest_sha256());
    assert_eq!(marker["databaseReference"], value["reference"]);
    assert_eq!(marker["generation"], value["selectionGeneration"]);
    assert_ne!(
        fs::read(f.f.config.state.join("controller-state.json")).unwrap(),
        journal
    );
    assert!(f.f.config.state.join("host-update.json").is_file());
    assert!(f
        .f
        .config
        .state
        .join("host-update-selection.json")
        .is_file());
    assert_eq!(
        fs::read(f.f.config.state.join("host-state.json")).unwrap(),
        host
    );
    assert_eq!(
        fs::read(f.f.config.data.join(".host-profile")).unwrap(),
        profile
    );
    assert_eq!(
        fs::read(f.f.config.state.join("database/original")).unwrap(),
        b"untouched original"
    );
    assert_eq!(f.accounts(), accounts);
    for _ in 0..2 {
        let resumed =
            f.f.source
                .current
                .resume_update_selection_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(false),
                    &mut f.store,
                )
                .unwrap();
        assert_eq!(serde_json::to_value(resumed).unwrap(), value);
    }
    let mut owner = crate::host_state::Owner::acquire_update(&f.f.config.state, SECURE_ID).unwrap();
    assert!(
        matches!(owner.activate(ID,f.f.source.next.manifest_sha256(),HostMode::Server),Err(e) if e=="host_update_pending")
    );
}

#[cfg(unix)]
#[test]
fn update_selection_recovery_completes_only_exact_previous_selected_or_torn_next_journal() {
    use std::{io::Write, sync::atomic::AtomicBool};
    for cut in ["previous", "empty", "short", "half", "selected"] {
        let (mut f, dump, raw) = supervised_preparation_fixture("normal");
        let path = f.f.config.state.join("controller-state.json");
        let previous = fs::read(&path).unwrap();
        let selected =
            f.f.source
                .current
                .select_update_candidate_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(false),
                    &mut f.store,
                    |_, _, mut file| {
                        file.write_all(&dump).unwrap();
                        Ok(raw.clone())
                    },
                )
                .unwrap();
        let expected = serde_json::to_value(selected).unwrap();
        let next = fs::read(&path).unwrap();
        let torn = match cut {
            "previous" => previous.as_slice(),
            "empty" => &next[..0],
            "short" => &next[..9],
            "half" => &next[..next.len() / 2],
            _ => next.as_slice(),
        };
        fs::write(&path, torn).unwrap();
        let accounts = f.accounts();
        let resumed =
            f.f.source
                .current
                .resume_update_selection_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(false),
                    &mut f.store,
                )
                .unwrap();
        assert_eq!(serde_json::to_value(resumed).unwrap(), expected, "{cut}");
        assert_eq!(fs::read(&path).unwrap(), next, "{cut}");
        assert_eq!(
            fs::read(f.f.config.state.join("database/original")).unwrap(),
            b"untouched original"
        );
        assert_eq!(f.accounts(), accounts);
    }
}

#[cfg(unix)]
#[test]
fn update_selection_recovery_refuses_tamper_foreign_state_changed_inputs_and_lost_authority() {
    use std::{io::Write, sync::atomic::AtomicBool};
    for fault in [
        "mac",
        "consumption",
        "foreign-journal",
        "foreign-prefix",
        "credentials",
        "source",
        "media",
        "database",
        "pid",
        "dump",
        "result",
        "code",
        "floor",
        "cancel",
        "linked-capsule",
    ] {
        let (mut f, dump, raw) = supervised_preparation_fixture("normal");
        let state = f.f.config.state.clone();
        let path = state.join("controller-state.json");
        let selected =
            f.f.source
                .current
                .select_update_candidate_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(false),
                    &mut f.store,
                    |_, _, mut file| {
                        file.write_all(&dump).unwrap();
                        Ok(raw.clone())
                    },
                )
                .unwrap();
        let value = serde_json::to_value(selected).unwrap();
        let reference = &value["reference"];
        let target = state
            .join("restore-targets")
            .join(reference["operationId"].as_str().unwrap())
            .join(reference["attemptId"].as_str().unwrap());
        let capsule = state.join("host-update-selection.json");
        match fault {
            "mac" => {
                let mut v: Value = serde_json::from_slice(&fs::read(&capsule).unwrap()).unwrap();
                v["mac"] = "0".repeat(64).into();
                fs::write(&capsule, serde_json::to_vec(&v).unwrap()).unwrap();
            }
            "consumption" => {
                let file = state.join("host-update.json");
                let mut v = fs::read(&file).unwrap();
                v.push(b' ');
                fs::write(file, v).unwrap();
            }
            "foreign-journal" => {
                let mut v: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                v["generation"] = uuid::Uuid::new_v4().to_string().into();
                fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
            }
            "foreign-prefix" => fs::write(&path, b"{\"foreign\"").unwrap(),
            "credentials" => f.store.0.clear(),
            "source" => fs::write(state.join("host-state.json"), b"{}").unwrap(),
            "media" => crate::runtime_store::private_directory(&state.join("media")).unwrap(),
            "database" => {
                fs::rename(target.join("database"), target.join("retained-database")).unwrap();
                crate::runtime_store::private_directory(&target.join("database")).unwrap();
            }
            "pid" => fs::write(
                target.join("database/postmaster.pid"),
                b"not-an-adoptable-pid",
            )
            .unwrap(),
            "dump" => fs::write(
                state
                    .join("restore-input")
                    .join(reference["operationId"].as_str().unwrap())
                    .join("input/database.dump"),
                b"changed retained input",
            )
            .unwrap(),
            "result" => fs::write(target.join("restore-result.json"), b"{}").unwrap(),
            "code" => {
                fs::write(f.f.source.target.0.join("node"), b"changed signed target").unwrap()
            }
            "floor" => {
                let mut newer = HostFixture::new();
                newer.1["epoch"] = json!(3);
                newer.1["sourceRevision"] = json!("c".repeat(40));
                let runtime = newer.verify().unwrap();
                f.f.source
                    .authority
                    .activate(SECURE_ID, &runtime, &mut || Ok(()))
                    .unwrap();
            }
            "linked-capsule" => fs::hard_link(&capsule, state.join("capsule-alias")).unwrap(),
            _ => {}
        }
        let before = fs::read(&path).unwrap();
        let accounts = f.accounts();
        assert!(
            f.f.source
                .current
                .resume_update_selection_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(fault == "cancel"),
                    &mut f.store
                )
                .is_err(),
            "{fault}"
        );
        assert_eq!(fs::read(&path).unwrap(), before, "{fault}");
        assert_eq!(f.accounts(), accounts, "{fault}");
        assert_eq!(
            fs::read(state.join("database/original")).unwrap(),
            b"untouched original",
            "{fault}"
        );
        assert!(state.join("host-update.json").is_file());
        assert!(crate::manager_profile::ProfileGuard::acquire(&f.f.config).is_ok());
    }
}

#[test]
fn update_selection_refuses_unconsumed_requests_before_any_backup_or_pointer_effect() {
    use std::sync::atomic::AtomicBool;
    let mut f = ConsumptionFixture::new();
    let before = fs::read(f.f.config.state.join("controller-state.json")).unwrap();
    let accounts = f.accounts();
    assert!(f
        .f
        .source
        .current
        .select_update_candidate_test(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &AtomicBool::new(false),
            &mut f.store,
            |_, _, _| panic!("unconsumed update reached backup reader")
        )
        .is_err());
    assert_eq!(
        fs::read(f.f.config.state.join("controller-state.json")).unwrap(),
        before
    );
    assert_eq!(f.accounts(), accounts);
    assert!(!f.f.config.state.join("host-update-selection.json").exists());
    assert!(!f.f.config.state.join("restore-input").exists());
}

#[test]
fn update_selection_requires_existing_cutpoint_recovery_before_staging_another_attempt() {
    use std::sync::atomic::AtomicBool;
    let (mut f, _, _) = input_staging_fixture();
    let state = &f.f.config.state;
    fs::write(
        state.join("host-update-selection.json"),
        b"retained transaction requiring authentication",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            state.join("host-update-selection.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let before = fs::read(state.join("controller-state.json")).unwrap();
    let accounts = f.accounts();
    let mut reads = 0;
    assert!(f
        .f
        .source
        .current
        .select_update_candidate_test(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &AtomicBool::new(false),
            &mut f.store,
            |_, _, _| {
                reads += 1;
                Err("unexpected new backup read".into())
            }
        )
        .is_err());
    assert_eq!(
        reads, 0,
        "an existing cutpoint must go through authenticated resume"
    );
    assert!(!state.join("restore-input").exists());
    assert_eq!(
        fs::read(state.join("controller-state.json")).unwrap(),
        before
    );
    assert_eq!(f.accounts(), accounts);
    assert_eq!(
        fs::read(state.join("host-update-selection.json")).unwrap(),
        b"retained transaction requiring authentication"
    );
}

#[test]
fn update_selection_refuses_source_database_replaced_at_the_publication_boundary() {
    let (f, _, _) = input_staging_fixture();
    let state = &f.f.config.state;
    let operation = uuid::Uuid::new_v4().to_string();
    let attempt = uuid::Uuid::new_v4().to_string();
    let root = state.join("restore-targets");
    let operation_root = root.join(&operation);
    let target = operation_root.join(&attempt);
    for path in [&root, &operation_root, &target, &target.join("database")] {
        crate::runtime_store::private_directory(path).unwrap();
    }
    let reference = crate::host_database::Reference::capture(state, &operation, &attempt).unwrap();
    let before = fs::read(state.join("controller-state.json")).unwrap();
    fs::rename(state.join("database"), state.join("retained-original")).unwrap();
    crate::runtime_store::private_directory(&state.join("database")).unwrap();
    let mut owner = crate::host_state::Owner::acquire_update(state, SECURE_ID).unwrap();
    assert!(
        owner
            .prepare_update_selection(
                ID,
                f.f.source.current.manifest_sha256(),
                f.f.source.next.manifest_sha256(),
                &reference
            )
            .is_err(),
        "selection must bind the database from authenticated consumption, not a later replacement"
    );
    drop(owner);
    assert_eq!(
        fs::read(state.join("controller-state.json")).unwrap(),
        before
    );
    assert_eq!(
        fs::read(state.join("retained-original/original")).unwrap(),
        b"untouched original"
    );
    assert!(!state.join("host-update-selection.json").exists());
}

#[cfg(unix)]
type PublicationRecords = [(std::path::PathBuf, Vec<u8>, Vec<u8>); 3];

#[cfg(unix)]
fn publication_records(f: &ConsumptionFixture) -> PublicationRecords {
    let capsule: Value = serde_json::from_slice(
        &fs::read(f.f.config.state.join("host-update-selection.json")).unwrap(),
    )
    .unwrap();
    let source = capsule["intent"]["bindings"][0].as_str().unwrap();
    let target = capsule["intent"]["bindings"][1].as_str().unwrap();
    let state =
        cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&f.f.config.state).unwrap());
    let data =
        cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&f.f.config.data).unwrap());
    let record = |binding: &str| {
        format!(r#"{{"schemaVersion":1,"installationId":{},"secureInstallationId":{},"stateIdentity":{},"managerIdentity":{},"profileBindingSha256":{}}}"#,json!(f.f.config.installation_id),json!(SECURE_ID),json!(crate::copy_source::root_identity(&state).unwrap()),json!(crate::copy_source::root_identity(&data).unwrap()),json!(binding)).into_bytes()
    };
    let host = |r: &VerifiedHostRuntime| {
        format!(
            r#"{{"schemaVersion":1,"manifestSha256":{},"sourceRevision":{},"postgresMajor":"19"}}"#,
            json!(r.manifest_sha256()),
            json!(r.source_revision())
        )
        .into_bytes()
    };
    [
        (
            f.f.config.data.join(".host-configuration.json"),
            record(source),
            record(target),
        ),
        (
            f.f.config.data.join(".host-profile"),
            source.as_bytes().to_vec(),
            target.as_bytes().to_vec(),
        ),
        (
            f.f.config.state.join("host-state.json"),
            host(&f.f.source.current),
            host(&f.f.source.next),
        ),
    ]
}

#[cfg(unix)]
fn publication_fixture() -> (ConsumptionFixture, PublicationRecords) {
    publication_fixture_with("normal")
}

#[cfg(unix)]
fn publication_fixture_with(mode: &str) -> (ConsumptionFixture, PublicationRecords) {
    use std::{io::Write, sync::atomic::AtomicBool};
    let (mut f, dump, raw) = supervised_preparation_fixture(mode);
    f.f.source
        .current
        .select_update_candidate_test(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &AtomicBool::new(false),
            &mut f.store,
            |_, _, mut file| {
                file.write_all(&dump).unwrap();
                Ok(raw.clone())
            },
        )
        .unwrap();
    let records = publication_records(&f);
    // The synthetic credential seed predates a persisted configuration; model the installed source record.
    fs::write(&records[0].0, &records[0].1).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&records[0].0, fs::Permissions::from_mode(0o600)).unwrap();
    (f, records)
}

#[cfg(unix)]
#[test]
fn update_publication_recovers_every_metadata_boundary_and_retains_writer_fence() {
    use std::sync::atomic::AtomicBool;
    for boundary in 0..3 {
        for cut in ["old", "empty", "half", "next", "journal"] {
            let (mut f, records) = publication_fixture();
            let accounts = f.accounts();
            let journal = fs::read(f.f.config.state.join("controller-state.json")).unwrap();
            for (i, (path, _, next)) in records.iter().enumerate() {
                if i < boundary {
                    fs::write(path, next).unwrap();
                }
                if i == boundary {
                    match cut {
                        "empty" => fs::write(path, []).unwrap(),
                        "half" => fs::write(path, &next[..next.len() / 2]).unwrap(),
                        "next" => fs::write(path, next).unwrap(),
                        _ => {}
                    }
                }
            }
            if cut == "journal" {
                let capsule: Value = serde_json::from_slice(
                    &fs::read(f.f.config.state.join("host-update-selection.json")).unwrap(),
                )
                .unwrap();
                let previous: crate::host_state::Marker =
                    serde_json::from_value(capsule["intent"]["selection"]["previous"].clone())
                        .unwrap();
                fs::write(
                    f.f.config.state.join("controller-state.json"),
                    serde_json::to_vec(&previous).unwrap(),
                )
                .unwrap();
            }
            for _ in 0..2 {
                let result =
                    f.f.source
                        .current
                        .publish_update_selection_test(
                            &f.f.source.next,
                            [&f.f.config, &f.destination],
                            &f.f.source.authority.execution(),
                            &AtomicBool::new(false),
                            &mut f.store,
                        )
                        .unwrap_or_else(|error| panic!("boundary {boundary} cut {cut}: {error}"));
                let value = serde_json::to_value(result).unwrap();
                assert_eq!(value["state"], "published-pending-verification");
                assert_eq!(value["offlineChecksums"], false);
                assert_eq!(value["schemaValidated"], false);
                for (path, _, next) in &records {
                    assert_eq!(fs::read(path).unwrap(), *next);
                }
                assert_eq!(f.accounts(), accounts);
                assert_eq!(
                    fs::read(f.f.config.state.join("controller-state.json")).unwrap(),
                    journal
                );
                assert_eq!(
                    fs::read(f.f.config.state.join("database/original")).unwrap(),
                    b"untouched original"
                );
                assert!(f.f.config.state.join("host-update.json").is_file());
            }
            assert!(f
                .f
                .source
                .current
                .resume_update_selection_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(false),
                    &mut f.store
                )
                .is_err());
            assert!(crate::manager_profile::configuration_id(
                &f.destination.state,
                &f.destination.data,
                SECURE_ID
            )
            .is_err());
            let mut owner =
                crate::host_state::Owner::acquire_update(&f.f.config.state, SECURE_ID).unwrap();
            assert!(
                matches!(owner.activate(ID,f.f.source.next.manifest_sha256(),HostMode::Server),Err(e) if e=="host_update_pending")
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn update_publication_refuses_foreign_missing_or_unsafe_metadata_before_any_write() {
    use std::{
        os::unix::fs::{symlink, PermissionsExt},
        sync::atomic::AtomicBool,
    };
    for fault in [
        "foreign-config",
        "foreign-profile",
        "foreign-host",
        "missing-config",
        "missing-profile",
        "missing-host",
        "hardlink",
        "symlink",
        "public",
        "mac",
        "credentials",
        "cancel",
        "code",
        "floor",
        "consumption",
        "media",
        "database",
        "pid",
        "result",
        "dump",
    ] {
        let (mut f, records) = publication_fixture();
        let capsule = f.f.config.state.join("host-update-selection.json");
        let selection: Value = serde_json::from_slice(&fs::read(&capsule).unwrap()).unwrap();
        let reference = &selection["intent"]["selection"]["next"]["databaseReference"];
        let target =
            f.f.config
                .state
                .join("restore-targets")
                .join(reference["operationId"].as_str().unwrap())
                .join(reference["attemptId"].as_str().unwrap());
        match fault {
            "consumption" => {
                let path = f.f.config.state.join("host-update.json");
                let mut bytes = fs::read(&path).unwrap();
                bytes.push(b' ');
                fs::write(path, bytes).unwrap();
            }
            "code" => {
                fs::write(f.f.source.target.0.join("node"), b"changed signed target").unwrap()
            }
            "floor" => {
                let mut newer = HostFixture::new();
                newer.1["epoch"] = json!(3);
                newer.1["sourceRevision"] = json!("c".repeat(40));
                let runtime = newer.verify().unwrap();
                f.f.source
                    .authority
                    .activate(SECURE_ID, &runtime, &mut || Ok(()))
                    .unwrap();
            }
            "media" => {
                crate::runtime_store::private_directory(&f.f.config.state.join("media")).unwrap()
            }
            "database" => {
                fs::rename(target.join("database"), target.join("retained-database")).unwrap();
                crate::runtime_store::private_directory(&target.join("database")).unwrap();
            }
            "pid" => fs::write(target.join("database/postmaster.pid"), b"untrusted pid").unwrap(),
            "result" => fs::write(target.join("restore-result.json"), b"{}").unwrap(),
            "dump" => fs::write(
                f.f.config
                    .state
                    .join("restore-input")
                    .join(reference["operationId"].as_str().unwrap())
                    .join("input/database.dump"),
                b"changed dump",
            )
            .unwrap(),
            "foreign-config" => fs::write(&records[0].0, b"foreign").unwrap(),
            "foreign-profile" => fs::write(&records[1].0, b"foreign").unwrap(),
            "foreign-host" => fs::write(&records[2].0, b"foreign").unwrap(),
            "missing-config" => fs::remove_file(&records[0].0).unwrap(),
            "missing-profile" => fs::remove_file(&records[1].0).unwrap(),
            "missing-host" => fs::remove_file(&records[2].0).unwrap(),
            "hardlink" => {
                fs::hard_link(&records[0].0, f.f.config.data.join("foreign-link")).unwrap()
            }
            "symlink" => {
                fs::remove_file(&records[0].0).unwrap();
                symlink(&records[2].0, &records[0].0).unwrap();
            }
            "public" => {
                fs::set_permissions(&records[0].0, fs::Permissions::from_mode(0o644)).unwrap()
            }
            "mac" => {
                let mut bytes = fs::read(&capsule).unwrap();
                let i = bytes.len() - 3;
                bytes[i] = if bytes[i] == b'a' { b'b' } else { b'a' };
                fs::write(capsule, bytes).unwrap();
            }
            "credentials" => f.store.0.clear(),
            _ => {}
        }
        let before: Vec<_> = records
            .iter()
            .map(|(path, _, _)| fs::read(path).ok())
            .collect();
        let journal = fs::read(f.f.config.state.join("controller-state.json")).unwrap();
        let accounts = f.accounts();
        assert!(
            f.f.source
                .current
                .publish_update_selection_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(fault == "cancel"),
                    &mut f.store
                )
                .is_err(),
            "accepted {fault}"
        );
        for ((path, _, _), expected) in records.iter().zip(before) {
            assert_eq!(fs::read(path).ok(), expected, "changed {fault}");
        }
        assert_eq!(
            fs::read(f.f.config.state.join("controller-state.json")).unwrap(),
            journal
        );
        assert_eq!(f.accounts(), accounts);
        assert!(f.f.config.state.join("host-update.json").is_file());
    }
}

#[cfg(unix)]
#[test]
fn fresh_update_verification_checks_the_retained_target_again_without_restoring_or_clearing_fence()
{
    use std::sync::atomic::AtomicBool;
    let (mut f, records) = publication_fixture();
    let accounts = f.accounts();
    let journal = fs::read(f.f.config.state.join("controller-state.json")).unwrap();
    let capsule = fs::read(f.f.config.state.join("host-update-selection.json")).unwrap();
    let targets: Vec<_> = fs::read_dir(f.f.config.state.join("restore-targets"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    let mut previous = None;
    for count in 1..=2 {
        let checked =
            f.f.source
                .current
                .verify_update_selection_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(false),
                    &mut f.store,
                )
                .unwrap();
        let value = serde_json::to_value(checked).unwrap();
        assert_eq!(value["state"], "published-verified");
        assert_eq!(value["offlineChecksums"], true);
        assert_eq!(value["schemaValidated"], true);
        if let Some(previous) = previous {
            assert_eq!(value, previous);
        }
        previous = Some(value);
        assert_eq!(
            fs::read(f.f.config.state.join("update-verification-started")).unwrap(),
            vec![b'v'; count]
        );
        assert_eq!(f.accounts(), accounts);
        assert_eq!(
            fs::read(f.f.config.state.join("controller-state.json")).unwrap(),
            journal
        );
        assert_eq!(
            fs::read(f.f.config.state.join("host-update-selection.json")).unwrap(),
            capsule
        );
        assert_eq!(
            fs::read(f.f.config.state.join("database/original")).unwrap(),
            b"untouched original"
        );
        assert_eq!(
            fs::read_dir(f.f.config.state.join("restore-targets"))
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<Vec<_>>(),
            targets
        );
        for (path, _, next) in &records {
            assert_eq!(fs::read(path).unwrap(), *next);
        }
    }
    let mut owner = crate::host_state::Owner::acquire_update(&f.f.config.state, SECURE_ID).unwrap();
    assert!(
        matches!(owner.activate(ID,f.f.source.next.manifest_sha256(),HostMode::Server),Err(e) if e=="host_update_pending")
    );
}

#[cfg(unix)]
#[test]
fn fresh_update_verification_refuses_child_failure_foreign_proof_and_post_child_drift() {
    use std::sync::atomic::AtomicBool;
    for mode in [
        "verification-failed",
        "verification-foreign",
        "verification-unchecked",
        "verification-unschemed",
        "verification-source",
        "verification-dump",
        "verification-original",
        "verification-profile",
    ] {
        let (mut f, _) = publication_fixture_with(mode);
        let accounts = f.accounts();
        let journal = fs::read(f.f.config.state.join("controller-state.json")).unwrap();
        assert!(
            f.f.source
                .current
                .verify_update_selection_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(false),
                    &mut f.store
                )
                .is_err(),
            "accepted {mode}"
        );
        if mode == "verification-profile" {
            assert_eq!(
                fs::read(f.f.config.data.join(".host-profile")).unwrap(),
                b"0".repeat(64)
            );
        }
        assert_eq!(
            fs::read(f.f.config.state.join("update-verification-started")).unwrap(),
            b"v",
            "child not reached {mode}"
        );
        assert_eq!(f.accounts(), accounts);
        assert_eq!(
            fs::read(f.f.config.state.join("controller-state.json")).unwrap(),
            journal
        );
        let original = if mode == "verification-original" {
            "retained-original/original"
        } else {
            "database/original"
        };
        assert_eq!(
            fs::read(f.f.config.state.join(original)).unwrap(),
            b"untouched original"
        );
        assert!(f.f.config.state.join("host-update.json").exists());
        assert!(crate::manager_profile::ProfileGuard::acquire(&f.f.config).is_ok());
    }
}

#[cfg(unix)]
#[test]
fn fresh_update_verification_cancellation_drains_the_owned_target_and_keeps_recovery_fence() {
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };
    let (mut f, _) = publication_fixture_with("verification-hang");
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    let state = f.f.config.state.clone();
    let watcher = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !state.join("update-verification-started").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        signal.store(true, Ordering::Release);
    });
    let accounts = f.accounts();
    assert!(f
        .f
        .source
        .current
        .verify_update_selection_test(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &cancel,
            &mut f.store
        )
        .is_err());
    watcher.join().unwrap();
    assert_eq!(
        fs::read(f.f.config.state.join("update-verification-stop")).unwrap(),
        b"stopped"
    );
    assert_eq!(f.accounts(), accounts);
    assert!(f.f.config.state.join("host-update.json").exists());
    assert!(crate::manager_profile::ProfileGuard::acquire(&f.f.config).is_ok());
}

#[test]
fn fresh_update_verification_requires_consumption_and_target_admission_before_any_child() {
    use std::sync::atomic::AtomicBool;
    for admitted in [false, true] {
        let mut f = ConsumptionFixture::new();
        if admitted {
            f.f.source
                .authority
                .activate(SECURE_ID, &f.f.source.next, &mut || Ok(()))
                .unwrap();
        }
        let accounts = f.accounts();
        let journal = f.f.record();
        assert!(f
            .f
            .source
            .current
            .verify_update_selection_test(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &AtomicBool::new(false),
                &mut f.store
            )
            .is_err());
        assert!(!f
            .f
            .config
            .state
            .join("update-verification-started")
            .exists());
        assert!(!f.f.config.state.join("restore-input").exists());
        assert_eq!(f.accounts(), accounts);
        assert_eq!(f.f.record(), journal);
    }
}

#[cfg(unix)]
#[test]
fn update_commit_archives_exact_evidence_then_allows_only_target_discovery() {
    use std::sync::atomic::AtomicBool;
    let (mut f, _) = publication_fixture();
    let accounts = f.accounts();
    let journal = fs::read(f.f.config.state.join("controller-state.json")).unwrap();
    let names = [
        "host-update.json",
        "host-update-recovery.json",
        "host-update-selection.json",
    ];
    let evidence: Vec<_> = names
        .iter()
        .map(|n| fs::read(f.f.config.state.join(n)).unwrap())
        .collect();
    let consumption: Value = serde_json::from_slice(&evidence[0]).unwrap();
    let operation = consumption["operationId"].as_str().unwrap();
    let result =
        f.f.source
            .current
            .finalize_update_selection_test(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &AtomicBool::new(false),
                &mut f.store,
            )
            .unwrap();
    let value = serde_json::to_value(result).unwrap();
    assert_eq!(value["state"], "committed");
    assert_eq!(value["offlineChecksums"], true);
    assert_eq!(value["schemaValidated"], true);
    for ((name, kind), bytes) in names
        .iter()
        .zip(["consumption", "recovery", "selection"])
        .zip(&evidence)
    {
        assert!(!f.f.config.state.join(name).exists());
        assert_eq!(
            fs::read(
                f.f.config
                    .state
                    .join(format!("host-update-history-{operation}-{kind}.json"))
            )
            .unwrap(),
            *bytes
        );
    }
    assert_eq!(
        fs::read(f.f.config.state.join("controller-state.json")).unwrap(),
        journal
    );
    assert_eq!(
        fs::read(f.f.config.state.join("database/original")).unwrap(),
        b"untouched original"
    );
    assert_eq!(f.accounts(), accounts);
    assert_eq!(
        crate::manager_profile::configuration_id(
            &f.destination.state,
            &f.destination.data,
            SECURE_ID
        )
        .unwrap()
        .as_deref(),
        Some(ID)
    );
    let mut owner = crate::host_state::Owner::acquire(&f.f.config.state, false, SECURE_ID).unwrap();
    owner
        .inspect(ID, f.f.source.next.manifest_sha256())
        .unwrap();
    assert!(owner
        .inspect(ID, f.f.source.current.manifest_sha256())
        .is_err());
    assert!(f
        .f
        .source
        .authority
        .execution()
        .with_admitted(&f.f.source.current, &mut || Ok(()))
        .is_err());
}

#[cfg(unix)]
#[test]
fn update_commit_recovery_reverifies_each_archive_and_active_removal_cutpoint() {
    use std::sync::atomic::AtomicBool;
    for cut in 0..6 {
        let (mut f, _) = publication_fixture();
        let names = [
            "host-update.json",
            "host-update-recovery.json",
            "host-update-selection.json",
        ];
        let value: Value =
            serde_json::from_slice(&fs::read(f.f.config.state.join(names[0])).unwrap()).unwrap();
        let operation = value["operationId"].as_str().unwrap();
        for (index, (name, kind)) in names
            .iter()
            .zip(["consumption", "recovery", "selection"])
            .enumerate()
        {
            if index < cut {
                fs::copy(
                    f.f.config.state.join(name),
                    f.f.config
                        .state
                        .join(format!("host-update-history-{operation}-{kind}.json")),
                )
                .unwrap();
            }
        }
        if cut >= 4 {
            fs::remove_file(f.f.config.state.join(names[2])).unwrap();
        }
        if cut >= 5 {
            fs::remove_file(f.f.config.state.join(names[1])).unwrap();
        }
        assert!(crate::manager_profile::configuration_id(
            &f.destination.state,
            &f.destination.data,
            SECURE_ID
        )
        .is_err());
        let result =
            f.f.source
                .current
                .finalize_update_selection_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(false),
                    &mut f.store,
                )
                .unwrap_or_else(|e| panic!("cut {cut}: {e}"));
        assert_eq!(serde_json::to_value(result).unwrap()["state"], "committed");
        assert_eq!(
            fs::read(f.f.config.state.join("update-verification-started")).unwrap(),
            b"v"
        );
        assert!(!f.f.config.state.join(names[0]).exists());
        assert_eq!(
            fs::read(f.f.config.state.join("database/original")).unwrap(),
            b"untouched original"
        );
    }
}

#[cfg(unix)]
#[test]
fn update_commit_refuses_foreign_or_unsafe_history_without_removing_the_fence() {
    use std::{
        os::unix::fs::{symlink, PermissionsExt},
        sync::atomic::AtomicBool,
    };
    for fault in [
        "consumption",
        "recovery",
        "selection",
        "empty",
        "hardlink",
        "symlink",
        "public",
        "verification",
    ] {
        let (mut f, _) = publication_fixture_with(if fault == "verification" {
            "verification-failed"
        } else {
            "normal"
        });
        let names = [
            "host-update.json",
            "host-update-recovery.json",
            "host-update-selection.json",
        ];
        let before: Vec<_> = names
            .iter()
            .map(|name| fs::read(f.f.config.state.join(name)).unwrap())
            .collect();
        let value: Value = serde_json::from_slice(&before[0]).unwrap();
        let operation = value["operationId"].as_str().unwrap();
        let path = f.f.config.state.join(format!(
            "host-update-history-{operation}-{}.json",
            if ["consumption", "recovery", "selection"].contains(&fault) {
                fault
            } else {
                "selection"
            }
        ));
        if fault != "verification" {
            if fault == "symlink" {
                symlink(f.f.config.state.join(names[2]), &path).unwrap();
            } else {
                fs::write(
                    &path,
                    if fault == "empty" {
                        b"".as_slice()
                    } else {
                        b"foreign".as_slice()
                    },
                )
                .unwrap();
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(if fault == "public" { 0o644 } else { 0o600 }),
                )
                .unwrap();
                if fault == "hardlink" {
                    fs::hard_link(&path, f.f.config.state.join("foreign-history-link")).unwrap();
                }
            }
        }
        assert!(
            f.f.source
                .current
                .finalize_update_selection_test(
                    &f.f.source.next,
                    [&f.f.config, &f.destination],
                    &f.f.source.authority.execution(),
                    &AtomicBool::new(false),
                    &mut f.store
                )
                .is_err(),
            "accepted {fault}"
        );
        for (name, expected) in names.iter().zip(before) {
            assert_eq!(
                fs::read(f.f.config.state.join(name)).unwrap(),
                expected,
                "removed {fault}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn update_commit_final_readiness_failure_retains_fence_and_legacy_exclusion_then_reverifies() {
    use std::{os::unix::fs::PermissionsExt, sync::atomic::AtomicBool};
    let (mut f, _) = publication_fixture();
    f.f.source
        .current
        .verify_update_selection_test(
            &f.f.source.next,
            [&f.f.config, &f.destination],
            &f.f.source.authority.execution(),
            &AtomicBool::new(false),
            &mut f.store,
        )
        .unwrap();
    let names = [
        "host-update.json",
        "host-update-recovery.json",
        "host-update-selection.json",
    ];
    let evidence: Vec<_> = names
        .iter()
        .map(|name| fs::read(f.f.config.state.join(name)).unwrap())
        .collect();
    let capsule: Value = serde_json::from_slice(&evidence[2]).unwrap();
    let selection: crate::host_state::UpdateSelection =
        serde_json::from_value(capsule["intent"]["selection"].clone()).unwrap();
    let lease = f.f.config.state.join("lease.lock");
    fs::write(&lease, []).unwrap();
    fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).unwrap();
    let mut owner = crate::host_state::Owner::acquire_update(&f.f.config.state, SECURE_ID).unwrap();
    let busy = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lease)
        .unwrap();
    busy.try_lock().unwrap();
    assert_eq!(
        owner
            .finalize_update_selection(
                &selection,
                [&evidence[0], &evidence[1], &evidence[2]],
                || panic!("busy legacy host reached commit")
            )
            .unwrap_err(),
        "host_already_owned"
    );
    for (name, bytes) in names.iter().zip(&evidence) {
        assert_eq!(fs::read(f.f.config.state.join(name)).unwrap(), *bytes);
    }
    drop(busy);
    assert_eq!(
        owner
            .finalize_update_selection(
                &selection,
                [&evidence[0], &evidence[1], &evidence[2]],
                || {
                    assert!(f.f.config.state.join(names[0]).exists());
                    assert!(!f.f.config.state.join(names[1]).exists());
                    assert!(!f.f.config.state.join(names[2]).exists());
                    let competing = fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&lease)
                        .unwrap();
                    assert!(
                        competing.try_lock().is_err(),
                        "legacy host was not excluded through final fence boundary"
                    );
                    Err("synthetic_final_readiness_failed".into())
                }
            )
            .unwrap_err(),
        "synthetic_final_readiness_failed"
    );
    drop(owner);
    assert_eq!(
        fs::read(f.f.config.state.join(names[0])).unwrap(),
        evidence[0]
    );
    let result =
        f.f.source
            .current
            .finalize_update_selection_test(
                &f.f.source.next,
                [&f.f.config, &f.destination],
                &f.f.source.authority.execution(),
                &AtomicBool::new(false),
                &mut f.store,
            )
            .unwrap();
    assert_eq!(serde_json::to_value(result).unwrap()["state"], "committed");
    assert_eq!(
        fs::read(f.f.config.state.join("update-verification-started")).unwrap(),
        b"vv"
    );
}

#[test]
fn update_commit_history_publication_names_reject_paths_aliases_and_unknown_kinds() {
    for kind in ["consumption", "recovery", "selection"] {
        assert!(crate::host_state::valid_update_history_name(&format!(
            "host-update-history-11111111-1111-4111-8111-111111111111-{kind}.json"
        )));
    }
    for name in [
        "../host-update-history-11111111-1111-4111-8111-111111111111-selection.json",
        "host-update-history-11111111-1111-4111-8111-111111111111-selection.json/child",
        "host-update-history-11111111-1111-4111-8111-111111111111-unknown.json",
        "host-update-history-00000000-0000-0000-0000-000000000000-selection.json",
        "host-update-history-🦀-selection.json",
        ".host-profile",
        "host-update-history-11111111111141118111111111111111-selection.json",
    ] {
        assert!(
            !crate::host_state::valid_update_history_name(name),
            "accepted {name}"
        );
    }
}
