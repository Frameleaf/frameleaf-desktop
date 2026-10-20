//! Opt-in real backup and cross-version migration; fixture keys never enter release trust.
use super::*;
use crate::host_epochs::{host_authority::Authority, HostEpochAuthority};
use crate::host_state::Owner;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

struct UpdateAuthority {
    base: Authority,
    recovery: PathBuf,
}
impl HostEpochAuthority for UpdateAuthority {
    fn installation_id(&self) -> Result<String, String> {
        self.base.installation_id()
    }
    fn with_admitted(
        &self,
        id: &str,
        runtime: &VerifiedHostRuntime,
        operation: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.base.with_admitted(id, runtime, operation)
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
            .map_err(|_| "nested fixture authority")?;
        if saved.0 != id || target.epoch() <= source.epoch() {
            return Err("fixture transition identity changed".into());
        }
        saved.1.require_admitted(source)?;
        prepare()?;
        assert!(
            self.recovery.is_file(),
            "target admission requires durable recovery intent"
        );
        saved.1.admit(target)?;
        publish()
    }
}
#[test]
fn fixture_transition_prepares_before_admission_and_retains_floor_on_lost_acknowledgement() {
    use crate::host_epochs::{host_authority::ID, host_fixture::Fixture};
    let source = Fixture::new();
    let mut target = Fixture::new();
    target.1["epoch"] = json!(2);
    let current = source.verify().unwrap();
    let next = target.verify().unwrap();
    let recovery = source.2.join("fixture-recovery");
    let authority = UpdateAuthority {
        base: Authority::admitted(&current),
        recovery: recovery.clone(),
    };
    let result = authority.transition(
        ID,
        [&current, &next],
        &mut || {
            fs::write(&recovery, b"fixture intent").unwrap();
            Ok(())
        },
        &mut || Err("lost acknowledgement".into()),
    );
    assert_eq!(result.err().as_deref(), Some("lost acknowledgement"));
    assert!(authority
        .with_admitted(ID, &current, &mut || Ok(()))
        .is_err());
    authority.with_admitted(ID, &next, &mut || Ok(())).unwrap();
}

fn initialized_profile(
    config: &Configuration,
    candidate: &Path,
    manifest: &str,
) -> crate::manager_profile::update::tests::Store {
    let mut store = crate::manager_profile::update::tests::Store::default();
    crate::manager_profile::update::tests::seed(config, candidate, manifest, &mut store);
    let binding = fs::read_to_string(config.data.join(".host-profile")).unwrap();
    ProfileGuard::acquire(config)
        .unwrap()
        .persist_configuration(config, &binding)
        .unwrap();
    store
}
#[test]
fn fixture_profile_includes_canonical_configuration_before_update() {
    use crate::host_epochs::{host_authority::ID, host_fixture::Fixture};
    let source = Fixture::new();
    let directories = Fixture::new();
    let runtime = source.verify().unwrap();
    let state = directories.2.join("state");
    let data = directories.2.join("manager");
    crate::runtime_store::private_directory(&state).unwrap();
    crate::runtime_store::private_directory(&data).unwrap();
    let config = Configuration {
        installation_id: "aaaaaaaaaaaa".into(),
        secure_installation_id: ID.into(),
        name: "Synthetic".into(),
        release: "frameleaf-v3.0.0-1".into(),
        controller: if cfg!(windows) {
            std::env::current_exe().unwrap()
        } else {
            fs::canonicalize("/bin/echo").unwrap()
        },
        state,
        data,
        origin: "https://127.0.0.1:54328".into(),
        database_port: 54329,
        api_port: 2283,
    };
    let _store = initialized_profile(&config, &source.2, runtime.manifest_sha256());
    assert_eq!(
        crate::manager_profile::configuration_id(&config.state, &config.data, ID)
            .unwrap()
            .as_deref(),
        Some(config.installation_id.as_str())
    );
    let authority = Authority::admitted(&runtime);
    let execution = authority.execution();
    assert_eq!(
        crate::host_setup::require_admitted_profile(
            &runtime,
            &execution,
            &config.state,
            &config.data,
            ID
        )
        .unwrap(),
        config.installation_id
    );
    let empty = Authority(std::sync::Mutex::new((
        ID.into(),
        crate::host_epochs::HostEpochs::default(),
    )));
    assert!(crate::host_setup::require_admitted_profile(
        &runtime,
        &empty.execution(),
        &config.state,
        &config.data,
        ID
    )
    .is_err());
    fs::remove_file(config.data.join(".host-configuration.json")).unwrap();
    assert!(crate::host_setup::require_admitted_profile(
        &runtime,
        &execution,
        &config.state,
        &config.data,
        ID
    )
    .is_err());
    assert!(!config.data.join(".host-configuration.json").exists());
}

fn runtime(pack: &Path) -> VerifiedHostRuntime {
    let raw = fs::read(pack.join("manifest.json")).unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    VerifiedHostRuntime::verify(
        &pack.join("payload"),
        &raw,
        &key.sign(&raw).to_bytes(),
        &[key.verifying_key()],
        2,
    )
    .unwrap()
}
fn helper(node: &Path, config: &Value, mode: &str) -> Value {
    let mut input = config.clone();
    input["mode"] = mode.into();
    let mut command = Command::new(node);
    command
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../tools/seed_host_restore_fixture.mjs"))
        .env_clear();
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&input).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    if !output.status.success() {
        fs::write(
            Path::new(config["root"].as_str().unwrap()).join(format!("helper-{mode}.stderr.log")),
            &output.stderr,
        )
        .unwrap();
    }
    assert!(
        output.status.success(),
        "owned helper mode {mode} failed: {}",
        output.status
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
#[ignore = "requires distinct measured source/target packs, test-only target migration, and a new private root; no OS-store or installed claim"]
fn actual_cross_version_update_preserves_original_and_migrates_selected_database() {
    let source_pack = PathBuf::from(std::env::var_os("FRAMELEAF_TEST_UPDATE_SOURCE").unwrap())
        .canonicalize()
        .unwrap();
    let target_pack = PathBuf::from(std::env::var_os("FRAMELEAF_TEST_UPDATE_TARGET").unwrap())
        .canonicalize()
        .unwrap();
    let root = PathBuf::from(std::env::var_os("FRAMELEAF_TEST_UPDATE_ROOT").unwrap());
    assert!(
        root.is_absolute() && !root.exists(),
        "never adopt an existing profile"
    );
    crate::runtime_store::private_directory(&root).unwrap();
    let current = runtime(&source_pack);
    let next = runtime(&target_pack);
    assert!(next.epoch() > current.epoch());
    eprintln!("qualification: both runtime inventories verified");
    let authority = UpdateAuthority {
        base: Authority::admitted(&current),
        recovery: root.join("profile/host-update-recovery.json"),
    };
    let execution = HostExecution::new(&authority, crate::host_epochs::host_authority::ID).unwrap();
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let ports = (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    );
    drop((a, b));
    let state = root.join("profile");
    let data = root.join("manager");
    crate::runtime_store::private_directory(&state).unwrap();
    crate::runtime_store::private_directory(&data).unwrap();
    let config = Configuration {
        installation_id: "aaaaaaaaaaaa".into(),
        secure_installation_id: crate::host_epochs::host_authority::ID.into(),
        name: "Synthetic controller qualification".into(),
        release: "frameleaf-v3.0.0-1".into(),
        controller: if cfg!(windows) {
            std::env::current_exe().unwrap()
        } else {
            fs::canonicalize("/bin/echo").unwrap()
        },
        state: state.clone(),
        data,
        origin: "https://127.0.0.1:54328".into(),
        database_port: ports.0,
        api_port: ports.1,
    };
    let destination = Configuration {
        installation_id: config.installation_id.clone(),
        secure_installation_id: config.secure_installation_id.clone(),
        name: config.name.clone(),
        release: "frameleaf-v3.0.0-2".into(),
        controller: config.controller.clone(),
        state: config.state.clone(),
        data: config.data.clone(),
        origin: config.origin.clone(),
        database_port: ports.0,
        api_port: ports.1,
    };
    let mut owner = Owner::acquire(&state, true, &config.secure_installation_id).unwrap();
    owner
        .activate(
            &config.installation_id,
            current.manifest_sha256(),
            HostMode::Server,
        )
        .unwrap();
    let manifest: Value =
        serde_json::from_slice(&fs::read(source_pack.join("manifest.json")).unwrap()).unwrap();
    let mut input = json!({"root":root,"state":state,"manager":target_pack.join("payload/manager/app/build"),
        "secureInstallationId":config.secure_installation_id,"runtime":source_pack.join("payload"),
        "password":"synthetic existing database password","manifestSha256":current.manifest_sha256(),
        "sourceRevision":current.source_revision(),"postgresMajor":"19","databasePort":ports.0,"apiPort":ports.1,"entryPoints":manifest["entryPoints"],
        "update":{"backupKey":"k".repeat(43),"targetManifestSha256":next.manifest_sha256()}});
    let node = source_pack
        .join("payload")
        .join(manifest["entryPoints"]["node"].as_str().unwrap());
    let backup = helper(&node, &input, "seed-update");
    eprintln!("qualification: real encrypted backup complete");
    owner.clean_stop().unwrap();
    drop(owner);
    let mut store = initialized_profile(&config, &source_pack, current.manifest_sha256());
    current
        .prepare_update_qualification(&next, [&config, &destination], &execution, &mut store)
        .unwrap();
    eprintln!("qualification: reservation and target credentials prepared");
    input["update"]["backupOperationId"] = backup["backupOperationId"].clone();
    let approval = helper(&node, &input, "approve-update");
    let token = Zeroizing::new(approval["approval"].as_str().unwrap().to_owned());
    current
        .consume_update_approval_with(
            &next,
            [&config, &destination],
            &execution,
            Some(&token),
            clock,
            &mut store,
        )
        .unwrap();
    eprintln!("qualification: Manager approval consumed");
    let cancel = AtomicBool::new(false);
    current
        .begin_update_handover_with(
            &next,
            [&config, &destination],
            &execution,
            &cancel,
            &mut store,
        )
        .unwrap();
    assert!(authority
        .with_admitted(&config.secure_installation_id, &current, &mut || Ok(()))
        .is_err());
    eprintln!("qualification: target admitted and source epoch fenced");
    let deadline = Instant::now() + Duration::from_secs(7200);
    let selected = current
        .select_candidate_with(
            &next,
            [&config, &destination],
            &execution,
            (&cancel, deadline),
            &mut store,
            |payload, key, file| {
                next.stage_update_backup_held(&config, payload, key, &cancel, deadline, file)
            },
        )
        .unwrap();
    assert_eq!(selected.state, "selected-pending-publication");
    eprintln!("qualification: migrated target selected with writer fence");
    {
        let mut owner = Owner::acquire_update(&state, &config.secure_installation_id).unwrap();
        assert!(owner
            .activate(
                &config.installation_id,
                next.manifest_sha256(),
                HostMode::Server
            )
            .is_err());
    }
    for (label, step) in [
        ("publish", SelectionStep::Publish),
        ("verify", SelectionStep::Verify),
        ("finalize", SelectionStep::Finalize),
    ] {
        eprintln!("qualification: starting {label}");
        current
            .resume_selection_with(
                &next,
                [&config, &destination],
                &execution,
                (&cancel, Instant::now() + Duration::from_secs(7200)),
                &mut store,
                step,
            )
            .unwrap();
    }
    assert!(!state.join("host-update.json").exists());
    assert_eq!(
        crate::host_setup::require_admitted_profile(
            &next,
            &execution,
            &state,
            &config.data,
            &config.secure_installation_id
        )
        .unwrap(),
        config.installation_id
    );
    assert!(authority
        .with_admitted(&config.secure_installation_id, &current, &mut || Ok(()))
        .is_err());
    eprintln!("qualification: committed target passes the app's lost-acknowledgement reopen guard");
    let password = Zeroizing::new("synthetic existing database password".to_owned());
    let mut owner = Owner::acquire(&state, true, &config.secure_installation_id).unwrap();
    owner
        .activate(
            &config.installation_id,
            next.manifest_sha256(),
            HostMode::Server,
        )
        .unwrap();
    let mut running = next
        .start_mode(
            &state,
            &password,
            ports,
            HostMode::Server,
            Some(&mut owner),
            &execution,
        )
        .unwrap();
    running.wait_ready(Duration::from_secs(240)).unwrap();
    let target_manifest: Value =
        serde_json::from_slice(&fs::read(target_pack.join("manifest.json")).unwrap()).unwrap();
    let target_node = target_pack
        .join("payload")
        .join(target_manifest["entryPoints"]["node"].as_str().unwrap());
    let mut target_input = input.clone();
    target_input["runtime"] = json!(target_pack.join("payload"));
    target_input["entryPoints"] = target_manifest["entryPoints"].clone();
    let selected = helper(&target_node, &target_input, "selected-update");
    assert_eq!(selected["selectedRows"], true);
    assert_eq!(selected["targetMigration"], true);
    assert_eq!(selected["writeTransaction"], true);
    assert_eq!(selected["photos"]["originalBytes"], true);
    assert_eq!(selected["photos"]["thumbnailBytes"], true);
    assert_eq!(selected["photos"]["newUpload"], true);
    running.stop().unwrap();
    drop(running);
    owner.clean_stop().unwrap();
    drop(owner);
    assert_eq!(
        helper(&target_node, &target_input, "original-update")["originalRows"],
        true
    );
    assert!(!state.join("database/postmaster.pid").exists());
    fs::write(root.join("qualification.json"),serde_json::to_vec_pretty(&json!({"actualPostgres":true,"realEncryptedBackup":true,"managerGeneratedApproval":true,
        "sourceEpoch":current.epoch(),"targetEpoch":next.epoch(),"targetMigration":true,"sourceEpochFenced":true,"selectionWriterFenced":true,
        "completedAcknowledgementGuard":true,"selectedWriterReady":true,"selectedWriteTransaction":true,"originalRowsRetained":true,
        "photoOriginalBytesRetained":true,"photoThumbnailBytesRetained":true,"newPhotoUploadAfterUpdate":true,"installedAcceptance":false})).unwrap()).unwrap();
}
