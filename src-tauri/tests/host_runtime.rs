use ed25519_dalek::{Signer, SigningKey};
use frameleaf_desktop::host_runtime::VerifiedHostRuntime;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf};
use uuid::Uuid;

struct Fixture(PathBuf, Value, PathBuf);
impl Fixture {
    fn new() -> Self {
        let candidate = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-host-{}", Uuid::new_v4()));
        let root = candidate.join("payload");
        fs::create_dir_all(&root).unwrap();
        let paths = BTreeMap::from([
            ("node", "node"),
            ("server", "server/main.js"),
            ("postgres", "pg/postgres"),
            ("initdb", "pg/initdb"),
            ("pgDump", "pg/pg_dump"),
            ("pgRestore", "pg/pg_restore"),
            ("pgIsready", "pg/pg_isready"),
            ("pgChecksums", "pg/pg_checksums"),
            ("pgCtl", "pg/pg_ctl"),
            ("psql", "pg/psql"),
            ("createdb", "pg/createdb"),
            ("vector", "pg/vector"),
            ("hdr", "media/hdr"),
            ("ffmpeg", "media/ffmpeg"),
            ("ffprobe", "media/ffprobe"),
            ("exiftool", "media/exiftool"),
            ("rawRenderer", "raw/bin/darktable-cli"),
            ("rawDecoder", "raw/bin/dcraw_emu"),
            ("webIndex", "build/www/index.html"),
            ("studio", "studio/worker"),
            ("studioBrowser", "browser/chrome"),
            ("studioBrowserGuard", "studio/guard/studio-browser-guard"),
            ("corePlugin", "build/plugins/core/manifest.json"),
            ("mlManifest", "ml/manifest.json"),
            ("manager", "manager/app/build/main.js"),
            ("managerWebIndex", "manager/app/ui/dist/index.html"),
            ("backupEngine", "backup/restic"),
        ]);
        let mut files = serde_json::Map::new();
        for name in paths.values().copied().chain([
            "backup/LICENSE",
            "backup/component.json",
            "studio/engine-build.json",
            "studio/guard/studio-browser-guard.mjs",
            "studio/tools/bundled-worker-fonts.mjs",
            "studio/tools/render-worker-font-inputs.mjs",
            "studio/runtime/admission-font.json",
            "studio/runtime/admission-font.ttf",
            "build/geodata/geodata-date.txt",
            "build/geodata/cities500.txt",
            "build/geodata/admin1CodesASCII.txt",
            "build/geodata/admin2Codes.txt",
            "build/geodata/countryInfo.txt",
            "build/geodata/ne_10m_admin_0_countries.geojson",
            "build/geodata/landmarks.ndjson.gz",
            "manager/app/release-worker.cjs",
            "manager/app/media-copy.cjs",
            "manager/.github/frameleaf-release.cjs",
            "manager/.github/verify-release-bundle.cjs",
            "manager/cosign.pub",
            "manager/component.json",
            "manager/package.json",
            "manager/LICENSE",
            "manager/node_modules/@nestjs/common/package.json",
            "manager/node_modules/@nestjs/core/package.json",
            "manager/node_modules/@nestjs/platform-express/package.json",
            "manager/node_modules/express/package.json",
            "manager/node_modules/js-yaml/package.json",
            "manager/node_modules/reflect-metadata/package.json",
            "manager/node_modules/rxjs/package.json",
            "manager/node_modules/zod/package.json",
        ]) {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"fixture").unwrap();
            files.insert(
                name.into(),
                json!({"bytes":7,"sha256":format!("{:x}",Sha256::digest(b"fixture"))}),
            );
        }
        let spec = json!({"schemaVersion":1,"protocolVersion":2,"epoch":1,
            "platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,
            "sourceRevision":"a".repeat(40),"nodeVersion":"26.11.1",
            "postgresVersion":"19beta4","vectorVersion":"0.8.7","certified":false,
            "entryPoints":paths,"files":files});
        Self(root, spec, candidate)
    }
    fn verify(&self) -> Result<VerifiedHostRuntime, String> {
        let key = SigningKey::from_bytes(&[42; 32]);
        let raw = serde_json::to_vec(&self.1).unwrap();
        VerifiedHostRuntime::verify(
            &self.0,
            &raw,
            &key.sign(&raw).to_bytes(),
            &[key.verifying_key()],
            1,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.2);
    }
}

#[test]
fn backup_engine_descriptor_comes_from_the_signed_role_and_inventory() {
    let mut fixture = Fixture::new();
    let verified = fixture.verify().unwrap();
    let engine = verified.backup_engine().unwrap();
    assert_eq!(engine.executable, fixture.0.join("backup/restic"));
    assert_eq!(engine.sha256, format!("{:x}", Sha256::digest(b"fixture")));
    assert_eq!(
        serde_json::to_value(&engine).unwrap(),
        json!({"executable":fixture.0.join("backup/restic"),"sha256":engine.sha256})
    );
    fs::write(&engine.executable, b"changed").unwrap();
    assert_eq!(verified.backup_engine().unwrap().sha256, engine.sha256);
    assert_eq!(
        fixture.verify().err().as_deref(),
        Some("runtime_artifact_changed")
    );
    fs::write(&engine.executable, b"fixture").unwrap();
    fs::write(fixture.0.join("backup/alternate"), b"fixture").unwrap();
    fixture.1["entryPoints"]["backupEngine"] = json!("backup/alternate");
    fixture.1["files"]["backup/alternate"] = fixture.1["files"]["backup/restic"].clone();
    assert_eq!(
        fixture
            .verify()
            .unwrap()
            .backup_engine()
            .unwrap()
            .executable,
        fixture.0.join("backup/alternate")
    );
}

#[cfg(unix)]
#[test]
fn owned_checkpoint_transport_matches_receipts_and_cancels_without_a_second_channel_slot() {
    use std::{
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    use zeroize::Zeroizing;
    let operation = "11111111-1111-4111-8111-111111111111";
    for mode in ["normal", "cancel", "wrong-operation"] {
        let mut fixture = Fixture::new();
        let script = r##"#!/bin/sh
exec /usr/bin/python3 -c '
import sys,json
mode="RESPONSE_MODE"
c=json.loads(sys.stdin.readline())
print(json.dumps({"state":"running"}),flush=True)
pending=None
for line in sys.stdin:
 if line=="stop\n":
  if pending is not None: print(json.dumps({"state":"checkpoint-failed","operationId":pending,"code":"host_checkpoint_failed"}),flush=True)
  print(json.dumps({"state":"stopped"}),flush=True)
  break
 request=json.loads(line)
 if request["protocolVersion"]!=1 or request["action"]!="checkpoint": sys.exit(9)
 pending=request["operationId"]
 if mode=="cancel": continue
 operation="22222222-2222-4222-8222-222222222222" if mode=="wrong-operation" else pending
 print(json.dumps({"state":"checkpoint","schemaVersion":1,"operationId":operation,"manifestSha256":c["manifestSha256"],"sourceRevision":c["sourceRevision"],"postgresMajor":"19","databaseFormat":"frameleaf-canonical","dump":{"bytes":27,"sha256":"c"*64}}),flush=True)
 pending=None
'
"##.replace("RESPONSE_MODE", mode);
        fs::write(fixture.0.join("node"), script.as_bytes()).unwrap();
        fs::set_permissions(fixture.0.join("node"), fs::Permissions::from_mode(0o700)).unwrap();
        fixture.1["files"]["node"] = json!({"bytes":script.len(),"sha256":format!("{:x}",Sha256::digest(script.as_bytes()))});
        let runtime = fixture.verify().unwrap();
        let mut child = runtime
            .start(
                &fixture.2.join("state"),
                &Zeroizing::new("synthetic-private-checkpoint-password".into()),
                54321,
                54322,
            )
            .unwrap();
        assert!(child.request_checkpoint(operation).is_err());
        child.wait_ready(Duration::from_secs(10)).unwrap();
        child.request_checkpoint(operation).unwrap();
        assert!(child.request_checkpoint(operation).is_err());
        if mode == "cancel" {
            child.stop().unwrap();
            assert!(!child.is_running().unwrap());
            continue;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let result = loop {
            match child.poll_checkpoint() {
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                result => break result,
            }
        };
        if mode == "wrong-operation" {
            assert_eq!(result.unwrap_err(), "host_checkpoint_protocol_invalid");
        } else {
            let receipt = result
                .unwrap()
                .expect("owned child did not acknowledge checkpoint");
            assert_eq!(receipt["operationId"], operation);
            assert_eq!(receipt["manifestSha256"], runtime.manifest_sha256());
            assert_eq!(receipt["dump"]["bytes"], 27);
            child.stop().unwrap();
        }
    }
}

#[cfg(unix)]
#[test]
fn host_start_refuses_a_linked_database_before_launching_any_process() {
    use zeroize::Zeroizing;
    let fixture = Fixture::new();
    let state = fixture.0.with_extension("state");
    fs::create_dir(&state).unwrap();
    let _cleanup = Fixture(state.clone(), json!(null), state.clone());
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&fixture.0, state.join("database")).unwrap();
    let verified = fixture.verify().unwrap();
    let result = verified.start(
        &state,
        &Zeroizing::new("synthetic-host-password-with-enough-length".into()),
        54321,
        54322,
    );
    assert!(matches!(result, Err(ref code) if code == "runtime_link_forbidden"));
    assert!(!state.join("agent.log").exists());
}

#[test]
fn direct_host_start_cannot_bypass_a_controller_managed_profile() {
    let fixture = Fixture::new();
    let state = fixture.2.join("state");
    fs::create_dir(&state).unwrap();
    fs::write(
        state.join("controller-state.json"),
        b"even a torn marker requires its controller",
    )
    .unwrap();
    let verified = fixture.verify().unwrap();
    assert!(
        matches!(verified.start(&state, &zeroize::Zeroizing::new("synthetic-host-password-with-enough-length".into()), 54321, 54322), Err(code) if code == "host_controller_required")
    );
    assert!(!state.join("agent.log").exists());
}

#[test]
fn host_start_refuses_maintenance_before_creating_private_state() {
    use zeroize::Zeroizing;
    let fixture = Fixture::new();
    let verified = fixture.verify().unwrap();
    fs::write(fixture.2.join(".package-maintenance"), b"").unwrap();
    let state = fixture.2.join("state");
    let result = verified.start(
        &state,
        &Zeroizing::new("synthetic-host-password-with-enough-length".into()),
        54321,
        54322,
    );
    assert!(matches!(result, Err(ref code) if code == "host_package_maintenance"));
    assert!(!state.exists());
    assert!(fixture.verify().is_ok());
}

#[test]
fn host_runtime_requires_signed_complete_source_pinned_components() {
    let mut fixture = Fixture::new();
    assert!(fixture.verify().is_ok());
    let original = fixture.1.clone();
    for (field, value) in [
        ("postgresVersion", json!("16.0")),
        ("vectorVersion", json!("0.8.6")),
        ("nodeVersion", json!("26.0.0")),
        ("certified", json!(true)),
        ("protocolVersion", json!(1)),
        ("epoch", json!(0)),
        ("platform", json!("other")),
        ("sourceRevision", json!("main")),
    ] {
        fixture.1 = original.clone();
        fixture.1[field] = value;
        assert!(fixture.verify().is_err(), "accepted invalid {field}");
    }
    fixture.1 = original.clone();
    fixture.1["entryPoints"]["postgres"] = json!("../outside");
    assert!(fixture.verify().is_err());
    fixture.1 = original.clone();
    fixture.1["entryPoints"]
        .as_object_mut()
        .unwrap()
        .remove("pgRestore");
    assert!(fixture.verify().is_err());
    fixture.1 = original.clone();
    fixture.1["files"]
        .as_object_mut()
        .unwrap()
        .remove("build/geodata/cities500.txt");
    fs::remove_file(fixture.0.join("build/geodata/cities500.txt")).unwrap();
    assert!(fixture.verify().is_err());
}

#[test]
fn host_runtime_rejects_untrusted_tampered_or_extra_payloads_and_rollback() {
    let fixture = Fixture::new();
    let key = SigningKey::from_bytes(&[42; 32]);
    let raw = serde_json::to_vec(&fixture.1).unwrap();
    let sig = key.sign(&raw).to_bytes();
    assert!(VerifiedHostRuntime::verify(&fixture.0, &raw, &sig, &[], 1).is_err());
    assert!(
        frameleaf_desktop::release_policy::verify_host_runtime(&fixture.0, &raw, &sig).is_err()
    );
    assert!(
        VerifiedHostRuntime::verify(&fixture.0, &raw, &sig, &[key.verifying_key()], 2).is_err()
    );
    let mut changed = raw.clone();
    changed.push(b' ');
    assert!(
        VerifiedHostRuntime::verify(&fixture.0, &changed, &sig, &[key.verifying_key()], 1).is_err()
    );
    fs::write(fixture.0.join("extra"), b"extra").unwrap();
    assert!(fixture.verify().is_err());
    fs::remove_file(fixture.0.join("extra")).unwrap();
    fs::write(fixture.0.join("node"), b"changed").unwrap();
    assert!(fixture.verify().is_err());
}

#[cfg(unix)]
#[test]
fn rust_owner_drains_agent_output_and_restarts_without_reinitializing_database() {
    use std::{net::TcpListener, os::unix::fs::PermissionsExt, process::Command, time::Duration};
    use zeroize::Zeroizing;
    let mut fixture = Fixture::new();
    let node = Command::new("node")
        .args(["--print", "process.execPath"])
        .output()
        .unwrap();
    assert!(node.status.success());
    let node_path = PathBuf::from(String::from_utf8(node.stdout).unwrap().trim())
        .canonicalize()
        .unwrap();
    let node = fs::read(&node_path).unwrap();
    let mut put = |name: &str, bytes: &[u8], executable: bool| {
        let path = fixture.0.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
        )
        .unwrap();
        fixture.1["files"][name] =
            json!({"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes))});
    };
    put("node", &node, true);
    // Homebrew Node can load an adjacent libnode; this fixture tests lifecycle, not portable linkage.
    #[cfg(target_os = "macos")]
    if let Ok(entries) = fs::read_dir(node_path.parent().unwrap().parent().unwrap().join("lib")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("libnode.") && name.ends_with(".dylib") {
                put(&name, &fs::read(entry.path()).unwrap(), false);
            }
        }
    }
    put("pg/initdb",b"#!/bin/sh\nmkdir \"$2\" || exit 1\nprintf 19 >\"$2/PG_VERSION\"\necho init >>init-count\n",true);
    put("pg/postgres",b"#!/bin/sh\necho $$ >\"$2/postmaster.pid\"\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n",true);
    put("pg/pg_isready", b"#!/bin/sh\nexit 0\n", true);
    put("pg/createdb", b"#!/bin/sh\ntouch db-created\n", true);
    put(
        "pg/psql",
        b"#!/bin/sh\nif test -f db-created; then echo 1; fi\n",
        true,
    );
    put(
        "pg/pg_ctl",
        b"#!/bin/sh\nkill -TERM \"$(head -n 1 \"$3/postmaster.pid\")\"\n",
        true,
    );
    put(
        "server/main.js",
        br#"const http = require('node:http');
const server=http.createServer((_,res)=>res.end(JSON.stringify({res:'pong'})));
process.send?.('frameleaf:owner-ready:v1');
server.listen(Number(process.env.FRAMELEAF_PORT),'127.0.0.1',()=>{
  console.log('Frameleaf Server is listening on');console.log('Frameleaf Microservices is running');
});
process.on('SIGTERM',()=>server.close(()=>process.exit(0)));
process.on('message',message=>{if(message==='frameleaf:stop')server.close(()=>process.exit(0));});
"#,
        false,
    );
    let state = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("frameleaf-host-state-{}", Uuid::new_v4()));
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let cleanup = Fixture(state.clone(), json!(null), state.clone());
    let verified = fixture.verify().unwrap();
    let password = Zeroizing::new("synthetic-host-password-with-enough-length".to_string());
    for cycle in 0..3 {
        let database = TcpListener::bind("127.0.0.1:0").unwrap();
        let api = TcpListener::bind("127.0.0.1:0").unwrap();
        let database_port = database.local_addr().unwrap().port();
        let api_port = api.local_addr().unwrap().port();
        drop(database);
        drop(api);
        let mut process = verified
            .start(&state, &password, database_port, api_port)
            .unwrap();
        if cycle == 1 {
            let cancelled = std::sync::atomic::AtomicBool::new(true);
            assert_ne!(
                process.wait_ready_or_cancel(Duration::from_secs(15), &cancelled),
                Ok(true)
            );
            assert_ne!(process.is_running(), Ok(true));
            continue;
        }
        if cycle == 2 {
            assert!(process
                .wait_ready_or_cancel(
                    Duration::from_secs(15),
                    &std::sync::atomic::AtomicBool::new(false),
                )
                .unwrap());
        } else {
            process
                .wait_ready(Duration::from_secs(15))
                .unwrap_or_else(|error| {
                    panic!(
                        "{error}: {}",
                        fs::read_to_string(state.join("agent.log")).unwrap_or_default()
                    )
                });
        }
        assert!(process.is_running().unwrap());
        process.stop().unwrap();
        assert!(!process.is_running().unwrap());
    }
    let database = TcpListener::bind("127.0.0.1:0").unwrap();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let dp = database.local_addr().unwrap().port();
    let ap = api.local_addr().unwrap().port();
    drop(database);
    drop(api);
    let mut crashed = verified.start(&state, &password, dp, ap).unwrap();
    crashed.wait_ready(Duration::from_secs(15)).unwrap();
    let pg_pid = fs::read_to_string(state.join("database/postmaster.pid"))
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap();
    assert_eq!(
        unsafe { libc::kill(crashed.process_id() as i32, libc::SIGKILL) },
        0
    );
    assert!(crashed.stop().is_err());
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while unsafe { libc::kill(pg_pid, 0) } == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_ne!(
        unsafe { libc::kill(pg_pid, 0) },
        0,
        "agent crash left its database process alive"
    );
    assert_eq!(
        fs::read_to_string(state.join("init-count")).unwrap(),
        "init\n"
    );
    assert!(!state.join("database-password.tmp").exists());
    assert!(!fs::read_to_string(state.join("host-state.json"))
        .unwrap()
        .contains(password.as_str()));
    drop(cleanup);
}

#[test]
fn host_raw_decoder_must_be_explicit_and_inventory_verified() {
    let mut fixture = Fixture::new();
    let original = fixture.1.clone();
    fixture.1["entryPoints"]
        .as_object_mut()
        .unwrap()
        .remove("rawDecoder");
    assert!(fixture.verify().is_err());
    fixture.1 = original;
    fixture.1["files"]
        .as_object_mut()
        .unwrap()
        .remove("raw/bin/dcraw_emu");
    fs::remove_file(fixture.0.join("raw/bin/dcraw_emu")).unwrap();
    assert!(matches!(fixture.verify(), Err(ref code) if code == "host_component_missing"));
}

#[test]
fn studio_browser_requires_an_explicit_inventory_verified_component() {
    let mut fixture = Fixture::new();
    assert!(fixture.verify().is_ok());
    let original = fixture.1.clone();
    fixture.1["entryPoints"]
        .as_object_mut()
        .unwrap()
        .remove("studioBrowser");
    assert!(fixture.verify().is_err());
    fixture.1 = original.clone();
    fixture.1["entryPoints"]["studioBrowser"] = json!("../chrome");
    assert!(fixture.verify().is_err());
    fixture.1 = original.clone();
    fixture.1["files"]
        .as_object_mut()
        .unwrap()
        .remove("browser/chrome");
    fs::remove_file(fixture.0.join("browser/chrome")).unwrap();
    assert!(matches!(fixture.verify(), Err(ref code) if code == "host_component_missing"));
    fixture.1 = original;
    fs::write(fixture.0.join("browser/chrome"), b"tampered").unwrap();
    assert!(fixture.verify().is_err());
}

#[test]
fn studio_guard_requires_an_explicit_inventory_verified_component() {
    let mut fixture = Fixture::new();
    let original = fixture.1.clone();
    fixture.1["entryPoints"]
        .as_object_mut()
        .unwrap()
        .remove("studioBrowserGuard");
    assert!(fixture.verify().is_err());
    fixture.1 = original.clone();
    fixture.1["entryPoints"]["studioBrowserGuard"] = json!("../guard");
    assert!(fixture.verify().is_err());
    fixture.1 = original.clone();
    fixture.1["files"]
        .as_object_mut()
        .unwrap()
        .remove("studio/guard/studio-browser-guard");
    fs::remove_file(fixture.0.join("studio/guard/studio-browser-guard")).unwrap();
    assert!(matches!(fixture.verify(), Err(ref code) if code == "host_component_missing"));
    fixture.1 = original;
    fs::write(
        fixture.0.join("studio/guard/studio-browser-guard"),
        b"tampered",
    )
    .unwrap();
    assert!(fixture.verify().is_err());
}

#[test]
fn studio_metadata_and_guard_module_require_signed_inventory() {
    for path in [
        "studio/engine-build.json",
        "studio/guard/studio-browser-guard.mjs",
        "studio/tools/bundled-worker-fonts.mjs",
        "studio/tools/render-worker-font-inputs.mjs",
        "studio/runtime/admission-font.json",
        "studio/runtime/admission-font.ttf",
    ] {
        let mut fixture = Fixture::new();
        fixture.1["files"].as_object_mut().unwrap().remove(path);
        assert!(matches!(fixture.verify(), Err(ref code) if code == "host_component_missing"));
    }
}

#[test]
fn host_manifest_bounds_fit_combined_server_and_ml_inventories() {
    let fixture = Fixture::new();
    let key = SigningKey::from_bytes(&[42; 32]);
    let mut raw = serde_json::to_vec(&fixture.1).unwrap();
    // Real server + ML inventories already exceed 10 MiB; JSON whitespace avoids creating 67,000 fixture files.
    raw.resize(11 * 1024 * 1024, b' ');
    assert!(VerifiedHostRuntime::verify(
        &fixture.0,
        &raw,
        &key.sign(&raw).to_bytes(),
        &[key.verifying_key()],
        1,
    )
    .is_ok());
    raw.resize(16 * 1024 * 1024 + 1, b' ');
    assert!(matches!(VerifiedHostRuntime::verify(
        &fixture.0, &raw, &key.sign(&raw).to_bytes(), &[key.verifying_key()], 1,
    ), Err(ref code) if code == "host_signature_invalid"));
}

#[test]
#[ignore = "requires FRAMELEAF_TEST_HOST_CANDIDATE pointing to an assembled component payload"]
fn assembled_host_payload_matches_signed_inventory_contract() {
    let candidate = PathBuf::from(std::env::var("FRAMELEAF_TEST_HOST_CANDIDATE").unwrap());
    assert!(candidate.is_absolute());
    let raw = fs::read(candidate.join("manifest.json")).unwrap();
    // This test authority never enters application release trust or leaves a signature in the pack.
    let key = SigningKey::from_bytes(&[42; 32]);
    let verified = VerifiedHostRuntime::verify(
        &candidate.join("payload"),
        &raw,
        &key.sign(&raw).to_bytes(),
        &[key.verifying_key()],
        2,
    )
    .unwrap();
    assert!(!verified.certified());
}

#[test]
#[ignore = "requires factory-signed FRAMELEAF_TEST_HOST_CANDIDATE and a new FRAMELEAF_TEST_HOST_STATE"]
fn factory_signed_host_starts_and_restarts_through_compiled_authority() {
    use frameleaf_desktop::release_policy;
    use std::{net::TcpListener, time::Duration};
    use zeroize::Zeroizing;
    let candidate = PathBuf::from(std::env::var("FRAMELEAF_TEST_HOST_CANDIDATE").unwrap());
    let state = PathBuf::from(std::env::var("FRAMELEAF_TEST_HOST_STATE").unwrap());
    assert!(candidate.is_absolute() && state.is_absolute() && !state.exists());
    let raw = fs::read(candidate.join("manifest.json")).unwrap();
    let signature: [u8; 64] = fs::read(candidate.join("manifest.sig"))
        .unwrap()
        .try_into()
        .unwrap();
    let host =
        release_policy::verify_host_runtime(&candidate.join("payload"), &raw, &signature).unwrap();
    let listeners = [
        TcpListener::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let database_port = listeners[0].local_addr().unwrap().port();
    let api_port = listeners[1].local_addr().unwrap().port();
    drop(listeners);
    fs::create_dir(&state).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let password = Zeroizing::new(format!("synthetic-{}", Uuid::new_v4()));
    for _ in 0..2 {
        let mut process = host
            .start(&state, &password, database_port, api_port)
            .unwrap();
        process.wait_ready(Duration::from_secs(240)).unwrap();
        #[cfg(unix)]
        let pid = process.process_id();
        process.stop().unwrap();
        #[cfg(unix)]
        {
            let output = std::process::Command::new("/bin/ps")
                .args(["-axo", "pgid=,stat="])
                .output()
                .unwrap();
            assert!(output.status.success());
            for row in String::from_utf8(output.stdout).unwrap().lines() {
                let mut parts = row.split_whitespace();
                let group = parts.next().unwrap().parse::<u32>().unwrap();
                let status = parts.next().unwrap();
                assert!(
                    group != pid || status.starts_with('Z'),
                    "owned process remains after stop"
                );
            }
        }
    }
}

#[test]
#[ignore = "requires factory-signed host, approved model cache and new FRAMELEAF_TEST_HOST_ML_STATE"]
fn factory_host_nested_ml_installs_qualifies_and_predicts() {
    use frameleaf_desktop::{model_catalogue::approved_profile, release_policy};
    use std::{
        net::TcpListener,
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };
    let candidate = PathBuf::from(std::env::var("FRAMELEAF_TEST_HOST_CANDIDATE").unwrap());
    let cache = PathBuf::from(std::env::var("FRAMELEAF_FACTORY_MODEL_CACHE").unwrap());
    let state = PathBuf::from(std::env::var("FRAMELEAF_TEST_HOST_ML_STATE").unwrap());
    assert!(
        candidate.is_absolute() && cache.is_absolute() && state.is_absolute() && !state.exists()
    );
    let raw = fs::read(candidate.join("manifest.json")).unwrap();
    let signature: [u8; 64] = fs::read(candidate.join("manifest.sig"))
        .unwrap()
        .try_into()
        .unwrap();
    let _host =
        release_policy::verify_host_runtime(&candidate.join("payload"), &raw, &signature).unwrap();
    let manifest: Value = serde_json::from_slice(&raw).unwrap();
    let ml_manifest = candidate
        .join("payload")
        .join(manifest["entryPoints"]["mlManifest"].as_str().unwrap());
    let ml = ml_manifest.parent().unwrap();
    let ml_raw = fs::read(&ml_manifest).unwrap();
    let ml_signature: [u8; 64] = fs::read(ml.join("manifest.sig"))
        .unwrap()
        .try_into()
        .unwrap();
    fs::create_dir(&state).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let workspace = state.join("work");
    fs::create_dir(&workspace).unwrap();
    let store = release_policy::open_runtime_store(&state.join("store")).unwrap();
    store
        .install_and_activate(&ml.join("payload"), &ml_raw, &ml_signature)
        .unwrap();
    let installed = store.load_active().unwrap().unwrap();
    assert_eq!(installed.provider(), "CPUExecutionProvider");
    let entries =
        json!({"clip":{"textual":{"modelName":"ViT-B-16-SigLIP-384__webli","options":{}}}});
    let profile = approved_profile(
        "ViT-B-16-SigLIP-384__webli",
        &entries,
        installed.source_revision(),
        installed.provider(),
    )
    .unwrap()
    .unwrap();
    let (spec, fixture) = profile.challenge(&Uuid::new_v4().to_string()).unwrap();
    let reference: Value = serde_json::from_slice(&spec).unwrap();
    let qualified = installed
        .qualify(&cache, &workspace, &spec, &fixture, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(qualified.report()["state"], "ready-cpu");
    assert_eq!(qualified.manifest_sha256(), installed.manifest_sha256());
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let mut sidecar = installed
        .start_qualified_sidecar(&qualified, &cache, &workspace, port)
        .unwrap();
    let scratch = sidecar.working_dir().to_owned();
    drop(installed);
    assert!(
        store
            .install_and_activate(&ml.join("payload"), &ml_raw, &ml_signature)
            .is_err(),
        "active sidecar must hold runtime lease"
    );
    tauri::async_runtime::block_on(async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let base = format!("http://127.0.0.1:{port}");
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            assert!(
                sidecar.is_running().unwrap(),
                "nested ML sidecar exited before readiness"
            );
            if let Ok(response) = client
                .get(format!("{base}/ping"))
                .bearer_auth(sidecar.authorization())
                .send()
                .await
            {
                let ready = response.status().is_success();
                response.bytes().await.unwrap();
                if ready {
                    break;
                }
            }
            assert!(Instant::now() < deadline, "nested ML readiness timeout");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let unauthenticated = client.get(format!("{base}/ping")).send().await.unwrap();
        assert_eq!(unauthenticated.status(), 401);
        unauthenticated.bytes().await.unwrap();
        let refused = client
            .post(format!("{base}/predict"))
            .bearer_auth(sidecar.authorization())
            .form(&[("entries", "{}"), ("text", "unqualified")])
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), 409);
        refused.bytes().await.unwrap();
        let predicted = client
            .post(format!("{base}/predict"))
            .bearer_auth(sidecar.authorization())
            .form(&[
                ("entries", entries.to_string()),
                ("text", String::from_utf8(fixture).unwrap()),
            ])
            .send()
            .await
            .unwrap();
        assert!(predicted.status().is_success());
        let actual: Value = predicted.json().await.unwrap();
        let left: Vec<f64> = serde_json::from_str(actual["clip"].as_str().unwrap()).unwrap();
        let right: Vec<f64> =
            serde_json::from_str(reference["expectedOutput"]["clip"].as_str().unwrap()).unwrap();
        assert_eq!(left.len(), 768);
        assert_eq!(left.len(), right.len());
        for (a, b) in left.iter().zip(right) {
            assert!(a.is_finite() && (a - b).abs() <= 1e-4 + 1e-3 * b.abs());
        }
    });
    sidecar.stop().unwrap();
    assert!(!sidecar.is_running().unwrap());
    drop(sidecar);
    assert!(!scratch.exists());
    store
        .install_and_activate(&ml.join("payload"), &ml_raw, &ml_signature)
        .unwrap();
}

#[test]
fn manager_backend_recovery_ui_and_backup_engine_are_mandatory_signed_host_roles() {
    for role in ["manager", "managerWebIndex", "backupEngine"] {
        let mut fixture = Fixture::new();
        fixture.verify().unwrap();
        fixture.1["entryPoints"]
            .as_object_mut()
            .unwrap()
            .remove(role);
        assert!(fixture.verify().is_err());
    }
}

#[test]
fn signed_but_user_writable_host_cannot_receive_manager_credentials() {
    let fixture = Fixture::new();
    let verified = fixture.verify().unwrap();
    assert!(
        matches!(verified.manager_programs(), Err(ref code) if code == "native_manager_unprotected" || code == "native_manager_protection_unavailable")
    );
}
