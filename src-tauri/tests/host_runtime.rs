use ed25519_dalek::{Signer, SigningKey};
use frameleaf_desktop::host_runtime::VerifiedHostRuntime;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf};
use uuid::Uuid;

struct Fixture(PathBuf, Value);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-host-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
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
            ("rawRenderer", "media/raw"),
            ("webIndex", "build/www/index.html"),
            ("studio", "studio/worker"),
            ("corePlugin", "build/plugins/core/manifest.json"),
            ("mlManifest", "ml/manifest.json"),
        ]);
        let mut files = serde_json::Map::new();
        for name in paths.values().copied().chain([
            "build/geodata/geodata-date.txt",
            "build/geodata/cities500.txt",
            "build/geodata/admin1CodesASCII.txt",
            "build/geodata/admin2Codes.txt",
            "build/geodata/countryInfo.txt",
            "build/geodata/ne_10m_admin_0_countries.geojson",
            "build/geodata/landmarks.ndjson.gz",
        ]) {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"fixture").unwrap();
            files.insert(
                name.into(),
                json!({"bytes":7,"sha256":format!("{:x}",Sha256::digest(b"fixture"))}),
            );
        }
        let spec = json!({"schemaVersion":1,"protocolVersion":1,"epoch":1,
            "platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,
            "sourceRevision":"a".repeat(40),"nodeVersion":"26.11.1",
            "postgresVersion":"19beta4","vectorVersion":"0.8.7","certified":false,
            "entryPoints":paths,"files":files});
        Self(root, spec)
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
        let _ = fs::remove_dir_all(&self.0);
    }
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
        ("protocolVersion", json!(2)),
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
server.listen(Number(process.env.FRAMELEAF_PORT),'127.0.0.1',()=>{
  console.log('Frameleaf Server is listening on');console.log('Frameleaf Microservices is running');
});
process.on('SIGTERM',()=>server.close(()=>process.exit(0)));
"#,
        false,
    );
    let state = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("frameleaf-host-state-{}", Uuid::new_v4()));
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let cleanup = Fixture(state.clone(), json!(null));
    let verified = fixture.verify().unwrap();
    let password = Zeroizing::new("synthetic-host-password-with-enough-length".to_string());
    for _ in 0..2 {
        let database = TcpListener::bind("127.0.0.1:0").unwrap();
        let api = TcpListener::bind("127.0.0.1:0").unwrap();
        let database_port = database.local_addr().unwrap().port();
        let api_port = api.local_addr().unwrap().port();
        drop(database);
        drop(api);
        let mut process = verified
            .start(&state, &password, database_port, api_port)
            .unwrap();
        process
            .wait_ready(Duration::from_secs(15))
            .unwrap_or_else(|error| {
                panic!(
                    "{error}: {}",
                    fs::read_to_string(state.join("agent.log")).unwrap_or_default()
                )
            });
        process.stop().unwrap();
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
