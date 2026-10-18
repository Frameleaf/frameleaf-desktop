use frameleaf_desktop::manager_tls::TlsIdentity;
use std::cell::Cell;

#[test]
fn tls_identity_is_persisted_before_use_and_remains_bound_to_installation_and_origin() {
    let saved = Cell::new(false);
    let identity = TlsIdentity::load_or_create(
        "aaaaaaaaaaaa",
        "https://manager.test:9443",
        || Ok(None),
        |_| {
            saved.set(true);
            Ok(())
        },
    )
    .unwrap();
    assert!(saved.get());
    assert!(identity
        .certificate()
        .starts_with("-----BEGIN CERTIFICATE-----"));
    let public = identity.certificate().to_owned();
    let serialized = serde_json::to_string(&identity).unwrap();
    let restored = TlsIdentity::load_or_create(
        "aaaaaaaaaaaa",
        "https://manager.test:9443",
        || Ok(Some(serde_json::from_str(&serialized).unwrap())),
        |_| panic!("existing identity must not be replaced"),
    )
    .unwrap();
    assert!(restored.certificate() == public);
    for (id, origin) in [
        ("bbbbbbbbbbbb", "https://manager.test:9443"),
        ("aaaaaaaaaaaa", "https://other.test:9443"),
    ] {
        assert!(TlsIdentity::load_or_create(
            id,
            origin,
            || Ok(Some(serde_json::from_str(&serialized).unwrap())),
            |_| panic!("identity cannot be silently replaced")
        )
        .is_err());
    }
    let wire = serde_json::to_value(restored.wire()).unwrap();
    assert!(wire["certificatePem"].is_string());
    assert!(wire["privateKeyPem"]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN PRIVATE KEY-----"));
    assert_eq!(wire.as_object().unwrap().len(), 2);
}

#[test]
fn credential_store_failure_never_returns_an_ephemeral_tls_identity() {
    assert!(TlsIdentity::load_or_create(
        "aaaaaaaaaaaa",
        "https://manager.test:9443",
        || Err("credential_store_locked_or_unavailable".into()),
        |_| panic!("must not write after locked read")
    )
    .is_err());
    assert!(TlsIdentity::load_or_create(
        "aaaaaaaaaaaa",
        "https://manager.test:9443",
        || Ok(None),
        |_| Err("credential_store_unavailable".into())
    )
    .is_err());
    for (id, origin) in [
        ("invalid", "https://manager.test:9443"),
        ("aaaaaaaaaaaa", "http://manager.test:9443"),
        ("aaaaaaaaaaaa", "https://manager.test:9443/path"),
        ("aaaaaaaaaaaa", "https://user:secret@manager.test:9443"),
    ] {
        assert!(TlsIdentity::load_or_create(
            id,
            origin,
            || panic!("invalid binding must not access keystore"),
            |_| Ok(())
        )
        .is_err());
    }
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires private Node and compiled Manager; synthetic TLS only, no OS-keystore access"]
async fn native_manager_fresh_tls_uses_private_stdin_with_empty_path() {
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::{BufRead, BufReader, Read, Write},
        path::PathBuf,
        process::{Child, Command, Stdio},
        time::Duration,
    };
    use zeroize::Zeroizing;
    struct Owned(Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let node = PathBuf::from(std::env::var("FRAMELEAF_TEST_NODE").unwrap());
    let manager = PathBuf::from(std::env::var("FRAMELEAF_TEST_MANAGER").unwrap());
    let output = PathBuf::from(std::env::var("FRAMELEAF_TEST_OUTPUT").unwrap());
    assert!(node.is_absolute() && manager.is_absolute() && output.is_absolute());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    drop(listener);
    fs::create_dir(&output).unwrap();
    let origin = origin.as_str();
    let identity =
        TlsIdentity::load_or_create("aaaaaaaaaaaa", origin, || Ok(None), |_| Ok(())).unwrap();
    let other =
        TlsIdentity::load_or_create("bbbbbbbbbbbb", origin, || Ok(None), |_| Ok(())).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
    params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let expired = params.self_signed(&key).unwrap();
    let probes = Zeroizing::new(serde_json::to_vec(&serde_json::json!({"good":identity.wire(),"other":other.wire(),"expired":{"certificatePem":expired.pem(),"privateKeyPem":key.serialize_pem()}})).unwrap());
    let script = "import assert from 'node:assert/strict';import{pathToFileURL}from'node:url';const{validateNativeTls}=await import(pathToFileURL(process.argv[1]+'/build/runtime/native-service.js'));let raw='';for await(const chunk of process.stdin)raw+=chunk;const p=JSON.parse(raw);validateNativeTls(p.good,'https://127.0.0.1:9443');for(const [tls,origin] of [[{...p.good,privateKeyPem:p.other.privateKeyPem},'https://127.0.0.1:9443'],[p.good,'https://other.test:9443'],[p.good,'http://127.0.0.1:9443'],[p.expired,'https://127.0.0.1:9443']])assert.throws(()=>validateNativeTls(tls,origin),/native_tls_invalid/);";
    let mut probe = Owned(
        Command::new(&node)
            .args(["--input-type=module", "--eval", script])
            .arg(&manager)
            .env_clear()
            .env("PATH", "")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    probe.0.stdin.take().unwrap().write_all(&probes).unwrap();
    assert!(
        probe.0.wait().unwrap().success(),
        "native TLS validator rejected valid identity or accepted invalid binding"
    );
    let controller = PathBuf::from("/bin/echo").canonicalize().unwrap();
    let data = output.join("manager");
    let config = Zeroizing::new(serde_json::to_vec(&serde_json::json!({
        "protocolVersion":2,"backupKey":"k".repeat(43),"installation":{"runtime":"native","id":"aaaaaaaaaaaa","controller":controller,"candidate":output.join("runtime"),"state":output.join("state"),"manifestSha256":"b".repeat(64),"sourceRevision":"c".repeat(40),"certified":false,"databasePort":54329,"apiPort":2283},
        "controllerSha256":format!("{:x}",Sha256::digest(fs::read(&controller).unwrap())),"backupEngine":{"executable":controller,"sha256":format!("{:x}",Sha256::digest(fs::read(&controller).unwrap()))},"name":"Synthetic native TLS fixture","release":"frameleaf-v3.0.0-1","password":"synthetic native database password","tls":identity.wire()
    })).unwrap());
    let mut child = Owned(
        Command::new(&node)
            .arg(manager.join("build/main.js"))
            .env_clear()
            .env("PATH", "")
            .env("MANAGER_RUNTIME", "native")
            .env("MANAGER_DATA", &data)
            .env("MANAGER_ORIGIN", origin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (receipt_tx, receipt_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stdout)
            .take(1025)
            .read_until(b'\n', &mut bytes)
            .unwrap();
        let _ = receipt_tx.send(bytes);
    });
    let mut pipe = child.0.stdin.take().unwrap();
    pipe.write_all(&config).unwrap();
    pipe.write_all(b"\n").unwrap();
    drop(pipe);
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(
            reqwest::Certificate::from_pem(identity.certificate().as_bytes()).unwrap(),
        )
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let mut ready = false;
    for _ in 0..100 {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "native Manager exited before HTTPS readiness"
        );
        if let Ok(reply) = client
            .get(format!("{origin}/manager-api/status"))
            .send()
            .await
        {
            assert!(reply.status().is_success());
            assert_eq!(
                reply.json::<serde_json::Value>().await.unwrap()["claimed"],
                false
            );
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "native Manager TLS startup deadline");
    let receipt = receipt_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("owned Manager readiness pipe");
    assert!(receipt.len() <= 1024 && receipt.ends_with(b"\n"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&receipt).unwrap(),
        serde_json::json!({
            "protocolVersion":2,"state":"ready","installationId":"aaaaaaaaaaaa", "manifestSha256":"b".repeat(64),"origin":origin
        })
    );
    // A different child must not claim readiness from the first child's healthy HTTPS listener.
    let mut conflict = Owned(
        Command::new(&node)
            .arg(manager.join("build/main.js"))
            .env_clear()
            .env("PATH", "")
            .env("MANAGER_RUNTIME", "native")
            .env("MANAGER_DATA", output.join("conflict"))
            .env("MANAGER_ORIGIN", origin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut pipe = conflict.0.stdin.take().unwrap();
    pipe.write_all(&config).unwrap();
    pipe.write_all(b"\n").unwrap();
    drop(pipe);
    let mut failed = false;
    for _ in 0..100 {
        if let Some(status) = conflict.0.try_wait().unwrap() {
            assert!(!status.success());
            failed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        failed,
        "listener conflict must fail within the startup deadline"
    );
    let mut conflict_output = Vec::new();
    conflict
        .0
        .stdout
        .take()
        .unwrap()
        .take(1025)
        .read_to_end(&mut conflict_output)
        .unwrap();
    assert!(
        conflict_output.is_empty(),
        "failed child emitted a ready receipt"
    );

    assert!(
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap()
            .get(format!("{origin}/manager-api/status"))
            .send()
            .await
            .is_err(),
        "untrusted certificate must remain refused"
    );
    assert!(!data.join("tls.key").exists() && !data.join("tls.crt").exists());
    for entry in fs::read_dir(&data).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = fs::read(path).unwrap();
            for marker in [
                b"BEGIN PRIVATE KEY".as_slice(),
                b"synthetic native database password".as_slice(),
            ] {
                assert!(
                    !bytes.windows(marker.len()).any(|value| value == marker),
                    "native credential leaked into Manager data"
                );
            }
        }
    }
    // Only an owned unreaped child is signalled; no stored PID or unrelated process is adopted.
    assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGTERM) }, 0);
    let mut stopped = false;
    for _ in 0..100 {
        if let Some(status) = child.0.try_wait().unwrap() {
            use std::os::unix::process::ExitStatusExt;
            assert!(status.success() || status.signal() == Some(libc::SIGTERM));
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(stopped, "owned native Manager did not drain");
}
