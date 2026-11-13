use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::{collections::BTreeSet, net::TcpListener};

const CUDA: &str = "CUDAExecutionProvider";
const OPENVINO: &str = "OpenVINOExecutionProvider";
/// The pack `tools/deliver_runtime.mjs` cut (tools/test_deliver_runtime.mjs keeps it current):
/// CUDA for Windows, signed with the fixture key both test suites derive.
const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/accelerated_pack/fixture");

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(b"frameleaf accelerated pack fixture key").into())
}
fn keys() -> Vec<VerifyingKey> {
    vec![signing_key().verifying_key()]
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
/// A private folder standing in for the worker's data folder.
fn scratch() -> PathBuf {
    let path = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("frameleaf-pack-{}", uuid::Uuid::new_v4()));
    private_directory(&path).unwrap();
    path
}
fn fixture() -> Delivery {
    let raw = fs::read(Path::new(FIXTURE).join("cuda-ort.json")).unwrap();
    let signature: [u8; 64] = fs::read(Path::new(FIXTURE).join("cuda-ort.sig"))
        .unwrap()
        .try_into()
        .unwrap();
    Delivery::verify(&raw, &signature, &keys(), 2, "windows", "x86_64").unwrap()
}
fn place_parts(data: &Path, source: &Path) {
    private_directory(&root(data)).unwrap();
    private_directory(&root(data).join("parts")).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        fs::copy(
            entry.path(),
            root(data).join("parts").join(entry.file_name()),
        )
        .unwrap();
    }
}
fn files_under(directory: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(next).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.insert(
                    path.strip_prefix(directory)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace('\\', "/"),
                );
            }
        }
    }
    found
}

/// A pack cut here, the way the factory tool cuts one, so single details can be made wrong.
struct Built {
    raw: Vec<u8>,
    signature: [u8; 64],
    parts: Vec<(String, Vec<u8>)>,
    files: Vec<(String, Vec<u8>)>,
}
impl Built {
    fn delivery(&self) -> Result<Delivery, String> {
        Delivery::verify(&self.raw, &self.signature, &keys(), 2, "windows", "x86_64")
    }
    fn place(&self, data: &Path) {
        private_directory(&root(data)).unwrap();
        private_directory(&root(data).join("parts")).unwrap();
        for (name, bytes) in &self.parts {
            fs::write(root(data).join("parts").join(name), bytes).unwrap();
        }
    }
}
#[derive(Clone)]
struct Recipe {
    epoch: u64,
    manifest_epoch: u64,
    /// Bytes appended after the last payload file.
    trailing: Vec<u8>,
    /// Sign the pack's runtime manifest with a key the app does not trust.
    stranger: bool,
    /// Change the delivery manifest before it is signed.
    change: fn(&mut serde_json::Value),
}
impl Default for Recipe {
    fn default() -> Self {
        Self {
            epoch: 7,
            manifest_epoch: 7,
            trailing: Vec::new(),
            stranger: false,
            change: |_| {},
        }
    }
}
fn build(recipe: Recipe) -> Built {
    let mut files: Vec<(String, Vec<u8>)> = vec![
        ("python/python.exe".into(), b"interpreter".to_vec()),
        ("Lib/a.py".into(), vec![7; 300]),
        ("Lib/Z.py".into(), vec![9; 41]),
        ("Lib/empty.py".into(), Vec::new()),
        ("lib-b/cudnn.dll".into(), vec![3; 500]),
    ];
    files.sort();
    let listed: serde_json::Map<String, serde_json::Value> = files
        .iter()
        .map(|(name, bytes)| {
            (
                name.clone(),
                serde_json::json!({"bytes": bytes.len(), "sha256": sha(bytes)}),
            )
        })
        .collect();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1, "protocolVersion": 1, "epoch": recipe.manifest_epoch,
        "platform": "windows", "architecture": "x86_64", "provider": CUDA,
        "python": "python/python.exe", "sourceRevision": "c".repeat(40), "files": listed,
    }))
    .unwrap();
    let signer = if recipe.stranger {
        SigningKey::from_bytes(&[5; 32])
    } else {
        signing_key()
    };
    let mut archive = manifest.clone();
    archive.extend_from_slice(&signer.sign(&manifest).to_bytes());
    for (_, bytes) in &files {
        archive.extend_from_slice(bytes);
    }
    archive.extend_from_slice(&recipe.trailing);
    let parts: Vec<(String, Vec<u8>)> = archive
        .chunks(400)
        .enumerate()
        .map(|(index, chunk)| (format!("pack.part{:02}", index + 1), chunk.to_vec()))
        .collect();
    let mut delivery = serde_json::json!({
        "schemaVersion": 1, "profile": "cuda-ort", "platform": "windows",
        "architecture": "x86_64", "provider": CUDA, "epoch": recipe.epoch,
        "manifestSha256": sha(&manifest), "manifestBytes": manifest.len(),
        "bytes": archive.len(),
        "parts": parts.iter().map(|(name, bytes)| serde_json::json!({
            "name": name, "bytes": bytes.len(), "sha256": sha(bytes),
        })).collect::<Vec<_>>(),
    });
    (recipe.change)(&mut delivery);
    let raw = serde_json::to_vec(&delivery).unwrap();
    Built {
        signature: signing_key().sign(&raw).to_bytes(),
        raw,
        parts,
        files,
    }
}

#[derive(Default)]
struct Device(BTreeSet<String>, Option<String>);
impl Probe for Device {
    fn exists(&self, path: &str) -> bool {
        self.0.contains(path)
    }
    fn read(&self, _: &str) -> Option<String> {
        None
    }
    fn list(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn variable(&self, name: &str) -> Option<String> {
        self.1.clone().filter(|_| name == "SystemRoot")
    }
}
fn nvidia() -> Device {
    Device(
        BTreeSet::from(["C:\\Windows\\System32\\nvcuda.dll".to_owned()]),
        Some("C:\\Windows".into()),
    )
}

#[test]
fn the_pack_the_factory_tool_cut_is_rebuilt_from_its_signed_manifests() {
    let data = scratch();
    let delivery = fixture();
    assert_eq!(delivery.provider(), CUDA);
    assert!(delivery.0.parts.len() > 2);
    place_parts(&data, &Path::new(FIXTURE).join("parts"));
    let cancel = AtomicBool::new(false);
    unpack(&delivery, &data, &keys(), &cancel).unwrap();
    // The unpacked pack is the one the delivery manifest names, with every file its own signed
    // runtime manifest lists and nothing else.
    assert!(ready_matches(&data, &delivery));
    let raw = fs::read(ready(&data).join(ACCELERATED_MANIFEST)).unwrap();
    let signature: [u8; 64] = fs::read(ready(&data).join(ACCELERATED_SIGNATURE))
        .unwrap()
        .try_into()
        .unwrap();
    assert!(signed(&raw, &signature, &keys()));
    let manifest: PackManifest = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        files_under(&ready(&data).join("payload")),
        manifest.files.keys().cloned().collect()
    );
    for (name, artifact) in &manifest.files {
        let bytes = fs::read(ready(&data).join("payload").join(name)).unwrap();
        assert_eq!(bytes.len() as u64, artifact.bytes, "{name}");
        assert_eq!(sha(&bytes), artifact.sha256, "{name}");
    }
    assert!(manifest.files.values().any(|artifact| artifact.bytes == 0));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |name: &str| {
            fs::metadata(ready(&data).join("payload").join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(&manifest.python), 0o700);
        assert_eq!(mode("Lib/a.py"), 0o600);
    }
    // The parts are gone once the pack is rebuilt, and installing it releases the payload while
    // the signed manifest keeps naming the installed runtime.
    assert!(!root(&data).join("parts").exists());
    installed(&ready(&data));
    assert!(!ready(&data).join("payload").exists());
    assert!(ready_matches(&data, &delivery));
    assert_eq!(status_of(&data, Some(&delivery)).state, "ready");
    let _ = fs::remove_dir_all(data);
}

#[test]
fn a_delivery_manifest_is_trusted_only_with_a_release_signature_for_this_computer() {
    let raw = fs::read(Path::new(FIXTURE).join("cuda-ort.json")).unwrap();
    let signature: [u8; 64] = fs::read(Path::new(FIXTURE).join("cuda-ort.sig"))
        .unwrap()
        .try_into()
        .unwrap();
    let verify = |raw: &[u8], signature: &[u8; 64], keys: &[VerifyingKey], floor, os, arch| {
        Delivery::verify(raw, signature, keys, floor, os, arch).map(|_| ())
    };
    assert_eq!(
        verify(&raw, &signature, &keys(), 7, "windows", "x86_64"),
        Ok(())
    );
    // A signature that is not the release key's, over these bytes.
    let mut wrong = signature;
    wrong[3] ^= 1;
    let stranger = [SigningKey::from_bytes(&[5; 32]).verifying_key()];
    let mut altered = raw.clone();
    let digit = altered.iter().position(|byte| *byte == b'7').unwrap();
    altered[digit] = b'8';
    for (raw, signature, keys) in [
        (&raw, &wrong, &keys()[..]),
        (&raw, &signature, &stranger[..]),
        (&altered, &signature, &keys()[..]),
        (&raw, &signature, &[][..]),
    ] {
        assert_eq!(
            verify(raw, signature, keys, 2, "windows", "x86_64").unwrap_err(),
            "accelerated_pack_signature_invalid"
        );
    }
    // Correctly signed, but for another computer or below the release floor (a rollback).
    for (floor, os, arch) in [
        (2, "linux", "x86_64"),
        (2, "windows", "aarch64"),
        (8, "windows", "x86_64"),
    ] {
        assert_eq!(
            verify(&raw, &signature, &keys(), floor, os, arch).unwrap_err(),
            "accelerated_pack_manifest_invalid",
            "{floor} {os} {arch}"
        );
    }
}

#[test]
fn a_signed_delivery_manifest_with_unusable_contents_is_refused() {
    assert!(build(Recipe::default()).delivery().is_ok());
    let changes: [fn(&mut serde_json::Value); 13] = [
        |value| value["schemaVersion"] = 2.into(),
        |value| value["provider"] = "CPUExecutionProvider".into(),
        |value| value["provider"] = "CoreMLExecutionProvider".into(),
        |value| value["manifestSha256"] = "short".into(),
        |value| value["bytes"] = (value["bytes"].as_u64().unwrap() + 1).into(),
        |value| value["parts"] = serde_json::json!([]),
        |value| value["parts"][0]["name"] = "../escape".into(),
        |value| value["parts"][0]["name"] = "Upper.part01".into(),
        |value| value["parts"][1]["name"] = value["parts"][0]["name"].clone(),
        |value| value["parts"][0]["sha256"] = "zz".into(),
        // GitHub serves no release file of 2 GiB or more.
        |value| {
            value["parts"][0]["bytes"] = (2u64 * 1024 * 1024 * 1024).into();
            value["bytes"] =
                (value["bytes"].as_u64().unwrap() + 2 * 1024 * 1024 * 1024 - 400).into();
        },
        |value| value["unknown"] = true.into(),
        |value| value["manifestBytes"] = 0.into(),
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let built = build(Recipe {
            change,
            ..Recipe::default()
        });
        assert_eq!(
            built.delivery().unwrap_err(),
            "accelerated_pack_manifest_invalid",
            "change {index}"
        );
    }
}

#[test]
fn parts_that_are_wrong_missing_or_truncated_never_become_a_pack() {
    let cancel = AtomicBool::new(false);
    let built = build(Recipe::default());
    let delivery = built.delivery().unwrap();
    let last = built.parts.len() - 1;
    type Damage = fn(&Path, &str);
    let damages: [(Damage, usize); 4] = [
        // One byte of a part differs from the digest the signed manifest gives it.
        (
            |parts, name| {
                let mut bytes = fs::read(parts.join(name)).unwrap();
                bytes[17] ^= 1;
                fs::write(parts.join(name), bytes).unwrap();
            },
            1,
        ),
        (|parts, name| fs::remove_file(parts.join(name)).unwrap(), 2),
        (
            |parts, name| {
                let bytes = fs::read(parts.join(name)).unwrap();
                fs::write(parts.join(name), &bytes[..bytes.len() - 1]).unwrap();
            },
            last,
        ),
        (
            |parts, name| {
                let mut bytes = fs::read(parts.join(name)).unwrap();
                bytes.push(0);
                fs::write(parts.join(name), bytes).unwrap();
            },
            0,
        ),
    ];
    for (damage, index) in damages {
        let data = scratch();
        built.place(&data);
        damage(&root(&data).join("parts"), &built.parts[index].0);
        assert_eq!(
            unpack(&delivery, &data, &keys(), &cancel).unwrap_err(),
            "accelerated_pack_archive_invalid",
            "part {index}"
        );
        // Nothing the worker would install, nothing half-unpacked, and the bad parts are gone
        // so the next download starts clean.
        assert!(!ready(&data).exists());
        assert_eq!(status_of(&data, Some(&delivery)).state, "available");
        assert_eq!(
            fs::read_dir(root(&data)).unwrap().count(),
            0,
            "part {index}"
        );
        let _ = fs::remove_dir_all(data);
    }
    // Undamaged, the same pack unpacks; a cancelled unpack keeps the verified parts.
    let data = scratch();
    built.place(&data);
    assert_eq!(
        unpack(&delivery, &data, &keys(), &AtomicBool::new(true)).unwrap_err(),
        "worker_setup_cancelled"
    );
    assert_eq!(
        fs::read_dir(root(&data).join("parts")).unwrap().count(),
        built.parts.len()
    );
    assert!(!ready(&data).exists());
    unpack(&delivery, &data, &keys(), &cancel).unwrap();
    for (name, bytes) in &built.files {
        assert_eq!(
            &fs::read(ready(&data).join("payload").join(name)).unwrap(),
            bytes
        );
    }
    let _ = fs::remove_dir_all(data);
}

#[test]
fn a_pack_that_disagrees_with_its_delivery_manifest_is_refused() {
    let cancel = AtomicBool::new(false);
    for (label, recipe) in [
        (
            "bytes after the last file",
            Recipe {
                trailing: b"extra".to_vec(),
                ..Recipe::default()
            },
        ),
        (
            "a runtime manifest the release key did not sign",
            Recipe {
                stranger: true,
                ..Recipe::default()
            },
        ),
        (
            "a runtime manifest of another epoch",
            Recipe {
                manifest_epoch: 6,
                ..Recipe::default()
            },
        ),
        (
            "another runtime manifest than the one named",
            Recipe {
                change: |value| value["manifestSha256"] = "0".repeat(64).into(),
                ..Recipe::default()
            },
        ),
    ] {
        let data = scratch();
        let built = build(recipe);
        built.place(&data);
        assert_eq!(
            unpack(&built.delivery().unwrap(), &data, &keys(), &cancel).unwrap_err(),
            "accelerated_pack_archive_invalid",
            "{label}"
        );
        assert!(!ready(&data).exists(), "{label}");
        let _ = fs::remove_dir_all(data);
    }
}

#[test]
fn a_downloaded_pack_is_admitted_only_at_the_processor_runtimes_epoch() {
    // Newer would make the runtime store refuse the processor runtime as a rollback; older is
    // a rollback itself. Either way the processor keeps the work.
    assert_eq!(epoch_admissible(br#"{"epoch":7}"#, 7), Ok(()));
    for (manifest, processor) in [
        (&br#"{"epoch":8}"#[..], 7),
        (br#"{"epoch":6}"#, 7),
        (br#"{"epoch":"7"}"#, 7),
        (br#"{}"#, 7),
        (b"not json", 7),
    ] {
        assert_eq!(
            epoch_admissible(manifest, processor).unwrap_err(),
            "accelerated_pack_epoch_mismatch"
        );
    }
    for code in [
        "accelerated_pack_epoch_mismatch",
        "runtime_epoch_rollback",
        "runtime_epoch_reused",
        "runtime_signature_invalid",
        "runtime_artifact_changed",
        "accelerated_pack_missing",
    ] {
        assert!(install_failure_is_final(code), "{code}");
    }
    // These say nothing about the pack: it stays for the next start.
    for code in [
        "runtime_store_busy",
        "runtime_store_lock_failed",
        "runtime_epoch_credential_missing",
        "provider_device_ineligible",
        "runtime_store_read_failed",
    ] {
        assert!(!install_failure_is_final(code), "{code}");
    }
}

#[test]
fn a_pack_that_could_not_be_installed_is_discarded_with_its_reason() {
    let data = scratch();
    let built = build(Recipe::default());
    let delivery = built.delivery().unwrap();
    built.place(&data);
    unpack(&delivery, &data, &keys(), &AtomicBool::new(false)).unwrap();
    assert_eq!(status_of(&data, Some(&delivery)).state, "ready");
    discard(&data, &ready(&data), "runtime_epoch_rollback");
    assert!(!ready(&data).exists());
    let status = status_of(&data, Some(&delivery));
    assert_eq!(status.state, "failed");
    assert_eq!(status.code.as_deref(), Some("runtime_epoch_rollback"));
    assert_eq!(status.provider.as_deref(), Some(CUDA));
    assert_eq!(status.bytes, delivery.bytes());
    // The reason belongs to that pack: another release's pack is simply available.
    let other = build(Recipe {
        epoch: 8,
        manifest_epoch: 8,
        ..Recipe::default()
    })
    .delivery()
    .unwrap();
    let status = status_of(&data, Some(&other));
    assert_eq!((status.state.as_str(), status.code), ("available", None));
    assert_eq!(status_of(&data, None).state, "none");
    let _ = fs::remove_dir_all(data);
}

#[test]
fn a_pack_is_offered_only_for_a_device_this_computer_has() {
    let bundle = scratch();
    fs::create_dir(bundle.join(DELIVERIES)).unwrap();
    for name in ["cuda-ort.json", "cuda-ort.sig"] {
        fs::copy(
            Path::new(FIXTURE).join(name),
            bundle.join(DELIVERIES).join(name),
        )
        .unwrap();
    }
    let offered = |device: &Device, keys: &[VerifyingKey], os: &str| {
        offer_with(&bundle, keys, 2, os, "x86_64", device).map(|d| d.provider().to_owned())
    };
    assert_eq!(
        offered(&nvidia(), &keys(), "windows").as_deref(),
        Some(CUDA)
    );
    // No NVIDIA driver, another operating system, or a manifest the app's key did not sign.
    assert_eq!(offered(&Device::default(), &keys(), "windows"), None);
    assert_eq!(offered(&nvidia(), &keys(), "linux"), None);
    assert_eq!(offered(&nvidia(), &[], "windows"), None);
    assert_eq!(
        offered(
            &nvidia(),
            &[SigningKey::from_bytes(&[5; 32]).verifying_key()],
            "windows"
        ),
        None
    );
    // An installer that carries its own accelerated runtime has nothing to download.
    fs::write(bundle.join(ACCELERATED_MANIFEST), b"{}").unwrap();
    assert_eq!(offered(&nvidia(), &keys(), "windows"), None);
    fs::remove_file(bundle.join(ACCELERATED_MANIFEST)).unwrap();
    // A delivery manifest without its signature is no offer.
    fs::remove_file(bundle.join(DELIVERIES).join("cuda-ort.sig")).unwrap();
    assert_eq!(offered(&nvidia(), &keys(), "windows"), None);
    let _ = fs::remove_dir_all(bundle);
}

#[test]
fn cuda_is_offered_before_openvino_and_each_only_with_its_own_device() {
    let bundle = scratch();
    fs::create_dir(bundle.join(DELIVERIES)).unwrap();
    for (profile, provider) in [("cuda-ort", CUDA), ("openvino-ort", OPENVINO)] {
        let mut raw =
            serde_json::from_slice::<serde_json::Value>(&build(Recipe::default()).raw).unwrap();
        raw["profile"] = profile.into();
        raw["provider"] = provider.into();
        raw["platform"] = "linux".into();
        let raw = serde_json::to_vec(&raw).unwrap();
        fs::write(
            bundle.join(DELIVERIES).join(format!("{profile}.json")),
            &raw,
        )
        .unwrap();
        fs::write(
            bundle.join(DELIVERIES).join(format!("{profile}.sig")),
            signing_key().sign(&raw).to_bytes(),
        )
        .unwrap();
    }
    struct Linux(bool, bool);
    impl Probe for Linux {
        fn exists(&self, path: &str) -> bool {
            self.0 && path == "/proc/driver/nvidia/version"
        }
        fn read(&self, path: &str) -> Option<String> {
            (self.1 && path == "/sys/class/drm/card0/device/vendor").then(|| "0x8086\n".into())
        }
        fn list(&self, directory: &str) -> Vec<String> {
            if directory == "/sys/class/drm" {
                vec!["card0".into()]
            } else {
                Vec::new()
            }
        }
        fn variable(&self, _: &str) -> Option<String> {
            None
        }
    }
    let offered = |nvidia, intel| {
        offer_with(
            &bundle,
            &keys(),
            2,
            "linux",
            "x86_64",
            &Linux(nvidia, intel),
        )
        .map(|delivery| delivery.provider().to_owned())
    };
    assert_eq!(offered(true, true).as_deref(), Some(CUDA));
    assert_eq!(offered(true, false).as_deref(), Some(CUDA));
    assert_eq!(offered(false, true).as_deref(), Some(OPENVINO));
    assert_eq!(offered(false, false), None);
    let _ = fs::remove_dir_all(bundle);
}

#[test]
fn not_now_only_quiets_the_offer_and_downloads_are_https_only() {
    let data = scratch();
    let delivery = build(Recipe::default()).delivery().unwrap();
    assert!(!status_of(&data, Some(&delivery)).declined);
    private_directory(&root(&data)).unwrap();
    fs::write(root(&data).join("declined"), &delivery.0.manifest_sha256).unwrap();
    let status = status_of(&data, Some(&delivery));
    assert_eq!(
        (status.state.as_str(), status.declined),
        ("available", true)
    );
    // Nothing was fetched or created by declining.
    assert_eq!(fs::read_dir(root(&data)).unwrap().count(), 1);
    let _ = fs::remove_dir_all(data);

    assert!(
        RELEASE.starts_with("https://github.com/Frameleaf/frameleaf-desktop/releases/download/v")
    );
    assert_eq!(
        part_url(RELEASE, "pack.part01").unwrap(),
        format!("{RELEASE}pack.part01")
    );
    for (base, name) in [
        ("http://github.com/Frameleaf/", "pack.part01"),
        ("https://github.com/Frameleaf", "pack.part01"),
        (RELEASE, "../pack.part01"),
        (RELEASE, "pack/part01"),
        (RELEASE, "pack.part01?x=1"),
        (RELEASE, ""),
    ] {
        assert_eq!(
            part_url(base, name).unwrap_err(),
            "accelerated_pack_download_invalid",
            "{base} {name}"
        );
    }
}

#[tokio::test]
async fn the_release_client_refuses_plain_http() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/pack.part01", listener.local_addr().unwrap());
    let error = release_client()
        .unwrap()
        .get(&url)
        .send()
        .await
        .unwrap_err();
    assert!(error.is_builder(), "{error:?}");
}

/// Serve one scripted raw reply per connection, then report the requests received.
fn serve(script: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let task = std::thread::spawn(move || {
        script
            .into_iter()
            .map(|reply| {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut request = [0; 4096];
                let read = stream.read(&mut request).unwrap();
                let _ = stream.write_all(&reply);
                String::from_utf8_lossy(&request[..read]).to_lowercase()
            })
            .collect()
    });
    (url, task)
}
/// A reply that declares `length` body bytes; a shorter `body` drops the connection early.
fn reply(status: &str, headers: &str, length: usize, body: &[u8]) -> Vec<u8> {
    let mut reply = format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {length}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    reply.extend_from_slice(body);
    reply
}
fn urls(base: &str, built: &Built) -> Vec<String> {
    built
        .parts
        .iter()
        .map(|(name, _)| format!("{base}{name}"))
        .collect()
}

#[tokio::test]
async fn an_interrupted_download_resumes_and_the_pack_is_rebuilt() {
    let data = scratch();
    let built = build(Recipe::default());
    let delivery = built.delivery().unwrap();
    let client = crate::transport::client().unwrap();
    let cancel = AtomicBool::new(false);
    let seen = Mutex::new(Vec::new());
    let progress = |received: u64| seen.lock().unwrap().push(received);
    // The connection drops in the middle of the first part and no retry gets through: the
    // download stops with what it received kept.
    let first = &built.parts[0].1;
    let mut script = vec![reply(
        "200 OK",
        "ETag: \"v1\"\r\n",
        first.len(),
        &first[..150],
    )];
    script.extend((0..4).map(|_| reply("503 Service Unavailable", "", 0, b"")));
    let (base, server) = serve(script);
    assert_eq!(
        fetch_parts(
            &delivery,
            &data,
            &client,
            &urls(&base, &built),
            &cancel,
            &progress
        )
        .await
        .unwrap_err(),
        "accelerated_pack_download_interrupted"
    );
    server.join().unwrap();
    assert!(!ready(&data).exists());
    assert_eq!(status_of(&data, Some(&delivery)).state, "available");
    // Asked again, it continues that part from byte 150 and fetches the rest.
    let mut script = vec![reply(
        "206 Partial Content",
        &format!(
            "Content-Range: bytes 150-{}/{}\r\n",
            first.len() - 1,
            first.len()
        ),
        first.len() - 150,
        &first[150..],
    )];
    script.extend(
        built.parts[1..]
            .iter()
            .map(|(_, bytes)| reply("200 OK", "", bytes.len(), bytes)),
    );
    let (base, server) = serve(script);
    fetch_parts(
        &delivery,
        &data,
        &client,
        &urls(&base, &built),
        &cancel,
        &progress,
    )
    .await
    .unwrap();
    let requests = server.join().unwrap();
    assert!(
        requests[0].contains("\r\nrange: bytes=150-\r\n"),
        "{}",
        requests[0]
    );
    assert!(requests[1..]
        .iter()
        .all(|request| !request.contains("range:")));
    assert_eq!(seen.lock().unwrap().last(), Some(&delivery.bytes()));
    // Asked once more with every part already there, nothing is requested at all.
    let nowhere = urls("http://127.0.0.1:9/", &built);
    fetch_parts(&delivery, &data, &client, &nowhere, &cancel, &progress)
        .await
        .unwrap();
    assert_eq!(
        fetch_parts(&delivery, &data, &client, &nowhere[1..], &cancel, &progress)
            .await
            .unwrap_err(),
        "accelerated_pack_download_invalid"
    );
    unpack(&delivery, &data, &keys(), &cancel).unwrap();
    assert_eq!(status_of(&data, Some(&delivery)).state, "ready");
    for (name, bytes) in &built.files {
        assert_eq!(
            &fs::read(ready(&data).join("payload").join(name)).unwrap(),
            bytes
        );
    }
    let _ = fs::remove_dir_all(data);
}

#[tokio::test]
async fn a_part_with_the_wrong_bytes_is_refused_and_nothing_is_installable() {
    let data = scratch();
    let built = build(Recipe::default());
    let delivery = built.delivery().unwrap();
    let client = crate::transport::client().unwrap();
    let cancel = AtomicBool::new(false);
    // The host serves the right number of bytes with the wrong content, twice.
    let wrong = vec![b'x'; built.parts[0].1.len()];
    let (base, server) = serve(vec![
        reply("200 OK", "", wrong.len(), &wrong),
        reply("200 OK", "", wrong.len(), &wrong),
    ]);
    assert_eq!(
        fetch_parts(
            &delivery,
            &data,
            &client,
            &urls(&base, &built),
            &cancel,
            &|_| {}
        )
        .await
        .unwrap_err(),
        "accelerated_pack_download_invalid"
    );
    server.join().unwrap();
    assert!(!ready(&data).exists());
    assert_eq!(fs::read_dir(root(&data).join("parts")).unwrap().count(), 0);
    // A host that answers with something else entirely (a missing release) is refused as well.
    let (base, server) = serve(vec![reply("404 Not Found", "", 0, b"")]);
    assert_eq!(
        fetch_parts(
            &delivery,
            &data,
            &client,
            &urls(&base, &built),
            &cancel,
            &|_| {}
        )
        .await
        .unwrap_err(),
        "accelerated_pack_download_invalid"
    );
    server.join().unwrap();
    // Cancelling keeps the processor too, and is not remembered as a failure.
    let (base, _server) = serve(Vec::new());
    assert_eq!(
        fetch_parts(
            &delivery,
            &data,
            &client,
            &urls(&base, &built),
            &AtomicBool::new(true),
            &|_| {}
        )
        .await
        .unwrap_err(),
        "worker_setup_cancelled"
    );
    assert_eq!(status_of(&data, Some(&delivery)).state, "available");
    let _ = fs::remove_dir_all(data);
}
