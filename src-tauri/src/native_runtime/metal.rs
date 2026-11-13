//! The CoreML device collector the server requires (`desktop-runtime-attestation.ts`): a fixed
//! private package named by the signed manifest, never a module the pack or a server selects.
use super::{digest_valid, Manifest, ModuleNamespace};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, ffi::OsString, path::Path};

pub(super) const PACKAGE: &str = "private/frameleaf_desktop_ml";
pub(super) const FILES: [&str; 5] = [
    "__init__.py",
    "entry.py",
    "metal_observer.py",
    "metal_inference.py",
    "_frameleaf_coreml_observer.dylib",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Descriptor {
    kind: String,
}

pub(super) fn validate(manifest: &Manifest) -> Result<(), String> {
    let Some(descriptor) = &manifest.device_observer else {
        return Ok(());
    };
    if descriptor.kind != "metal-v1"
        || manifest.provider != "CoreMLExecutionProvider"
        || manifest.platform != "macos"
        || manifest.architecture != "aarch64"
        || !matches!(manifest.module_namespace, ModuleNamespace::Frameleaf)
        || FILES.iter().any(|name| {
            manifest
                .files
                .get(&format!("{PACKAGE}/{name}"))
                .is_none_or(|file| {
                    !digest_valid(&file.sha256, 64)
                        || file.bytes == 0
                        || file.bytes > 4 * 1024 * 1024
                })
        })
    {
        return Err("runtime_device_observer_invalid".into());
    }
    Ok(())
}

pub(super) fn arguments(
    manifest: &Manifest,
    root: &Path,
    mode: &str,
) -> Result<Vec<OsString>, String> {
    validate(manifest)?;
    if manifest.device_observer.is_none() {
        return Ok(vec![format!(
            "{}.{mode}",
            manifest.module_namespace.prefix()
        )
        .into()]);
    }
    if !matches!(mode, "native_runtime" | "native_qualification") {
        return Err("runtime_device_entrypoint_invalid".into());
    }
    let library = manifest
        .files
        .get(&format!("{PACKAGE}/_frameleaf_coreml_observer.dylib"))
        .ok_or("runtime_device_observer_invalid")?;
    Ok(vec![
        "frameleaf-desktop-metal-v1".into(),
        root.join("private").into_os_string(),
        library.sha256.clone().into(),
        mode.into(),
    ])
}

pub(super) fn collector_hash(manifest: &Manifest) -> Option<&str> {
    manifest.device_observer.as_ref()?;
    manifest
        .files
        .get(&format!("{PACKAGE}/_frameleaf_coreml_observer.dylib"))
        .map(|file| file.sha256.as_str())
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Device {
    name: String,
    identity_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Facts {
    abi_version: u32,
    collector_sha256: String,
    os_build: String,
    devices: Vec<Device>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelProof {
    sha256: String,
    calls: u64,
    compute_buffers: u64,
    compute_dispatches: u64,
    gpu_nanoseconds: f64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proof {
    provider: String,
    facts: Facts,
    models: Vec<ModelProof>,
}

pub(super) fn validate_report(
    report: &serde_json::Value,
    spec: &serde_json::Value,
    expected_collector: &str,
) -> Result<(), String> {
    // The same code as every other refused report: the worker falls back on it.
    let invalid = || String::from("runtime_qualification_report_invalid");
    let proof: Proof =
        serde_json::from_value(report["deviceExecution"].clone()).map_err(|_| invalid())?;
    if proof.provider != "CoreMLExecutionProvider"
        || proof.facts.abi_version != 1
        || proof.facts.collector_sha256 != expected_collector
        || !digest_valid(expected_collector, 64)
        || proof.facts.os_build.is_empty()
        || proof.facts.os_build.chars().count() > 256
        || !(1..=16).contains(&proof.facts.devices.len())
        || !(1..=64).contains(&proof.models.len())
        || report["runtime"]["system"] != "Darwin"
        || !matches!(
            report["runtime"]["architecture"].as_str(),
            Some("arm64" | "aarch64")
        )
        || report["runtime"]["deviceEvidence"]
            != serde_json::to_value(&proof.facts).map_err(|_| invalid())?
        || serde_json::to_vec(&proof.facts)
            .map_err(|_| invalid())?
            .len()
            > 16384
    {
        return Err(invalid());
    }
    let mut identities = BTreeSet::new();
    for device in &proof.facts.devices {
        if device.name.is_empty()
            || device.name.chars().count() > 256
            || !digest_valid(&device.identity_sha256, 64)
            || !identities.insert(&device.identity_sha256)
        {
            return Err(invalid());
        }
    }
    let models = spec["models"]
        .as_array()
        .filter(|models| (1..=64).contains(&models.len()))
        .ok_or_else(invalid)?;
    let mut expected = BTreeSet::new();
    for model in models {
        let kind = model["type"]
            .as_str()
            .filter(|kind| matches!(*kind, "textual" | "visual" | "detection" | "recognition"))
            .ok_or_else(invalid)?;
        let digest = model["artifacts"][format!("{kind}/model.onnx")]
            .as_str()
            .filter(|hash| digest_valid(hash, 64))
            .ok_or_else(invalid)?;
        expected.insert(digest.to_owned());
    }
    let mut observed = BTreeSet::new();
    for model in proof.models {
        if !digest_valid(&model.sha256, 64)
            || !observed.insert(model.sha256)
            || model.calls < 2
            || model.calls > model.compute_buffers
            || model.compute_buffers > model.compute_dispatches
            || model.compute_dispatches >= 1 << 63
            || !model.gpu_nanoseconds.is_finite()
            || model.gpu_nanoseconds <= 0.0
            || model.gpu_nanoseconds > 600_000_000_000.0 * model.calls as f64
        {
            return Err(invalid());
        }
    }
    if observed != expected {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const COREML: &str = "CoreMLExecutionProvider";

    fn proof() -> (serde_json::Value, serde_json::Value) {
        let facts = json!({"abiVersion":1,"collectorSha256":"a".repeat(64),"osBuild":"Version 27.2 (Build fixture)","devices":[{"name":"GPU","identitySha256":"b".repeat(64)}]});
        let report = json!({"protocolVersion":1,"modelKey":"fixture","provider":"CoreMLExecutionProvider","preprocessingSha256":"d".repeat(64),"fixtureSha256":"e".repeat(64),"bindingSha256":"f".repeat(64),"runtimeFingerprint":"1".repeat(64),"reason":null,"state":"ready-mixed","coldMilliseconds":100.0,"warmMilliseconds":5.0,
            "runtime":{"system":"Darwin","architecture":"arm64","deviceEvidence":facts},
            "deviceExecution":{"provider":"CoreMLExecutionProvider","facts":facts,"models":[{"sha256":"c".repeat(64),"calls":2,"computeBuffers":12,"computeDispatches":518,"gpuNanoseconds":1000.0}]},
            "execution":[{"reason":null,"state":"ready-mixed","nodes":{"CoreMLExecutionProvider":2}}]});
        let spec = json!({"modelKey":"fixture","provider":"CoreMLExecutionProvider","preprocessingSha256":"d".repeat(64),"fixtureSha256":"e".repeat(64),"models":[{"type":"textual","artifacts":{"textual/model.onnx":"c".repeat(64)}}]});
        (report, spec)
    }

    #[test]
    fn coreml_report_requires_signed_collector_and_complete_model_device_proof() {
        let (report, spec) = proof();
        let check = |report: &serde_json::Value, collector: Option<&str>| {
            super::super::validate_report(report, &spec, &"f".repeat(64), COREML, collector, None)
        };
        assert!(check(&report, Some(&"a".repeat(64))).is_ok());
        assert!(check(&report, None).is_err());
        assert!(check(&report, Some(&"9".repeat(64))).is_err());
        for pointer in [
            "/deviceExecution/models/0/sha256",
            "/deviceExecution/facts/collectorSha256",
            "/runtime/deviceEvidence/osBuild",
            "/state",
            "/execution/0/state",
        ] {
            let mut changed = report.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("changed");
            assert!(check(&changed, Some(&"a".repeat(64))).is_err(), "{pointer}");
        }
        for (pointer, value) in [
            ("/deviceExecution/models/0/calls", json!(true)),
            ("/deviceExecution/models/0/calls", json!(1)),
            ("/deviceExecution/models/0/computeBuffers", json!(0)),
            ("/deviceExecution/models/0/gpuNanoseconds", json!(0.0)),
            ("/deviceExecution/facts/devices", json!([])),
            ("/execution/0/nodes", json!({"CPUExecutionProvider":2})),
        ] {
            let mut changed = report.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(check(&changed, Some(&"a".repeat(64))).is_err(), "{pointer}");
        }
    }

    fn manifest() -> Manifest {
        let files: serde_json::Map<String, serde_json::Value> = FILES
            .iter()
            .map(|name| {
                (
                    format!("{PACKAGE}/{name}"),
                    json!({"sha256":"a".repeat(64),"bytes":10}),
                )
            })
            .collect();
        serde_json::from_value(json!({"schemaVersion":1,"protocolVersion":1,"epoch":1,
            "platform":"macos","architecture":"aarch64","provider":"CoreMLExecutionProvider",
            "python":"python","sourceRevision":"b".repeat(40),"moduleNamespace":"frameleaf_ml",
            "deviceObserver":{"kind":"metal-v1"},"files":files}))
        .unwrap()
    }

    #[test]
    fn descriptor_cannot_select_another_platform_namespace_kind_or_missing_file() {
        let valid = manifest();
        assert!(validate(&valid).is_ok());
        for field in [
            "platform",
            "architecture",
            "provider",
            "kind",
            "namespace",
            "file",
        ] {
            let mut changed = manifest();
            match field {
                "platform" => changed.platform = "linux".into(),
                "architecture" => changed.architecture = "x86_64".into(),
                "provider" => changed.provider = "CPUExecutionProvider".into(),
                "kind" => {
                    changed.device_observer.as_mut().unwrap().kind = "arbitrary-module".into()
                }
                "namespace" => changed.module_namespace = ModuleNamespace::Immich,
                "file" => {
                    changed.files.remove(&format!("{PACKAGE}/entry.py"));
                }
                _ => unreachable!(),
            }
            assert_eq!(
                validate(&changed).unwrap_err(),
                "runtime_device_observer_invalid",
                "{field}"
            );
        }
        assert!(
            serde_json::from_value::<Descriptor>(json!({"kind":"metal-v1","module":"os"})).is_err()
        );
    }

    #[test]
    fn entrypoint_and_expected_hash_come_only_from_fixed_signed_inventory() {
        let manifest = manifest();
        let args = arguments(
            &manifest,
            Path::new("/owned/runtime"),
            "native_qualification",
        )
        .unwrap();
        assert_eq!(
            args,
            vec![
                OsString::from("frameleaf-desktop-metal-v1"),
                Path::new("/owned/runtime").join("private").into_os_string(),
                OsString::from("a".repeat(64)),
                OsString::from("native_qualification")
            ]
        );
        assert!(arguments(&manifest, Path::new("/owned/runtime"), "os").is_err());
    }

    #[test]
    fn signed_descriptor_binds_every_private_entrypoint_byte() {
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};
        use std::fs;
        // The manifest is checked against this computer, so only Apple Silicon can admit it.
        let admitted = cfg!(all(target_os = "macos", target_arch = "aarch64"));
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-metal-manifest-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let mut files = serde_json::Map::new();
        for name in std::iter::once("python".to_string())
            .chain(FILES.iter().map(|name| format!("{PACKAGE}/{name}")))
        {
            let path = root.join(&name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"owned fixture").unwrap();
            files.insert(
                name,
                json!({"sha256":format!("{:x}",Sha256::digest(b"owned fixture")),"bytes":13}),
            );
        }
        let manifest = json!({"schemaVersion":1,"protocolVersion":1,"epoch":1,
            "platform":"macos","architecture":"aarch64","provider":COREML,"python":"python",
            "sourceRevision":"a".repeat(40),"moduleNamespace":"frameleaf_ml",
            "deviceObserver":{"kind":"metal-v1"},"files":files});
        let raw = serde_json::to_vec(&manifest).unwrap();
        let key = SigningKey::from_bytes(&[71; 32]);
        let verify = || {
            super::super::VerifiedRuntime::verify(
                &root,
                &raw,
                &key.sign(&raw).to_bytes(),
                &[key.verifying_key()],
                1,
            )
        };
        assert_eq!(verify().is_ok(), admitted);
        fs::write(root.join(PACKAGE).join("entry.py"), b"changed bytes").unwrap();
        assert!(verify().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn python_gate_selects_the_fixed_private_entrypoint_with_the_signed_hash() {
        use std::{
            fs,
            io::{Read, Write},
            process::{Command, Stdio},
        };
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-metal-gate-{}", uuid::Uuid::new_v4()));
        let package = root.join("frameleaf_desktop_ml");
        fs::create_dir_all(&package).unwrap();
        fs::write(package.join("__init__.py"), b"").unwrap();
        fs::write(
            package.join("entry.py"),
            "import sys\ndef run(mode,expected):\n assert mode=='native_qualification'\n assert expected=='a'*64\n assert sys.argv==[mode,'--owned-fixture']\n",
        )
        .unwrap();
        let mut command = Command::new(if cfg!(windows) { "python" } else { "python3" });
        command
            .args([
                "-I",
                "-B",
                "-c",
                super::super::GATE,
                "frameleaf-desktop-metal-v1",
            ])
            .arg(&root)
            .arg("a".repeat(64))
            .args(["native_qualification", "--owned-fixture"])
            .env("PYTHONPATH", root.join("untrusted-ambient-path"))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        crate::process_tree::configure(&mut command);
        let mut child = command.spawn().unwrap();
        let tree = crate::process_tree::ProcessTree::attach(&child).unwrap();
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(super::super::START).unwrap();
        let status = child.wait().unwrap();
        drop(pipe);
        tree.terminate();
        let mut errors = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .take(4096)
            .read_to_string(&mut errors)
            .unwrap();
        fs::remove_dir_all(root).unwrap();
        assert!(status.success(), "fixed entrypoint failed: {errors}");
    }
}

/// A real qualification of a locally built pack (`tools/build_runtime.py --profile coreml-ort`),
/// signed here with a throwaway key: the release trust policy is not involved and not weakened.
///
/// `FRAMELEAF_TEST_ACCELERATED_PACK` names the pack, `FRAMELEAF_TEST_MODEL_CACHE` an owned
/// directory for the catalogue's models (downloaded and hash-checked as the app does), and
/// `FRAMELEAF_TEST_QUALIFY_MODELS` a comma-separated list of catalogue model names.
/// FD-63: `FRAMELEAF_TEST_QUALIFY_REPORTS`, when set, names an existing directory that receives
/// one JSON file per profile (the provider, model, outcome and the accepted report), so a
/// hardware run keeps the evidence itself rather than a line of text about it.
#[cfg(test)]
mod local_pack {
    use super::super::VerifiedRuntime;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{fs, path::PathBuf, sync::atomic::AtomicBool};

    #[test]
    #[ignore = "needs a locally built accelerated pack; downloads models and runs them on the GPU"]
    fn local_pack_qualifies_each_provider_against_the_catalogue() {
        let variable = |name: &str| PathBuf::from(std::env::var_os(name).expect(name));
        let pack = variable("FRAMELEAF_TEST_ACCELERATED_PACK");
        let models = variable("FRAMELEAF_TEST_MODEL_CACHE");
        let names = std::env::var("FRAMELEAF_TEST_QUALIFY_MODELS").expect("model names");
        let scratch = models.join("scratch");
        fs::create_dir_all(&scratch).unwrap();
        let reports = std::env::var_os("FRAMELEAF_TEST_QUALIFY_REPORTS").map(PathBuf::from);
        let mut index = 0;
        // What the app itself decides before it would try a provider on this computer
        // (`install_from` in provider_selection.rs): no device, or a driver too old for it.
        let probe = crate::provider_selection::Host;
        let app_gate = |provider: &str| {
            if provider == "CPUExecutionProvider" {
                None
            } else if !crate::provider_selection::device_eligible(
                provider,
                std::env::consts::OS,
                std::env::consts::ARCH,
                &probe,
            ) {
                Some("provider_device_ineligible")
            } else if crate::provider_selection::driver_outdated(
                provider,
                std::env::consts::OS,
                &probe,
            ) {
                Some("provider_driver_outdated")
            } else {
                None
            }
        };
        let mut record = |provider: &str,
                          name: &str,
                          kind: &str,
                          failure: Option<&str>,
                          refusal: Option<&str>,
                          report: Option<&serde_json::Value>| {
            if let Some(directory) = &reports {
                index += 1;
                // `refusalReason`: the code a refusing runtime wrote in its report (FD-63), absent
                // when the process ended without one.
                let evidence = serde_json::json!({
                    "provider": provider, "model": name, "fixtureKind": kind,
                    "qualified": failure.is_none(), "failure": failure, "report": report,
                    "refusal": refusal,
                    "refusalReason": refusal.and_then(|why| why.split_whitespace().next()),
                    "appGate": app_gate(provider),
                });
                fs::write(
                    directory.join(format!("qualification-{index:02}.json")),
                    serde_json::to_vec_pretty(&evidence).unwrap(),
                )
                .unwrap();
            }
        };
        let key = SigningKey::from_bytes(&[71; 32]);
        let cancel = AtomicBool::new(false);
        let client = crate::transport::client().unwrap();
        let mut failures = Vec::new();
        for manifest in ["manifest.json", "manifest-accelerated.json"] {
            let raw = fs::read(pack.join(manifest)).unwrap();
            let runtime = VerifiedRuntime::verify(
                &pack.join("payload"),
                &raw,
                &key.sign(&raw).to_bytes(),
                &[key.verifying_key()],
                1,
            )
            .unwrap();
            for name in names.split(',') {
                let profiles = crate::model_catalogue::setup_profiles(
                    name,
                    runtime.source_revision(),
                    runtime.provider(),
                )
                .unwrap();
                assert!(!profiles.is_empty(), "no {name} profile for {manifest}");
                for profile in profiles {
                    let cache = tauri::async_runtime::block_on(profile.prepare_cache(
                        &models,
                        &client,
                        &cancel,
                        true,
                        |_| {},
                    ))
                    .unwrap();
                    let (spec, fixture) = profile
                        .challenge(&uuid::Uuid::new_v4().to_string())
                        .unwrap();
                    let kind = serde_json::from_slice::<serde_json::Value>(&spec).unwrap()
                        ["fixtureKind"]
                        .to_string();
                    let plain = kind.trim_matches('"').to_owned();
                    let mut refused = None;
                    match runtime.qualify_explained(
                        &cache,
                        &scratch,
                        &spec,
                        &fixture,
                        &cancel,
                        &mut refused,
                    ) {
                        Ok(qualified) => {
                            let report = qualified.report();
                            record(runtime.provider(), name, &plain, None, None, Some(report));
                            eprintln!(
                                "QUALIFIED {} {name} {kind} state={} cold={:.0}ms warm={:.1}ms nodes={} device={}",
                                runtime.provider(),
                                report["state"],
                                report["coldMilliseconds"].as_f64().unwrap(),
                                report["warmMilliseconds"].as_f64().unwrap(),
                                report["execution"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .map(|item| item["nodes"].to_string())
                                    .collect::<Vec<_>>()
                                    .join("+"),
                                report["deviceExecution"]["models"],
                            );
                        }
                        Err(code) => {
                            eprintln!("FAILED {} {name} {kind} {code}", runtime.provider());
                            record(
                                runtime.provider(),
                                name,
                                &plain,
                                Some(&code),
                                refused.as_deref(),
                                None,
                            );
                            failures.push(format!("{} {name} {kind} {code}", runtime.provider()));
                        }
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{failures:?}");
    }
}
