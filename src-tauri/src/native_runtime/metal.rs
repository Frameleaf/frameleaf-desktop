use super::{digest_valid, Manifest, ModuleNamespace};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, ffi::OsString, path::Path};

#[cfg(test)]
mod grouped;
#[cfg(test)]
mod sealed;

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
    let invalid = || String::from("runtime_device_execution_invalid");
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
        assert!(super::super::validate_report(
            &report,
            &spec,
            &"f".repeat(64),
            Some(&"a".repeat(64))
        )
        .is_ok());
        assert!(super::super::validate_report(&report, &spec, &"f".repeat(64), None).is_err());
        assert!(super::super::validate_report(
            &report,
            &spec,
            &"f".repeat(64),
            Some(&"9".repeat(64))
        )
        .is_err());
        for pointer in [
            "/deviceExecution/models/0/sha256",
            "/deviceExecution/facts/collectorSha256",
            "/runtime/deviceEvidence/osBuild",
            "/state",
            "/execution/0/state",
        ] {
            let mut changed = report.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("changed");
            assert!(
                super::super::validate_report(
                    &changed,
                    &spec,
                    &"f".repeat(64),
                    Some(&"a".repeat(64))
                )
                .is_err(),
                "{pointer}"
            );
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
            assert!(
                super::super::validate_report(
                    &changed,
                    &spec,
                    &"f".repeat(64),
                    Some(&"a".repeat(64))
                )
                .is_err(),
                "{pointer}"
            );
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
}
