//! Which provider each workload runs on: the accelerated runtime where the app ships one, this
//! computer is eligible and the workload qualified with it; the processor otherwise.
//!
//! The processor runtime is always installed and is never replaced. The accelerated runtime is a
//! second signed manifest over the same pack (`manifest-accelerated.json`), installed in its own
//! store; every fault on that side leaves the processor in charge.
use crate::{
    ml_transport::{AcceptedQualification, WorkerTransport},
    model_catalogue::ApprovedProfile,
    native_predictor::NativePredictor,
    native_runtime::QualifiedRuntime,
    runtime_store::{read_bounded, InstalledRuntime, RuntimeAttestation},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

pub(crate) const CPU: &str = "CPUExecutionProvider";
const ACCELERATED_MANIFEST: &str = "manifest-accelerated.json";
const ACCELERATED_SIGNATURE: &str = "manifest-accelerated.sig";
const ACCELERATED_STORE: &str = "runtimes-accelerated";
const WORKLOADS: [&str; 3] = ["clip", "ocr", "face"];

/// What this computer has. Injected so each operating system's rule is tested on all of them.
pub(crate) trait Probe {
    fn exists(&self, path: &str) -> bool;
    fn read(&self, path: &str) -> Option<String>;
    fn list(&self, directory: &str) -> Vec<String>;
    fn variable(&self, name: &str) -> Option<String>;
}
pub(crate) struct Host;
impl Probe for Host {
    fn exists(&self, path: &str) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }
    fn read(&self, path: &str) -> Option<String> {
        read_bounded(Path::new(path), 4096)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }
    fn list(&self, directory: &str) -> Vec<String> {
        std::fs::read_dir(directory)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .take(256)
            .collect()
    }
    fn variable(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// Whether this computer has the device a provider needs. Only a first gate: qualification is
/// what proves the provider works here, and an absent or unrecognised device means the processor.
pub(crate) fn device_eligible(provider: &str, os: &str, arch: &str, probe: &dyn Probe) -> bool {
    match (provider, os, arch) {
        // Every Apple Silicon Mac has a Metal GPU; the collector proves it did the work.
        ("CoreMLExecutionProvider", "macos", "aarch64") => true,
        // The NVIDIA kernel driver publishes this while it is loaded.
        ("CUDAExecutionProvider", "linux", "x86_64") => probe.exists("/proc/driver/nvidia/version"),
        // The NVIDIA display driver installs its CUDA driver library into System32.
        ("CUDAExecutionProvider", "windows", "x86_64") => probe
            .variable("SystemRoot")
            .is_some_and(|root| probe.exists(&format!("{root}\\System32\\nvcuda.dll"))),
        // An Intel (PCI vendor 0x8086) display adapter.
        ("OpenVINOExecutionProvider", "linux", "x86_64") => {
            probe.list("/sys/class/drm").iter().any(|card| {
                card.strip_prefix("card")
                    .is_some_and(|index| index.bytes().all(|b| b.is_ascii_digit()))
                    && probe
                        .read(&format!("/sys/class/drm/{card}/device/vendor"))
                        .is_some_and(|vendor| vendor.trim() == "0x8086")
            })
        }
        _ => false,
    }
}

/// The provider a workload runs on, and why that is the processor when an accelerated runtime
/// was there to use.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkloadProvider {
    pub workload: String,
    pub provider: String,
    pub fallback: Option<String>,
}

/// The one decision: `accelerated` is the provider of the accelerated runtime usable on this
/// computer (if any), `offered` whether the catalogue and the server have that provider's
/// profiles for the workload's model, and `failure` what happened when it was last tried with
/// this runtime epoch. Returns the provider and, when the processor stands in, the reason.
pub(crate) fn select_provider(
    accelerated: Option<&str>,
    offered: bool,
    failure: Option<&str>,
) -> (String, Option<String>) {
    match (accelerated, offered, failure) {
        (Some(provider), true, None) if provider != CPU => (provider.into(), None),
        (Some(provider), true, Some(code)) if provider != CPU => (CPU.into(), Some(code.into())),
        _ => (CPU.into(), None),
    }
}

/// FD-56: an accelerated provider keeps a workload only where it measured faster than the
/// processor on this computer. The times are the warm inference of the same qualification
/// fixtures on each provider; a time that is missing or not a positive number decides nothing
/// (`None`), and the caller then keeps the processor.
pub(crate) fn measured_faster(accelerated_ms: Option<f64>, cpu_ms: Option<f64>) -> Option<bool> {
    let usable = |value: f64| value.is_finite() && value > 0.0;
    match (accelerated_ms, cpu_ms) {
        (Some(accelerated), Some(cpu)) if usable(accelerated) && usable(cpu) => {
            Some(accelerated < cpu)
        }
        _ => None,
    }
}

/// The warm inference time of a workload: the sum over its qualified profiles, or `None` when
/// any report does not carry one.
pub(crate) fn warm_milliseconds<'a>(
    reports: impl IntoIterator<Item = &'a serde_json::Value>,
) -> Option<f64> {
    let mut total = None;
    for report in reports {
        let warm = report.get("warmMilliseconds")?.as_f64()?;
        total = Some(total.unwrap_or(0.0) + warm);
    }
    total
}

/// What one accelerated runtime (its signed manifest names the epoch) is remembered for on this
/// computer: the providers that failed or measured slower, so they are not retried every time
/// the worker starts, and the workloads it measured faster for, so they are not measured again.
/// A newer runtime starts clean.
pub(crate) struct Failures {
    path: PathBuf,
    runtime: String,
    codes: BTreeMap<String, String>,
    faster: BTreeSet<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Remembered {
    schema_version: u32,
    runtime: String,
    failures: BTreeMap<String, String>,
    #[serde(default)]
    faster: BTreeSet<String>,
}
fn code_shaped(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
impl Failures {
    /// A missing, unreadable or foreign record remembers nothing: the provider is tried once
    /// more, and a failure is then held for this run whether or not it can be written.
    pub(crate) fn load(path: &Path, runtime: &str) -> Self {
        let (codes, faster) = read_bounded(path, 16 * 1024)
            .ok()
            .and_then(|raw| serde_json::from_slice::<Remembered>(&raw).ok())
            .filter(|saved| {
                saved.schema_version == 1
                    && saved.runtime == runtime
                    && saved.failures.iter().all(|(workload, code)| {
                        WORKLOADS.contains(&workload.as_str()) && code_shaped(code)
                    })
                    && saved
                        .faster
                        .iter()
                        .all(|workload| WORKLOADS.contains(&workload.as_str()))
            })
            .map(|saved| (saved.failures, saved.faster))
            .unwrap_or_default();
        Self {
            path: path.into(),
            runtime: runtime.into(),
            codes,
            faster,
        }
    }
    pub(crate) fn get(&self, workload: &str) -> Option<&str> {
        self.codes.get(workload).map(String::as_str)
    }
    /// Measured faster than the processor with this runtime. A remembered failure wins.
    pub(crate) fn is_faster(&self, workload: &str) -> bool {
        self.faster.contains(workload) && !self.codes.contains_key(workload)
    }
    fn hold(&mut self, workload: &str, code: &str) {
        if WORKLOADS.contains(&workload) && code_shaped(code) {
            self.codes.insert(workload.into(), code.into());
            self.faster.remove(workload);
        }
    }
    fn hold_faster(&mut self, workload: &str) {
        if WORKLOADS.contains(&workload) && !self.codes.contains_key(workload) {
            self.faster.insert(workload.into());
        }
    }
    /// Best effort: the failure already holds for this run.
    fn save(&self) {
        let saved = Remembered {
            schema_version: 1,
            runtime: self.runtime.clone(),
            failures: self.codes.clone(),
            faster: self.faster.clone(),
        };
        let Ok(raw) = serde_json::to_vec(&saved) else {
            return;
        };
        let temporary = self
            .path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        if std::fs::write(&temporary, raw).is_err()
            || std::fs::rename(&temporary, &self.path).is_err()
        {
            let _ = std::fs::remove_file(temporary);
        }
    }
}

fn workload_of(group: &[ApprovedProfile]) -> &str {
    group
        .first()
        .and_then(|profile| profile.model_key().split(':').next())
        .unwrap_or("")
}

/// The accelerated runtime's side of a plan: its provider, signed manifest and the workloads the
/// server offers it, each with a full profile group.
pub(crate) struct Offer {
    pub provider: String,
    pub manifest_sha256: String,
    pub groups: Vec<Vec<ApprovedProfile>>,
}

/// The provider chosen for every workload of this run.
pub(crate) struct Plan {
    cpu: Vec<Vec<ApprovedProfile>>,
    offer: Option<Offer>,
    /// Why a bundled accelerated runtime is not usable at all on this computer.
    unavailable: Option<String>,
    failures: Option<Failures>,
    /// Refusals that hold for this run only (the server's answer may change).
    refused: BTreeMap<String, String>,
}
impl Plan {
    pub(crate) fn new(
        cpu: Vec<Vec<ApprovedProfile>>,
        offer: Option<Offer>,
        unavailable: Option<String>,
        failures: &Path,
    ) -> Self {
        // An accelerated group stands in for the processor group of the same workload only when
        // it is the same models (the catalogue's provider twins share their model keys), so the
        // model files already prepared and the processor fallback both apply to it.
        let offer = offer.map(|mut offer| {
            offer.groups.retain(|group| {
                cpu.iter().any(|base| {
                    base.len() == group.len()
                        && group.iter().all(|profile| {
                            base.iter()
                                .any(|twin| twin.model_key() == profile.model_key())
                        })
                })
            });
            offer
        });
        let failures = offer
            .as_ref()
            .map(|offer| Failures::load(failures, &offer.manifest_sha256));
        Self {
            cpu,
            offer,
            unavailable,
            failures,
            refused: BTreeMap::new(),
        }
    }
    fn accelerated_group(&self, workload: &str) -> Option<&Vec<ApprovedProfile>> {
        self.offer
            .as_ref()?
            .groups
            .iter()
            .find(|group| workload_of(group) == workload)
    }
    fn choice(&self, workload: &str) -> (String, Option<String>) {
        let failure = self
            .failures
            .as_ref()
            .and_then(|failures| failures.get(workload))
            .or_else(|| self.refused.get(workload).map(String::as_str));
        let (provider, fallback) = select_provider(
            self.offer.as_ref().map(|offer| offer.provider.as_str()),
            self.accelerated_group(workload).is_some(),
            failure,
        );
        (provider, fallback.or_else(|| self.unavailable.clone()))
    }
    /// One profile group per workload the processor runtime can serve, each for the provider
    /// chosen. A workload only the accelerated runtime is offered is left out: nothing could
    /// stand in for it.
    pub(crate) fn groups(&self) -> Vec<Vec<ApprovedProfile>> {
        self.cpu
            .iter()
            .map(|group| {
                let workload = workload_of(group);
                match self.accelerated_group(workload) {
                    Some(accelerated) if self.choice(workload).0 != CPU => accelerated.clone(),
                    _ => group.clone(),
                }
            })
            .collect()
    }
    pub(crate) fn providers(&self) -> Vec<WorkloadProvider> {
        self.cpu
            .iter()
            .map(|group| {
                let workload = workload_of(group);
                let (provider, fallback) = self.choice(workload);
                WorkloadProvider {
                    workload: workload.into(),
                    provider,
                    fallback,
                }
            })
            .collect()
    }
    /// FD-56: the accelerated provider is chosen for this workload but has not yet been measured
    /// against the processor with this runtime, so the caller measures before serving with it.
    pub(crate) fn unmeasured(&self, workload: &str) -> bool {
        self.choice(workload).0 != CPU
            && !self
                .failures
                .as_ref()
                .is_some_and(|failures| failures.is_faster(workload))
    }
    /// The processor profiles of a workload, the twins of its accelerated ones.
    pub(crate) fn cpu_group(&self, workload: &str) -> Option<&Vec<ApprovedProfile>> {
        self.cpu.iter().find(|group| workload_of(group) == workload)
    }
    /// Settle a measurement (`measured_faster`). Faster: the provider keeps the workload and
    /// that is remembered for this runtime epoch. Slower: the processor, remembered the same
    /// way. Unknown: the processor for this run only, so it is measured again next time.
    /// Returns whether the workload moved to the processor.
    pub(crate) fn measured(
        &mut self,
        workload: &str,
        accelerated_ms: Option<f64>,
        cpu_ms: Option<f64>,
    ) -> bool {
        if self.choice(workload).0 == CPU {
            return false;
        }
        match measured_faster(accelerated_ms, cpu_ms) {
            Some(true) => {
                if let Some(failures) = &mut self.failures {
                    failures.hold_faster(workload);
                    failures.save();
                }
                false
            }
            Some(false) => self.demote(workload, "provider_slower", true),
            None => self.demote(workload, "provider_speed_unknown", false),
        }
    }
    /// The accelerated provider failed for this workload: use the processor from now on. Returns
    /// whether anything changed (false when the workload already ran on the processor, so the
    /// caller reports the failure as before). `remember` keeps the failure for this runtime
    /// epoch; a refusal by the server holds for this run only.
    pub(crate) fn demote(&mut self, workload: &str, code: &str, remember: bool) -> bool {
        if self.choice(workload).0 == CPU {
            return false;
        }
        match (&mut self.failures, remember) {
            (Some(failures), true) => {
                failures.hold(workload, code);
                failures.save();
            }
            _ => {
                self.refused.insert(workload.into(), code.into());
            }
        }
        // A code that cannot be recorded must still end the attempt.
        if self.choice(workload).0 != CPU {
            self.refused
                .insert(workload.into(), "provider_failed".into());
        }
        true
    }
    /// The accelerated runtime's process did not serve: every workload on it moves to the
    /// processor, remembered for this runtime epoch.
    ///
    /// Stopping the worker, signing out or a pause for power or network is never the provider's
    /// fault, whatever process happened to be starting at that moment.
    pub(crate) fn demote_runtime(&mut self, manifest_sha256: &str, code: &str) -> bool {
        if code.ends_with("_cancelled")
            || code.starts_with("resource_")
            || self
                .offer
                .as_ref()
                .is_none_or(|offer| offer.manifest_sha256 != manifest_sha256)
        {
            return false;
        }
        let workloads: Vec<String> = self
            .cpu
            .iter()
            .map(|group| workload_of(group).to_owned())
            .collect();
        let mut changed = false;
        for workload in workloads {
            changed |= self.demote(&workload, code, true);
        }
        changed
    }
}

/// One installed runtime with the factory attestation the server asks for.
pub(crate) struct Lane {
    pub installed: InstalledRuntime,
    pub attestation: RuntimeAttestation,
}
/// The processor runtime and, where one is usable, the accelerated runtime beside it.
pub(crate) struct Runtimes {
    cpu: Lane,
    accelerated: Option<Lane>,
}
impl Runtimes {
    pub(crate) fn new(
        installed: InstalledRuntime,
        attestation: RuntimeAttestation,
        accelerated: Option<Lane>,
    ) -> Self {
        Self {
            cpu: Lane {
                installed,
                attestation,
            },
            accelerated,
        }
    }
    pub(crate) fn cpu(&self) -> &InstalledRuntime {
        &self.cpu.installed
    }
    pub(crate) fn accelerated(&self) -> Option<&InstalledRuntime> {
        self.accelerated.as_ref().map(|lane| &lane.installed)
    }
    fn lane(&self, provider: &str) -> Result<&Lane, String> {
        std::iter::once(&self.cpu)
            .chain(&self.accelerated)
            .find(|lane| lane.installed.provider() == provider)
            .ok_or_else(|| "worker_provider_unavailable".into())
    }
    pub(crate) fn attestation(&self, provider: &str) -> Result<&RuntimeAttestation, String> {
        Ok(&self.lane(provider)?.attestation)
    }
    pub(crate) fn qualify(
        &self,
        provider: &str,
        cache: &Path,
        private_root: &Path,
        spec: &[u8],
        fixture: &[u8],
        cancel: &AtomicBool,
    ) -> Result<QualifiedRuntime, String> {
        self.lane(provider)?
            .installed
            .qualify(cache, private_root, spec, fixture, cancel)
    }
    /// One process per runtime that has a qualified binding; `port` serves the first.
    pub(crate) fn start(
        &self,
        bindings: &[(&QualifiedRuntime, &AcceptedQualification)],
        cache: &Path,
        private_root: &Path,
        port: u16,
    ) -> Result<NativePredictor, String> {
        let mut runtimes = vec![(&self.cpu.installed, port)];
        if let Some(lane) = &self.accelerated {
            let reservation = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .map_err(|_| "runtime_port_unavailable")?;
            let second = reservation
                .local_addr()
                .map_err(|_| "runtime_port_unavailable")?
                .port();
            drop(reservation);
            runtimes.push((&lane.installed, second));
        }
        NativePredictor::start_lanes(&runtimes, bindings, cache, private_root)
    }
}

/// Install (or keep) the accelerated runtime the app bundles and load it. `Ok(None)` when the
/// app ships none. Errors are reasons the processor is used instead, never fatal to the worker.
fn install_accelerated(
    bundle: &Path,
    data: &Path,
    cpu_release: &str,
    probe: &dyn Probe,
) -> Result<Option<Lane>, String> {
    use crate::release_policy::open_runtime_store;
    let manifest_path = bundle.join(ACCELERATED_MANIFEST);
    match std::fs::symlink_metadata(&manifest_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("runtime_store_read_failed".into()),
        Ok(_) => {}
    }
    let manifest = read_bounded(&manifest_path, 8 * 1024 * 1024)?;
    // Read before trust only to skip a runtime this computer has no device for; the store
    // verifies the signature and every byte before anything runs.
    let provider = serde_json::from_slice::<serde_json::Value>(&manifest)
        .ok()
        .and_then(|value| value.get("provider")?.as_str().map(str::to_owned))
        .ok_or("runtime_manifest_invalid")?;
    if provider == CPU
        || !device_eligible(
            &provider,
            std::env::consts::OS,
            std::env::consts::ARCH,
            probe,
        )
    {
        return Err("provider_device_ineligible".into());
    }
    let store = open_runtime_store(&data.join(ACCELERATED_STORE))?;
    // A stale release (older epoch than the processor runtime) cannot load; the bundle replaces it.
    let active = store.load_active().ok().flatten();
    let install = active.as_ref().is_none_or(|active| {
        crate::worker_setup::bundle_supersedes(active.manifest_sha256(), active.epoch(), &manifest)
    });
    let installed = match active {
        Some(active) if !install => active,
        active => {
            // Release the shared lease first: activation takes the store's exclusive lock.
            drop(active);
            let signature: [u8; 64] = read_bounded(&bundle.join(ACCELERATED_SIGNATURE), 64)?
                .try_into()
                .map_err(|_| "runtime_signature_invalid")?;
            let shared = open_runtime_store(&data.join("runtimes"))?.release_payload(cpu_release);
            store.install_and_activate_sharing(
                &bundle.join("payload"),
                &manifest,
                &signature,
                Some(&shared),
            )?;
            store.load_active()?.ok_or("runtime_activation_failed")?
        }
    };
    if installed.provider() != provider {
        return Err("runtime_manifest_incompatible".into());
    }
    let attestation = store.attestation(&installed)?;
    Ok(Some(Lane {
        installed,
        attestation,
    }))
}

/// Open the accelerated runtime (if the app ships one this computer can use), ask the server
/// which workloads it offers that provider, and plan each workload's provider.
pub(crate) async fn open(
    paths: &crate::worker_setup::SetupPaths,
    cpu: &InstalledRuntime,
    worker: &WorkerTransport,
    cpu_groups: Vec<Vec<ApprovedProfile>>,
) -> (Option<Lane>, Plan) {
    let (bundle, data, release) = (
        paths.bundle.clone(),
        paths.data.clone(),
        cpu.manifest_sha256().to_owned(),
    );
    let opened = tauri::async_runtime::spawn_blocking(move || {
        install_accelerated(&bundle, &data, &release, &Host)
    })
    .await
    .unwrap_or_else(|_| Err("runtime_preparation_failed".into()));
    let offered = match opened {
        Ok(Some(lane)) => {
            let (source, provider) = (
                lane.installed.source_revision().to_owned(),
                lane.installed.provider().to_owned(),
            );
            match worker
                .model_inventory(&source, &provider)
                .await
                .and_then(|inventory| {
                    crate::worker_setup::inventory_profiles(&inventory, &source, &provider)
                }) {
                Ok((groups, _)) => Ok(Some((lane, groups))),
                Err(code) => Err(code),
            }
        }
        Ok(None) => Ok(None),
        Err(code) => Err(code),
    };
    let failures = paths.data.join("provider-failures.json");
    match offered {
        Ok(Some((lane, groups))) => {
            let offer = Offer {
                provider: lane.installed.provider().into(),
                manifest_sha256: lane.installed.manifest_sha256().into(),
                groups,
            };
            (
                Some(lane),
                Plan::new(cpu_groups, Some(offer), None, &failures),
            )
        }
        Ok(None) => (None, Plan::new(cpu_groups, None, None, &failures)),
        Err(code) => (None, Plan::new(cpu_groups, None, Some(code), &failures)),
    }
}

/// After a successful qualification: reclaim accelerated runtime packs that can never run again.
pub(crate) fn reclaim_superseded(data: &Path, bundle: &Path, active: &str) {
    if let Ok(store) = crate::release_policy::open_runtime_store(&data.join(ACCELERATED_STORE)) {
        let rollback = crate::release_policy::bundled_release(bundle, ACCELERATED_MANIFEST);
        let _ = store.prune(active, rollback.as_deref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const COREML: &str = "CoreMLExecutionProvider";
    const CUDA: &str = "CUDAExecutionProvider";
    const OPENVINO: &str = "OpenVINOExecutionProvider";
    const SOURCE: &str = "f2c451a6bf71ca3f3aec986e07f0852937268e2f";

    #[derive(Default)]
    struct Fixture {
        files: BTreeMap<String, String>,
        variables: BTreeMap<String, String>,
    }
    impl Fixture {
        fn file(mut self, path: &str, text: &str) -> Self {
            self.files.insert(path.into(), text.into());
            self
        }
    }
    impl Probe for Fixture {
        fn exists(&self, path: &str) -> bool {
            self.files.contains_key(path)
        }
        fn read(&self, path: &str) -> Option<String> {
            self.files.get(path).cloned()
        }
        fn list(&self, directory: &str) -> Vec<String> {
            let prefix = format!("{directory}/");
            self.files
                .keys()
                .filter_map(|path| path.strip_prefix(&prefix)?.split('/').next())
                .map(str::to_owned)
                .collect()
        }
        fn variable(&self, name: &str) -> Option<String> {
            self.variables.get(name).cloned()
        }
    }

    #[test]
    fn a_provider_is_eligible_only_where_its_device_is_present() {
        let none = Fixture::default();
        assert!(device_eligible(COREML, "macos", "aarch64", &none));
        for (provider, os, arch) in [
            (COREML, "macos", "x86_64"),
            (COREML, "linux", "aarch64"),
            (CUDA, "macos", "aarch64"),
            (CUDA, "linux", "aarch64"),
            (CUDA, "linux", "x86_64"),
            (CUDA, "windows", "x86_64"),
            (OPENVINO, "linux", "x86_64"),
            (OPENVINO, "windows", "x86_64"),
            (CPU, "linux", "x86_64"),
            ("MIGraphXExecutionProvider", "linux", "x86_64"),
        ] {
            assert!(
                !device_eligible(provider, os, arch, &none),
                "{provider} {os}"
            );
        }
        let nvidia = Fixture::default().file("/proc/driver/nvidia/version", "NVRM version");
        assert!(device_eligible(CUDA, "linux", "x86_64", &nvidia));
        assert!(!device_eligible(OPENVINO, "linux", "x86_64", &nvidia));
        let mut windows = Fixture::default().file("C:\\Windows\\System32\\nvcuda.dll", "");
        assert!(!device_eligible(CUDA, "windows", "x86_64", &windows));
        windows
            .variables
            .insert("SystemRoot".into(), "C:\\Windows".into());
        assert!(device_eligible(CUDA, "windows", "x86_64", &windows));
        let intel = Fixture::default()
            .file("/sys/class/drm/card0/device/vendor", "0x10de\n")
            .file("/sys/class/drm/card1/device/vendor", "0x8086\n")
            .file("/sys/class/drm/card1-DP-1/status", "connected");
        assert!(device_eligible(OPENVINO, "linux", "x86_64", &intel));
        assert!(!device_eligible(CUDA, "linux", "x86_64", &intel));
        let amd = Fixture::default().file("/sys/class/drm/card0/device/vendor", "0x1002\n");
        assert!(!device_eligible(OPENVINO, "linux", "x86_64", &amd));
    }

    #[test]
    fn the_best_qualified_provider_is_chosen_and_the_processor_otherwise() {
        let cpu = || (CPU.to_string(), None);
        assert_eq!(
            select_provider(Some(COREML), true, None),
            (COREML.into(), None)
        );
        assert_eq!(select_provider(Some(CUDA), true, None), (CUDA.into(), None));
        // No accelerated runtime, or none offered for this workload: the processor, no fallback.
        assert_eq!(select_provider(None, true, None), cpu());
        assert_eq!(select_provider(None, false, Some("ignored")), cpu());
        assert_eq!(select_provider(Some(COREML), false, None), cpu());
        assert_eq!(select_provider(Some(CPU), true, None), cpu());
        // A remembered failure: the processor, with the reason for the status.
        assert_eq!(
            select_provider(Some(COREML), true, Some("runtime_qualification_failed")),
            (CPU.into(), Some("runtime_qualification_failed".into()))
        );
    }

    fn group(name: &str, provider: &str) -> Vec<ApprovedProfile> {
        let profiles = crate::model_catalogue::setup_profiles(name, SOURCE, provider).unwrap();
        assert!(!profiles.is_empty(), "{name} {provider}");
        profiles
    }
    fn directory() -> PathBuf {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-providers-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        root
    }
    fn plan(root: &Path, manifest: &str) -> Plan {
        Plan::new(
            vec![
                group("ViT-B-32__openai", CPU),
                group("PP-OCRv5_mobile", CPU),
                group("buffalo_s", CPU),
            ],
            Some(Offer {
                provider: COREML.into(),
                manifest_sha256: manifest.into(),
                // The server offers CoreML for search and faces, not for text recognition.
                groups: vec![
                    group("ViT-B-32__openai", COREML),
                    group("buffalo_s", COREML),
                ],
            }),
            None,
            &root.join("provider-failures.json"),
        )
    }
    fn chosen(plan: &Plan) -> Vec<(String, String, Option<String>)> {
        let providers = plan.providers();
        // The groups handed to qualification are for exactly the providers reported.
        for (group, status) in plan.groups().iter().zip(&providers) {
            assert_eq!(workload_of(group), status.workload);
            assert!(group
                .iter()
                .all(|profile| profile.provider() == status.provider));
        }
        providers
            .into_iter()
            .map(|item| (item.workload, item.provider, item.fallback))
            .collect()
    }
    fn row(
        workload: &str,
        provider: &str,
        fallback: Option<&str>,
    ) -> (String, String, Option<String>) {
        (
            workload.into(),
            provider.into(),
            fallback.map(str::to_owned),
        )
    }

    #[test]
    fn an_accelerated_provider_keeps_a_workload_only_where_it_measured_faster() {
        assert_eq!(measured_faster(Some(20.0), Some(28.0)), Some(true));
        assert_eq!(measured_faster(Some(28.0), Some(20.0)), Some(false));
        // A tie is not faster.
        assert_eq!(measured_faster(Some(20.0), Some(20.0)), Some(false));
        // A time that is missing, zero, negative or not a number decides nothing.
        for unusable in [None, Some(0.0), Some(-1.0), Some(f64::NAN), Some(f64::INFINITY)] {
            assert_eq!(measured_faster(unusable, Some(20.0)), None);
            assert_eq!(measured_faster(Some(20.0), unusable), None);
        }
        let reports = [
            serde_json::json!({"warmMilliseconds": 8.5}),
            serde_json::json!({"warmMilliseconds": 11}),
        ];
        assert_eq!(warm_milliseconds(&reports), Some(19.5));
        assert_eq!(warm_milliseconds(&reports[..0]), None);
        let broken = [
            reports[0].clone(),
            serde_json::json!({"warmMilliseconds": "fast"}),
        ];
        assert_eq!(warm_milliseconds(&broken), None);
        assert_eq!(warm_milliseconds(&[serde_json::json!({})]), None);
    }

    #[test]
    fn a_measurement_is_remembered_for_the_runtime_epoch_and_unknown_keeps_the_processor() {
        let root = directory();
        let manifest = "a".repeat(64);
        let mut first = plan(&root, &manifest);
        // Chosen but not yet measured with this runtime; the processor's own workload never is.
        assert!(first.unmeasured("clip") && first.unmeasured("face"));
        assert!(!first.unmeasured("ocr"));
        assert_eq!(
            first
                .cpu_group("face")
                .map(|group| group[0].provider().to_owned()),
            Some(CPU.to_owned())
        );
        assert!(first.cpu_group("absent").is_none());
        // Faster: it keeps the workload and is not measured again.
        assert!(!first.measured("face", Some(20.0), Some(28.0)));
        assert!(!first.unmeasured("face"));
        // Slower: the processor, with the reason.
        assert!(first.measured("clip", Some(50.0), Some(30.0)));
        assert!(!first.unmeasured("clip"));
        // A workload on the processor has nothing to settle.
        assert!(!first.measured("ocr", Some(1.0), Some(2.0)));
        assert!(!first.measured("clip", Some(1.0), Some(2.0)));
        let expected = [
            row("clip", CPU, Some("provider_slower")),
            row("ocr", CPU, None),
            row("face", COREML, None),
        ];
        assert_eq!(chosen(&first), expected);
        // Both outcomes hold for the next start with the same runtime.
        let again = plan(&root, &manifest);
        assert_eq!(chosen(&again), expected);
        assert!(!again.unmeasured("face") && !again.unmeasured("clip"));
        // A newer runtime is measured from scratch.
        let newer = plan(&root, &"b".repeat(64));
        assert!(newer.unmeasured("clip") && newer.unmeasured("face"));
        assert_eq!(chosen(&newer)[0], row("clip", COREML, None));

        // Unknown (the measurement was interrupted, or a report had no time): the processor for
        // this run only, and measured again next time.
        let other = directory();
        let mut unknown = plan(&other, &manifest);
        assert!(unknown.measured("face", Some(20.0), None));
        assert!(unknown.measured("clip", None, Some(30.0)));
        assert_eq!(
            chosen(&unknown),
            [
                row("clip", CPU, Some("provider_speed_unknown")),
                row("ocr", CPU, None),
                row("face", CPU, Some("provider_speed_unknown")),
            ]
        );
        let retried = plan(&other, &manifest);
        assert!(retried.unmeasured("clip") && retried.unmeasured("face"));
        assert_eq!(chosen(&retried)[2], row("face", COREML, None));

        // A later failure outranks an earlier "faster", and is what is remembered.
        let third = directory();
        let mut failing = plan(&third, &manifest);
        assert!(!failing.measured("face", Some(20.0), Some(28.0)));
        assert!(failing.demote("face", "runtime_process_stopped", true));
        let after = plan(&third, &manifest);
        assert_eq!(
            chosen(&after)[2],
            row("face", CPU, Some("runtime_process_stopped"))
        );
        assert!(!after.unmeasured("face"));

        // A record written before measurements existed still loads; one naming an unknown
        // workload as faster remembers nothing.
        let legacy = directory();
        let path = legacy.join("provider-failures.json");
        std::fs::write(
            &path,
            format!(r#"{{"schemaVersion":1,"runtime":"{manifest}","failures":{{"face":"provider_failed"}}}}"#),
        )
        .unwrap();
        let loaded = Failures::load(&path, &manifest);
        assert_eq!(loaded.get("face"), Some("provider_failed"));
        assert!(!loaded.is_faster("face") && !loaded.is_faster("clip"));
        std::fs::write(
            &path,
            format!(r#"{{"schemaVersion":1,"runtime":"{manifest}","failures":{{}},"faster":["clip","video"]}}"#),
        )
        .unwrap();
        assert!(!Failures::load(&path, &manifest).is_faster("clip"));
        for directory in [root, other, third, legacy] {
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn a_failed_provider_falls_back_once_and_is_remembered_for_the_runtime_epoch() {
        let root = directory();
        let manifest = "a".repeat(64);
        let mut first = plan(&root, &manifest);
        assert_eq!(
            chosen(&first),
            [
                row("clip", COREML, None),
                row("ocr", CPU, None),
                row("face", COREML, None)
            ]
        );
        // A workload already on the processor is not a provider failure.
        assert!(!first.demote("ocr", "runtime_qualification_failed", true));
        assert!(first.demote("face", "runtime_qualification_timeout", true));
        // The same failure cannot be taken twice: no retry loop.
        assert!(!first.demote("face", "runtime_qualification_timeout", true));
        // A refusal by the server holds for this run only.
        assert!(first.demote("clip", "worker_qualification_refused", false));
        let fallen = [
            row("clip", CPU, Some("worker_qualification_refused")),
            row("ocr", CPU, None),
            row("face", CPU, Some("runtime_qualification_timeout")),
        ];
        assert_eq!(chosen(&first), fallen);
        // The next start with the same runtime does not try the failed provider again.
        let second = plan(&root, &manifest);
        assert_eq!(
            chosen(&second),
            [
                row("clip", COREML, None),
                row("ocr", CPU, None),
                row("face", CPU, Some("runtime_qualification_timeout"))
            ]
        );
        // A new runtime epoch (another signed manifest) starts clean.
        let mut newer = plan(&root, &"b".repeat(64));
        assert_eq!(
            chosen(&newer),
            [
                row("clip", COREML, None),
                row("ocr", CPU, None),
                row("face", COREML, None)
            ]
        );
        // A process that did not serve moves every workload of that runtime, and only that one.
        assert!(!newer.demote_runtime(&manifest, "runtime_process_stopped"));
        // Stopping the worker or a resource pause while that process starts is not its failure.
        for code in [
            "worker_setup_cancelled",
            "worker_cancelled",
            "runtime_cancelled",
            "resource_system_resumed",
        ] {
            assert!(!newer.demote_runtime(&"b".repeat(64), code), "{code}");
        }
        assert_eq!(chosen(&newer)[0], row("clip", COREML, None));
        assert_eq!(
            chosen(&plan(&root, &"b".repeat(64)))[2],
            row("face", COREML, None)
        );
        assert!(newer.demote_runtime(&"b".repeat(64), "runtime_process_stopped"));
        assert_eq!(
            chosen(&newer),
            [
                row("clip", CPU, Some("runtime_process_stopped")),
                row("ocr", CPU, None),
                row("face", CPU, Some("runtime_process_stopped"))
            ]
        );
        assert!(!newer.demote_runtime(&"b".repeat(64), "runtime_process_stopped"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_unreadable_or_unwritable_failure_record_never_causes_a_retry_loop() {
        let root = directory();
        let manifest = "a".repeat(64);
        let record = root.join("provider-failures.json");
        for damaged in [
            "{",
            r#"{"schemaVersion":2,"runtime":"x","failures":{}}"#,
            r#"{"schemaVersion":1,"runtime":"aaaa","failures":{"face":"../etc"},"extra":1}"#,
        ] {
            std::fs::write(&record, damaged).unwrap();
            assert_eq!(
                chosen(&plan(&root, &manifest))[2],
                row("face", COREML, None)
            );
        }
        // The record cannot be written (its place is a directory): the failure holds for the run.
        std::fs::remove_file(&record).unwrap();
        std::fs::create_dir(&record).unwrap();
        let mut current = plan(&root, &manifest);
        assert!(current.demote("face", "runtime_qualification_failed", true));
        assert_eq!(
            chosen(&current)[2],
            row("face", CPU, Some("runtime_qualification_failed"))
        );
        // A code that is not code-shaped is still a failure.
        assert!(current.demote("clip", "Not A Code", true));
        assert_eq!(
            chosen(&current)[0],
            row("clip", CPU, Some("provider_failed"))
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn without_a_usable_accelerated_runtime_every_workload_runs_on_the_processor() {
        let root = directory();
        let cpu = vec![group("buffalo_s", CPU)];
        let none = Plan::new(cpu.clone(), None, None, &root.join("failures.json"));
        assert_eq!(chosen(&none), [row("face", CPU, None)]);
        // The app ships one but this computer cannot use it: the status says why.
        let mut unusable = Plan::new(
            cpu,
            None,
            Some("provider_device_ineligible".into()),
            &root.join("failures.json"),
        );
        assert_eq!(
            chosen(&unusable),
            [row("face", CPU, Some("provider_device_ineligible"))]
        );
        assert!(!unusable.demote("face", "runtime_qualification_failed", true));
        assert!(!root.join("failures.json").exists());
        // An offer for another model than the processor group's cannot stand in for it.
        let other = Plan::new(
            vec![group("buffalo_s", CPU)],
            Some(Offer {
                provider: COREML.into(),
                manifest_sha256: "a".repeat(64),
                groups: vec![group("buffalo_l", COREML)],
            }),
            None,
            &root.join("failures.json"),
        );
        assert_eq!(chosen(&other), [row("face", CPU, None)]);
        std::fs::remove_dir_all(root).unwrap();
    }
}
