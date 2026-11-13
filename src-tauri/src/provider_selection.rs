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
pub(crate) const ACCELERATED_MANIFEST: &str = "manifest-accelerated.json";
pub(crate) const ACCELERATED_SIGNATURE: &str = "manifest-accelerated.sig";
#[cfg(not(windows))]
pub(crate) const ACCELERATED_STORE: &str = "runtimes-accelerated";
/// FD-63: Windows opens a library only below 260 characters, and an installed release already
/// spends about 150 of them on the profile, this store and the release's own name. With the long
/// name, a library the runtime cannot do without (numpy's OpenBLAS, 93 characters inside the
/// pack) fell beyond the limit for a profile folder of 18 characters or more. No Windows
/// installation has an accelerated store yet, so the short name moves nothing.
/// `tools/check_windows_cuda_libraries.py` holds every pack to the same arithmetic.
#[cfg(windows)]
pub(crate) const ACCELERATED_STORE: &str = "gpu";
const REMEMBERED: &str = "provider-failures.json";
/// How Windows names an Intel or NVIDIA display adapter (the PCI vendor of its hardware id).
const INTEL_ADAPTER: &str = "pci\\ven_8086&";
const NVIDIA_ADAPTER: &str = "pci\\ven_10de&";
const WORKLOADS: [&str; 3] = ["clip", "ocr", "face"];

/// What this computer has. Injected so each operating system's rule is tested on all of them.
pub(crate) trait Probe {
    fn exists(&self, path: &str) -> bool;
    fn read(&self, path: &str) -> Option<String>;
    fn list(&self, directory: &str) -> Vec<String>;
    fn variable(&self, name: &str) -> Option<String>;
    /// Windows: every display adapter a driver is installed for, as its hardware id in lower
    /// case (`pci\ven_8086&dev_a7a0...`) and that driver's version. Empty anywhere else.
    fn adapters(&self) -> Vec<(String, String)> {
        Vec::new()
    }
}
/// The display adapter class of the Windows registry: one numbered key per adapter that has a
/// driver, naming the hardware id the driver matched and the driver's version.
#[cfg(windows)]
fn display_adapters() -> Vec<(String, String)> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }
    fn text(key: &[u16], value: &str) -> Option<String> {
        let value = wide(value);
        let mut words = [0u16; 512];
        let mut size = std::mem::size_of_val(&words) as u32;
        // SAFETY: both names are NUL-terminated and outlive the call; `size` is the size of
        // `words` in bytes, and the call writes no more than that and reports what it wrote.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                words.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status != 0 {
            return None;
        }
        let written = words.get(..size as usize / 2)?;
        String::from_utf16(written.split(|word| *word == 0).next()?).ok()
    }
    // The keys are numbered from 0000; a removed adapter can leave a gap.
    (0..64)
        .filter_map(|index| {
            let key = wide(&format!(
                "SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e968-e325-11ce-bfc1-08002be10318}}\\{index:04}"
            ));
            Some((
                text(&key, "MatchingDeviceId")?.to_ascii_lowercase(),
                text(&key, "DriverVersion").unwrap_or_default(),
            ))
        })
        .collect()
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
    #[cfg(windows)]
    fn adapters(&self) -> Vec<(String, String)> {
        display_adapters()
    }
}

/// Linux: the PCI device id of every Intel (PCI vendor 0x8086) display adapter.
fn intel_cards(probe: &dyn Probe) -> Vec<String> {
    let mut cards = probe.list("/sys/class/drm");
    cards.sort();
    cards
        .iter()
        .filter(|card| {
            card.strip_prefix("card")
                .is_some_and(|index| index.bytes().all(|b| b.is_ascii_digit()))
                && probe
                    .read(&format!("/sys/class/drm/{card}/device/vendor"))
                    .is_some_and(|vendor| vendor.trim() == "0x8086")
        })
        .map(|card| {
            probe
                .read(&format!("/sys/class/drm/{card}/device/device"))
                .unwrap_or_default()
                .trim()
                .to_owned()
        })
        .collect()
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
        ("OpenVINOExecutionProvider", "linux", "x86_64") => !intel_cards(probe).is_empty(),
        // FD-64: an Intel display adapter with its graphics driver installed. The pinned OpenVINO
        // (2025.4) runs its GPU device on Intel HD, UHD, Iris and Arc graphics under Windows 10
        // and 11 and needs that driver, which it does not carry; Windows lists an adapter under
        // the Intel hardware id only once such a driver is installed for it.
        ("OpenVINOExecutionProvider", "windows", "x86_64") => probe
            .adapters()
            .iter()
            .any(|(adapter, _)| adapter.starts_with(INTEL_ADAPTER)),
        _ => false,
    }
}

/// FD-63: the oldest NVIDIA driver for Windows that runs any CUDA 12 (NVIDIA's release notes:
/// 527.41 for CUDA 12.0). The pack's CUDA is 12.x, so no older driver can run it.
const CUDA_MINIMUM_WINDOWS_DRIVER: (u32, u32) = (527, 41);

/// NVIDIA's own driver version (`560.94`) from the version Windows records for the driver
/// (`32.0.15.6094`): the last five digits of its third and fourth fields.
fn nvidia_driver(version: &str) -> Option<(u32, u32)> {
    let fields: Vec<&str> = version.trim().split('.').collect();
    if fields.len() != 4
        || fields
            .iter()
            .any(|field| field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()))
        || fields[2].len() > 4
        || fields[3].len() > 4
    {
        return None;
    }
    let digits = format!("{}{:0>4}", fields[2], fields[3]);
    let tail = digits.get(digits.len().checked_sub(5)?..)?;
    Some((tail[..3].parse().ok()?, tail[3..].parse().ok()?))
}

/// FD-63: whether the NVIDIA driver installed on Windows is known to be too old for the pack's
/// CUDA. Only a version that is read and understood can say so: with no NVIDIA adapter listed,
/// or a version in another form, the answer is no and qualification decides as before. One
/// adapter with a driver that is new enough is enough.
pub(crate) fn driver_outdated(provider: &str, os: &str, probe: &dyn Probe) -> bool {
    if (provider, os) != ("CUDAExecutionProvider", "windows") {
        return false;
    }
    let drivers: Vec<Option<(u32, u32)>> = probe
        .adapters()
        .iter()
        .filter(|(adapter, _)| adapter.starts_with(NVIDIA_ADAPTER))
        .map(|(_, driver)| nvidia_driver(driver))
        .collect();
    !drivers.is_empty()
        && drivers
            .iter()
            .all(|driver| driver.is_some_and(|version| version < CUDA_MINIMUM_WINDOWS_DRIVER))
}

/// FD-64: the device and driver a remembered result was measured with, as a digest. A driver
/// update, an operating system update that carries the driver, or another card changes it, and
/// the provider is then tried again. Empty when nothing identifies the device, which only
/// matches a result remembered the same way.
pub(crate) fn device_identity(provider: &str, os: &str, probe: &dyn Probe) -> String {
    use sha2::{Digest, Sha256};
    let adapters = |vendor: &str| {
        let mut found: Vec<String> = probe
            .adapters()
            .into_iter()
            .filter(|(adapter, _)| adapter.starts_with(vendor))
            .map(|(adapter, driver)| format!("{adapter} {driver}"))
            .collect();
        found.sort();
        found.join("\n")
    };
    let facts = match (provider, os) {
        // CoreML and the Metal driver come with macOS: its version and build.
        ("CoreMLExecutionProvider", "macos") => probe
            .read("/System/Library/CoreServices/SystemVersion.plist")
            .unwrap_or_default(),
        // The loaded NVIDIA driver's version and the model of each card it drives.
        ("CUDAExecutionProvider", "linux") => {
            let mut facts = probe
                .read("/proc/driver/nvidia/version")
                .unwrap_or_default();
            let mut cards = probe.list("/proc/driver/nvidia/gpus");
            cards.sort();
            for card in cards {
                let information = probe
                    .read(&format!("/proc/driver/nvidia/gpus/{card}/information"))
                    .unwrap_or_default();
                for line in information
                    .lines()
                    .filter(|line| line.starts_with("Model:") || line.starts_with("GPU UUID:"))
                {
                    facts.push_str(line);
                    facts.push('\n');
                }
            }
            facts
        }
        ("CUDAExecutionProvider", "windows") => adapters(NVIDIA_ADAPTER),
        ("OpenVINOExecutionProvider", "windows") => adapters(INTEL_ADAPTER),
        // The Intel cards and the kernel that carries their driver.
        ("OpenVINOExecutionProvider", "linux") => {
            let cards = intel_cards(probe);
            if cards.is_empty() {
                String::new()
            } else {
                format!(
                    "{}\n{}",
                    cards.join("\n"),
                    probe.read("/proc/sys/kernel/osrelease").unwrap_or_default()
                )
            }
        }
        _ => String::new(),
    };
    if facts.trim().is_empty() {
        String::new()
    } else {
        format!("{:x}", Sha256::digest(facts.as_bytes()))
    }
}

/// FD-64: a cause that says nothing lasting about the provider: its process was not serving
/// in time, which a busy computer explains as well as a faulty provider does. The processor
/// takes over for this run and the provider is tried again the next time the worker starts.
fn passing(code: &str) -> bool {
    matches!(code, "worker_execution_deadline" | "runtime_not_ready")
}

/// FD-64: Retry Setup forgets what was remembered, so the provider is tried and measured again.
pub(crate) fn forget(data: &Path) {
    let _ = std::fs::remove_file(data.join(REMEMBERED));
}

/// FD-64: the request for what the server offers the accelerated runtime failed. A failure the
/// worker reconnects after (`Err`) ends this preparation so it is asked again; any other is the
/// reason the processor is used for this run.
fn inventory_failure(code: String) -> Result<String, String> {
    if crate::worker_setup::retryable(&code) {
        Err(code)
    } else {
        Ok(code)
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
/// A newer runtime starts clean, and so does another device or driver (`device_identity`).
pub(crate) struct Failures {
    path: PathBuf,
    runtime: String,
    device: String,
    codes: BTreeMap<String, String>,
    /// Workload -> the model keys of the accelerated group that measured faster. The result is
    /// about those models: another model offered for the same workload is measured itself.
    faster: BTreeMap<String, BTreeSet<String>>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Remembered {
    schema_version: u32,
    runtime: String,
    /// Absent in a record saved before results named their device: it then matches no device.
    #[serde(default)]
    device: String,
    failures: BTreeMap<String, String>,
    /// Results saved before they named their models: read so the record still loads, never
    /// trusted and never written again (the workload is measured again).
    #[serde(default, skip_serializing)]
    faster: BTreeSet<String>,
    #[serde(default)]
    measured: BTreeMap<String, BTreeSet<String>>,
}
fn model_key_shaped(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|b| b.is_ascii_graphic())
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
    pub(crate) fn load(path: &Path, runtime: &str, device: &str) -> Self {
        let (codes, faster) = read_bounded(path, 16 * 1024)
            .ok()
            .and_then(|raw| serde_json::from_slice::<Remembered>(&raw).ok())
            .filter(|saved| {
                saved.schema_version == 1
                    && saved.runtime == runtime
                    && saved.device == device
                    && saved.failures.iter().all(|(workload, code)| {
                        WORKLOADS.contains(&workload.as_str()) && code_shaped(code)
                    })
                    && saved
                        .faster
                        .iter()
                        .all(|workload| WORKLOADS.contains(&workload.as_str()))
                    && saved.measured.iter().all(|(workload, keys)| {
                        WORKLOADS.contains(&workload.as_str())
                            && !keys.is_empty()
                            && keys.len() <= 64
                            && keys.iter().all(|key| model_key_shaped(key))
                    })
            })
            .map(|saved| (saved.failures, saved.measured))
            .unwrap_or_default();
        Self {
            path: path.into(),
            runtime: runtime.into(),
            device: device.into(),
            codes,
            faster,
        }
    }
    pub(crate) fn get(&self, workload: &str) -> Option<&str> {
        self.codes.get(workload).map(String::as_str)
    }
    /// These models measured faster than the processor with this runtime. A remembered failure
    /// wins, and a result for other models of the same workload says nothing about these.
    pub(crate) fn is_faster(&self, workload: &str, keys: &BTreeSet<String>) -> bool {
        !keys.is_empty()
            && self.faster.get(workload) == Some(keys)
            && !self.codes.contains_key(workload)
    }
    fn hold(&mut self, workload: &str, code: &str) {
        if WORKLOADS.contains(&workload) && code_shaped(code) {
            self.codes.insert(workload.into(), code.into());
            self.faster.remove(workload);
        }
    }
    fn hold_faster(&mut self, workload: &str, keys: BTreeSet<String>) {
        if WORKLOADS.contains(&workload)
            && !self.codes.contains_key(workload)
            && !keys.is_empty()
            && keys.len() <= 64
            && keys.iter().all(|key| model_key_shaped(key))
        {
            self.faster.insert(workload.into(), keys);
        }
    }
    /// Best effort: the failure already holds for this run.
    fn save(&self) {
        let saved = Remembered {
            schema_version: 1,
            runtime: self.runtime.clone(),
            device: self.device.clone(),
            failures: self.codes.clone(),
            faster: BTreeSet::new(),
            measured: self.faster.clone(),
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
    /// `device_identity` of the device this runtime would use.
    pub device: String,
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
            .map(|offer| Failures::load(failures, &offer.manifest_sha256, &offer.device));
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
            && !self.failures.as_ref().is_some_and(|failures| {
                failures.is_faster(workload, &self.accelerated_keys(workload))
            })
    }
    /// The model keys of the accelerated group offered for a workload: what a measurement is of.
    fn accelerated_keys(&self, workload: &str) -> BTreeSet<String> {
        self.accelerated_group(workload)
            .into_iter()
            .flatten()
            .map(|profile| profile.model_key().to_owned())
            .collect()
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
                let keys = self.accelerated_keys(workload);
                if let Some(failures) = &mut self.failures {
                    failures.hold_faster(workload, keys);
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
    /// processor, remembered for this runtime epoch and device unless the cause is a passing
    /// one (`passing`), which holds for this run only.
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
            changed |= self.demote(&workload, code, !passing(code));
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

/// What installing an accelerated runtime asks of this computer. Tests answer for it.
pub(crate) struct Installer<'a> {
    /// Whether this computer has the device a provider needs.
    pub eligible: &'a dyn Fn(&str) -> bool,
    /// FD-63: whether the device's driver is known to be too old for that provider's pack.
    pub outdated: &'a dyn Fn(&str) -> bool,
    /// Open the runtime store at a path with the app's release authority.
    pub store: &'a dyn Fn(&Path) -> Result<crate::runtime_store::RuntimeStore, String>,
}

/// Install (or keep) the accelerated runtime and load it: the one the app bundles, or (FD-60)
/// the pack the person downloaded for this computer's device. `Ok(None)` when there is neither.
/// Errors are reasons the processor is used instead, never fatal to the worker.
fn install_accelerated(
    bundle: &Path,
    data: &Path,
    cpu_release: &str,
    cpu_epoch: u64,
    probe: &dyn Probe,
) -> Result<Option<Lane>, String> {
    let with = Installer {
        eligible: &|provider| {
            device_eligible(
                provider,
                std::env::consts::OS,
                std::env::consts::ARCH,
                probe,
            )
        },
        outdated: &|provider| driver_outdated(provider, std::env::consts::OS, probe),
        store: &|path| crate::release_policy::open_runtime_store(path),
    };
    match std::fs::symlink_metadata(bundle.join(ACCELERATED_MANIFEST)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match crate::accelerated_pack::installable(bundle, data, probe) {
                Some(directory) => {
                    install_downloaded(&directory, data, cpu_release, cpu_epoch, &with).map(Some)
                }
                None => Ok(None),
            }
        }
        Err(_) => Err("runtime_store_read_failed".into()),
        Ok(_) => install_from(bundle, data, cpu_release, None, &with).map(Some),
    }
}

/// Install the pack unpacked in `directory` at the processor runtime's epoch. Once the store
/// holds it the unpacked payload is released. A failure that says the pack can never be
/// installed here discards it with its reason, so it is not tried again at every start and the
/// person can download it again; any other failure leaves it for the next start.
pub(crate) fn install_downloaded(
    directory: &Path,
    data: &Path,
    cpu_release: &str,
    cpu_epoch: u64,
    with: &Installer,
) -> Result<Lane, String> {
    match install_from(directory, data, cpu_release, Some(cpu_epoch), with) {
        Ok(lane) => {
            crate::accelerated_pack::installed(directory);
            Ok(lane)
        }
        Err(code) => {
            if crate::accelerated_pack::install_failure_is_final(&code) {
                crate::accelerated_pack::discard(data, directory, &code);
            }
            Err(code)
        }
    }
}

/// `source` holds the signed accelerated manifest and its payload. `downloaded` is the processor
/// runtime's epoch when `source` is a downloaded pack rather than the app's own bundle.
fn install_from(
    source: &Path,
    data: &Path,
    cpu_release: &str,
    downloaded: Option<u64>,
    with: &Installer,
) -> Result<Lane, String> {
    let manifest = read_bounded(&source.join(ACCELERATED_MANIFEST), 8 * 1024 * 1024)?;
    // Read before trust only to skip a runtime this computer has no device for; the store
    // verifies the signature and every byte before anything runs.
    let provider = serde_json::from_slice::<serde_json::Value>(&manifest)
        .ok()
        .and_then(|value| value.get("provider")?.as_str().map(str::to_owned))
        .ok_or("runtime_manifest_invalid")?;
    if provider == CPU || !(with.eligible)(&provider) {
        return Err("provider_device_ineligible".into());
    }
    // FD-63: a driver known to be too old is said so, instead of a check that cannot pass.
    if (with.outdated)(&provider) {
        return Err("provider_driver_outdated".into());
    }
    if let Some(cpu_epoch) = downloaded {
        crate::accelerated_pack::epoch_admissible(&manifest, cpu_epoch)?;
    }
    let store = (with.store)(&data.join(ACCELERATED_STORE))?;
    // A stale release (older epoch than the processor runtime) cannot load; the bundle replaces it.
    let loaded = store.load_active();
    let unreadable = loaded.as_ref().err().cloned();
    let active = loaded.ok().flatten();
    let install = active.as_ref().is_none_or(|active| {
        crate::worker_setup::bundle_supersedes(active.manifest_sha256(), active.epoch(), &manifest)
    });
    // A downloaded pack's unpacked files are removed once the store holds it. If the store
    // cannot be read now, that decides nothing about the pack; if it no longer holds it, the
    // pack has to be downloaded again.
    if install && downloaded.is_some() && std::fs::symlink_metadata(source.join("payload")).is_err()
    {
        return Err(unreadable.unwrap_or_else(|| "accelerated_pack_missing".into()));
    }
    let installed = match active {
        Some(active) if !install => active,
        active => {
            // Release the shared lease first: activation takes the store's exclusive lock.
            drop(active);
            let signature: [u8; 64] = read_bounded(&source.join(ACCELERATED_SIGNATURE), 64)?
                .try_into()
                .map_err(|_| "runtime_signature_invalid")?;
            // A bundled pack shares its files with the processor runtime of the same pack. A
            // downloaded one is linked from where it was unpacked instead of stored twice. The
            // store checks every byte of the result either way.
            let shared = match downloaded {
                Some(_) => source.join("payload"),
                None => (with.store)(&data.join("runtimes"))?.release_payload(cpu_release),
            };
            store.install_and_activate_sharing(
                &source.join("payload"),
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
    Ok(Lane {
        installed,
        attestation,
    })
}

/// Open the accelerated runtime (if the app ships one this computer can use), ask the server
/// which workloads it offers that provider, and plan each workload's provider.
pub(crate) async fn open(
    paths: &crate::worker_setup::SetupPaths,
    cpu: &InstalledRuntime,
    worker: &WorkerTransport,
    cpu_groups: Vec<Vec<ApprovedProfile>>,
) -> Result<(Option<Lane>, Plan), String> {
    let (bundle, data, release, epoch) = (
        paths.bundle.clone(),
        paths.data.clone(),
        cpu.manifest_sha256().to_owned(),
        cpu.epoch(),
    );
    let opened = tauri::async_runtime::spawn_blocking(move || {
        install_accelerated(&bundle, &data, &release, epoch, &Host).map(|lane| {
            lane.map(|lane| {
                let device =
                    device_identity(lane.installed.provider(), std::env::consts::OS, &Host);
                (lane, device)
            })
        })
    })
    .await
    .unwrap_or_else(|_| Err("runtime_preparation_failed".into()));
    let offered = match opened {
        Ok(Some((lane, device))) => {
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
                Ok((groups, _)) => Ok(Some((lane, device, groups))),
                Err(code) => Err(inventory_failure(code)?),
            }
        }
        Ok(None) => Ok(None),
        Err(code) => Err(code),
    };
    let failures = paths.data.join(REMEMBERED);
    Ok(match offered {
        Ok(Some((lane, device, groups))) => {
            let offer = Offer {
                provider: lane.installed.provider().into(),
                manifest_sha256: lane.installed.manifest_sha256().into(),
                device,
                groups,
            };
            (
                Some(lane),
                Plan::new(cpu_groups, Some(offer), None, &failures),
            )
        }
        Ok(None) => (None, Plan::new(cpu_groups, None, None, &failures)),
        Err(code) => (None, Plan::new(cpu_groups, None, Some(code), &failures)),
    })
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
        adapters: Vec<(String, String)>,
    }
    impl Fixture {
        fn adapter(mut self, hardware: &str, driver: &str) -> Self {
            self.adapters.push((hardware.into(), driver.into()));
            self
        }
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
        fn adapters(&self) -> Vec<(String, String)> {
            self.adapters.clone()
        }
    }
    const INTEL_ARC: &str = "pci\\ven_8086&dev_56a0";
    const NVIDIA_CARD: &str = "pci\\ven_10de&dev_2684";

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
    fn an_nvidia_driver_too_old_for_cuda_12_is_known_only_from_a_version_that_is_understood() {
        assert_eq!(nvidia_driver("32.0.15.6094"), Some((560, 94)));
        assert_eq!(nvidia_driver("31.0.15.2756"), Some((527, 56)));
        assert_eq!(nvidia_driver("27.21.14.5671"), Some((456, 71)));
        assert_eq!(nvidia_driver("30.0.14.9649"), Some((496, 49)));
        for unknown in [
            "",
            "560.94",
            "32.0.15",
            "32.0.15.x",
            "32.0.15.60941",
            "10.0.1.2.3",
        ] {
            assert_eq!(nvidia_driver(unknown), None, "{unknown}");
        }
        let outdated = |fixture: &Fixture| driver_outdated(CUDA, "windows", fixture);
        // The first driver for CUDA 12.0 and anything newer pass; the one before does not.
        assert!(!outdated(
            &Fixture::default().adapter(NVIDIA_CARD, "31.0.15.2741")
        ));
        assert!(!outdated(
            &Fixture::default().adapter(NVIDIA_CARD, "32.0.15.6094")
        ));
        assert!(outdated(
            &Fixture::default().adapter(NVIDIA_CARD, "31.0.15.2740")
        ));
        assert!(outdated(
            &Fixture::default().adapter(NVIDIA_CARD, "27.21.14.5671")
        ));
        // Unknown never refuses: no NVIDIA adapter listed, or a version in another form.
        assert!(!outdated(&Fixture::default()));
        assert!(!outdated(
            &Fixture::default().adapter(INTEL_ARC, "27.21.14.5671")
        ));
        assert!(!outdated(&Fixture::default().adapter(NVIDIA_CARD, "")));
        assert!(!outdated(
            &Fixture::default()
                .adapter(NVIDIA_CARD, "27.21.14.5671")
                .adapter(NVIDIA_CARD, "unknown")
        ));
        // A second card with a driver that is new enough is enough.
        assert!(!outdated(
            &Fixture::default()
                .adapter(NVIDIA_CARD, "27.21.14.5671")
                .adapter("pci\\ven_10de&dev_1c82", "32.0.15.6094")
        ));
        // Only CUDA on Windows is judged this way.
        let old = Fixture::default().adapter(NVIDIA_CARD, "27.21.14.5671");
        assert!(!driver_outdated(CUDA, "linux", &old));
        assert!(!driver_outdated(OPENVINO, "windows", &old));
    }

    #[test]
    fn openvino_is_eligible_on_windows_with_an_intel_adapter_and_its_driver() {
        // An NVIDIA card, and an Intel one Windows drives with its basic display driver (no
        // Intel graphics driver, so it is not listed under the Intel hardware id).
        let other = Fixture::default()
            .adapter(NVIDIA_CARD, "32.0.15.6094")
            .adapter("pci\\cc_0300", "10.0.26100.1");
        assert!(!device_eligible(OPENVINO, "windows", "x86_64", &other));
        let intel = other.adapter(INTEL_ARC, "32.0.101.6078");
        assert!(device_eligible(OPENVINO, "windows", "x86_64", &intel));
        // Integrated graphics count the same; the vendor must be the whole field.
        let integrated = Fixture::default().adapter("pci\\ven_8086&dev_a7a0&subsys_0b1a1028", "");
        assert!(device_eligible(OPENVINO, "windows", "x86_64", &integrated));
        let lookalike = Fixture::default().adapter("pci\\ven_80860&dev_a7a0", "1");
        assert!(!device_eligible(OPENVINO, "windows", "x86_64", &lookalike));
        // Only where the app ships that runtime, and never for another provider or system.
        assert!(!device_eligible(OPENVINO, "windows", "aarch64", &intel));
        assert!(!device_eligible(OPENVINO, "linux", "x86_64", &intel));
        assert!(!device_eligible(CUDA, "windows", "x86_64", &intel));
        // The app targets what the runtime packs are built for.
        let profiles: serde_json::Value =
            serde_json::from_str(include_str!("../../runtime/profiles.json")).unwrap();
        let targets = profiles["profiles"]["openvino-ort"]["targets"]
            .as_array()
            .unwrap();
        assert!(targets.iter().any(|target| target == "windows-x86_64"));
    }

    #[test]
    fn the_device_identity_follows_the_card_and_its_driver_on_every_system() {
        let identity = |provider: &str, os: &str, probe: &Fixture| {
            let value = device_identity(provider, os, probe);
            assert!(value.is_empty() || value.len() == 64, "{value}");
            value
        };
        // Nothing to read: no identity, on every system.
        let none = Fixture::default();
        for (provider, os) in [
            (COREML, "macos"),
            (CUDA, "linux"),
            (CUDA, "windows"),
            (OPENVINO, "linux"),
            (OPENVINO, "windows"),
            (CPU, "linux"),
        ] {
            assert_eq!(identity(provider, os, &none), "", "{provider} {os}");
        }
        // Windows: the adapter of the provider's vendor and its driver version.
        let windows = |driver: &str| {
            Fixture::default()
                .adapter(NVIDIA_CARD, driver)
                .adapter(INTEL_ARC, "32.0.101.6078")
        };
        let before = identity(CUDA, "windows", &windows("31.0.15.3623"));
        assert!(!before.is_empty());
        assert_eq!(before, identity(CUDA, "windows", &windows("31.0.15.3623")));
        assert_ne!(before, identity(CUDA, "windows", &windows("32.0.15.6094")));
        // Another vendor's driver update is not this provider's.
        assert_eq!(
            identity(OPENVINO, "windows", &windows("31.0.15.3623")),
            identity(OPENVINO, "windows", &windows("32.0.15.6094"))
        );
        let swapped = Fixture::default().adapter("pci\\ven_10de&dev_2204", "31.0.15.3623");
        assert_ne!(before, identity(CUDA, "windows", &swapped));
        // Linux CUDA: the loaded driver's version and each card's model.
        let linux = |version: &str, model: &str| {
            Fixture::default()
                .file("/proc/driver/nvidia/version", version)
                .file(
                    "/proc/driver/nvidia/gpus/0000:01:00.0/information",
                    &format!("Model: \t\t {model}\nIRQ:   \t\t 131\n"),
                )
        };
        let old = identity(CUDA, "linux", &linux("NVRM version: 535.54", "RTX 3080"));
        assert!(!old.is_empty());
        assert_ne!(
            old,
            identity(CUDA, "linux", &linux("NVRM version: 570.86", "RTX 3080"))
        );
        assert_ne!(
            old,
            identity(CUDA, "linux", &linux("NVRM version: 535.54", "RTX 4090"))
        );
        // Linux OpenVINO: the Intel card and the kernel that carries its driver.
        let intel = |device: &str, kernel: &str| {
            Fixture::default()
                .file("/sys/class/drm/card0/device/vendor", "0x8086\n")
                .file("/sys/class/drm/card0/device/device", device)
                .file("/proc/sys/kernel/osrelease", kernel)
        };
        let first = identity(OPENVINO, "linux", &intel("0x56a0\n", "6.8.0-45\n"));
        assert!(!first.is_empty());
        assert_ne!(
            first,
            identity(OPENVINO, "linux", &intel("0x56a0\n", "6.11.0-9\n"))
        );
        assert_ne!(
            first,
            identity(OPENVINO, "linux", &intel("0xa7a0\n", "6.8.0-45\n"))
        );
        // macOS: the system version and build.
        let mac = |build: &str| {
            Fixture::default().file("/System/Library/CoreServices/SystemVersion.plist", build)
        };
        assert_ne!(
            identity(COREML, "macos", &mac("15.6 24G84")),
            identity(COREML, "macos", &mac("15.7 24G222"))
        );
        // This computer answers without failing, whatever it has.
        identity(COREML, std::env::consts::OS, &Fixture::default());
        let _ = device_identity(CUDA, std::env::consts::OS, &Host);
        assert!(Host.adapters().len() <= 64);
    }

    #[test]
    fn a_remembered_failure_is_retried_after_a_driver_update_a_passing_cause_or_retry_setup() {
        let root = directory();
        let manifest = "a".repeat(64);
        let fallen = |plan: &Plan| chosen(plan)[2].clone();
        // A qualification failure with the old driver is remembered for that driver...
        let mut old = plan_on(&root, &manifest, "driver-1");
        assert!(old.demote("face", "runtime_qualification_failed", true));
        assert_eq!(
            fallen(&plan_on(&root, &manifest, "driver-1")),
            row("face", CPU, Some("runtime_qualification_failed"))
        );
        // ...and the provider is tried again once the driver or the card is another.
        let mut updated = plan_on(&root, &manifest, "driver-2");
        assert_eq!(fallen(&updated), row("face", COREML, None));
        assert!(updated.unmeasured("face"));
        // What the new driver does is what is remembered from then on.
        assert!(!updated.measured("face", Some(20.0), Some(28.0)));
        assert!(!plan_on(&root, &manifest, "driver-2").unmeasured("face"));
        assert!(plan_on(&root, &manifest, "driver-1").unmeasured("face"));
        // A record saved before results named their device says nothing about this one.
        let record = root.join("provider-failures.json");
        std::fs::write(
            &record,
            format!(r#"{{"schemaVersion":1,"runtime":"{manifest}","failures":{{"face":"runtime_qualification_failed"}}}}"#),
        )
        .unwrap();
        assert_eq!(
            fallen(&plan_on(&root, &manifest, "driver-2")),
            row("face", COREML, None)
        );

        // A process that missed its readiness deadline moves its workloads to the processor for
        // this run, without a retry loop, and is tried again at the next start.
        for code in ["worker_execution_deadline", "runtime_not_ready"] {
            assert!(passing(code));
            let mut busy = plan_on(&root, &manifest, "driver-2");
            assert!(busy.demote_runtime(&manifest, code), "{code}");
            assert!(!busy.demote_runtime(&manifest, code), "{code}");
            assert_eq!(fallen(&busy), row("face", CPU, Some(code)));
            assert_eq!(
                fallen(&plan_on(&root, &manifest, "driver-2")),
                row("face", COREML, None),
                "{code}"
            );
        }
        // A process that died is the provider's failure and is remembered.
        assert!(!passing("runtime_process_stopped") && !passing("runtime_qualification_timeout"));
        let mut crashed = plan_on(&root, &manifest, "driver-2");
        assert!(crashed.demote_runtime(&manifest, "runtime_process_stopped"));
        let remembered = row("face", CPU, Some("runtime_process_stopped"));
        assert_eq!(fallen(&plan_on(&root, &manifest, "driver-2")), remembered);

        // Retry Setup forgets it: the provider is tried and measured again.
        forget(&root);
        assert!(!record.exists());
        let retried = plan_on(&root, &manifest, "driver-2");
        assert_eq!(fallen(&retried), row("face", COREML, None));
        assert!(retried.unmeasured("face") && retried.unmeasured("clip"));
        // Nothing to forget is not an error.
        forget(&root);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_dropped_connection_while_asking_for_the_accelerated_offer_is_retried() {
        // What the worker reconnects after ends the preparation, so the offer is asked again.
        for code in [
            "worker_request_interrupted",
            "server_response_interrupted",
            "server_unreachable_or_certificate_invalid",
            "worker_session_renewal_required",
            "server_http_503",
        ] {
            assert!(crate::worker_setup::retryable(code), "{code}");
            assert_eq!(inventory_failure(code.into()), Err(code.to_owned()));
        }
        // An answer that will not change by asking again is why the processor is used.
        for code in [
            "worker_model_inventory_invalid",
            "server_http_400",
            "server_http_404",
        ] {
            assert_eq!(inventory_failure(code.into()), Ok(code.to_owned()));
        }
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
        plan_on(root, manifest, "")
    }
    fn plan_on(root: &Path, manifest: &str, device: &str) -> Plan {
        Plan::new(
            vec![
                group("ViT-B-32__openai", CPU),
                group("PP-OCRv5_mobile", CPU),
                group("buffalo_s", CPU),
            ],
            Some(Offer {
                provider: COREML.into(),
                manifest_sha256: manifest.into(),
                device: device.into(),
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
        for unusable in [
            None,
            Some(0.0),
            Some(-1.0),
            Some(f64::NAN),
            Some(f64::INFINITY),
        ] {
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
        let loaded = Failures::load(&path, &manifest, "");
        assert_eq!(loaded.get("face"), Some("provider_failed"));
        let any: BTreeSet<String> = ["face:key".to_owned()].into();
        assert!(!loaded.is_faster("face", &any) && !loaded.is_faster("clip", &any));
        std::fs::write(
            &path,
            format!(r#"{{"schemaVersion":1,"runtime":"{manifest}","failures":{{}},"faster":["clip","video"]}}"#),
        )
        .unwrap();
        assert!(!Failures::load(&path, &manifest, "").is_faster("clip", &any));
        // A result saved before results named their models still loads (its failures hold) but
        // is not trusted: the workload is measured again.
        std::fs::write(
            &path,
            format!(r#"{{"schemaVersion":1,"runtime":"{manifest}","failures":{{"ocr":"provider_slower"}},"faster":["face"]}}"#),
        )
        .unwrap();
        let old = Failures::load(&path, &manifest, "");
        assert_eq!(old.get("ocr"), Some("provider_slower"));
        assert!(!old.is_faster("face", &any));
        let mut reopened = plan(&legacy, &manifest);
        assert!(reopened.unmeasured("face"));

        // The result is about the models that were measured. The server then offers another
        // face model with the same runtime: it is measured itself, not waved through.
        assert!(!reopened.measured("face", Some(20.0), Some(28.0)));
        assert!(!reopened.unmeasured("face"));
        let other_model = |root: &Path| {
            Plan::new(
                vec![group("buffalo_l", CPU)],
                Some(Offer {
                    provider: COREML.into(),
                    manifest_sha256: manifest.clone(),
                    device: String::new(),
                    groups: vec![group("buffalo_l", COREML)],
                }),
                None,
                &root.join("provider-failures.json"),
            )
        };
        let mut switched = other_model(&legacy);
        assert_eq!(chosen(&switched), [row("face", COREML, None)]);
        assert!(switched.unmeasured("face"));
        // Slower with this model: the processor, whatever the other model measured.
        assert!(switched.measured("face", Some(300.0), Some(200.0)));
        assert_eq!(
            chosen(&other_model(&legacy)),
            [row("face", CPU, Some("provider_slower"))]
        );
        // And measured faster with this model, the result does not carry back to the first.
        let fourth = directory();
        let mut second = other_model(&fourth);
        assert!(!second.measured("face", Some(30.0), Some(260.0)));
        assert!(!other_model(&fourth).unmeasured("face"));
        assert!(plan(&fourth, &manifest).unmeasured("face"));
        std::fs::remove_dir_all(fourth).unwrap();
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
                device: String::new(),
                groups: vec![group("buffalo_l", COREML)],
            }),
            None,
            &root.join("failures.json"),
        );
        assert_eq!(chosen(&other), [row("face", CPU, None)]);
        std::fs::remove_dir_all(root).unwrap();
    }
}
