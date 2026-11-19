#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Snapshot {
    pub external_power: Option<bool>,
    pub unmetered: Option<bool>,
    pub available_memory: Option<u64>,
}
impl Snapshot {
    /// Admission: a known battery or metered link refuses work. An unknown reading (no UPower or
    /// NetworkManager, no battery sensor) is not a restriction anyone chose and never blocks.
    pub fn refusal(&self, required_memory: u64) -> Option<&'static str> {
        if let Some(reason) = self.refusal_while_loaded() {
            return Some(reason);
        }
        match self.available_memory {
            None => Some("memory_unknown"),
            Some(bytes) if bytes < required_memory => Some("memory_low"),
            Some(_) => None,
        }
    }
    /// While the worker's own models are loaded, available memory already excludes them, so the
    /// memory floor is an admission check only: re-applying it would evict the worker it admitted.
    pub fn refusal_while_loaded(&self) -> Option<&'static str> {
        if self.external_power == Some(false) {
            return Some("on_battery");
        }
        if self.unmetered == Some(false) {
            return Some("metered_network");
        }
        None
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn sample() -> Snapshot {
    use block2::{Block, RcBlock};
    use core_foundation::{
        base::{CFType, TCFType},
        string::CFString,
    };
    use dispatch2::{DispatchQueue, DispatchRetained};
    use std::{ffi::c_void, sync::mpsc, time::Duration};
    unsafe extern "C" {
        fn mach_host_self() -> libc::mach_port_t;
        fn mach_port_deallocate(
            task: libc::mach_port_t,
            name: libc::mach_port_t,
        ) -> libc::kern_return_t;
        static mach_task_self_: libc::mach_port_t;
    }
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOPSCopyPowerSourcesInfo() -> *const c_void;
        fn IOPSGetProvidingPowerSourceType(snapshot: *const c_void) -> *const c_void;
    }
    #[link(name = "Network", kind = "framework")]
    unsafe extern "C" {
        fn nw_path_monitor_create() -> *mut c_void;
        fn nw_path_monitor_set_queue(monitor: *mut c_void, queue: *mut DispatchQueue);
        fn nw_path_monitor_set_update_handler(
            monitor: *mut c_void,
            handler: &Block<dyn Fn(*mut c_void)>,
        );
        fn nw_path_monitor_start(monitor: *mut c_void);
        fn nw_path_monitor_cancel(monitor: *mut c_void);
        fn nw_path_get_status(path: *mut c_void) -> i32;
        fn nw_path_is_expensive(path: *mut c_void) -> bool;
        fn nw_path_is_constrained(path: *mut c_void) -> bool;
        fn nw_release(object: *mut c_void);
    }
    let power = unsafe {
        let raw = IOPSCopyPowerSourcesInfo();
        if raw.is_null() {
            None
        } else {
            let info = CFType::wrap_under_create_rule(raw);
            let value = IOPSGetProvidingPowerSourceType(info.as_CFTypeRef());
            if value.is_null() {
                None
            } else {
                match CFString::wrap_under_get_rule(value.cast())
                    .to_string()
                    .as_str()
                {
                    "AC Power" => Some(true),
                    "Battery Power" => Some(false),
                    _ => None,
                }
            }
        }
    };
    let unmetered = unsafe {
        let monitor = nw_path_monitor_create();
        if monitor.is_null() {
            None
        } else {
            let queue = DispatchQueue::new("app.frameleaf.resource-policy", None);
            let (tx, rx) = mpsc::sync_channel(1);
            let handler = RcBlock::new(move |path: *mut c_void| {
                let state = if nw_path_get_status(path) == 1 {
                    Some(!nw_path_is_expensive(path) && !nw_path_is_constrained(path))
                } else {
                    None
                };
                let _ = tx.try_send(state);
            });
            nw_path_monitor_set_queue(monitor, DispatchRetained::as_ptr(&queue).as_ptr());
            nw_path_monitor_set_update_handler(monitor, &handler);
            nw_path_monitor_start(monitor);
            let state = rx.recv_timeout(Duration::from_secs(2)).ok().flatten();
            nw_path_monitor_cancel(monitor);
            nw_release(monitor);
            state
        }
    };
    let memory = unsafe {
        let host = mach_host_self();
        let mut stats: libc::vm_statistics64 = std::mem::zeroed();
        let mut count = libc::HOST_VM_INFO64_COUNT;
        let result = libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            (&mut stats as *mut libc::vm_statistics64).cast(),
            &mut count,
        );
        mach_port_deallocate(mach_task_self_, host);
        let page = libc::sysconf(libc::_SC_PAGESIZE);
        if result != libc::KERN_SUCCESS || count < libc::HOST_VM_INFO64_COUNT || page <= 0 {
            None
        } else {
            // Reclaimable inactive pages plus free pages match the native runtime's admission measure.
            (u64::from(stats.free_count) + u64::from(stats.inactive_count)).checked_mul(page as u64)
        }
    };
    Snapshot {
        external_power: power,
        unmetered,
        available_memory: memory,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn sample() -> Snapshot {
    use dbus::blocking::{stdintf::org_freedesktop_dbus::Properties, Connection};
    use std::{io::Read, time::Duration};
    let bus = Connection::new_system().ok();
    let power = bus.as_ref().and_then(|bus| {
        bus.with_proxy(
            "org.freedesktop.UPower",
            "/org/freedesktop/UPower",
            Duration::from_secs(2),
        )
        .get::<bool>("org.freedesktop.UPower", "OnBattery")
        .ok()
        .map(|battery| !battery)
    });
    let unmetered = bus.as_ref().and_then(|bus| {
        let value = bus
            .with_proxy(
                "org.freedesktop.NetworkManager",
                "/org/freedesktop/NetworkManager",
                Duration::from_secs(2),
            )
            .get::<u32>("org.freedesktop.NetworkManager", "Metered")
            .ok()?;
        match value {
            1 | 3 => Some(false),
            2 | 4 => Some(true),
            _ => None,
        }
    });
    let memory = (|| {
        let mut text = String::new();
        std::fs::File::open("/proc/meminfo")
            .ok()?
            .take(16384)
            .read_to_string(&mut text)
            .ok()?;
        let line = text
            .lines()
            .find_map(|line| line.strip_prefix("MemAvailable:"))?;
        line.split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()?
            .checked_mul(1024)
    })();
    Snapshot {
        external_power: power,
        unmetered,
        available_memory: memory,
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn sample() -> Snapshot {
    use windows::Networking::Connectivity::{NetworkCostType, NetworkInformation};
    use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};
    use windows_sys::Win32::System::{
        Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS},
        SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
    };
    let power = unsafe {
        let mut value: SYSTEM_POWER_STATUS = std::mem::zeroed();
        if GetSystemPowerStatus(&mut value) == 0 {
            None
        } else {
            match value.ACLineStatus {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            }
        }
    };
    let memory = unsafe {
        let mut value: MEMORYSTATUSEX = std::mem::zeroed();
        value.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut value) == 0 {
            None
        } else {
            Some(value.ullAvailPhys)
        }
    };
    let unmetered = (|| {
        struct Runtime;
        impl Drop for Runtime {
            fn drop(&mut self) {
                unsafe {
                    RoUninitialize();
                }
            }
        }
        unsafe {
            RoInitialize(RO_INIT_MULTITHREADED).ok()?;
        }
        let _runtime = Runtime;
        let profile = NetworkInformation::GetInternetConnectionProfile().ok()?;
        let cost = profile.GetConnectionCost().ok()?;
        let kind = cost.NetworkCostType().ok()?;
        if kind == NetworkCostType::Unknown {
            return None;
        }
        Some(
            kind == NetworkCostType::Unrestricted
                && !cost.Roaming().ok()?
                && !cost.OverDataLimit().ok()?
                && !cost.ApproachingDataLimit().ok()?,
        )
    })();
    Snapshot {
        external_power: power,
        unmetered,
        available_memory: memory,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires a supported desktop OS with live power/network services"]
    fn live_native_resource_probe_reports_bounded_platform_facts() {
        let started = std::time::Instant::now();
        let state = sample();
        assert!(started.elapsed() < std::time::Duration::from_secs(7));
        eprintln!(
            "power={:?} unmetered={:?} availableMemoryBytes={:?}",
            state.external_power, state.unmetered, state.available_memory
        );
        assert!(state.external_power.is_some());
        assert!(state.unmetered.is_some());
        assert!(state.available_memory.is_some_and(|bytes| bytes > 0));
    }
    #[test]
    fn balanced_requires_power_network_and_memory_before_admitting_work() {
        let ready = Snapshot {
            external_power: Some(true),
            unmetered: Some(true),
            available_memory: Some(4096),
        };
        assert_eq!(ready.refusal(4096), None);
        for (snapshot, expected) in [
            (
                Snapshot {
                    external_power: Some(false),
                    ..ready
                },
                "on_battery",
            ),
            (
                Snapshot {
                    unmetered: Some(false),
                    ..ready
                },
                "metered_network",
            ),
            (
                Snapshot {
                    available_memory: None,
                    ..ready
                },
                "memory_unknown",
            ),
            (
                Snapshot {
                    available_memory: Some(4095),
                    ..ready
                },
                "memory_low",
            ),
        ] {
            assert_eq!(snapshot.refusal(4096), Some(expected));
        }
    }
    #[test]
    fn unknown_power_or_network_state_does_not_block_work() {
        // Linux without UPower or NetworkManager reports neither; that must not park the worker.
        let unknown = Snapshot {
            external_power: None,
            unmetered: None,
            available_memory: Some(4096),
        };
        assert_eq!(unknown.refusal(4096), None);
        assert_eq!(unknown.refusal_while_loaded(), None);
        // A known restriction still wins over an unknown reading.
        let battery = Snapshot {
            external_power: Some(false),
            ..unknown
        };
        assert_eq!(battery.refusal(4096), Some("on_battery"));
        let metered = Snapshot {
            unmetered: Some(false),
            ..unknown
        };
        assert_eq!(metered.refusal_while_loaded(), Some("metered_network"));
    }
    #[test]
    fn the_memory_floor_is_not_reapplied_to_the_workers_own_loaded_models() {
        // Admitted with 4096 free; the loaded models then leave 512 "available".
        let loaded = Snapshot {
            external_power: Some(true),
            unmetered: Some(true),
            available_memory: Some(512),
        };
        assert_eq!(loaded.refusal(4096), Some("memory_low"));
        assert_eq!(loaded.refusal_while_loaded(), None);
        let unreadable = Snapshot {
            available_memory: None,
            ..loaded
        };
        assert_eq!(unreadable.refusal_while_loaded(), None);
    }
}
