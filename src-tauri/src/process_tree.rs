//! OS process ownership; the Python gate opens only after this owner is installed.
use std::process::{Child, Command};

#[cfg(all(test, windows))]
#[path = "process_tree_windows_tests.rs"]
mod windows_tests;

#[cfg(unix)]
pub struct ProcessTree(i32);
#[cfg(windows)]
pub struct ProcessTree(std::os::windows::io::OwnedHandle);

/// What tells one process from a later one that reuses its PID: its start time and its program.
#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProcessIdentity {
    pub pid: u32,
    pub started: String,
    pub program: std::path::PathBuf,
}
/// What can be said about the process holding a PID right now. `Unknown` is its own answer:
/// a lookup that failed proves neither that the process exists nor that it is gone.
#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Presence {
    /// No live process has this PID.
    Absent,
    Present(ProcessIdentity),
    Unknown,
}
#[cfg(unix)]
impl ProcessIdentity {
    /// The identity of the live process with this PID, when it could be read.
    pub(crate) fn of(pid: u32) -> Option<Self> {
        match Self::lookup(pid) {
            Presence::Present(identity) => Some(identity),
            Presence::Absent | Presence::Unknown => None,
        }
    }
    pub(crate) fn lookup(pid: u32) -> Presence {
        // PID 0 and 1 and anything outside pid_t are never a child this app started; a record
        // naming one says nothing about the process it meant.
        let Some(raw) = i32::try_from(pid).ok().filter(|pid| *pid > 1) else {
            return Presence::Unknown;
        };
        #[cfg(target_os = "macos")]
        {
            let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
            let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
            if unsafe {
                libc::proc_pidinfo(
                    raw,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    info.as_mut_ptr().cast(),
                    size,
                )
            } != size
            {
                return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                    Presence::Absent
                } else {
                    Presence::Unknown
                };
            }
            let info = unsafe { info.assume_init() };
            if info.pbi_pid != pid {
                return Presence::Unknown;
            }
            // SZOMB: an exited process that has not been reaped is not alive.
            if info.pbi_status == 5 {
                return Presence::Absent;
            }
            let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
            let length =
                unsafe { libc::proc_pidpath(raw, path.as_mut_ptr().cast(), path.len() as u32) };
            if length <= 0 {
                return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                    Presence::Absent
                } else {
                    Presence::Unknown
                };
            }
            path.truncate(length as usize);
            let Ok(program) = String::from_utf8(path) else {
                return Presence::Unknown;
            };
            Presence::Present(Self {
                pid,
                started: format!("{}.{:06}", info.pbi_start_tvsec, info.pbi_start_tvusec),
                program: program.into(),
            })
        }
        #[cfg(target_os = "linux")]
        {
            let _ = raw;
            // Only "no such process" proves absence; any other failure is unknown.
            let gone = |error: &std::io::Error| {
                error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH)
            };
            let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(stat) => stat,
                Err(error) if gone(&error) => return Presence::Absent,
                Err(_) => return Presence::Unknown,
            };
            // The command name may contain spaces and brackets; fields resume after the last ')'.
            let Some(mut fields) = stat
                .rfind(')')
                .and_then(|end| stat.get(end + 1..))
                .map(str::split_ascii_whitespace)
            else {
                return Presence::Unknown;
            };
            match fields.next() {
                // An exited process that has not been reaped is not alive.
                Some("Z" | "X" | "x") => return Presence::Absent,
                Some(_) => {}
                None => return Presence::Unknown,
            }
            // Field 22 of proc(5) stat: start time in clock ticks since this boot.
            let Some(ticks) = fields.nth(18).filter(|ticks| {
                !ticks.is_empty() && ticks.bytes().all(|byte| byte.is_ascii_digit())
            }) else {
                return Presence::Unknown;
            };
            let Ok(boot) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") else {
                return Presence::Unknown;
            };
            let program = match std::fs::read_link(format!("/proc/{pid}/exe")) {
                Ok(program) => program,
                Err(error) if gone(&error) => return Presence::Absent,
                Err(_) => return Presence::Unknown,
            };
            Presence::Present(Self {
                pid,
                started: format!("{}:{ticks}", boot.trim()),
                program,
            })
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = raw;
            Presence::Unknown
        }
    }
}

pub fn configure(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        // A single bounded ML job must yield CPU time to foreground applications.
        unsafe {
            command.pre_exec(|| {
                if libc::getpriority(libc::PRIO_PROCESS, 0) >= 10
                    || libc::setpriority(libc::PRIO_PROCESS, 0, 10) == 0
                {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(
            0x08000000 | windows_sys::Win32::System::Threading::BELOW_NORMAL_PRIORITY_CLASS,
        );
    }
}
impl ProcessTree {
    #[cfg(windows)]
    pub(crate) fn terminate_confirmed(&self, timeout: std::time::Duration) -> Result<(), String> {
        use std::{os::windows::io::AsRawHandle, time::Instant};
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject, TerminateJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };
        let deadline = Instant::now() + timeout;
        let empty = || {
            let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            if unsafe {
                QueryInformationJobObject(
                    self.0.as_raw_handle(),
                    JobObjectBasicAccountingInformation,
                    (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    std::mem::size_of_val(&info) as u32,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err("runtime_process_shutdown_unconfirmed".to_string());
            }
            Ok(info.ActiveProcesses == 0)
        };
        if empty()? {
            return Ok(());
        }
        if unsafe { TerminateJobObject(self.0.as_raw_handle(), 1) } == 0 {
            return Err("runtime_process_shutdown_unconfirmed".into());
        }
        loop {
            if empty()? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("runtime_process_shutdown_unconfirmed".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Whether every process in the owned job has exited.
    #[cfg(windows)]
    pub(crate) fn is_empty(&self) -> Result<bool, String> {
        self.active().map(|active| active == 0)
    }

    /// How many live processes the owned job holds, whatever started them: a job that does
    /// not allow breakaway keeps every descendant, including those in jobs nested inside it.
    #[cfg(windows)]
    pub(crate) fn active(&self) -> Result<u32, String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        if unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err("runtime_process_state_unavailable".to_string());
        }
        Ok(info.ActiveProcesses)
    }

    /// Every process the owned job holds now, with the program each one runs. A program is
    /// reported only for a process that could be opened and is confirmed to be in this job
    /// through that handle, so an ID reused meanwhile is never mistaken for a member.
    #[cfg(windows)]
    pub(crate) fn members(&self) -> Result<Vec<(u32, Option<String>)>, String> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::{
            JobObjects::{IsProcessInJob, JobObjectBasicProcessIdList, QueryInformationJobObject},
            Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        };
        // JOBOBJECT_BASIC_PROCESS_ID_LIST: two 32-bit counts, then pointer-sized process IDs.
        // A job with more processes than fit fails the query, which is reported as unreadable.
        const LIMIT: usize = 256;
        let first = 8 / std::mem::size_of::<usize>();
        let mut list = vec![0usize; first + LIMIT];
        if unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectBasicProcessIdList,
                list.as_mut_ptr().cast(),
                std::mem::size_of_val(list.as_slice()) as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err("runtime_process_state_unavailable".into());
        }
        let (assigned, listed) = unsafe {
            let counts = list.as_ptr().cast::<u32>();
            (*counts as usize, *counts.add(1) as usize)
        };
        if listed != assigned || listed > LIMIT {
            return Err("runtime_process_state_unavailable".into());
        }
        Ok(list[first..first + listed]
            .iter()
            .map(|id| {
                let id = *id as u32;
                let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, id) };
                if raw.is_null() {
                    return (id, None);
                }
                let process = unsafe { OwnedHandle::from_raw_handle(raw) };
                let mut member = 0;
                let mut name = [0u16; 1024];
                let mut length = name.len() as u32;
                let known = unsafe {
                    IsProcessInJob(process.as_raw_handle(), self.0.as_raw_handle(), &mut member)
                        != 0
                        && member != 0
                        && QueryFullProcessImageNameW(
                            process.as_raw_handle(),
                            0,
                            name.as_mut_ptr(),
                            &mut length,
                        ) != 0
                };
                let program = known
                    .then(|| String::from_utf16(&name[..length as usize]).ok())
                    .flatten();
                (id, program)
            })
            .collect())
    }

    pub fn attach(child: &Child) -> Result<Self, String> {
        #[cfg(unix)]
        {
            Ok(Self(
                child
                    .id()
                    .try_into()
                    .map_err(|_| "runtime_process_invalid")?,
            ))
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsHandle;
            Self::attach_handle(child.as_handle())
        }
    }

    #[cfg(windows)]
    /// Apply the existing job ownership contract to native suspended-process handles too.
    pub(crate) fn attach_handle(
        child: std::os::windows::io::BorrowedHandle<'_>,
    ) -> Result<Self, String> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        // An unnamed non-inherited job terminates every child when this process loses ownership.
        unsafe {
            let raw = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if raw.is_null() {
                return Err("runtime_process_owner_failed".into());
            }
            let handle = OwnedHandle::from_raw_handle(raw);
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                raw,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of_val(&info) as u32,
            ) == 0
                || AssignProcessToJobObject(raw, child.as_raw_handle()) == 0
            {
                return Err("runtime_process_owner_failed".into());
            }
            Ok(Self(handle))
        }
    }
    pub fn terminate(&self) {
        #[cfg(unix)]
        // Each child is created in its own group; a negative PID addresses only that group.
        unsafe {
            libc::kill(-self.0, libc::SIGKILL);
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            unsafe {
                windows_sys::Win32::System::JobObjects::TerminateJobObject(
                    self.0.as_raw_handle(),
                    1,
                );
            }
        }
    }
}
