//! OS process ownership; the Python gate opens only after this owner is installed.
use std::process::{Child, Command};

#[cfg(all(test, windows))]
#[path = "process_tree_windows_tests.rs"]
mod windows_tests;

#[cfg(unix)]
pub struct ProcessTree(i32);
#[cfg(windows)]
pub struct ProcessTree(std::os::windows::io::OwnedHandle);

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
