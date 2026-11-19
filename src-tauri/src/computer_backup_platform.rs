//! FD-77: what Computer backup needs from each OS: the background agent (launchd on macOS, the Task
//! Scheduler on Windows), Touch ID or Windows Hello before the recovery key is shown, the macOS Full Disk
//! Access check, battery power, and on Windows a Volume Shadow Copy so open files are read as they were.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------- one run at a time

/// Held while a backup runs; a second agent started meanwhile exits at once. The file is created
/// exclusively and holds the pid; one left by a crashed run is taken over once that process is gone.
pub(crate) struct RunLock(PathBuf);

impl RunLock {
    pub(crate) fn take(path: &Path) -> Result<RunLock, ()> {
        for _ in 0..2 {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    let _ = write!(file, "{}", std::process::id());
                    return Ok(RunLock(path.to_path_buf()));
                }
                Err(_) => {
                    let pid = fs::read_to_string(path)
                        .ok()
                        .and_then(|text| text.trim().parse::<u32>().ok());
                    if pid.is_some_and(alive) {
                        return Err(());
                    }
                    let _ = fs::remove_file(path);
                }
            }
        }
        Err(())
    }
}

impl Drop for RunLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(unix)]
fn alive(pid: u32) -> bool {
    // Signal 0 checks the process exists without touching it.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(windows)]
fn alive(pid: u32) -> bool {
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains(&pid.to_string()))
}

// ---------------------------------------------------------------- the computer

pub(crate) fn os() -> &'static str {
    if cfg!(target_os = "macos") {
        "mac"
    } else if cfg!(windows) {
        "windows"
    } else {
        "linux"
    }
}

pub(crate) fn platform() -> String {
    format!(
        "desktop/{}",
        if cfg!(target_os = "macos") {
            "macos"
        } else {
            std::env::consts::OS
        }
    )
}

/// The name people gave this computer: System Settings › General › Sharing on a Mac.
pub(crate) fn computer_name() -> String {
    #[cfg(target_os = "macos")]
    if let Ok(out) = Command::new("scutil")
        .args(["--get", "ComputerName"])
        .output()
    {
        let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !name.is_empty() {
            return name.chars().filter(|c| !c.is_control()).take(100).collect();
        }
    }
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "This computer".into())
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect()
}

/// On battery right now. Unknown counts as plugged in, so a desktop never waits.
pub(crate) fn on_battery() -> bool {
    #[cfg(target_os = "macos")]
    return Command::new("pmset")
        .args(["-g", "batt"])
        .output()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("'Battery Power'"));
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
        let mut status: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
        // ACLineStatus 0 is offline (on battery); 1 online; 255 unknown.
        return unsafe { GetSystemPowerStatus(&mut status) } != 0 && status.ACLineStatus == 0;
    }
    #[allow(unreachable_code)]
    false
}

// ---------------------------------------------------------------- Full Disk Access (macOS)

/// Whether macOS lets this app read protected places. TCC's own database is readable only with Full Disk
/// Access, so opening it is the usual check.
pub(crate) fn full_disk_access() -> bool {
    #[cfg(target_os = "macos")]
    return fs::File::open(
        crate::computer_backup::home().join("Library/Application Support/com.apple.TCC/TCC.db"),
    )
    .is_ok();
    #[allow(unreachable_code)]
    true
}

pub(crate) fn open_full_disk_access_settings() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    return Command::new("open")
        .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
        .status()
        .map(drop)
        .map_err(|_| "computer_backup_settings_unavailable".into());
    #[allow(unreachable_code)]
    Ok(())
}

// ---------------------------------------------------------------- the owner is here

#[cfg(target_os = "macos")]
extern "C" {
    fn frameleaf_confirm_owner(reason: *const std::ffi::c_char) -> bool;
}

/// Touch ID or the Mac's password; Windows Hello. False when the person cancels or it isn't set up.
pub(crate) fn confirm_owner(reason: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        let reason = std::ffi::CString::new(reason).unwrap_or_default();
        return unsafe { frameleaf_confirm_owner(reason.as_ptr()) };
    }
    #[cfg(windows)]
    {
        use windows::core::HSTRING;
        use windows::Security::Credentials::UI::{
            UserConsentVerificationResult, UserConsentVerifier,
        };
        return UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(reason))
            .and_then(|operation| operation.get())
            .is_ok_and(|result| result == UserConsentVerificationResult::Verified);
    }
    // ponytail: Linux has no common prompt; the desktop session itself is the check there.
    #[allow(unreachable_code)]
    {
        let _ = reason;
        true
    }
}

// ---------------------------------------------------------------- the background agent

const LABEL: &str = "app.frameleaf.desktop.computer-backup";
#[cfg(windows)]
const TASK: &str = "Frameleaf\\Computer Backup";

#[cfg(target_os = "macos")]
fn plist_path() -> PathBuf {
    crate::computer_backup::home().join(format!("Library/LaunchAgents/{LABEL}.plist"))
}

/// The plist launchd runs every 15 minutes, and once at log-in.
pub(crate) fn launch_agent_plist(exe: &Path) -> String {
    let escape = |text: &str| {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{}</string><string>{}</string></array>
  <key>StartInterval</key><integer>900</integer>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>10</integer>
</dict>
</plist>
"#,
        escape(&exe.to_string_lossy()),
        crate::computer_backup::AGENT_FLAG
    )
}

/// Starts the agent with the OS. On Windows it asks once for administrator rights, so the agent may
/// take a Volume Shadow Copy; declined, it still runs, reading open files as they are.
pub(crate) fn install_agent() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|_| "computer_backup_agent_failed")?;
    #[cfg(target_os = "macos")]
    {
        let path = plist_path();
        fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))
            .map_err(|_| "computer_backup_agent_failed")?;
        fs::write(&path, launch_agent_plist(&exe)).map_err(|_| "computer_backup_agent_failed")?;
        let domain = format!("gui/{}", unsafe { libc::getuid() });
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{LABEL}")])
            .status();
        let ok = Command::new("launchctl")
            .args(["bootstrap", &domain])
            .arg(&path)
            .status()
            .is_ok_and(|s| s.success());
        return if ok {
            Ok(())
        } else {
            Err("computer_backup_agent_failed".into())
        };
    }
    #[cfg(windows)]
    {
        let run = format!(
            "\"{}\" {}",
            exe.display(),
            crate::computer_backup::AGENT_FLAG
        );
        let args = [
            "/Create", "/F", "/SC", "MINUTE", "/MO", "15", "/TN", TASK, "/TR", &run,
        ];
        // Elevated: the task runs with this user's highest rights, which VSS needs.
        let list = args
            .iter()
            .chain(["/RL", "HIGHEST"].iter())
            .map(|a| format!("'{}'", a.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(",");
        let elevated = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &format!("$p = Start-Process schtasks -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList @({list}); exit $p.ExitCode")])
            .status()
            .is_ok_and(|s| s.success());
        if elevated
            || Command::new("schtasks")
                .args(args)
                .status()
                .is_ok_and(|s| s.success())
        {
            return Ok(());
        }
        return Err("computer_backup_agent_failed".into());
    }
    // ponytail: no agent on Linux yet; backups run while the app is open (Back Up Now).
    #[allow(unreachable_code)]
    {
        let _ = exe;
        Ok(())
    }
}

pub(crate) fn remove_agent() {
    #[cfg(target_os = "macos")]
    {
        let domain = format!("gui/{}", unsafe { libc::getuid() });
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{LABEL}")])
            .status();
        let _ = fs::remove_file(plist_path());
    }
    #[cfg(windows)]
    {
        let _ = Command::new("schtasks")
            .args(["/Delete", "/F", "/TN", TASK])
            .status();
    }
}

/// Back Up Now: the agent, started at once and left to finish even if the window closes.
pub(crate) fn start_agent_now() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|_| "computer_backup_agent_failed")?;
    let mut command = Command::new(exe);
    command.args([crate::computer_backup::AGENT_FLAG, "--now"]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0008); // CREATE_NO_WINDOW | DETACHED_PROCESS
    }
    command
        .spawn()
        .map(drop)
        .map_err(|_| "computer_backup_agent_failed".into())
}

// ---------------------------------------------------------------- open files (Windows)

/// A Volume Shadow Copy of each volume the chosen folders are on, deleted when dropped. Elsewhere, and
/// when Windows refuses (no administrator rights), files are read where they are.
pub(crate) struct OpenFiles {
    #[allow(dead_code)]
    shadows: Vec<(String, String, String)>, // (volume root, shadow id, device path)
}

impl OpenFiles {
    pub(crate) fn take(folders: Vec<PathBuf>) -> OpenFiles {
        #[cfg(windows)]
        {
            let mut volumes: Vec<String> = folders
                .iter()
                .filter_map(|folder| {
                    folder
                        .to_string_lossy()
                        .get(..3)
                        .map(|root| root.to_uppercase())
                })
                .filter(|root| root.ends_with(":\\"))
                .collect();
            volumes.dedup();
            let shadows = volumes
                .into_iter()
                .filter_map(|volume| shadow(&volume).map(|(id, device)| (volume, id, device)))
                .collect();
            return OpenFiles { shadows };
        }
        #[allow(unreachable_code)]
        {
            let _ = folders;
            OpenFiles {
                shadows: Vec::new(),
            }
        }
    }

    /// Where to read `folder` from: inside its volume's shadow copy, or the folder itself.
    pub(crate) fn read_path(&self, folder: &Path) -> PathBuf {
        let text = folder.to_string_lossy();
        for (volume, _, device) in &self.shadows {
            if text.to_uppercase().starts_with(volume.as_str()) {
                return PathBuf::from(format!(
                    "{}\\{}",
                    device.trim_end_matches('\\'),
                    &text[volume.len()..]
                ));
            }
        }
        folder.to_path_buf()
    }
}

#[cfg(windows)]
fn powershell(script: &str) -> Option<String> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// (shadow id, `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`)
#[cfg(windows)]
fn shadow(volume: &str) -> Option<(String, String)> {
    let script = format!(
        "$r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{{Volume='{volume}'; Context='ClientAccessible'}}; \
         if ($r.ReturnValue -ne 0) {{ exit 1 }}; \
         $s = Get-CimInstance Win32_ShadowCopy | Where-Object {{ $_.ID -eq $r.ShadowID }}; \
         Write-Output \"$($s.ID)|$($s.DeviceObject)\""
    );
    let line = powershell(&script)?;
    let (id, device) = line.split_once('|')?;
    Some((
        id.to_string(),
        format!(
            "\\\\?\\GLOBALROOT{}",
            device.trim_start_matches("\\\\?\\GLOBALROOT")
        ),
    ))
}

impl Drop for OpenFiles {
    fn drop(&mut self) {
        #[cfg(windows)]
        for (_, id, _) in &self.shadows {
            let id = id.replace('\'', "");
            let _ = powershell(&format!("Get-CimInstance Win32_ShadowCopy | Where-Object {{ $_.ID -eq '{id}' }} | Remove-CimInstance"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_launch_agent_runs_the_backup_every_quarter_hour() {
        let plist = launch_agent_plist(Path::new(
            "/Applications/Frameleaf.app/Contents/MacOS/frameleaf-desktop",
        ));
        assert!(plist.contains("<string>/Applications/Frameleaf.app/Contents/MacOS/frameleaf-desktop</string><string>--computer-backup</string>"));
        assert!(plist.contains("<key>StartInterval</key><integer>900</integer>"));
    }

    #[test]
    fn one_run_holds_the_lock_and_a_dead_holder_is_taken_over() {
        let path =
            std::env::temp_dir().join(format!("frameleaf-run-lock-{}", uuid::Uuid::new_v4()));
        let held = RunLock::take(&path).unwrap();
        assert!(RunLock::take(&path).is_err());
        drop(held);
        fs::write(&path, "999999999").unwrap();
        assert!(RunLock::take(&path).is_ok());
    }

    #[test]
    fn folders_outside_a_shadow_copy_are_read_in_place() {
        let open = OpenFiles {
            shadows: vec![(
                "C:\\".into(),
                "{id}".into(),
                "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3".into(),
            )],
        };
        assert_eq!(
            open.read_path(Path::new("C:\\Users\\Pat\\Documents")),
            PathBuf::from(
                "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3\\Users\\Pat\\Documents"
            )
        );
        assert_eq!(
            open.read_path(Path::new("D:\\Work")),
            PathBuf::from("D:\\Work")
        );
        std::mem::forget(open);
    }
}
