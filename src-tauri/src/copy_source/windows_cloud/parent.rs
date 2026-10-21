//! The parent owns policy checks and the reader's Job; no credentials cross the pipe.
use super::{Copied, Event, Progress, Request};
use crate::process_tree::{self, ProcessTree};
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
static UNCERTAIN_SHUTDOWN: AtomicBool = AtomicBool::new(false);
const MAX_EVENT_BYTES: u64 = 4096;

pub(super) fn run(
    request: &Request,
    cancelled: &AtomicBool,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
) -> Result<Copied, String> {
    if UNCERTAIN_SHUTDOWN.load(Ordering::Acquire) {
        return Err("source_copy_shutdown_unconfirmed".into());
    }
    request.validate()?;
    super::super::cancel(cancelled)?;
    gate()?;
    let input = serde_json::to_vec(request).map_err(|_| "source_child_request_invalid")?;
    if input.len() > super::MAX_REQUEST_BYTES {
        return Err("source_child_request_invalid".into());
    }
    let executable = std::env::current_exe().map_err(|_| "source_copy_interrupted")?;
    #[cfg(test)]
    let executable = executable
        .parent()
        .and_then(|deps| deps.parent())
        .ok_or("source_copy_interrupted")?
        .join("frameleaf-desktop.exe");
    let system_root = std::env::var_os("SystemRoot").ok_or("source_copy_interrupted")?;
    let mut command = Command::new(executable);
    command
        .arg("--source-read")
        .env_clear()
        .env("SystemRoot", &system_root)
        .env("WINDIR", &system_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    process_tree::configure(&mut command);
    let mut child = command.spawn().map_err(|_| "source_copy_interrupted")?;
    let tree = match ProcessTree::attach(&child) {
        Ok(tree) => tree,
        Err(_) => {
            use std::os::windows::io::AsRawHandle;
            let _ = child.kill();
            if unsafe {
                windows_sys::Win32::System::Threading::WaitForSingleObject(
                    child.as_raw_handle(),
                    5000,
                )
            } != windows_sys::Win32::Foundation::WAIT_OBJECT_0
            {
                UNCERTAIN_SHUTDOWN.store(true, Ordering::Release);
                return Err("source_copy_shutdown_unconfirmed".into());
            }
            let _ = child.wait();
            return Err("source_copy_interrupted".into());
        }
    };
    let (sender, receiver) = mpsc::sync_channel::<Result<Option<Event>, String>>(2);
    let mut writer = None;
    let mut reader = None;
    let result = (|| {
        let mut stdin = child.stdin.take().ok_or("source_copy_interrupted")?;
        let stdout = child.stdout.take().ok_or("source_copy_interrupted")?;
        writer = Some(
            thread::Builder::new()
                .name("source input".into())
                .spawn(move || stdin.write_all(&input))
                .map_err(|_| "source_copy_interrupted")?,
        );
        reader = Some(
            thread::Builder::new()
                .name("source progress".into())
                .spawn(move || {
                    let mut stream = BufReader::new(stdout);
                    loop {
                        let mut line = Vec::new();
                        let message = match (&mut stream)
                            .take(MAX_EVENT_BYTES + 1)
                            .read_until(b'\n', &mut line)
                        {
                            Ok(0) => Ok(None),
                            Ok(_)
                                if line.len() as u64 <= MAX_EVENT_BYTES
                                    && line.last() == Some(&b'\n') =>
                            {
                                serde_json::from_slice(&line)
                                    .map(Some)
                                    .map_err(|_| "source_copy_interrupted".into())
                            }
                            _ => Err("source_copy_interrupted".into()),
                        };
                        let done = !matches!(message, Ok(Some(_)));
                        if sender.send(message).is_err() || done {
                            break;
                        }
                    }
                })
                .map_err(|_| "source_copy_interrupted")?,
        );
        let mut progress = Progress::new(request);
        let mut complete = None;
        let mut eof = false;
        let mut next_gate = Instant::now();
        loop {
            super::super::cancel(cancelled)?;
            if Instant::now() >= next_gate {
                gate()?;
                next_gate = Instant::now() + Duration::from_secs(1);
            }
            let status = child.try_wait().map_err(|_| "source_copy_interrupted")?;
            if let Some(status) = status {
                if !status.success() {
                    return Err("source_copy_interrupted".into());
                }
                if eof {
                    return complete.ok_or_else(|| "source_copy_interrupted".into());
                }
            }
            if eof {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(Some(event))) => {
                    if let Some(value) = progress.accept(event)? {
                        complete = Some(value);
                    }
                }
                Ok(Ok(None)) => eof = true,
                Ok(Err(code)) => return Err(code),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("source_copy_interrupted".into())
                }
            }
        }
    })();
    let stopped = tree.terminate_confirmed(Duration::from_secs(5));
    if stopped.is_err() {
        // Closing the Job still requests termination; keep private staging and refuse another reader.
        UNCERTAIN_SHUTDOWN.store(true, Ordering::Release);
        drop(receiver);
        return Err("source_copy_shutdown_unconfirmed".into());
    }
    let joined = child.wait().is_ok();
    drop(receiver);
    let written = writer.is_none_or(|thread| thread.join().is_ok_and(|result| result.is_ok()));
    let drained = reader.is_none_or(|thread| thread.join().is_ok());
    if !joined || !drained || (result.is_ok() && !written) {
        return Err("source_copy_interrupted".into());
    }
    let copied = result?;
    super::super::cancel(cancelled)?;
    gate()?;
    Ok(copied)
}
