//! Runs only in the native Apple Silicon qualification harness.
use super::VerifiedHostRuntime;
use crate::{native_runtime, process_tree, release_policy, runtime_store};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};

const RUNNER: &str = include_str!("../../runtime/studio-voiceover-qualification.mjs");
const MAX_WAV_BYTES: usize = 44 + 30 * 24_000 * 4;
const PREVIEW_LIMIT: Duration = Duration::from_secs(65);
const OPTIONAL_ROOT: &str = "studio/kokoro";
const CANDIDATE: &str = "studio/kokoro/app/studio/tools/qualification/fd36-kokoro/candidate.mjs";

#[derive(Clone, Copy)]
enum Voice {
    Heart,
    Bella,
}

impl Voice {
    fn id(self) -> &'static str {
        match self {
            Self::Heart => "af_heart",
            Self::Bella => "af_bella",
        }
    }
}

fn preview(
    host: &VerifiedHostRuntime,
    voice: Voice,
    script: &str,
    cancelled: &AtomicBool,
    started: impl FnOnce(),
) -> Result<Vec<u8>, String> {
    if cancelled.load(Ordering::Acquire) {
        return Err("host_voiceover_preview_cancelled".into());
    }
    if script.trim().is_empty() || script.encode_utf16().count() > 400 || script.contains('\0') {
        return Err("host_voiceover_script_invalid".into());
    }
    if !host.manifest.files.contains_key(CANDIDATE) {
        return Err("host_voiceover_candidate_unavailable".into());
    }

    let mut command = Command::new(host.root.join(&host.manifest.entry_points.node));
    command
        .current_dir(host.root.join(OPTIONAL_ROOT))
        .env_clear()
        .args(["--input-type=module", "-e", RUNNER, voice.id()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    process_tree::configure(&mut command);
    let mut child = command.spawn().map_err(|_| "host_voiceover_start_failed")?;
    let group = match process_tree::ProcessTree::attach(&child) {
        Ok(group) => group,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let result = (|| {
        child
            .stdin
            .take()
            .ok_or("host_voiceover_pipe_failed")?
            .write_all(script.as_bytes())
            .map_err(|_| "host_voiceover_pipe_failed")?;
        let stdout = child.stdout.take().ok_or("host_voiceover_pipe_failed")?;
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take((MAX_WAV_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = sender.send(result);
        });
        started();
        let deadline = Instant::now() + PREVIEW_LIMIT;
        let mut audio = None;
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err("host_voiceover_preview_cancelled".into());
            }
            if Instant::now() >= deadline {
                return Err("host_voiceover_preview_timeout".into());
            }
            if audio.is_none() {
                match receiver.try_recv() {
                    Ok(Ok(wav))
                        if (45..=MAX_WAV_BYTES).contains(&wav.len())
                            && wav.starts_with(b"RIFF") =>
                    {
                        audio = Some(wav);
                    }
                    Ok(_) | Err(TryRecvError::Disconnected) => {
                        return Err("host_voiceover_preview_invalid".into());
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|_| "host_voiceover_preview_failed")?
            {
                if !status.success() {
                    return Err("host_voiceover_preview_failed".into());
                }
                if let Some(wav) = audio.take() {
                    return Ok(wav);
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    if result.is_err() {
        group.terminate();
        let _ = child.wait();
    }
    result
}

fn verify_candidate(candidate: &Path) -> Result<VerifiedHostRuntime, String> {
    native_runtime::absolute_directory(candidate)?;
    let manifest = runtime_store::read_bounded(&candidate.join("manifest.json"), 16 * 1024 * 1024)?;
    let signature: [u8; 64] = runtime_store::read_bounded(&candidate.join("manifest.sig"), 64)?
        .try_into()
        .map_err(|_| "host_signature_invalid")?;
    release_policy::verify_host_runtime(&candidate.join("payload"), &manifest, &signature)
}

#[test]
#[ignore = "requires a private Apple Silicon host candidate signed by compiled release authority"]
fn signed_apple_silicon_voiceover_previews_and_cancels() {
    let candidate = std::env::var_os("FRAMELEAF_STUDIO_VOICEOVER_SIGNED_CANDIDATE")
        .expect("signed qualification candidate directory");
    let host = verify_candidate(Path::new(&candidate)).expect("verify signed host candidate");
    let cancelled = AtomicBool::new(false);
    let script = "These photographs show the first snow of the year.";
    let heart = preview(&host, Voice::Heart, script, &cancelled, || {}).expect("Heart preview");
    let bella = preview(&host, Voice::Bella, script, &cancelled, || {}).expect("Bella preview");
    for wav in [&heart, &bella] {
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[22..24], &1_u16.to_le_bytes());
        assert_eq!(&wav[24..28], &24_000_u32.to_le_bytes());
    }
    assert_ne!(heart, bella);
    assert_eq!(
        preview(&host, Voice::Heart, script, &cancelled, || {
            cancelled.store(true, Ordering::Release);
        })
        .unwrap_err(),
        "host_voiceover_preview_cancelled"
    );
    println!(
        "Kokoro qualification manifest={} af_heart={:x} af_bella={:x} cancellation=passed",
        host.manifest_sha256(),
        Sha256::digest(&heart),
        Sha256::digest(&bella),
    );
}
