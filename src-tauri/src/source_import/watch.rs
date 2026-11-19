//! Reconcile an approved folder in the background using the verified copy executor.

use super::*;
use std::time::Duration;

const STATE: &str = "watch.json";
const SCAN_INTERVAL: Duration = if cfg!(test) {
    Duration::from_millis(5)
} else {
    Duration::from_secs(60)
};
/// The longest pause between attempts after repeated failures.
const MAX_BACKOFF: Duration = if cfg!(test) {
    Duration::from_millis(40)
} else {
    Duration::from_secs(15 * 60)
};
/// Verified keys kept in the state file itself; a signed journal file stays under 4 MiB.
const SEGMENT_KEYS: usize = 40_000;
const MAX_SEGMENTS: u32 = 4096;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchState {
    source: String,
    active: Option<String>,
    verified: BTreeSet<String>,
    /// Full sets of verified keys moved to their own signed files, so the record of what the
    /// server verified has no ceiling and a verified file is never sent again.
    #[serde(default, skip_serializing_if = "is_zero")]
    segments: u32,
}
fn is_zero(value: &u32) -> bool {
    *value == 0
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Segment {
    source: String,
    index: u32,
    keys: BTreeSet<String>,
}
fn segment_name(index: u32) -> String {
    format!("watch-verified-{index}.json")
}
/// The verified keys of every sealed segment, read once and kept while the watcher runs.
#[derive(Default)]
struct Sealed {
    segments: u32,
    keys: BTreeSet<String>,
}
impl Sealed {
    fn sync(
        &mut self,
        journal: &Journal,
        state: &WatchState,
        identity: &DeviceIdentity,
    ) -> Result<(), String> {
        if self.segments > state.segments {
            *self = Self::default();
        }
        while self.segments < state.segments {
            let segment: Segment = journal.read(&segment_name(self.segments), identity)?;
            if segment.source != state.source || segment.index != self.segments {
                return Err("source_journal_invalid".into());
            }
            self.keys.extend(segment.keys);
            self.segments += 1;
        }
        Ok(())
    }
}
impl WatchState {
    fn load(
        journal: &Journal,
        consent: &Consent,
        identity: &DeviceIdentity,
    ) -> Result<Self, String> {
        let state: Self = match fs::symlink_metadata(journal.root.join(STATE)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self {
                source: consent.source_id().into(),
                ..Self::default()
            },
            _ => journal.read(STATE, identity)?,
        };
        if state.source != consent.source_id()
            || state.active.as_deref().is_some_and(|id| !uuid(id))
            || state.verified.len() > SEGMENT_KEYS + crate::photo_sources::BATCH_FILES
            || state.segments > MAX_SEGMENTS
        {
            return Err("source_journal_invalid".into());
        }
        Ok(state)
    }

    fn record(&mut self, files: &[String], position: usize, skipped: &BTreeSet<usize>) {
        self.verified.extend(
            files[..position]
                .iter()
                .enumerate()
                .filter(|(index, _)| !skipped.contains(index))
                .map(|(_, key)| key.clone()),
        );
        self.active = None;
    }

    /// Moves a full set of verified keys into its own signed file. The segment is durable before
    /// the state that counts it, so a stop in between only rewrites the same segment.
    fn seal(
        &mut self,
        journal: &Journal,
        sealed: &mut Sealed,
        identity: &DeviceIdentity,
    ) -> Result<(), String> {
        if self.verified.len() < SEGMENT_KEYS {
            return Ok(());
        }
        if self.segments >= MAX_SEGMENTS {
            return Err("source_watch_history_full".into());
        }
        sealed.sync(journal, self, identity)?;
        let segment = Segment {
            source: self.source.clone(),
            index: self.segments,
            keys: std::mem::take(&mut self.verified),
        };
        journal.write(&segment_name(segment.index), &segment, identity)?;
        sealed.keys.extend(segment.keys);
        sealed.segments += 1;
        self.segments += 1;
        Ok(())
    }
}

fn file_key(file: &SourceFile) -> Result<String, String> {
    digest(&(
        &file.relative,
        file.watch_version
            .as_ref()
            .ok_or("source_journal_invalid")?,
    ))
}

pub(super) fn batch(journal: &Journal) -> Result<Journal, String> {
    let root = journal.root.join("watch-batch");
    crate::runtime_store::private_directory(&root)?;
    crate::runtime_store::private_directory(&root.join("stage"))?;
    Ok(Journal { root })
}

fn idle(consent: &Consent, state: &str) -> ImportView {
    ImportView {
        state: state.into(),
        source_id: consent.source_id().into(),
        ..ImportView::default()
    }
}

pub(super) fn status(
    base: &Path,
    saved: &SavedConnection,
    consent: &Consent,
    identity: &DeviceIdentity,
) -> Result<ImportView, String> {
    check_location(base, consent.approval(saved, identity)?)?;
    let journal = Journal::new(base, consent.source_id())?;
    status_at(&journal, saved, consent, identity)
}

fn status_at(
    journal: &Journal,
    saved: &SavedConnection,
    consent: &Consent,
    identity: &DeviceIdentity,
) -> Result<ImportView, String> {
    let state = WatchState::load(journal, consent, identity)?;
    if state.active.is_none() {
        return Ok(idle(consent, "watch-paused"));
    }
    let (manifest, cursor) = load(&batch(journal)?, identity, consent, saved)?;
    if state.active.as_deref() != Some(&manifest.id) {
        return Err("source_journal_invalid".into());
    }
    Ok(view(&manifest, &cursor, "watch-paused", None))
}

pub(super) fn history_run(
    journal: &Journal,
    saved: &SavedConnection,
    consent: &Consent,
    identity: &DeviceIdentity,
) -> Result<Option<(Manifest, Cursor)>, String> {
    let state = WatchState::load(journal, consent, identity)?;
    let batch = Journal {
        root: journal.root.join("watch-batch"),
    };
    let run = history::snapshot(&batch, saved, consent, identity)?;
    Ok(run.filter(|(manifest, cursor)| match &state.active {
        Some(id) => id == &manifest.id,
        None => cursor.state == "complete",
    }))
}

fn check_location(base: &Path, approval: &crate::copy_source::CopyApproval) -> Result<(), String> {
    if base.starts_with(approval.root()) || approval.root().starts_with(base) {
        return Err("source_staging_overlap".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prepare_batch(
    journal: &Journal,
    batch: &Journal,
    watch: &mut WatchState,
    sealed: &BTreeSet<String>,
    observed: &mut BTreeSet<String>,
    consent: &Consent,
    approval: &crate::copy_source::CopyApproval,
    identity: &DeviceIdentity,
) -> Result<bool, String> {
    use crate::photo_sources::{Pin, BATCH_FILES};
    let mut new = Vec::new();
    let mut latest = BTreeSet::new();
    // The folder is streamed: only one batch of unverified files is held, however large it is.
    let mut scan = crate::photo_sources::scan_each(
        approval.root(),
        Pin::Watched(approval.root_identity()),
        &mut |file| {
            if latest.len() == BATCH_FILES {
                return Ok(());
            }
            let key = file_key(&file)?;
            if !watch.verified.contains(&key) && !sealed.contains(&key) {
                // Wait for a second scan so a file still being written is not imported immediately.
                if observed.contains(&key) {
                    new.push(file);
                }
                latest.insert(key);
            }
            Ok(())
        },
    )?;
    if scan.inventory.truncated {
        return Err("source_inventory_partial".into());
    }
    *observed = latest;
    if new.is_empty() {
        return Ok(false);
    }
    new.sort_by(|a, b| a.relative.cmp(&b.relative));
    scan.files = new;
    let mut manifest = make_manifest(consent, approval, scan, None)?;
    // Availability from the full scan is not a summary of this incremental batch.
    manifest.availability = None;
    // With no committed batch, these slots may contain a completed batch or a pre-launch
    // checkpoint. Both have empty staging. The active id is durable before any server call.
    if fs::read_dir(batch.root.join("stage"))
        .map_err(|_| "source_journal_invalid")?
        .next()
        .is_some()
    {
        return Err("source_journal_invalid".into());
    }
    batch.write("manifest.json", &manifest, identity)?;
    batch.write("cursor.json", &Cursor::new(&manifest)?, identity)?;
    watch.active = Some(manifest.id);
    journal.write(STATE, watch, identity)?;
    Ok(true)
}

/// Failures that only the person can resolve: the approval, the signed-in account or server, or
/// the signed journal itself is no longer what was approved. Everything else (a busy disk or
/// server, a dropped connection, a full staging volume) may pass, so the watcher tries again.
fn needs_person(code: &str) -> bool {
    matches!(
        code,
        "source_approval_required"
            | "source_approval_changed"
            | "source_approval_invalid"
            | "source_root_changed"
            | "source_download_permission_required"
            | "source_control_invalid"
            | "source_staging_overlap"
            | "source_watch_local_required"
            | "source_folder_invalid"
            | "source_folder_excluded"
            | "source_choose_photo_subfolder"
            | "source_package_requires_provider"
            | "source_journal_invalid"
            | "source_journal_too_large"
            | "source_stage_invalid"
            | "source_stage_changed"
            | "source_receipt_invalid"
            | "source_upload_journal_invalid"
            | "source_upload_binding_invalid"
            | "source_upload_receipt_invalid"
            | "source_upload_budget_exhausted"
            | "source_upload_budget_required"
            | "source_run_changed"
            | "source_run_terminal"
            | "source_watch_history_full"
            | "server_identity_changed"
            | "account_identity_changed"
            | "sign_in_required"
    ) || code.starts_with("source_album_")
        || ["server_http_", "source_upload_http_"]
            .iter()
            .any(|prefix| matches!(code.strip_prefix(prefix), Some("401" | "403")))
}
fn retryable(code: &str) -> bool {
    !needs_person(code)
}
/// The pause before the next attempt: the scan interval, doubled after each failure in a row.
fn backoff(failures: u32) -> Duration {
    SCAN_INTERVAL
        .saturating_mul(1u32 << failures.min(16))
        .min(MAX_BACKOFF.max(SCAN_INTERVAL))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    client: &Client,
    origin: &url::Url,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    consent: &Consent,
    journal: &Journal,
    base: &Path,
    cancel: &AtomicBool,
    wake: &tokio::sync::Notify,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
    notify: &(dyn Fn(ImportView) + Sync),
    transfer: &ImportTransfer,
) -> Result<(), String> {
    let approval = consent.approval(saved, identity)?;
    let batch = batch(journal)?;
    let mut observed = BTreeSet::new();
    let mut sealed = Sealed::default();
    let mut backfill = true;
    let mut failures = 0;
    while !cancel.load(Ordering::Acquire) {
        let result = async {
            // Recheck the current session and pause state before inspecting any folder entries.
            gate()?;
            let mut watch = WatchState::load(journal, consent, identity)?;
            sealed.sync(journal, &watch, identity)?;
            if backfill && watch.active.is_none() {
                if let Ok(Some((manifest, cursor))) =
                    history::snapshot(&batch, saved, consent, identity)
                {
                    history::completed_watch(base, saved, identity, &manifest, &cursor);
                }
                backfill = false;
            }
            if watch.active.is_none()
                && !prepare_batch(
                    journal,
                    &batch,
                    &mut watch,
                    &sealed.keys,
                    &mut observed,
                    consent,
                    approval,
                    identity,
                )?
            {
                return Ok(());
            }
            let (manifest, cursor) = load(&batch, identity, consent, saved)?;
            if watch.active.as_deref() != Some(&manifest.id) {
                return Err("source_journal_invalid".into());
            }
            if !matches!(cursor.state.as_str(), "complete" | "cancelled") {
                let _permit = transfer.acquire(cancel, wake).await?;
                notify(view(&manifest, &cursor, "copying", None));
                let publish = |value: ImportView| {
                    if value.state != "needs-attention"
                        || !value.code.as_deref().is_some_and(retryable)
                    {
                        notify(value);
                    }
                };
                execute(
                    client, origin, saved, identity, consent, &batch, cancel, gate, &publish,
                )
                .await?;
            }
            let (_, cursor) = load(&batch, identity, consent, saved)?;
            if cursor.state != "complete" {
                return Err("source_run_terminal".into());
            }
            history::completed_watch(base, saved, identity, &manifest, &cursor);
            backfill = false;
            let keys = manifest
                .files
                .iter()
                .map(file_key)
                .collect::<Result<Vec<_>, _>>()?;
            watch.record(&keys, cursor.position, &cursor.watch_skipped);
            watch.seal(journal, &mut sealed, identity)?;
            journal.write(STATE, &watch, identity)?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                failures = 0;
                notify(idle(consent, "watching"));
            }
            Err(code) if cancel.load(Ordering::Acquire) => return Err(code),
            Err(code) if retryable(&code) => {
                failures += 1;
                observed.clear();
                // The stored state may itself be what could not be read; keep watching.
                let mut value = status_at(journal, saved, consent, identity)
                    .unwrap_or_else(|_| idle(consent, "watching"));
                value.state = "watching".into();
                value.code = Some(code);
                notify(value);
            }
            Err(code) => return Err(code),
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff(failures)) => {}
            _ = wake.notified() => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_inventory_retries_but_replaced_roots_require_approval() {
        assert!(retryable("source_inventory_unreadable"));
        assert!(retryable("source_inventory_partial"));
        assert!(!retryable("source_root_changed"));
    }

    /// A watched source folder with two photos, and its approval.
    fn watched() -> (PathBuf, SavedConnection, DeviceIdentity, Consent) {
        // Linux /tmp can be tmpfs, which is outside the watched-volume allowlist.
        #[cfg(target_os = "linux")]
        let fixture_parent = {
            let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
            fs::create_dir_all(&target).unwrap();
            target
        };
        #[cfg(not(target_os = "linux"))]
        let fixture_parent = std::env::temp_dir();
        let base = fs::canonicalize(fixture_parent)
            .unwrap()
            .join(format!("frameleaf-watch-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&base).unwrap();
        let source = base.join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("one.jpg"), b"first").unwrap();
        fs::write(source.join("two.jpg"), b"second").unwrap();
        let saved = SavedConnection {
            server: "https://nas.test/".into(),
            server_id: "nas".into(),
            account_id: "owner".into(),
            name: "Fixture".into(),
            token: "synthetic-token".into(),
            device_name: "Fixture".into(),
            mode: "client-worker".into(),
            device_id: Some("device".into()),
        };
        let identity = DeviceIdentity::generate();
        let picker = crate::source_consent::SourceConsent::default();
        let chosen = picker
            .select(picker.generation().unwrap(), source.clone())
            .unwrap();
        let mut consent = picker
            .approve(
                &saved,
                &identity,
                &chosen.selection_id,
                true,
                true,
                None,
                |_| Ok(()),
            )
            .unwrap();
        consent.registered = true;
        (base, saved, identity, consent)
    }

    #[test]
    fn the_watcher_keeps_running_after_a_transient_failure_and_backs_off() {
        assert!(retryable("source_stage_write_failed"));
        assert!(retryable("source_capacity_insufficient"));
        assert!(retryable("source_upload_capacity_exceeded"));
        assert!(retryable("server_http_404"));
        assert!(retryable("source_upload_http_503"));
        for code in [
            "source_approval_required",
            "source_journal_invalid",
            "server_identity_changed",
            "source_upload_budget_exhausted",
            "server_http_401",
            "source_upload_http_403",
            "source_album_unavailable_for_write",
        ] {
            assert!(!retryable(code), "{code}");
        }
        assert_eq!(backoff(0), SCAN_INTERVAL);
        assert_eq!(backoff(1), SCAN_INTERVAL * 2);
        assert!(backoff(2) > backoff(1));
        assert_eq!(backoff(40), MAX_BACKOFF);

        let (base, saved, identity, consent) = watched();
        let journal = Journal::new(&base, consent.source_id()).unwrap();
        let cancel = AtomicBool::new(false);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        // The first pass fails as a full staging disk would; the third is the person stopping.
        let gate = || match calls.fetch_add(1, Ordering::AcqRel) {
            0 => Err("source_stage_write_failed".into()),
            1 => Ok(()),
            _ => {
                cancel.store(true, Ordering::Release);
                Err("source_copy_cancelled".into())
            }
        };
        let seen = Mutex::new(Vec::new());
        let notify = |value: ImportView| seen.lock().unwrap().push((value.state, value.code));
        let result = tauri::async_runtime::block_on(run(
            &transport::client().unwrap(),
            &url::Url::parse("http://127.0.0.1:9/").unwrap(),
            &saved,
            &identity,
            &consent,
            &journal,
            &base,
            &cancel,
            &tokio::sync::Notify::new(),
            &gate,
            &notify,
            &ImportTransfer::default(),
        ));
        assert_eq!(result.unwrap_err(), "source_copy_cancelled");
        assert_eq!(
            *seen.lock().unwrap(),
            [
                (
                    "watching".to_string(),
                    Some("source_stage_write_failed".to_string())
                ),
                ("watching".to_string(), None),
            ]
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn the_verified_record_has_no_ceiling_and_sealed_files_are_never_selected_again() {
        let (base, saved, identity, consent) = watched();
        let approval = consent.approval(&saved, &identity).unwrap();
        let journal = Journal::new(&base, consent.source_id()).unwrap();
        let batch = batch(&journal).unwrap();
        let mut state = WatchState::load(&journal, &consent, &identity).unwrap();
        let mut sealed = Sealed::default();
        // More verified files than the old 50,000 ceiling, recorded a batch at a time.
        for round in 0..6 {
            let keys: Vec<String> = (0..10_000)
                .map(|index| format!("{:064x}", round * 10_000 + index))
                .collect();
            state.record(&keys, keys.len(), &BTreeSet::new());
            state.seal(&journal, &mut sealed, &identity).unwrap();
            journal.write(STATE, &state, &identity).unwrap();
        }
        assert_eq!((state.segments, state.verified.len()), (1, 20_000));
        assert_eq!(sealed.keys.len(), 40_000);

        // After a restart every verified key is known again.
        let mut state = WatchState::load(&journal, &consent, &identity).unwrap();
        let mut restored = Sealed::default();
        restored.sync(&journal, &state, &identity).unwrap();
        assert_eq!(restored.keys.len() + state.verified.len(), 60_000);
        assert!(restored.keys.contains(&format!("{:064x}", 0)));

        // A file whose verification lives only in a sealed segment is not imported again.
        let mut observed = BTreeSet::new();
        let none = BTreeSet::new();
        for _ in 0..2 {
            prepare_batch(
                &journal,
                &batch,
                &mut state,
                &none,
                &mut observed,
                &consent,
                approval,
                &identity,
            )
            .unwrap();
        }
        let manifest: Manifest = batch.read("manifest.json", &identity).unwrap();
        assert_eq!(manifest.files.len(), 2);
        let verified: BTreeSet<String> = manifest
            .files
            .iter()
            .map(|file| file_key(file).unwrap())
            .collect();
        state.active = None;
        let mut observed = BTreeSet::new();
        for _ in 0..2 {
            assert!(!prepare_batch(
                &journal,
                &batch,
                &mut state,
                &verified,
                &mut observed,
                &consent,
                approval,
                &identity
            )
            .unwrap());
        }
        assert!(observed.is_empty());

        // A segment that was replaced or belongs elsewhere is refused, not ignored.
        let other: Segment = journal.read(&segment_name(0), &identity).unwrap();
        journal
            .write(&segment_name(0), &Segment { index: 7, ..other }, &identity)
            .unwrap();
        assert!(Sealed::default().sync(&journal, &state, &identity).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn checkpoint_reconciles_new_files_and_refuses_a_replaced_root() {
        let (base, saved, identity, consent) = watched();
        let source = base.join("source");
        let approval = consent.approval(&saved, &identity).unwrap();
        let journal = Journal::new(&base, consent.source_id()).unwrap();
        let batch = batch(&journal).unwrap();
        let mut state = WatchState::load(&journal, &consent, &identity).unwrap();
        let mut observed = BTreeSet::new();
        assert!(!prepare_batch(
            &journal,
            &batch,
            &mut state,
            &BTreeSet::new(),
            &mut observed,
            &consent,
            approval,
            &identity
        )
        .unwrap());
        assert!(prepare_batch(
            &journal,
            &batch,
            &mut state,
            &BTreeSet::new(),
            &mut observed,
            &consent,
            approval,
            &identity
        )
        .unwrap());
        let manifest: Manifest = batch.read("manifest.json", &identity).unwrap();
        let versions = manifest
            .files
            .iter()
            .map(file_key)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        state.record(&versions, 2, &BTreeSet::from([1]));
        journal.write(STATE, &state, &identity).unwrap();

        fs::write(source.join("three.jpg"), b"new").unwrap();
        observed.clear(); // In-memory observations are rebuilt after restart.
        let mut state = WatchState::load(&journal, &consent, &identity).unwrap();
        let mut observed = BTreeSet::new();
        assert!(!prepare_batch(
            &journal,
            &batch,
            &mut state,
            &BTreeSet::new(),
            &mut observed,
            &consent,
            approval,
            &identity
        )
        .unwrap());
        assert!(prepare_batch(
            &journal,
            &batch,
            &mut state,
            &BTreeSet::new(),
            &mut observed,
            &consent,
            approval,
            &identity
        )
        .unwrap());
        let manifest: Manifest = batch.read("manifest.json", &identity).unwrap();
        assert_eq!(
            manifest
                .files
                .iter()
                .map(|file| file.relative.as_str())
                .collect::<Vec<_>>(),
            ["three.jpg", "two.jpg"]
        );

        fs::rename(&source, base.join("old")).unwrap();
        fs::create_dir(&source).unwrap();
        fs::write(source.join("private.jpg"), b"unapproved").unwrap();
        assert_eq!(
            crate::photo_sources::scan_batch(
                &source,
                crate::photo_sources::Pin::Watched(approval.root_identity()),
                None
            )
            .err()
            .as_deref(),
            Some("source_root_changed")
        );
        assert_eq!(fs::read(base.join("old/one.jpg")).unwrap(), b"first");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn only_verified_versions_are_remembered() {
        let mut watch = WatchState::default();
        let files = ["verified", "changed", "pending"].map(String::from);
        watch.record(&files, 2, &BTreeSet::from([1]));
        assert!(watch.verified.contains("verified"));
        assert!(!watch.verified.contains("changed"));
        assert!(!watch.verified.contains("pending"));
    }
}
