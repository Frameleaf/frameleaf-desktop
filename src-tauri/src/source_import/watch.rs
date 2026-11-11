//! Reconcile an approved folder in the background using the verified copy executor.

use super::*;
use std::time::Duration;

const STATE: &str = "watch.json";
const SCAN_INTERVAL: Duration = Duration::from_secs(60);
const MAX_VERIFIED: usize = 50_000;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchState {
    source: String,
    active: Option<String>,
    verified: BTreeSet<String>,
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
            || state.verified.len() > MAX_VERIFIED
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

fn check_location(base: &Path, approval: &crate::copy_source::CopyApproval) -> Result<(), String> {
    if base.starts_with(approval.root()) || approval.root().starts_with(base) {
        return Err("source_staging_overlap".into());
    }
    Ok(())
}

fn prepare_batch(
    journal: &Journal,
    batch: &Journal,
    watch: &mut WatchState,
    observed: &mut BTreeSet<String>,
    consent: &Consent,
    approval: &crate::copy_source::CopyApproval,
    identity: &DeviceIdentity,
) -> Result<bool, String> {
    let mut scan = crate::photo_sources::scan_approved(approval.root(), approval.root_identity())?;
    if scan.inventory.truncated {
        return Err("source_inventory_partial".into());
    }
    if scan.unreadable > 0 {
        return Err("source_inventory_unreadable".into());
    }
    let mut new = Vec::new();
    let mut latest = BTreeSet::new();
    for file in scan.files {
        let key = file_key(&file)?;
        if !watch.verified.contains(&key) {
            // Wait for a second scan so a file still being written is not imported immediately.
            if observed.contains(&key) {
                new.push(file);
            }
            latest.insert(key);
        }
    }
    *observed = latest;
    if new.is_empty() {
        return Ok(false);
    }
    if watch.verified.len() + new.len() > MAX_VERIFIED {
        return Err("source_watch_history_full".into());
    }
    scan.files = new;
    let mut manifest = make_manifest(consent, approval, scan)?;
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

fn retryable(code: &str) -> bool {
    matches!(
        code,
        "metered_network"
            | "network_unknown"
            | "source_server_processing"
            | "source_upload_interrupted"
            | "server_response_interrupted"
            | "source_item_changed"
            | "source_folder_unavailable"
            | "source_inventory_unreadable"
            | "source_inventory_partial"
            | "source_root_unavailable"
            | "runtime_file_unavailable"
    ) || ["server_http_", "source_upload_http_"]
        .iter()
        .any(|prefix| {
            code.strip_prefix(prefix)
                .and_then(|status| status.parse::<u16>().ok())
                .is_some_and(|status| status == 429 || (500..600).contains(&status))
        })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    client: &Client,
    origin: &url::Url,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    consent: &Consent,
    journal: &Journal,
    cancel: &AtomicBool,
    wake: &tokio::sync::Notify,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
    notify: &(dyn Fn(ImportView) + Sync),
    transfer: &ImportTransfer,
) -> Result<(), String> {
    let approval = consent.approval(saved, identity)?;
    let batch = batch(journal)?;
    let mut observed = BTreeSet::new();
    while !cancel.load(Ordering::Acquire) {
        let result = async {
            // Recheck the current session and pause state before inspecting any folder entries.
            gate()?;
            let mut watch = WatchState::load(journal, consent, identity)?;
            if watch.active.is_none()
                && !prepare_batch(
                    journal,
                    &batch,
                    &mut watch,
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
            let keys = manifest
                .files
                .iter()
                .map(file_key)
                .collect::<Result<Vec<_>, _>>()?;
            watch.record(&keys, cursor.position, &cursor.watch_skipped);
            journal.write(STATE, &watch, identity)?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => notify(idle(consent, "watching")),
            Err(code) if cancel.load(Ordering::Acquire) => return Err(code),
            Err(code) if retryable(&code) => {
                observed.clear();
                let mut value = status_at(journal, saved, consent, identity)?;
                value.state = "watching".into();
                value.code = Some(code);
                notify(value);
            }
            Err(code) => return Err(code),
        }
        tokio::select! {
            _ = tokio::time::sleep(SCAN_INTERVAL) => {}
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

    #[test]
    fn checkpoint_reconciles_new_files_and_refuses_a_replaced_root() {
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
            .approve(&saved, &identity, &chosen.selection_id, true, true, |_| {
                Ok(())
            })
            .unwrap();
        consent.registered = true;
        let approval = consent.approval(&saved, &identity).unwrap();
        let journal = Journal::new(&base, consent.source_id()).unwrap();
        let batch = batch(&journal).unwrap();
        let mut state = WatchState::load(&journal, &consent, &identity).unwrap();
        let mut observed = BTreeSet::new();
        assert!(!prepare_batch(
            &journal,
            &batch,
            &mut state,
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
            crate::photo_sources::scan_approved(&source, approval.root_identity())
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
