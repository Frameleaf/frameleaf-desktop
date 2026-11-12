//! Read-only history summaries. Only the current signed journal can authorize a retry.
use super::*;

const FILE: &str = "history.json";
const MAX_ARCHIVED: usize = 100;
static ARCHIVE: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Kind {
    Folder,
    Camera,
    Watch,
    Drop,
}

impl Kind {
    pub(super) fn for_consent(credential: &str, consent: &Consent) -> Self {
        if credential == crate::drop_import::CREDENTIAL {
            Self::Drop
        } else if consent.watch {
            Self::Watch
        } else if consent.camera() {
            Self::Camera
        } else {
            Self::Folder
        }
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum Status {
    Ready,
    Running,
    Interrupted,
    Complete,
    Cancelled,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Entry {
    run_id: String,
    kind: Kind,
    status: Status,
    created_at: Option<u64>,
    album: Option<String>,
    verified: usize,
    total: usize,
    skipped: u64,
    /// How many of the skipped files have a known reason, by reason code. Never a filename.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    skipped_reasons: BTreeMap<String, u64>,
    album_pending: bool,
    can_retry: bool,
}

impl Entry {
    pub(super) fn from_run(kind: Kind, manifest: &Manifest, cursor: &Cursor, active: bool) -> Self {
        let status = match cursor.state.as_str() {
            // A finished batch of a larger folder is one step of an import that is still going.
            "complete" if continues(manifest, cursor) && active => Status::Running,
            "complete" if continues(manifest, cursor) => Status::Interrupted,
            "complete" => Status::Complete,
            "cancelled" => Status::Cancelled,
            _ if active => Status::Running,
            "ready" => Status::Ready,
            _ => Status::Interrupted,
        };
        let view = view(manifest, cursor, "", None);
        Self {
            run_id: manifest.id.clone(),
            kind,
            status,
            created_at: manifest.created_at,
            album: manifest
                .destination
                .as_ref()
                .map(|album| album.name.clone()),
            verified: view.completed,
            total: view.total,
            skipped: view.skipped,
            skipped_reasons: skipped_reasons(manifest, cursor),
            album_pending: view.album_pending,
            can_retry: status == Status::Interrupted && cursor.upload_budget.is_some(),
        }
    }

    fn retired(mut self) -> Self {
        if matches!(self.status, Status::Ready | Status::Running) {
            self.status = Status::Interrupted;
        }
        self.can_retry = false;
        self
    }

    fn permits_retry(&self, kind: Kind, run_id: &str) -> bool {
        self.can_retry && self.kind == kind && self.run_id == run_id
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    scope: String,
    entries: Vec<Entry>,
}

fn scope(saved: &SavedConnection, identity: &DeviceIdentity) -> Result<String, String> {
    digest(&(
        &saved.server,
        &saved.server_id,
        &saved.account_id,
        &saved.device_id,
        identity.sign(&format!(
            "frameleaf-desktop/import-history-session/v1\n{}",
            saved.token
        )),
    ))
}

fn archive(base: &Path, scope: &str) -> Journal {
    Journal {
        root: base.join("photo-import-history").join(scope),
    }
}

fn read(journal: &Journal, scope: &str, identity: &DeviceIdentity) -> Result<Archive, String> {
    let value: Archive = match fs::symlink_metadata(journal.root.join(FILE)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Archive {
            scope: scope.into(),
            entries: Vec::new(),
        },
        _ => journal.read(FILE, identity)?,
    };
    if value.scope != scope
        || value.entries.len() > MAX_ARCHIVED
        || value.entries.iter().any(|entry| {
            !uuid(&entry.run_id)
                || entry.verified > entry.total
                || entry.can_retry
                || matches!(entry.status, Status::Ready | Status::Running)
        })
    {
        return Err("source_history_invalid".into());
    }
    Ok(value)
}

fn sort(entries: &mut [Entry]) {
    entries.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.run_id.cmp(&b.run_id))
    });
}

fn record(
    base: &Path,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    entry: Entry,
) -> Result<(), String> {
    let scope = scope(saved, identity)?;
    let journal = archive(base, &scope);
    let _guard = ARCHIVE.lock().map_err(|_| "source_history_unavailable")?;
    crate::runtime_store::private_directory(&base.join("photo-import-history"))?;
    crate::runtime_store::private_directory(&journal.root)?;
    let mut history = match read(&journal, &scope, identity) {
        Err(code)
            if matches!(
                code.as_str(),
                "source_history_invalid" | "source_journal_invalid"
            ) =>
        {
            let path = journal.root.join(FILE);
            if !fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_file()) {
                return Err(code);
            }
            fs::rename(
                &path,
                journal
                    .root
                    .join(format!("history-invalid-{}.json", uuid::Uuid::new_v4())),
            )
            .map_err(|_| "source_history_unavailable")?;
            eprintln!("Desktop preserved an unreadable import history archive");
            Archive {
                scope,
                entries: Vec::new(),
            }
        }
        other => other?,
    };
    let entry = entry.retired();
    if history.entries.contains(&entry) {
        return Ok(());
    }
    history.entries.retain(|prior| prior.run_id != entry.run_id);
    history.entries.push(entry);
    sort(&mut history.entries);
    history.entries.truncate(MAX_ARCHIVED);
    journal.write(FILE, &history, identity)
}

pub(super) fn completed_watch(
    base: &Path,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    manifest: &Manifest,
    cursor: &Cursor,
) {
    completed(base, saved, identity, Kind::Watch, manifest, cursor);
}

/// Keeps the summary of a completed run whose journal is about to hold the next one.
pub(super) fn completed(
    base: &Path,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    kind: Kind,
    manifest: &Manifest,
    cursor: &Cursor,
) {
    if cursor.state != "complete" {
        return;
    }
    let mut entry = Entry::from_run(kind, manifest, cursor, false);
    entry.status = Status::Complete;
    if record(base, saved, identity, entry).is_err() {
        eprintln!("Desktop could not retain an import history summary");
    }
}

fn current_entry(
    base: &Path,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    jobs: &SourceJobs,
    active: bool,
) -> Result<Option<Entry>, String> {
    let Some(consent) = credentials::load::<Consent>(jobs.credential)? else {
        return Ok(None);
    };
    if !consent.registered {
        return Ok(None);
    }
    consent.approval(saved, identity)?;
    let root = base.join("photo-imports").join(consent.source_id());
    if !root.exists() {
        return Ok(None);
    }
    let journal = Journal { root };
    let run = if consent.watch {
        watch::history_run(&journal, saved, &consent, identity)?
    } else {
        snapshot(&journal, saved, &consent, identity)?
    };
    let kind = Kind::for_consent(jobs.credential, &consent);
    Ok(run.map(|(manifest, cursor)| Entry::from_run(kind, &manifest, &cursor, active)))
}

pub(super) fn snapshot(
    journal: &Journal,
    saved: &SavedConnection,
    consent: &Consent,
    identity: &DeviceIdentity,
) -> Result<Option<(Manifest, Cursor)>, String> {
    if !journal.root.join("manifest.json").exists() || !journal.root.join("cursor.json").exists() {
        return Ok(None);
    }
    let manifest = load_manifest(journal, identity, consent, saved)?;
    let cursor: Cursor = journal.read("cursor.json", identity)?;
    cursor.validate(&manifest)?;
    Ok(Some((manifest, cursor)))
}

async fn running(jobs: &SourceJobs) -> bool {
    jobs.running
        .lock()
        .await
        .as_ref()
        .is_some_and(|value| !value.task.inner().is_finished())
}

pub(crate) fn retire(base: &Path, saved: &SavedConnection, jobs: &SourceJobs) {
    // A history failure must never prevent withdrawing source approval.
    let result = (|| {
        let identity = credentials::identity()?;
        if let Some(entry) = current_entry(base, saved, &identity, jobs, false)? {
            record(base, saved, &identity, entry)?;
        }
        Ok::<_, String>(())
    })();
    if result.is_err() {
        eprintln!("Desktop could not retain an import history summary");
    }
}

#[tauri::command]
pub(crate) async fn photo_import_history(
    window: tauri::WebviewWindow,
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::DesktopState>,
) -> Result<Vec<Entry>, String> {
    crate::require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let base = crate::import_base(&app)?;
    let identity = credentials::identity()?;
    let scope = scope(saved, &identity)?;
    let mut entries = read(&archive(&base, &scope), &scope, &identity)
        .map(|history| history.entries)
        .unwrap_or_else(|_| {
            eprintln!("Desktop could not read archived import history");
            Vec::new()
        });
    let folder = app.state::<SourceJobs>();
    let drops = app.state::<crate::drop_import::DropImport>();
    for jobs in [&*folder, &drops.jobs] {
        // A source may be changing while the worker checkpoints. Preserve the archive and the
        // other source if the current pair of signed files cannot be read as one run.
        if let Ok(Some(entry)) = current_entry(&base, saved, &identity, jobs, running(jobs).await) {
            entries.retain(|prior| prior.run_id != entry.run_id);
            entries.push(entry);
        }
    }
    sort(&mut entries);
    Ok(entries)
}

#[tauri::command]
pub(crate) async fn retry_photo_import(
    window: tauri::WebviewWindow,
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::DesktopState>,
    kind: Kind,
    run_id: String,
) -> Result<ImportView, String> {
    crate::require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let base = crate::import_base(&app)?;
    let identity = credentials::identity()?;
    let folder = app.state::<SourceJobs>();
    let drops = app.state::<crate::drop_import::DropImport>();
    let jobs = if kind == Kind::Drop {
        &drops.jobs
    } else {
        &*folder
    };
    if running(jobs).await
        || current_entry(&base, saved, &identity, jobs, false)?
            .is_none_or(|entry| !entry.permits_retry(kind, &run_id))
    {
        return Err("source_history_retry_unavailable".into());
    }
    if kind == Kind::Watch {
        jobs.resume_watch(app.clone(), base, saved.clone()).await
    } else {
        jobs.start(app.clone(), base, saved.clone()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved() -> SavedConnection {
        SavedConnection {
            server: "https://nas.test/".into(),
            server_id: "nas".into(),
            account_id: "owner".into(),
            name: "Synthetic owner".into(),
            token: "synthetic-current-session".into(),
            device_name: "Synthetic Desktop".into(),
            mode: "client-worker".into(),
            device_id: Some("desktop".into()),
        }
    }

    fn run() -> (Manifest, Cursor) {
        let manifest = Manifest {
            id: uuid::Uuid::new_v4().to_string(),
            source_id: uuid::Uuid::new_v4().to_string(),
            scope: "synthetic-approval".into(),
            created_at: Some(2000),
            destination: Some(Destination {
                id: uuid::Uuid::new_v4().to_string(),
                name: "Approved album".into(),
                shared: true,
            }),
            files: vec![SourceFile {
                relative: "private-folder/photo.jpg".into(),
                bytes: 10,
                watch_version: None,
            }],
            total_bytes: 10,
            skipped: 0,
            availability: None,
            skipped_reasons: BTreeMap::new(),
            more: false,
            continues: None,
        };
        let mut cursor = Cursor::new(&manifest).unwrap();
        cursor.state = "paused".into();
        (manifest, cursor)
    }

    #[test]
    fn only_a_current_interrupted_run_with_its_exact_kind_and_id_can_retry() {
        let (manifest, mut cursor) = run();
        let current = Entry::from_run(Kind::Drop, &manifest, &cursor, false);
        assert!(current.permits_retry(Kind::Drop, &manifest.id));
        assert!(!current.permits_retry(Kind::Camera, &manifest.id));
        assert!(!current.permits_retry(Kind::Drop, &uuid::Uuid::new_v4().to_string()));
        assert!(!current.retired().permits_retry(Kind::Drop, &manifest.id));
        assert!(!Entry::from_run(Kind::Drop, &manifest, &cursor, true).can_retry);
        cursor.upload_budget = None;
        assert!(!Entry::from_run(Kind::Drop, &manifest, &cursor, false).can_retry);
        cursor.state = "cancelled".into();
        assert!(!Entry::from_run(Kind::Drop, &manifest, &cursor, false).can_retry);
    }

    #[test]
    fn signed_watch_and_retired_history_survive_reload_without_paths_or_old_identity_bleed() {
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("frameleaf-import-history-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&base).unwrap();
        let identity = DeviceIdentity::generate();
        let saved = saved();
        let (watched, mut complete) = run();
        complete.position = 1;
        complete.state = "complete".into();
        completed_watch(&base, &saved, &identity, &watched, &complete);
        completed_watch(&base, &saved, &identity, &watched, &complete);
        let (drop, interrupted) = run();
        record(
            &base,
            &saved,
            &identity,
            Entry::from_run(Kind::Drop, &drop, &interrupted, false),
        )
        .unwrap();

        let current_scope = scope(&saved, &identity).unwrap();
        let journal = archive(&base, &current_scope);
        let history = read(&journal, &current_scope, &identity).unwrap();
        assert_eq!(history.entries.len(), 2);
        assert!(history.entries.iter().any(|entry| entry.kind == Kind::Watch
            && entry.status == Status::Complete
            && entry.verified == 1));
        assert!(history.entries.iter().any(|entry| entry.kind == Kind::Drop
            && entry.status == Status::Interrupted
            && !entry.can_retry));
        let wire = serde_json::to_string(&history.entries).unwrap();
        assert!(wire.contains("Approved album"));
        assert!(!wire.contains("private-folder"));
        assert!(!wire.contains("photo.jpg"));
        assert!(!wire.contains(&saved.token));

        let mut other = saved.clone();
        other.token = "synthetic-previous-session".into();
        let other_scope = scope(&other, &identity).unwrap();
        assert_ne!(other_scope, current_scope);
        assert!(read(&archive(&base, &other_scope), &other_scope, &identity)
            .unwrap()
            .entries
            .is_empty());
        assert!(read(&journal, &other_scope, &identity).is_err());
        assert!(read(&journal, &current_scope, &DeviceIdentity::generate()).is_err());
        fs::write(journal.root.join(FILE), b"invalid history bytes").unwrap();
        assert!(read(&journal, &current_scope, &identity).is_err());
        completed_watch(&base, &saved, &identity, &watched, &complete);
        assert_eq!(
            read(&journal, &current_scope, &identity)
                .unwrap()
                .entries
                .len(),
            1
        );
        let retained = fs::read_dir(&journal.root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("history-invalid-")
            })
            .unwrap();
        assert_eq!(fs::read(retained).unwrap(), b"invalid history bytes");
        fs::remove_dir_all(base).unwrap();
    }
}
