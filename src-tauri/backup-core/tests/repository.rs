//! The TypeScript engine's repository, hardening and maintenance tests, ported.

mod common;

use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::{
    manifest, noise, path, sha256, Dying, Folder, Refusing, CHUNKER, PACK_TARGET, ROOT_KEY,
};
use frameleaf_backup_core::{
    backup, find, fs_source, list_folder, prune, read_file, restore, retain, verify, BackupOptions,
    DirStore, Error, MemoryStore, PruneOptions, Repository, RetentionPolicy, Snapshot, Source,
    SourceEntry, Store,
};

fn options() -> BackupOptions<'static> {
    BackupOptions {
        pack_target: Some(PACK_TARGET),
        ..Default::default()
    }
}

fn library(root: &Path) -> std::path::PathBuf {
    let library = root.join("library");
    fs::create_dir_all(library.join("Documents/Tax")).unwrap();
    fs::create_dir(library.join("empty")).unwrap();
    fs::write(
        library.join("Documents/Tax/Return 2025.xlsx"),
        noise(50_000, 2),
    )
    .unwrap();
    fs::write(
        library.join("Documents/notes.txt"),
        "remember the milk\n".repeat(400),
    )
    .unwrap();
    fs::write(library.join("big.bin"), noise(300_000, 3)).unwrap();
    fs::write(library.join("nothing"), "").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("Documents/notes.txt", library.join("link")).unwrap();
    library
}

fn dir_repository(root: &Path) -> (Arc<dyn Store>, Repository) {
    let store: Arc<dyn Store> = Arc::new(DirStore::new(root.join("storage")));
    let repository = Repository::init(store.clone(), &ROOT_KEY, None, Some(CHUNKER)).unwrap();
    (store, repository)
}

fn content(repository: &Repository, snapshot: &Snapshot, name: &str) -> Vec<u8> {
    let entry = find(repository, snapshot, &path(&[name])).unwrap().unwrap();
    read_file(repository, &entry)
        .unwrap()
        .flat_map(Result::unwrap)
        .collect()
}

#[test]
fn brings_back_everything_exactly_then_one_folder_then_one_file() {
    let work = tempfile::tempdir().unwrap();
    let library = library(work.path());
    let (store, mut repository) = dir_repository(work.path());
    let first = backup(&mut repository, &fs_source(&library), &options()).unwrap();
    assert!(first.problems.is_empty());
    assert_eq!(first.snapshot.stats.files, 4);

    let reopened = Repository::open(store, &ROOT_KEY).unwrap();
    let mut reopened = reopened;
    reopened.load_index().unwrap();
    let snapshot = reopened.read_snapshot(&first.key).unwrap();
    restore(
        &reopened,
        &snapshot,
        &[],
        &work.path().join("everything"),
        None,
    )
    .unwrap();
    assert_eq!(
        manifest(&work.path().join("everything")),
        manifest(&library)
    );

    let names: Vec<_> = list_folder(&reopened, &snapshot, &path(&["Documents"]))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["Tax", "notes.txt"]);
    let folder = list_folder(&reopened, &snapshot, &[])
        .unwrap()
        .into_iter()
        .find(|e| e.name == "Documents")
        .unwrap();
    assert_eq!((folder.files, folder.size), (Some(2), 50_000 + 18 * 400));

    restore(
        &reopened,
        &snapshot,
        &path(&["Documents", "Tax"]),
        &work.path().join("one-folder"),
        None,
    )
    .unwrap();
    assert_eq!(
        fs::read(work.path().join("one-folder/Tax/Return 2025.xlsx")).unwrap(),
        noise(50_000, 2)
    );
    restore(
        &reopened,
        &snapshot,
        &path(&["big.bin"]),
        &work.path().join("one/file"),
        None,
    )
    .unwrap();
    assert_eq!(
        fs::read(work.path().join("one/file/big.bin")).unwrap(),
        noise(300_000, 3)
    );
}

#[test]
fn sends_nothing_new_and_reads_no_unchanged_file_on_a_second_run() {
    let work = tempfile::tempdir().unwrap();
    let library = library(work.path());
    let (_, mut repository) = dir_repository(work.path());
    let first = backup(&mut repository, &fs_source(&library), &options()).unwrap();
    let second = backup(&mut repository, &fs_source(&library), &options()).unwrap();
    assert_eq!(second.snapshot.stats.stored_bytes, 0);
    assert_eq!(second.unchanged, 4);
    assert_eq!(
        second.snapshot.tree, first.snapshot.tree,
        "an unchanged library has the same root"
    );
    assert_eq!(second.snapshot.parent.as_deref(), Some(first.key.as_str()));
    assert_eq!(second.snapshot.seq, 2);
}

#[test]
fn stores_only_the_changed_part_of_an_edited_file_and_keeps_the_earlier_version() {
    let work = tempfile::tempdir().unwrap();
    let library = library(work.path());
    let (_, mut repository) = dir_repository(work.path());
    let first = backup(&mut repository, &fs_source(&library), &options()).unwrap();
    let mut edited = noise(300_000, 3);
    edited[150_000..150_010].copy_from_slice(b"0123456789");
    fs::write(library.join("big.bin"), &edited).unwrap();
    let second = backup(&mut repository, &fs_source(&library), &options()).unwrap();
    assert!(
        second.snapshot.stats.stored_bytes < 60_000,
        "{}",
        second.snapshot.stats.stored_bytes
    );
    assert_eq!(content(&repository, &second.snapshot, "big.bin"), edited);
    assert_eq!(
        content(&repository, &first.snapshot, "big.bin"),
        noise(300_000, 3)
    );
}

#[test]
fn moves_aside_what_is_in_the_way_and_deletes_nothing() {
    let work = tempfile::tempdir().unwrap();
    let library = library(work.path());
    let (_, mut repository) = dir_repository(work.path());
    let first = backup(&mut repository, &fs_source(&library), &options()).unwrap();
    let target = work.path().join("target");
    fs::create_dir_all(target.join("Documents")).unwrap();
    fs::write(target.join("Documents/notes.txt"), "newer words").unwrap();
    fs::write(target.join("Documents/mine.txt"), "untouched").unwrap();
    fs::write(target.join("Documents/notes.txt.kept"), "taken").unwrap();
    let aside = |place: &Path| std::path::PathBuf::from(format!("{}.kept", place.display()));
    let result = restore(
        &repository,
        &first.snapshot,
        &path(&["Documents"]),
        &target,
        Some(&aside),
    )
    .unwrap();
    assert_eq!(
        result.moved_aside,
        [(
            target.join("Documents/notes.txt"),
            target.join("Documents/notes.txt.kept-2")
        )]
    );
    assert_eq!(
        fs::read_to_string(target.join("Documents/notes.txt.kept-2")).unwrap(),
        "newer words"
    );
    assert_eq!(
        fs::read_to_string(target.join("Documents/notes.txt.kept")).unwrap(),
        "taken"
    );
    assert_eq!(
        fs::read_to_string(target.join("Documents/mine.txt")).unwrap(),
        "untouched"
    );
    assert_eq!(
        fs::read_to_string(target.join("Documents/notes.txt")).unwrap(),
        "remember the milk\n".repeat(400)
    );
}

#[test]
fn refuses_the_wrong_key_and_notices_changed_bytes() {
    let work = tempfile::tempdir().unwrap();
    let library = library(work.path());
    let (store, mut repository) = dir_repository(work.path());
    let first = backup(&mut repository, &fs_source(&library), &options()).unwrap();
    assert!(matches!(
        Repository::open(store.clone(), &[9; 32]),
        Err(Error::Unseal)
    ));
    let pack = store.list("p/").unwrap()[0].key.clone();
    let file = work.path().join("storage").join(&pack);
    let mut bytes = fs::read(&file).unwrap();
    bytes[20] ^= 1;
    fs::remove_file(&file).unwrap();
    fs::write(&file, bytes).unwrap();
    let report = verify(&mut repository, Some(&|_, _| true)).unwrap();
    assert_eq!(report.damaged_packs, [pack]);
    let snapshot = repository.read_snapshot(&first.key).unwrap();
    assert!(restore(&repository, &snapshot, &[], &work.path().join("out"), None).is_err());
}

#[test]
fn keeps_names_and_content_out_of_storage() {
    let store = Arc::new(MemoryStore::new());
    let mut repository = Repository::init(store.clone(), &ROOT_KEY, None, Some(CHUNKER)).unwrap();
    let secret = "Tax return of a very private person".to_string();
    backup(
        &mut repository,
        &Folder(vec![
            (secret.clone(), noise(40_000, 11)),
            ("notes".into(), secret.repeat(50).into_bytes()),
        ]),
        &options(),
    )
    .unwrap();
    let everything: Vec<u8> = store
        .objects
        .lock()
        .unwrap()
        .iter()
        .flat_map(|(key, (body, _))| [key.as_bytes(), body].concat())
        .collect();
    let contains = |needle: &[u8]| {
        everything
            .windows(needle.len())
            .any(|window| window == needle)
    };
    assert!(!contains(secret.as_bytes()));
    assert!(!contains(&noise(40_000, 11)[..64]));
}

/// Kill mid-run: a run whose index write fails leaves packs nobody points at; the next run adopts them.
#[test]
fn loses_nothing_when_a_run_stops_before_its_index_or_snapshot_is_written() {
    let work = tempfile::tempdir().unwrap();
    let library = library(work.path());
    let (store, mut repository) = dir_repository(work.path());
    let first = backup(&mut repository, &fs_source(&library), &options()).unwrap();

    fs::write(library.join("new.bin"), noise(120_000, 9)).unwrap();
    let failing: Arc<dyn Store> = Arc::new(Refusing {
        inner: store.clone(),
        prefix: "i/",
    });
    let mut interrupted = Repository::open(failing, &ROOT_KEY).unwrap();
    assert!(backup(&mut interrupted, &fs_source(&library), &options())
        .unwrap_err()
        .to_string()
        .contains("connection lost"));
    assert_eq!(
        repository
            .list_snapshots()
            .unwrap()
            .into_iter()
            .map(|(key, _)| key)
            .collect::<Vec<_>>(),
        [first.key]
    );

    let mut resumed = Repository::open(store, &ROOT_KEY).unwrap();
    let second = backup(&mut resumed, &fs_source(&library), &options()).unwrap();
    assert!(
        second.snapshot.stats.stored_bytes < 20_000,
        "{}",
        second.snapshot.stats.stored_bytes
    );
    restore(
        &resumed,
        &second.snapshot,
        &[],
        &work.path().join("after"),
        None,
    )
    .unwrap();
    assert_eq!(manifest(&work.path().join("after")), manifest(&library));
}

#[test]
fn ignores_an_index_that_points_at_a_pack_which_is_gone_and_reads_the_file_again() {
    let work = tempfile::tempdir().unwrap();
    let library = library(work.path());
    let (store, mut repository) = dir_repository(work.path());
    backup(&mut repository, &fs_source(&library), &options()).unwrap();
    for pack in store.list("p/").unwrap() {
        store.delete(&pack.key).unwrap();
    }
    let second = backup(&mut repository, &fs_source(&library), &options()).unwrap();
    assert_eq!(second.unchanged, 0);
    restore(
        &repository,
        &second.snapshot,
        &[],
        &work.path().join("again"),
        None,
    )
    .unwrap();
    assert_eq!(manifest(&work.path().join("again")), manifest(&library));
}

/// Stopped while reading a file: what was stored is kept, no snapshot is written, and the next run sends none of it again.
#[test]
fn keeps_what_it_stored_when_it_is_stopped_so_the_next_run_sends_none_of_it_again() {
    struct StopOn<'a>(Folder, &'a AtomicBool);
    impl Source for StopOn<'_> {
        fn list(&self, at: &[String]) -> io::Result<Vec<SourceEntry>> {
            self.0.list(at)
        }
        fn read<'a>(&'a self, at: &[String]) -> io::Result<Box<dyn io::Read + 'a>> {
            if at[0] == "c-keep.bin" {
                self.1.store(true, Ordering::SeqCst);
            }
            self.0.read(at)
        }
    }
    let first = vec![
        ("a-small.bin".to_string(), noise(10_000, 1)),
        ("b-old.bin".into(), noise(200_000, 2)),
        ("c-keep.bin".into(), noise(60_000, 3)),
    ];
    let store = Arc::new(MemoryStore::new());
    let mut repository = Repository::init(store.clone(), &ROOT_KEY, None, Some(CHUNKER)).unwrap();
    let stop = AtomicBool::new(false);
    let stopped = backup(
        &mut repository,
        &StopOn(Folder(first.clone()), &stop),
        &BackupOptions {
            stop: Some(&stop),
            ..options()
        },
    );
    assert!(matches!(stopped, Err(Error::Stopped)));
    assert!(store.list("s/").unwrap().is_empty());
    assert!(store.list("p/").unwrap().len() > 2);

    let mut reopened = Repository::open(store, &ROOT_KEY).unwrap();
    let resumed = backup(&mut reopened, &Folder(first.clone()), &options()).unwrap();
    assert!(
        resumed.snapshot.stats.stored_bytes < 80_000,
        "{}",
        resumed.snapshot.stats.stored_bytes
    );
    assert_eq!(
        content(&reopened, &resumed.snapshot, "b-old.bin"),
        first[1].1
    );
}

/// Killed after each write a backup makes, in turn: the earlier snapshot stays whole, no snapshot ever
/// points at something missing, and the next run finishes the job.
#[test]
fn is_safe_to_kill_a_backup_at_each_commit_step() {
    let before = vec![
        ("a.bin".to_string(), noise(30_000, 1)),
        ("b.bin".into(), noise(90_000, 2)),
    ];
    let after = vec![
        ("a.bin".to_string(), noise(30_000, 1)),
        ("b.bin".into(), noise(90_000, 2)),
        ("c.bin".into(), noise(150_000, 3)),
    ];
    let base = Arc::new(MemoryStore::new());
    let mut repository = Repository::init(base.clone(), &ROOT_KEY, None, Some(CHUNKER)).unwrap();
    let first = backup(&mut repository, &Folder(before.clone()), &options()).unwrap();
    let mut finished = false;
    let mut stop_at = 1;
    while !finished {
        assert!(stop_at < 100);
        let attempt = Arc::new(base.copy());
        let dying: Arc<dyn Store> = Arc::new(Dying::new(attempt.clone(), stop_at));
        match backup(
            &mut Repository::open(dying, &ROOT_KEY).unwrap(),
            &Folder(after.clone()),
            &options(),
        ) {
            Ok(_) => finished = true,
            Err(error) => assert_eq!(error.to_string(), "stopped"),
        }
        let mut reopened = Repository::open(attempt.clone(), &ROOT_KEY).unwrap();
        let report = verify(&mut reopened, Some(&|_, _| true)).unwrap();
        assert!(
            report.missing.is_empty()
                && report.damaged_snapshots.is_empty()
                && report.damaged_packs.is_empty(),
            "step {stop_at}: {report:?}"
        );
        let old = reopened.read_snapshot(&first.key).unwrap();
        assert_eq!(content(&reopened, &old, "b.bin"), before[1].1);
        let next = backup(&mut reopened, &Folder(after.clone()), &options()).unwrap();
        for (name, body) in &after {
            assert_eq!(
                &content(&reopened, &next.snapshot, name),
                body,
                "step {stop_at}"
            );
        }
        stop_at += 1;
    }
    assert!(stop_at > 3, "the backup made several writes");
}

fn two_backups() -> (Arc<MemoryStore>, String) {
    let first = vec![
        ("a-small.bin".to_string(), noise(10_000, 1)),
        ("b-old.bin".into(), noise(200_000, 2)),
        ("c-keep.bin".into(), noise(60_000, 3)),
    ];
    let second = vec![
        first[0].clone(),
        first[2].clone(),
        ("d-new.bin".into(), noise(30_000, 4)),
    ];
    let store = Arc::new(MemoryStore::new());
    let mut repository = Repository::init(store.clone(), &ROOT_KEY, None, Some(CHUNKER)).unwrap();
    backup(&mut repository, &Folder(first), &options()).unwrap();
    let b = backup(&mut repository, &Folder(second), &options()).unwrap();
    (store, b.key)
}

fn everything() -> PruneOptions<'static> {
    PruneOptions {
        policy: RetentionPolicy {
            keep_last: 1,
            keep_days: 0,
            keep_monthly: 0,
        },
        min_age_days: 0,
        pack_target: PACK_TARGET,
        now: Some(time::OffsetDateTime::now_utc() + time::Duration::days(1)),
        ..Default::default()
    }
}

fn whole(store: Arc<dyn Store>, key: &str) {
    let mut repository = Repository::open(store, &ROOT_KEY).unwrap();
    let report = verify(&mut repository, Some(&|_, _| true)).unwrap();
    assert!(
        report.missing.is_empty()
            && report.damaged_packs.is_empty()
            && report.damaged_snapshots.is_empty(),
        "{report:?}"
    );
    let snapshot = repository.read_snapshot(key).unwrap();
    assert_eq!(
        content(&repository, &snapshot, "a-small.bin"),
        noise(10_000, 1)
    );
    assert_eq!(
        content(&repository, &snapshot, "c-keep.bin"),
        noise(60_000, 3)
    );
    assert_eq!(
        content(&repository, &snapshot, "d-new.bin"),
        noise(30_000, 4)
    );
}

fn size(store: &MemoryStore) -> usize {
    store
        .objects
        .lock()
        .unwrap()
        .values()
        .map(|(body, _)| body.len())
        .sum()
}

#[test]
fn keeps_recent_backups_then_the_newest_of_each_month_and_always_the_last_few() {
    let parse = |text: &str| {
        time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).unwrap()
    };
    let snapshots: Vec<(String, String)> = [
        ("a", "2025-01-05T00:00:00.000Z"),
        ("b", "2025-01-20T00:00:00.000Z"),
        ("c", "2025-02-10T00:00:00.000Z"),
        ("d", "2025-11-01T00:00:00.000Z"),
        ("e", "2025-11-30T00:00:00.000Z"),
        ("f", "not a date"),
        ("g", "2026-01-01T00:00:00.000Z"),
    ]
    .iter()
    .map(|(key, time)| (key.to_string(), time.to_string()))
    .collect();
    let mut kept: Vec<_> = retain(
        &snapshots,
        &RetentionPolicy {
            keep_last: 1,
            keep_days: 40,
            keep_monthly: 12,
        },
        parse("2026-01-15T00:00:00.000Z"),
    )
    .into_iter()
    .collect();
    kept.sort();
    // As the TypeScript engine answers: January 2025 is twelve months back, one too many.
    assert_eq!(kept, ["c", "e", "f", "g"]);
    // A clock years ahead never empties a repository.
    let ahead = retain(
        &snapshots,
        &RetentionPolicy {
            keep_last: 0,
            keep_days: 0,
            keep_monthly: 0,
        },
        parse("2099-01-01T00:00:00.000Z"),
    );
    assert_eq!(ahead.len(), 2);
    assert!(ahead.contains("g") && ahead.contains("f"));
}

#[test]
fn prunes_an_old_backup_and_the_data_only_it_needed() {
    let (store, b) = two_backups();
    let before = size(&store);
    let mut repository = Repository::open(store.clone(), &ROOT_KEY).unwrap();
    let report = prune(&mut repository, &everything()).unwrap();
    assert_eq!(report.removed_snapshots.len(), 1);
    assert!(report.freed_bytes > 150_000, "{report:?}");
    assert!(size(&store) < before - 150_000);
    whole(store, &b);
}

#[test]
fn leaves_packs_younger_than_the_minimum_age_alone() {
    let (store, b) = two_backups();
    let packs = store.list("p/").unwrap();
    let mut repository = Repository::open(store.clone(), &ROOT_KEY).unwrap();
    let report = prune(
        &mut repository,
        &PruneOptions {
            min_age_days: 90,
            ..everything()
        },
    )
    .unwrap();
    assert_eq!(report.deleted_packs, 0);
    assert_eq!(store.list("p/").unwrap(), packs);
    whole(store, &b);
}

#[test]
fn refuses_to_thin_a_repository_in_which_a_kept_backup_is_missing_a_piece() {
    let (store, _) = two_backups();
    let mut repository = Repository::open(store.clone(), &ROOT_KEY).unwrap();
    repository.load_index().unwrap();
    let snapshot = repository
        .read_snapshot(&repository.list_snapshots().unwrap()[1].0)
        .unwrap();
    let entry = find(&repository, &snapshot, &path(&["d-new.bin"]))
        .unwrap()
        .unwrap();
    let chunk: [u8; 32] = hex::decode(&entry.chunks.unwrap()[0])
        .unwrap()
        .try_into()
        .unwrap();
    let pack = repository.index[&chunk].pack.to_string();
    store.delete(&pack).unwrap();
    let objects = store.list("").unwrap().len();
    assert!(matches!(
        prune(&mut repository, &everything()),
        Err(Error::MissingBlob(_))
    ));
    assert_eq!(
        store.list("").unwrap().len(),
        objects,
        "nothing was changed"
    );
}

#[test]
fn is_safe_to_stop_a_prune_at_any_step_and_a_second_run_finishes_the_job() {
    let (store, b) = two_backups();
    let mut finished = false;
    let mut stop_at = 1;
    while !finished {
        assert!(stop_at < 200);
        let attempt = Arc::new(store.copy());
        let dying: Arc<dyn Store> = Arc::new(Dying::new(attempt.clone(), stop_at));
        match prune(
            &mut Repository::open(dying, &ROOT_KEY).unwrap(),
            &everything(),
        ) {
            Ok(_) => finished = true,
            Err(error) => assert_eq!(error.to_string(), "stopped"),
        }
        whole(attempt.clone(), &b);
        prune(
            &mut Repository::open(attempt.clone(), &ROOT_KEY).unwrap(),
            &everything(),
        )
        .unwrap();
        whole(attempt.clone(), &b);
        assert_eq!(
            attempt
                .list("s/")
                .unwrap()
                .into_iter()
                .map(|o| o.key)
                .collect::<Vec<_>>(),
            std::slice::from_ref(&b)
        );
        stop_at += 1;
    }
    assert!(stop_at > 3, "the prune made several changes");
}

#[test]
fn only_says_what_it_would_remove_when_asked_for_a_dry_run() {
    let (store, _) = two_backups();
    let objects = store.copy().objects.into_inner().unwrap();
    let mut repository = Repository::open(store.clone(), &ROOT_KEY).unwrap();
    let report = prune(
        &mut repository,
        &PruneOptions {
            dry_run: true,
            ..everything()
        },
    )
    .unwrap();
    assert_eq!(report.removed_snapshots.len(), 1);
    assert!(report.freed_bytes > 0);
    assert_eq!(*store.objects.lock().unwrap(), objects);
}

#[test]
fn keeps_what_the_caller_chooses_and_the_newest_backup_whatever_it_chooses() {
    let (store, b) = two_backups();
    let mut repository = Repository::open(store.clone(), &ROOT_KEY).unwrap();
    let first = repository.list_snapshots().unwrap()[0].0.clone();
    let choose = |snapshots: &[(String, String)]| {
        vec![
            snapshots[0].0.clone(),
            "s/000000000099-ffffffffffffffff".into(),
        ]
    };
    let report = prune(
        &mut repository,
        &PruneOptions {
            keep: Some(&choose),
            ..everything()
        },
    )
    .unwrap();
    assert_eq!(
        (report.kept_snapshots, report.removed_snapshots.len()),
        (2, 0)
    );
    let none = |_: &[(String, String)]| Vec::new();
    let report = prune(
        &mut repository,
        &PruneOptions {
            keep: Some(&none),
            ..everything()
        },
    )
    .unwrap();
    assert_eq!(report.removed_snapshots, [first]);
    whole(store, &b);
}

#[test]
fn works_around_an_index_object_that_can_no_longer_be_opened_and_replaces_it() {
    let (store, b) = two_backups();
    let index = store.list("i/").unwrap()[0].key.clone();
    store.objects.lock().unwrap().get_mut(&index).unwrap().0[30] ^= 1;
    let mut repository = Repository::open(store.clone(), &ROOT_KEY).unwrap();
    let report = verify(&mut repository, None).unwrap();
    assert_eq!(report.damaged_indexes, std::slice::from_ref(&index));
    assert!(report.missing.is_empty());
    prune(
        &mut repository,
        &PruneOptions {
            min_age_days: 90,
            ..everything()
        },
    )
    .unwrap();
    assert!(!store
        .list("i/")
        .unwrap()
        .iter()
        .any(|object| object.key == index));
    whole(store, &b);
}

#[test]
fn numbers_and_names_a_snapshot_as_asked() {
    let store = Arc::new(MemoryStore::new());
    let mut repository = Repository::init(store, &ROOT_KEY, None, Some(CHUNKER)).unwrap();
    let files = Folder(vec![("a".into(), noise(1000, 1))]);
    let id = "0123456789abcdef0123456789abcdef";
    let named = backup(
        &mut repository,
        &files,
        &BackupOptions {
            sequence: Some(7),
            snapshot_id: Some(id.into()),
            ..options()
        },
    )
    .unwrap();
    assert_eq!(named.key, format!("s/000000000007-{id}"));
    assert_eq!(named.snapshot.seq, 7);
    assert!(matches!(
        backup(
            &mut repository,
            &files,
            &BackupOptions {
                sequence: Some(7),
                snapshot_id: Some(id.into()),
                ..options()
            }
        ),
        Err(Error::ObjectExists(_))
    ));
    let again = backup(
        &mut repository,
        &files,
        &BackupOptions {
            sequence: Some(7),
            ..options()
        },
    )
    .unwrap();
    assert_eq!(
        repository
            .list_snapshots()
            .unwrap()
            .iter()
            .map(|(_, seq)| *seq)
            .collect::<Vec<_>>(),
        [7, 7]
    );
    assert_eq!(again.ciphertext_sha256.len(), 64);
    assert!(backup(
        &mut repository,
        &files,
        &BackupOptions {
            snapshot_id: Some("NOT-HEX".into()),
            ..options()
        }
    )
    .is_err());
}

#[test]
fn reports_a_file_it_cannot_read_and_an_unsafe_name_and_still_finishes() {
    struct Troubled;
    impl Source for Troubled {
        fn list(&self, _: &[String]) -> io::Result<Vec<SourceEntry>> {
            let entry = |name: &str| SourceEntry {
                name: name.into(),
                kind: frameleaf_backup_core::EntryType::File,
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                size: 3,
                target: None,
                unreadable: None,
                key: None,
            };
            Ok(vec![
                entry("nothing"),
                entry("fine"),
                entry(".."),
                entry("a/b"),
            ])
        }
        fn read<'a>(&'a self, at: &[String]) -> io::Result<Box<dyn io::Read + 'a>> {
            if at[0] == "nothing" {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "permission denied",
                ));
            }
            Ok(Box::new(&b"abc"[..]))
        }
    }
    let mut repository =
        Repository::init(Arc::new(MemoryStore::new()), &ROOT_KEY, None, Some(CHUNKER)).unwrap();
    let result = backup(&mut repository, &Troubled, &options()).unwrap();
    assert_eq!(result.problems.len(), 3);
    assert_eq!(result.problems[0].message, "permission denied");
    assert_eq!(result.snapshot.stats.files, 1);
    assert_eq!(content(&repository, &result.snapshot, "fine"), b"abc");
}

#[test]
fn keeps_dates_before_1970_and_exact_modes() {
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("old.txt"), "old").unwrap();
    let old = std::time::UNIX_EPOCH - std::time::Duration::from_millis(86_400_123);
    fs::File::options()
        .write(true)
        .open(source.join("old.txt"))
        .unwrap()
        .set_modified(old)
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(source.join("old.txt"), fs::Permissions::from_mode(0o640)).unwrap();
    }
    let (_, mut repository) = dir_repository(work.path());
    let result = backup(&mut repository, &fs_source(&source), &options()).unwrap();
    restore(
        &repository,
        &result.snapshot,
        &[],
        &work.path().join("out"),
        None,
    )
    .unwrap();
    let info = fs::metadata(work.path().join("out/old.txt")).unwrap();
    assert_eq!(info.modified().unwrap(), old);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(info.permissions().mode() & 0o7777, 0o640);
    }
    assert_eq!(
        sha256(&fs::read(work.path().join("out/old.txt")).unwrap()),
        sha256(b"old")
    );
}

#[test]
fn never_replaces_an_object_and_leaves_no_half_written_file_behind() {
    let work = tempfile::tempdir().unwrap();
    let store = DirStore::new(work.path());
    store.put("p/aa", b"first").unwrap();
    assert!(matches!(
        store.put("p/aa", b"second"),
        Err(Error::ObjectExists(_))
    ));
    assert_eq!(store.get("p/aa", None).unwrap(), b"first");
    assert_eq!(store.list("p/").unwrap().len(), 1);
    assert_eq!(fs::read_dir(work.path().join("p")).unwrap().count(), 1);
    assert!(store.put("../escape", b"x").is_err());
    assert!(DirStore::new(work.path().join("not-yet"))
        .list("")
        .unwrap()
        .is_empty());
}
