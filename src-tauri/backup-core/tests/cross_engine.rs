//! A repository written by either engine restores with the other. tests/fixtures/ts-repo was stored by
//! the TypeScript engine (tools/export_fixtures.mjs); `writes_a_repository_for_the_typescript_engine`
//! stores one for tools/check_rust_repo.mjs to read back.

mod common;

use std::path::Path;
use std::sync::Arc;

use common::{assert_restored, copy_dir, fixtures, library, VersionSource};
use frameleaf_backup_core::{
    backup, prune, restore, verify, BackupOptions, DirStore, PruneOptions, Repository,
    RetentionPolicy, Store,
};
use serde_json::Value;

fn ts_snapshots() -> Vec<Value> {
    let fixture: Value =
        serde_json::from_slice(&std::fs::read(fixtures().join("ts-repo.json")).unwrap()).unwrap();
    fixture["snapshots"].as_array().unwrap().clone()
}

fn root_key() -> Vec<u8> {
    hex::decode(library().root_key).unwrap()
}

/// A copy of the TypeScript engine's repository, so a test can write to it.
fn ts_repository(work: &Path) -> Repository {
    copy_dir(&fixtures().join("ts-repo"), &work.join("repo"));
    let store: Arc<dyn Store> = Arc::new(DirStore::new(work.join("repo")));
    Repository::open(store, &root_key()).unwrap()
}

#[test]
fn restores_every_snapshot_the_typescript_engine_stored() {
    let work = tempfile::tempdir().unwrap();
    let mut repository = ts_repository(work.path());
    repository.load_index().unwrap();
    let snapshots = ts_snapshots();
    let listed = repository.list_snapshots().unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<_>>(),
        snapshots
            .iter()
            .map(|s| s["key"].as_str().unwrap())
            .collect::<Vec<_>>()
    );
    for (index, want) in snapshots.iter().enumerate() {
        let snapshot = repository
            .read_snapshot(want["key"].as_str().unwrap())
            .unwrap();
        assert_eq!(snapshot.tree, want["tree"].as_str().unwrap());
        let target = work.path().join(format!("restored-{index}"));
        let result = restore(&repository, &snapshot, &[], &target, None).unwrap();
        assert_eq!(result.files, want["stats"]["files"].as_u64().unwrap());
        assert_restored(&target, &want["expected"]);
    }
    let report = verify(&mut repository, Some(&|_, _| true)).unwrap();
    assert!(
        report.missing.is_empty()
            && report.damaged_packs.is_empty()
            && report.damaged_snapshots.is_empty(),
        "{report:?}"
    );
    assert_eq!(report.snapshots, 2);
}

#[test]
fn builds_the_same_merkle_trees_as_the_typescript_engine() {
    let work = tempfile::tempdir().unwrap();
    let mut repository = ts_repository(work.path());
    let packs_before = repository.store.list("p/").unwrap().len();
    let snapshots = ts_snapshots();
    // The same library, backed up again by this engine: every tree comes out byte for byte the same, so
    // nothing is new, and the root has the id the TypeScript engine gave it.
    let library = library();
    let again = backup(
        &mut repository,
        &VersionSource(library.versions[1].clone()),
        &BackupOptions {
            pack_target: Some(library.pack_target),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(again.snapshot.tree, snapshots[1]["tree"].as_str().unwrap());
    assert_eq!(again.snapshot.stats.stored_bytes, 0);
    assert_eq!(again.unchanged, again.snapshot.stats.files);
    assert_eq!(again.snapshot.seq, 3);
    assert_eq!(repository.store.list("p/").unwrap().len(), packs_before);

    let first = backup(
        &mut repository,
        &VersionSource(library.versions[0].clone()),
        &BackupOptions::default(),
    )
    .unwrap();
    assert_eq!(first.snapshot.tree, snapshots[0]["tree"].as_str().unwrap());
}

#[test]
fn prunes_a_repository_the_typescript_engine_stored() {
    let work = tempfile::tempdir().unwrap();
    let mut repository = ts_repository(work.path());
    let snapshots = ts_snapshots();
    let report = prune(
        &mut repository,
        &PruneOptions {
            policy: RetentionPolicy {
                keep_last: 1,
                keep_days: 0,
                keep_monthly: 0,
            },
            min_age_days: 0,
            pack_target: 64 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        report.removed_snapshots,
        [snapshots[0]["key"].as_str().unwrap()]
    );
    let reopened = Repository::open(repository.store.clone(), &root_key());
    let mut reopened = reopened.unwrap();
    let check = verify(&mut reopened, Some(&|_, _| true)).unwrap();
    assert!(
        check.missing.is_empty() && check.damaged_packs.is_empty(),
        "{check:?}"
    );
    let snapshot = reopened
        .read_snapshot(snapshots[1]["key"].as_str().unwrap())
        .unwrap();
    restore(&reopened, &snapshot, &[], &work.path().join("after"), None).unwrap();
    assert_restored(&work.path().join("after"), &snapshots[1]["expected"]);
}

/// Stores the library with this engine where `FRAMELEAF_RUST_REPO_OUT` says, for tools/check_rust_repo.mjs.
#[test]
#[ignore = "run by tools/check_rust_repo.mjs"]
fn writes_a_repository_for_the_typescript_engine() {
    let out = std::env::var("FRAMELEAF_RUST_REPO_OUT").expect("FRAMELEAF_RUST_REPO_OUT");
    let _ = std::fs::remove_dir_all(&out);
    let library = library();
    let store: Arc<dyn Store> = Arc::new(DirStore::new(&out));
    let mut repository = Repository::init(store, &root_key(), None, Some(library.chunker)).unwrap();
    let mut written = Vec::new();
    for version in &library.versions {
        let time = time::OffsetDateTime::parse(
            &version.time,
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let result = backup(
            &mut repository,
            &VersionSource(version.clone()),
            &BackupOptions {
                pack_target: Some(library.pack_target),
                time: Some(time),
                ..Default::default()
            },
        )
        .unwrap();
        written.push(serde_json::json!({ "key": result.key, "tree": result.snapshot.tree }));
    }
    std::fs::write(
        format!("{out}.json"),
        serde_json::to_vec_pretty(&serde_json::json!({ "snapshots": written })).unwrap(),
    )
    .unwrap();
}
