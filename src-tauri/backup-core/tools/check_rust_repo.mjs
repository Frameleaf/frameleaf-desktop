// Has this engine store the cross-engine library, then reads it back with the TypeScript engine: every
// snapshot restores as tools/library.mjs says, verify finds nothing wrong, and a TypeScript prune leaves the newest snapshot whole.
//
//   node tools/check_rust_repo.mjs <built packages/backup-core dist folder>
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, lstat, mkdtemp, readFile, readdir, readlink, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import { expected, rootKey, versions } from './library.mjs';

const core = await import(pathToFileURL(join(resolve(process.argv[2]), 'index.js')).href);
const crate = join(dirname(fileURLToPath(import.meta.url)), '..');
const work = await mkdtemp(join(tmpdir(), 'rust-repo-'));
const out = join(work, 'repo');
try {
  execFileSync(
    'cargo',
    ['test', '-p', 'frameleaf-backup-core', '--test', 'cross_engine', 'writes_a_repository_for_the_typescript_engine', '--', '--ignored', '--exact'],
    { cwd: crate, stdio: 'inherit', env: { ...process.env, FRAMELEAF_RUST_REPO_OUT: out } },
  );
  const written = JSON.parse(await readFile(`${out}.json`, 'utf8')).snapshots;

  const repository = await core.Repository.open(core.dirStore(out), { rootKey });
  const report = await core.verify(repository, { readPack: () => true });
  assert.deepEqual([report.missing, report.damagedPacks, report.damagedSnapshots, report.damagedIndexes], [[], [], [], []]);
  assert.equal(report.snapshots, versions.length);

  for (const [index, version] of versions.entries()) {
    const snapshot = await repository.readSnapshot(written[index].key);
    const target = join(work, `restored-${index}`);
    await core.restore(repository, snapshot, [], target);
    for (const [name, want] of Object.entries(expected(version))) {
      const place = join(target, name);
      const info = await lstat(place);
      if (want.type === 'file') {
        assert.equal(createHash('sha256').update(await readFile(place)).digest('hex'), want.sha256, name);
        assert.equal(info.mode & 0o7777, want.mode, name);
        assert.equal(Math.floor((await stat(place)).mtimeMs), want.mtime, name);
      } else if (want.type === 'dir') {
        assert.ok(info.isDirectory(), name);
      } else {
        assert.equal(await readlink(place), want.target, name);
      }
    }
    const count = async (at) =>
      (await Promise.all((await readdir(at, { withFileTypes: true })).map(async (item) => 1 + (item.isDirectory() ? await count(join(at, item.name)) : 0)))).reduce((a, b) => a + b, 0);
    assert.equal(await count(target), Object.keys(expected(version)).length, 'nothing more was restored');
  }

  const copy = join(work, 'pruned');
  await cp(out, copy, { recursive: true });
  const pruned = await core.Repository.open(core.dirStore(copy), { rootKey });
  await core.prune(pruned, { policy: { keepLast: 1, keepDays: 0, keepMonthly: 0 }, minAgeDays: 0, packTarget: 64 * 1024 });
  const after = await core.verify(await core.Repository.open(core.dirStore(copy), { rootKey }), { readPack: () => true });
  assert.deepEqual([after.snapshots, after.missing, after.damagedPacks], [1, [], []]);
  console.log('The TypeScript engine reads, verifies and prunes what the Rust engine stored.');
} finally {
  await rm(work, { recursive: true, force: true });
}
