import assert from 'node:assert/strict';
import { test } from 'node:test';
import { formatBytes, health, nextBackup, protectedTotals, runRow, type ComputerBackupView, type Run } from '../src/computer-backup.ts';

const view = (change: Partial<ComputerBackupView>): ComputerBackupView => ({
  os: 'mac', computer: 'Mac', connected: true, connecting: null, plan: true, enabled: true, folders: [], schedule: { every: 'day', at: 120, stopBy: 420, limitMbps: null, waitOnBattery: true, keep: 'recommended' },
  running: null, runs: [], lastSuccess: null, problem: null, offline: false, skipped: 0, usage: null, fullDiskAccess: true, keySavedAt: null, lockedCopy: false, purge: null, ...change,
});

test('the page state follows the plan, set-up, the running backup and the last problem', () => {
  assert.equal(health(view({ plan: false })), 'noplan');
  assert.equal(health(view({ enabled: false })), 'off');
  assert.equal(health(view({ running: { startedAt: 0, files: 0, bytes: 0, totalFiles: 0, totalBytes: 0, storedBytes: 0 }, problem: 'x' })), 'running');
  assert.equal(health(view({ offline: true, problem: 'computer_backup_cloud_unreachable' })), 'offline');
  assert.equal(health(view({ problem: 'lease-held' })), 'warning');
  assert.equal(health(view({ problem: 'computer_backup_stopped' })), 'on', 'a stop the person asked for is not a problem');
});

test('the next daily backup is today until it has run, then tomorrow', () => {
  const schedule = view({}).schedule;
  const day = new Date(2026, 10, 18);
  const at = (hours: number) => new Date(day).setHours(hours, 0, 0, 0);
  assert.match(nextBackup(schedule, at(-20), at(1)), /^today at /);
  assert.match(nextBackup(schedule, at(2) + 60_000, at(9)), /^tomorrow at /);
  assert.equal(nextBackup(schedule, at(-20), at(9)), 'in a few minutes', 'a missed slot runs at the agent’s next check');
});

test('recent runs and totals read as the prototype does', () => {
  const run: Run = { at: Date.now(), kind: 'backup', ok: true, files: 26_556, bytes: 1.1 * 1024 ** 3, tookMs: 9 * 60_000, problem: null, from: null, original: null };
  assert.match(runRow(run, () => '').detail, /1\.1 GB new · 26,556 files · took 9 minutes$/);
  const failed = runRow({ ...run, ok: false, problem: 'computer_backup_cloud_unreachable' }, () => 'Frameleaf Cloud couldn’t be reached.');
  assert.equal(failed.title, 'Didn’t finish');
  assert.match(failed.detail, /couldn’t be reached\. The next backup carried on/);
  assert.equal(runRow({ ...run, kind: 'restore', files: 2, original: true }, () => '').title, 'Restored 2 files');
  assert.equal(formatBytes(62.2 * 1024 ** 3), '62.2 GB');
  const folder = { id: 'a', name: 'A', path: '/a', photos: false };
  assert.deepEqual(protectedTotals([{ ...folder, on: true, size: 10, files: 2 }, { ...folder, on: false, size: 99, files: 9 }]), { bytes: 10, files: 2, count: 1 });
});
