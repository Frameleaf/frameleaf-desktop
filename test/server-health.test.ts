import { test } from 'node:test';
import assert from 'node:assert/strict';
import { backupHealth, backupWarning, libraryHeadroom, storageWarning } from '../src/server-health.ts';
import type { AttentionItem, ServerSummary } from '../src/server-types.ts';

const admin: ServerSummary = { me: { isAdmin: true }, connections: null, storage: null, version: null, attention: null };
const warning: AttentionItem = {
  id: 'backup:buddy', kind: 'backup', reason: 'backup-behind', level: 'now',
  backup: { place: 'buddy', lastSuccessAt: null, days: null },
};

test('library capacity distinguishes a full volume from absent or invalid measurements', () => {
  assert.deepEqual(libraryHeadroom({ diskAvailableRaw: 0, diskSizeRaw: 1e12, diskUsagePercentage: 100 }), {
    capacity: '0 bytes free of 1 TB', usedPercent: 100,
  });
  assert.deepEqual(libraryHeadroom({ diskAvailableRaw: 2e9, diskSizeRaw: 1e12, diskUsagePercentage: 101 }), {
    capacity: '2 GB free of 1 TB', usedPercent: null,
  });
  for (const storage of [null, {}, { diskAvailableRaw: 0, diskSizeRaw: 0 }, { diskAvailableRaw: 12, diskSizeRaw: 8 }]) {
    assert.deepEqual(libraryHeadroom(storage), { capacity: null, usedPercent: null });
  }
});

test('backup status is admin-only and trusts a check, not the absence of visible warnings', () => {
  assert.equal(backupHealth(null), null);
  assert.equal(backupHealth({ ...admin, me: { isAdmin: false }, attention: { items: [warning] } }), null);
  assert.equal(backupHealth(admin)?.label, 'Unknown');
  assert.equal(backupHealth({ ...admin, attention: { checks: [] } })?.label, 'Unknown');
  for (const [state, label] of [['unknown', 'Unknown'], ['off', 'Off'], ['ok', 'No warnings reported'], ['attention', 'Needs attention']]) {
    assert.equal(backupHealth({ ...admin, attention: { checks: [{ kind: 'backup', state }] } })?.label, label);
  }
  assert.equal(backupHealth({ ...admin, attention: { items: [warning], dismissed: [warning.id] } })?.label, 'Needs attention');
});

test('storage and backup warnings identify the affected drive and destination', () => {
  const storage = { availableBytes: 0, totalBytes: 1e9, usedPercent: 100 };
  assert.deepEqual(storageWarning({ id: 'storage', kind: 'storage', reason: 'out-of-space', level: 'now', storage: { ...storage, drive: 'thumbnails' } }), {
    title: 'Thumbnail drive is out of space', detail: '0 bytes free of 1 GB',
  });
  assert.equal(storageWarning({ id: 'storage', kind: 'storage', reason: 'nearly-full', level: 'soon', storage }).title, 'Server storage is nearly full');
  assert.deepEqual(backupWarning(warning), {
    title: 'Buddy Backup is behind', detail: 'No successful backup time reported.', page: 'photos',
  });
  assert.equal(backupWarning({ ...warning, reason: 'not-backed-up' }).title, 'No Cloud or Buddy Backup is set up');
  assert.equal(backupWarning({ ...warning, reason: 'backup-failed', backup: { ...warning.backup!, place: 'cloud' } }).page, 'cloud');
});
