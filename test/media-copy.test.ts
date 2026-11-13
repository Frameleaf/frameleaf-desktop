import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { get } from 'svelte/store';
import { cancelCopy, explainCopy, mediaCopy, saveCopy, type CopyState } from '../src/media-copy.ts';
import { managerError } from '../src/manager-state.ts';

const saved = { path: '/Volumes/Backup/package', originals: 12, bytes: 3456 };
/** A fake backend whose save stays in flight until the test settles it. */
function backend() {
  const calls: string[] = [];
  let settle: { resolve: (value: unknown) => void; reject: (error: unknown) => void } | null = null;
  const invoke = (command: string) => {
    calls.push(command);
    if (command !== 'save_preservation_copy') return Promise.resolve();
    return new Promise((resolve, reject) => { settle = { resolve, reject }; });
  };
  return { calls, invoke, finish: (value: unknown) => settle!.resolve(value), fail: (error: unknown) => settle!.reject(error) };
}
/** What a mounted MediaCopy page does with the store: subscribe on mount, unsubscribe on unmount. */
function mount() {
  let shown: CopyState | null = null;
  const unmount = mediaCopy.subscribe(value => { shown = value; });
  return { shown: () => shown!, unmount };
}

test('leaving the Backups page keeps the copy running and a return shows it in progress', async () => {
  const { calls, invoke, finish } = backend();
  const first = mount();
  const copy = saveCopy(invoke, 'package', 'mac');
  assert.equal(first.shown().copying, true);
  first.unmount();
  assert.deepEqual(calls, ['save_preservation_copy']);

  const second = mount();
  assert.equal(second.shown().copying, true);
  assert.equal(second.shown().cancelling, false);
  second.unmount();
  finish(saved);
  await copy;
  assert.deepEqual(calls, ['save_preservation_copy']);

  const third = mount();
  assert.deepEqual(third.shown(), { copying: false, cancelling: false, saved, message: '' });
  third.unmount();
});

test('the page itself never cancels a copy when it is destroyed', () => {
  const source = readFileSync(new URL('../src/MediaCopy.svelte', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /onDestroy|onMount|\$effect/);
  assert.equal(source.match(/cancel_preservation_copy|cancelCopy\(/g)?.length, 1);
  assert.match(source, /onclick=\{\(\) => cancelCopy\(invoke, platform\)\}>Cancel copy</);
});

test('only an explicit cancel reaches the backend, and a second save cannot start alongside', async () => {
  const { calls, invoke, fail } = backend();
  const copy = saveCopy(invoke, 'package', 'mac');
  await saveCopy(invoke, 'package', 'mac');
  assert.deepEqual(calls, ['save_preservation_copy']);
  await cancelCopy(invoke, 'mac');
  assert.deepEqual(calls, ['save_preservation_copy', 'cancel_preservation_copy']);
  assert.equal(get(mediaCopy).cancelling, true);
  fail('media_copy_cancelled');
  await copy;
  assert.deepEqual(get(mediaCopy), { copying: false, cancelling: false, saved: null, message: 'Media copy cancelled.' });
});

test('drive advice names a file system for this computer', () => {
  assert.match(explainCopy('media_copy_destination_unsupported', 'mac'), /APFS/);
  for (const platform of ['windows', 'linux'] as const) {
    assert.doesNotMatch(explainCopy('media_copy_destination_unsupported', platform), /APFS/);
  }
  assert.match(explainCopy('media_copy_destination_unsupported', 'windows'), /NTFS/);
  assert.match(explainCopy('unexpected', 'linux'), /could not be completed/);
});

test('Manager pairing errors explain HTTPS, clock skew and the codes Manager now passes through', () => {
  const generic = managerError('unexpected');
  for (const code of ['manager_https_required', 'manager_clock_skew', 'desktop_operation_not_authorized', 'desktop_transport_refused', 'native_backup_owner_unavailable']) {
    assert.notEqual(managerError(code), generic, code);
  }
  assert.match(managerError('manager_https_required'), /HTTPS/);
  assert.match(managerError('manager_clock_skew'), /clock/);
});
