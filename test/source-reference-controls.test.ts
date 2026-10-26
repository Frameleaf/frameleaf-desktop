import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { setImmediate } from 'node:timers/promises';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const scan = { scanId: 'a'.repeat(64), current: true, abandoned: false, spent: 10, resources: 2, completed: 0, reservedBytes: 10, discardable: false };
const archived = { ...scan, scanId: 'b'.repeat(64), current: false, abandoned: true, discardable: true };
const status = { sourceId: 'source-a', scans: [scan, archived] };
function component() {
  const source = readFileSync(new URL('../src/ReferenceScans.svelte', import.meta.url), 'utf8');
  const script = source.slice(source.indexOf('>') + 1, source.indexOf('</script>'));
  const pending: { name: string; args: Record<string, unknown>; resolve(value: unknown): void; reject(error: unknown): void }[] = [];
  let mount!: () => () => void;
  const exports: Record<string, unknown> = {};
  const code = ts.transpileModule(`${script}\nexport { refresh, control, confirmDiscard }; export const current = () => ({ status, message, busy, confirmation });`, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  runInNewContext(code, { exports, $state: (value: unknown) => value, $props: () => ({ sourceId: status.sourceId, photos: false }), require: (name: string) => {
    if (name === 'svelte') return { onMount: (callback: typeof mount) => { mount = callback; } };
    assert.equal(name, '@tauri-apps/api/core');
    return { invoke: (name: string, args: Record<string, unknown>) => new Promise((resolve, reject) => { pending.push({ name, args, resolve, reject }); }) };
  } });
  return { ...exports, pending, mount: () => mount() } as unknown as {
    refresh(): Promise<void>; control(action: string, value: typeof scan): Promise<void>; confirmDiscard(value: typeof scan): void;
    current(): { status: typeof status | null; message: string; busy: boolean; confirmation: string | null };
    pending: typeof pending; mount(): () => void;
  };
}
async function loaded() {
  const view = component(); const unmount = view.mount();
  view.pending[0].resolve(status); await setImmediate();
  return { view, unmount };
}
test('reference status is source-bound and refresh grants no original access', async () => {
  for (const reply of [status, { ...status, sourceId: 'other' }, null]) {
    const view = component(); const unmount = view.mount();
    assert.equal(view.pending[0].name, 'photo_reference_status');
    assert.equal(view.pending[0].args.sourceId, status.sourceId);
    view.pending[0].resolve(reply); await setImmediate();
    assert.equal(view.current().status, reply?.sourceId === status.sourceId ? reply : null);
    assert.equal(view.pending.length, 1); unmount();
  }
});
test('abandon requires the displayed current scan and binds its native request', async () => {
  const { view, unmount } = await loaded();
  await view.control('abandon', archived); assert.equal(view.pending.length, 1);
  const work = view.control('abandon', scan);
  assert.equal(view.pending[1].name, 'control_photo_reference');
  assert.equal(view.pending[1].args.expectedScan, scan.scanId);
  assert.equal(view.pending[1].args.sourceId, status.sourceId);
  view.pending[1].resolve({ ...status, scans: [{ ...scan, abandoned: true }, archived] });
  await work; assert.equal(view.current().status?.scans[0].abandoned, true); unmount();
});
test('discard requires a separate confirmation and a confirmed quota release', async () => {
  const { view, unmount } = await loaded();
  await view.control('discard', archived); assert.equal(view.pending.length, 1);
  view.confirmDiscard(archived);
  const work = view.control('discard', archived);
  assert.equal(view.pending[1].args.expectedScan, archived.scanId);
  view.pending[1].resolve({ ...status, scans: [scan, { ...archived, reservedBytes: 0, discardable: false }] });
  await work; assert.equal(view.current().status?.scans[1].reservedBytes, 0);
  assert.match(view.current().message, /discarded/); unmount();
});
test('a refused cleanup and foreign response preserve displayed history', async () => {
  for (const reply of ['source_cache_cleanup_pending', { ...status, sourceId: 'other' }, status, null]) {
    const { view, unmount } = await loaded(); view.confirmDiscard(archived);
    const work = view.control('discard', archived);
    if (typeof reply === 'string') view.pending[1].reject(reply); else view.pending[1].resolve(reply);
    await work; assert.equal(view.current().status, status);
    assert.doesNotMatch(view.current().message, /Cache discarded/); unmount();
  }
});
test('unmount after revocation or sign-out rejects delayed replies and errors', async () => {
  for (const action of ['refresh', 'abandon', 'discard']) for (const fails of [false, true]) {
    const { view, unmount } = await loaded(); view.confirmDiscard(archived);
    const work = action === 'refresh' ? view.refresh() : view.control(action, action === 'discard' ? archived : scan);
    unmount(); const before = view.current();
    if (fails) view.pending[1].reject('source_approval_invalid'); else view.pending[1].resolve({ ...status, scans: [] });
    await work; assert.equal(view.current().status, before.status); assert.equal(view.current().message, before.message);
  }
});
test('a newer refresh supersedes an older snapshot', async () => {
  const { view, unmount } = await loaded(); const old = view.refresh(); const latest = view.refresh();
  const newer = { ...status, scans: [] }; view.pending[2].resolve(newer); await latest;
  view.pending[1].resolve(status); await old; assert.equal(view.current().status, newer); unmount();
});
test('unknown controls, stale scan objects and job-owned caches cannot invoke native mutations', async () => {
  const { view, unmount } = await loaded();
  for (const action of ['read', 'rescan', 'publish', 'start']) await view.control(action, scan);
  await view.control('abandon', { ...scan }); view.confirmDiscard(scan); await view.control('discard', scan);
  assert.equal(view.pending.length, 1); unmount();
});

test('reference UI commands are permitted only in the packaged local main window', () => {
  const ui = readFileSync(new URL('../src/ReferenceScans.svelte', import.meta.url), 'utf8');
  const manifest = readFileSync(new URL('../src-tauri/build.rs', import.meta.url), 'utf8');
  const capability = JSON.parse(readFileSync(new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8'));
  const commands = [...ui.matchAll(/invoke(?:<[^\n]*?>)?\('([^']+)'/g)].map(match => match[1]);
  assert.equal(commands.length, 2);
  for (const command of commands) {
    assert.ok(manifest.includes(`"${command}"`), `${command} must exist in the application ACL manifest`);
    assert.ok(capability.permissions.includes(`allow-${command.replaceAll('_', '-')}`));
  }
  assert.deepEqual(capability.windows, ['main']); assert.equal(capability.local, true);
  assert.equal('remote' in capability, false);
});
