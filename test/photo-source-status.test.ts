import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { setImmediate } from 'node:timers/promises';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

// Exercise the component's async command handlers without a native window or provider.
function component() {
  const componentSource = readFileSync(new URL('../src/PhotoSources.svelte', import.meta.url), 'utf8');
  const script = componentSource.slice(componentSource.indexOf('>') + 1, componentSource.indexOf('</script>'));
  const pending = new Map<string, { resolve: (value: unknown) => void; reject: (error: unknown) => void }>();
  let mount!: () => () => void;
  let event!: (value: { payload: unknown }) => void;
  const exports: Record<string, unknown> = {};
  const modules: Record<string, unknown> = {
    '@tauri-apps/api/core': {
      isTauri: () => true,
      invoke: (name: string) => new Promise((resolve, reject) => { pending.set(name, { resolve, reject }); }),
    },
    '@tauri-apps/api/event': { listen: async (_name: string, callback: typeof event) => { event = callback; return () => {}; } },
    svelte: { onMount: (callback: typeof mount) => { mount = callback; } },
    './source-copy-state': {},
  };
  const code = ts.transpileModule(`${script}\nexport { revoke, loadConsent }; export const current = () => ({ consent, job, message, blockedConsent });`, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  runInNewContext(code, { exports, require: (name: string) => {
    assert.ok(name in modules, `unexpected import: ${name}`);
    return modules[name];
  }, $state: (value: unknown) => value, $derived: (value: unknown) => value });
  return { ...exports, pending, mount: () => mount(), emit: (payload: unknown) => event({ payload }) } as unknown as {
    current: () => { consent: typeof source | null; job: typeof job | null; message: string; blockedConsent: boolean };
    revoke: () => Promise<void>; loadConsent: () => Promise<void>;
    pending: typeof pending; mount: () => () => void; emit: (payload: unknown) => void;
  };
}
const source = { id: 'source-a', registered: true };
const job = { sourceId: source.id, state: 'paused', completed: 0 };
async function loadingJob() {
  const view = component();
  const unmount = view.mount();
  await setImmediate();
  view.pending.get('photo_source_status')!.resolve(source);
  await setImmediate();
  return { view, unmount };
}

test('a delayed job snapshot cannot restore a revoked source', async () => {
  for (const fails of [false, true]) {
    const { view, unmount } = await loadingJob();
    const revoke = view.revoke();
    view.pending.get('revoke_photo_source')!.resolve(true);
    await revoke;
    const message = view.current().message;
    if (fails) view.pending.get('photo_import_status')!.reject('source_approval_invalid');
    else view.pending.get('photo_import_status')!.resolve(job);
    await setImmediate();
    assert.equal(view.current().consent, null);
    assert.equal(view.current().job, null);
    assert.equal(view.current().message, message);
    unmount();
  }
});
test('a delayed empty snapshot cannot erase newer live progress', async () => {
  const { view, unmount } = await loadingJob();
  const progress = { ...job, completed: 1 };
  view.emit(progress);
  view.pending.get('photo_import_status')!.resolve(null);
  await setImmediate();
  assert.equal(view.current().job, progress);
  unmount();
});
test('initial snapshots accept the current source and refuse another source', async () => {
  for (const value of [job, { ...job, sourceId: 'source-b' }, null]) {
    const { view, unmount } = await loadingJob();
    view.pending.get('photo_import_status')!.resolve(value);
    await setImmediate();
    assert.equal(view.current().job, value?.sourceId === source.id ? value : null);
    unmount();
  }
});
test('permission refresh replies and errors cannot supersede completed revocation', async () => {
  for (const fails of [false, true]) {
    const { view, unmount } = await loadingJob();
    view.pending.get('photo_import_status')!.resolve(job);
    await setImmediate();
    const refresh = view.loadConsent();
    const revoke = view.revoke();
    view.pending.get('revoke_photo_source')!.resolve(true);
    await revoke;
    const message = view.current().message;
    if (fails) view.pending.get('photo_source_status')!.reject('photos_permission_required');
    else view.pending.get('photo_source_status')!.resolve(source);
    await refresh;
    assert.equal(view.current().consent, null);
    assert.equal(view.current().blockedConsent, false);
    assert.equal(view.current().message, message);
    unmount();
  }
});
