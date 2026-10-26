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
  const pending = new Map<string, { resolve: (value: unknown) => void; reject: (error: unknown) => void; args?: Record<string, unknown> }>();
  let mount!: () => () => void;
  let event!: (value: { payload: unknown }) => void;
  const exports: Record<string, unknown> = {};
  const modules: Record<string, unknown> = {
    '@tauri-apps/api/core': {
      isTauri: () => true,
      invoke: (name: string, args?: Record<string, unknown>) => new Promise((resolve, reject) => { pending.set(name, { resolve, reject, args }); }),
    },
    '@tauri-apps/api/event': { listen: async (_name: string, callback: typeof event) => { event = callback; return () => {}; } },
    svelte: { onMount: (callback: typeof mount) => { mount = callback; } },
    './source-copy-state': {},
  };
  const code = ts.transpileModule(`${script}\nexport { revoke, loadConsent, prepareCopy, controlCopy, approve, choose, setMode }; export function acknowledge(){allowReads=true;} export { reconnect as reconnectCall }; export const current = () => ({ consent, job, message, blockedConsent, sourceMode, allowReads });`, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  runInNewContext(code, { exports, require: (name: string) => {
    assert.ok(name in modules, `unexpected import: ${name}`);
    return modules[name];
  }, $state: (value: unknown) => value, $derived: (value: unknown) => value });
  return { ...exports, pending, mount: () => mount(), emit: (payload: unknown) => event({ payload }) } as unknown as {
    current: () => { consent: typeof source | null; job: typeof job | null; message: string; blockedConsent: boolean; sourceMode:string; allowReads:boolean };
    reconnectCall: () => Promise<void>; revoke: () => Promise<void>; loadConsent: () => Promise<void>;
    approve: (retry?:boolean) => Promise<void>; choose: () => Promise<void>; setMode: (mode:string) => void; acknowledge: () => void;
    prepareCopy: () => Promise<void>; controlCopy: (action: string) => Promise<void>;
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

const copyActions = ['prepare', 'resume', 'pause', 'cancel', 'approve-upload', 'approve-export', 'approve-read'];
for (const action of copyActions) {
  test(`${action} replies cannot replace newer live copy progress`, async () => {
    const { view, unmount } = await loadingJob();
    view.pending.get('photo_import_status')!.resolve(job);
    await setImmediate();
    const command = action === 'prepare' ? view.prepareCopy() : view.controlCopy(action);
    const progress = { ...job, completed: 2 };
    view.emit(progress);
    view.pending.get(action === 'prepare' ? 'prepare_photo_import' : 'control_photo_import')!.resolve(job);
    await command;
    assert.equal(view.current().job, progress);
    unmount();
  });
  test(`${action} accepts a current reply but refuses another source`, async () => {
    for (const sourceId of [source.id, 'source-b']) {
      const { view, unmount } = await loadingJob();
      view.pending.get('photo_import_status')!.resolve(null);
      await setImmediate();
      const command = action === 'prepare' ? view.prepareCopy() : view.controlCopy(action);
      const reply = { ...job, sourceId, completed: 1 };
      view.pending.get(action === 'prepare' ? 'prepare_photo_import' : 'control_photo_import')!.resolve(reply);
      await command;
      assert.equal(view.current().job, sourceId === source.id ? reply : null);
      unmount();
    }
  });
}

for (const action of copyActions) {
  test(`${action} replies and errors cannot supersede revocation`, async () => {
    for (const fails of [false, true]) {
      const { view, unmount } = await loadingJob();
      view.pending.get('photo_import_status')!.resolve(job);
      await setImmediate();
      const command = action === 'prepare' ? view.prepareCopy() : view.controlCopy(action);
      const revoke = view.revoke();
      view.pending.get('revoke_photo_source')!.resolve(true);
      await revoke;
      const message = view.current().message;
      const reply = view.pending.get(action === 'prepare' ? 'prepare_photo_import' : 'control_photo_import')!;
      if (fails) reply.reject('source_approval_invalid');
      else reply.resolve(job);
      await command;
      assert.equal(view.current().consent, null);
      assert.equal(view.current().job, null);
      assert.equal(view.current().message, message);
      unmount();
    }
  });
}

test('reference consent cannot display or start a copy job', async () => {
  const view = component();
  const unmount = view.mount();
  await setImmediate();
  view.pending.get('photo_source_status')!.resolve({ ...source, mode: 'reference' });
  await setImmediate();
  assert.equal(view.pending.has('photo_import_status'), false);
  view.emit(job);
  assert.equal(view.current().job, null);
  await view.prepareCopy();
  await view.controlCopy('resume');
  assert.equal(view.pending.has('prepare_photo_import'), false);
  assert.equal(view.pending.has('control_photo_import'), false);
  assert.match(view.current().message, /does not allow copying/);
  unmount();
});

const inactiveReference = { ...source, mode: 'reference', registered: false, reconnectRequired: true };
async function loadingReference() {
  const view = component();const unmount=view.mount();await setImmediate();
  view.pending.get('photo_source_status')!.resolve(inactiveReference);await setImmediate();
  return { view, unmount };
}
test('reconnect restores only the same explicitly approved reference source', async () => {
  const {view,unmount}=await loadingReference();
  const reconnect=view.reconnectCall();
  assert.equal(view.pending.has('reconnect_photo_source'),true);
  assert.equal(view.pending.get('reconnect_photo_source')!.args?.sourceId, source.id);
  const active={...inactiveReference,registered:true,reconnectRequired:false};
  view.pending.get('reconnect_photo_source')!.resolve(active);await reconnect;
  assert.equal(view.current().consent,active);assert.equal(view.current().job,null);
  assert.equal(view.pending.has('prepare_photo_import'),false);
  unmount();
});
test('reconnect replies and failures cannot restore a revoked reference',async()=>{
  for(const fails of [false,true]){
    const {view,unmount}=await loadingReference();const reconnect=view.reconnectCall();
    const revoke=view.revoke();view.pending.get('revoke_photo_source')!.resolve(true);await revoke;
    const message=view.current().message;
    if(fails)view.pending.get('reconnect_photo_source')!.reject('source_registration_unavailable');
    else view.pending.get('reconnect_photo_source')!.resolve({...inactiveReference,registered:true,reconnectRequired:false});
    await reconnect;assert.equal(view.current().consent,null);assert.equal(view.current().message,message);unmount();
  }
});
test('reconnect refuses another source or mode in the native response',async()=>{
  for(const change of [{id:'other'},{mode:'copy'},{registered:false},{reconnectRequired:true}]){
    const {view,unmount}=await loadingReference();const reconnect=view.reconnectCall();
    view.pending.get('reconnect_photo_source')!.resolve({...inactiveReference,registered:true,reconnectRequired:false,...change});await reconnect;
    assert.equal(view.current().consent,inactiveReference);assert.match(view.current().message,/did not confirm/);unmount();
  }
});
test('copy and active-reference consent cannot invoke reconnect',async()=>{
  for(const value of [source,{...inactiveReference,registered:true,reconnectRequired:false}]){
    const view=component();const unmount=view.mount();await setImmediate();view.pending.get('photo_source_status')!.resolve(value);await setImmediate();
    await view.reconnectCall();assert.equal(view.pending.has('reconnect_photo_source'),false);unmount();
  }
});

const selectedFolder={kind:'folder',selectionId:'chosen-folder',path:'/Synthetic originals',photos:2,logicalBytes:10,skipped:0,truncated:false,availability:{available:2,needsDownload:0,notReady:0,unknown:0,pinned:0,downloadBytes:0}};
async function chosen(){const view=component();const call=view.choose();view.pending.get('choose_photo_folder')!.resolve(selectedFolder);await call;return view;}
test('reference setup requires its own acknowledgement and sends explicit immutable mode',async()=>{
 const view=await chosen();view.acknowledge();view.setMode('reference');assert.equal(view.current().allowReads,false);
 await view.approve();assert.equal(view.pending.has('approve_photo_folder'),false);
 view.acknowledge();const call=view.approve();assert.equal(view.pending.get('approve_photo_folder')!.args?.mode,'reference');
 view.pending.get('approve_photo_folder')!.resolve({...source,mode:'reference',kind:'folder',allowDownload:true,allowPhotosHydration:false});await call;
 assert.equal((view.current().consent as {mode?:string})?.mode,'reference');assert.equal(view.current().job,null);
});
test('a changed mode or late approval reply cannot install reference or copy permission',async()=>{
 for(const late of [false,true]){const view=await chosen();view.setMode('reference');view.acknowledge();const call=view.approve();
 if(late){const removed=view.revoke();view.pending.get('revoke_photo_source')!.resolve(true);await removed;}
 view.pending.get('approve_photo_folder')!.resolve({...source,mode:late?'reference':'copy',kind:'folder',allowDownload:true,allowPhotosHydration:false});await call;
 assert.equal(view.current().consent,null);}
});

test('a failed fresh approval status lookup cannot restore permission after revocation',async()=>{
 const view=await chosen();view.setMode('reference');view.acknowledge();const approval=view.approve();
 view.pending.get('approve_photo_folder')!.reject('source_registration_unavailable');await setImmediate();
 assert.ok(view.pending.has('photo_source_status'));const revoke=view.revoke();view.pending.get('revoke_photo_source')!.resolve(true);await revoke;
 view.pending.get('photo_source_status')!.resolve({...source,mode:'reference',kind:'folder',allowDownload:true,allowPhotosHydration:false});await approval;
 assert.equal(view.current().consent,null);assert.match(view.current().message,/permission removed/);
});
