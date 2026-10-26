import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { setImmediate } from 'node:timers/promises';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const scan = { scanId: 'a'.repeat(64), current: true, abandoned: false, spent: 10, resources: 2, completed: 0, reservedBytes: 10, discardable: false, remaining: 0, nextReadBytes: 10, additionalReadAllowance: 10, canRescan: false, prepared: false };
const archived = { ...scan, scanId: 'b'.repeat(64), current: false, abandoned: true, discardable: true };
const status = { sourceId: 'source-a', scans: [scan, archived] };
const transfer = { resourceKey: 'c'.repeat(64), resourceId: '00000000-0000-4000-8000-000000000001', version: 'd'.repeat(64), stateId: 'e'.repeat(64), bytes: 10, readUsed: 5, readRemaining: 0, uploadUsed: 0, uploadRemaining: 3, additionalUpload: 7, readCost: 10, additionalRead: 10, cacheRecorded: true };
const publication = { resourceKey: transfer.resourceKey, recordId: 'f'.repeat(64), originalFileName: 'original.jpg', state: 'recorded', receipt: { publishedAt: '2026-10-26T12:00:00Z' }, transfer };
function component() {
  const source = readFileSync(new URL('../src/ReferenceScans.svelte', import.meta.url), 'utf8');
  const script = source.slice(source.indexOf('>') + 1, source.indexOf('</script>'));
  const pending: { name: string; args: Record<string, unknown>; resolve(value: unknown): void; reject(error: unknown): void }[] = [];
  let mount!: () => () => void;
  const exports: Record<string, unknown> = {};
  const code = ts.transpileModule(`${script}\nexport { refresh, control, confirmDiscard, publicationMessage, approveTransfer, approveRead }; export const inspectFilesCall=()=>inspectFiles(); export const toggleFileCall=(key:string)=>toggleFile(key); export const planSelectionCall=()=>planSelection(); export const current = () => ({ status, message, busy, confirmation });`, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  runInNewContext(code, { exports, $state: (value: unknown) => value, $props: () => ({ sourceId: status.sourceId, photos: false }), require: (name: string) => {
    if (name === 'svelte') return { onMount: (callback: typeof mount) => { mount = callback; } };
    assert.equal(name, '@tauri-apps/api/core');
    return { invoke: (name: string, args: Record<string, unknown>) => new Promise((resolve, reject) => { pending.push({ name, args, resolve, reject }); }) };
  } });
  return { ...exports, pending, mount: () => mount() } as unknown as {
    inspectFilesCall(): Promise<void>; toggleFileCall(key:string): void; planSelectionCall(): Promise<void>;
    approveRead(value: typeof publication): Promise<void>;
    approveTransfer(value: typeof publication): Promise<void>;
    publicationMessage(value: { state: string }): string;
    refresh(): Promise<void>; control(action: string, value: typeof scan): Promise<void>; confirmDiscard(value: typeof scan): void;
    current(): { status: typeof status | null; message: string; busy: boolean; confirmation: string | null };
    pending: typeof pending; mount(): () => void;
  };
}
async function loaded(value: typeof status & { publications?: typeof publication[] } = status) {
  const view = component(); const unmount = view.mount();
  view.pending[0].resolve(value); await setImmediate();
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
  for (const action of ['read', 'select', 'publish', 'start']) await view.control(action, scan);
  await view.control('abandon', { ...scan }); view.confirmDiscard(scan); await view.control('discard', scan);
  assert.equal(view.pending.length, 1); unmount();
});

test('reference UI commands are permitted only in the packaged local main window', () => {
  const ui = readFileSync(new URL('../src/ReferenceScans.svelte', import.meta.url), 'utf8') + readFileSync(new URL('../src/ReferenceRead.svelte', import.meta.url), 'utf8');
  const manifest = readFileSync(new URL('../src-tauri/build.rs', import.meta.url), 'utf8');
  const capability = JSON.parse(readFileSync(new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8'));
  const commands = [...ui.matchAll(/invoke(?:<[^\n]*?>)?\('([^']+)'/g)].map(match => match[1]);
  assert.equal(commands.length, 15);
  for (const command of commands) {
    assert.ok(manifest.includes(`"${command}"`), `${command} must exist in the application ACL manifest`);
    assert.ok(capability.permissions.includes(`allow-${command.replaceAll('_', '-')}`));
  }
  assert.deepEqual(capability.windows, ['main']); assert.equal(capability.local, true);
  assert.equal('remote' in capability, false);
});

test('rescan preserves selected scope and accepts only a fresh zero-allowance scan', async () => {
  for (const valid of [false,true]) {
    const row = {...scan,completed:2,prepared:true,canRescan:true};
    const displayed = {...status,scans:[row,archived]};
    const {view,unmount}=await loaded(displayed);
    const work=view.control('rescan',row);
    assert.equal(view.pending[1].args.action,'rescan');
    assert.equal('relatives' in view.pending[1].args,false);
    assert.equal('additional' in view.pending[1].args,false);
    const reply={...status,scans:[{...scan,scanId:valid?'c'.repeat(64):scan.scanId,spent:0}]};
    view.pending[1].resolve(reply);await work;
    assert.equal(view.current().status,valid?reply:displayed);unmount();
  }
});
test('read approval sends the exact displayed amount without executing reads or uploads',async()=>{
  const {view,unmount}=await loaded();
  const work=view.control('approve-read',scan);
  assert.equal(view.pending[1].args.action,'approve-read');
  assert.equal(view.pending[1].args.additional,10);
  assert.equal(view.pending[1].args.expectedScan,scan.scanId);
  const reply={...status,scans:[{...scan,remaining:10,additionalReadAllowance:0},archived]};
  view.pending[1].resolve(reply);await work;
  assert.equal(view.current().status,reply);assert.equal(view.pending.length,2);
  await view.control('approve-read',reply.scans[0]);assert.equal(view.pending.length,2);unmount();
});
test('incomplete scans cannot rescan and archived scans cannot receive new read authority',async()=>{
  const {view,unmount}=await loaded();
  await view.control('rescan',scan);await view.control('approve-read',archived);
  assert.equal(view.pending.length,1);unmount();
});
test('new preparation replies cannot revive an unmounted source',async()=>{
  for(const action of ['rescan','approve-read']) for(const fails of [false,true]){
    const row=action==='rescan'?{...scan,completed:2,prepared:true,canRescan:true}:scan;
    const {view,unmount}=await loaded({...status,scans:[row,archived]});
    const work=view.control(action,row);unmount();const before=view.current();
    if(fails)view.pending[1].reject('source_photo_session_changed');
    else view.pending[1].resolve({...status,scans:[{...scan,remaining:10,additionalReadAllowance:0}]});
    await work;assert.equal(view.current().status,before.status);assert.equal(view.current().message,before.message);
  }
});

test('a retained pending cache cannot request another original-read grant',async()=>{
  const row={...scan,nextReadBytes:null,additionalReadAllowance:0,reservedBytes:10};
  const {view,unmount}=await loaded({...status,scans:[row,archived]});
  await view.control('approve-read',row);
  assert.equal(view.pending.length,1);unmount();
});

// A saved receipt must never hide an interrupted replacement or imply fresh server availability.
test('publication labels keep interrupted steps separate from retained receipts', () => {
  const view = component();
  for (const [state, expected] of [
    ['run', /not confirmed/], ['item', /not confirmed/], ['publish', /may have completed/],
    ['complete', /completion is pending/], ['recorded', /saved locally/], ['unknown', /needs attention/],
  ] as const) assert.match(view.publicationMessage({state}), expected);
});

test('transfer approval binds the publication and exact budget state without granting original reads', async () => {
 const displayed={...status,publications:[publication]};const {view,unmount}=await loaded(displayed);
 const call=view.approveTransfer(publication);const request=view.pending[1];assert.equal(request.name,'approve_photo_reference_transfer');
 assert.deepEqual(JSON.parse(JSON.stringify(request.args)),{input:{sourceId:status.sourceId,resourceKey:publication.resourceKey,recordId:publication.recordId,stateId:transfer.stateId,additional:7}});
 const approved={...transfer,stateId:'a'.repeat(64),uploadRemaining:10,additionalUpload:0};request.resolve(approved);await call;
 assert.match(view.current().message,/Transfer allowance saved/);assert.equal(view.pending.length,3);
 assert.equal(view.pending[2].name,'photo_reference_status');assert.equal(view.current().busy,true);
 const refreshed={...displayed,publications:[{...publication,transfer:approved}],serving:{selectionId:'b'.repeat(64),resources:1,maxTransferBytes:10}};
 view.pending[2].resolve(refreshed);await setImmediate();assert.equal(view.current().status,refreshed);assert.equal(view.current().busy,false);
 await view.approveTransfer(publication);assert.equal(view.pending.length,3);unmount();
});
test('a changed or malformed transfer reply cannot claim a grant or replace displayed history', async () => {
 for(const change of [{readRemaining:10},{uploadUsed:10},{resourceId:'other'},{stateId:transfer.stateId},{additionalUpload:7}]){
  const displayed={...status,publications:[publication]};const {view,unmount}=await loaded(displayed);const call=view.approveTransfer(publication);
  view.pending[1].resolve({...transfer,stateId:'a'.repeat(64),uploadRemaining:10,additionalUpload:0,...change});await call;
  assert.equal(view.current().status,displayed);assert.doesNotMatch(view.current().message,/Transfer allowance saved/);unmount();
 }
});
test('pending publication or a sufficient allowance cannot receive transfer approval', async () => {
 for(const value of [{...publication,state:'publish'},{...publication,transfer:{...transfer,additionalUpload:0}}]){
  const {view,unmount}=await loaded({...status,publications:[value]});await view.approveTransfer(value);assert.equal(view.pending.length,1);unmount();
 }
});
test('unmount ignores delayed transfer acknowledgements and errors', async () => {
 for(const fails of [false,true]){const {view,unmount}=await loaded({...status,publications:[publication]});const call=view.approveTransfer(publication);unmount();const before=view.current();
 if(fails)view.pending[1].reject('source_transfer_state_changed');else view.pending[1].resolve({...transfer,stateId:'a'.repeat(64),uploadRemaining:10,additionalUpload:0});await call;
 assert.equal(view.current().status,before.status);assert.equal(view.current().message,before.message);}
});

test('an exact original-read grant preserves transfer budgets and waits for metadata refresh',async()=>{
 const displayed={...status,publications:[publication]};const {view,unmount}=await loaded(displayed);
 const call=view.approveRead(publication);const request=view.pending[1];
 assert.equal(request.name,'approve_photo_reference_original_read');
 assert.deepEqual(JSON.parse(JSON.stringify(request.args)),{input:{sourceId:status.sourceId,resourceKey:publication.resourceKey,recordId:publication.recordId,stateId:transfer.stateId,additional:10}});
 const approved={...transfer,stateId:'b'.repeat(64),readRemaining:10,additionalRead:0};request.resolve(approved);await call;
 assert.equal(view.pending[2].name,'photo_reference_status');assert.equal(view.current().busy,true);
 view.pending[2].resolve({...displayed,publications:[{...publication,transfer:approved}]});await setImmediate();
 assert.equal(view.current().busy,false);unmount();
});

test('a recorded but consumed original can receive a separate transfer grant without another read grant',async()=>{
 const value={...publication,transfer:{...transfer,cacheRecorded:false}};
 const {view,unmount}=await loaded({...status,publications:[value]});const call=view.approveTransfer(value);
 view.pending[1].resolve({...value.transfer,stateId:'a'.repeat(64),uploadRemaining:10,additionalUpload:0});await call;
 assert.equal(view.pending[2].name,'photo_reference_status');view.pending[2].resolve(null);await setImmediate();unmount();
});

test('a fresh reference scan chooses only displayed bounded files and creates no allowances',async()=>{
 const {view,unmount}=await loaded({...status,scans:[]});const inspect=view.inspectFilesCall();
 assert.equal(view.pending[1].name,'photo_reference_files');view.pending[1].resolve({sourceId:status.sourceId,files:[{relative:'one.jpg',bytes:10},{relative:'two.jpg',bytes:20}],stagingRemaining:15});await inspect;
 view.toggleFileCall('two.jpg');await view.planSelectionCall();assert.equal(view.pending.length,2);
 view.toggleFileCall('one.jpg');const plan=view.planSelectionCall();assert.equal(view.pending[2].name,'plan_photo_reference');
 assert.deepEqual(JSON.parse(JSON.stringify(view.pending[2].args)),{sourceId:status.sourceId,relatives:['one.jpg'],expectedScan:null});
 view.pending[2].resolve({...status,scans:[{...scan,spent:0,remaining:0,resources:1,prepared:false,abandoned:false}]});await plan;
 assert.equal(view.current().status?.scans[0].spent,0);unmount();
});
test('an incomplete current scan cannot be replaced by choosing new files',async()=>{
 const {view,unmount}=await loaded();const inspect=view.inspectFilesCall();view.pending[1].resolve({sourceId:status.sourceId,files:[{relative:'one.jpg',bytes:10}],stagingRemaining:10});await inspect;
 view.toggleFileCall('one.jpg');await view.planSelectionCall();assert.equal(view.pending.length,2);unmount();
});

test('a completed unchanged batch may reuse verified metadata without another original read',async()=>{
 const current={...scan,prepared:true,canRescan:true};const displayed={...status,scans:[current]};
 const {view,unmount}=await loaded(displayed);const inspect=view.inspectFilesCall();
 view.pending[1].resolve({sourceId:status.sourceId,files:[{relative:'one.jpg',bytes:10}],stagingRemaining:10});await inspect;
 view.toggleFileCall('one.jpg');const call=view.planSelectionCall();assert.equal(view.pending[2].args.expectedScan,current.scanId);
 const next={...displayed,scans:[{...current,scanId:'c'.repeat(64),resources:1,spent:0,remaining:0}]};
 view.pending[2].resolve(next);await call;assert.equal(view.current().status,next);assert.match(view.current().message,/No original-read/);unmount();
});
