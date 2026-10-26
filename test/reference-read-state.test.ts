import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { setImmediate } from 'node:timers/promises';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';
const sourceId='00000000-0000-4000-8000-000000000101';
const scan={resources:2,scanId:'a'.repeat(64),current:true,abandoned:false,prepared:false,additionalReadAllowance:0,nextReadBytes:10};
const work={operation:'prepare' as const,sourceId,scanId:scan.scanId,requestId:'00000000-0000-4000-8000-000000000001',state:'preparing',code:null as string|null};
const publication={resourceKey:'c'.repeat(64),recordId:'d'.repeat(64),originalFileName:'Synthetic pending.jpg',state:'publish'};
const publicationWork={...work,operation:'publish' as const,state:'publishing'};
const serving={selectionId:'e'.repeat(64),resources:2,maxTransferBytes:20};
const servingWork={operation:'serve' as const,sourceId,selectionId:serving.selectionId,requestId:work.requestId,state:'waiting',code:null as string|null};
const recoveryWork={operation:'recover' as const,sourceId,resourceKey:publication.resourceKey,recordId:publication.recordId,requestId:work.requestId,state:'recovering',code:null as string|null};
function component(selected: typeof scan|null=scan, cryptoMode: 'uuid'|'bytes'|'none'='uuid'){
 const source=readFileSync(new URL('../src/ReferenceRead.svelte',import.meta.url),'utf8');
 const script=source.slice(source.indexOf('>')+1,source.indexOf('</script>'));
 const pending:{name:string;args:Record<string,unknown>;resolve(v:unknown):void;reject(e:unknown):void}[]=[];
 let mount!:()=>()=>void;let event!:(e:{payload:unknown})=>void;let sequence=0;let settled=0;let active=false;let unlistened=false;
 const exports:Record<string,unknown>={};
 const code=ts.transpileModule(`${script}\nexport { start, startRecovery, startPublication, startServing, pause, checkStatus }; export const current=()=>({work,message,ready,startPending,pausePending});`,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
 runInNewContext(code,{exports,$state:(v:unknown)=>v,$props:()=>({sourceId,scan:selected,publications:[publication],serving,disabled:false,onActiveChange:(v:boolean)=>active=v,onSettled:()=>settled++}),crypto:cryptoMode==='uuid'?{randomUUID:()=>`00000000-0000-4000-8000-${String(++sequence).padStart(12,'0')}`} : cryptoMode==='bytes'?{getRandomValues:(bytes:Uint8Array)=>{bytes.fill(7);return bytes;}}:{},require:(name:string)=>{
  if(name==='svelte')return{onMount:(callback:typeof mount)=>mount=callback};
  if(name==='@tauri-apps/api/event')return{listen:async(channel:string,callback:typeof event)=>{assert.equal(channel,'photo-reference-work');event=callback;return()=>unlistened=true;}};
  assert.equal(name,'@tauri-apps/api/core');return{invoke:(name:string,args:Record<string,unknown>)=>new Promise((resolve,reject)=>pending.push({name,args,resolve,reject}))};
 }});
 return {...exports,pending,mount:()=>mount(),emit:(payload:unknown)=>event({payload}),observed:()=>({active,settled,unlistened})}as unknown as{
  startServing():Promise<void>;start():Promise<void>;startPublication():Promise<void>;startRecovery(value:typeof publication):Promise<void>;pause():Promise<void>;checkStatus():Promise<void>;current():{work:typeof work|typeof recoveryWork|typeof publicationWork|typeof servingWork|null;message:string;ready:boolean;startPending:boolean;pausePending:boolean};pending:typeof pending;mount():()=>void;emit(v:unknown):void;observed():{active:boolean;settled:number;unlistened:boolean};
 };
}
async function loaded(selected:typeof scan|null=scan,snapshot:typeof work|typeof recoveryWork|typeof publicationWork|typeof servingWork|null=null){const view=component(selected);const unmount=view.mount();await setImmediate();assert.equal(view.pending[0].name,'photo_reference_work_status');view.pending[0].resolve(snapshot);await setImmediate();return{view,unmount};}
test('opening the panel checks status and never starts a read',{timeout:5000},async()=>{
 const {view,unmount}=await loaded();assert.equal(view.pending.length,1);assert.equal(view.observed().active,false);assert.equal(view.current().ready,true);unmount();assert.equal(view.observed().unlistened,true);
});
test('start binds source scan and request without granting more allowance',{timeout:5000},async()=>{
 const {view,unmount}=await loaded();const call=view.start();const request=view.pending[1];
 assert.equal(request.name,'start_photo_reference_read');assert.equal(request.args.sourceId,sourceId);assert.equal(request.args.expectedScan,scan.scanId);assert.equal(request.args.requestId,work.requestId);assert.equal('additional'in request.args,false);
 request.resolve(work);await call;assert.equal(view.observed().active,true);assert.equal(view.observed().settled,0);
 view.emit({...work,state:'stopped'});await setImmediate();assert.equal(view.observed().active,false);assert.equal(view.observed().settled,1);unmount();
});
test('a terminal event before start acknowledgement cannot be replaced by a late starting reply',{timeout:5000},async()=>{
 const {view,unmount}=await loaded();const call=view.start();view.emit({...work,state:'stopped'});view.pending[1].resolve({...work,state:'starting'});await call;
 assert.equal(view.current().work?.state,'stopped');assert.equal(view.observed().active,false);assert.equal(view.observed().settled,1);unmount();
});
test('foreign progress cannot replace the owned request',{timeout:5000},async()=>{
 const {view,unmount}=await loaded();const call=view.start();view.pending[1].resolve(work);await call;
 for(const change of [{sourceId:'other'},{scanId:'b'.repeat(64)},{requestId:'00000000-0000-4000-8000-000000000999'}])view.emit({...work,...change,state:'stopped'});
 assert.equal(view.current().work?.state,'preparing');assert.equal(view.observed().active,true);unmount();
});
test('pause waits for its scoped confirmation and defeats a late start acknowledgement',{timeout:5000},async()=>{
 const {view,unmount}=await loaded();const start=view.start();const pause=view.pause();
 assert.equal(view.pending[2].name,'pause_photo_reference_read');assert.equal(view.pending[2].args.requestId,work.requestId);assert.equal(view.pending[2].args.expectedScan,scan.scanId);
 view.emit({...work,state:'stopped'});assert.equal(view.current().pausePending,true);view.pending[2].resolve({...work,state:'paused'});await pause;
 view.pending[1].resolve(work);await start;assert.equal(view.current().work?.state,'paused');assert.equal(view.observed().active,false);assert.equal(view.observed().settled,1);unmount();
});
test('status restoration preserves a terminal event received before the status reply',{timeout:5000},async()=>{
 const view=component();const unmount=view.mount();await setImmediate();view.emit({...work,state:'stopped'});view.pending[0].resolve(work);await setImmediate();
 assert.equal(view.current().work?.state,'stopped');assert.equal(view.observed().active,false);assert.equal(view.observed().settled,1);unmount();
});
test('a reloaded panel can pause existing work without starting another read',{timeout:5000},async()=>{
 const {view,unmount}=await loaded(null,work);assert.equal(view.observed().active,true);const pause=view.pause();assert.equal(view.pending[1].name,'pause_photo_reference_read');view.pending[1].resolve({...work,state:'paused'});await pause;assert.equal(view.observed().active,false);unmount();
});
test('no read starts for unapproved abandoned complete or missing scans',{timeout:5000},async()=>{
 for(const selected of [null,{...scan,additionalReadAllowance:10},{...scan,abandoned:true},{...scan,prepared:true},{...scan,current:false}]){
  const {view,unmount}=await loaded(selected);await view.start();assert.equal(view.pending.length,1);unmount();
 }
});
test('an unconfirmed stop fences new starts and does not refresh as completed',{timeout:5000},async()=>{
 const {view,unmount}=await loaded(null,work);const pause=view.pause();view.pending[1].reject('source_read_shutdown_unconfirmed');await pause;
 assert.equal(view.observed().active,true);assert.equal(view.observed().settled,0);assert.match(view.current().message,/confirm|stop/i);await view.start();assert.equal(view.pending.length,2);unmount();
});
test('revocation teardown ignores all delayed replies errors and events',{timeout:5000},async()=>{
 for(const action of ['start','pause','status'])for(const fails of [false,true]){
  const {view,unmount}=await loaded(scan,action==='pause'?work:null);const call=action==='start'?view.start():action==='pause'?view.pause():view.checkStatus();await setImmediate();unmount();const before=view.current();
  if(fails)view.pending[1].reject('source_approval_changed');else view.pending[1].resolve(work);
  view.emit({...work,state:'stopped'});await call;assert.equal(view.current().work,before.work);assert.equal(view.current().message,before.message);assert.equal(view.observed().settled,0);
 }
});

test('a rejected start with a verified empty owner does not leave controls stuck',{timeout:5000},async()=>{
 const {view,unmount}=await loaded();const call=view.start();view.pending[1].reject('source_read_already_running');await setImmediate();
 assert.equal(view.pending[2].name,'photo_reference_work_status');view.pending[2].resolve(null);await call;
 assert.equal(view.current().startPending,false);assert.equal(view.current().work,null);assert.equal(view.observed().active,false);unmount();
});
test('an invalid initial status fails closed instead of starting another reader',{timeout:5000},async()=>{
 for(const reply of [undefined,{...work,sourceId:'other'}]){
  const view=component();const unmount=view.mount();await setImmediate();view.pending[0].resolve(reply);await setImmediate();
  assert.equal(view.current().ready,false);await view.start();assert.equal(view.pending.length,1);assert.equal(view.observed().active,true);unmount();
 }
});

test('buffered active progress cannot replace a terminal status snapshot',{timeout:5000},async()=>{
 const view=component();const unmount=view.mount();await setImmediate();view.emit(work);view.pending[0].resolve({...work,state:'stopped'});await setImmediate();
 assert.equal(view.current().work?.state,'stopped');assert.equal(view.observed().active,false);unmount();
});
test('a late stopped event cannot clear an unconfirmed stop',{timeout:5000},async()=>{
 const {view,unmount}=await loaded(null,work);const pause=view.pause();view.pending[1].reject('source_read_shutdown_unconfirmed');await pause;
 view.emit({...work,state:'stopped'});assert.equal(view.observed().active,true);assert.equal(view.observed().settled,0);unmount();
});
test('request IDs use secure random bytes on WebViews without randomUUID',{timeout:5000},async()=>{
 for(const mode of ['bytes','none'] as const){
  const view=component(scan,mode);const unmount=view.mount();await setImmediate();view.pending[0].resolve(null);await setImmediate();
  const call=view.start();
  if(mode==='none'){await call;assert.equal(view.pending.length,1);assert.match(view.current().message,/Secure request IDs/);}
  else{const requestId=String(view.pending[1].args.requestId);assert.match(requestId,/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);view.pending[1].resolve({...work,requestId,state:'stopped'});await call;}
  unmount();
 }
});

test('recovery binds the displayed record and cannot grant read or upload allowance',{timeout:5000},async()=>{
 const {view,unmount}=await loaded(null);
 await view.startRecovery({...publication});assert.equal(view.pending.length,1);
 const call=view.startRecovery(publication);const request=view.pending[1];
 assert.equal(request.name,'start_photo_reference_recovery');assert.equal(request.args.sourceId,sourceId);
 assert.equal(request.args.resourceKey,publication.resourceKey);assert.equal(request.args.expectedRecord,publication.recordId);
 assert.equal('additional' in request.args,false);request.resolve(recoveryWork);await call;
 view.emit({...recoveryWork,recordId:'e'.repeat(64),state:'stopped'});assert.equal(view.observed().active,true);
 const pause=view.pause();assert.equal(view.pending[2].name,'pause_photo_reference_recovery');
 assert.equal(view.pending[2].args.expectedRecord,publication.recordId);
 view.pending[2].resolve({...recoveryWork,state:'paused'});await pause;
 assert.equal(view.current().work?.state,'paused');assert.equal(view.observed().active,false);unmount();
});
test('a restored recovery keeps other operations blocked until its own confirmed stop',{timeout:5000},async()=>{
 const {view,unmount}=await loaded(scan,recoveryWork);await view.start();await view.startRecovery(publication);assert.equal(view.pending.length,1);
 view.emit({...work,state:'stopped'});assert.equal(view.current().work?.state,'recovering');
 const pause=view.pause();view.pending[1].reject('source_read_shutdown_unconfirmed');await pause;
 assert.equal(view.observed().active,true);assert.equal(view.observed().settled,0);unmount();
});

test('publication requires a completed displayed scan and never grants more allowance',{timeout:5000},async()=>{
 for(const selected of [null,scan,{...scan,prepared:true,abandoned:true},{...scan,prepared:true,current:false}]){
  const {view,unmount}=await loaded(selected);await view.startPublication();assert.equal(view.pending.length,1);unmount();
 }
 const {view,unmount}=await loaded({...scan,prepared:true});const start=view.startPublication();
 assert.equal(view.pending[1].name,'start_photo_reference_publication');assert.equal(view.pending[1].args.expectedScan,scan.scanId);
 assert.equal('additional' in view.pending[1].args,false);assert.equal('resourceKey' in view.pending[1].args,false);
 view.pending[1].resolve(publicationWork);await start;
 view.emit({...work,state:'stopped'});assert.equal(view.current().work?.state,'publishing');
 const pause=view.pause();assert.equal(view.pending[2].name,'pause_photo_reference_publication');
 view.pending[2].resolve({...publicationWork,state:'paused'});await pause;assert.equal(view.observed().active,false);unmount();
});
test('restored publication excludes reads and recovery until confirmed stop',{timeout:5000},async()=>{
 const {view,unmount}=await loaded({...scan,prepared:true},publicationWork);
 await view.start();await view.startRecovery(publication);await view.startPublication();assert.equal(view.pending.length,1);
 view.emit({...recoveryWork,state:'stopped'});assert.equal(view.observed().active,true);
 const pause=view.pause();view.pending[1].reject('source_read_shutdown_unconfirmed');await pause;
 assert.equal(view.observed().active,true);assert.equal(view.observed().settled,0);unmount();
});

test('serving binds the displayed selection and stays active during a policy pause',async()=>{
 const {view,unmount}=await loaded();const call=view.startServing();const request=view.pending[1];
 assert.equal(request.name,'start_photo_reference_serving');assert.equal(request.args.sourceId,sourceId);
 assert.equal(request.args.expectedSelection,serving.selectionId);assert.equal(request.args.requestId,work.requestId);
 assert.deepEqual(Object.keys(request.args).sort(),['expectedSelection','requestId','sourceId']);
 request.resolve(servingWork);await call;assert.equal(view.observed().active,true);
 view.emit({...servingWork,state:'paused',code:'on_battery'});assert.equal(view.observed().active,true);assert.equal(view.observed().settled,0);
 view.emit({...servingWork,selectionId:'f'.repeat(64),state:'stopped'});assert.equal(view.observed().active,true);
 const paused=view.pause();assert.equal(view.pending[2].name,'pause_photo_reference_serving');
 assert.equal(view.pending[2].args.expectedSelection,serving.selectionId);
 view.pending[2].resolve({...servingWork,state:'paused',code:null});await paused;
 assert.equal(view.observed().active,false);assert.equal(view.observed().settled,1);unmount();
});
