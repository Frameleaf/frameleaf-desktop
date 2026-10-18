import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp,mkdir,realpath,readFile,writeFile,rm,symlink,link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import subprocess from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { basename } from 'node:path';
import filesystem from 'node:fs/promises';
import * as owner from '../runtime/host-agent.mjs';
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
async function fixture(t,run){
 const state=await realpath(await mkdtemp(join(tmpdir(),'frameleaf-restore-input-')));t.after(()=>rm(state,{recursive:true,force:true}));
 const suffix=process.platform==='win32'?'.exe':'';
 const c={state,runtime:join(state,'signed-runtime'),manifestSha256:'a'.repeat(64),sourceRevision:'b'.repeat(40),postgresMajor:'19',databasePort:54329,apiPort:2283,password:'synthetic private database password',entryPoints:Object.fromEntries(['node','server','postgres','initdb','createdb','psql','pgIsready','pgCtl','pgDump','pgRestore','hdr','studioBrowserGuard','studio'].map(name=>[name,'bin/'+name+suffix]))};
 Object.assign(c.entryPoints,{ffmpeg:'media/ffmpeg'+suffix,ffprobe:'media/ffprobe'+suffix,rawRenderer:'raw/darktable-cli'+suffix,rawDecoder:'raw/dcraw_emu'+suffix,studioBrowser:'browser/chrome'+suffix});
 await owner.claimState(c);
 const bytes=Buffer.from('PGDMP restore input fixture');
 const recovery={schemaVersion:1,runtime:'native',mediaIncluded:false,databaseFormat:'frameleaf-canonical',libraryId:'c'.repeat(12),createdAt:1234,installation:{id:'d'.repeat(12),name:'Library',release:'frameleaf-v3.0.0-1'},checkpoint:{protocolVersion:1,state:'checkpoint',schemaVersion:1,operationId:'11111111-1111-4111-8111-111111111111',manifestSha256:'e'.repeat(64),sourceRevision:'f'.repeat(40),postgresMajor:'19',databaseFormat:'frameleaf-canonical',dump:{bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')}}};
 const binding={schemaVersion:1,runtime:'native',operationId:'22222222-2222-4222-8222-222222222222',reviewId:'33333333-3333-4333-8333-333333333333',snapshotId:'1'.repeat(64),installationId:'2'.repeat(12),manifestSha256:c.manifestSha256,sourceRevision:c.sourceRevision,libraryId:recovery.libraryId,recoverySha256:digest(recovery)};
 const path=join(state,'restore-input',binding.operationId);
 await mkdir(join(path,'input'),{recursive:true,mode:0o700});await writeFile(join(path,'input','database.dump'),bytes,{mode:0o600});await writeFile(join(path,'input','recovery.json'),JSON.stringify(recovery),{mode:0o600});await writeFile(join(path,'restore-intent.json'),JSON.stringify(binding),{mode:0o600});
 await run({c,bytes,recovery,binding,path});
}
test('owner reads only exact staged restore bytes bound to the target runtime without starting processes',async t=>{
 await fixture(t,async({c,recovery,binding,path})=>{
  assert.equal(typeof owner.readHostRestoreInput,'function');
  const result=await owner.readHostRestoreInput(c,binding);
  assert.deepEqual(result,{binding,recovery,dump:join(path,'input','database.dump')});
 });
});
test('owner refuses malformed bindings, changed bytes, links and unknown restore input',async t=>{
 for(const mutation of ['binding','digest','dump','extra','link','hardlink','profile'])await fixture(t,async({c,binding,path})=>{
  assert.equal(typeof owner.readHostRestoreInput,'function');
  const supplied={...binding};
  if(mutation==='binding')supplied.path='/outside';
  if(mutation==='digest')supplied.recoverySha256='0'.repeat(64);
  if(mutation==='dump')await writeFile(join(path,'input','database.dump'),'changed');
  if(mutation==='extra')await writeFile(join(path,'foreign'),'retain');
  if(mutation==='profile')await writeFile(join(c.state,'host-state.json'),'{}',{mode:0o600});
  if(mutation==='link'||mutation==='hardlink'){
   const file=join(path,'input','database.dump'),other=join(c.state,'outside');await writeFile(other,await readFile(file),{mode:0o600});await rm(file);if(mutation==='link')await symlink(other,file);else await link(other,file);
  }
  await assert.rejects(owner.readHostRestoreInput(c,supplied),/host_restore_input_invalid/);
 });
});


async function restoreFixture(t, run) {
 await fixture(t,async f=>{
  f.recovery.checkpoint.sourceRevision=f.c.sourceRevision;
  f.binding.recoverySha256=digest(f.recovery);
  await writeFile(join(f.path,'input','recovery.json'),JSON.stringify(f.recovery),{mode:0o600});
  await writeFile(join(f.path,'restore-intent.json'),JSON.stringify(f.binding),{mode:0o600});
  await mkdir(join(f.c.state,'database'),{mode:0o700});await writeFile(join(f.c.state,'database','sentinel'),'original database must survive',{mode:0o600});
  const calls=[];let pg,exists=false,failRestore=false,canonical=true,failStop=false;
  const original=subprocess.spawn;
  subprocess.spawn=(file,args,options)=>{
   const name=basename(file).replace(/\.exe$/,'');calls.push({name,args,options});
   assert.ok(['initdb','postgres','pgIsready','psql','createdb','pgRestore','node','pgCtl'].includes(name),'unexpected process '+name);
   const child=new EventEmitter();Object.assign(child,{pid:7000+calls.length,exitCode:null,signalCode:null,stdout:new PassThrough(),stderr:new PassThrough()});
   const exit=(code=0)=>{if(child.exitCode!==null)return;child.exitCode=code;child.stdout.end();child.stderr.end();child.emit('exit',code,null);child.emit('close',code,null);};child.kill=()=>exit();
   if(name==='postgres'){pg=child;exists=false;writeFileSync(join(args[args.indexOf('-D')+1],'postmaster.pid'),String(child.pid)+'\n');}
   else queueMicrotask(()=>{
    if(name==='initdb'){mkdirSync(args[args.indexOf('-D')+1],{mode:0o700});writeFileSync(join(args[args.indexOf('-D')+1],'PG_VERSION'),'19');}
    if(name==='psql')child.stdout.write(args.at(-1).includes('pg_database')?(exists?'1\n':'\n'):JSON.stringify({postgresMajor:19,vectorVersion:'0.8.7',canonical})+'\n');
    if(name==='createdb')exists=true;
    if(name==='pgRestore'&&!args.includes('--list')&&failRestore){failRestore=false;exit(1);return;}
    if(name==='node'){
     assert.deepEqual(args.slice(1),['frameleaf-admin','restore-state']);
     assert.equal(options.env.FRAMELEAF_MANAGER_ORIGIN,'restored_library');
     assert.equal(options.env.FRAMELEAF_MANAGER_INSTALLATION,f.binding.installationId);
     assert.equal(options.env.FRAMELEAF_MANAGER_RESTORE_OPERATION_ID,f.binding.operationId);
    }
    if(name==='pgCtl'){if(failStop){failStop=false;exit(1);return;}pg.kill();}exit();
   });
   return child;
  };syncBuiltinESMExports();
  try{await run({...f,calls,failRestore:()=>{failRestore=true;},invalidSchema:()=>{canonical=false;},failStop:()=>{failStop=true;}});}
  finally{subprocess.spawn=original;syncBuiltinESMExports();pg?.kill();}
 });
}

test('restore creates and validates a fresh cluster, drains it, and retains the original database',async t=>{
 await restoreFixture(t,async({c,binding,calls})=>{
  assert.equal(typeof owner.restoreHostDatabase,'function');
  const receipt=await owner.restoreHostDatabase(c,binding,new Promise(()=>{}));
  assert.equal(receipt.state,'restore-prepared');assert.deepEqual(receipt.binding,binding);
  assert.equal(receipt.validation.executionStateReconstructed,true);
  assert.equal(receipt.validation.canonical,true);
  const data=calls.find(x=>x.name==='postgres').args[1];
  assert.ok(data.startsWith(join(c.state,'restore-targets',binding.operationId)));
  assert.notEqual(data,join(c.state,'database'));
  assert.deepEqual(calls.map(x=>x.name),['initdb','postgres','pgIsready','psql','createdb','pgRestore','pgRestore','node','psql','pgCtl']);
  const restore=calls.find(x=>x.name==='pgRestore'&&!x.args.includes('--list'));
  for(const flag of ['--single-transaction','--exit-on-error','--no-owner','--no-acl'])assert.ok(restore.args.includes(flag));
  assert.ok(!JSON.stringify(calls.map(x=>x.args)).includes(c.password));
  assert.equal(await readFile(join(c.state,'database','sentinel'),'utf8'),'original database must survive');
  assert.deepEqual(JSON.parse(await readFile(join(data,'..','restore-result.json'),'utf8')),receipt);
 });
});

test('uncertain restore attempts are retained and a retry never replays into their database',async t=>{
 await restoreFixture(t,async({c,binding,calls,failRestore})=>{
  assert.equal(typeof owner.restoreHostDatabase,'function');failRestore();
  await assert.rejects(owner.restoreHostDatabase(c,binding,new Promise(()=>{})));
  const first=calls.find(x=>x.name==='postgres').args[1];
  const receipt=await owner.restoreHostDatabase(c,binding,new Promise(()=>{}));
  const starts=calls.filter(x=>x.name==='postgres');assert.equal(starts.length,2);assert.notEqual(starts[1].args[1],first);
  assert.ok(await readFile(join(first,'PG_VERSION')));assert.equal(receipt.state,'restore-prepared');
  assert.equal(await readFile(join(c.state,'database','sentinel'),'utf8'),'original database must survive');
 });
});

test('failed canonical validation cannot publish a prepared restore target',async t=>{
 await restoreFixture(t,async({c,binding,calls,invalidSchema})=>{
  assert.equal(typeof owner.restoreHostDatabase,'function');invalidSchema();
  await assert.rejects(owner.restoreHostDatabase(c,binding,new Promise(()=>{})),/host_restore_database_invalid/);
  const data=calls.find(x=>x.name==='postgres').args[1];
  await assert.rejects(readFile(join(data,'..','restore-result.json')),{code:'ENOENT'});
  assert.equal(calls.at(-1).name,'pgCtl');
 });
});


test('restore requires confirmed clean shutdown before publishing its result',async t=>{
 await restoreFixture(t,async({c,binding,calls,failStop})=>{
  failStop();
  await assert.rejects(owner.restoreHostDatabase(c,binding,new Promise(()=>{})),/host_restore_shutdown_unconfirmed/);
  const data=calls.find(x=>x.name==='postgres').args[1];
  await assert.rejects(readFile(join(data,'..','restore-result.json')),{code:'ENOENT'});
 });
});

test('a cancelled restore cannot allocate a target or start a process',async t=>{
 await restoreFixture(t,async({c,binding,calls})=>{
  await assert.rejects(owner.restoreHostDatabase(c,binding,Promise.resolve()),/host_restore_cancelled/);
  assert.deepEqual(calls,[]);
  await assert.rejects(readFile(join(c.state,'restore-targets')),{code:'ENOENT'});
  await assert.rejects(owner.runHost(c,new Promise(()=>{}),()=>assert.fail(),{}),/host_restore_authority_invalid/);
 });
});

test('a backup requiring another runtime cannot be restored using the currently selected runtime',async t=>{
 await restoreFixture(t,async({c,binding,recovery,path,calls})=>{
  recovery.checkpoint.sourceRevision='e'.repeat(40);binding.recoverySha256=digest(recovery);
  await writeFile(join(path,'input','recovery.json'),JSON.stringify(recovery),{mode:0o600});
  await writeFile(join(path,'restore-intent.json'),JSON.stringify(binding),{mode:0o600});
  await assert.rejects(owner.restoreHostDatabase(c,binding,new Promise(()=>{})),/host_restore_runtime_required/);
  assert.deepEqual(calls,[]);
 });
});


test('cancellation during final input verification cannot publish a prepared target',async t=>{
 await restoreFixture(t,async({c,binding,calls})=>{
  let stop;const stopping=new Promise(resolve=>{stop=resolve;});
  const original=filesystem.realpath;
  const probe=t.mock.method(filesystem,'realpath',async(...args)=>{
   const value=await original(...args);
   if(args[0]===join(c.state,'restore-input')&&calls.at(-1)?.name==='pgCtl')stop();
   return value;
  });syncBuiltinESMExports();
  try{await assert.rejects(owner.restoreHostDatabase(c,binding,stopping),/host_restore_cancelled/);}
  finally{probe.mock.restore();syncBuiltinESMExports();}
  const data=calls.find(x=>x.name==='postgres').args[1];
  await assert.rejects(readFile(join(data,'..','restore-result.json')),{code:'ENOENT'});
 });
});

test('cancellation during result sync cannot return a successful prepared target',async t=>{
 await restoreFixture(t,async({c,binding})=>{
  let stop;const stopping=new Promise(resolve=>{stop=resolve;});
  const original=filesystem.open;
  const probe=t.mock.method(filesystem,'open',async(...args)=>{
   const handle=await original(...args);
   if(basename(String(args[0]))==='restore-result.json'){
    const sync=handle.sync.bind(handle);
    t.mock.method(handle,'sync',async()=>{await sync();stop();});
   }
   return handle;
  });syncBuiltinESMExports();
  try{await assert.rejects(owner.restoreHostDatabase(c,binding,stopping),/host_restore_cancelled/);}
  finally{probe.mock.restore();syncBuiltinESMExports();}
 });
});

test('restore maintenance admits only exact input bindings and starts no original database',async t=>{
 await restoreFixture(t,async({c,binding,calls})=>{
  const config={...c,mode:'restore-prepare'};
  const request={protocolVersion:1,action:'prepare-restore',operationId:binding.operationId,binding};
  assert.deepEqual(owner.checkpointControlRequest(config,JSON.stringify(request)),request);
  assert.throws(()=>owner.checkpointControlRequest({...c,mode:'server'},JSON.stringify(request)),/host_checkpoint_request_invalid/);
  for(const changed of [{...request,path:'/outside'},{...request,operationId:'11111111-1111-4111-8111-111111111111'},{...request,binding:{...binding,recoverySha256:'invalid'}},{...request,binding:{...binding,manifestSha256:'0'.repeat(64)}}])
   assert.throws(()=>owner.checkpointControlRequest(config,JSON.stringify(changed)),/host_checkpoint_request_invalid/);
  let stop,handler;const stopping=new Promise(resolve=>{stop=resolve;});
  let ready;const waiting=new Promise(resolve=>{ready=resolve;});
  const host=owner.runHost(config,stopping,value=>{handler=value;ready();});
  await Promise.race([waiting,host]);
  assert.deepEqual(calls,[]);
  await assert.rejects(handler({action:'checkpoint',operationId:binding.operationId}),/host_checkpoint_unavailable/);
  const work=handler(request);
  await assert.rejects(handler(request),/host_checkpoint_unavailable/);
  const receipt=await work;assert.equal(receipt.state,'restore-prepared');assert.deepEqual(receipt.binding,binding);
  stop();await host;
  assert.equal(await readFile(join(c.state,'database','sentinel'),'utf8'),'original database must survive');
 });
});


async function preparedTargetFixture(t, run) {
  await restoreFixture(t, async (f) => {
    const receipt = await owner.restoreHostDatabase(
      f.c,
      f.binding,
      new Promise(() => {}),
    );
    const target = join(
      f.c.state,
      'restore-targets',
      f.binding.operationId,
      receipt.attemptId,
    );
    const database = join(target, 'database');
    // The subprocess fixture models exit; real pg_ctl also removes this file on a clean stop.
    await rm(join(database, 'postmaster.pid'));
    await filesystem.chmod(join(database, 'PG_VERSION'), 0o600);
    await run({ ...f, receipt, target, database });
  });
}

test('prepared target inspection rechecks exact durable evidence and physical identities without starting or moving a database', async (t) => {
  assert.equal(typeof owner.readHostRestoreTarget, 'function');
  await preparedTargetFixture(
    t,
    async ({ c, receipt, target, database, calls }) => {
      const count = calls.length;
      assert.deepEqual(await owner.readHostRestoreTarget(c, receipt), {
        receipt,
        target,
        database,
      });
      assert.equal(calls.length, count);
      assert.equal(
        await readFile(join(c.state, 'database', 'sentinel'), 'utf8'),
        'original database must survive',
      );
      assert.equal(await readFile(join(database, 'PG_VERSION'), 'utf8'), '19');
    },
  );
});

test('prepared target inspection refuses malformed or foreign receipt authority', async (t) => {
  assert.equal(typeof owner.readHostRestoreTarget, 'function');
  for (const mutation of [
    'attempt',
    'binding',
    'profile',
    'target',
    'database',
    'validation',
    'extra',
  ]) {
    await preparedTargetFixture(t, async ({ c, receipt }) => {
      const changed = structuredClone(receipt);
      if (mutation === 'attempt') changed.attemptId = '../outside';
      if (mutation === 'binding') changed.binding.libraryId = '0'.repeat(12);
      if (mutation === 'profile') changed.profileIdentity = '1:2';
      if (mutation === 'target') changed.targetIdentity = '1:3';
      if (mutation === 'database') changed.databaseIdentity = '1:4';
      if (mutation === 'validation') changed.validation.canonical = false;
      if (mutation === 'extra') changed.path = '/caller/selected/database';
      await assert.rejects(
        owner.readHostRestoreTarget(c, changed),
        /host_restore_target_invalid/,
      );
    });
  }
});

test('prepared target inspection refuses changed on-disk evidence, a live target and replaced directories', async (t) => {
  assert.equal(typeof owner.readHostRestoreTarget, 'function');
  for (const mutation of [
    'result',
    'intent',
    'version',
    'pid',
    'link',
    'hardlink',
    'replace',
  ]) {
    await preparedTargetFixture(t, async ({ c, receipt, target, database }) => {
      const result = join(target, 'restore-result.json');
      if (mutation === 'result')
        await writeFile(
          result,
          JSON.stringify({ ...receipt, targetIdentity: '1:3' }),
          { mode: 0o600 },
        );
      if (mutation === 'intent') {
        const intent = JSON.parse(
          await readFile(join(target, 'restore-target.json'), 'utf8'),
        );
        await writeFile(
          join(target, 'restore-target.json'),
          JSON.stringify({
            ...intent,
            attemptId: '44444444-4444-4444-8444-444444444444',
          }),
          { mode: 0o600 },
        );
      }
      if (mutation === 'version')
        await writeFile(join(database, 'PG_VERSION'), '18', { mode: 0o600 });
      if (mutation === 'pid')
        await writeFile(join(database, 'postmaster.pid'), '1234', {
          mode: 0o600,
        });
      if (mutation === 'link' || mutation === 'hardlink') {
        const retained = join(target, 'retained-result.json');
        await filesystem.rename(result, retained);
        if (mutation === 'link') await symlink(retained, result);
        else await link(retained, result);
      }
      if (mutation === 'replace') {
        await filesystem.rename(database, join(target, 'retained-database'));
        await mkdir(database, { mode: 0o700 });
        await writeFile(join(database, 'PG_VERSION'), '19', { mode: 0o600 });
      }
      await assert.rejects(
        owner.readHostRestoreTarget(c, receipt),
        /host_restore_target_invalid/,
      );
      assert.equal(
        await readFile(join(c.state, 'database', 'sentinel'), 'utf8'),
        'original database must survive',
      );
    });
  }
});
