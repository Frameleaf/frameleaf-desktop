import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp,mkdir,realpath,readFile,writeFile,rm,symlink,link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import subprocess from 'node:child_process';
import { writeFileSync, rmSync, mkdirSync } from 'node:fs';
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
  const calls=[];let pg,pgData,pgReadonly=false,exists=false,failRestore=false,canonical=true,failStop=false,badReceipt=false,failValidation=false,readOnlyProof=true,postgresMajor=19,vectorVersion='0.8.7';
  const original=subprocess.spawn;
  subprocess.spawn=(file,args,options)=>{
   const name=basename(file).replace(/\.exe$/,'');calls.push({name,args,options});
   assert.ok(['initdb','postgres','pgIsready','psql','createdb','pgRestore','node','pgCtl','pg_checksums'].includes(name),'unexpected process '+name);
   const child=new EventEmitter();Object.assign(child,{pid:7000+calls.length,exitCode:null,signalCode:null,stdout:new PassThrough(),stderr:new PassThrough()});
   const exit=(code=0)=>{if(child.exitCode!==null)return;child.exitCode=code;child.stdout.end();child.stderr.end();child.emit('exit',code,null);child.emit('close',code,null);};child.kill=()=>exit();
   if(name==='postgres'){pg=child;pgData=args[args.indexOf('-D')+1];pgReadonly=args.includes('default_transaction_read_only=on');exists=pgReadonly;writeFileSync(join(pgData,'postmaster.pid'),String(child.pid)+'\n');}
   else queueMicrotask(()=>{
    if(name==='initdb'){mkdirSync(args[args.indexOf('-D')+1],{mode:0o700});writeFileSync(join(args[args.indexOf('-D')+1],'PG_VERSION'),'19');}
    if(name==='psql')child.stdout.write(args.at(-1).includes('pg_database')?(exists?'1\n':'\n'):JSON.stringify({postgresMajor,vectorVersion,canonical,...(args.at(-1).includes('transaction_read_only')?{readOnly:pgReadonly&&readOnlyProof}:{})})+'\n');
    if(name==='createdb')exists=true;
    if(name==='pgRestore'&&!args.includes('--list')&&failRestore){failRestore=false;exit(1);return;}
    if(name==='node'){
     assert.deepEqual(args.slice(1),['frameleaf-admin',pgReadonly?'validate-restore':'restore-state']);
     if(pgReadonly){if(failValidation){child.stderr.write('synthetic secret validation error');exit(1);return;}child.stdout.write(JSON.stringify({protocolVersion:1,state:'restore-schema-valid',installationId:f.binding.installationId,operationId:badReceipt?'33333333-3333-4333-8333-333333333333':f.binding.operationId})+'\n');}
     assert.equal(options.env.FRAMELEAF_MANAGER_ORIGIN,'restored_library');
     assert.equal(options.env.FRAMELEAF_MANAGER_INSTALLATION,f.binding.installationId);
     assert.equal(options.env.FRAMELEAF_MANAGER_RESTORE_OPERATION_ID,f.binding.operationId);
    }
    if(name==='pgCtl'){if(failStop){failStop=false;exit(1);return;}if(pgReadonly)rmSync(join(pgData,'postmaster.pid'));pg.kill();}exit();
   });
   return child;
  };syncBuiltinESMExports();
  try{await run({...f,calls,failRestore:()=>{failRestore=true;},invalidSchema:()=>{canonical=false;},failStop:()=>{failStop=true;},invalidValidationReceipt:()=>{badReceipt=true;},failValidation:()=>{failValidation=true;},invalidReadOnly:()=>{readOnlyProof=false;},invalidPgVersion:()=>{postgresMajor=18;},invalidVector:()=>{vectorVersion='0.8.6';}});}
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

test('prepared target inspection revalidates staged input and the current profile descriptor', async (t) => {
  assert.equal(typeof owner.readHostRestoreTarget, 'function');
  for (const mutation of ['input', 'profile']) {
    await preparedTargetFixture(t, async ({ c, receipt, path }) => {
      if (mutation === 'input')
        await writeFile(
          join(path, 'input', 'database.dump'),
          'changed after preparation',
          { mode: 0o600 },
        );
      else
        await writeFile(join(c.state, 'host-state.json'), '{}', {
          mode: 0o600,
        });
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

test('prepared target inspection refuses a changed target descriptor and a database replaced during inspection', async (t) => {
  assert.equal(typeof owner.readHostRestoreTarget, 'function');
  for (const mutation of ['marker', 'race']) {
    await preparedTargetFixture(t, async ({ c, receipt, target, database }) => {
      if (mutation === 'marker')
        await writeFile(join(target, 'host-state.json'), '{}', { mode: 0o600 });
      let replaced = false,
        probe;
      if (mutation === 'race') {
        const original = filesystem.open;
        probe = t.mock.method(filesystem, 'open', async (...args) => {
          const file = await original(...args);
          if (!replaced && args[0] === join(target, 'restore-result.json')) {
            replaced = true;
            await filesystem.rename(
              database,
              join(target, 'retained-database'),
            );
            await mkdir(database, { mode: 0o700 });
            await writeFile(join(database, 'PG_VERSION'), '19', {
              mode: 0o600,
            });
          }
          return file;
        });
        syncBuiltinESMExports();
      }
      try {
        await assert.rejects(
          owner.readHostRestoreTarget(c, receipt),
          /host_restore_target_invalid/,
        );
      } finally {
        probe?.mock.restore();
        syncBuiltinESMExports();
      }
      if (mutation === 'race') assert.equal(replaced, true);
    });
  }
});

test('prepared target inspection refuses an oversized PG_VERSION before streaming its contents', async (t) => {
  assert.equal(typeof owner.readHostRestoreTarget, 'function');
  await preparedTargetFixture(t, async ({ c, receipt, database }) => {
    const version = join(database, 'PG_VERSION');
    await filesystem.truncate(version, 1024 * 1024);
    const original = filesystem.open;
    let contentReads = 0;
    const probe = t.mock.method(filesystem, 'open', async (...args) => {
      const handle = await original(...args);
      if (args[0] === version)
        t.mock.method(handle, 'createReadStream', () => {
          contentReads++;
          throw Error('oversized version content must not be scanned');
        });
      return handle;
    });
    syncBuiltinESMExports();
    try {
      await assert.rejects(
        owner.readHostRestoreTarget(c, receipt),
        /host_restore_target_invalid/,
      );
      assert.equal(contentReads, 0);
    } finally {
      probe.mock.restore();
      syncBuiltinESMExports();
    }
  });
});

test('prepared target inspection bounds a version stream that grows after the opened-file size check', async (t) => {
  assert.equal(typeof owner.readHostRestoreTarget, 'function');
  await preparedTargetFixture(t, async ({ c, receipt, database }) => {
    const version = join(database, 'PG_VERSION');
    const original = filesystem.open;
    let chunks = 0;
    const probe = t.mock.method(filesystem, 'open', async (...args) => {
      const handle = await original(...args);
      if (args[0] === version)
        t.mock.method(handle, 'createReadStream', () =>
          (async function* () {
            chunks++;
            yield Buffer.alloc(17, 0x31);
            chunks++;
            throw Error('must reject before consuming another oversized chunk');
          })(),
        );
      return handle;
    });
    syncBuiltinESMExports();
    try {
      await assert.rejects(
        owner.readHostRestoreTarget(c, receipt),
        /host_restore_target_invalid/,
      );
      assert.equal(chunks, 1);
    } finally {
      probe.mock.restore();
      syncBuiltinESMExports();
    }
  });
});
test('offline restore verification checks only the prepared cluster with the signed checksum tool', async (t) => {
  assert.equal(typeof owner.verifyHostRestoreTarget, 'function');
  for (const failure of [false, true]) {
    await preparedTargetFixture(
      t,
      async ({ c, receipt, target, database, calls }) => {
        // Retained controller metadata is outside the cluster checksum scope.
        await writeFile(join(target, 'activation-intent.json'), JSON.stringify({ schemaVersion: 1, prepared: receipt }), { mode: 0o600 });
        c.entryPoints.pgChecksums =
          'bin/pg_checksums' + (process.platform === 'win32' ? '.exe' : '');
        const priorCalls = calls.length;
        const seen = [];
        const probe = t.mock.method(
          subprocess,
          'spawn',
          (file, args, options) => {
            seen.push({ file, args, options });
            const child = new EventEmitter();
            Object.assign(child, {
              pid: 8999,
              exitCode: null,
              signalCode: null,
            });
            child.kill = () => {
              child.exitCode = 1;
              child.emit('close', 1, null);
              return true;
            };
            queueMicrotask(() => {
              child.exitCode = failure ? 1 : 0;
              child.emit('close', child.exitCode, null);
            });
            return child;
          },
        );
        syncBuiltinESMExports();
        try {
          const work = owner.verifyHostRestoreTarget(
            c,
            receipt,
            new Promise(() => {}),
          );
          if (failure)
            await assert.rejects(work, /host_restore_offline_invalid/);
          else
            assert.deepEqual(await work, {
              receipt,
              target,
              database,
              offlineChecksums: true,
            });
          assert.equal(seen.length, 1);
          assert.equal(
            seen[0].file,
            join(c.runtime, c.entryPoints.pgChecksums),
          );
          assert.deepEqual(seen[0].args, ['--check', '--pgdata', database]);
          assert.equal(seen[0].options.stdio, 'ignore');
          assert.ok(!JSON.stringify(seen[0].args).includes(c.password));
          assert.equal(calls.length, priorCalls);
          assert.equal(
            await readFile(join(c.state, 'database', 'sentinel'), 'utf8'),
            'original database must survive',
          );
        } finally {
          probe.mock.restore();
          syncBuiltinESMExports();
        }
      },
    );
  }
});

test('offline restore verification refuses cancellation, unsafe cluster contents and changed target evidence', async (t) => {
  assert.equal(typeof owner.verifyHostRestoreTarget, 'function');
  for (const mutation of [
    'cancel-before',
    'cancel-during',
    'hardlink',
    'directory-link',
    'changed',
    'tool-path',
  ]) {
    await preparedTargetFixture(t, async ({ c, receipt, target, database }) => {
      c.entryPoints.pgChecksums =
        'bin/pg_checksums' + (process.platform === 'win32' ? '.exe' : '');
      let stop;
      const stopping = new Promise((resolve) => {
        stop = resolve;
      });
      if (mutation === 'cancel-before') stop();
      if (mutation === 'tool-path') c.entryPoints.pgChecksums = '../outside';
      if (mutation === 'hardlink')
        await link(
          join(database, 'PG_VERSION'),
          join(database, 'linked-version'),
        );
      if (mutation === 'directory-link')
        await symlink(
          c.state,
          join(database, 'outside'),
          process.platform === 'win32' ? 'junction' : 'dir',
        );
      let starts = 0,
        kills = 0;
      const probe = t.mock.method(subprocess, 'spawn', () => {
        starts++;
        const child = new EventEmitter();
        Object.assign(child, { pid: 8999, exitCode: null, signalCode: null });
        child.kill = () => {
          kills++;
          child.exitCode = 1;
          child.emit('close', 1, null);
          return true;
        };
        queueMicrotask(async () => {
          if (mutation === 'cancel-during') {
            stop();
            return;
          }
          if (mutation === 'changed')
            await writeFile(join(target, 'restore-result.json'), '{}', {
              mode: 0o600,
            });
          child.exitCode = 0;
          child.emit('close', 0, null);
        });
        return child;
      });
      syncBuiltinESMExports();
      try {
        await assert.rejects(
          owner.verifyHostRestoreTarget(c, receipt, stopping),
          /host_restore_offline_invalid|host_restore_cancelled/,
        );
        assert.equal(
          starts,
          ['cancel-during', 'changed'].includes(mutation) ? 1 : 0,
        );
        if (mutation === 'cancel-during') assert.ok(kills > 0);
        assert.equal(
          await readFile(join(c.state, 'database', 'sentinel'), 'utf8'),
          'original database must survive',
        );
      } finally {
        probe.mock.restore();
        syncBuiltinESMExports();
      }
    });
  }
});
test('offline verification cancels while hashing staged input without launching a checksum process', async (t) => {
  assert.equal(typeof owner.verifyHostRestoreTarget, 'function');
  await preparedTargetFixture(t, async ({ c, receipt, path, bytes }) => {
    c.entryPoints.pgChecksums =
      'bin/pg_checksums' + (process.platform === 'win32' ? '.exe' : '');
    let stop;
    const stopping = new Promise((resolve) => {
      stop = resolve;
    });
    let chunks = 0,
      starts = 0;
    const original = filesystem.open;
    const fileProbe = t.mock.method(filesystem, 'open', async (...args) => {
      const handle = await original(...args);
      if (args[0] === join(path, 'input', 'database.dump'))
        t.mock.method(handle, 'createReadStream', () =>
          (async function* () {
            chunks++;
            stop();
            yield bytes;
            chunks++;
            throw Error('cancelled dump must not consume another chunk');
          })(),
        );
      return handle;
    });
    const spawnProbe = t.mock.method(subprocess, 'spawn', () => {
      starts++;
      throw Error('must not spawn');
    });
    syncBuiltinESMExports();
    try {
      await assert.rejects(
        owner.verifyHostRestoreTarget(c, receipt, stopping),
        /host_restore_cancelled/,
      );
      assert.equal(chunks, 1);
      assert.equal(starts, 0);
    } finally {
      fileProbe.mock.restore();
      spawnProbe.mock.restore();
      syncBuiltinESMExports();
    }
  });
});

test('prepared target metadata hashes stop if a JSON file grows beyond its opened-file bound', async (t) => {
  await preparedTargetFixture(t, async ({ c, receipt, target }) => {
    let chunks = 0;
    const original = filesystem.open;
    const probe = t.mock.method(filesystem, 'open', async (...args) => {
      const handle = await original(...args);
      if (args[0] === join(target, 'restore-target.json'))
        t.mock.method(handle, 'createReadStream', () =>
          (async function* () {
            chunks++;
            yield Buffer.alloc(4097, 0x31);
            chunks++;
            throw Error('oversized metadata must not consume another chunk');
          })(),
        );
      return handle;
    });
    syncBuiltinESMExports();
    try {
      await assert.rejects(
        owner.readHostRestoreTarget(c, receipt),
        /host_restore_target_invalid/,
      );
      assert.equal(chunks, 1);
    } finally {
      probe.mock.restore();
      syncBuiltinESMExports();
    }
  });
});

test('restore owner verifies the exact prepared target without exposing paths or starting an application', async t => {
  await preparedTargetFixture(t, async ({ c, receipt, calls }) => {
    c = { ...c, mode: 'restore-prepare', entryPoints: { ...c.entryPoints,
      pgChecksums: 'bin/pg_checksums' + (process.platform === 'win32' ? '.exe' : '') } };
    const request = { protocolVersion: 1, action: 'verify-restore', operationId: receipt.binding.operationId, prepared: receipt, verificationId: '44444444-4444-4444-8444-444444444444' };
    assert.deepEqual(owner.checkpointControlRequest(c, JSON.stringify(request)), request);
    assert.deepEqual(owner.checkpointControlRequest(c, JSON.stringify(request) + ' '.repeat(1024)), request);
    assert.throws(() => owner.checkpointControlRequest(c, JSON.stringify(request) + ' '.repeat(4096)), /host_checkpoint_request_invalid/);
    for (const changed of [
      { ...request, schemaValidated: true }, { ...request, path: '/outside' }, { ...request, operationId: '11111111-1111-4111-8111-111111111111' },
      { ...request, prepared: { ...receipt, path: '/outside' } },
      { ...request, prepared: { ...receipt, binding: { ...receipt.binding, manifestSha256: '0'.repeat(64) } } },
    ]) assert.throws(() => owner.checkpointControlRequest(c, JSON.stringify(changed)), /host_checkpoint_request_invalid/);
    assert.throws(() => owner.checkpointControlRequest({ ...c, mode: 'server' }, JSON.stringify(request)), /host_checkpoint_request_invalid/);
    let stop, handler, ready;
    const stopping = new Promise(resolve => { stop = resolve; });
    const waiting = new Promise(resolve => { ready = resolve; });
    const prior = calls.length;
    const host = owner.runHost(c, stopping, value => { handler = value; ready(); });
    try {
      await Promise.race([waiting, host]);
      const work = handler(request);
      await assert.rejects(handler(request), /host_checkpoint_unavailable/);
      assert.deepEqual(await work, { state: 'restore-verified', prepared: receipt, offlineChecksums: true, schemaValidated: true, verificationId: request.verificationId });
      assert.deepEqual(calls.slice(prior).map(call => call.name), ['pg_checksums','postgres','pgIsready','psql','psql','node','pgCtl','pg_checksums']);
      assert.equal(await readFile(join(c.state, 'database/sentinel'), 'utf8'), 'original database must survive');
    } finally { stop(); await host; }
  });
});


test('canonical target validation never publishes proof for schema, helper, receipt, stop or cancellation failures', async t => {
  for (const mutation of ['schema', 'helper', 'receipt', 'stop', 'cancel', 'read-only', 'postgres', 'vector']) {
    await preparedTargetFixture(t, async f => {
      f.c.entryPoints.pgChecksums = 'bin/pg_checksums' + (process.platform === 'win32' ? '.exe' : '');
      if (mutation === 'schema') f.invalidSchema();
      if (mutation === 'read-only') f.invalidReadOnly();
      if (mutation === 'postgres') f.invalidPgVersion();
      if (mutation === 'vector') f.invalidVector();
      if (mutation === 'helper') f.failValidation();
      if (mutation === 'receipt') f.invalidValidationReceipt();
      if (mutation === 'stop') f.failStop();
      const prior = f.calls.length;
      await assert.rejects(owner.validateHostRestoreTarget(f.c, f.receipt, mutation === 'cancel' ? Promise.resolve() : new Promise(() => {})), /host_restore_(canonical_invalid|cancelled)/);
      assert.ok(!f.calls.slice(prior).some(call => ['initdb', 'createdb', 'pgRestore'].includes(call.name)));
      assert.ok(!(await readFile(join(f.target, 'host.log'), 'utf8')).includes('synthetic secret validation error'));
      assert.equal(await readFile(join(f.c.state, 'database/sentinel'), 'utf8'), 'original database must survive');
    });
  }
});
