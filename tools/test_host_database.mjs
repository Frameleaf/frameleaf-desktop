import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import * as subprocess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtemp, mkdir, readFile, readdir, realpath, rm, writeFile, lstat } from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, basename, toNamespacedPath } from 'node:path';
import { claimState, runHost, validateConfig, canonicalHostPathMatches } from '../runtime/host-agent.mjs';

async function fixture(t, body) {
  const state = await realpath(await mkdtemp(join(tmpdir(), 'frameleaf-database-only-')));
  t.after(() => rm(state, { recursive: true, force: true }));
  const occupied = createServer();
  await new Promise(resolve => occupied.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => occupied.close(resolve)));
  const probe = createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const databasePort = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const suffix = process.platform === 'win32' ? '.exe' : '';
  const c = { mode: 'database', state, runtime: join(state, 'runtime'), manifestSha256: 'a'.repeat(64),
    sourceRevision: 'b'.repeat(40), postgresMajor: '19', password: 'synthetic private database password',
    databasePort, apiPort: occupied.address().port,
    entryPoints: Object.fromEntries(['node','server','postgres','initdb','createdb','psql','pgIsready','pgCtl','pgDump','pgRestore',
      'hdr','studioBrowserGuard','studio'].map(name => [name, 'bin/'+name+suffix])) };
  Object.assign(c.entryPoints, { ffmpeg: 'media/ffmpeg'+suffix, ffprobe: 'media/ffprobe'+suffix,
    rawRenderer: 'raw/darktable-cli'+suffix, rawDecoder: 'raw/dcraw_emu'+suffix, studioBrowser: 'browser/chrome'+suffix });
  await claimState(c);
  await mkdir(join(state, 'database'), { mode: 0o700 });
  await writeFile(join(state, 'database/PG_VERSION'), '19', { mode: 0o600 });
  const calls = []; let pg; let exists = true;
  const original = subprocess.default.spawn;
  subprocess.default.spawn = (file, args, options) => {
    const name = basename(file).replace(/\.exe$/, '');
    calls.push({ name, args, options });
    assert.ok(['postgres','psql','pgIsready','pgCtl','pgDump','pgRestore'].includes(name), 'unexpected process: '+name);
    const child = new EventEmitter();
    Object.assign(child, { pid: 4242 + calls.length, exitCode: null, signalCode: null, stdout: new PassThrough(), stderr: new PassThrough() });
    const exit = () => { if (child.exitCode !== null) return; child.exitCode=0; child.stdout.end(); child.stderr.end(); child.emit('exit',0,null); child.emit('close',0,null); };
    child.kill = exit;
    if (name === 'postgres') { pg=child; writeFileSync(join(args[args.indexOf('-D')+1],'postmaster.pid'),String(child.pid)+'\n'); }
    else queueMicrotask(() => {
      if (name === 'psql') child.stdout.write(exists ? '1\n' : '\n');
      if (name === 'pgDump') writeFileSync(args[args.indexOf('--file')+1], 'PGDMP synthetic offline dump');
      if (name === 'pgCtl') pg.kill();
      exit();
    });
    return child;
  };
  syncBuiltinESMExports();
  try { await body({ c, calls, missing: () => { exists=false; } }); }
  finally { subprocess.default.spawn=original; syncBuiltinESMExports(); pg?.kill(); }
}

test('database-only hosting checkpoints and cleans up without opening the API or starting application services', async t => {
  await fixture(t, async ({ c, calls }) => {
    c.state = toNamespacedPath(c.state);
    let stop, work;
    const stopping = new Promise(resolve => { stop=resolve; });
    const op = '11111111-1111-4111-8111-111111111111';
    await runHost(c, stopping, handler => {
      work = (async () => {
        const receipt = await handler({ action: 'checkpoint', operationId: op });
        const cleaned = await handler({ action: 'cleanup-checkpoint', operationId: op, checkpoint: receipt });
        assert.equal(cleaned.state, 'checkpoint-cleaned');
      })().finally(stop);
    });
    await work;
    assert.deepEqual(calls.map(c => c.name), ['postgres','pgIsready','psql','pgDump','pgRestore','pgCtl']);
    assert.ok(calls[0].args.includes('default_transaction_read_only=on'));
    assert.equal(calls.find(c => c.name==='pgDump').options.env.PGPASSWORD,c.password);
    assert.ok(!JSON.stringify(calls.map(c=>c.args)).includes(c.password));
    const names = await readdir(c.state);
    for (const name of ['media','studio-trust','studio-work']) assert.ok(!names.includes(name));
    assert.equal(calls[0].options.env.DB_PASSWORD,undefined);
  });
});

test('offline backup refuses missing physical or logical databases without provisioning replacements', async t => {
  await fixture(t, async ({c,calls,missing}) => {
    missing();
    await assert.rejects(runHost(c,new Promise(()=>{}),()=>assert.fail('missing logical database cannot be ready')), /host_database_missing/);
    assert.deepEqual(calls.map(c=>c.name),['postgres','pgIsready','psql','pgCtl']);
    calls.length=0;
    await rm(join(c.state,'database'),{recursive:true});
    await assert.rejects(runHost(c,new Promise(()=>{}),()=>assert.fail()),/host_database_missing/);
    assert.deepEqual(calls,[]);
  });
});

test('offline backup refuses an unowned profile without creating an ownership marker', async t => {
  await fixture(t, async ({c,calls}) => {
    await rm(join(c.state,'host-state.json'));
    await assert.rejects(runHost(c,new Promise(()=>{}),()=>assert.fail()),/host_database_missing/);
    assert.deepEqual(calls,[]);
    await assert.rejects(readFile(join(c.state,'host-state.json')),{code:'ENOENT'});
  });
});

test('host mode is a closed choice and defaults only when omitted', async t => {
  await fixture(t, async ({c}) => {
    for(const mode of [null,'',false,'backup','DATABASE',{}]) assert.throws(()=>validateConfig({...c,mode}),/host_config_invalid/);
    assert.doesNotThrow(()=>validateConfig({...c,mode:'server'}));
    const {mode,...legacy}=c;
    assert.doesNotThrow(()=>validateConfig(legacy));
  });
});


test('cleanup-only owner retires an exact checkpoint with no database, ports or child processes', async t => {
  await fixture(t, async ({c,calls}) => {
    c.mode='checkpoint-cleanup';
    await rm(join(c.state,'database'),{recursive:true});
    const occupied=createServer();
    await new Promise(resolve=>occupied.listen(c.databasePort,'127.0.0.1',resolve));
    t.after(()=>new Promise(resolve=>occupied.close(resolve)));
    const operationId='22222222-2222-4222-8222-222222222222';
    const dump=Buffer.from('PGDMP verified cleanup bytes');
    const checkpoint={schemaVersion:1,operationId,manifestSha256:c.manifestSha256,sourceRevision:c.sourceRevision,
      postgresMajor:'19',databaseFormat:'frameleaf-canonical',dump:{bytes:dump.length,sha256:createHash('sha256').update(dump).digest('hex')}};
    const directory=join(c.state,'checkpoints',operationId);
    await mkdir(directory,{recursive:true,mode:0o700});
    await writeFile(join(directory,'database.dump'),dump,{mode:0o600});
    await writeFile(join(directory,'checkpoint.json'),JSON.stringify(checkpoint),{mode:0o600});
    let stop,work;
    const stopping=new Promise(resolve=>{stop=resolve;});
    await runHost(c,stopping,handler=>{
      work=(async()=>{
        await assert.rejects(handler({action:'checkpoint',operationId}),/host_checkpoint_unavailable/);
        const receipt=await handler({action:'cleanup-checkpoint',operationId,checkpoint});
        assert.deepEqual(receipt,{...checkpoint,state:'checkpoint-cleaned'});
      })().finally(stop);
    });
    await work;
    assert.deepEqual(calls,[]);
    await assert.rejects(readdir(directory),{code:'ENOENT'});
    for(const name of ['database','home','media','studio-trust','studio-work','host.log'])
      assert.ok(!(await readdir(c.state)).includes(name),name+' must remain absent');
  });
});

test('cleanup-only owner refuses an unowned profile before creating state or launching children', async t => {
  await fixture(t, async ({c,calls})=>{
    c.mode='checkpoint-cleanup';
    await rm(join(c.state,'host-state.json'));
    await assert.rejects(runHost(c,new Promise(()=>{}),()=>assert.fail()),/host_state_invalid/);
    assert.deepEqual(calls,[]);
    await assert.rejects(readFile(join(c.state,'host-state.json')),{code:'ENOENT'});
  });
});

async function selectedDatabase(c) {
  const operationId = '11111111-1111-4111-8111-111111111111';
  const attemptId = '22222222-2222-4222-8222-222222222222';
  const root = join(c.state, 'restore-targets'), operation = join(root, operationId), target = join(operation, attemptId);
  const paths = [c.state, root, operation, target, join(target, 'database')];
  for (const path of paths.slice(1)) await mkdir(path, { mode: 0o700 });
  await writeFile(join(paths[4], 'PG_VERSION'), '19', { mode: 0o600 });
  const identities = [];
  for (const path of paths) {
    const meta = await lstat(path, { bigint: true });
    const identity = process.platform === 'win32'
      ? `${meta.dev}:${meta.ino >> 32n}:${meta.ino & 0xffffffffn}` : `${meta.dev}:${meta.ino}`;
    identities.push(createHash('sha256').update(identity).digest('hex'));
  }
  c.databaseReference = { operationId, attemptId, identities };
  return paths[4];
}
test('database maintenance starts the selected retained target and preserves the original profile', async t => {
  await fixture(t, async ({ c, calls }) => {
    c.state = toNamespacedPath(c.state);
    const selected = await selectedDatabase(c);
    await writeFile(join(c.state, 'database/sentinel'), 'original', { mode: 0o600 });
    let stop;
    await runHost(c, new Promise(resolve => { stop = resolve; }), () => stop());
    const postgres = calls.find(call => call.name === 'postgres');
    assert.equal(postgres.args[postgres.args.indexOf('-D') + 1], selected);
    assert.equal(postgres.options.cwd, c.state);
    assert.equal(await readFile(join(c.state, 'database/sentinel'), 'utf8'), 'original');
    assert.ok(!calls.some(call => ['initdb', 'createdb', 'node'].includes(call.name)));
  });
});
test('changed or path-bearing selected references fail before any database process', async t => {
  for (const mutation of ['identity', 'path', 'null', 'missing']) await fixture(t, async ({ c, calls }) => {
    const selected = await selectedDatabase(c);
    if (mutation === 'identity') c.databaseReference.identities[4] = '0'.repeat(64);
    if (mutation === 'path') c.databaseReference.path = '/outside';
    if (mutation === 'null') c.databaseReference = null;
    if (mutation === 'missing') await rm(selected, { recursive: true });
    await assert.rejects(runHost(c, new Promise(() => {}), () => assert.fail()), /host_database_reference_invalid/);
    assert.deepEqual(calls, []);
  });
});

test('selected server databases never provision a missing physical or logical database', async t => {
  for (const absent of ['physical', 'logical']) await fixture(t, async ({ c, calls, missing }) => {
    const selected = await selectedDatabase(c);
    c.mode = 'server';
    const port = createServer();
    await new Promise(resolve => port.listen(0, '127.0.0.1', resolve));
    c.apiPort = port.address().port;
    await new Promise(resolve => port.close(resolve));
    if (absent === 'physical') await rm(join(selected, 'PG_VERSION'));
    else missing();
    await assert.rejects(runHost(c, new Promise(() => {}), () => assert.fail()), /host_database_missing/);
    assert.ok(!calls.some(call => ['initdb', 'createdb', 'node'].includes(call.name)));
    if (absent === 'physical') assert.deepEqual(calls, []);
  });
});


test('canonical host paths allow only the Windows local-drive verbatim prefix difference', () => {
  const canonical = String.raw`C:\private\profile`;
  const extended = String.raw`\\?\C:\private\profile`;
  assert.equal(canonicalHostPathMatches(canonical, extended, 'win32'), true);
  for (const platform of ['darwin', 'linux'])
    assert.equal(canonicalHostPathMatches(canonical, extended, platform), false);
  for (const expected of [
    String.raw`\\?\c:\private\profile`,
    String.raw`\\?\C:\PRIVATE\profile`,
    String.raw`\\?\C:\private\other\..\profile`,
    String.raw`\\?\C:\alias\profile`,
    String.raw`\\?\D:\private\profile`,
    String.raw`\\.\C:\private\profile`,
    String.raw`\\?\UNC\server\share`,
  ]) assert.equal(canonicalHostPathMatches(canonical, expected, 'win32'), false, expected);
  assert.equal(canonicalHostPathMatches(String.raw`\\server\share`, String.raw`\\?\UNC\server\share`, 'win32'), false);
  for (const platform of ['win32', 'darwin', 'linux']) {
    assert.equal(canonicalHostPathMatches(canonical, canonical, platform), true);
    assert.equal(canonicalHostPathMatches('/private/profile', '/private/alias', platform), false);
  }
});

test('physical Windows state comparisons require a captured root and volume identity', () => {
  const physicalRoot = String.raw`\\.\GLOBALROOT\Device\HarddiskVolume3\private\profile`;
  const canonicalRoot = String.raw`C:\private\profile`;
  const binding = { physicalRoot, canonicalRoot, volumeSerial: 42 };
  assert.equal(canonicalHostPathMatches(`${canonicalRoot}\\database`, `${physicalRoot}\\database`, 'win32', binding, 42n), true);
  assert.equal(canonicalHostPathMatches(canonicalRoot, physicalRoot, 'win32', binding, 42n), true);
  for (const [actual, expected, captured, device] of [
    [canonicalRoot, physicalRoot, undefined, 42n],
    [canonicalRoot, physicalRoot, binding, 43n],
    [`${canonicalRoot}\\database`, `${physicalRoot}2\\database`, binding, 42n],
    [`${canonicalRoot}\\database`, `${physicalRoot}\\..\\database`, binding, 42n],
    [canonicalRoot.replace('C:', 'D:'), physicalRoot, binding, 42n],
    [canonicalRoot, physicalRoot.replace('Volume3', 'Volume4'), binding, 42n],
    [`${canonicalRoot}\\alias`, `${physicalRoot}\\database`, binding, 42n],
  ]) assert.equal(canonicalHostPathMatches(actual, expected, 'win32', captured, device), false);
  assert.equal(canonicalHostPathMatches(canonicalRoot, physicalRoot, 'linux', binding, 42n), false);
});
