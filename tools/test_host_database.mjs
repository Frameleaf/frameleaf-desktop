import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import * as subprocess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtemp, mkdir, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';
import { claimState, runHost, validateConfig } from '../runtime/host-agent.mjs';

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
    if (name === 'postgres') { pg=child; writeFileSync(join(state,'database/postmaster.pid'),String(child.pid)+'\n'); }
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
