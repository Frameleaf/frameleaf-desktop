import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp,mkdir,realpath,readFile,writeFile,rm,symlink,link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
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
