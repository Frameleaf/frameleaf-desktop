import {test} from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,readFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {join} from 'node:path';
import {tmpdir} from 'node:os';

const footer=new URL('../runtime/host-update-agent.mjs',import.meta.url);
const configuration={mode:'restore-prepare',state:join(tmpdir(),'synthetic-update-profile'),runtime:join(tmpdir(),'synthetic-target-runtime'),manifestSha256:'a'.repeat(64),sourceRevision:'b'.repeat(40),postgresMajor:'19',password:'synthetic database password',databasePort:54329,apiPort:2283,entryPoints:Object.fromEntries(['node','server','postgres','initdb','createdb','psql','pgIsready','pgCtl','pgDump','pgRestore','hdr','studioBrowserGuard','studio'].map(x=>[x,'bin/'+x]))};
const suffix=process.platform==='win32'?'.exe':'';
Object.assign(configuration.entryPoints,{ffmpeg:'media/ffmpeg'+suffix,ffprobe:'media/ffprobe'+suffix,rawRenderer:'raw/darktable-cli'+suffix,rawDecoder:'raw/dcraw_emu'+suffix,studioBrowser:'browser/chrome'+suffix});
// These boundaries stand in for the separately tested database, filesystem and offline/schema work.
const operations=`
restoreHostUpdateDatabase=async(c,request,stopping)=>{
 if(request.fault==='restore')throw new Error('private database password');
 if(request.fault==='wait')await stopping;
 await new Promise(resolve=>setTimeout(resolve,25));
 return {state:'update-prepared',update:request};
};
readHostUpdateTarget=async(c,receipt,check)=>{check();if(receipt.update.fault==='inspect')throw new Error('private inspector error');return {receipt};};
validateHostUpdateTarget=async(c,receipt,stopping)=>{await readHostUpdateTarget(c,receipt,()=>{});if(receipt.update.fault==='verify-wait'){process.stderr.write('fixture-verification-ready\\n');await stopping;}if(receipt.update.fault==='verify')throw new Error('private checksum/schema error');return {receipt:receipt.update.fault==='foreign'?{...receipt,state:'foreign'}:receipt,offlineChecksums:receipt.update.fault!=='unchecked',schemaValidated:receipt.update.fault!=='unschemed'};};
validateSelectedHostUpdateTarget=async(c,receipt,stopping)=>validateHostUpdateTarget(c,receipt,stopping);
`;
async function run(message,control='',eof=false,afterVerification=false){
 assert.ok(existsSync(footer),'the update preparation entry must exist');
 const agent=readFileSync(new URL('../runtime/host-agent.mjs',import.meta.url),'utf8');
 const source=Buffer.from(agent+'\n'+operations+'\n'+readFileSync(footer,'utf8')).toString('base64');
 const child=spawn(process.execPath,['--input-type=module','--eval',readFileSync(new URL('../runtime/host-bootstrap.mjs',import.meta.url),'utf8')],{env:{...process.env,FRAMELEAF_HOST_AGENT:'0'},stdio:['pipe','pipe','pipe'],timeout:5000});
 let stdout='',stderr='';child.stdout.on('data',x=>stdout+=x);child.stderr.on('data',x=>{stderr+=x;if(afterVerification&&stderr.includes('fixture-verification-ready')){afterVerification=false;if(control)child.stdin.write(control);if(eof)child.stdin.end();}});child.stdin.on('error',()=>{});
 const closed=once(child,'close');
 child.stdin.write(source+'\n'+message+'\n'+(afterVerification?'':control));
 if(eof&&!afterVerification)child.stdin.end();
 const [code,signal]=await closed;return {code,signal,stdout,stderr};
}
test('update entry returns only offline/schema-verified preparation and finishes while the controller stays connected',async()=>{
 const result=await run(JSON.stringify({configuration,update:{fault:'none'}}));
 assert.deepEqual(result,{code:0,signal:null,stdout:'{"state":"update-verified","prepared":{"state":"update-prepared","update":{"fault":"none"}},"offlineChecksums":true,"schemaValidated":true}\n',stderr:''});
});
test('update entry redacts bad requests and database or inspection failures',async()=>{
 for(const value of ['private invalid JSON',JSON.stringify({configuration,update:{},secret:'private'}),JSON.stringify({configuration:{...configuration,mode:'server'},update:{}}),...['restore','inspect','verify','unchecked','unschemed','foreign'].map(fault=>JSON.stringify({configuration,update:{fault}}))]){
  assert.deepEqual(await run(value),{code:1,signal:null,stdout:'',stderr:'host_update_preparation_failed\n'});
 }
});
test('update entry cancels on stop, invalid controls and controller loss without publishing success',async()=>{
 const message=JSON.stringify({configuration,update:{fault:'wait'}});
 for(const [control,eof] of [['stop\n',false],['unknown-private-control\n',false],['',true]]){
  assert.deepEqual(await run(message,control,eof),{code:1,signal:null,stdout:'',stderr:'host_update_preparation_failed\n'});
 }
});

test('update entry cancels during offline/schema verification without publishing verified evidence',async()=>{
 const message=JSON.stringify({configuration,update:{fault:'verify-wait'}});
 for(const [control,eof] of [['stop\n',false],['unknown-private-control\n',false],['',true]]){
  assert.deepEqual(await run(message,control,eof,true),{code:1,signal:null,stdout:'',stderr:'fixture-verification-ready\nhost_update_preparation_failed\n'});
 }
});

test('retained update entry verifies the supplied receipt without invoking restore',async()=>{
 const update={fault:'restore'},prepared={state:'update-prepared',update};
 const result=await run(JSON.stringify({configuration,update,prepared}));
 assert.deepEqual(result,{code:0,signal:null,stdout:JSON.stringify({state:'update-verified',prepared,offlineChecksums:true,schemaValidated:true})+'\n',stderr:''});
});

test('retained update entry refuses malformed or mismatched retained requests and never falls back to restore',async()=>{
 const update={fault:'restore'};
 for(const prepared of [null,{}, {state:'restore-prepared',update},{state:'update-prepared',update:{fault:'other'}}])assert.deepEqual(await run(JSON.stringify({configuration,update,prepared})),{code:1,signal:null,stdout:'',stderr:'host_update_preparation_failed\n'});
 for(const fault of ['inspect','verify','unchecked','unschemed','foreign']){
  const update={fault},prepared={state:'update-prepared',update};
  assert.deepEqual(await run(JSON.stringify({configuration,update,prepared})),{code:1,signal:null,stdout:'',stderr:'host_update_preparation_failed\n'});
 }
});

test('retained update entry cancels verification without publishing success',async()=>{
 const update={fault:'verify-wait'},prepared={state:'update-prepared',update};
 for(const [control,eof] of [['stop\n',false],['unknown-private-control\n',false],['',true]])assert.deepEqual(await run(JSON.stringify({configuration,update,prepared}),control,eof,true),{code:1,signal:null,stdout:'',stderr:'fixture-verification-ready\nhost_update_preparation_failed\n'});
});
