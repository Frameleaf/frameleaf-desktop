import assert from 'node:assert/strict';
import {readdir,readFile} from 'node:fs/promises';
import {test} from 'node:test';

async function sources(directory) {
 const entries=await readdir(new URL(directory,import.meta.url),{withFileTypes:true});
 return (await Promise.all(entries.map(async entry=>entry.isDirectory()?sources(`${directory}/${entry.name}`):/\.(rs|ts|svelte|mjs)$/.test(entry.name)?[`${directory}/${entry.name}`]:[]))).flat();
}

test('desktop authorization has no claim-code or setup-code bootstrap dependency',async()=>{
 const forbidden=/claim-key|claim_proof|claim_local|manager-api\/setup|(?:claim|setup)[_-]?code/i;
 for(const directory of ['../src','../src-tauri/src','../runtime'])for(const path of await sources(directory)){
  assert.equal(forbidden.test(await readFile(new URL(path,import.meta.url),'utf8')),false,path);
 }
});

test('local authorization keeps existing-account sign-in available and explains initialization',async()=>{
 const source=await readFile(new URL('../src/LocalHost.svelte',import.meta.url),'utf8');
 assert.equal(source.includes('choose a Manager password'),false);
 assert.ok(source.includes('existing Manager password'));
 const {managerError}=await import('../src/manager-state.ts');
 assert.match(managerError('manager_initialization_required'),/administrator account/i);
});


test('local initialization refusal precedes device identity and credential-store probes',async()=>{
 const source=await readFile(new URL('../src-tauri/src/host_setup.rs',import.meta.url),'utf8');
 const method=source.slice(source.indexOf('pub(crate) async fn authorize('),source.indexOf('pub(crate) async fn photos_url('));
 const initialized=method.indexOf('if !running.manager.claimed().await?');
 const refusal=method.indexOf('return Err("manager_initialization_required".into());');
 assert.ok(initialized>=0&&refusal>initialized);
 for(const call of ['crate::credentials::identity()','crate::credentials::load','crate::credentials::save','crate::credentials::delete'])assert.ok(method.indexOf(call)>refusal,call);
});
