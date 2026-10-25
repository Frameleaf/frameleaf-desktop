import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {readFile,mkdir} from 'node:fs/promises';
import {join,isAbsolute} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

// Opt-in browser qualification: only a synthetic IPC bridge, never real Manager credentials or commands.
if(process.env.FRAMELEAF_MANAGER_UI_TEST!=='1') {process.stdout.write('Manager UI browser qualification is opt-in.\n');process.exit(0);}
const executablePath=process.env.FRAMELEAF_TEST_BROWSER;
const playwright=process.env.FRAMELEAF_TEST_PLAYWRIGHT;
const output=process.env.FRAMELEAF_TEST_OUTPUT;
assert.ok(executablePath&&isAbsolute(executablePath)&&playwright&&isAbsolute(playwright)&&output&&isAbsolute(output));
const {chromium}=await import(pathToFileURL(playwright));
const root=fileURLToPath(new URL('..',import.meta.url));
const listener=createServer();await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve));const address=listener.address();assert.ok(address&&typeof address!=='string');await new Promise(resolve=>listener.close(resolve));
const origin=`http://127.0.0.1:${address.port}`;
const vite=spawn(process.execPath,[join(root,'node_modules/vite/bin/vite.js'),'--host','127.0.0.1','--port',String(address.port),'--strictPort'],{cwd:root,stdio:['ignore','pipe','pipe']});
const ended=new Promise(resolve=>vite.once('close',resolve));
let browser;
const view={origin:'https://manager.test:9443',managerId:'11111111-1111-4111-8111-111111111111',deviceId:'22222222-2222-4222-8222-222222222222',installationId:'aaaaaaaaaaaa',expiresAt:Date.now()+86400000,scopes:['status','start','stop','restart','backup'],certificateSha256:null};
const operationId='33333333-3333-4333-8333-333333333333';
const password='synthetic Manager UI password';
const wire=JSON.parse(await readFile(join(root,'src-tauri/src/manager_wire.json'),'utf8'));
const makeOperation=(action,state='running')=>({id:operationId,kind:action,state,step:action==='backup'?'database-backup':action,completed:state==='complete'?[action]:[],error:null,createdAt:Date.now(),updatedAt:Date.now()});
async function fixture(scenario,run,viewport={width:1100,height:1000},colorScheme='light'){
 const context=await browser.newContext({viewport,colorScheme});
 const calls=[],keys=new Map(),errors=[];
 const localScenario=scenario.startsWith('local');
 const fixturePassword=scenario==='local-unicode'?'🌱'.repeat(128):password;
 let accountCreated=scenario==='localhost';
 let paired=scenario.startsWith('local-update')||scenario!=='pair'&&!localScenario,authorized=!['reauth','recovery-reauth'].includes(scenario),lost=scenario==='lost',current=['resume','recovery-reauth'].includes(scenario)?makeOperation('stop','interrupted'):null;
 const localRecord={schemaVersion:1,manifestSha256:'a'.repeat(64),controllerSha256:'b'.repeat(64),version:'3.0.0',epoch:10,sourceRevision:'a'.repeat(40)};
 let local={state:'idle',code:null,backgroundActive:false,installation:null,origin:null};
 const updateScenario=scenario.startsWith('local-update');
 const targetRecord={...localRecord,manifestSha256:'c'.repeat(64),version:'3.1.0',epoch:11,sourceRevision:'c'.repeat(40)};
 if(updateScenario)local={state:'manager-ready',code:null,backgroundActive:true,installation:localRecord,origin:'https://127.0.0.1:9443'};
 if(scenario.startsWith('local-update-recovery-'))local={...local,state:'update-pending',backgroundActive:false,pendingUpdate:{operationId,fromManifestSha256:localRecord.manifestSha256,toManifestSha256:targetRecord.manifestSha256,phase:scenario.slice('local-update-recovery-'.length).replace('-missing-grant','')}};
 let updateCancelled=false,updateAuthorized=scenario!=='local-update-reauth';
 let refuseLocalStop=true;
 let reviewLost=scenario==='recovery',reviewReady=false;const reviews=new Map(),restores=new Map();let restoreLost=scenario==='recovery-restore',restored=null;
 const manager={...view,...(localScenario?{origin:'https://127.0.0.1:9443',certificateSha256:wire.certificateSha256}:{}),scopes:scenario==='readonly'?['status']:scenario.startsWith('recovery')?[...view.scopes,'restore']:view.scopes};
 if(updateScenario)manager.scopes=[...view.scopes,...(scenario==='local-update-no-permission'?[]:['update'])];
 await context.exposeBinding('__managerInvoke',async(_source,command,args={})=>{
  calls.push({command,args:structuredClone(args)});
  if(command==='plugin:event|listen')return 1;
  if(command==='plugin:event|unlisten')return;
  if(command==='local_host_status'){if(scenario==='local-update-invalid')throw 'host_update_discovery_invalid';return local;}
  if(command==='installed_local_hosts'&&scenario==='local-update-inventory-unavailable')throw 'host_install_record_invalid';
  if(command==='installed_local_hosts')return updateScenario?[localRecord,targetRecord,{...localRecord,manifestSha256:'d'.repeat(64),version:'2.9.0',epoch:9},{...localRecord,manifestSha256:'e'.repeat(64),version:'3.0.1',epoch:10},{schemaVersion:1,manifestSha256:'f'.repeat(64),controllerSha256:'b'.repeat(64),code:'host_signature_invalid'}]:localScenario?[localRecord]:[];
  if(command==='prepare_local_host'){assert.equal(args.manifestSha256,localRecord.manifestSha256);await new Promise(resolve=>setTimeout(resolve,300));local={state:'manager-ready',code:null,backgroundActive:true,installation:localRecord,origin:'https://127.0.0.1:9443'};return local;}
  if(command==='stop_local_host_manager'){if(refuseLocalStop){refuseLocalStop=false;throw 'host_controller_already_owned';}local={...local,state:'idle',backgroundActive:false};return local;}
  if(command==='cancel_local_host_start'){updateCancelled=true;return;}
  if(command==='update_local_host'){
   assert.equal(args.manifestSha256,targetRecord.manifestSha256);assert.equal(args.backupOperationId,operationId);assert.equal(args.migrationsApproved,true);
   if(!updateAuthorized)throw 'manager_recent_auth_required';
   await new Promise(resolve=>setTimeout(resolve,600));
   if(scenario==='local-update-failed'){local={...local,state:'update-pending',backgroundActive:false,pendingUpdate:{operationId,fromManifestSha256:localRecord.manifestSha256,toManifestSha256:targetRecord.manifestSha256,phase:'approvalConsumed'}};throw 'host_update_verification_failed';}
   if(updateCancelled)throw 'native_host_update_cancelled';
   local={...local,installation:targetRecord,pendingUpdate:null};return local;
  }
  if(command==='recover_local_host_update'){
   assert.equal(args.manifestSha256,targetRecord.manifestSha256);assert.equal(args.cancelUpdate,local.pendingUpdate.phase!=='approvalConsumed');
   await new Promise(resolve=>setTimeout(resolve,300));
   local={...local,state:'manager-ready',backgroundActive:true,installation:args.cancelUpdate?localRecord:targetRecord,pendingUpdate:null};if(scenario.endsWith('-missing-grant'))paired=false;return local;
  }
  if(command==='restore_connection')return null;
  if(command==='worker_setup_status')return {state:'stopped',code:null,control:'stopped',workloads:[]};
  if(command==='authorize_local_manager'){
   assert.ok(Object.keys(args).every(key=>['administratorName','allowManagement','allowRecovery','allowUpdates','password'].includes(key)));
   assert.equal(args.password,fixturePassword);assert.equal(args.allowManagement,true);
   assert.equal(typeof args.allowRecovery,'boolean');assert.equal(typeof args.allowUpdates,'boolean');
   if(args.administratorName!=null){
    assert.equal(args.administratorName,'New owner');
    if(accountCreated)throw 'manager_account_exists';
    accountCreated=true;
    if(scenario==='local-account-race')throw 'manager_account_exists';
   }else if(!accountCreated)throw 'manager_initialization_required';
   manager.scopes=[...view.scopes,...(args.allowRecovery?['restore']:[]),...(args.allowUpdates?['update']:[])];
   await new Promise(resolve=>setTimeout(resolve,300));paired=true;return manager;
  }
  if(command==='open_local_photos'){assert.ok(localScenario);assert.ok(paired&&local.backgroundActive);assert.deepEqual(args,{});return;}
  if(command==='manager_view')return paired?manager:null;
  if(command==='manager_certificate_fingerprint')return wire.certificateSha256;
  if(command==='pair_manager'){assert.equal(args.password,password);assert.equal(args.allowManagement,true);assert.equal(typeof args.allowRecovery,'boolean');assert.equal(typeof args.allowUpdates,'boolean');manager.scopes=[...view.scopes,...(args.allowRecovery?['restore']:[]),...(args.allowUpdates?['update']:[])];paired=true;return {...manager,certificateSha256:args.certificate?.sha256||null};}
  if(command==='reauthenticate_manager'){assert.equal(args.password,password);authorized=true;updateAuthorized=true;return;}
  if(command==='disconnect_manager'){assert.equal(args.password,password);paired=false;return;}
  if(command==='manager_request'){
   const request=args.command;
   if(scenario==='devicechanged'&&paired)throw 'manager_device_changed';
   if(request.kind==='status')return {manager:{id:manager.managerId,origin:manager.origin},installation:{id:manager.installationId,name:localScenario?'My local library':'Example server',release:'frameleaf-v3.0.0-1',port:2283},operations:current?[current]:scenario==='local-update-active'?[makeOperation('backup')]:scenario==='local-update-no-backup'?[{...makeOperation('backup','complete'),error:'synthetic failed backup'}]:updateScenario?[makeOperation('backup','complete')]:[]};
   if(request.kind==='backups'){if(!authorized)throw 'manager_recent_auth_required';assert.ok(manager.scopes.includes('restore'));return [{id:'a'.repeat(64),time:new Date().toISOString()}];}
   if(request.kind==='review-restore'){
    assert.ok(manager.scopes.includes('restore'));assert.equal(request.snapshot,'a'.repeat(64));
    if(!reviews.has(request.key))reviews.set(request.key,{snapshot:request.snapshot});
    if(reviewLost){reviewLost=false;throw 'manager_response_interrupted';}
    return {id:request.key,snapshot:request.snapshot,installationId:manager.installationId,state:'preparing'};
   }
   if(request.kind==='restore-review'){
    assert.ok(reviews.has(request.id));assert.equal(request.snapshot,reviews.get(request.id).snapshot);
    return {id:request.id,snapshot:request.snapshot,installationId:manager.installationId,expires:Date.now()+900000,state:reviewReady?'prepared':'preparing',...(reviewReady?{libraryId:manager.installationId,release:'frameleaf-v3.0.0-1',targetRelease:'frameleaf-v3.0.0-1',createdAt:Date.now()-86400000,mediaIncluded:false,requiresRuntimeChange:false}:{})};
   }
   if(request.kind==='restore'){
    if(!authorized)throw 'manager_recent_auth_required';assert.ok(reviews.has(request.reviewId));
    if(scenario==='recovery-restore-expired')throw 'native_restore_review_expired';
    if(!restores.has(request.key)){restored=makeOperation('restore');restores.set(request.key,restored);}
    if(restoreLost){restoreLost=false;throw 'manager_response_interrupted';}
    return {id:restored.id};
   }
   if(request.kind==='restore-operation'){if(!authorized)throw 'manager_recent_auth_required';assert.equal(request.id,restored.id);return restored;}
   if(request.kind==='resume-restore'){if(!authorized)throw 'manager_recent_auth_required';assert.equal(request.id,restored.id);restored={...restored,state:'running',error:null};return {id:restored.id};}
   if(request.kind==='control'){
    if(!authorized)throw 'manager_recent_auth_required';
    if(!keys.has(request.key)){current=makeOperation(request.action);keys.set(request.key,current);}
    if(lost){lost=false;throw 'manager_unreachable_or_certificate_invalid';}
    return {id:keys.get(request.key).id};
   }
   if(request.kind==='operation'){assert.equal(request.id,operationId);return current;}
   if(request.kind==='resume'){assert.equal(request.id,operationId);current={...current,state:'running'};return {id:operationId};}
  }
  throw Error(`Unexpected fixture command: ${command}`);
 });
 await context.addInitScript(()=>{
  globalThis.isTauri=true;
  globalThis.__TAURI_INTERNALS__={invoke:(command,args)=>globalThis.__managerInvoke(command,args),transformCallback:()=>1};
 });
 const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));
 try{
  await page.goto(origin,{waitUntil:'networkidle'});
  const ui=page.getByRole('region',{name:'Server management'});
  await ui.getByRole('heading',{name:'Server management'}).waitFor();
  if(!localScenario&&!['pair','devicechanged'].includes(scenario))await ui.getByText('Example server',{exact:true}).waitFor();
  await run({page,ui,calls,keys,reviews,restores,finishRestore:()=>{restored={...restored,state:'complete',step:'native-restore-started',completed:['native-restore-started'],updatedAt:Date.now()};},interruptRestore:()=>{restored={...restored,state:'interrupted'};authorized=false;},finishReview:()=>{reviewReady=true;},loseNext:()=>{lost=true;},finish:()=>{current={...current,state:'complete',completed:[current.kind],updatedAt:Date.now()};}});
  assert.deepEqual(errors,[]);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'horizontal overflow');
 }finally{await context.close();}
}
try{
 await new Promise((resolve,reject)=>{
  let text='';const timer=setTimeout(()=>reject(Error('Vite startup timeout')),10000);
  vite.stdout.on('data',chunk=>{text+=chunk;if(text.includes('Local:')){clearTimeout(timer);resolve();}});
  vite.once('error',reject);vite.once('exit',code=>{if(code)reject(Error('Vite exited before ready'));});
 });
 browser=await chromium.launch({executablePath,headless:true,args:['--disable-gpu']});
 await mkdir(output,{recursive:true});
 await fixture('local-update-inventory-unavailable',async({page})=>{
  page.setDefaultTimeout(5000);
  await page.getByRole('radio',{name:/Run Frameleaf here/}).check();
  const local=page.getByRole('region',{name:'Local library setup'});
  await local.getByRole('heading',{name:'Local Manager is ready',exact:true}).waitFor();
  await local.getByRole('alert').waitFor();
  assert.ok(await local.getByRole('button',{name:'Stop local management',exact:true}).isEnabled());
  assert.equal(await local.getByRole('button',{name:'Review server update',exact:true}).count(),0);
  assert.equal(await local.getByRole('button',{name:'Prepare my server profile',exact:true}).count(),0);
 });
 await fixture('local-update-recovery-approvalConsumed-missing-grant',async({page})=>{
  page.setDefaultTimeout(5000);
  await page.getByRole('radio',{name:/Run Frameleaf here/}).check();
  const local=page.getByRole('region',{name:'Local library setup'});
  await local.getByRole('button',{name:'Resume interrupted update',exact:true}).click();
  await local.getByText('Server update completed. Start your server below when ready.',{exact:true}).waitFor();
  assert.equal(await local.getByRole('button',{name:'Open local Photos',exact:true}).count(),0);
  await local.getByLabel('Local Manager password',{exact:true}).waitFor();
 });
 for(const scenario of ['local-update','local-update-reauth','local-update-failed','local-update-no-permission','local-update-no-backup','local-update-active','local-update-cancelled'])await fixture(scenario,async({page,calls})=>{
  page.setDefaultTimeout(5000);
  await page.getByRole('radio',{name:/Run Frameleaf here/}).check();
  const local=page.getByRole('region',{name:'Local library setup'});
  await local.getByRole('button',{name:'Review server update',exact:true}).click();
  if(['local-update-no-permission','local-update-active'].includes(scenario)){
   await local.getByRole('alert').filter({hasText:scenario==='local-update-active'?/operation is active/:/server update permission/}).waitFor();
   assert.equal(calls.filter(v=>v.command==='update_local_host').length,0);return;
  }
  await local.getByRole('option',{name:'Frameleaf 3.1.0 · package 11',exact:true}).waitFor({state:'attached'});
  assert.equal(await local.locator('#update-package option[value="'+ 'd'.repeat(64) +'"]').count(),0);
  assert.equal(await local.locator('#update-package option[value="'+ 'e'.repeat(64) +'"]').count(),0);
  assert.equal(await local.locator('#update-package option[value="'+ 'f'.repeat(64) +'"]').count(),0);
  await local.getByText('An installed server package needs repair. It cannot be selected for an update. Your running server can still be managed.',{exact:true}).waitFor();
  const update=local.getByRole('button',{name:'Update local server',exact:true});
  assert.ok(await update.isDisabled());
  await local.getByLabel('Server package for update').selectOption('c'.repeat(64));
  if(scenario==='local-update-no-backup'){
   await local.getByText('Create a database backup below, then review the update again.',{exact:true}).waitFor();
   assert.ok(await update.isDisabled());assert.equal(calls.filter(v=>v.command==='update_local_host').length,0);return;
  }
  await local.getByLabel('Completed database backup').selectOption(operationId);
  assert.ok(await update.isDisabled());
  await local.getByLabel('I approve this server update and its database migrations.').check();
  await local.screenshot({path:join(output,scenario+'-review.png')});
  await update.click();
  if(scenario==='local-update-cancelled'){
   await local.getByRole('button',{name:'Stop after current step',exact:true}).click();
   await local.getByRole('alert').waitFor();
   assert.equal(calls.filter(v=>v.command==='cancel_local_host_start').length,1);
   assert.equal(calls.filter(v=>v.command==='update_local_host').length,1);return;
  }
  if(scenario==='local-update'){
   assert.ok(await page.getByRole('button',{name:'Start server',exact:true}).isDisabled());
   assert.ok(await page.getByRole('radio',{name:/Connect to my server/}).isDisabled());
  }
  if(scenario==='local-update-reauth'){
   await local.getByLabel('Manager password for update').fill(password);
   await local.getByRole('button',{name:'Authorize update',exact:true}).click();
  }
  if(scenario==='local-update-failed'){
   await local.getByRole('button',{name:'Resume interrupted update',exact:true}).waitFor();
   assert.equal(await local.getByRole('button',{name:'Prepare local Manager',exact:true}).count(),0);
   assert.equal(await local.getByRole('button',{name:'Prepare my server profile',exact:true}).count(),0);
   await page.reload({waitUntil:'networkidle'});
   await page.getByRole('radio',{name:/Run Frameleaf here/}).check();
   await local.getByRole('button',{name:'Resume interrupted update',exact:true}).waitFor();
   assert.equal(await local.getByRole('button',{name:'Review server update',exact:true}).count(),0);return;
  }
  await local.getByText('Server update completed. Start your server below when ready.',{exact:true}).waitFor();
  assert.ok(calls.filter(v=>v.command==='manager_view').length>=2);
  assert.equal(calls.filter(v=>v.args?.command?.kind==='control').length,0);
  assert.equal(await local.getByLabel('Manager password for update').count(),0);
  assert.ok(!(await page.evaluate(()=>JSON.stringify(localStorage))).includes(password));
  await local.screenshot({path:join(output,scenario+'.png')});
 },scenario==='local-update'?{width:390,height:1000}:{width:1100,height:1000},scenario==='local-update'?'dark':'light');
 for(const phase of ['reserved','preparingCredentials','credentialsPrepared','approvalConsumed'])await fixture('local-update-recovery-'+phase,async({page,calls})=>{
  page.setDefaultTimeout(5000);
  await page.getByRole('radio',{name:/Run Frameleaf here/}).check();
  const local=page.getByRole('region',{name:'Local library setup'});
  const consumed=phase==='approvalConsumed';
  const action=consumed?'Resume interrupted update':'Cancel interrupted update';
  await local.getByRole('button',{name:action,exact:true}).waitFor();
  assert.equal(await local.getByRole('button',{name:'Prepare local Manager',exact:true}).count(),0);
  assert.equal(await local.getByRole('button',{name:consumed?'Cancel interrupted update':'Resume interrupted update',exact:true}).count(),0);
  assert.ok(await page.getByRole('button',{name:'Start server',exact:true}).isDisabled());
  await local.screenshot({path:join(output,'local-update-recovery-'+phase+'.png')});
  await local.getByRole('button',{name:action,exact:true}).click();
  await local.getByText(consumed?'Server update completed. Start your server below when ready.':'Interrupted update cancelled. Your original server is ready to manage.',{exact:true}).waitFor();
  assert.equal(calls.filter(v=>v.command==='recover_local_host_update').length,1);
  assert.equal(calls.filter(v=>v.args?.command?.kind==='control').length,0);
 });
 await fixture('local-update-invalid',async({page,calls})=>{
  page.setDefaultTimeout(5000);
  await page.getByRole('radio',{name:/Run Frameleaf here/}).check();
  const local=page.getByRole('region',{name:'Local library setup'});
  await local.getByRole('alert').waitFor();
  assert.equal(await local.getByRole('button',{name:'Prepare local Manager',exact:true}).count(),0);
  assert.equal(await local.getByRole('button',{name:'Prepare my server profile',exact:true}).count(),0);
  assert.equal(calls.filter(v=>['prepare_local_host','provision_local_host_profile'].includes(v.command)).length,0);
 });
 for(const scenario of ['local-account','local-account-race','local-unicode'])await fixture(scenario,async({page,calls})=>{
  page.setDefaultTimeout(5000);
  const chosenPassword=scenario==='local-unicode'?'🌱'.repeat(128):password;
  await page.getByRole('radio',{name:/Run Frameleaf here/}).check();
  const local=page.getByRole('region',{name:'Local library setup'});
  await local.getByRole('button',{name:'Prepare local Manager'}).click();
  await local.getByRole('heading',{name:'Local Manager is ready'}).waitFor();
  await local.getByLabel('Local Manager password',{exact:true}).fill(chosenPassword);
  await local.getByLabel('Allow this computer to manage this local server.').check();
  await local.getByRole('button',{name:'Authorize local management',exact:true}).click();
  await local.getByRole('alert').waitFor();
  assert.match(await local.getByRole('alert').innerText(),/administrator account/i);
  assert.equal(calls.filter(x=>x.command==='authorize_local_manager').length,1);
  await local.getByRole('button',{name:'Create a local Manager account',exact:true}).click();
  await local.getByLabel('Administrator name',{exact:true}).fill('New owner');
  await local.getByLabel('Local Manager password',{exact:true}).fill(chosenPassword);
  const confirm=local.getByLabel('Confirm Manager password',{exact:true});
  await confirm.fill('different synthetic password');
  await local.getByText('The passwords do not match.',{exact:true}).waitFor();
  const create=local.getByRole('button',{name:'Create account and authorize',exact:true});
  assert.ok(await create.isDisabled());
  assert.equal(calls.filter(x=>x.command==='authorize_local_manager').length,1);
  await confirm.fill(chosenPassword);assert.ok(await create.isEnabled());
  await local.screenshot({path:join(output,scenario+'-before.png')});
  await create.click();
  const input=local.getByLabel('Local Manager password',{exact:true});assert.equal(await input.inputValue(),'');
  if(scenario==='local-account-race'){
   await local.getByRole('alert').waitFor();assert.match(await local.getByRole('alert').innerText(),/already.*account|account.*already/i);
   assert.equal(await local.getByLabel('Confirm Manager password',{exact:true}).count(),0);
   assert.equal(calls.filter(x=>x.command==='authorize_local_manager').length,2);
   await input.fill(chosenPassword);await local.getByRole('button',{name:'Authorize local management',exact:true}).click();
  }
  await local.getByText('Local management is authorized.',{exact:false}).waitFor();
  const authorizations=calls.filter(x=>x.command==='authorize_local_manager');
  assert.equal(authorizations.filter(x=>x.args.administratorName!=null).length,1);
  assert.equal(authorizations[0].args.administratorName??null,null);
  assert.equal(await local.getByLabel('Confirm Manager password',{exact:true}).count(),0);
  await local.screenshot({path:join(output,scenario+'-authorized.png')});
 });
 await fixture('localhost',async({page,calls})=>{
  await page.getByRole('radio',{name:/Run Frameleaf here/}).check();
  const local=page.getByRole('region',{name:'Local library setup'});
  const prepare=local.getByRole('button',{name:'Prepare local Manager'});
  await prepare.waitFor();await prepare.click();
  await local.getByRole('heading',{name:'Preparing local management…'}).waitFor();
  assert.ok(await page.getByRole('radio',{name:/Connect to my server/}).isDisabled());
  await local.getByRole('heading',{name:'Local Manager is ready'}).waitFor();
  const updates=local.getByLabel('Also allow requests for server updates.');assert.equal(await updates.count(),1);assert.equal(await updates.isChecked(),false);await updates.check();
  assert.ok(await page.getByRole('radio',{name:/Connect to my server/}).isDisabled());
  await local.getByText('The photo server has not been started by this setup step.',{exact:false}).waitFor();
  const authorize=local.getByRole('button',{name:'Authorize local management'});
  const input=local.getByLabel('Local Manager password',{exact:true});
  await input.fill(password);assert.ok(await authorize.isDisabled());
  await local.getByLabel('Allow this computer to manage this local server.').check();
  await local.getByLabel('Also allow backup recovery reviews and restore operations.').check();
  assert.ok(await authorize.isEnabled());await authorize.click();
  assert.equal(await input.inputValue(),'');assert.ok(await updates.isDisabled());
  await local.getByText('Local management is authorized.',{exact:false}).waitFor();
  await page.getByRole('region',{name:'Server management'}).getByText('My local library',{exact:true}).waitFor();
  assert.equal(calls.filter(value=>value.command==='authorize_local_manager').length,1);
  await local.getByText('Your Photos account is separate from your Manager password.',{exact:false}).waitFor();
  await local.getByRole('button',{name:'Open local Photos',exact:true}).click();
  assert.equal(calls.filter(value=>value.command==='open_local_photos').length,1);
  await local.screenshot({path:join(output,'local-manager-authorized.png')});
  const stop=local.getByRole('button',{name:'Stop local management'});
  await stop.click();await local.getByRole('alert').waitFor();
  assert.match(await local.getByRole('alert').innerText(),/Stop the photo server in Manager/);
  assert.ok(await page.getByRole('radio',{name:/Connect to my server/}).isDisabled());
  await local.screenshot({path:join(output,'local-host-stop-refused.png')});
  await stop.click();await page.getByRole('radio',{name:/Connect to my server/}).waitFor();
  assert.ok(await page.getByRole('radio',{name:/Connect to my server/}).isEnabled());
  assert.equal(await local.getByRole('button',{name:'Open local Photos',exact:true}).count(),0);
  assert.equal(calls.filter(value=>value.command==='prepare_local_host').length,1);
  const management=page.getByRole('region',{name:'Server management'});
  await management.getByRole('button',{name:'Disconnect Manager',exact:true}).click();
  await management.getByLabel('Manager password',{exact:true}).fill(password);
  await management.getByRole('button',{name:'Revoke and disconnect',exact:true}).click();
  await management.getByRole('button',{name:'Pair with Manager',exact:true}).waitFor();
  assert.equal(await management.getByLabel('Also allow requests for server updates.').isChecked(),false);
  await prepare.click();
  await local.getByRole('heading',{name:'Local Manager is ready'}).waitFor();
  assert.equal(await local.getByLabel('Also allow requests for server updates.').isChecked(),false);
 });
 await fixture('devicechanged',async({ui,calls})=>{
  await ui.getByRole('alert').waitFor();
  assert.ok(await ui.getByRole('button',{name:'Start server',exact:true}).isDisabled());
  assert.ok(await ui.getByRole('button',{name:'Authorize actions',exact:true}).isDisabled());
  await ui.getByLabel('Manager password',{exact:true}).fill(password);
  await ui.getByRole('button',{name:'Revoke and disconnect',exact:true}).click();
  await ui.getByRole('button',{name:'Pair with Manager',exact:true}).waitFor();
  assert.equal(calls.filter(value=>value.command==='disconnect_manager').length,1);
  assert.equal(calls.filter(value=>value.command==='reauthenticate_manager').length,0);
 });
 await fixture('pair',async({page,ui,calls})=>{
  await ui.getByLabel('Manager HTTPS address').fill(view.origin);
  await ui.getByLabel('Manager password',{exact:true}).fill(password);
  const pair=ui.getByRole('button',{name:'Pair with Manager',exact:true});assert.ok(await pair.isDisabled());
  await ui.getByLabel('Allow this computer to start, stop and restart this server, and create database backups.').check();
  await ui.getByLabel('Also allow backup recovery reviews and restore operations.').check();
  const updates=ui.getByLabel('Also allow requests for server updates.');assert.equal(await updates.count(),1);assert.equal(await updates.isChecked(),false);await updates.check();
  await ui.getByText('Use a certificate for a private Manager',{exact:true}).click();
  await ui.getByLabel('Public certificate',{exact:true}).fill(wire.certificatePem);
  assert.ok(await pair.isDisabled());
  await ui.getByRole('button',{name:'Review certificate fingerprint'}).click();
  await ui.getByText(wire.certificateSha256,{exact:true}).waitFor();
  await ui.getByLabel('I verified this certificate fingerprint.').check();assert.ok(await pair.isEnabled());
  await ui.getByLabel('Public certificate',{exact:true}).fill(wire.certificatePem+'\n');assert.ok(await pair.isDisabled());
  await ui.getByRole('button',{name:'Review certificate fingerprint'}).click();
  await ui.getByLabel('I verified this certificate fingerprint.').check();
  await ui.screenshot({path:join(output,'manager-pair-certificate.png')});
  await pair.click();await ui.getByText('Example server',{exact:true}).waitFor();
  const request=calls.find(value=>value.command==='pair_manager');assert.equal(request.args.certificate.sha256,wire.certificateSha256);assert.equal(request.args.allowRecovery,true);assert.equal(request.args.allowUpdates,true);await ui.getByText('Server update requests: allowed.',{exact:true}).waitFor();
  assert.ok(!(await page.textContent('body')).includes(password));
  assert.ok(!(await page.evaluate(()=>JSON.stringify(localStorage))).includes(password));
 });
 await fixture('lost',async({page,ui,calls,keys,finish,loseNext})=>{
  await ui.getByText('Server update requests: not granted.',{exact:true}).waitFor();
  await ui.getByRole('button',{name:'Start server',exact:true}).click();
  await ui.getByRole('button',{name:'Retry existing request'}).waitFor();
  const original=calls.find(value=>value.args?.command?.kind==='control').args.command.key;
  await page.reload({waitUntil:'networkidle'});
  await ui.getByRole('button',{name:'Retry existing request'}).click();
  await ui.getByText('In progress',{exact:true}).waitFor();
  const retried=calls.filter(value=>value.args?.command?.kind==='control');assert.equal(retried.length,2);assert.equal(retried[1].args.command.key,original);assert.equal(keys.size,1);
  assert.ok(await ui.getByRole('button',{name:'Start server',exact:true}).isDisabled());
  await ui.screenshot({path:join(output,'manager-operation.png')});
  finish();await ui.getByRole('button',{name:'Check operation'}).click();await ui.getByText('Completed',{exact:true}).waitFor();
  assert.ok(await ui.getByRole('button',{name:'Start server',exact:true}).isEnabled());
  assert.ok(!(await page.evaluate(()=>JSON.stringify(localStorage))).includes(original));
  loseNext();
  await ui.getByRole('button',{name:'Stop server',exact:true}).click();
  await ui.getByRole('button',{name:'Confirm stop'}).click();
  await ui.getByRole('button',{name:'Retry existing request'}).waitFor();
  await ui.getByText('Request outcome has not been confirmed',{exact:true}).waitFor();
  assert.equal(await ui.getByText('Completed',{exact:true}).count(),0);
 });
 await fixture('reauth',async({page,ui,calls})=>{
  await ui.getByRole('button',{name:'Stop server',exact:true}).click();
  assert.equal(calls.filter(value=>value.args?.command?.kind==='control').length,0);
  await ui.getByRole('button',{name:'Cancel',exact:true}).click();
  await ui.getByRole('button',{name:'Stop server',exact:true}).click();await ui.getByRole('button',{name:'Confirm stop'}).click();
  await ui.getByLabel('Manager password',{exact:true}).fill(password);
  await ui.getByRole('button',{name:'Authorize and continue'}).click();await ui.getByText('In progress',{exact:true}).waitFor();
  const requests=calls.filter(value=>value.args?.command?.kind==='control');assert.equal(requests.length,2);assert.equal(requests[0].args.command.key,requests[1].args.command.key);
  assert.ok(!(await page.textContent('body')).includes(password));
 });
 await fixture('resume',async({ui,calls,finish})=>{
  await ui.getByText('Interrupted',{exact:true}).waitFor();await ui.getByRole('button',{name:'Resume operation'}).click();
  await ui.getByText('In progress',{exact:true}).waitFor();assert.equal(calls.filter(value=>value.args?.command?.kind==='resume').length,1);
  finish();await ui.getByRole('button',{name:'Check operation'}).click();await ui.getByText('Completed',{exact:true}).waitFor();
  await ui.getByRole('button',{name:'Disconnect Manager',exact:true}).click();
  await ui.getByLabel('Manager password',{exact:true}).fill(password);await ui.getByRole('button',{name:'Revoke and disconnect'}).click();
  await ui.getByRole('button',{name:'Pair with Manager',exact:true}).waitFor();assert.equal(calls.filter(value=>value.command==='disconnect_manager').length,1);
 });
 await fixture('readonly',async({ui})=>{
  for(const name of ['Start server','Stop server','Restart server','Create database backup'])assert.ok(await ui.getByRole('button',{name,exact:true}).isDisabled());
  await ui.screenshot({path:join(output,'manager-narrow-dark.png')});
 },{width:390,height:900},'dark');
 await fixture('paired',async({page,ui,calls})=>{
  await page.evaluate(()=>{Storage.prototype.setItem=function(){throw new DOMException('synthetic storage failure','QuotaExceededError');};});
  await ui.getByRole('button',{name:'Start server',exact:true}).click();
  await ui.getByRole('alert').waitFor();assert.equal(calls.filter(value=>value.args?.command?.kind==='control').length,0);
 });
 await fixture('recovery',async({page,ui,calls,reviews,finishReview})=>{
  await ui.getByRole('button',{name:'Load database backups',exact:true}).click();
  await ui.getByRole('button',{name:'Review selected backup',exact:true}).click();
  await ui.getByRole('button',{name:'Check backup review',exact:true}).waitFor();
  const original=calls.find(value=>value.args?.command?.kind==='review-restore').args.command.key;
  assert.ok((await page.evaluate(()=>JSON.stringify(localStorage))).includes(original));
  await page.reload({waitUntil:'networkidle'});
  await ui.getByRole('button',{name:'Check backup review',exact:true}).click();
  await ui.getByText('Backup review is in progress. Check again when ready.',{exact:true}).waitFor();
  const retries=calls.filter(value=>value.args?.command?.kind==='review-restore');assert.equal(retries.length,2);assert.equal(retries[1].args.command.key,original);assert.equal(reviews.size,1);
  finishReview();await ui.getByRole('button',{name:'Check backup review',exact:true}).click();
  await ui.getByText('Backup review is ready.',{exact:true}).waitFor();
  await ui.getByRole('button',{name:'Restore this backup',exact:true}).waitFor();
  assert.equal(calls.filter(value=>value.args?.command?.kind==='control').length,0);
  await ui.screenshot({path:join(output,'manager-backup-review.png')});
  await ui.getByRole('button',{name:'Choose another backup',exact:true}).click();
  assert.ok(!(await page.evaluate(()=>JSON.stringify(localStorage))).includes(original));
 });
 await fixture('recovery-reauth',async({ui,calls})=>{
  await ui.getByText('Interrupted',{exact:true}).waitFor();
  await ui.getByRole('button',{name:'Load database backups',exact:true}).click();
  await ui.getByLabel('Manager password',{exact:true}).fill(password);
  await ui.getByRole('button',{name:'Authorize and review',exact:true}).click();
  await ui.getByRole('button',{name:'Review selected backup',exact:true}).waitFor();
  assert.equal(calls.filter(value=>['resume','control'].includes(value.args?.command?.kind)).length,0);
 });
 await fixture('recovery-storage',async({page,ui,calls})=>{
  await ui.getByRole('button',{name:'Load database backups',exact:true}).click();
  await page.evaluate(()=>{Storage.prototype.setItem=function(){throw new DOMException('synthetic storage failure','QuotaExceededError');};});
  await ui.getByRole('button',{name:'Review selected backup',exact:true}).click();
  await ui.getByRole('alert').waitFor();
  assert.equal(calls.filter(value=>value.args?.command?.kind==='review-restore').length,0);
 });
 async function reviewed(ui,finishReview){
  await ui.getByRole('button',{name:'Load database backups',exact:true}).click();
  await ui.getByRole('button',{name:'Review selected backup',exact:true}).click();
  finishReview();await ui.getByRole('button',{name:'Check backup review',exact:true}).click();
  await ui.getByRole('button',{name:'Restore this backup',exact:true}).click();
  assert.equal(await ui.getByRole('button',{name:'Restore database',exact:true}).isDisabled(),true);
 }
 await fixture('recovery-restore',async({page,ui,calls,restores,finishReview,finishRestore})=>{
  await reviewed(ui,finishReview);
  assert.equal(calls.filter(v=>v.args?.command?.kind==='restore').length,0);
  await ui.getByLabel('I understand and want to restore this database backup.',{exact:true}).check();
  await ui.getByRole('button',{name:'Restore database',exact:true}).click();
  await ui.getByRole('button',{name:'Check database restore',exact:true}).waitFor();
  const first=calls.find(v=>v.args?.command?.kind==='restore').args.command;
  assert.notEqual(first.key,first.reviewId);assert.equal(restores.size,1);
  await page.reload({waitUntil:'networkidle'});
  await ui.getByRole('button',{name:'Check database restore',exact:true}).click();
  await ui.getByText('Database restore is running. Keep the computer and server connected.',{exact:true}).waitFor();
  const requests=calls.filter(v=>v.args?.command?.kind==='restore');assert.equal(requests.length,2);assert.equal(requests[1].args.command.key,first.key);assert.equal(restores.size,1);
  assert.equal(await ui.getByRole('button',{name:'Start server',exact:true}).isDisabled(),true);
  finishRestore();await ui.getByRole('button',{name:'Check database restore',exact:true}).click();
  await ui.getByText('Database restore completed. The server reported ready.',{exact:true}).waitFor();
  await ui.screenshot({path:join(output,'manager-database-restore.png')});
  await ui.getByRole('button',{name:'Finish restore',exact:true}).click();
  assert.ok(!(await page.evaluate(()=>JSON.stringify(localStorage))).includes(first.key));
  assert.equal(calls.filter(v=>['control','resume'].includes(v.args?.command?.kind)).length,0);
 });
 await fixture('recovery-restore-resume',async({ui,calls,finishReview,interruptRestore})=>{
  await reviewed(ui,finishReview);
  await ui.getByLabel('I understand and want to restore this database backup.',{exact:true}).check();
  await ui.getByRole('button',{name:'Restore database',exact:true}).click();
  interruptRestore();await ui.getByRole('button',{name:'Check database restore',exact:true}).click();
  await ui.getByLabel('Manager password',{exact:true}).fill(password);
  await ui.getByRole('button',{name:'Authorize database restore',exact:true}).click();
  await ui.getByRole('button',{name:'Resume database restore',exact:true}).click();
  await ui.getByText('Database restore is running. Keep the computer and server connected.',{exact:true}).waitFor();
  assert.equal(calls.filter(v=>v.args?.command?.kind==='restore').length,1);
  assert.equal(calls.filter(v=>v.args?.command?.kind==='resume-restore').length,1);
  assert.equal(calls.filter(v=>['control','resume'].includes(v.args?.command?.kind)).length,0);
 });
 await fixture('recovery-restore-storage',async({page,ui,calls,finishReview})=>{
  await reviewed(ui,finishReview);
  await page.evaluate(()=>{Storage.prototype.setItem=function(){throw new DOMException('synthetic storage failure','QuotaExceededError');};});
  await ui.getByLabel('I understand and want to restore this database backup.',{exact:true}).check();
  await ui.getByRole('button',{name:'Restore database',exact:true}).click();
  await ui.getByRole('alert').waitFor();assert.equal(calls.filter(v=>v.args?.command?.kind==='restore').length,0);
 });
 await fixture('recovery-restore-expired',async({page,ui,calls,finishReview})=>{
  await reviewed(ui,finishReview);
  await ui.getByLabel('I understand and want to restore this database backup.',{exact:true}).check();
  await ui.getByRole('button',{name:'Restore database',exact:true}).click();
  await ui.getByText('The backup review expired before this restore was accepted. Review the backup again.',{exact:true}).waitFor();
  assert.ok(!(await page.evaluate(()=>JSON.stringify(localStorage))).includes('frameleaf.manager-restore:'));
  assert.equal(calls.filter(v=>v.args?.command?.kind==='restore').length,1);
 });
 process.stdout.write('Manager UI browser flows passed: local update consent/grants/backup filtering/recent-auth/cancel/busy/failure/reload/four-phase recovery/invalid discovery, password-only account creation/race/Unicode, pairing/certificate consent, lost reply+reload, recent auth+confirmation, resume+disconnect, readonly/narrow/dark, storage failure, backup review/reload/consent/isolated recent auth.\n');
}finally{
 await browser?.close();if(vite.exitCode===null) vite.kill('SIGTERM');await ended;
}
