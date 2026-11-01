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
 let paired=!['pair','localhost'].includes(scenario),authorized=scenario!=='reauth',lost=scenario==='lost',current=scenario==='resume'?makeOperation('stop','interrupted'):null;
 const localRecord={schemaVersion:1,manifestSha256:'a'.repeat(64),controllerSha256:'b'.repeat(64)};
 let local={state:'idle',code:null,backgroundActive:false,installation:null,origin:null};
 let refuseLocalStop=true;
 const manager={...view,...(scenario==='localhost'?{origin:'https://127.0.0.1:9443',certificateSha256:wire.certificateSha256}:{}),scopes:scenario==='readonly'?['status']:view.scopes};
 await context.exposeBinding('__managerInvoke',async(_source,command,args={})=>{
  calls.push({command,args:structuredClone(args)});
  if(command==='plugin:event|listen')return 1;
  if(command==='plugin:event|unlisten')return;
  if(command==='local_host_status')return local;
  if(command==='installed_local_hosts')return scenario==='localhost'?[localRecord]:[];
  if(command==='prepare_local_host'){assert.equal(args.manifestSha256,localRecord.manifestSha256);await new Promise(resolve=>setTimeout(resolve,300));local={state:'manager-ready',code:null,backgroundActive:true,installation:localRecord,origin:'https://127.0.0.1:9443'};return local;}
  if(command==='stop_local_host_manager'){if(refuseLocalStop){refuseLocalStop=false;throw 'host_controller_already_owned';}local={...local,state:'idle',backgroundActive:false};return local;}
  if(command==='restore_connection')return null;
  if(command==='worker_setup_status')return {state:'stopped',code:null,control:'stopped',workloads:[]};
  if(command==='authorize_local_manager'){assert.deepEqual(Object.keys(args).sort(),['allowManagement','password']);assert.equal(args.password,password);assert.equal(args.allowManagement,true);await new Promise(resolve=>setTimeout(resolve,300));paired=true;return manager;}
  if(command==='open_local_photos'){assert.equal(scenario,'localhost');assert.ok(paired&&local.backgroundActive);assert.deepEqual(args,{});return;}
  if(command==='manager_view')return paired?manager:null;
  if(command==='manager_certificate_fingerprint')return wire.certificateSha256;
  if(command==='pair_manager'){assert.equal(args.password,password);assert.equal(args.allowManagement,true);paired=true;return {...manager,certificateSha256:args.certificate?.sha256||null};}
  if(command==='reauthenticate_manager'){assert.equal(args.password,password);authorized=true;return;}
  if(command==='disconnect_manager'){assert.equal(args.password,password);paired=false;return;}
  if(command==='manager_request'){
   const request=args.command;
   if(scenario==='devicechanged'&&paired)throw 'manager_device_changed';
   if(request.kind==='status')return {manager:{id:manager.managerId,origin:manager.origin},installation:{id:manager.installationId,name:scenario==='localhost'?'My local library':'Example NAS',release:'frameleaf-v3.0.0-1',port:2283},operations:current?[current]:[]};
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
  if(!['pair','localhost','devicechanged'].includes(scenario))await ui.getByText('Example NAS',{exact:true}).waitFor();
  await run({page,ui,calls,keys,loseNext:()=>{lost=true;},finish:()=>{current={...current,state:'complete',completed:[current.kind],updatedAt:Date.now()};}});
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
 await fixture('localhost',async({page,calls})=>{
  await page.getByRole('radio',{name:/Run Frameleaf here/}).check();
  const local=page.getByRole('region',{name:'Local library setup'});
  const prepare=local.getByRole('button',{name:'Prepare local Manager'});
  await prepare.waitFor();await prepare.click();
  await local.getByRole('heading',{name:'Preparing local management…'}).waitFor();
  assert.ok(await page.getByRole('radio',{name:/Connect to my server/}).isDisabled());
  await local.getByRole('heading',{name:'Local Manager is ready'}).waitFor();
  assert.ok(await page.getByRole('radio',{name:/Connect to my server/}).isDisabled());
  await local.getByText('The photo server has not been started by this setup step.',{exact:false}).waitFor();
  const authorize=local.getByRole('button',{name:'Authorize local management'});
  const input=local.getByLabel('Local Manager password',{exact:true});
  await input.fill(password);assert.ok(await authorize.isDisabled());
  await local.getByLabel('Allow this computer to manage this local server.').check();
  assert.ok(await authorize.isEnabled());await authorize.click();
  assert.equal(await input.inputValue(),'');
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
  await pair.click();await ui.getByText('Example NAS',{exact:true}).waitFor();
  const request=calls.find(value=>value.command==='pair_manager');assert.equal(request.args.certificate.sha256,wire.certificateSha256);
  assert.ok(!(await page.textContent('body')).includes(password));
  assert.ok(!(await page.evaluate(()=>JSON.stringify(localStorage))).includes(password));
 });
 await fixture('lost',async({page,ui,calls,keys,finish,loseNext})=>{
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
 process.stdout.write('Manager UI browser flows passed: pairing/certificate consent, lost reply+reload, recent auth+confirmation, resume+disconnect, readonly/narrow/dark, storage failure.\n');
}finally{
 await browser?.close();if(vite.exitCode===null) vite.kill('SIGTERM');await ended;
}
