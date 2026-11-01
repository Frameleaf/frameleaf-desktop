import assert from 'node:assert/strict';
import { test } from 'node:test';
import { controlIntent, restoreIntent, intentKey, managerError, localProfilePending, type ManagerView } from '../src/manager-state.ts';
test('local profile authorization survives reload and ends only after backend and request complete',()=>{
 assert.equal(localProfilePending('provisioning',false),true);
 assert.equal(localProfilePending('provisioning',true),true);
 assert.equal(localProfilePending('profile-ready',true),true);
 for(const state of [undefined,'idle','profile-ready','needs-attention','manager-ready'])assert.equal(localProfilePending(state,false),false);
});
const manager:ManagerView={origin:'https://manager.test:9443',managerId:'11111111-1111-4111-8111-111111111111',deviceId:'22222222-2222-4222-8222-222222222222',installationId:'aaaaaaaaaaaa',expiresAt:1900000000000,scopes:['status','start','stop','restart','backup'],certificateSha256:null};
test('a retry keeps its durable request key and cannot silently switch action',()=>{
 const initial=controlIntent(manager,'stop',null);
 assert.equal(controlIntent(manager,'stop',initial).key,initial.key);
 assert.throws(()=>controlIntent(manager,'restart',initial),/manager_operation_pending/);
 assert.throws(()=>controlIntent({...manager,scopes:['status']},'stop',null),/manager_scope_denied/);
});
test('pending intent restores only for the same Manager, device and installation',()=>{
 const initial=controlIntent(manager,'backup',null),raw=JSON.stringify(initial);
 assert.deepEqual(restoreIntent(raw,manager),initial);
 for(const patch of [{origin:'https://other.test'},{managerId:crypto.randomUUID()},{deviceId:crypto.randomUUID()},{installationId:'bbbbbbbbbbbb'}])
  assert.equal(restoreIntent(raw,{...manager,...patch}),null);
 for(const patch of [{action:'shell'},{key:'bad'},{id:'bad'},{secret:'private-token'}])
  assert.equal(restoreIntent(JSON.stringify({...initial,...patch}),manager),null);
 assert.equal(restoreIntent('{',manager),null);
 assert.equal(restoreIntent(null,manager),null);
 assert.notEqual(intentKey(manager),intentKey({...manager,installationId:'bbbbbbbbbbbb'}));
});
test('remote or native diagnostic text is never echoed as a UI error',()=>{
 assert.match(managerError('manager_recent_auth_required'),/password/i);
 assert.match(managerError('credential_store_locked_or_unavailable'),/unlock/i);
 assert.ok(!managerError('private-token-in-a-diagnostic').includes('private-token'));
});
test('prototype property names cannot become UI error content',()=>{
 for(const code of ['constructor','toString','__proto__'])assert.equal(typeof managerError(code),'string');
});
