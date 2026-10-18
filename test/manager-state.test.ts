import assert from 'node:assert/strict';
import { test } from 'node:test';
import { controlIntent, restoreIntent, intentKey, managerError, localProfilePending, profileSetupCopy, type ManagerView } from '../src/manager-state.ts';
test('profile setup copy distinguishes local preparation from system authorization', () => {
 const local=profileSetupCopy(false), authorized=profileSetupCopy(true);
 assert.doesNotMatch(JSON.stringify(local), /administrator|authorization request/i);
 assert.match(local.pending, /preparing/i);
 assert.match(authorized.preparation, /administrator/i);
 assert.match(authorized.quit, /authorization request/i);
});
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

test('backup review request keys survive retries and stay bound to Manager and snapshot', async () => {
 const {backupReviewIntent,restoreBackupReview,backupReviewKey}=await import('../src/manager-state.ts');
 const owner={...manager,scopes:[...manager.scopes,'restore']},snapshot='a'.repeat(64);
 const intent=backupReviewIntent(owner,snapshot,null);
 assert.equal(backupReviewIntent(owner,snapshot,intent).key,intent.key);
 assert.deepEqual(restoreBackupReview(JSON.stringify(intent),owner),intent);
 assert.equal(restoreBackupReview(JSON.stringify(intent),{...owner,installationId:'bbbbbbbbbbbb'}),null);
 assert.equal(restoreBackupReview(JSON.stringify({...intent,path:'/private'}),owner),null);
 assert.equal(restoreBackupReview(JSON.stringify({...intent,snapshot:[snapshot]}),owner),null);
 assert.throws(()=>backupReviewIntent(manager,snapshot,null),/manager_scope_denied/);
 assert.throws(()=>backupReviewIntent(owner,'b'.repeat(64),intent),/manager_review_pending/);
 assert.notEqual(backupReviewKey(owner),intentKey(owner));
});

test('restore intent requires a fresh compatible review and preserves one execution key across reload', async () => {
 const {createBackupRestoreIntent,parseBackupRestoreIntent,backupRestoreKey}=await import('../src/manager-state.ts');
 const owner={...manager,scopes:[...manager.scopes,'restore']};
 const review={id:crypto.randomUUID(),snapshot:'a'.repeat(64),installationId:owner.installationId,expires:Date.now()+900000,state:'prepared' as const,libraryId:owner.installationId,release:'frameleaf-v3.0.0-1',targetRelease:'frameleaf-v3.0.0-1',createdAt:1,mediaIncluded:false as const,requiresRuntimeChange:false};
 const intent=createBackupRestoreIntent(owner,review,null);
 assert.notEqual(intent.key,review.id);
 assert.equal(createBackupRestoreIntent(owner,review,intent).key,intent.key);
 assert.deepEqual(parseBackupRestoreIntent(JSON.stringify(intent),owner),intent);
 for(const patch of [{expires:0},{requiresRuntimeChange:true},{installationId:'b'.repeat(12)},{state:'preparing'}])assert.throws(()=>createBackupRestoreIntent(owner,{...review,...patch},null));
 assert.throws(()=>createBackupRestoreIntent(manager,review,null),/manager_scope_denied/);
 assert.throws(()=>createBackupRestoreIntent(owner,{...review,id:crypto.randomUUID()},intent),/manager_restore_pending/);
 for(const patch of [{reviewId:'bad'},{id:'00000000-0000-0000-0000-000000000000'},{password:'secret'},{snapshot:['a'.repeat(64)]}])assert.equal(parseBackupRestoreIntent(JSON.stringify({...intent,...patch}),owner),null);
 assert.equal(parseBackupRestoreIntent(JSON.stringify(intent),{...owner,deviceId:crypto.randomUUID()}),null);
 assert.notEqual(backupRestoreKey(owner),intentKey(owner));
});
