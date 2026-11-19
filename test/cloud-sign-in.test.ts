import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { cleanProof, proofReady, recoveryUrl, screenAfter, secondStepCopy, secondSteps } from '../src/cloud-sign-in.ts';
import { connectionError } from '../src/errors.ts';

const read = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');
const generic = connectionError('not_a_known_code');

test('the screen after an emailed Verification Code follows what Cloud offers', () => {
  // An authenticator, with Recovery Codes left: Cloud's preferred method first; the Passkey it also lists is the browser's.
  assert.deepEqual(screenAfter({ status: 'next', methods: ['totp', 'recovery_code', 'passkey'] }), { mode: 'second', methods: ['totp', 'recovery_code'], recovery: false });
  assert.deepEqual(screenAfter({ status: 'next', methods: ['recovery_code'] }), { mode: 'second', methods: ['recovery_code'], recovery: false });
  assert.deepEqual(screenAfter({ status: 'next', methods: ['password', 'passkey'] }), { mode: 'second', methods: ['password'], recovery: false });
  // Only a Passkey, or a method this app does not know: the browser finishes, never a dead end.
  assert.deepEqual(screenAfter({ status: 'next', methods: ['passkey'] }), { mode: 'browser', recovery: false });
  assert.deepEqual(screenAfter({ status: 'next', methods: ['toString', 'something_new'] }), { mode: 'browser', recovery: false });
  assert.deepEqual(screenAfter({ status: 'browser' }), { mode: 'browser', recovery: false });
  assert.deepEqual(secondSteps([]), []);
});

test('each second step is named in the fixed words', () => {
  assert.deepEqual(secondStepCopy('totp'), { title: 'Two-Step Verification', sub: 'Enter the Verification Code from your authenticator app.', label: 'Verification Code', choose: 'Use My Authenticator App' });
  assert.equal(secondStepCopy('recovery_code').label, 'Recovery Code');
  assert.equal(secondStepCopy('recovery_code').choose, 'Use a Recovery Code');
  assert.equal(secondStepCopy('password').label, 'Password');
});

test('a proof is shaped for its step before Verify is offered', () => {
  assert.equal(cleanProof('email_code', '12 34-567'), '123456');
  assert.equal(cleanProof('totp', 'abc'), '');
  assert.equal(cleanProof('recovery_code', ' ABCDE-FGHJK '), 'ABCDE-FGHJK');
  assert.equal(cleanProof('password', ' pass word '), ' pass word ');
  assert.equal(proofReady('email_code', '123456'), true);
  assert.equal(proofReady('totp', '12345'), false);
  assert.equal(proofReady('recovery_code', ''), false);
  assert.equal(proofReady('recovery_code', 'ABCDE-FGHJK'), true);
  assert.equal(proofReady('password', ''), false);
  assert.equal(proofReady('password', 'x'), true);
});

test('every Frameleaf account refusal has its own actionable message', () => {
  for (const code of ['cloud_email_wrong_code', 'cloud_email_wrong_recovery_code', 'cloud_email_wrong_password', 'cloud_email_second_step_locked', 'cloud_email_account_blocked', 'cloud_email_expired_code', 'cloud_exchange_interaction_required']) {
    assert.notEqual(connectionError(code), generic, code);
  }
  assert.match(connectionError('cloud_email_wrong_code'), /Verification Code/);
  assert.match(connectionError('cloud_email_expired_code'), /Send a new Verification Code/);
  assert.match(connectionError('cloud_email_wrong_recovery_code'), /Recovery Code/);
  // The server token Cloud refuses until the server is approved: say where to approve it.
  assert.match(connectionError('cloud_exchange_interaction_required'), /this server’s own sign-in/);
});

test('the account screen has every step state and none of the old wording', () => {
  const screen = read('../src/FrameleafAccount.svelte');
  for (const mode of ["mode === 'code'", "mode === 'second'", "mode === 'browser'"]) assert.ok(screen.includes(mode), mode);
  for (const words of ['Send a New Verification Code', 'aria-label="Verification Code"', 'Enter the Verification Code to finish.', 'Continue in My Browser', 'Use a Passkey in My Browser']) assert.ok(screen.includes(words), words);
  // The proof goes to the app with its method, and a refused server token opens the server's own sign-in.
  assert.match(screen, /invoke<Completed>\('cloud_email_complete', \{ method: using, proof: given \}\)/);
  assert.match(read('../src/pages/Welcome.svelte'), /'cloud_exchange_interaction_required'\) await openServer\(/);
  for (const source of [screen, read('../src/errors.ts'), read('../src/cloud-sign-in.ts'), read('../src/pages/Welcome.svelte')]) {
    for (const old of ['Email code', 'email code', 'Send a New Code', 'Enter the code to finish', 'That code ', '>Code<']) assert.ok(!source.includes(old), old);
  }
  // Nothing typed for a step is kept in browser storage.
  assert.doesNotMatch(screen, /localStorage|sessionStorage/);
});

test('a step Cloud marks for recovery offers the recovery link directly, and no other step does', () => {
  // After an emailed Verification Code on an account with a Passkey or an authenticator.
  assert.deepEqual(screenAfter({ status: 'next', methods: ['totp', 'passkey'], recovery: true }), { mode: 'second', methods: ['totp'], recovery: true });
  assert.deepEqual(screenAfter({ status: 'next', methods: ['passkey'], recovery: true }), { mode: 'browser', recovery: true });
  assert.deepEqual(screenAfter({ status: 'browser', recovery: true }), { mode: 'browser', recovery: true });
  // Only Cloud's own `true` counts.
  assert.equal(screenAfter({ status: 'next', methods: ['totp'], recovery: 'yes' as unknown as boolean }).recovery, false);
  assert.equal(recoveryUrl, 'https://frameleaf.cloud/recover');
  const screen = read('../src/FrameleafAccount.svelte');
  // Both the second step and the browser hand-off show the link when recovery is offered, opened by the backend.
  assert.equal(screen.match(/\{#if recovery\}<button [^>]*onclick=\{recover\}>Recover My Account<\/button>\{\/if\}/g)?.length, 2);
  assert.match(screen, /invoke\('open_external', \{ url: recoveryUrl \}\)/);
  assert.match(screen, /recovery = next\.recovery;/);
});
