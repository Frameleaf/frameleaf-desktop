import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { beginStep, chooseMethod, methodChoice, noStepUp, otherMethods, proofLabel, proofReady, stepFailed, stepPrompt, stepUpAfterFailure, stepUpDismissed, verificationRequired } from '../src/sign-in-steps.ts';
import { connectionError } from '../src/errors.ts';

test('a step opens on the server’s preferred proof and offers the others', () => {
  const step = beginStep({ transaction: 'txn', methods: ['totp', 'recovery_code'] });
  assert.deepEqual(step, { transaction: 'txn', methods: ['totp', 'recovery_code'], method: 'totp', sentTo: null, passkey: false, failure: '' });
  assert.deepEqual(otherMethods(step), ['recovery_code']);
  assert.equal(stepPrompt(step), 'Enter the Verification Code from your authenticator app.');
  assert.equal(proofLabel(step.method), 'Verification Code');

  const recovery = chooseMethod(step, 'recovery_code');
  assert.equal(recovery.method, 'recovery_code');
  assert.deepEqual(otherMethods(recovery), ['totp']);
  assert.equal(stepPrompt(recovery), 'Enter one of your Recovery Codes. Each one works once.');
  assert.equal(proofLabel(recovery.method), 'Recovery Code');
  // A proof the server did not offer cannot be chosen.
  assert.equal(chooseMethod(step, 'email_code'), step);
});

test('an emailed Verification Code names where it was sent', () => {
  const step = beginStep({ transaction: 'txn', methods: ['email_code', 'recovery_code', 'email_code'], sentTo: 'a•••@example.test' });
  assert.deepEqual(step.methods, ['email_code', 'recovery_code']);
  assert.equal(step.method, 'email_code');
  assert.equal(stepPrompt(step), 'Enter the Verification Code sent to a•••@example.test.');
  assert.equal(stepPrompt(beginStep({ transaction: 'txn', methods: ['email_code'], sentTo: ' ' })), 'Enter the Verification Code sent to your email.');
});

test('a wrong code keeps the step, its transaction and its chosen proof, with a clear message', () => {
  const step = chooseMethod(beginStep({ transaction: 'txn', methods: ['totp', 'recovery_code'] }), 'recovery_code');
  const failed = stepFailed(step, 'sign_in_recovery_code_wrong');
  assert.deepEqual(failed, { ...step, failure: 'That Recovery Code didn’t work, or it was already used.' });
  assert.match(stepFailed(step, 'sign_in_code_wrong').failure, /^That Verification Code didn’t work\./);
  // Choosing another proof clears the message and keeps the transaction.
  assert.deepEqual(chooseMethod(failed, 'totp'), { ...step, method: 'totp' });
});

test('a Passkey-only step has nothing to enter and says so', () => {
  const step = beginStep({ transaction: 'txn', methods: ['passkey'] });
  assert.equal(step.method, null);
  assert.deepEqual(step.methods, []);
  assert.equal(step.passkey, true);
  assert.equal(stepPrompt(step), 'This needs a Passkey, and this app can’t use a Passkey yet.');
  assert.equal(proofReady(step.method, '123456'), false);
  // A Passkey offered beside a code leaves the code step usable; unknown names are ignored.
  const mixed = beginStep({ transaction: 'txn', methods: ['passkey', 'frameleaf', 'totp'] });
  assert.equal(mixed.method, 'totp');
  assert.equal(stepPrompt(beginStep({ transaction: 'txn', methods: ['frameleaf'] })), 'This needs a step this app can’t finish yet.');
});

test('only a complete proof can be sent', () => {
  for (const [method, proof, ready] of [
    ['totp', '123456', true], ['totp', ' 123456 ', true], ['totp', '12345', false], ['totp', '1234567', false], ['totp', '12a456', false],
    ['email_code', '654321', true], ['email_code', '', false],
    ['recovery_code', 'abcd-efgh', true], ['recovery_code', '   ', false], ['recovery_code', 'x'.repeat(33), false],
  ] as const) assert.equal(proofReady(method, proof), ready, `${method} ${proof}`);
});

test('a refusal that needs Two-Step Verification carries its methods and transaction; nothing else does', () => {
  assert.deepEqual(verificationRequired({ code: 'verification_required', methods: ['frameleaf', 'totp', 7], transaction: 'txn' }), { transaction: 'txn', methods: ['frameleaf', 'totp'] });
  assert.deepEqual(verificationRequired({ code: 'verification_required', transaction: 'txn' }), { transaction: 'txn', methods: [] });
  for (const other of ['verification_required', 'server_http_403', null, undefined, {}, { code: 'verification_required' }, { code: 'other', transaction: 'txn' }, new Error('verification_required')]) {
    assert.equal(verificationRequired(other), null);
  }
  // A page that only shows a message still names it.
  assert.equal(connectionError({ code: 'verification_required', methods: [], transaction: 'txn' }), 'This needs Two-Step Verification.');
});

test('the words on screen are the fixed sign-in vocabulary', () => {
  const words = [
    ...(['totp', 'email_code', 'recovery_code'] as const).flatMap(method => [methodChoice(method), proofLabel(method), stepPrompt(chooseMethod(beginStep({ transaction: 't', methods: [method] }), method))]),
    stepPrompt(beginStep({ transaction: 't', methods: ['passkey'] })),
    ...['sign_in_code_wrong', 'sign_in_recovery_code_wrong', 'sign_in_code_invalid', 'sign_in_too_many_attempts', 'sign_in_two_step_unsupported', 'verification_required', 'server_refused_verification_required', 'server_refused_two_factor_setup_required', 'server_refused_frameleaf_sign_in_required'].map(connectionError),
  ];
  for (const text of words) {
    assert.notEqual(text, connectionError('unknown_code'), 'every new code has its own copy');
    for (const term of ['Passkey', 'Password', 'Verification Code', 'Recovery Code', 'Two-Step Verification']) {
      const loose = new RegExp(term.replace(/[ -]/g, '[ -]'), 'gi');
      for (const found of text.match(loose) ?? []) assert.equal(found, term, text);
    }
    assert.doesNotMatch(text, /two-factor|2FA|one-time|OTP|backup code|security code|passcode/i, text);
  }
});

// Overview's summary and the AI library panel load in the background; this is the state of their Verify prompt.
test('a background request refused until Two-Step Verification opens the Verify prompt, once', () => {
  const refusal = (transaction: string) => ({ code: 'verification_required', methods: ['totp', 'recovery_code'], transaction });
  let retried = 0;
  const retry = () => { retried += 1; };

  const asked = stepUpAfterFailure(noStepUp, refusal('first'), retry);
  assert.deepEqual(asked, { request: { offer: { transaction: 'first', methods: ['totp', 'recovery_code'] }, retry }, dismissed: false });
  // The prompt starts on a proof this app can enter, so it offers Verify.
  assert.equal(beginStep(asked.request!.offer).method, 'totp');
  asked.request!.retry();
  assert.equal(retried, 1);

  // The next poll is refused again with a new transaction: the open prompt, and what is typed in it, stays.
  assert.equal(stepUpAfterFailure(asked, refusal('second'), retry), asked);
  // Dismissed, it does not come back with the next poll.
  assert.equal(stepUpAfterFailure(stepUpDismissed, refusal('third'), retry), stepUpDismissed);
  // Any other failure shows no prompt: an outage, a refusal by code, no administrator rights.
  for (const other of ['server_unreachable_or_certificate_invalid', 'server_refused_verification_required', 'admin_required', Error('verification_required'), null, undefined])
    assert.equal(stepUpAfterFailure(noStepUp, other, retry), noStepUp);
});

test('Overview and the AI library panel show the shared Verify prompt for their own requests', () => {
  const read = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');
  const app = read('../src/App.svelte');
  const overview = read('../src/pages/Overview.svelte');
  const library = read('../src/pages/AiLibrary.svelte');
  // Overview's summary is loaded by the app shell, which hands the refused request to the page.
  assert.match(app, /await invoke<ServerSummary>\('server_summary'\)[\s\S]{0,200}stepUpAfterFailure\(summaryStepUp, failed/);
  assert.match(app, /<Overview [^>]*stepUp=\{summaryStepUp\.request\}[^>]*onstepupclose=\{\(\) => \{ summaryStepUp = stepUpDismissed; \}\}/);
  assert.match(overview, /\{#if stepUp\}\{#key stepUp\}<StepUp offer=\{stepUp\.offer\} retry=\{stepUp\.retry\} onclose=\{onstepupclose\} \/>/);
  assert.match(library, /await invoke<LibraryAiProcessing>\('server_ai_processing'\)[\s\S]{0,300}stepUpAfterFailure\(prompt, failed/);
  assert.match(library, /<StepUp offer=\{stepUp\.request\.offer\} retry=\{stepUp\.request\.retry\}/);
  // After a correct proof the prompt closes and the refused request runs again. Closing unmounts the
  // prompt, so the retry has to be taken from its props first (reading it afterwards throws, unseen).
  assert.match(read('../src/StepUp.svelte'), /const again = retry;\s*onclose\(\);\s*again\(\);/);
  // One prompt component: neither page has its own sheet or wording for it.
  for (const page of [overview, library]) {
    assert.match(page, /import StepUp from '\.\.\/StepUp\.svelte';/);
    assert.doesNotMatch(page, /server_step_up|<Sheet|This needs/);
  }
});
