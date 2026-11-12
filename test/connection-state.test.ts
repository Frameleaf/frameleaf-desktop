import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { reconnectDelay, savedSignInState, savedSignInView } from '../src/connection-state.ts';

test('an unreachable server shows the reconnecting screen, not the signed-out one', () => {
  const state = savedSignInState('server_unreachable_or_certificate_invalid');
  assert.equal(state, 'reconnecting');
  const view = savedSignInView(state);
  assert.equal(view.signIn, false);
  assert.equal(view.clearSavedSignIn, false);
  assert.equal(view.autoRetry, true);
  assert.match(view.panel!.title, /Reconnecting/);
  assert.match(view.panel!.detail, /sign-in is saved/);
});

test('a server asking for Two-Step Verification keeps the sign-in and never offers to clear it', () => {
  const state = savedSignInState('verification_required');
  assert.equal(state, 'needs-verification');
  const view = savedSignInView(state);
  assert.deepEqual([view.signIn, view.clearSavedSignIn, view.autoRetry], [false, false, false]);
  assert.match(view.panel!.title, /Two-Step Verification/);
});

test('only a rejected or unusable sign-in falls back to sign-in with the clear action', () => {
  for (const code of ['server_http_401', 'server_http_403', 'account_identity_changed', 'server_identity_not_confirmed', new Error('server_http_401')]) {
    assert.equal(savedSignInState(code), 'stale');
  }
  assert.deepEqual(savedSignInView('stale'), { signIn: true, clearSavedSignIn: true, autoRetry: false, panel: null });
  assert.equal(savedSignInState('credential_unlock_required'), 'locked');
  assert.deepEqual(savedSignInView('locked'), { signIn: true, clearSavedSignIn: false, autoRetry: false, panel: null });
  assert.deepEqual(savedSignInView(null), { signIn: true, clearSavedSignIn: false, autoRetry: false, panel: null });
});

test('reconnect attempts back off from five seconds to a five minute ceiling', () => {
  assert.deepEqual([0, 1, 2, 3, 6, 7, 50].map(reconnectDelay), [5_000, 10_000, 20_000, 40_000, 300_000, 300_000, 300_000]);
});

test('the window renders the kept sign-in panel in place of the sign-in form and retries by itself', () => {
  const app = readFileSync(new URL('../src/App.svelte', import.meta.url), 'utf8');
  // The panel branch comes first, so the Welcome sign-in form is not rendered while a sign-in is kept.
  assert.match(app, /\{#if kept\.panel\}[\s\S]*?\{kept\.panel\.title\}[\s\S]*?\{:else if !connection\}\s*<Welcome/);
  assert.match(app, /const kept = \$derived\(savedSignInView\(connection \? null : keptSignIn\)\)/);
  assert.match(app, /setTimeout\(\(\) => \{ void restoreSaved\(false, true\); \}, reconnectDelay\(reconnectAttempt\+\+\)\)/);
  assert.match(app, /ononline=\{networkBack\}/);
});
