import assert from 'node:assert/strict';
import { test } from 'node:test';
import { restoredPage, shortcutPage } from '../src/navigation.ts';

test('restores only an available route for the current verified connection and account', () => {
  const raw = JSON.stringify({ scope: 'server-account-a', page: 'wallet' });
  assert.equal(restoredPage(raw, 'server-account-a', true), 'wallet');
  assert.equal(restoredPage(raw, 'server-account-a', false), 'overview');
  assert.equal(restoredPage(raw, 'server-account-b', true), 'overview');
  assert.equal(restoredPage(raw, '', true), 'overview');
  assert.equal(restoredPage('{', 'server-account-a', true), 'overview');
  assert.equal(restoredPage('{"scope":"server-account-a","page":"approve-restore"}', 'server-account-a', true), 'overview');
});

test('uses Command on macOS and Control on Windows and Linux for number shortcuts', () => {
  const event = { key: '2', metaKey: false, ctrlKey: false, shiftKey: false, altKey: false };
  assert.equal(shortcutPage({ ...event, metaKey: true }, true), 'sources');
  assert.equal(shortcutPage({ ...event, ctrlKey: true }, false), 'sources');
  assert.equal(shortcutPage({ ...event, ctrlKey: true }, true), null);
  assert.equal(shortcutPage({ ...event, metaKey: true }, false), null);
  assert.equal(shortcutPage({ ...event, metaKey: true, ctrlKey: true }, true), null);
  assert.equal(shortcutPage({ ...event, metaKey: true, shiftKey: true }, true), null);
  assert.equal(shortcutPage({ ...event, ctrlKey: true, altKey: true }, false), null);
  assert.equal(shortcutPage({ ...event, key: '9', ctrlKey: true }, false), null);
});
