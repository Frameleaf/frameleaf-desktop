import assert from 'node:assert/strict';
import { enabled, withBrowser } from './ui_test_support.mjs';

// Opt-in browser qualification of the sidebar, keyboard shortcuts, page restore and sign-out sheet.
// Synthetic IPC exercises keyboard behavior without loading a saved credential or library.
// Run it with `npm run test:ui`.
if (!enabled) process.exit(0);
await withBrowser(async ({ browser, origin }) => {
  const page = await browser.newPage({ userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' });
  const errors = [];
  const calls = [];
  const managerRequests = [];
  const manager = {
    origin: 'https://nas.example:9443', managerId: 'manager-a', deviceId: 'device-a',
    installationId: 'library-a', expiresAt: Date.now() + 86_400_000, scopes: ['status', 'stop'],
    certificateSha256: null,
  };
  let scope = 'server-account-a';
  let admin = true;
  let summaryUnavailable = false;
  let releaseSignOut;
  const signOut = new Promise(resolve => { releaseSignOut = resolve; });
  page.on('pageerror', error => errors.push(error.message));
  await page.exposeFunction('navigationInvoke', (command, args) => {
    calls.push(command);
    if (command === 'plugin:event|listen') return 1;
    if (['discover_camera_folders', 'photo_import_history'].includes(command)) return [];
    if (command === 'local_host_status') return { backgroundActive: false };
    if (command === 'restore_connection') return {
      navigationScope: scope, server: 'https://nas.example', name: 'Pat', mode: 'client', state: 'ready',
      features: { worker: false, workerSession: false, enrollment: true, nativeHost: false, sources: false },
    };
    if (command === 'server_summary') {
      if (summaryUnavailable) throw Error('Temporary library outage');
      return { me: { isAdmin: admin } };
    }
    if (command === 'remote_status') return { remote: { enabled: false } };
    if (command === 'manager_view') return manager;
    if (command === 'manager_request') {
      managerRequests.push(args.command.kind);
      return { manager, installation: { name: 'Test library', release: '1.2.3' }, operations: [] };
    }
    if (command === 'sign_out') return signOut;
    return null;
  });
  await page.addInitScript(() => {
    globalThis.isTauri = true;
    globalThis.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} };
    globalThis.__TAURI_INTERNALS__ = { invoke: (...args) => globalThis.navigationInvoke(...args), transformCallback: () => 1 };
  });
  await page.goto(origin);
  const sidebar = page.getByRole('navigation', { name: 'Sidebar' });
  const account = sidebar.getByRole('button', { name: /Pat/ });
  const heading = name => page.getByRole('heading', { name, exact: true });
  await heading('My computer').waitFor();
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Skip to main content');
  assert.ok(await page.getByRole('link', { name: 'Skip to main content' }).evaluate(element =>
    element.getBoundingClientRect().top >= 40));
  await page.keyboard.press('Enter');
  assert.equal(await heading('My computer').evaluate(element => element === document.activeElement), true);

  await page.keyboard.press('Meta+2');
  await heading('Photo sources').waitFor();
  assert.equal(await heading('Photo sources').evaluate(element => element === document.activeElement), true);
  await page.reload();
  await heading('Photo sources').waitFor();

  await account.focus();
  await page.keyboard.press('Enter');
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Open Photos');
  await page.keyboard.press('Escape');
  assert.equal(await account.evaluate(element => element === document.activeElement), true);
  assert.equal(await account.getAttribute('aria-expanded'), 'false');

  await page.keyboard.press('Enter');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Offline Albums');
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Switch library…');
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Sign out…');
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog');
  await dialog.waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Cancel');
  await page.keyboard.press('Shift+Tab');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Sign Out');
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Cancel');
  await page.keyboard.press('Meta+1');
  await page.keyboard.press('Escape');
  await dialog.waitFor({ state: 'hidden' });
  assert.equal(await account.evaluate(element => element === document.activeElement), true);
  await heading('Photo sources').waitFor();
  assert.equal(calls.includes('sign_out'), false);

  scope = 'server-account-b';
  await page.reload();
  await heading('My computer').waitFor();
  await sidebar.getByRole('button', { name: 'AI credit' }).waitFor();
  await page.keyboard.press('Meta+7');
  await heading('AI credit').waitFor();
  await page.keyboard.press('Meta+8');
  await heading('Remote access').waitFor();
  const remoteToggle = page.getByRole('switch', { name: 'Remote access' });
  const refreshCount = calls.filter(command => command === 'server_summary').length;
  summaryUnavailable = true;
  await remoteToggle.click();
  await remoteToggle.waitFor();
  await page.waitForFunction(() => !document.querySelector('[role="switch"][aria-label="Remote access"]').disabled);
  assert.equal(calls.filter(command => command === 'server_summary').length, refreshCount + 1);
  assert.equal(await heading('Remote access').isVisible(), true);
  summaryUnavailable = false;
  admin = false;
  await page.reload();
  await heading('My computer').waitFor();
  assert.equal(await sidebar.getByRole('button', { name: 'AI credit' }).count(), 0);
  await page.keyboard.press('Meta+4');
  await heading('Test library').waitFor();
  const authorize = page.getByRole('button', { name: 'Authorize…' });
  await authorize.click();
  const password = page.getByLabel('Manager password');
  assert.equal(await password.evaluate(element => element === document.activeElement), true);
  await password.fill('disposable-test');
  await page.reload();
  await heading('Test library').waitFor();
  await authorize.waitFor();
  assert.equal(await page.getByRole('dialog').count(), 0);
  assert.equal(calls.includes('reauthenticate_manager'), false);
  assert.deepEqual(managerRequests, ['status', 'status']);

  await account.focus();
  await page.keyboard.press('Enter');
  await sidebar.getByRole('button', { name: 'Sign out…' }).click();
  await dialog.getByRole('button', { name: 'Sign Out' }).click();
  await dialog.getByRole('button', { name: 'Signing out…' }).waitFor();
  await page.keyboard.press('Escape');
  assert.equal(await dialog.isVisible(), true);
  releaseSignOut({ remoteRevoked: true, localCleared: true, photosCleared: true });
  await dialog.waitFor({ state: 'hidden' });
  assert.equal(await page.evaluate(() => localStorage.getItem('frameleaf.last-page.v1')), null);
  assert.deepEqual(calls.filter(command => command === 'sign_out'), ['sign_out']);
  assert.deepEqual(errors, []);
  process.stdout.write('Navigation UI browser flows passed: skip link, page shortcuts and restore, account menu, sign-out sheet, administrator pages.\n');
});
