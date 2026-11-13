import assert from 'node:assert/strict';
import { readFile, mkdir } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { enabled, root, withBrowser } from './ui_test_support.mjs';
import { managerError } from '../src/manager-state.ts';

// Opt-in browser qualification of the Manager page: only a synthetic IPC bridge, never real Manager
// credentials or commands. Run it with `npm run test:ui`.
if (!enabled) { process.stdout.write('Manager UI browser qualification is opt-in.\n'); process.exit(0); }
// Optional: a folder that receives screenshots of the main states.
const output = process.env.FRAMELEAF_TEST_OUTPUT;
assert.ok(!output || isAbsolute(output));

const view = {
  origin: 'https://manager.test:9443', managerId: '11111111-1111-4111-8111-111111111111', deviceId: '22222222-2222-4222-8222-222222222222',
  installationId: 'aaaaaaaaaaaa', expiresAt: Date.now() + 86400000, scopes: ['status', 'start', 'stop', 'restart', 'backup'], certificateSha256: null,
};
const operationId = '33333333-3333-4333-8333-333333333333';
const snapshot = 'a'.repeat(64);
const password = 'synthetic Manager UI password';
const publicHttp = 'http://manager.example.com:2282';
const wire = JSON.parse(await readFile(join(root, 'src-tauri/src/manager_wire.json'), 'utf8'));
const makeOperation = (action, state = 'running') => ({ id: operationId, kind: action, state, step: action === 'backup' ? 'database-backup' : action, completed: state === 'complete' ? [action] : [], error: null, createdAt: Date.now(), updatedAt: Date.now() });
const allowControl = 'Allow this computer to start, stop and restart this server, and create database backups.';
const allowRecovery = 'Also allow backup recovery reviews and restore operations.';
const understandRestore = 'I understand and want to restore this database backup.';
// The hint under an http:// address: allowed at home, HTTPS for a Manager reached over the internet.
const httpHint = /^HTTP is for a Manager on this computer or your home network\..*HTTPS/;

await withBrowser(async ({ browser, origin }) => {
  if (output) await mkdir(output, { recursive: true });
  const shot = async (target, name) => { if (output) await target.screenshot({ path: join(output, name) }); };

  /** One signed-in app with a synthetic Manager behind the IPC bridge, opened on the Manager page. */
  async function fixture(scenario, run, viewport = { width: 1100, height: 1000 }, colorScheme = 'light') {
    const context = await browser.newContext({ viewport, colorScheme });
    const calls = [], keys = new Map(), errors = [];
    const unpaired = ['pair', 'pair-http', 'pair-public-http'].includes(scenario);
    let paired = !unpaired, authorized = !['reauth', 'recovery-reauth'].includes(scenario), lost = scenario === 'lost';
    let current = ['resume', 'recovery-reauth'].includes(scenario) ? makeOperation('stop', 'interrupted') : null;
    let reviewLost = scenario === 'recovery', reviewReady = false;
    const reviews = new Map(), restores = new Map();
    let restoreLost = scenario === 'recovery-restore', restored = null;
    const manager = { ...view, scopes: scenario === 'readonly' ? ['status'] : scenario.startsWith('recovery') ? [...view.scopes, 'restore'] : view.scopes };
    await context.exposeBinding('__managerInvoke', async (_source, command, args = {}) => {
      calls.push({ command, args: structuredClone(args) });
      if (command === 'plugin:event|listen') return 1;
      if (command === 'local_host_status') return { backgroundActive: false };
      if (command === 'restore_connection') return {
        navigationScope: 'server-account-a', server: 'https://photos.test', name: 'Pat', mode: 'client', state: 'ready',
        features: { worker: false, workerSession: false, enrollment: true, nativeHost: false, sources: false },
      };
      if (command === 'worker_setup_status') return { state: 'stopped', code: null, control: 'stopped', workloads: [] };
      if (command === 'server_summary') return { me: { isAdmin: false } };
      // The rest of the app shell stays idle; only Manager's own commands are scripted below.
      if (!/manager/.test(command)) return null;
      if (command === 'manager_view') return paired ? manager : null;
      if (command === 'manager_certificate_fingerprint') return wire.certificateSha256;
      if (command === 'pair_manager') {
        assert.deepEqual(Object.keys(args).sort(), ['allowManagement', 'allowRecovery', 'certificate', 'origin', 'password']);
        assert.equal(args.password, password); assert.equal(args.allowManagement, true); assert.equal(typeof args.allowRecovery, 'boolean');
        // The backend refuses plain HTTP only for a host outside this computer and the home network.
        if (args.origin === publicHttp) throw 'manager_https_required';
        if (args.allowRecovery) manager.scopes = [...view.scopes, 'restore'];
        manager.origin = new URL(args.origin).origin;
        manager.certificateSha256 = args.certificate?.sha256 || null;
        paired = true;
        return manager;
      }
      if (command === 'reauthenticate_manager') { assert.equal(args.password, password); authorized = true; return null; }
      if (command === 'disconnect_manager') { assert.equal(args.password, password); paired = false; return true; }
      if (command === 'manager_request') {
        const request = args.command;
        if (scenario === 'devicechanged' && paired) throw 'manager_device_changed';
        if (request.kind === 'status') return { manager: { id: manager.managerId, origin: manager.origin }, installation: { id: manager.installationId, name: 'Example NAS', release: 'frameleaf-v3.0.0-1', port: 2283 }, operations: current ? [current] : [] };
        if (request.kind === 'backups') { if (!authorized) throw 'manager_recent_auth_required'; assert.ok(manager.scopes.includes('restore')); return [{ id: snapshot, time: new Date().toISOString() }]; }
        if (request.kind === 'review-restore') {
          assert.ok(manager.scopes.includes('restore')); assert.equal(request.snapshot, snapshot);
          if (!reviews.has(request.key)) reviews.set(request.key, { snapshot: request.snapshot });
          if (reviewLost) { reviewLost = false; throw 'manager_response_interrupted'; }
          return { id: request.key, snapshot: request.snapshot, installationId: manager.installationId, state: 'preparing' };
        }
        if (request.kind === 'restore-review') {
          assert.ok(reviews.has(request.id)); assert.equal(request.snapshot, reviews.get(request.id).snapshot);
          return { id: request.id, snapshot: request.snapshot, installationId: manager.installationId, expires: Date.now() + 900000, state: reviewReady ? 'prepared' : 'preparing', ...(reviewReady ? { libraryId: manager.installationId, release: 'frameleaf-v3.0.0-1', targetRelease: 'frameleaf-v3.0.0-1', createdAt: Date.now() - 86400000, mediaIncluded: false, requiresRuntimeChange: false } : {}) };
        }
        if (request.kind === 'restore') {
          if (!authorized) throw 'manager_recent_auth_required'; assert.ok(reviews.has(request.reviewId));
          if (scenario === 'recovery-restore-expired') throw 'native_restore_review_expired';
          if (!restores.has(request.key)) { restored = { ...makeOperation('restore'), step: 'native-restore-verify' }; restores.set(request.key, restored); }
          if (restoreLost) { restoreLost = false; throw 'manager_response_interrupted'; }
          return { id: restored.id };
        }
        if (request.kind === 'restore-operation') { if (!authorized) throw 'manager_recent_auth_required'; assert.equal(request.id, restored.id); return restored; }
        if (request.kind === 'resume-restore') { if (!authorized) throw 'manager_recent_auth_required'; assert.equal(request.id, restored.id); restored = { ...restored, state: 'running', error: null }; return { id: restored.id }; }
        if (request.kind === 'control') {
          if (!authorized) throw 'manager_recent_auth_required';
          if (!keys.has(request.key)) { current = makeOperation(request.action); keys.set(request.key, current); }
          if (lost) { lost = false; throw 'manager_unreachable_or_certificate_invalid'; }
          return { id: keys.get(request.key).id };
        }
        if (request.kind === 'operation') { assert.equal(request.id, operationId); return current; }
        if (request.kind === 'resume') { assert.equal(request.id, operationId); current = { ...current, state: 'running' }; return { id: operationId }; }
      }
      throw Error(`Unexpected fixture command: ${command} ${JSON.stringify(args)}`);
    });
    await context.addInitScript(() => {
      globalThis.isTauri = true;
      globalThis.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} };
      globalThis.__TAURI_INTERNALS__ = { invoke: (command, args) => globalThis.__managerInvoke(command, args), transformCallback: () => 1 };
    });
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    try {
      await page.goto(origin, { waitUntil: 'networkidle' });
      await page.getByRole('navigation', { name: 'Sidebar' }).getByRole('button', { name: 'Manager' }).click();
      // The page is a landmark named by its title: the library once Manager answers, else a fixed title.
      const title = unpaired ? 'Server management' : scenario === 'devicechanged' ? 'Manager' : 'Example NAS';
      const ui = page.getByRole('region', { name: title });
      await ui.getByRole('heading', { name: title, exact: true, level: 1 }).waitFor();
      await run({
        page, ui, calls, keys, reviews, restores, dialog: page.getByRole('dialog'),
        operation: ui.locator('[aria-label="Manager operation"]'),
        restoreProgress: ui.locator('[aria-label="Database restore progress"]'),
        stored: () => page.evaluate(() => JSON.stringify(localStorage)),
        finishRestore: () => { restored = { ...restored, state: 'complete', step: 'native-restore-started', completed: ['native-restore-started'], updatedAt: Date.now() }; },
        interruptRestore: () => { restored = { ...restored, state: 'interrupted' }; authorized = false; },
        finishReview: () => { reviewReady = true; },
        loseNext: () => { lost = true; },
        finish: () => { current = { ...current, state: 'complete', completed: [current.kind], updatedAt: Date.now() }; },
      });
      assert.deepEqual(errors, []);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'horizontal overflow');
    } catch (error) {
      error.message = `Manager UI scenario “${scenario}”: ${error.message}`;
      throw error;
    } finally { await context.close(); }
  }
  const button = (scope, name) => scope.getByRole('button', { name, exact: true });
  const controls = scope => scope.filter(value => value.command === 'manager_request' && value.args.command.kind === 'control');
  const requests = (calls, ...kinds) => calls.filter(value => value.command === 'manager_request' && kinds.includes(value.args.command.kind));

  // A changed device key blocks every action and offers only removing the pairing.
  await fixture('devicechanged', async ({ page, ui, dialog, calls }) => {
    await dialog.getByRole('heading', { name: 'Disconnect Manager?' }).waitFor();
    assert.equal(await ui.getByRole('alert').innerText().then(text => text.includes(managerError('manager_device_changed'))), true);
    for (const name of ['Start', 'Stop', 'Restart', 'Back up', 'Authorize…']) assert.ok(await button(ui, name).isDisabled(), name);
    await dialog.getByLabel('Manager password', { exact: true }).fill(password);
    await button(dialog, 'Remove Pairing').click();
    await button(page.getByRole('region', { name: 'Server management' }), 'Pair with Manager').waitFor();
    assert.equal(calls.filter(value => value.command === 'disconnect_manager').length, 1);
    assert.equal(calls.filter(value => value.command === 'reauthenticate_manager').length, 0);
  });

  // HTTPS with a private certificate: pairing waits for the fingerprint of exactly the pasted certificate.
  await fixture('pair', async ({ page, ui, calls, stored }) => {
    await ui.getByLabel('Manager address').fill(view.origin);
    await ui.getByLabel('Manager password', { exact: true }).fill(password);
    const pair = button(ui, 'Pair with Manager'); assert.ok(await pair.isDisabled());
    await ui.getByLabel(allowControl).check();
    await ui.getByLabel(allowRecovery).check();
    await ui.getByLabel('Use a certificate for a private Manager').check();
    await ui.getByLabel('Public certificate', { exact: true }).fill(wire.certificatePem);
    assert.ok(await pair.isDisabled());
    await button(ui, 'Review certificate fingerprint').click();
    await ui.getByText(wire.certificateSha256, { exact: true }).waitFor();
    await ui.getByLabel('I verified this certificate fingerprint.').check(); assert.ok(await pair.isEnabled());
    await ui.getByLabel('Public certificate', { exact: true }).fill(wire.certificatePem + '\n'); assert.ok(await pair.isDisabled());
    await button(ui, 'Review certificate fingerprint').click();
    await ui.getByLabel('I verified this certificate fingerprint.').check();
    await shot(ui, 'manager-pair-certificate.png');
    await pair.click();
    const paired = page.getByRole('region', { name: 'Example NAS' });
    await paired.getByText('Manager access', { exact: true }).waitFor();
    const request = calls.find(value => value.command === 'pair_manager');
    assert.equal(request.args.certificate.sha256, wire.certificateSha256); assert.equal(request.args.allowRecovery, true);
    assert.ok(!(await page.textContent('body')).includes(password));
    assert.ok(!(await stored()).includes(password));
  });

  // Plain HTTP pairs with a Manager on this computer or the home network, without a certificate step.
  for (const address of ['http://tower.local:2282', 'http://192.168.1.10:2282', 'http://nas:2282', 'http://127.0.0.1:2282']) await fixture('pair-http', async ({ page, ui, calls }) => {
    await ui.getByLabel('Manager address').fill(view.origin);
    await ui.getByLabel('Use a certificate for a private Manager').check();
    await ui.getByLabel('Public certificate', { exact: true }).fill(wire.certificatePem);
    await ui.getByLabel('Manager address').fill(address);
    await ui.getByText(httpHint).waitFor();
    assert.equal(await ui.getByLabel('Public certificate', { exact: true }).count(), 0);
    await ui.getByLabel('Manager password', { exact: true }).fill(password);
    const pair = button(ui, 'Pair with Manager'); assert.ok(await pair.isDisabled());
    await ui.getByLabel(allowControl).check();
    assert.ok(await pair.isEnabled(), `${address} must be allowed to pair over HTTP`);
    await pair.click();
    await page.getByRole('region', { name: 'Example NAS' }).getByText('HTTP · unencrypted', { exact: true }).waitFor();
    const request = calls.find(value => value.command === 'pair_manager');
    assert.equal(request.args.origin, address);
    assert.equal(request.args.certificate, null);
  });

  // Plain HTTP to a public host: the backend refuses it and the form says to use HTTPS.
  await fixture('pair-public-http', async ({ page, ui, calls }) => {
    await ui.getByLabel('Manager address').fill(publicHttp);
    await ui.getByText(httpHint).waitFor();
    await ui.getByLabel('Manager password', { exact: true }).fill(password);
    await ui.getByLabel(allowControl).check();
    await button(ui, 'Pair with Manager').click();
    const alert = ui.getByRole('alert');
    await alert.waitFor();
    assert.ok((await alert.innerText()).includes(managerError('manager_https_required')));
    assert.match(managerError('manager_https_required'), /HTTPS/);
    await button(ui, 'Pair with Manager').waitFor();
    assert.equal(await page.getByRole('region', { name: 'Example NAS' }).count(), 0);
    assert.equal(calls.filter(value => value.command === 'pair_manager').length, 1);
    assert.equal(await ui.getByLabel('Manager password', { exact: true }).inputValue(), '');
    assert.ok(!(await page.textContent('body')).includes(password));
  });

  // A lost reply keeps the request and retries it with its original key, across a reload.
  await fixture('lost', async ({ page, ui, dialog, operation, calls, keys, finish, loseNext, stored }) => {
    await button(ui, 'Start').click();
    await button(operation, 'Retry').waitFor();
    const original = controls(calls)[0].args.command.key;
    await page.reload({ waitUntil: 'networkidle' });
    await button(operation, 'Retry').click();
    await operation.getByRole('status').getByText('In progress', { exact: true }).waitFor();
    const retried = controls(calls); assert.equal(retried.length, 2); assert.equal(retried[1].args.command.key, original); assert.equal(keys.size, 1);
    assert.ok(await button(ui, 'Start').isDisabled());
    await shot(ui, 'manager-operation.png');
    finish(); await button(operation, 'Check').click();
    await operation.getByRole('status').getByText('Completed', { exact: true }).waitFor();
    assert.ok(await button(ui, 'Start').isEnabled());
    assert.ok(!(await stored()).includes(original));
    loseNext();
    await button(ui, 'Stop').click();
    await button(dialog, 'Stop Server').click();
    await button(operation, 'Retry').waitFor();
    await operation.getByText('Request outcome has not been confirmed', { exact: true }).waitFor();
    assert.equal(await operation.getByText('Completed', { exact: true }).count(), 0);
  });

  // Stop asks for confirmation first; a Manager that wants a recent sign-in gets the same request again.
  await fixture('reauth', async ({ page, ui, dialog, operation, calls }) => {
    await button(ui, 'Stop').click();
    await dialog.getByRole('heading', { name: 'Stop “Example NAS”?' }).waitFor();
    assert.equal(controls(calls).length, 0);
    await button(dialog, 'Cancel').click();
    await dialog.waitFor({ state: 'hidden' });
    assert.equal(controls(calls).length, 0);
    await button(ui, 'Stop').click(); await button(dialog, 'Stop Server').click();
    await dialog.getByRole('heading', { name: 'Authorize Manager actions' }).waitFor();
    await dialog.getByLabel('Manager password', { exact: true }).fill(password);
    await button(dialog, 'Authorize and Continue').click();
    await operation.getByRole('status').getByText('In progress', { exact: true }).waitFor();
    const sent = controls(calls); assert.equal(sent.length, 2); assert.equal(sent[0].args.command.key, sent[1].args.command.key);
    assert.equal(sent[0].args.command.action, 'stop');
    assert.ok(!(await page.textContent('body')).includes(password));
  });

  // An interrupted operation resumes; disconnecting revokes the pairing and returns to the pairing form.
  await fixture('resume', async ({ page, ui, dialog, operation, calls, finish }) => {
    await operation.getByRole('status').getByText('Interrupted', { exact: true }).waitFor();
    await button(operation, 'Resume').click();
    await operation.getByRole('status').getByText('In progress', { exact: true }).waitFor();
    assert.equal(requests(calls, 'resume').length, 1);
    finish(); await button(operation, 'Check').click();
    await operation.getByRole('status').getByText('Completed', { exact: true }).waitFor();
    await button(ui, 'Disconnect…').click();
    await dialog.getByLabel('Manager password', { exact: true }).fill(password);
    await button(dialog, 'Remove Pairing').click();
    await button(page.getByRole('region', { name: 'Server management' }), 'Pair with Manager').waitFor();
    assert.equal(calls.filter(value => value.command === 'disconnect_manager').length, 1);
  });

  // Status-only access disables every action, at the smallest window size and in dark mode.
  await fixture('readonly', async ({ ui }) => {
    for (const name of ['Start', 'Stop', 'Restart', 'Back up']) assert.ok(await button(ui, name).isDisabled(), name);
    await ui.getByText('Status only', { exact: true }).waitFor();
    await shot(ui, 'manager-narrow-dark.png');
  }, { width: 900, height: 640 }, 'dark');

  // Nothing is sent when the request receipt cannot be saved first.
  await fixture('paired', async ({ page, ui, calls }) => {
    await page.evaluate(() => { Storage.prototype.setItem = function () { throw new DOMException('synthetic storage failure', 'QuotaExceededError'); }; });
    await button(ui, 'Start').click();
    assert.ok((await ui.getByRole('alert').innerText()).includes(managerError('manager_local_state_unavailable')));
    assert.equal(controls(calls).length, 0);
  });

  const reviewsTable = ui => ui.locator('[aria-label="Database backup reviews"]');
  // A backup review keeps its request key across a lost reply and a reload, and can be abandoned.
  await fixture('recovery', async ({ page, ui, calls, reviews, finishReview, stored }) => {
    const table = reviewsTable(ui);
    await button(ui, 'Load backups').click();
    await button(table, 'Review').click();
    await button(table, 'Check review').waitFor();
    const original = requests(calls, 'review-restore')[0].args.command.key;
    assert.ok((await stored()).includes(original));
    await page.reload({ waitUntil: 'networkidle' });
    await button(table, 'Check review').click();
    await table.getByText('Backup review is in progress. Check again when ready.', { exact: true }).waitFor();
    const retries = requests(calls, 'review-restore'); assert.equal(retries.length, 2); assert.equal(retries[1].args.command.key, original); assert.equal(reviews.size, 1);
    finishReview(); await button(table, 'Check review').click();
    await table.getByText(/^Database backup verified\./).waitFor();
    assert.equal(controls(calls).length, 0);
    await shot(ui, 'manager-backup-review.png');
    await button(table, 'Choose another backup').click();
    await table.getByText('Review of backup', { exact: false }).waitFor({ state: 'detached' });
    assert.ok(!(await stored()).includes(original));
  });

  // Authorizing to load backups never resumes or repeats the interrupted server operation.
  await fixture('recovery-reauth', async ({ ui, dialog, operation, calls }) => {
    await operation.getByRole('status').getByText('Interrupted', { exact: true }).waitFor();
    await button(ui, 'Load backups').click();
    await dialog.getByLabel('Manager password', { exact: true }).fill(password);
    await button(dialog, 'Authorize and Review').click();
    await button(reviewsTable(ui), 'Review').waitFor();
    assert.equal(requests(calls, 'resume', 'control').length, 0);
  });

  await fixture('recovery-storage', async ({ page, ui, calls }) => {
    await button(ui, 'Load backups').click();
    await button(reviewsTable(ui), 'Review').waitFor();
    await page.evaluate(() => { Storage.prototype.setItem = function () { throw new DOMException('synthetic storage failure', 'QuotaExceededError'); }; });
    await button(reviewsTable(ui), 'Review').click();
    await ui.getByRole('alert').waitFor();
    assert.equal(requests(calls, 'review-restore').length, 0);
  });

  /** Loads backups, reviews the first and opens the restore confirmation, which starts unconfirmed. */
  async function reviewed({ ui, dialog, finishReview }) {
    const table = reviewsTable(ui);
    await button(ui, 'Load backups').click();
    await button(table, 'Review').click();
    await button(table, 'Check review').waitFor();
    finishReview(); await button(table, 'Check review').click();
    await button(table, 'Restore database…').click();
    await dialog.getByRole('heading', { name: 'Restore the database for “Example NAS”?' }).waitFor();
    assert.equal(await button(dialog, 'Restore Database').isDisabled(), true);
  }
  const running = 'Database restore is running. Keep the computer and server connected.';

  // A confirmed restore keeps its own request key across a lost reply and a reload until it is finished.
  await fixture('recovery-restore', async (state) => {
    const { page, ui, dialog, restoreProgress, calls, restores, finishRestore, stored } = state;
    await reviewed(state);
    assert.equal(requests(calls, 'restore').length, 0);
    await dialog.getByLabel(understandRestore, { exact: true }).check();
    await button(dialog, 'Restore Database').click();
    await button(restoreProgress, 'Check').waitFor();
    const first = requests(calls, 'restore')[0].args.command;
    assert.notEqual(first.key, first.reviewId); assert.equal(restores.size, 1);
    await page.reload({ waitUntil: 'networkidle' });
    await button(restoreProgress, 'Check').click();
    await restoreProgress.getByText(running, { exact: false }).waitFor();
    const sent = requests(calls, 'restore'); assert.equal(sent.length, 2); assert.equal(sent[1].args.command.key, first.key); assert.equal(restores.size, 1);
    assert.equal(await button(ui, 'Start').isDisabled(), true);
    finishRestore(); await button(restoreProgress, 'Check').click();
    await restoreProgress.getByText('Manager verified the database and started the server. Check original photos and videos separately.', { exact: true }).waitFor();
    await shot(ui, 'manager-database-restore.png');
    await button(restoreProgress, 'Done with database restore').click();
    await restoreProgress.waitFor({ state: 'detached' });
    assert.ok(!(await stored()).includes(first.key));
    assert.equal(requests(calls, 'control', 'resume').length, 0);
  });

  // An interrupted restore asks for the Manager password again and resumes the same restore.
  await fixture('recovery-restore-resume', async (state) => {
    const { dialog, restoreProgress, calls, interruptRestore } = state;
    await reviewed(state);
    await dialog.getByLabel(understandRestore, { exact: true }).check();
    await button(dialog, 'Restore Database').click();
    await button(restoreProgress, 'Check').waitFor();
    interruptRestore(); await button(restoreProgress, 'Check').click();
    await dialog.getByLabel('Manager password', { exact: true }).fill(password);
    await button(dialog, 'Authorize Restore').click();
    await button(restoreProgress, 'Resume').click();
    await restoreProgress.getByText(running, { exact: false }).waitFor();
    assert.equal(requests(calls, 'restore').length, 1);
    assert.equal(requests(calls, 'resume-restore').length, 1);
    assert.equal(requests(calls, 'control', 'resume').length, 0);
  });

  await fixture('recovery-restore-storage', async (state) => {
    const { page, ui, dialog, calls } = state;
    await reviewed(state);
    await page.evaluate(() => { Storage.prototype.setItem = function () { throw new DOMException('synthetic storage failure', 'QuotaExceededError'); }; });
    await dialog.getByLabel(understandRestore, { exact: true }).check();
    await button(dialog, 'Restore Database').click();
    await ui.getByRole('alert').waitFor({ state: 'attached' });
    assert.equal(requests(calls, 'restore').length, 0);
  });

  // A review that expired before Manager accepted the restore leaves no pending restore behind.
  await fixture('recovery-restore-expired', async (state) => {
    const { ui, dialog, calls, stored } = state;
    await reviewed(state);
    await dialog.getByLabel(understandRestore, { exact: true }).check();
    await button(dialog, 'Restore Database').click();
    await ui.getByText(managerError('native_restore_review_expired'), { exact: true }).waitFor({ state: 'attached' });
    assert.ok(!(await stored()).includes('frameleaf.manager-restore:'));
    assert.equal(requests(calls, 'restore').length, 1);
  });

  process.stdout.write('Manager UI browser flows passed: device change, certificate and home-network HTTP pairing, public HTTP refusal, lost reply and reload, recent sign-in, resume and disconnect, status-only access, storage failure, backup review and database restore.\n');
});
