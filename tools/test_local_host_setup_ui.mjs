import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// Browser qualification uses synthetic IPC. It never installs or starts a real companion.
if (process.env.FRAMELEAF_MANAGER_UI_TEST !== '1') process.exit(0);
const { FRAMELEAF_TEST_BROWSER: executablePath, FRAMELEAF_TEST_PLAYWRIGHT: playwright } = process.env;
assert.ok((!executablePath || isAbsolute(executablePath)) && playwright && isAbsolute(playwright));
const { chromium } = await import(pathToFileURL(playwright));
const root = fileURLToPath(new URL('..', import.meta.url));
const socket = createServer();
await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
const address = socket.address();
assert.ok(address && typeof address !== 'string');
await new Promise(resolve => socket.close(resolve));
const origin = `http://127.0.0.1:${address.port}`;
const vite = spawn(process.execPath, [join(root, 'node_modules/vite/bin/vite.js'), '--host', '127.0.0.1', '--port', String(address.port), '--strictPort'], { cwd: root, stdio: ['ignore', 'pipe', 'inherit'], env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' } });
const ended = new Promise(resolve => vite.once('close', resolve));
let browser;
const installed = { manifestSha256: 'a'.repeat(64), controllerSha256: 'b'.repeat(64), version: '1.2.4', library: true };
const update = { ...installed, manifestSha256: 'c'.repeat(64), version: '1.2.5', library: false };
try {
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(Error('Vite startup timeout')), 10000);
    vite.stdout.on('data', chunk => { if (chunk.includes('Local:')) { clearTimeout(timeout); resolve(); } });
    vite.once('error', reject);
  });
  browser = await chromium.launch({ ...(executablePath ? { executablePath } : {}), headless: true, args: ['--disable-gpu'] });
  const page = await browser.newPage();
  const calls = [];
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  let packages = [];
  let compatibility = 'refused';
  let status = { state: 'idle', code: null, backgroundActive: false, installation: null, origin: null, companionPlatform: 'windows', profileSetupAvailable: true, profileRequiresAuthorization: false };
  await page.exposeFunction('hostInvoke', (command, args) => {
    calls.push({ command, args });
    if (command === 'plugin:event|listen') return 1;
    if (command === 'installed_local_hosts') return packages;
    if (command === 'local_host_status') return status;
    if (command === 'check_local_host_package') {
      assert.ok(packages.some(record => record.manifestSha256 === args.manifestSha256 &&
        record.controllerSha256 === args.controllerSha256));
      return compatibility;
    }
    if (command === 'provision_local_host_profile') {
      assert.equal(args.manifestSha256, installed.manifestSha256);
      status = { ...status, state: 'profile-ready', installation: installed };
      return status;
    }
    if (command === 'prepare_local_host') {
      assert.equal(args.manifestSha256, update.manifestSha256);
      status = { ...status, state: 'manager-ready', backgroundActive: true, installation: update };
      return status;
    }
    if (command === 'discover_servers') return [];
    return null;
  });
  await page.addInitScript(() => {
    globalThis.isTauri = true;
    globalThis.__TAURI_INTERNALS__ = { invoke: (...args) => globalThis.hostInvoke(...args), transformCallback: () => 1 };
  });
  await page.goto(origin);
  await page.getByRole('radio', { name: /Run Frameleaf here/ }).check();
  const setup = page.getByRole('region', { name: 'Local library setup' });
  await setup.getByText(/Companion Server EXE for Windows x64/).waitFor();
  await setup.getByRole('button', { name: 'Open companion downloads' }).click();
  assert.deepEqual(calls.filter(call => call.command === 'open_external'), [
    { command: 'open_external', args: { url: 'https://github.com/Frameleaf/frameleaf-desktop/releases' } },
  ]);
  assert.equal(await setup.getByRole('button', { name: 'Prepare local Manager' }).count(), 0);

  packages = [{ ...installed, library: false }];
  await setup.getByRole('button', { name: 'Check installation' }).click();
  const prepareProfile = setup.getByRole('button', { name: 'Prepare Profile' });
  await setup.getByText('Companion package refused', { exact: true }).waitFor();
  assert.ok(await prepareProfile.isDisabled());
  compatibility = 'unknown';
  await setup.getByRole('button', { name: 'Check installation' }).click();
  await setup.getByText('Compatibility unknown', { exact: true }).waitFor();
  assert.ok(await prepareProfile.isDisabled());
  assert.equal(calls.filter(call => ['provision_local_host_profile', 'prepare_local_host'].includes(call.command)).length, 0);
  compatibility = 'verified';
  await setup.getByRole('button', { name: 'Check installation' }).click();
  await setup.getByText('Companion package verified', { exact: true }).waitFor();
  assert.equal(await setup.getByRole('button', { name: 'Prepare local Manager' }).count(), 0);
  await prepareProfile.click();
  await setup.getByRole('button', { name: 'Prepare local Manager' }).waitFor();
  assert.equal(calls.filter(call => call.command === 'prepare_local_host').length, 0);

  packages = [installed, update];
  await setup.getByRole('button', { name: 'Check installation' }).click();
  const select = setup.getByLabel('Installed server package');
  assert.equal(await select.inputValue(), installed.manifestSha256);
  await select.selectOption(update.manifestSha256);
  // A backend that cannot move a library to another package: no offer to, and one press back to its own.
  await setup.getByText('Your library can’t move to this package yet', { exact: true }).waitFor();
  assert.equal(await setup.getByRole('button', { name: 'Review package change' }).count(), 0);
  await setup.getByRole('button', { name: 'Use My Library’s Package' }).click();
  await setup.getByRole('button', { name: 'Prepare local Manager' }).waitFor();
  assert.equal(await select.inputValue(), installed.manifestSha256);
  // A backend that says it can is offered the change, whatever the platform.
  status.packageChangeAvailable = true;
  await setup.getByRole('button', { name: 'Check installation' }).click();
  await select.selectOption(update.manifestSha256);
  await setup.getByRole('button', { name: 'Review package change' }).waitFor();
  // One that says nothing can only on macOS and Linux.
  delete status.packageChangeAvailable;
  status.companionPlatform = 'linux';
  await setup.getByRole('button', { name: 'Check installation' }).click();
  compatibility = 'refused';
  await select.selectOption(update.manifestSha256);
  await setup.getByText('Companion package refused', { exact: true }).waitFor();
  const review = setup.getByRole('button', { name: 'Review package change' });
  assert.ok(await review.isDisabled());
  compatibility = 'verified';
  await select.selectOption(installed.manifestSha256);
  await select.selectOption(update.manifestSha256);
  await review.click();
  const dialog = page.getByRole('dialog', { name: 'Move this library to another package?' });
  await dialog.getByText('Current Library 1.2.4 → Library 1.2.5').waitFor();
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  assert.equal(calls.filter(call => call.command === 'prepare_local_host').length, 0);
  await review.click();
  await dialog.getByRole('button', { name: 'Continue with this package' }).click();
  await setup.getByText('Local Manager is ready', { exact: true }).waitFor();
  assert.equal(calls.filter(call => call.command === 'prepare_local_host').length, 1);
  assert.deepEqual(errors, []);
  console.log('Companion compatibility, profile gating and explicit package move passed.');
} finally {
  await browser?.close();
  vite.kill();
  await ended;
}
