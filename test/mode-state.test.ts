import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
import { workerStatus, safeMode } from '../src/mode-state.ts';

test('local setup commands are registered and permitted only in the packaged main window', () => {
  const ui = readFileSync(new URL('../src/LocalHost.svelte', import.meta.url), 'utf8');
  const manifest = readFileSync(new URL('../src-tauri/build.rs', import.meta.url), 'utf8');
  const handler = readFileSync(new URL('../src-tauri/src/lib.rs', import.meta.url), 'utf8').match(/tauri::generate_handler!\[([\s\S]*?)\]/)?.[1] ?? '';
  const capability = JSON.parse(readFileSync(new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8'));
  const commands = [...ui.matchAll(/\binvoke(?:<[^>]+>)?\(\s*['"]([a-z_]+)['"]/g)].map(match => match[1]);
  assert.ok(commands.includes('provision_local_host_profile'));
  for (const command of commands) {
    assert.match(handler, new RegExp(`\\b${command}\\b`), `missing invoke handler: ${command}`);
    assert.ok(manifest.includes(JSON.stringify(command)), `missing app command: ${command}`);
    assert.ok(capability.permissions.includes(`allow-${command.replaceAll('_', '-')}`), `missing permission: ${command}`);
  }
  assert.equal(capability.local, true);
  assert.deepEqual(capability.windows, ['main']);
  assert.equal(capability.remote, undefined);
});

test('local setup names a busy port, offers a companion update and always offers a quit path', () => {
  const ui = readFileSync(new URL('../src/LocalHost.svelte', import.meta.url), 'utf8');
  assert.match(ui, /\/\^local_port_in_use_\(\\d\+\)\$\/[\s\S]{0,200}using port \$\{port\[1\]\}/);
  assert.match(ui, /value === 'host_manifest_incompatible'\) return outdatedCompanion/);
  assert.match(ui, /outdated: \{ label: 'Companion update needed'/);
  assert.match(ui, /packageCheck === 'outdated'\) && view\?\.companionPlatform\}<button[^>]*onclick=\{openDownloads\}/);
  assert.match(ui, /'native-host-exit-blocked', \(\) => \{ quitOffered = !profilePending;/);
  assert.match(ui, /quitOffered && view\?\.backgroundActive[^\n]*onclick=\{stopAndQuit\}>Stop and quit</);
  assert.match(ui, /invoke\('quit_local_host'\)/);
});

test('every invoke() in the Svelte front end names a registered, permitted command', () => {
  const { readdirSync, statSync } = require('node:fs');
  const { join } = require('node:path');
  const { fileURLToPath } = require('node:url');
  const root = fileURLToPath(new URL('../src/', import.meta.url));
  const files: string[] = [];
  const walk = (dir: string) => { for (const entry of readdirSync(dir)) { const path = join(dir, entry); if (statSync(path).isDirectory()) walk(path); else if (path.endsWith('.svelte')) files.push(path); } };
  walk(root);
  const manifest = readFileSync(new URL('../src-tauri/build.rs', import.meta.url), 'utf8');
  const handler = readFileSync(new URL('../src-tauri/src/lib.rs', import.meta.url), 'utf8').match(/tauri::generate_handler!\[([\s\S]*?)\]/)?.[1] ?? '';
  const main = JSON.parse(readFileSync(new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8'));
  const offline = JSON.parse(readFileSync(new URL('../src-tauri/capabilities/offline-photos.json', import.meta.url), 'utf8'));
  const offlineComponent = join(root, 'OfflinePhotos.svelte');
  assert.equal(offline.local, true);
  assert.deepEqual(offline.windows, ['photos']);
  assert.equal(offline.remote, undefined);
  const commands = new Set<string>();
  for (const file of files) {
    const localOffline = file === offlineComponent;
    const capability = localOffline ? offline : main;
    for (const match of readFileSync(file, 'utf8').matchAll(/\binvoke(?:<[^>]+>)?\(\s*['"]([a-z_]+)['"]/g)) {
      const command = match[1]!;
      const permission = `allow-${command.replaceAll('_', '-')}`;
      commands.add(command);
      assert.match(handler, new RegExp(`\\b${command}\\b`), `missing invoke handler: ${command}`);
      assert.ok(manifest.includes(JSON.stringify(command)), `missing app command: ${command}`);
      assert.ok(capability.permissions.includes(permission), `missing permission: ${command}`);
      assert.ok(!(localOffline ? main : offline).permissions.includes(permission), `permission shared across windows: ${command}`);
    }
  }
  for (const expected of ['discover_servers', 'server_summary', 'cloud_status', 'wallet_status', 'update_wallet', 'remote_status', 'update_remote', 'test_remote_access', 'open_external', 'tray_refresh', 'cloud_sign_in', 'cloud_account', 'cloud_sign_out', 'cloud_servers', 'connect_cloud_server', 'offline_album_status']) {
    assert.ok(commands.has(expected), `front end never calls ${expected}`);
  }
});

test('persisted modes reject unknown values without treating them as hosting', () => {
  assert.equal(safeMode('local-server'), 'local-server');
  assert.equal(safeMode('client-worker'), 'client-worker');
  assert.equal(safeMode(''), null);
  assert.equal(safeMode('host'), null);
});
test('enrollment never implies qualified inference', () => {
  assert.equal(workerStatus({ state:'preparing', workerSupported:false }), 'Your server needs a desktop-worker update');
  assert.equal(workerStatus({ state:'awaiting-approval', workerSupported:false }), 'Waiting for administrator approval');
  assert.equal(workerStatus({ state:'preparing', workerSupported:true }), 'Preparing this computer');
  assert.equal(workerStatus({ state:'incompatible', workerSupported:true }), 'This computer is not compatible with the selected models');
});

test('worker credential setup failure stays visible before model qualification', () => {
  assert.equal(workerStatus({ state: 'worker-setup-failed', workerSupported: false }), 'Computer setup needs attention');
});

test('automatic runtime and model qualification never claim active processing', () => {
  for (const [state, expected] of [
    ['preparing-runtime', 'Preparing the AI runtime'],
    ['preparing-models', 'Preparing selected models'],
    ['model-download-required', 'Selected models need downloading'],
    ['qualifying', 'Checking this computer’s models'],
    ['qualified', 'Models qualified'],
    ['paused', 'AI processing paused'],
    ['setup-needs-attention', 'Computer setup needs attention'],
    ['no-eligible-work', 'No AI work is assigned to this computer'],
  ]) assert.equal(workerStatus({ state: state!, workerSupported: false }), expected);
});

test('serial worker reports startup and waiting without claiming active inference', () => {
  assert.equal(workerStatus({ state: 'starting-worker', workerSupported: false }), 'Starting this computer’s AI worker');
  assert.equal(workerStatus({ state: 'working', workerSupported: false }), 'Checking for AI work');
  assert.equal(workerStatus({ state: 'waiting-for-work', workerSupported: false }), 'Waiting for AI work');
});


test('user drain and immediate stop remain visible without claiming processing', () => {
  assert.equal(workerStatus({ state: 'pausing', workerSupported: false }), 'Finishing the current task');
  assert.equal(workerStatus({ state: 'stopped', workerSupported: false }), 'AI processing stopped');
});


test('reconnection is visible without claiming current inference or acceleration', () => {
  assert.equal(workerStatus({ state: 'reconnecting', workerSupported: false }), 'Reconnecting to your server');
});

test('runtime history failures explain recovery without suggesting a network retry', async () => {
  const { runtimeRecoveryMessage } = await import('../src/mode-state.ts');
  for (const code of ['runtime_epoch_credential_missing', 'runtime_epoch_identity_changed', 'runtime_epoch_recovery_required', 'runtime_epoch_record_invalid', 'runtime_epoch_binding_invalid', 'runtime_epoch_identity_invalid']) {
    assert.match(runtimeRecoveryMessage(code)!, /recovery/i);
    assert.match(runtimeRecoveryMessage(code)!, /Photos remain available/);
    assert.doesNotMatch(runtimeRecoveryMessage(code)!, /network|sign out|delete|reset/i);
  }
  for (const code of ['runtime_epoch_rollback', 'runtime_epoch_reused']) {
    assert.match(runtimeRecoveryMessage(code)!, /runtime was rejected/i);
    assert.match(runtimeRecoveryMessage(code)!, /Photos remain available/);
  }
  assert.equal(runtimeRecoveryMessage(null), null);
  assert.equal(runtimeRecoveryMessage('server_unreachable'), null);
  assert.equal(runtimeRecoveryMessage('runtime_epoch_unknown'), null);
});
