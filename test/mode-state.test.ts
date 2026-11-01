import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { workerStatus, safeMode } from '../src/mode-state.ts';

test('local setup commands are registered and permitted only in the packaged main window', () => {
  const ui = readFileSync(new URL('../src/LocalHost.svelte', import.meta.url), 'utf8');
  const manifest = readFileSync(new URL('../src-tauri/build.rs', import.meta.url), 'utf8');
  const capability = JSON.parse(readFileSync(new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8'));
  const commands = [...ui.matchAll(/\binvoke(?:<[^>]+>)?\(\s*['"]([a-z_]+)['"]/g)].map(match => match[1]);
  assert.ok(commands.includes('provision_local_host_profile'));
  for (const command of commands) {
    assert.ok(manifest.includes(JSON.stringify(command)), `missing app command: ${command}`);
    assert.ok(capability.permissions.includes(`allow-${command.replaceAll('_', '-')}`), `missing permission: ${command}`);
  }
  assert.equal(capability.local, true);
  assert.deepEqual(capability.windows, ['main']);
  assert.equal(capability.remote, undefined);
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


test('memory measurement failures require a runtime update without claiming readiness', async () => {
  const { runtimeRecoveryMessage } = await import('../src/mode-state.ts');
  for (const code of ['runtime_memory_measurement_required', 'runtime_memory_measurement_invalid']) {
    assert.match(runtimeRecoveryMessage(code)!, /updated.*runtime/i);
    assert.match(runtimeRecoveryMessage(code)!, /Photos remain available/);
  }
});


test('older qualification servers need an update while Photos remain available', async () => {
  const { runtimeRecoveryMessage } = await import('../src/mode-state.ts');
  assert.match(runtimeRecoveryMessage('desktop_worker_memory_unavailable')!, /server.*update/i);
  assert.match(runtimeRecoveryMessage('desktop_worker_memory_unavailable')!, /Photos remain available/);
});
