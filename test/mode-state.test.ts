import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
import { workerStatus, safeMode } from '../src/mode-state.ts';
import { errorCopy } from '../src/errors.ts';

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
  assert.match(ui, /quitOffered && view\?\.backgroundActive[^\n]*onclick=\{\(\) => stopAndQuit\(\)\}>Stop and quit</);
  assert.match(ui, /invoke\('quit_local_host', \{ leaveRunning \}\)/);
  // A Manager that will not stop must not make the app unquittable again.
  // Both quit buttons follow the backend: no local flag can outlive what it allows.
  assert.doesNotMatch(ui, /leaveOffered/);
  assert.match(ui, /view\?\.leaveAvailable && view\.backgroundActive[^\n]*onclick=\{\(\) => stopAndQuit\(true\)\}>Quit anyway</);
  assert.match(ui, /String\(error\) === 'native_manager_shutdown_unconfirmed' && current\?\.leaveAvailable \?/);
  assert.match(ui, /if \(!value\.backgroundActive\) quitOffered = false;/);
  const backend = readFileSync(new URL('../src-tauri/src/host_setup.rs', import.meta.url), 'utf8');
  assert.match(backend, /view\.leave_available\s*=\s*cfg!\(unix\)\s*&& view\.background_active\s*&& self\.exit_stop_failed\.load/);
  // The update message comes from the shared copy, not a second wording in App.svelte.
  const app = readFileSync(new URL('../src/App.svelte', import.meta.url), 'utf8');
  assert.doesNotMatch(app, /did not shut down cleanly/);
  assert.match(app, /error === 'update_library_not_idle'\s+\? errorCopy\('update_library_not_idle'\)/);
  // The offer promises an attempt, and a Manager that cannot be recorded keeps the app open.
  assert.match(ui, /Frameleaf will try to stop it the next time it opens/);
  assert.match(errorCopy('native_manager_record_unavailable')!, /Frameleaf is staying open/);
  // The screen keeps only the wording that differs here; everything else is the shared copy.
  assert.doesNotMatch(ui, /value === 'host_upgrade_downgrade_refused'|startsWith\('host_controller_'\)/);
  assert.match(ui, /if \(value\.startsWith\('credential_'\)\) return 'Unlock your computer’s secure credential store and try again\.';/);
  // Failures are announced, shown with more than colour, rendered through ErrorText and tied to the quit controls.
  assert.match(ui, /<Icon name="warn" \/><\/span><p id="local-host-failure" class="danger-text" role="alert"[^>]*><ErrorText text=\{failure\} \/>/);
  assert.match(ui, /aria-label="Stop local management and quit Frameleaf" aria-describedby=\{describedBy\} bind:this=\{quitButton\}/);
  assert.match(ui, /aria-label="Quit Frameleaf and leave local management running" aria-describedby=\{describedBy\} bind:this=\{leaveButton\}/);
  // A certificate about to expire is announced with its days, and an expired one says so.
  assert.match(ui, /\{#if view\?\.certificateExpiresInDays\}[\s\S]{0,200}role="status"><b>Local Manager’s security certificate expires in \{view\.certificateExpiresInDays\}/);
  assert.match(errorCopy('native_tls_identity_expired')!, /certificate on this computer has expired/);
  // A Manager that accepts a renewed certificate is renewed at the next start: the notice says that, not "update".
  assert.match(ui, /\{view\.certificateRenewable \? 'Frameleaf renews it the next time local management starts[^']*' : 'After that, local management on this computer will not start until the certificate is renewed/);
  // Photos say why they did not open: still starting, paused for a backup or restore, or not running.
  assert.match(errorCopy('local_photos_starting')!, /still starting/);
  assert.match(errorCopy('local_photos_maintenance')!, /paused while a backup or restore finishes/);
  for (const code of ['local_manager_record_unreadable', 'local_manager_record_unavailable'])
    assert.match(errorCopy(code)!, /where this library’s local Manager listens[\s\S]*have not been changed/, code);
  // Focus follows a new state: the offered quit button, and the heading when the stopped control goes.
  assert.match(ui, /if \(quitOffered\) focusOn\(\(\) => quitButton\);/);
  assert.match(ui, /if \(!view\?\.backgroundActive\) focusOn\(\(\) => title\);/);
  assert.match(ui, /<h2 class="group-title" tabindex="-1" bind:this=\{title\}>/);
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

const card = async (setup: { state: string; code?: string | null; control?: string; activeWorkload?: string | null; completedTasks?: number } | null, connectionState = 'preparing') => {
  const { workerView } = await import('../src/mode-state.ts');
  return workerView({ connectionState, workerSupported: true, computer: 'Mac', setup });
};

test('each worker failure family shows its own reason and the action that fixes it', async () => {
  const families: [code: string, headline: RegExp, detail: RegExp][] = [
    ['model_file_write_failed', /could not be saved/, /disk is full.*Free up disk space.*Retry Setup/],
    ['runtime_store_write_failed', /could not be saved/, /Free up disk space/],
    ['model_download_hash_mismatch', /model download failed/, /Check your connection.*Retry Setup/],
    ['server_response_interrupted', /did not answer/, /home network.*Retry Setup/],
    ['workload_desktop_pool_route_changed', /not shared with this computer/, /server’s owner.*machine learning settings/],
    ['server_http_401', /no longer accepts this computer/, /removed from your server.*Signing out will not fix this/],
    ['runtime_manifest_invalid', /runtime is missing/, /Install Frameleaf again.*Retry Setup/],
    ['runtime_start_failed', /runtime could not start/, /Quit and reopen Frameleaf.*Retry Setup/],
    ['worker_no_qualified_workloads', /did not pass the model checks/, /Retry Setup/],
    ['worker_lease_invalid', /out of step/, /Update Frameleaf and your server/],
    ['worker_session_required', /setting up again/, /Sign out and sign in again/],
    ['credential_store_locked_or_unavailable', /Unlock your credential store/, /Unlock.*Retry Setup/],
    ['runtime_epoch_rollback', /needs recovery/, /runtime was rejected/],
  ];
  const generic = await card({ state: 'setup-needs-attention', code: 'brand_new_backend_code' });
  const seen = new Set<string>();
  for (const [code, headline, detail] of families) {
    const view = await card({ state: 'setup-needs-attention', code });
    assert.match(view.headline, headline, code);
    assert.match(view.detail, detail, code);
    assert.equal(view.attention, 'needs-you', code);
    assert.equal(view.action, 'retry-setup', code);
    assert.deepEqual(view.pill, { label: 'Needs you', tone: 'bad' }, code);
    assert.equal(view.reference, null, code);
    assert.notEqual(view.detail, generic.detail, code);
    seen.add(view.headline);
  }
  assert.equal(seen.size, 12, 'the two storage codes share a headline; every other family has its own');
  // A build without a runtime cannot be repaired by reinstalling it, and says so.
  assert.equal((await card({ state: 'setup-needs-attention', code: 'runtime_pack_unavailable' })).detail, 'This build does not include a signed AI runtime yet. Photos remain available.');
});

test('a Windows update stops the library itself, and says why when that cannot be proven', () => {
  const updates = readFileSync(new URL('../src-tauri/src/updates.rs', import.meta.url), 'utf8');
  const install = updates.slice(updates.indexOf('async fn install_desktop_update'));
  // Windows: download, stop in order, take the gate, install. Elsewhere the gate comes first, as before.
  assert.match(install, /#\[cfg\(not\(windows\)\)\]\s*let _owner = host\.lock_for_update\(\)\?;[\s\S]*\.download\([\s\S]*#\[cfg\(windows\)\]\s*let _owner = \{\s*host\s*\.stop_for_update\(\)\s*\.await\s*\.map_err\(stop_refused\)\?;\s*host\.lock_for_update\(\)\?\s*\};[\s\S]*update\.install\(bytes\)/);
  // The stop is the orderly one, which needs the journal's idle proof, and it opens no gate by itself.
  const host = readFileSync(new URL('../src-tauri/src/host_setup.rs', import.meta.url), 'utf8');
  assert.match(host, /pub\(crate\) async fn stop_for_update\(&self\) -> Result<\(\), String> \{\s*self\.stop_proven\(true\)\.await\.map\(\|_\| \(\)\)\s*\}/);
  // The reason is shown with what it prevented, in the shared copy.
  const copy = errorCopy('update_library_stop_manager_pairing_required')!;
  assert.match(copy, /^Frameleaf did not install the update, because your library on this computer could not be stopped first\. /);
  assert.ok(copy.endsWith(errorCopy('manager_pairing_required')!));
  assert.match(errorCopy('update_library_stop_brand_new_reason')!, /Stop the photo server in Manager, then update Frameleaf\.$/);
  const app = readFileSync(new URL('../src/App.svelte', import.meta.url), 'utf8');
  assert.match(app, /error\.startsWith\('update_library_stop_'\)\s+\? errorCopy\(error\)/);
});

test('a macOS older than the AI runtime needs is a needs-you state with the declared version and no retry', async () => {
  const declared = JSON.parse(readFileSync(new URL('../packaging/macos/minimum-versions.json', import.meta.url), 'utf8')) as { app: string; aiRuntime: string };
  const version = declared.aiRuntime.replace(/\.0$/, '');
  assert.match(version, /^\d+(?:\.\d+)?$/);
  assert.equal(errorCopy('runtime_os_unsupported'), `AI processing needs macOS ${version} or later. Photos remain available.`);
  const view = await card({ state: 'setup-needs-attention', code: 'runtime_os_unsupported' });
  assert.equal(view.headline, 'This Mac’s macOS is too old for AI processing');
  assert.equal(view.detail, errorCopy('runtime_os_unsupported'));
  assert.equal(view.attention, 'needs-you');
  assert.equal(view.action, null, 'retrying cannot change the macOS version');
  assert.deepEqual(view.pill, { label: 'Needs you', tone: 'bad' });
  assert.equal(view.reference, null);
  // The backend reads the same declaration, and refuses before it prepares anything.
  const backend = readFileSync(new URL('../src-tauri/src/worker_setup.rs', import.meta.url), 'utf8');
  assert.match(backend, /include_str!\(\s*"\.\.\/\.\.\/packaging\/macos\/minimum-versions\.json"\s*\)/);
  assert.doesNotMatch(backend.slice(0, backend.indexOf('#[cfg(test)]')), /\(15,\s*0\)|"15(?:\.0)?"/);
  assert.match(backend, /runtime_os_supported\(macos, ai_runtime_macos_floor\(\)\)\?;\s*progress\.update\(\|status\| status\.models = None\);\s*progress\.set\(\s*"preparing-runtime"/);
});

test('memory, power and network pauses wait by themselves and say what they wait for', async () => {
  for (const [code, headline, detail] of [
    ['memory_low', 'Waiting for free memory', /enough memory.*continues by itself/],
    ['on_battery', 'Waiting for power', /Plug in this computer/],
    ['metered_network', 'Waiting for an unmetered network', /metered networks/],
    ['system_resumed', 'Rechecking after sleep', /Rechecking the selected models/],
  ] as const) {
    const view = await card({ state: 'paused', code });
    assert.equal(view.headline, headline);
    assert.match(view.detail, detail);
    assert.equal(view.attention, 'waiting');
    assert.equal(view.action, null);
    assert.deepEqual(view.pill, { label: 'Waiting', tone: 'wait' });
  }
  // Paused by the person is a choice, not a wait: with the code, and after reopening without one.
  for (const setup of [{ state: 'paused', code: 'user_paused', control: 'paused' }, { state: 'paused', code: null, control: 'paused' }]) {
    const view = await card(setup);
    assert.equal(view.attention, 'none');
    assert.match(view.detail, /Paused by you/);
    assert.deepEqual(view.pill, { label: 'Paused', tone: 'off' });
  }
});

test('the same failure reads as waiting while the worker retries and as needs-you once it gave up', async () => {
  for (const code of ['server_unreachable_or_certificate_invalid', 'model_download_interrupted', 'worker_lease_expired', 'runtime_process_stopped', 'server_http_503']) {
    const waiting = await card({ state: 'reconnecting', code });
    const stopped = await card({ state: 'setup-needs-attention', code });
    assert.equal(waiting.attention, 'waiting', code);
    assert.equal(waiting.action, null, code);
    assert.match(waiting.detail, /by itself/, code);
    assert.equal(stopped.attention, 'needs-you', code);
    assert.equal(stopped.action, 'retry-setup', code);
    assert.notEqual(waiting.headline, stopped.headline, code);
    assert.notEqual(waiting.detail, stopped.detail, code);
    assert.notDeepEqual(waiting.pill, stopped.pill, code);
  }
  assert.match((await card({ state: 'reconnecting', code: 'server_unreachable_or_certificate_invalid' })).detail, /home network/);
  const unassigned = await card({ state: 'no-eligible-work', code: 'worker_no_eligible_workloads' });
  assert.equal(unassigned.attention, 'waiting');
  assert.match(unassigned.detail, /server administrator.*checks again every few minutes/);
  const download = await card({ state: 'model-download-required', code: 'model_download_permission_required' });
  assert.deepEqual([download.attention, download.action], ['needs-you', 'download-models']);
  const approval = await card(null, 'awaiting-approval');
  assert.deepEqual([approval.attention, approval.action], ['needs-you', 'check-approval']);
  const offline = await card(null, 'offline');
  assert.deepEqual([offline.headline, offline.attention, offline.action], ['Server unavailable', 'needs-you', 'check-server']);
  assert.match(offline.detail, /home network.*Check Again/);
});

test('a worker failure with no copy shows the generic setup message and the code as a reference', async () => {
  const view = await card({ state: 'setup-needs-attention', code: 'brand_new_backend_code' });
  assert.equal(view.headline, 'Computer setup needs attention');
  assert.equal(view.detail, 'AI setup could not finish. Photos remain available. Retry setup when your server and network are ready.');
  assert.equal(view.reference, 'brand_new_backend_code');
  assert.equal(view.action, 'retry-setup');
  // A code with copy but no family still shows that copy, with no reference.
  const known = await card({ state: 'setup-needs-attention', code: 'model_file_changed' });
  assert.match(known.detail, /changed or could not be read/);
  assert.equal(known.reference, null);
});

test('the card says working only while a task runs, and counts finished tasks', async () => {
  // The backend sets 'working' while it asks for a task; only activeWorkload means one is running.
  for (const state of ['working', 'waiting-for-work']) {
    const idle = await card({ state, code: null, completedTasks: 0 });
    assert.equal(idle.headline, 'Waiting for AI work');
    assert.deepEqual(idle.pill, { label: 'Idle', tone: 'ok' });
    assert.equal(idle.finished, '0 tasks finished since AI processing last started');
  }
  const busy = await card({ state: 'working', code: null, activeWorkload: 'ocr', completedTasks: 1 });
  assert.equal(busy.headline, 'Processing on this computer');
  assert.deepEqual(busy.pill, { label: 'Working', tone: 'ok' });
  assert.equal(busy.finished, '1 task finished since AI processing last started');
  assert.equal((await card({ state: 'working', completedTasks: 1234 })).finished, `${(1234).toLocaleString()} tasks finished since AI processing last started`);
  // An older backend, or a bad value, shows no count rather than a wrong one.
  for (const completedTasks of [undefined, -1, 1.5, Number.NaN]) assert.equal((await card({ state: 'working', completedTasks })).finished, null);
  assert.deepEqual((await card({ state: 'preparing-models' })).pill, { label: 'Setting up', tone: 'wait' });
  assert.deepEqual((await card({ state: 'stopped', control: 'stopped' })).pill, { label: 'Stopped', tone: 'off' });
});

test('no worker card text shows a raw code or state name', async () => {
  const states = ['', 'preparing', 'preparing-runtime', 'preparing-models', 'model-download-required', 'qualifying', 'qualified', 'starting-worker', 'working', 'waiting-for-work', 'reconnecting', 'pausing', 'stopped', 'paused', 'setup-needs-attention', 'no-eligible-work', 'awaiting-approval', 'worker-setup-failed', 'credential-store-unavailable', 'unsupported-server', 'incompatible'];
  const codes = [null, 'user_paused', 'memory_low', 'server_http_401', 'server_http_503', 'model_file_write_failed', 'worker_setup_failed', 'runtime_epoch_reused', 'brand_new_backend_code'];
  for (const connectionState of ['preparing', 'offline', 'identity-changed', 'enrollment-failed', 'awaiting-approval'])
    for (const state of states) for (const code of codes) {
      const view = await card(state ? { state, code } : null, connectionState);
      for (const text of [view.headline, view.detail, view.pill.label]) {
        assert.ok(text.length > 0);
        assert.doesNotMatch(text, /[a-z0-9]_[a-z0-9]/, `${connectionState}/${state}/${code}: ${text}`);
        for (const name of states) if (name.includes('-')) assert.ok(!text.includes(name), `${connectionState}/${state}/${code}: ${text}`);
      }
    }
  assert.equal((await card({ state: 'unsupported-server' })).headline, 'Your server needs a desktop-worker update');
});
