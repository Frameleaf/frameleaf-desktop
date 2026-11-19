// Screens that once left a person with nothing to do next, and copy that named internals instead of
// what the person can do. Each test here fails on the earlier behaviour.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { keptVerification, savedSignInState } from '../src/connection-state.ts';
import { availabilityText, backupKeyText, backupRunText, oneDriveDiscovery } from '../src/ui-state.ts';
import { workerView } from '../src/mode-state.ts';
import { errorCopy } from '../src/errors.ts';

const source = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('a kept sign-in that needs Two-Step Verification is verified on its own screen', () => {
  assert.equal(savedSignInState('verification_required'), 'needs-verification');
  // The server offers a proof this app can enter: verify here, and nothing leads with Sign out.
  for (const methods of [['totp'], ['recovery_code'], ['passkey', 'totp', 'recovery_code']]) {
    assert.deepEqual(keptVerification({ transaction: 'txn', methods }, true), { verifyHere: true, signOutFirst: false, hint: '' });
  }
  // Only a Passkey, which this app cannot use: the Verify prompt explains, and Sign out leads.
  assert.deepEqual(keptVerification({ transaction: 'txn', methods: ['passkey'] }, true), { verifyHere: false, signOutFirst: true, hint: '' });
  // The server gave nothing to verify with: say how to carry on, and lead with Sign out.
  const none = keptVerification(null, true);
  assert.deepEqual([none.verifyHere, none.signOutFirst], [false, true]);
  assert.match(none.hint, /sign out, then sign in again/);
  // Until the answer arrives nothing is claimed either way.
  assert.deepEqual(keptVerification(null, false), { verifyHere: false, signOutFirst: false, hint: '' });

  const app = source('src/App.svelte');
  // The offer is asked for whenever the screen is shown, and the existing prompt takes it.
  assert.match(app, /if \(keptSignIn === 'needs-verification'\) void askKeptOffer\(\);/);
  assert.match(app, /await invoke\('saved_sign_in_verification'\);[\s\S]{0,120}catch \(error\) \{ offer = verificationRequired\(error\); \}/);
  assert.match(app, /\{#if verify && keptOffer\}\s*\{#key keptOffer\.transaction\}<StepUp offer=\{keptOffer\} retry=\{\(\) => \{ void restoreSaved\(true\); \}\}/);
  assert.match(app, /\{#if verify\?\.hint\}<p class="sub" role="status">\{verify\.hint\}<\/p>\{\/if\}/);
  assert.match(app, /class:primary=\{verify\?\.signOutFirst\}[\s\S]{0,80}>Sign out…</);
  // The backend answers for the saved sign-in while no connection is in use, and is permitted to.
  const admin = source('src-tauri/src/server_admin.rs');
  assert.match(admin, /pub\(crate\) async fn saved_sign_in_verification\(/);
  assert.match(admin, /pub\(crate\) async fn server_step_up\([\s\S]{0,500}let session = verifying_session\(&state\)\.await\?;/);
  assert.match(source('src-tauri/src/lib.rs'), /server_admin::saved_sign_in_verification,/);
  assert.ok(source('src-tauri/build.rs').includes('"saved_sign_in_verification"'));
  assert.ok(JSON.parse(source('src-tauri/capabilities/main.json')).permissions.includes('allow-saved-sign-in-verification'));
});

test('after a library move the confirmation row leaves Prepare local Manager in place', () => {
  const ui = source('src/LocalHost.svelte');
  // Its own block: as a branch of the chain it replaced the row that starts the library.
  assert.match(ui, /\{#if !carrying && carry\?\.previousDatabase && carry\.stage === 'switched'\}[\s\S]*?My library is all here<\/button>\s*<\/div>\s*\{\/if\}\s*\{#if carrying\}/);
  assert.doesNotMatch(ui, /\{:else if carry\?\.previousDatabase/);
  const chain = ui.slice(ui.indexOf('{#if carrying}'));
  assert.match(chain, /\{:else if selectedPackage && !needsProfile[\s\S]*?'Prepare local Manager'\}<\/button>/);
});

test('a package change is offered where the backend can make it, and otherwise the way back is offered', () => {
  const ui = source('src/LocalHost.svelte');
  // The backend's own answer wins; one that says nothing can only do it on macOS and Linux.
  assert.match(ui, /const canMovePackage = \$derived\(view\?\.packageChangeAvailable \?\? \(view\?\.companionPlatform === 'mac' \|\| view\?\.companionPlatform === 'linux'\)\);/);
  // Where it cannot: no claim that it can, the library's own package one press away, and no
  // "install the companion for this version" for a library that could not be moved to it.
  assert.match(ui, /\{:else if changingPackage && !canMovePackage\}[\s\S]{0,300}onclick=\{useLibraryPackage\}>Use My Library’s Package<\/button>/);
  assert.match(ui, /function useLibraryPackage\(\) \{[\s\S]{0,120}selected = libraryPackage\.manifestSha256;\s*void checkSelected\(\);/);
  assert.match(ui, /const libraryStranded = \$derived\(packageCheck === 'outdated' && !canMovePackage && !!libraryPackage && selected === libraryPackage\.manifestSha256\);/);
  assert.match(ui, /\{#if !libraryStranded\}\s*\{#if \(packageCheck === 'refused' \|\| packageCheck === 'outdated'\) && view\?\.companionPlatform\}<button/);
  assert.doesNotMatch(ui, /is unavailable on this computer/);
  for (const copy of ['packageMoveUnavailable', 'libraryStrandedCopy']) {
    const text = ui.match(new RegExp(`const ${copy} = '([^']*)'`))?.[1] ?? '';
    assert.match(text, /Your library has not been changed\./, copy);
    assert.match(text, /version of Frameleaf it last ran with/, copy);
  }
});

test('Remote access says why its Cloud switches are off, and AI credit explains a refusal once', () => {
  const remote = source('src/pages/Remote.svelte');
  assert.match(remote, /if \(link\.status === 'rejected' && status\.status === 'fulfilled'\) failed\(link\.reason, \(\) => \{ void load\(\); \}\);/);
  const wallet = source('src/pages/Wallet.svelte');
  // The error banner carries the explanation and Open Settings; no notice repeats it.
  assert.doesNotMatch(wallet, /wallet_step_up_required'[^\n]*notice =/);
  assert.match(errorCopy('wallet_step_up_required')!, /frameleaf\.cloud/);
  assert.match(wallet, /String\(failure\)\.includes\('frameleaf\.cloud'\) && wallet\?\.settingsUrl\}<button[\s\S]{0,80}>Open Settings</);
});

test('the last cloud backup is described in words, never with the server’s tokens', () => {
  const explain = (code: string) => code === 'known_code' ? 'The storage refused the upload.' : null;
  assert.equal(backupRunText({ status: 'completed' }, explain), 'Done');
  assert.equal(backupRunText({ status: 'waiting-for-key' }, explain), 'Waiting for your backup key');
  assert.equal(backupRunText({ status: 'cancelled' }, explain), 'Cancelled');
  assert.equal(backupRunText({ status: 'some-new-status' }, explain), 'Not finished');
  assert.equal(backupRunText({ status: 'failed', error: 'known_code' }, explain), 'Failed · The storage refused the upload.');
  // An error this app has no words for is not printed.
  assert.equal(backupRunText({ status: 'failed', error: 'ECONNRESET at s3.put' }, explain), 'Failed');
  assert.equal(backupRunText({ status: 'failed', error: null }, explain), 'Failed');
  assert.equal(backupKeyText('server'), 'backup key kept on your server');
  assert.match(backupKeyText('own-memory'), /entered again after each server restart/);
  assert.match(backupKeyText('own-stored'), /saved on your server/);
  assert.deepEqual([backupKeyText(null), backupKeyText('future-mode')], ['', '']);
  const page = source('src/pages/Cloud.svelte');
  assert.match(page, /backupRunText\(backup\.lastRun, errorCopy\)/);
  assert.doesNotMatch(page, /in your memory|backup\.lastRun\.error|: backup\.lastRun\.status\}/);
});

test('terms that did not load can be loaded again', () => {
  const ui = source('src/FrameleafAccount.svelte');
  assert.match(ui, /catch \(error\) \{ if \(asked === consentRequest\) \{ termsLoad = 'failed'; fail\(error\); \} \}/);
  assert.match(ui, /function retryConsents\(\) \{[^}]*void loadConsents\(\); \}/);
  assert.match(ui, /\{#if termsLoad === 'failed' && !consents\}[\s\S]{0,300}onclick=\{retryConsents\}>Try Again<\/button>/);
});

test('the server address field takes an address with no scheme, and the backend reduces it to an origin', () => {
  const field = source('src/pages/Welcome.svelte').match(/<input id="srv"[^>]*>/)?.[0] ?? '';
  // type="url" refuses "192.168.1.20:2283" before the app ever sees it.
  assert.match(field, /type="text"/);
  assert.match(field, /inputmode="url"/);
  assert.match(source('src-tauri/src/server_login.rs'), /pub\(crate\) async fn server_sign_in_options\([\s\S]{0,300}let base = crate::connection::typed_server\(&server\)\?;/);
  // A path is accepted now, so the copy no longer tells the person to remove it.
  assert.doesNotMatch(errorCopy('server_requires_https_origin')!, /path/);
});

test('the Welcome footer shows the version this build was made from', async () => {
  const { default: config } = await import('../vite.config.ts') as { default: { define?: Record<string, string> } };
  const { version } = JSON.parse(source('package.json')) as { version: string };
  assert.match(version, /^\d+\.\d+\.\d+$/);
  assert.equal(config.define?.['import.meta.env.VITE_APP_VERSION'], JSON.stringify(version));
  const welcome = source('src/pages/Welcome.svelte');
  assert.match(welcome, /const version = import\.meta\.env\.VITE_APP_VERSION as string;/);
  assert.doesNotMatch(welcome, /'0\.1\.0'/);
});

test('a folder preview says where its files are in plain words and leaves out what there is none of', () => {
  const none = { available: 0, needsDownload: 0, notReady: 0, unknown: 0, pinned: 0, downloadBytes: 0 };
  assert.equal(availabilityText(none), '');
  assert.equal(availabilityText({ ...none, available: 240 }), '240 files are on this computer. This can change before a copy starts.');
  assert.equal(availabilityText({ ...none, available: 1, needsDownload: 1, downloadBytes: 4_200_000 }),
    '1 file is on this computer. 1 file is stored online and needs downloading first (4.2 MB). This can change before a copy starts.');
  const all = availabilityText({ available: 12, needsDownload: 30, notReady: 2, unknown: 5, pinned: 7, downloadBytes: 2_100_000_000 });
  assert.equal(all, '12 files are on this computer. 30 files are stored online and need downloading first (2.1 GB). 2 files can’t be opened until your cloud storage app finishes syncing. 5 files could not be checked and may also need downloading. 7 files are set to always stay on this computer. This can change before a copy starts.');
  for (const text of [all, source('src/PhotoSources.svelte')]) assert.doesNotMatch(text, /OS-reported|provider not ready|request pinning|metadata snapshot/);
  // Nothing is rendered for a snapshot with nothing to say.
  assert.match(source('src/PhotoSources.svelte'), /\{#if folder\.availability && availabilityText\(folder\.availability\)\}/);
});

test('Find OneDrive Folders is offered only where the backend has somewhere to look', () => {
  assert.deepEqual([oneDriveDiscovery('mac'), oneDriveDiscovery('windows'), oneDriveDiscovery('linux')], [true, true, false]);
  assert.match(source('src/PhotoSources.svelte'), /\{#if findOneDrive\}<button[^>]*onclick=\{discover\}>Find OneDrive Folders<\/button>\{\/if\}/);
  // The backend adds candidates only on Windows (environment) and macOS (CloudStorage).
  const backend = source('src-tauri/src/lib.rs');
  assert.match(backend, /let supplied: Vec<_> = if cfg!\(target_os = "windows"\) \{/);
});

test('copy says what the person can do, not what is unfinished inside the app', () => {
  const cloud = errorCopy('source_cloud_copy_pending')!;
  assert.doesNotMatch(cloud, /implemented|placeholder/i);
  assert.match(cloud, /Copy the photos you want into an ordinary folder/);
  // A build without the AI runtime: plain words, and no button that cannot help.
  const view = workerView({ connectionState: 'preparing', workerSupported: true, computer: 'Mac', setup: { state: 'setup-needs-attention', code: 'runtime_pack_unavailable' } });
  assert.equal(view.detail, errorCopy('runtime_pack_unavailable'));
  assert.doesNotMatch(view.detail, /signed|runtime|build\b/i);
  assert.match(view.detail, /Photos remain available\./);
  assert.equal(view.action, null, 'retrying cannot add what this version does not include');
  assert.equal(view.attention, 'needs-you');
});

test('Password keeps its capital beside email', () => {
  // test/vocabulary.test.ts refuses the lowercase phrase anywhere in src/.
  for (const code of ['server_http_401', 'cloud_exchange_unsupported', 'cloud_exchange_interaction_required', 'login_details_invalid']) {
    assert.match(errorCopy(code)!, /email and Password/, code);
  }
});
