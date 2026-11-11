import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { constants } from 'node:fs';
import { access, lstat, readFile, readdir, realpath, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { setTimeout } from 'node:timers/promises';
import { diagnosePhoto } from './diagnose_installed_photo.mjs';

const [phase, receipt, qualificationInput, executableSha256] = process.argv.slice(2);
const interactive = phase === 'watch-interactive';
const recovery = ['recovery-seed', 'recovery-change', 'recovery-database', 'recovery-media'].includes(phase);
assert.ok(interactive || recovery || ['upload', 'verify', 'watch-signup', 'watch-create', 'watch-verify'].includes(phase));
if (interactive) {
  assert.ok(['darwin', 'linux'].includes(process.platform));
  assert.equal(process.env.FRAMELEAF_WATCH_DISPOSABLE, '1');
  assert.ok(process.stdin.isTTY && process.stderr.isTTY, 'An interactive desktop and terminal are required');
  assert.ok(isAbsolute(qualificationInput) && isAbsolute(receipt));
  assert.match(basename(receipt), /^frameleaf-watch-source-[0-9a-f-]{36}$/);
  assert.equal(await realpath(receipt), receipt);
  assert.deepEqual(await readdir(receipt), []);
  await verifyWatchExecutable(qualificationInput, executableSha256);
} else if (recovery) {
  assert.equal(process.platform, 'win32');
  assert.equal(process.env.FRAMELEAF_RECOVERY_DISPOSABLE, '1');
  assert.ok(isAbsolute(receipt) && basename(receipt) === 'media.json');
  assert.match(basename(dirname(receipt)), /^frameleaf-installed-recovery-[0-9a-f-]{36}$/);
} else {
  assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
}
if (!interactive && phase.startsWith('watch-')) {
  assert.equal(process.env.GITHUB_ACTIONS, 'true');
  assert.equal(process.platform, 'win32');
}
const password = process.env.FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD;
if (phase !== 'recovery-media') assert.ok(password?.length >= 32);
const credentials = { email: 'native-photo@example.invalid', password };
const original = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAKklEQVR4nGNQaEigKWIYtWDUglELRi0YtWDUglELRi0YtWDUglELhooFAHfgAD2FaRhWAAAAAElFTkSuQmCC', 'base64');
const filename = phase.startsWith('watch-') ? 'synthetic-watched-photo.png' : 'synthetic-native-photo.png';
let token;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const recoveryNames = ['synthetic-recovery-photo.png', 'synthetic-recovery-video.mp4'];
const beforeBackup = 'Synthetic description at recovery point';
const afterBackup = 'Synthetic description after recovery point';
const recoveryVideoSha256 = '7c8e01b8017b1bee64061b83a1e6bd047900dfc105294a04be2e3937374a8ab6';

/** Admit only a physical path whose executable and ancestors the test account cannot replace. */
async function verifyWatchExecutable(path, expected) {
  assert.ok(process.getuid() !== 0 && process.geteuid() !== 0);
  assert.equal(basename(path), 'frameleaf-desktop');
  assert.equal(await realpath(path), path);
  assert.match(expected, /^[a-f0-9]{64}$/);
  const ancestors = [];
  for (let ancestor = dirname(path); ; ancestor = dirname(ancestor)) {
    ancestors.push(ancestor);
    if (ancestor === dirname(ancestor)) break;
  }
  for (const directory of ancestors.reverse()) {
    const info = await lstat(directory);
    assert.ok(info.isDirectory(), 'Expected a physical installed Desktop directory');
    await requireProtectedPath(directory, info);
  }
  const file = await lstat(path);
  assert.ok(file.isFile() && file.size <= 256 * 1024 * 1024);
  await requireProtectedPath(path, file);
  assert.equal(createHash('sha256').update(await readFile(path)).digest('hex'), expected);
  if (process.platform === 'darwin') {
    const bundle = dirname(dirname(dirname(path)));
    assert.ok(bundle.endsWith('.app') && basename(dirname(path)) === 'MacOS' && basename(dirname(dirname(path))) === 'Contents');
    const codesign = spawn('/usr/bin/codesign', ['--verify', '--strict', '--deep', bundle], { stdio: 'ignore' });
    const [code] = await once(codesign, 'exit');
    assert.equal(code, 0, 'Installed Desktop bundle signature verification failed');
  }
}

/** Refuse ordinary-user writers while allowing the standard macOS admin-owned Applications group. */
async function requireProtectedPath(path, info) {
  const trustedGroup = info.gid === 0 || (process.platform === 'darwin' && info.gid === 80);
  assert.ok(info.uid === 0 && !(info.mode & (trustedGroup ? 0o002 : 0o022)), 'Expected an administrator-protected Desktop installation');
  await assert.rejects(access(path, constants.W_OK), { code: /^(EACCES|EPERM|EROFS)$/ }, 'The qualification account can modify its installed Desktop path');
}

async function request(path, options, statuses) {
  const headers = new Headers(options.headers);
  if (token) headers.set('Authorization', 'Bearer ' + token);
  const response = await fetch('http://127.0.0.1:2283' + path, {
    ...options, headers, redirect: 'error', signal: AbortSignal.timeout(30_000),
  });
  assert.ok(statuses.includes(response.status), path + ' returned ' + response.status);
  return response;
}
function postJson(path, data) {
  return request(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }, [201]);
}
async function upload(name, bytes, mime) {
  const form = new FormData();
  form.set('fileCreatedAt', '2026-01-01T00:00:00.000Z');
  form.set('fileModifiedAt', '2026-01-01T00:00:00.000Z');
  form.set('assetData', new Blob([bytes], { type: mime }), name);
  const asset = await (await request('/api/assets', { method: 'POST', body: form }, [201])).json();
  assert.equal(asset.status, 'created');
  assert.match(asset.id, /^[0-9a-f-]{36}$/);
  return asset.id;
}
const assetPath = id => '/api/assets/' + id;
const originalBytes = async id => Buffer.from(await (await request(assetPath(id) + '/original', {}, [200])).arrayBuffer());
const assetInfo = async id => (await request(assetPath(id), {}, [200])).json();
async function describe(id, description) {
  await request(assetPath(id), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ description }) }, [200]);
  assert.equal((await assetInfo(id)).exifInfo?.description, description);
}
async function mediaReceipt() {
  const items = JSON.parse(await readFile(receipt, 'utf8'));
  assert.deepEqual(items.map(item => item.name), recoveryNames);
  assert.notEqual(items[0].id, items[1].id);
  for (const item of items) {
    assert.match(item.id, /^[0-9a-f-]{36}$/);
    assert.match(item.sha256, /^[0-9a-f]{64}$/);
  }
  return items;
}
async function seedRecovery() {
  assert.ok(isAbsolute(qualificationInput));
  assert.equal((await stat(qualificationInput)).size, 5876);
  const video = await readFile(qualificationInput);
  assert.equal(sha256(video), recoveryVideoSha256, 'Expected the reviewed synthetic Library H.264 fixture');
  const items = [];
  for (const [index, bytes, mime] of [[0, original, 'image/png'], [1, video, 'video/mp4']]) {
    const name = recoveryNames[index];
    const id = await upload(name, bytes, mime);
    const stored = await originalBytes(id);
    assert.deepEqual(stored, bytes);
    await thumbnail(id, bytes);
    await writeFile(join(dirname(receipt), 'media-source', name), stored, { flag: 'wx' });
    items.push({ id, name, sha256: sha256(stored) });
  }
  await describe(items[0].id, beforeBackup);
  await writeFile(receipt, JSON.stringify(items), { flag: 'wx' });
}
async function verifyOriginal(id, expected = original) {
  assert.deepEqual(await originalBytes(id), expected);
  console.log('Installed Library synthetic original readback passed');
}
/** Require a processed image; report redacted queue diagnostics if it never appears. */
async function thumbnail(id, expected = original) {
  for (let i = 0; i < 90; i++) {
    const response = await request('/api/assets/' + id + '/thumbnail?size=thumbnail', {}, [200, 404]);
    if (response.ok) {
      assert.match(response.headers.get('content-type') || '', /^image\//);
      const bytes = Buffer.from(await response.arrayBuffer());
      assert.ok(bytes.length > 0 && !bytes.equals(expected));
      return createHash('sha256').update(bytes).digest('hex');
    }
    await response.body.cancel();
    await setTimeout(2000);
  }
  console.log(JSON.stringify({ photoQueues: await diagnosePhoto(request) }));
  throw Error('Timed out waiting for thumbnail');
}

/** Return the single matching asset ID, failing immediately if the watcher created duplicates. */
async function findWatched(name) {
  const response = await request('/api/search/metadata', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ originalFileName: name }),
  }, [200]);
  const { assets } = await response.json();
  const matches = assets.items.filter(item => item.originalFileName === name);
  assert.ok(matches.length <= 1, 'Watcher imported duplicate originals');
  if (matches.length) assert.match(matches[0].id, /^[0-9a-f-]{36}$/);
  return matches[0]?.id;
}

/** Wait for the original and its processed thumbnail to become readable. */
async function waitWatched(name, bytes) {
  const deadline = Date.now() + 210_000;
  for (;;) {
    const id = await findWatched(name);
    if (id) {
      await verifyOriginal(id, bytes);
      await thumbnail(id, bytes);
      return id;
    }
    if (Date.now() >= deadline) throw Error('Watched original did not appear');
    await setTimeout(2000);
  }
}

/** Recheck throughout two complete scan intervals rather than at one point in time. */
async function observeScans(check) {
  // The watcher scans every 60 seconds. Check beyond two complete scan intervals.
  const deadline = Date.now() + 130_000;
  do {
    await check();
    await setTimeout(5000);
  } while (Date.now() < deadline);
  await check();
}

/** Keep one launched process while the operator confirms native window and approval actions. */
async function qualifyInteractive() {
  const resumed = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAKklEQVR4nGM4o9FEU8QwasGoBaMWjFowasGoBaMWjFowasGoBaMWDBULAMew2Ewi/wTvAAAAAElFTkSuQmCC', 'base64');
  const resumedName = 'synthetic-resumed-photo.png';
  const hiddenFile = join(receipt, filename);
  const pausedFile = join(receipt, resumedName);
  const appEnvironment = { ...process.env };
  delete appEnvironment.FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD;
  const app = spawn(qualificationInput, [], { detached: true, stdio: 'ignore', env: appEnvironment });
  await once(app, 'spawn');
  const terminal = createInterface({ input: process.stdin, output: process.stderr });
  const stop = () => {
    if (app.exitCode !== null || app.signalCode !== null) return false;
    try { process.kill(-app.pid, 'SIGKILL'); }
    catch (error) { if (error.code !== 'ESRCH') throw error; }
    return true;
  };
  const abort = () => {
    stop();
    process.exit(1);
  };
  process.once('SIGINT', abort);
  process.once('SIGTERM', abort);
  terminal.once('SIGINT', abort);
  const running = () => assert.ok(app.exitCode === null && app.signalCode === null, 'Installed Desktop exited');
  const confirm = async (instruction) => {
    const reply = await terminal.question(`${instruction}\nType yes when confirmed: `, { signal: AbortSignal.timeout(180_000) });
    assert.equal(reply.trim(), 'yes', 'Required operator observation was not confirmed');
    running();
  };
  try {
    process.stderr.write(`Disposable Library: http://127.0.0.1:2283\nAccount: ${credentials.email}\nTemporary password: ${password}\n`);
    await confirm(`Sign in, open Photo sources, choose ${receipt}, enable Watch this folder and background reads, then approve. Confirm Pause Watching is available.`);
    await confirm('Close the Desktop window using its close button. Confirm it is no longer visible and Desktop remains in the Dock or tray. Keep the window closed until prompted.');
    await writeFile(hiddenFile, original, { flag: 'wx' });
    const hiddenId = await waitWatched(filename, original);
    await confirm('Confirm the window stayed closed until the original and thumbnail verified. Reopen the existing Desktop from the Dock or tray and pause watching. Confirm Resume Watching is available.');
    await writeFile(pausedFile, resumed, { flag: 'wx' });
    await observeScans(async () => {
      running();
      assert.equal(await findWatched(resumedName), undefined, 'A paused watcher imported an original');
      assert.equal(await findWatched(filename), hiddenId);
    });
    await confirm('Select Resume Watching for the same folder without choosing or approving it again. Confirm Pause Watching is available.');
    const resumedId = await waitWatched(resumedName, resumed);
    assert.notEqual(hiddenId, resumedId);
    await observeScans(async () => {
      running();
      assert.equal(await findWatched(filename), hiddenId);
      assert.equal(await findWatched(resumedName), resumedId);
    });
    assert.deepEqual(await readFile(hiddenFile), original);
    assert.deepEqual(await readFile(pausedFile), resumed);
    await confirm('Remove the watched-folder permission, confirm No folder approved, then sign out.');
  } finally {
    process.removeListener('SIGINT', abort);
    process.removeListener('SIGTERM', abort);
    terminal.close();
    if (stop()) await once(app, 'exit');
  }
}

if (phase === 'watch-create') {
  assert.ok(isAbsolute(receipt) && basename(receipt) === filename &&
    /^frameleaf-watch-source-[0-9a-f-]{36}$/.test(basename(dirname(receipt))));
  await writeFile(receipt, original, { flag: 'wx' });
  process.exit(0);
}
if (phase === 'recovery-media') {
  const restored = join(dirname(receipt), 'media-restored');
  assert.deepEqual((await readdir(restored)).sort(), [...recoveryNames].sort());
  for (const item of await mediaReceipt()) {
    assert.equal(sha256(await readFile(join(restored, item.name))), item.sha256);
  }
  console.log('Separate media archive restored and verified original photo and video bytes without Library access');
  process.exit(0);
}
assert.match(await (await request('/', {}, [200])).text(), /<html/i);
if (phase === 'upload' || phase === 'watch-signup' || interactive || phase === 'recovery-seed') {
  await postJson('/api/auth/admin-sign-up', { ...credentials, name: 'Synthetic qualification' });
}
if (phase === 'watch-signup') process.exit(0);
token = (await (await postJson('/api/auth/login', credentials)).json()).accessToken;
assert.ok(typeof token === 'string' && token.length > 0);
if (interactive) {
  await qualifyInteractive();
} else if (phase === 'recovery-seed') {
  await seedRecovery();
} else if (phase === 'recovery-change') {
  const [photo] = await mediaReceipt();
  assert.equal((await assetInfo(photo.id)).exifInfo?.description, beforeBackup);
  await describe(photo.id, afterBackup);
} else if (phase === 'recovery-database') {
  const items = await mediaReceipt();
  assert.equal((await assetInfo(items[0].id)).exifInfo?.description, beforeBackup, 'Database did not return to the selected recovery point');
  for (const item of items) {
    assert.equal((await assetInfo(item.id)).originalFileName, item.name);
    assert.equal(sha256(await originalBytes(item.id)), item.sha256);
  }
  console.log('Restored database metadata and verified both originals still readable from existing Library storage');
} else if (phase === 'watch-verify') {
  await waitWatched(filename, original);
} else if (phase === 'upload') {
  const id = await upload(filename, original, 'image/png');
  const checks = await Promise.allSettled([verifyOriginal(id), thumbnail(id)]);
  const failures = checks.filter(result => result.status === 'rejected');
  if (failures.length) throw new AggregateError(failures.map(result => result.reason), 'Installed photo qualification failed');
  await writeFile(receipt, JSON.stringify({ id, thumbnail: checks[1].value }), { flag: 'wx' });
} else {
  const asset = JSON.parse(await readFile(receipt, 'utf8'));
  const path = '/api/assets/' + asset.id;
  const info = await (await request(path, {}, [200])).json();
  assert.equal(info.id, asset.id);
  assert.equal(info.originalFileName, filename);
  await verifyOriginal(asset.id);
  assert.equal(await thumbnail(asset.id), asset.thumbnail);
}
console.log('Installed Library synthetic photo ' + phase + ' passed');
