import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { setTimeout } from 'node:timers/promises';
import { diagnosePhoto } from './diagnose_installed_photo.mjs';

const [phase, receipt] = process.argv.slice(2);
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
assert.ok(['upload', 'verify'].includes(phase));
const password = process.env.FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD;
assert.ok(password?.length >= 32);
const credentials = { email: 'native-photo@example.invalid', password };
const original = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAKklEQVR4nGNQaEigKWIYtWDUglELRi0YtWDUglELRi0YtWDUglELhooFAHfgAD2FaRhWAAAAAElFTkSuQmCC', 'base64');
const filename = 'synthetic-native-photo.png';
let token;

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
async function verifyOriginal(id) {
  assert.deepEqual(Buffer.from(await (await request('/api/assets/' + id + '/original', {}, [200])).arrayBuffer()), original);
  console.log('Installed Library synthetic original readback passed');
}
/** Require a processed image; report redacted queue diagnostics if it never appears. */
async function thumbnail(id) {
  for (let i = 0; i < 90; i++) {
    const response = await request('/api/assets/' + id + '/thumbnail?size=thumbnail', {}, [200, 404]);
    if (response.ok) {
      assert.match(response.headers.get('content-type') || '', /^image\//);
      const bytes = Buffer.from(await response.arrayBuffer());
      assert.ok(bytes.length > 0 && !bytes.equals(original));
      return createHash('sha256').update(bytes).digest('hex');
    }
    await response.body.cancel();
    await setTimeout(2000);
  }
  console.log(JSON.stringify({ photoQueues: await diagnosePhoto(request) }));
  throw Error('Timed out waiting for thumbnail');
}

assert.match(await (await request('/', {}, [200])).text(), /<html/i);
if (phase === 'upload') await postJson('/api/auth/admin-sign-up', { ...credentials, name: 'Synthetic qualification' });
token = (await (await postJson('/api/auth/login', credentials)).json()).accessToken;
assert.ok(typeof token === 'string' && token.length > 0);
if (phase === 'upload') {
  const form = new FormData();
  form.set('fileCreatedAt', '2026-01-01T00:00:00.000Z');
  form.set('fileModifiedAt', '2026-01-01T00:00:00.000Z');
  form.set('assetData', new Blob([original], { type: 'image/png' }), filename);
  const asset = await (await request('/api/assets', { method: 'POST', body: form }, [201])).json();
  assert.equal(asset.status, 'created');
  assert.match(asset.id, /^[0-9a-f-]{36}$/);
  const checks = await Promise.allSettled([verifyOriginal(asset.id), thumbnail(asset.id)]);
  const failure = checks.find(result => result.status === 'rejected');
  if (failure) throw failure.reason;
  await writeFile(receipt, JSON.stringify({ id: asset.id, thumbnail: checks[1].value }), { flag: 'wx' });
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
