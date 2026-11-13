import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

for (const status of [404, 500]) {
  test(`original readback failure preserves thumbnail ${status} failure and never writes a receipt`, () => {
    const root = mkdtempSync(join(tmpdir(), 'frameleaf-photo-cli-'));
    const receipt = join(root, 'receipt.json');
    const loader = `
      import { createRequire, syncBuiltinESMExports } from 'node:module';
      const require = createRequire(process.cwd() + '/package.json');
      require('node:timers/promises').setTimeout = async () => {};
      syncBuiltinESMExports();
      globalThis.fetch = async (url) => {
        const path = new URL(url).pathname;
        const json = (value, status = 200) => new Response(JSON.stringify(value), { status });
        if (path === '/') return new Response('<html>fixture</html>');
        if (path === '/api/auth/admin-sign-up') return json({}, 201);
        if (path === '/api/auth/login') return json({ accessToken: 'synthetic-token' }, 201);
        if (path === '/api/assets') return json({ id: '12345678-1234-4234-8234-123456789abc', status: 'created' }, 201);
        if (path.endsWith('/original')) return new Response('wrong-original');
        if (path.endsWith('/thumbnail')) return new Response('', { status: ${status} });
        if (path.startsWith('/api/queues/')) return json(path.endsWith('/jobs') ? [] : { statistics: {}, isPaused: false });
        throw Error('Unexpected fixture request');
      };
    `;
    try {
      const result = spawnSync(process.execPath, [
        '--import', 'data:text/javascript,' + encodeURIComponent(loader),
        'tools/qualify_installed_photo.mjs', 'upload', receipt,
      ], { encoding: 'utf8', timeout: 10_000, env: {
        ...process.env, RUNNER_ENVIRONMENT: 'github-hosted',
        FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD: 'synthetic-password-long-enough-for-qualification',
      } });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1);
      if (status === 404) assert.match(result.stdout, /"photoQueues"/);
      assert.match(result.stderr, /ERR_ASSERTION/);
      assert.match(result.stderr, status === 404 ? /Timed out waiting for thumbnail/ : /returned 500/);
      assert.equal(existsSync(receipt), false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
}

test('watched readback rejects two assets for the same synthetic original', () => {
  const loader = `
    Object.defineProperty(process, 'platform', { value: 'win32' });
    globalThis.fetch = async (url) => {
      const path = new URL(url).pathname;
      if (path === '/') return new Response('<html>fixture</html>');
      if (path === '/api/auth/login') return Response.json({ accessToken: 'synthetic-token' }, { status: 201 });
      if (path === '/api/search/metadata') {
        const first = { originalFileName: 'synthetic-watched-photo.png', id: '12345678-1234-4234-8234-123456789abc' };
        return Response.json({ assets: { items: [first, { ...first, id: '22345678-1234-4234-8234-123456789abc' }] } });
      }
      throw Error('Unexpected fixture request');
    };
  `;
  const result = spawnSync(process.execPath, [
    '--import', 'data:text/javascript,' + encodeURIComponent(loader),
    'tools/qualify_installed_photo.mjs', 'watch-verify',
  ], { encoding: 'utf8', timeout: 10_000, env: {
    ...process.env, RUNNER_ENVIRONMENT: 'github-hosted', GITHUB_ACTIONS: 'true',
    FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD: 'synthetic-password-long-enough-for-qualification',
  } });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Watcher imported duplicate originals/);
});

test('interactive watcher refuses a writable executable path before contacting Library', {
  skip: !['darwin', 'linux'].includes(process.platform),
}, () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'frameleaf-watch-cli-')));
  const source = join(root, 'frameleaf-watch-source-' + randomUUID());
  const executable = join(root, 'frameleaf-desktop');
  mkdirSync(source);
  writeFileSync(executable, 'synthetic executable candidate', { mode: 0o700 });
  const loader = `
    Object.defineProperty(process.stdin, 'isTTY', { value: true });
    Object.defineProperty(process.stderr, 'isTTY', { value: true });
    Object.defineProperty(process, 'getuid', { value: () => 501 });
    Object.defineProperty(process, 'geteuid', { value: () => 501 });
    globalThis.fetch = async () => { throw Error('Unexpected Library request'); };
  `;
  try {
    const result = spawnSync(process.execPath, [
      '--import', 'data:text/javascript,' + encodeURIComponent(loader),
      'tools/qualify_installed_photo.mjs', 'watch-interactive', source, executable, '0'.repeat(64),
    ], { encoding: 'utf8', timeout: 10_000, env: { ...process.env, FRAMELEAF_WATCH_DISPOSABLE: '1' } });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /administrator-protected Desktop installation|qualification account can modify/);
    assert.doesNotMatch(result.stderr, /Unexpected Library request/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
