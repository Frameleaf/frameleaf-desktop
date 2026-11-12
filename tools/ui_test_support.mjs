// Shared setup for the opt-in browser tests (tools/test_*_ui.mjs): a Vite dev server for this checkout and
// a headless Chromium driven through Playwright. `npm run test:ui` runs them; `npm test` skips them.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const root = fileURLToPath(new URL('..', import.meta.url));
export const enabled = process.env.FRAMELEAF_MANAGER_UI_TEST === '1';

/** Starts Vite and the browser, runs `work({ browser, origin })`, and always stops both. */
export async function withBrowser(work) {
  // FRAMELEAF_TEST_PLAYWRIGHT is playwright-core's index.mjs; FRAMELEAF_TEST_BROWSER is optional and
  // names a Chromium build to use instead of the one Playwright installed for itself.
  const { FRAMELEAF_TEST_PLAYWRIGHT: playwright, FRAMELEAF_TEST_BROWSER: executablePath } = process.env;
  assert.ok(playwright && isAbsolute(playwright), 'FRAMELEAF_TEST_PLAYWRIGHT must be the absolute path of playwright-core/index.mjs');
  assert.ok(!executablePath || isAbsolute(executablePath), 'FRAMELEAF_TEST_BROWSER must be an absolute path');
  const { chromium } = await import(pathToFileURL(playwright));
  const socket = createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const address = socket.address();
  assert.ok(address && typeof address !== 'string');
  await new Promise(resolve => socket.close(resolve));
  const vite = spawn(process.execPath, [join(root, 'node_modules/vite/bin/vite.js'), '--host', '127.0.0.1', '--port', String(address.port), '--strictPort'], { cwd: root, stdio: ['ignore', 'pipe', 'inherit'] });
  const ended = new Promise(resolve => vite.once('close', resolve));
  let browser;
  try {
    await new Promise((resolve, reject) => {
      let text = '';
      const timeout = setTimeout(() => reject(Error('Vite startup timeout')), 30000);
      vite.stdout.on('data', chunk => { text += chunk; if (text.includes('Local:')) { clearTimeout(timeout); resolve(); } });
      vite.once('error', reject);
      vite.once('exit', code => { if (code) reject(Error('Vite exited before it was ready')); });
    });
    browser = await chromium.launch({ ...(executablePath ? { executablePath } : {}), headless: true, args: ['--disable-gpu'] });
    await work({ browser, origin: `http://127.0.0.1:${address.port}` });
  } finally {
    await browser?.close();
    if (vite.exitCode === null) vite.kill();
    await ended;
  }
}
