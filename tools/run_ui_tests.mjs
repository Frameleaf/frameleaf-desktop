// `npm run test:ui`: runs the opt-in browser tests (tools/test_*_ui.mjs) one after another.
// They drive the real Svelte UI in headless Chromium against a synthetic IPC bridge; nothing signs in.
//
//   FRAMELEAF_TEST_PLAYWRIGHT  absolute path of playwright-core's index.mjs (required)
//   FRAMELEAF_TEST_BROWSER     absolute path of a Chromium build (optional; default: Playwright's own)
//   FRAMELEAF_TEST_OUTPUT      absolute folder for screenshots (optional)
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const tools = fileURLToPath(new URL('.', import.meta.url));
const playwright = process.env.FRAMELEAF_TEST_PLAYWRIGHT;
if (!playwright || !isAbsolute(playwright)) {
  process.stderr.write('Set FRAMELEAF_TEST_PLAYWRIGHT to the absolute path of playwright-core/index.mjs. See docs/releases.md, “Browser UI tests”.\n');
  process.exit(2);
}
const tests = readdirSync(tools).filter(name => /^test_.*_ui\.mjs$/.test(name)).sort();
if (tests.length === 0) { process.stderr.write('No browser UI tests were found.\n'); process.exit(2); }
const failed = [];
for (const name of tests) {
  process.stdout.write(`\n== ${name}\n`);
  const result = spawnSync(process.execPath, [join(tools, name)], { stdio: 'inherit', env: { ...process.env, FRAMELEAF_MANAGER_UI_TEST: '1' } });
  if (result.status !== 0) failed.push(name);
}
process.stdout.write(failed.length ? `\nBrowser UI tests failed: ${failed.join(', ')}\n` : `\nAll ${tests.length} browser UI tests passed.\n`);
process.exit(failed.length ? 1 : 0);
