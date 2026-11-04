import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as pause } from 'node:timers/promises';

assert.equal(process.platform, 'win32');
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
const profile = await mkdtemp(join(process.env.RUNNER_TEMP, 'frameleaf-webview-'));
const app = spawn(process.argv[2], [], {
  env: { ...process.env, WEBVIEW2_USER_DATA_FOLDER: profile,
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: '--remote-debugging-address=127.0.0.1 --remote-debugging-port=0' }
});

async function welcomeInteraction() {
  async function waitFor(find, label) {
    for (let i = 0; i < 100; i++) {
      const result = find();
      if (result) return result;
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    throw new Error('Missing ' + label);
  }
  const radio = label => [...document.querySelectorAll('[role="radio"]')].find(el => el.textContent.includes(label));
  await waitFor(() => document.querySelector('h2')?.textContent === 'Welcome' && document.querySelector('#srv'), 'Welcome server address form');
  const local = radio('Run Frameleaf here');
  if (!local || local.disabled) throw new Error('Local setup choice unavailable');
  local.click();
  await waitFor(() => document.querySelector('[aria-label="Local library setup"]')?.innerText.includes('Server component not installed'), 'native host discovery result');
  radio('Connect to my server').click();
  await waitFor(() => document.querySelector('#srv') && radio('Connect to my server').getAttribute('aria-checked') === 'true', 'return to server connection');
  return true;
}

try {
  let page;
  for (let i = 0; i < 120 && !page; i++) {
    assert.equal(app.exitCode, null, 'Installed executable exited before Welcome');
    try {
      const port = (await readFile(join(profile, 'EBWebView', 'DevToolsActivePort'), 'utf8')).split(/\r?\n/)[0];
      if (/^\d+$/.test(port)) {
        const targets = await (await fetch('http://127.0.0.1:' + port + '/json/list')).json();
        page = targets.find(t => t.type === 'page' && /^https?:\/\/tauri\.localhost\//.test(t.url));
      }
    } catch (error) {
      if (error.code !== 'ENOENT' && error.cause?.code !== 'ECONNREFUSED') throw error;
    }
    if (!page) await pause(500);
  }
  assert.ok(page, 'Installed Frameleaf WebView2 target did not appear');
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  try {
    const response = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Installed UI interaction timed out')), 70000);
      socket.onerror = () => { clearTimeout(timeout); reject(new Error('WebView2 connection failed')); };
      socket.onopen = () => socket.send(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: {
        expression: '(' + welcomeInteraction.toString() + ')()', awaitPromise: true, returnByValue: true
      }}));
      socket.onmessage = event => {
        const message = JSON.parse(event.data);
        if (message.id === 1) { clearTimeout(timeout); resolve(message); }
      };
    });
    assert.ifError(response.error && new Error(response.error.message));
    assert.ok(!response.result.exceptionDetails, response.result.result.description);
    assert.equal(response.result.result.value, true);
    console.log('Installed Welcome, native host discovery, and return to connection passed');
  } finally { socket.close(); }
} finally { app.kill(); }
