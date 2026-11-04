import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { setTimeout as pause } from 'node:timers/promises';

assert.equal(process.platform, 'win32');
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
const profile = await mkdtemp(join(process.env.RUNNER_TEMP, 'frameleaf-webview-'));
const listener = createServer();
await new Promise((resolve, reject) => listener.once('error', reject).listen(0, '127.0.0.1', resolve));
const port = listener.address().port;
await new Promise(resolve => listener.close(resolve));
const app = spawn(process.argv[2], [], {
  stdio: 'inherit',
  env: { ...process.env, WEBVIEW2_USER_DATA_FOLDER: profile,
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: '--remote-debugging-address=127.0.0.1 --remote-debugging-port=' + port }
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
  const local = await waitFor(() => {
    const choice = radio('Run Frameleaf here');
    return choice && !choice.disabled && choice;
  }, 'enabled local setup choice');
  local.click();
  await waitFor(() => document.querySelector('[aria-label="Local library setup"]')?.innerText.includes('Server component not installed'), 'native host discovery result');
  radio('Connect to my server').click();
  await waitFor(() => document.querySelector('#srv') && radio('Connect to my server').getAttribute('aria-checked') === 'true', 'return to server connection');
  return true;
}

try {
  let page;
  let observed = [];
  let connected = false;
  for (let i = 0; i < 120 && !page; i++) {
    assert.equal(app.exitCode, null, 'Installed executable exited before Welcome');
    try {
      const targets = await (await fetch('http://127.0.0.1:' + port + '/json/list')).json();
      connected = true;
      observed = targets.map(t => [t.type, t.url.split(/[?#]/)[0]]);
      page = targets.find(t => ['page', 'webview'].includes(t.type) && /^https?:\/\/tauri\.localhost(?:\/|$)/.test(t.url));
    } catch (error) {
      if (error.cause?.code !== 'ECONNREFUSED') throw error;
    }
    if (!page) await pause(500);
  }
  if (!page) {
    // Startup and missing-DLL dialogs can keep the executable alive without creating a WebView.
    spawnSync('powershell.exe', ['-NoProfile', '-Command', `
      $app = Get-Process -Id ${app.pid}
      $app | Select-Object ProcessName, SessionId, MainWindowTitle, Responding | Format-List
      Get-CimInstance Win32_Process -Filter "ParentProcessId=${app.pid}" | Select-Object Name, ProcessId | Format-Table
      Add-Type -AssemblyName UIAutomationClient
      $window = [System.Windows.Automation.AutomationElement]::FromHandle($app.MainWindowHandle)
      if ($window) {
        $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition) |
          Select-Object -First 30 | ForEach-Object { $_.Current.Name }
      }
    `], { stdio: 'inherit', timeout: 15000 });
    throw new Error('Installed WebView2 absent; debugger connected=' + connected + '; targets=' + JSON.stringify(observed));
  }
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
