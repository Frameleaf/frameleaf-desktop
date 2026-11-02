import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { once } from 'node:events';

const path = new URL('../runtime/host-bootstrap.mjs', import.meta.url);
const source = `import {createInterface} from 'node:readline';
const input=createInterface({input:process.stdin,crlfDelay:Infinity});
for await (const line of input) console.log(JSON.stringify(line));
/*${'large-agent-'.repeat(7000)}*/`;
const frame = Buffer.from(source).toString('base64') + '\n';

async function run(parts) {
  assert.ok(existsSync(path), 'the bounded pipe loader must exist');
  const bootstrap = readFileSync(path, 'utf8');
  assert.ok(bootstrap.length < 8000, 'launcher must fit the Windows command line');
  const child = spawn(process.execPath, ['--input-type=module', '--eval', bootstrap], {
    stdio: ['pipe', 'pipe', 'pipe'], timeout: 5000,
  });
  const ended = once(child, 'close');
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.stdin.on('error', () => {});
  for (const part of parts) {
    if (child.stdin.destroyed) break;
    if (!child.stdin.write(part)) await Promise.race([once(child.stdin, 'drain').catch(() => {}), ended]);
  }
  if (!child.stdin.destroyed) child.stdin.end();
  const [code, signal] = await ended;
  return { code, signal, stdout, stderr };
}

test('large agent source stays off argv and preserves coalesced configuration and controls', async () => {
  const result = await run([frame + '{"password":"synthetic-only"}\nstop\n']);
  assert.deepEqual(result, { code: 0, signal: null,
    stdout: '"{\\"password\\":\\"synthetic-only\\"}"\n"stop"\n', stderr: '' });
});

test('pipe loader preserves split source frames and unterminated final control', async () => {
  const result = await run([frame.slice(0, 3), frame.slice(3, -1), '\n', 'config\n', 'stop']);
  assert.deepEqual(result, { code: 0, signal: null, stdout: '"config"\n"stop"\n', stderr: '' });
});

test('pipe loader rejects malformed, truncated, empty and overlong source without disclosure', async () => {
  const highBit = Buffer.from(Buffer.from('console.log("must not execute")').toString('base64') + '\n');
  highBit[0] |= 128;
  for (const input of ['', '\n', 'not a base64 source\nprivate-config\n', 'YQ=\n',
    'YQ==', 'YR==\n', 'YQ===\n', 'YQ==\r\n',
    highBit,
    'A'.repeat(262145), 'A'.repeat(262145) + '\n']) {
    const result = await run([input]);
    assert.deepEqual(result, { code: 1, signal: null, stdout: '', stderr: 'host_agent_source_invalid\n' });
  }
});

test('rejected source reports its fixed error while parent input is backpressured', async () => {
  const result = await run(['A'.repeat(4 * 1024 * 1024), '\nprivate-config\n']);
  assert.deepEqual(result, { code: 1, signal: null, stdout: '', stderr: 'host_agent_source_invalid\n' });
});

test('pipe loader redacts import errors and starts source when no configuration follows', async () => {
  const bad = await run([Buffer.from('throw new Error("private-value")').toString('base64') + '\n']);
  assert.deepEqual(bad, { code: 1, signal: null, stdout: '', stderr: 'host_agent_source_invalid\n' });
  const good = await run([Buffer.from('console.log("loaded")').toString('base64') + '\n']);
  assert.deepEqual(good, { code: 0, signal: null, stdout: 'loaded\n', stderr: '' });
});

test('source at the size bound still permits a following control frame', async () => {
  const prefix = 'console.log("boundary"); //';
  const encoded = Buffer.from(prefix + 'x'.repeat(196608 - prefix.length)).toString('base64');
  const result = await run([encoded + '\ncontrol\n']);
  assert.deepEqual(result, { code: 0, signal: null, stdout: 'boundary\n', stderr: '' });
});
