const assert = require('node:assert/strict');
const { PassThrough } = require('node:stream');
const { test } = require('node:test');
const { observe } = require('./audit_installed_controller.cjs');

test('reports only a complete fixed controller refusal, never secret-bearing output', () => {
  const output = new PassThrough();
  const codes = [];
  observe(output, code => codes.push(code));
  const valid = JSON.stringify({ protocolVersion: 1, state: 'failed', code: 'runtime_store_directory_not_private' });
  output.write(valid.slice(0, 17));
  assert.deepEqual(codes, []);
  output.write(valid.slice(17) + '\n');
  assert.deepEqual(codes, ['runtime_store_directory_not_private']);
  const secret = 'Synthetic-private-password-123!';
  for (const value of [
    { protocolVersion: 1, state: 'failed', code: secret },
    { protocolVersion: 1, state: 'failed', code: 'host_invalid', password: secret },
    { protocolVersion: 1, state: 'running', code: 'host_invalid' },
    { protocolVersion: 2, state: 'failed', code: 'host_invalid' },
    { protocolVersion: 1, state: 'failed', code: 'host_' + 'x'.repeat(80) },
    { protocolVersion: 1, state: 'failed', code: 'unexpected_code' },
  ]) output.write(JSON.stringify(value) + '\n');
  output.write(secret + '\nnot-json\n');
  assert.deepEqual(codes, ['runtime_store_directory_not_private']);
});

test('disables observation after an oversized protocol line', () => {
  const output = new PassThrough();
  const codes = [];
  observe(output, code => codes.push(code));
  output.write('x'.repeat(16 * 1024 + 1));
  output.write('\n' + JSON.stringify({ protocolVersion: 1, state: 'failed', code: 'host_invalid' }) + '\n');
  assert.deepEqual(codes, []);
});

test('observes ESM spawn only for owner-pipe controllers and preserves spawn arguments', async () => {
  const childProcess = require('node:child_process');
  const { syncBuiltinESMExports } = require('node:module');
  const filename = require.resolve('./audit_installed_controller.cjs');
  const cached = require.cache[filename];
  const spawn = childProcess.spawn;
  const write = process.stderr.write;
  const calls = [], messages = [];
  const options = { env: { PRIVATE_SYNTHETIC_VALUE: 'never-print-this' }, stdio: 'pipe' };
  try {
    childProcess.spawn = (...args) => { calls.push(args); return { stdout: new PassThrough() }; };
    process.stderr.write = value => { messages.push(value); return true; };
    delete require.cache[filename];
    require(filename);
    const esm = await import('node:child_process');
    const receipt = JSON.stringify({ protocolVersion: 1, state: 'failed', code: 'host_state_invalid' }) + '\n';
    esm.spawn('another.exe', ['--owner-pipe'], options).stdout.write(receipt);
    esm.spawn('frameleaf-native-host.exe', ['--inspect-owner'], options).stdout.write(receipt);
    esm.spawn('frameleaf-native-host.exe', ['--owner-pipe'], options).stdout.write(receipt);
    assert.deepEqual(messages, ['Installed controller refusal: host_state_invalid\n']);
    assert.deepEqual(calls[2], ['frameleaf-native-host.exe', ['--owner-pipe'], options]);
    assert.equal(calls[2][2], options);
  } finally {
    childProcess.spawn = spawn;
    process.stderr.write = write;
    require.cache[filename] = cached;
    syncBuiltinESMExports();
  }
});
