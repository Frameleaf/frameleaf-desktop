import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { diagnose } from './diagnose_windows_host.mjs';

test('host diagnostics read only bounded categories and redact journal inputs and logs', () => {
  const root = mkdtempSync(join(tmpdir(), 'frameleaf-host-diagnostic-'));
  try {
    mkdirSync(join(root, 'manager')); mkdirSync(join(root, 'state'));
    const database = join(root, 'manager', 'manager.sqlite');
    const db = new DatabaseSync(database);
    db.exec('CREATE TABLE operations (value TEXT NOT NULL)');
    const insert = db.prepare('INSERT INTO operations VALUES (?)');
    const secret = 'synthetic-private-password-and-path';
    insert.run(JSON.stringify({ kind: 'start', state: 'failed', step: 'start-native-host', error: 'native_host_failed', input: { password: secret } }));
    insert.run(JSON.stringify({ kind: secret, state: secret, step: secret, error: 'native_' + secret }));
    db.close();
    writeFileSync(join(root, 'state', 'agent.log'), `host_config_invalid\nhost_agent_source_invalid\n${secret}\nhost_${secret}\n`);
    const before = readFileSync(database);
    const result = diagnose(root);
    assert.equal(result.journalReadable, true);
    assert.equal(result.agentLogReadable, true);
    assert.deepEqual(result.operations[0], { kind: 'unreported', state: 'unreported', step: 'unreported', error: 'unreported' });
    assert.deepEqual(result.operations[1], { kind: 'start', state: 'failed', step: 'start-native-host', error: 'native_host_failed' });
    assert.deepEqual(result.agentCodes, ['host_config_invalid', 'host_agent_source_invalid']);
    assert.ok(!JSON.stringify(result).includes(secret));
    assert.deepEqual(readFileSync(database), before);
    writeFileSync(join(root, 'state', 'agent.log'), 'x'.repeat(8192) + '\nhost_config_invalid\n');
    assert.deepEqual(diagnose(root).agentCodes, []);
    rmSync(database);
    assert.equal(diagnose(root).journalReadable, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
