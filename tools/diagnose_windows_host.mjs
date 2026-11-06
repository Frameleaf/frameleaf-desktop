import { DatabaseSync } from 'node:sqlite';
import { closeSync, fstatSync, openSync, readdirSync, readFileSync, readSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const errors = new Set(['operation_failed', 'native_controller_changed', 'native_controller_unavailable', 'native_controller_unprotected', 'native_credentials_unavailable', 'native_start_cancelled', 'native_startup_timeout', 'native_host_pipe_failed', 'native_host_protocol_invalid', 'native_host_identity_changed', 'native_host_failed', 'native_shutdown_unconfirmed', 'native_installation_invalid']);
const sources = [new URL('../runtime/host-agent.mjs', import.meta.url),
  ...readdirSync(new URL('../src-tauri/src/', import.meta.url), { recursive: true }).filter(name => name.endsWith('.rs')).map(name => new URL('../src-tauri/src/' + name.replaceAll('\\', '/'), import.meta.url))];
// Agent and controller refusal codes are fixed source literals; anything else in the log stays unreported.
const agentCodes = new Set(['host_agent_source_invalid', ...sources.flatMap(source => [...readFileSync(source, 'utf8').matchAll(/"((?:host|native|runtime)_[a-z_]+)"/g)].map(match => match[1]))]);
const member = (value, known) => known.has(value) ? value : 'unreported';

/** Report only fixed categories from the disposable runner, never journal inputs or raw stderr. */
export function diagnose(root) {
  const result = { operations: [], journalReadable: false, agentLogReadable: false, agentCodes: [] };
  let db;
  try {
    db = new DatabaseSync(join(root, 'manager', 'manager.sqlite'), { readOnly: true });
    result.operations = db.prepare("SELECT json_extract(value,'$.kind') AS kind, json_extract(value,'$.state') AS state, json_extract(value,'$.step') AS step, json_extract(value,'$.error') AS error FROM operations ORDER BY rowid DESC LIMIT 3").all().map(row => ({
      kind: member(row.kind, new Set(['start', 'stop', 'restart', 'backup', 'restore'])),
      state: member(row.state, new Set(['running', 'complete', 'failed', 'interrupted'])),
      step: member(row.step, new Set(['start-native-host', 'stop-native-host'])),
      error: row.error === null ? null : member(row.error, errors),
    }));
    result.journalReadable = true;
  } catch {} finally { db?.close(); }
  let fd;
  try {
    fd = openSync(join(root, 'state', 'agent.log'), 'r');
    // The log is append-only across starts, so the latest failure is at its end.
    const bytes = Buffer.alloc(8192);
    const start = Math.max(0, fstatSync(fd).size - bytes.length);
    const count = readSync(fd, bytes, 0, bytes.length, start);
    const lines = bytes.subarray(0, count).toString('utf8').split(/\r?\n/);
    if (start > 0) lines.shift();
    result.agentCodes = [...new Set(lines.filter(line => agentCodes.has(line)))];
    result.agentLogReadable = true;
  } catch {} finally { if (fd !== undefined) closeSync(fd); }
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.env.RUNNER_ENVIRONMENT !== 'github-hosted' || process.platform !== 'win32' || !process.env.LOCALAPPDATA)
    throw Error('Requires a disposable hosted Windows profile');
  console.log(JSON.stringify(diagnose(join(process.env.LOCALAPPDATA, 'Frameleaf Desktop Host'))));
}
