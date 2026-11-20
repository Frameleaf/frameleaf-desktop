import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

// Without the windows subsystem, every start of the installed app on Windows opens a console window too.
test('the Windows release build is a window app, not a console app', () => {
  const main = readFileSync(new URL('../src-tauri/src/main.rs', import.meta.url), 'utf8');
  assert.match(main, /^#!\[cfg_attr\(not\(debug_assertions\), windows_subsystem = "windows"\)\]$/m);
});
