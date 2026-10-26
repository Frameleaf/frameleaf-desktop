import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

test('PhotoKit metadata binds original identity and frozen version while tolerating array reorder', { skip: process.platform !== 'darwin' }, () => {
  const root = mkdtempSync(join(tmpdir(), 'frameleaf-photo-snapshot-'));
  try {
    const binary = join(root, 'snapshot');
    execFileSync('clang', ['-fobjc-arc', '-Werror', '-Wno-deprecated-declarations', '-framework', 'Foundation', '-framework', 'Photos', fileURLToPath(new URL('../src-tauri/native/tests/photos_snapshot.m', import.meta.url)), '-o', binary]);
    execFileSync(binary);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
