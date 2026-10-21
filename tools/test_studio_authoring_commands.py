import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from build_runtime import BuildError
from build_host_studio import adapt_authoring_command, bind_authoring_commands


CONFIG_FIXTURE = r"""import { fileURLToPath } from 'node:url'
import path from 'node:path'
const here = String.raw`D:\repo\studio\adapters\web`;
const engine = String.raw`D:\repo\studio\engine`;
const persistenceShim = here + String.raw`\src\shims\timeline-persistence.ts`;
const persistenceModule = engine + String.raw`\src\features\timeline\stores\timeline-persistence.ts`;
const upstreamWorkspaceDouble = engine + String.raw`\src\in-memory-handle.ts`;
const adapterWorkspaceDouble = here + String.raw`\test\in-memory-handle.ts`;
async function resolveFromEngine(source, importer, options) {
  if (!importer.startsWith(here) || importer.startsWith(engine)) return null
  return this.resolve(source, path.join(engine, 'src/main.tsx'), { ...options, skipSelf: true })
}
async function gatePersistence(source, importer, options) {
  if (!importer || importer === persistenceShim || !source.includes('timeline-persistence')) return null
  const resolved = await this.resolve(source, importer, { ...options, skipSelf: true });
  return resolved?.id === persistenceModule ? persistenceShim : null
}
async function workspaceDouble(source, importer, options) {
  const resolved = await this.resolve(source, importer, { ...options, skipSelf: true });
  return resolved?.id === upstreamWorkspaceDouble ? adapterWorkspaceDouble : null
}
"""


class StudioAuthoringCommandTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'requires authoring Node')
    def test_adapter_runs_the_pinned_javascript_launcher_without_a_shell(self):
        with tempfile.TemporaryDirectory(prefix='studio commands ') as temporary:
            root = Path(temporary).resolve()
            launcher = root / 'node_modules/vite-plus/bin/vp'
            launcher.parent.mkdir(parents=True)
            launcher.write_text('process.stdout.write(JSON.stringify(process.argv.slice(2)));')
            source = """import path from 'node:path';
import { execFileSync } from 'node:child_process';
const workspace = process.argv[2];
const vp = path.join(workspace, 'node_modules/.bin/vp');
const vpArgs = ['argument with spaces', 'literal;&value'];
execFileSync(vp, vpArgs, { cwd: workspace, stdio: 'inherit' });
"""
            script = root / 'adapter.mjs'
            script.write_text(adapt_authoring_command('adapter.mjs', source))
            result = subprocess.check_output([shutil.which('node'), script, root], text=True)
            self.assertEqual(result, '["argument with spaces","literal;&value"]')

    @unittest.skipUnless(shutil.which('node'), 'requires authoring Node')
    def test_attestation_uses_the_explicit_verified_npm_cli(self):
        with tempfile.TemporaryDirectory(prefix='studio npm ') as temporary:
            root = Path(temporary).resolve()
            cli = root / 'npm-cli.js'
            cli.write_text("process.stdout.write('12.2.0\\n');")
            source = """import { execFileSync } from 'node:child_process';
const npm = execFileSync('npm', ['--version'], { encoding: 'utf8' }).trim();
process.stdout.write(npm);
"""
            script = root / 'engine.mjs'
            script.write_text(adapt_authoring_command('engine.mjs', source))
            result = subprocess.check_output([shutil.which('node'), script], text=True,
                                             env={**os.environ, 'npm_execpath': str(cli)})
            self.assertEqual(result, '12.2.0')

    @unittest.skipUnless(shutil.which('node'), 'requires authoring Node')
    def test_vite_config_imports_resolved_modules_as_file_urls(self):
        with tempfile.TemporaryDirectory(prefix='studio config # ') as temporary:
            root = Path(temporary).resolve()
            module = root / 'plugin # %.mjs'
            module.write_text('export default 42;')
            source = CONFIG_FIXTURE + """const engineRequire = { resolve: () => process.argv[2] };
const tailwind = await import(engineRequire.resolve('@tailwindcss/vite'))
process.stdout.write(String(tailwind.default));
"""
            script = root / 'vite.config.mjs'
            script.write_text(adapt_authoring_command('vite.config.mjs', source))
            result = subprocess.check_output([shutil.which('node'), script, module], text=True)
            self.assertEqual(result, '42')

    @unittest.skipUnless(shutil.which('node'), 'requires authoring Node')
    def test_vite_resolvers_use_the_same_paths_for_windows_and_vite_ids(self):
        checks = r"""
import assert from 'node:assert/strict';
const engineRequire = { resolve: () => process.argv[2] };
const tailwind = await import(engineRequire.resolve('@tailwindcss/vite'));
const forward = value => value.replaceAll('\\', '/');
const importer = forward(here) + '/src/editor-frame.tsx';
const resolver = { resolve: async (source, from) => ({ id: source, importer: from }) };
const react = await resolveFromEngine.call(resolver, 'react', importer, {});
assert.equal(react?.id, 'react');
assert.equal(react.importer, forward(engine) + '/src/main.tsx');
assert.equal(await resolveFromEngine.call(resolver, 'react', forward(engine) + '/src/main.tsx', {}), null);
const persistence = { resolve: async () => ({ id: forward(persistenceModule) }) };
assert.equal(await gatePersistence.call(persistence, 'timeline-persistence', importer, {}), persistenceShim);
assert.equal(await gatePersistence.call(persistence, 'timeline-persistence', forward(persistenceShim), {}), null);
assert.equal(await gatePersistence.call({resolve: async () => null}, 'timeline-persistence', importer, {}), null);
const workspace = { resolve: async () => ({ id: forward(upstreamWorkspaceDouble) }) };
assert.equal(await workspaceDouble.call(workspace, 'in-memory-handle', importer, {}), adapterWorkspaceDouble);
assert.equal(await workspaceDouble.call({resolve: async () => null}, 'in-memory-handle', importer, {}), null);
"""
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / 'config.mjs'
            script.write_text(adapt_authoring_command('vite.config.mjs', CONFIG_FIXTURE + checks))
            module = Path(temporary) / 'plugin.mjs'
            module.write_text('export default 42;')
            result = subprocess.run([shutil.which('node'), script, module], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_changed_authoring_inputs_are_rejected_before_any_rewrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            tools = root / 'studio/tools'
            tools.mkdir(parents=True)
            for name in ['engine.mjs', 'adapter.mjs']:
                (tools / name).write_bytes(b'changed source')
            with self.assertRaises(BuildError):
                bind_authoring_commands(root)
            self.assertTrue(all(p.read_bytes() == b'changed source' for p in tools.iterdir()))
        for name, source in [('unknown.mjs', ''), ('adapter.mjs', ''), ('engine.mjs', ''),
                             ('engine.mjs', "execFileSync('npm', ['--version'], " * 2)]:
            with self.subTest(name=name), self.assertRaises(BuildError):
                adapt_authoring_command(name, source)
