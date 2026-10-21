import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from build_runtime import BuildError
from build_host_studio import adapt_authoring_command, bind_authoring_commands


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
