import json
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_host_exiftool_windows import adapt_exiftool_path, build
from build_runtime import BuildError, inventory


class WindowsExifToolTests(unittest.TestCase):
    source = ('exports.exiftoolPath = exiftoolPath;\n'
              'async function exiftoolPath(logger) { return globalFallback(); }\n'
              '//# sourceMappingURL=ExiftoolPath.js.map\n')

    def test_private_executable_replaces_global_fallback(self):
        result = adapt_exiftool_path(self.source, "39.0.1")
        self.assertIn('../../exiftool-vendored.exe/bin/exiftool.exe', result)
        self.assertIn('Private ExifTool executable is missing', result)
        self.assertNotIn('globalFallback', result)
        self.assertIn('exports.exiftoolPath = exiftoolPath;', result)

    def test_adaptation_preserves_utf8_and_crlf_outside_the_replaced_body(self):
        source = '// Café — vendor notice\r\n' + self.source.replace('\n', '\r\n')
        adapted = adapt_exiftool_path(source, '39.0.1')
        self.assertTrue(adapted.startswith('// Café — vendor notice\r\nexports.exiftoolPath = exiftoolPath;\r\n'))
        self.assertTrue(adapted.endswith('//# sourceMappingURL=ExiftoolPath.js.map\r\n'))
        self.assertNotIn('\n', adapted.replace('\r\n', ''))

    def test_changed_or_already_adapted_source_is_refused(self):
        for source, version in [(self.source, "40.0.0"),
                                (self.source.replace('async function', 'function'), "39.0.1"),
                                (self.source + self.source, "39.0.1"),
                                (adapt_exiftool_path(self.source, "39.0.1"), "39.0.1")]:
            with self.assertRaises(BuildError):
                adapt_exiftool_path(source, version)

    @unittest.skipUnless(shutil.which('node'), 'Node is required for resolver execution')
    def test_resolver_runs_and_refuses_missing_private_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            module = root / 'node_modules/exiftool-vendored/dist/ExiftoolPath.cjs'
            module.parent.mkdir(parents=True)
            executable = root / 'node_modules/exiftool-vendored.exe/bin/exiftool.exe'
            executable.parent.mkdir(parents=True)
            executable.write_text('synthetic resolver fixture; never executed')
            module.write_text('const _fs = require("node:fs"); const _path = require("node:path");\n' +
                              adapt_exiftool_path(self.source, '39.0.1'))
            result = subprocess.run([shutil.which('node'), '-e', '''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const [modulePath, executable] = process.argv.slice(1);
const { exiftoolPath } = require(modulePath);
(async () => {
  assert.equal(await exiftoolPath(), executable);
  fs.renameSync(executable, executable + '.held');
  await assert.rejects(exiftoolPath(), /Private ExifTool executable is missing/);
})().catch(error => { console.error(error); process.exitCode = 1; });
''', str(module), str(executable)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_unqualified_or_wrong_platform_input_is_refused_before_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'input'
            source.mkdir()
            for qualification, target in [('failed', 'Windows-AMD64'), ('passed', 'Darwin-arm64')]:
                (source / 'qualification.json').write_text(json.dumps({
                    'qualification': qualification, 'platform': target, 'files': {'fixture': {}},
                }))
                with patch('platform.system', return_value='Windows'), patch('platform.machine', return_value='AMD64'):
                    with self.assertRaises(BuildError):
                        build(source, root / 'output')
                self.assertFalse((root / 'output').exists())

    def test_missing_or_invalid_revision_is_refused_before_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'input'
            source.mkdir()
            for revision in [None, '', 'not-a-revision', True]:
                (source / 'qualification.json').write_text(json.dumps({
                    'qualification': 'passed', 'platform': 'Windows-AMD64',
                    'files': {'fixture': {}}, 'sourceRevision': revision,
                }))
                with patch('platform.system', return_value='Windows'), patch('platform.machine', return_value='AMD64'):
                    with self.assertRaises(BuildError):
                        build(source, root / 'output')
                self.assertFalse((root / 'output').exists())

    def test_altered_input_inventory_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'input'
            (source / 'server').mkdir(parents=True)
            (source / 'server/fixture').write_text('original')
            receipt = {'qualification': 'passed', 'platform': 'Windows-AMD64',
                       'sourceRevision': 'a' * 40, 'files': inventory(source / 'server')}
            (source / 'qualification.json').write_text(json.dumps(receipt))
            (source / 'server/fixture').write_text('changed')
            with patch('platform.system', return_value='Windows'), patch('platform.machine', return_value='AMD64'):
                with self.assertRaisesRegex(BuildError, 'host_exiftool_input_inventory_mismatch'):
                    build(source, root / 'output')
            self.assertEqual(json.loads((root / 'output/qualification.json').read_text())['qualification'], 'failed')

    def test_complete_staging_and_vendor_guards(self):
        for problem in [None, 'version', 'module', 'runtime', 'license_directory']:
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / 'input'
                vendor = source / 'server/node_modules/exiftool-vendored'
                executable = source / 'server/node_modules/exiftool-vendored.exe'
                (vendor / 'dist').mkdir(parents=True)
                executable.mkdir()
                (vendor / 'package.json').write_text('{"version":"39.0.1"}')
                (vendor / 'dist/ExiftoolPath.js').write_bytes(self.source.encode('utf-8'))
                (executable / 'package.json').write_text(json.dumps({'version': '0.0.0' if problem == 'version' else '13.59.3'}))
                for name in ['bin/exiftool.exe', 'bin/exiftool_files/perl.exe', 'bin/exiftool_files/perl532.dll',
                             'bin/exiftool_files/lib/Image/ExifTool.pm', 'LICENSE', 'bin/exiftool_files/LICENSE']:
                    path = executable / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('synthetic private resource')
                (executable / 'extra-private-resource').write_text('preserved')
                if problem == 'license_directory':
                    (executable / 'LICENSE').unlink()
                    (executable / 'LICENSE').mkdir()
                if problem == 'runtime':
                    (executable / 'bin/exiftool_files/perl532.dll').unlink()
                (source / 'qualification.json').write_text(json.dumps({
                    'qualification': 'passed', 'platform': 'Windows-AMD64', 'sourceRevision': 'a' * 40,
                    'files': inventory(source / 'server'),
                }))
                expected = hashlib.sha256(self.source.encode()).hexdigest() if problem != 'module' else '0' * 64
                with patch('platform.system', return_value='Windows'), patch('platform.machine', return_value='AMD64'), \
                     patch('build_host_exiftool_windows.VENDOR_MODULE_SHA256', expected):
                    if problem:
                        with self.assertRaises((BuildError, OSError)):
                            build(source, root / 'output')
                    else:
                        original_read = Path.read_text
                        original_write = Path.write_text
                        def read_utf8(path, *args, **kwargs):
                            self.assertEqual(kwargs.get('encoding'), 'utf-8')
                            return original_read(path, *args, **kwargs)
                        def write_utf8(path, *args, **kwargs):
                            self.assertEqual(kwargs.get('encoding'), 'utf-8')
                            self.assertEqual(kwargs.get('newline'), '\n')
                            return original_write(path, *args, **kwargs)
                        with patch.object(Path, 'read_text', read_utf8), patch.object(Path, 'write_text', write_utf8):
                            build(source, root / 'output')
                        report = json.loads((root / 'output/qualification.json').read_text())
                        self.assertEqual(report['qualification'], 'passed')
                        self.assertEqual(report['originalModuleSha256'], expected)
                        self.assertNotEqual(report['adaptedModuleSha256'], expected)
                        self.assertIn('node_modules/exiftool-vendored.exe/extra-private-resource', report['files']['server'])
                        self.assertEqual((vendor / 'dist/ExiftoolPath.js').read_text(), self.source)
