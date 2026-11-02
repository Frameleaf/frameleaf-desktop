import tempfile
import io
import json
import runpy
import sys
from contextlib import redirect_stdout, redirect_stderr
import unittest
from pathlib import Path
from unittest.mock import patch

from build_runtime import BuildError
from qualify_windows_pe import damaged_imports, qualify
from test_relocate_windows import pe


def fixture():
    data = bytearray(pe()) + bytearray(512)
    data[70:72] = (1).to_bytes(2, 'little')
    # One file-backed section, with three import descriptors (the last is null).
    data[336:340] = (512).to_bytes(4, 'little')
    data[340:344] = (4096).to_bytes(4, 'little')
    data[344:348] = (512).to_bytes(4, 'little')
    data[348:352] = (512).to_bytes(4, 'little')
    data[524:528] = (4200).to_bytes(4, 'little')
    data[544:548] = (4220).to_bytes(4, 'little')
    return bytes(data)


class WindowsPeQualificationTests(unittest.TestCase):
    def test_negative_fixtures_corrupt_only_the_targeted_import_field(self):
        data = fixture()
        malformed, partial = damaged_imports(data)
        self.assertEqual(malformed[:208] + malformed[212:], data[:208] + data[212:])
        self.assertEqual(int.from_bytes(malformed[208:212], 'little'), 0xffff0000)
        self.assertEqual(partial[:544] + partial[548:], data[:544] + data[548:])
        self.assertEqual(int.from_bytes(partial[544:548], 'little'), 0xffff0000)
        self.assertEqual(partial[524:528], data[524:528])

    def test_non_fixture_and_non_file_backed_imports_are_refused(self):
        data = bytearray(fixture())
        for value in [b'not-pe', fixture()[:60], pe(), bytes(data[:530])]:
            with self.subTest(value=value[:4]), self.assertRaises(BuildError):
                damaged_imports(value)
        data[208:212] = (0xffff0000).to_bytes(4, 'little')
        with self.assertRaises(BuildError):
            damaged_imports(bytes(data))

    def test_wrong_platform_refuses_before_creating_or_compiling_anything(self):
        with tempfile.TemporaryDirectory() as temporary, patch('qualify_windows_pe.platform.system', return_value='Darwin'):
            output = Path(temporary) / 'work'
            with self.assertRaisesRegex(BuildError, 'windows_required'):
                qualify(Path(temporary) / 'ucrt64', output)
            self.assertFalse(output.exists())

    def test_missing_tool_produces_a_failed_cli_receipt_without_compiling(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out, err = io.StringIO(), io.StringIO()
            with (patch('platform.system', return_value='Windows'),
                  patch.object(sys, 'argv', ['qualify_windows_pe.py', '--dependencies', str(root / 'ucrt64'), '--work', str(root / 'work')]),
                  patch('subprocess.run') as command,
                  redirect_stdout(out), redirect_stderr(err),
                  self.assertRaises(SystemExit) as failure):
                runpy.run_path(str(Path(__file__).with_name('qualify_windows_pe.py')), run_name='__main__')
            self.assertEqual(failure.exception.code, 1)
            self.assertEqual(json.loads(out.getvalue()), {'qualification': 'failed', 'scope': 'windows-pe-inspector', 'code': 'host_pe_probe_environment_failed'})
            self.assertIn('FileNotFoundError', err.getvalue())
            command.assert_not_called()
            self.assertFalse((root / 'work').exists())
