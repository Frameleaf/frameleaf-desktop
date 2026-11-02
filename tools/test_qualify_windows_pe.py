import tempfile
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
