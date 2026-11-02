import ctypes
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from windows_private_directory import create_private_directory, _windows_private_directory


class PrivateDirectoryTests(unittest.TestCase):
    def test_creation_is_private_and_never_replaces_existing_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'private'
            create_private_directory(root)
            if os.name != 'nt':
                self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            sentinel = root / 'sentinel'
            sentinel.write_text('retained')
            with self.assertRaises(FileExistsError):
                create_private_directory(root)
            self.assertEqual(sentinel.read_text(), 'retained')

    def test_windows_uses_inheritable_explicit_user_ace_at_creation(self):
        sid = 'S-1-5-21-1-2-3-1001'
        security = SimpleNamespace(ConvertStringSecurityDescriptorToSecurityDescriptorW=Mock(return_value=True))
        kernel = SimpleNamespace(CreateDirectoryW=Mock(return_value=True), LocalFree=Mock(return_value=None))
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {'SystemRoot': temporary}), patch(
            'windows_private_directory.subprocess.check_output', return_value=f'"runner","{sid}"\n'
        ), patch('windows_private_directory.ctypes.WinDLL', side_effect=[security, kernel], create=True):
            _windows_private_directory(Path(temporary) / 'private')
        sddl = security.ConvertStringSecurityDescriptorToSecurityDescriptorW.call_args.args[0]
        self.assertEqual(sddl, f'O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})')
        attributes = kernel.CreateDirectoryW.call_args.args[1]._obj
        self.assertFalse(attributes.inherit)
        kernel.LocalFree.assert_called_once()

    def test_invalid_identity_refuses_creation_before_loading_windows_apis(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {'SystemRoot': temporary}), patch(
            'windows_private_directory.ctypes.WinDLL', create=True
        ) as api:
            for identity in ['', 'not,csv', '"runner","S-1-5-18"', '"runner","S-1-5-21-1-2-3-1001)(A;;FA;;;WD)"']:
                with self.subTest(identity=identity), patch('windows_private_directory.subprocess.check_output', return_value=identity):
                    with self.assertRaisesRegex(ValueError, 'identity_invalid'):
                        _windows_private_directory(Path(temporary) / 'private')
            api.assert_not_called()


if __name__ == '__main__':
    unittest.main()
