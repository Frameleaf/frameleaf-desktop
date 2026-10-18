import importlib.util
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('deb_lifecycle', Path(__file__).with_name('qualify_linux_deb_lifecycle.py'))
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

class LifecycleGuardTests(unittest.TestCase):
    def test_local_execution_refuses_before_fixed_paths_or_dpkg(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(module, 'qualify') as qualify:
            with self.assertRaises(RuntimeError):
                module.main(['missing-binary'])
            qualify.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'Linux fixture uses POSIX leases')
    def test_existing_namespace_is_preserved_without_package_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'frameleaf'
            base.mkdir()
            keep = base / 'keep'
            keep.write_bytes(b'existing installation')
            with patch.object(module, 'BASE', base), patch.object(module.subprocess, 'run') as run:
                with self.assertRaises(FileExistsError):
                    module.qualify(__file__)
                run.assert_not_called()
            self.assertEqual(keep.read_bytes(), b'existing installation')

    @unittest.skipUnless(os.name == 'posix', 'Linux fixture uses POSIX leases')
    def test_failed_staging_cleans_only_the_namespace_created_by_this_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'frameleaf'
            sibling = Path(directory) / 'keep'
            sibling.write_bytes(b'outside fixture')
            with patch.object(module, 'BASE', base), patch.object(module.platform, 'machine', return_value='x86_64'), patch.object(module, 'stage_packages', side_effect=RuntimeError('fixture refused')):
                with self.assertRaisesRegex(RuntimeError, 'fixture refused'):
                    module.qualify(__file__)
            self.assertFalse(base.exists())
            self.assertEqual(sibling.read_bytes(), b'outside fixture')

    def test_qualification_requires_native_failure_receipt_not_any_dpkg_error(self):
        module.require_failure('dpkg output\n{"protocolVersion":1,"state":"failed","code":"host_signature_invalid"}\n', 'host_signature_invalid')
        for output in ['', 'host_signature_invalid', '{"state":"failed","code":"native_manager_unprotected"}', '{"state":"ready","code":"host_signature_invalid"}']:
            with self.subTest(output=output), self.assertRaises(AssertionError):
                module.require_failure(output, 'host_signature_invalid')
