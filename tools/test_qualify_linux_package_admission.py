import importlib.util
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name('qualify_linux_package_admission.py')
SPEC = importlib.util.spec_from_file_location('linux_admission', PATH)
admission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admission)


class AdmissionGuardTests(unittest.TestCase):
    def test_only_root_on_hosted_linux_is_admitted(self):
        env = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted'}
        with patch.dict(admission.os.environ, env, clear=True):
            admission.require_hosted_linux('Linux', 0, 0)
            for system, uid, euid in [('Darwin', 0, 0), ('Windows', 0, 0), ('Linux', 1000, 0), ('Linux', 0, 1000)]:
                with self.subTest(system=system, uid=uid, euid=euid):
                    with self.assertRaises(RuntimeError):
                        admission.require_hosted_linux(system, uid, euid)

    def test_local_and_self_hosted_environments_refuse(self):
        for env in [{}, {'GITHUB_ACTIONS': 'true'}, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted'}]:
            with patch.dict(admission.os.environ, env, clear=True):
                with self.assertRaises(RuntimeError):
                    admission.require_hosted_linux('Linux', 0, 0)

    def test_guard_runs_before_binary_or_fixed_path_access(self):
        with patch.dict(admission.os.environ, {}, clear=True), patch.object(admission, 'qualify') as qualify:
            with self.assertRaises(RuntimeError):
                admission.main(['missing-binary'])
            qualify.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'Linux qualification uses POSIX leases')
    def test_existing_namespace_is_never_adopted_or_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'frameleaf'
            base.mkdir()
            sentinel = base / 'keep'
            sentinel.write_bytes(b'existing installation')
            with patch.object(admission, 'BASE', base), patch.object(admission.subprocess, 'run') as run:
                with self.assertRaises(FileExistsError):
                    admission.qualify(__file__)
                run.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b'existing installation')

    @unittest.skipUnless(os.name == 'posix', 'Linux qualification uses POSIX leases')
    def test_failed_fixture_cleans_only_the_namespace_it_created(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'frameleaf'
            sibling = Path(directory) / 'keep'
            sibling.write_bytes(b'outside fixture')
            with patch.object(admission, 'BASE', base), patch.object(admission.subprocess, 'run', side_effect=RuntimeError('probe failed')):
                with self.assertRaisesRegex(RuntimeError, 'probe failed'):
                    admission.qualify(__file__)
            self.assertFalse(base.exists())
            self.assertEqual(sibling.read_bytes(), b'outside fixture')


if __name__ == '__main__':
    unittest.main()
