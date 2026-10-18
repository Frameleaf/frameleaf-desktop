import importlib.util
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

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

    @unittest.skipUnless(os.name == 'posix', 'Linux qualification uses POSIX permissions')
    def test_bootstrap_ancestors_are_protected_with_a_shared_runner_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'frameleaf'
            calls = 0

            def invoke(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return SimpleNamespace(returncode=1, stdout='{"state":"failed","code":"missing"}')
                self.assertEqual((base / 'Bootstrap').stat().st_mode & 0o777, 0o755)
                directories = list((base / 'Bootstrap').iterdir())
                self.assertEqual(len(directories), 1)
                self.assertEqual(directories[0].stat().st_mode & 0o777, 0o755)
                raise RuntimeError('stop_after_metadata')

            previous = os.umask(0o002)
            try:
                with patch.object(admission, 'BASE', base), patch.object(admission.subprocess, 'run', side_effect=invoke):
                    with self.assertRaisesRegex(RuntimeError, 'stop_after_metadata'):
                        admission.qualify(__file__)
            finally:
                os.umask(previous)
            self.assertFalse(base.exists())

    @unittest.skipUnless(os.name == 'posix', 'Linux qualification uses POSIX permissions')
    def test_cli_protects_later_fixture_files_and_restores_umask_on_success_or_failure(self):
        for failure in [False, True]:
            with tempfile.TemporaryDirectory() as directory:
                def fixture(_binary):
                    for name in ['installation.json', 'retained-data', 'controller']:
                        path = Path(directory) / name
                        path.write_bytes(b'synthetic fixture')
                        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
                    if failure:
                        raise RuntimeError('fixture_failed')

                previous = os.umask(0o002)
                try:
                    with patch.object(admission, 'require_hosted_linux'), patch.object(admission, 'qualify', side_effect=fixture):
                        if failure:
                            with self.assertRaisesRegex(RuntimeError, 'fixture_failed'):
                                admission.main(['synthetic-controller'])
                        else:
                            admission.main(['synthetic-controller'])
                    self.assertEqual(os.umask(0o002), 0o002)
                finally:
                    os.umask(previous)


if __name__ == '__main__':
    unittest.main()
