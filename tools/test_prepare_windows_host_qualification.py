import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import prepare_windows_host_qualification as prepare
from build_runtime import BuildError


class WindowsHostQualificationTests(unittest.TestCase):
    def test_prepare_binds_the_full_host_producer_and_explicit_archive_limit(self):
        for name in ['frameleaf-windows-unsigned-full-host-candidate', 'unrelated']:
            with tempfile.TemporaryDirectory() as temporary, self.subTest(name=name):
                root = Path(temporary)
                candidate, _, verified = self.fixture(root)
                with (patch.object(prepare.platform, 'system', return_value='Windows'),
                      patch.object(prepare.platform, 'machine', return_value='AMD64'),
                      patch.object(prepare.shutil, 'which', return_value=str(root / 'node.exe')),
                      patch.object(prepare, 'sha256', return_value='a619e2e09eb0d50ef4c733d678b4d22689d2afef138cd67fd3fa107b535f8819'),
                      patch.object(prepare, 'api', return_value={'name': name, 'workflow_run': {'id': 55}}),
                      patch.object(prepare, 'obtain', return_value=root) as obtain,
                      patch.object(prepare, 'admit', return_value=verified) as admit):
                    if name == 'unrelated':
                        with self.assertRaises(BuildError):
                            prepare.prepare(root / 'output', '1', 'b' * 64, 'c' * 40, 'ab' * 64)
                        obtain.assert_not_called()
                        admit.assert_not_called()
                    else:
                        result = prepare.prepare(root / 'output', '1', 'b' * 64, 'c' * 40, 'ab' * 64)
                        self.assertFalse(result['compiledLifecycleQualified'])
                        self.assertFalse(result['installedAcceptance'])
                        self.assertEqual(obtain.call_args.args, (root / 'output', 'input', 1, 'b' * 64, 55, 'c' * 40))
                        self.assertEqual(obtain.call_args.kwargs, {'maximum_bytes': 12 * 1024**3})
                        self.assertEqual(admit.call_args.args[0], candidate)

    def fixture(self, root):
        candidate = root / 'bundle'
        candidate.mkdir()
        manifest = {'sourceRevision': prepare.SOURCE, 'platform': 'windows',
                    'architecture': 'x86_64', 'epoch': 16}
        (candidate / 'manifest.json').write_text(json.dumps(manifest))
        digest = hashlib.sha256((candidate / 'manifest.json').read_bytes()).hexdigest()
        report = {'qualification': 'passed', 'sourceRevision': prepare.SOURCE,
                  'manifestSha256': digest, 'signaturePresent': False,
                  'runtimeQualified': False, 'redistributable': False,
                  'ml': {'manifestSha256': prepare.ML_MANIFEST}}
        (candidate / 'qualification.json').write_text(json.dumps(report))
        verified = {'keyId': 'desktop-release-2026-10', 'manifestSha256': digest,
                    'sourceRevision': prepare.SOURCE, 'epoch': 16, 'certified': False}
        return candidate, report, verified

    def test_signature_and_complete_inventory_verifier_precede_any_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate, _, verified = self.fixture(root)
            with patch.object(prepare, 'run', return_value=json.dumps(verified)) as run:
                self.assertEqual(prepare.admit(candidate, 'ab' * 64, root / 'node.exe', {}), verified)
            self.assertEqual((candidate / 'manifest.sig').read_bytes(), bytes.fromhex('ab' * 64))
            arguments = run.call_args.args[0]
            self.assertEqual(arguments[0], root / 'node.exe')
            self.assertIn('verifySignedHostCandidate', arguments[3])
            self.assertNotIn(str(candidate / 'payload/node.exe'), map(str, arguments))
            with self.assertRaises(FileExistsError):
                prepare.admit(candidate, 'ab' * 64, root / 'node.exe', {})

    def test_wrong_component_receipts_fail_before_signature_write_or_verifier(self):
        for field, value in [('qualification', 'failed'), ('sourceRevision', 'a' * 40),
                             ('signaturePresent', True), ('runtimeQualified', True),
                             ('redistributable', True), ('manifestSha256', 'b' * 64),
                             ('ml', {'manifestSha256': 'c' * 64})]:
            with tempfile.TemporaryDirectory() as temporary, self.subTest(field=field):
                candidate, report, _ = self.fixture(Path(temporary))
                (candidate / 'qualification.json').write_text(json.dumps(report | {field: value}))
                with patch.object(prepare, 'run') as run, self.assertRaises(BuildError):
                    prepare.admit(candidate, 'ab' * 64, Path('/unused'), {})
                run.assert_not_called()
                self.assertFalse((candidate / 'manifest.sig').exists())

    def test_invalid_signature_and_untrusted_verifier_result_are_refused(self):
        for signature in ['', 'aa', 'AB' * 64, '../outside']:
            with tempfile.TemporaryDirectory() as temporary:
                candidate, _, _ = self.fixture(Path(temporary))
                with patch.object(prepare, 'run') as run, self.assertRaises(BuildError):
                    prepare.admit(candidate, signature, Path('/unused'), {})
                run.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            candidate, _, verified = self.fixture(Path(temporary))
            with (patch.object(prepare, 'run', return_value=json.dumps(verified | {'keyId': 'fixture'})),
                  self.assertRaises(BuildError)):
                prepare.admit(candidate, 'ab' * 64, Path('/unused'), {})
