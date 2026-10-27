import hashlib
import io
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import prepare_windows_host_qualification as prepare
from build_runtime import BuildError


class WindowsHostQualificationTests(unittest.TestCase):
    def fixture(self, root):
        candidate = root / 'bundle'
        (candidate / 'payload/ml').mkdir(parents=True)
        ml = candidate / 'payload/ml/manifest.json'
        ml.write_bytes(b'{}')
        manifest = {'sourceRevision': prepare.SOURCE, 'platform': 'windows',
                    'architecture': 'x86_64', 'epoch': 18}
        (candidate / 'manifest.json').write_text(json.dumps(manifest))
        (candidate / 'manifest.sig').write_bytes(b'x' * 64)
        digest = hashlib.sha256((candidate / 'manifest.json').read_bytes()).hexdigest()
        ml_digest = hashlib.sha256(ml.read_bytes()).hexdigest()
        report = {'qualification': 'passed', 'sourceRevision': prepare.SOURCE,
                  'manifestSha256': digest, 'signaturePresent': True,
                  'runtimeQualified': False, 'redistributable': False,
                  'ml': {'manifestSha256': ml_digest}}
        (candidate / 'qualification.json').write_text(json.dumps(report))
        checked = {'keyId': 'desktop-release-2026-10', 'manifestSha256': digest,
                   'sourceRevision': prepare.SOURCE, 'epoch': 18, 'certified': False}
        return candidate, report, checked, ml_digest

    def test_signed_candidate_requires_complete_normal_verifier_and_exact_nested_ml(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate, _, checked, ml_digest = self.fixture(root)
            with (patch.object(prepare, 'ML_MANIFEST', ml_digest),
                  patch.object(prepare, 'run', return_value=json.dumps(checked)) as run):
                self.assertEqual(prepare.admit(candidate, root / 'node.exe', {}), checked)
            self.assertIn('verifySignedHostCandidate', run.call_args.args[0][3])
            self.assertEqual((candidate / 'manifest.sig').read_bytes(), b'x' * 64)
            (candidate / 'payload/ml/manifest.json').write_bytes(b'changed')
            with (patch.object(prepare, 'ML_MANIFEST', ml_digest), patch.object(prepare, 'run') as run,
                  self.assertRaises(BuildError)):
                prepare.admit(candidate, root / 'node.exe', {})
            run.assert_not_called()

    def test_wrong_receipts_and_stale_source_fail_before_verifier(self):
        for change in [{'signaturePresent': False}, {'runtimeQualified': True}, {'redistributable': True},
                       {'manifestSha256': 'a' * 64}, {'sourceRevision': 'f' * 40}]:
            with tempfile.TemporaryDirectory() as temporary, self.subTest(change=change):
                root = Path(temporary)
                candidate, report, _, ml_digest = self.fixture(root)
                (candidate / 'qualification.json').write_text(json.dumps({**report, **change}))
                with (patch.object(prepare, 'ML_MANIFEST', ml_digest), patch.object(prepare, 'run') as run,
                      self.assertRaises(BuildError)):
                    prepare.admit(candidate, root / 'node.exe', {})
                run.assert_not_called()

    def test_existing_output_is_preserved_before_download_or_acl_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / 'marker'; marker.write_text('preserved')
            with (patch.object(prepare.platform, 'system', return_value='Windows'),
                  patch.object(prepare.platform, 'machine', return_value='AMD64'),
                  patch.object(prepare, 'create_probe_directory') as create,
                  patch.object(prepare, 'api') as api, self.assertRaises(BuildError)):
                prepare.prepare(root, '1', 'a' * 64)
            create.assert_not_called(); api.assert_not_called()
            self.assertEqual(marker.read_text(), 'preserved')

    def test_only_exact_private_draft_asset_bytes_reach_admission(self):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, 'w') as archive:
            archive.writestr('bundle/manifest.json', '{}')
        data = raw.getvalue(); digest = hashlib.sha256(data).hexdigest()
        for case in ['valid', 'public', 'published', 'wrong-name', 'wrong-digest', 'download-failed', 'corrupt']:
            with tempfile.TemporaryDirectory() as temporary, self.subTest(case=case):
                root = Path(temporary)
                node = root / 'node.exe'; node.write_bytes(b'trusted-authoring-node-fixture')
                asset = {'id': 1, 'name': prepare.ASSET_NAME, 'state': 'uploaded',
                         'size': len(data), 'digest': 'sha256:' + digest}
                if case == 'wrong-name': asset['name'] = 'unrelated.zip'
                if case == 'wrong-digest': asset['digest'] = 'sha256:' + 'f' * 64
                def api(path):
                    return {'private': case != 'public'} if path == '' else {
                        'id': prepare.RELEASE_ID, 'draft': case != 'published', 'assets': [asset]}
                def download(arguments, **kwargs):
                    if case == 'download-failed': raise subprocess.CalledProcessError(1, arguments)
                    kwargs['stdout'].write(data[:-1] + b'x' if case == 'corrupt' else data)
                    return SimpleNamespace(returncode=0)
                with (patch.object(prepare.platform, 'system', return_value='Windows'),
                      patch.object(prepare.platform, 'machine', return_value='AMD64'),
                      patch.object(prepare.shutil, 'which', return_value=str(node)),
                      patch.object(prepare, 'NODE_SHA256', hashlib.sha256(node.read_bytes()).hexdigest()),
                      patch.object(prepare, 'create_probe_directory', side_effect=lambda path: path.mkdir()),
                      patch.object(prepare, 'api', side_effect=api),
                      patch.object(prepare.subprocess, 'run', side_effect=download) as transfer,
                      patch.object(prepare, 'admit', return_value={'manifestSha256': 'b' * 64}) as admit):
                    if case == 'valid':
                        result = prepare.prepare(root / 'output', '1', digest)
                        self.assertEqual(result['releaseAssetId'], 1)
                        self.assertFalse(result['compiledLifecycleQualified'])
                        self.assertFalse(result['installedAcceptance'])
                        self.assertFalse((root / 'output/input.zip').exists())
                        admit.assert_called_once()
                    else:
                        with self.assertRaises((BuildError, subprocess.CalledProcessError)):
                            prepare.prepare(root / 'output', '1', digest)
                        admit.assert_not_called()
                        if case not in {'download-failed', 'corrupt'}: transfer.assert_not_called()

    def test_foreign_authority_and_stale_epoch_are_refused(self):
        for change in [{'keyId': 'foreign'}, {'sourceRevision': 'f' * 40}, {'epoch': 17},
                       {'certified': True}, {'manifestSha256': 'a' * 64}]:
            with tempfile.TemporaryDirectory() as temporary, self.subTest(change=change):
                root = Path(temporary)
                candidate, _, checked, ml_digest = self.fixture(root)
                with (patch.object(prepare, 'ML_MANIFEST', ml_digest),
                      patch.object(prepare, 'run', return_value=json.dumps({**checked, **change})),
                      self.assertRaisesRegex(BuildError, 'authority_invalid')):
                    prepare.admit(candidate, root / 'node.exe', {})

    def test_signature_length_is_checked_before_the_verifier(self):
        for signature in [b'', b'x', b'x' * 65]:
            with tempfile.TemporaryDirectory() as temporary, self.subTest(size=len(signature)):
                root = Path(temporary)
                candidate, _, _, ml_digest = self.fixture(root)
                (candidate / 'manifest.sig').write_bytes(signature)
                with (patch.object(prepare, 'ML_MANIFEST', ml_digest), patch.object(prepare, 'run') as run,
                      self.assertRaises(BuildError)):
                    prepare.admit(candidate, root / 'node.exe', {})
                run.assert_not_called()

    def test_manifest_target_and_epoch_are_checked_independently_of_the_receipt(self):
        for change in [{'platform': 'linux'}, {'architecture': 'aarch64'}, {'epoch': 17},
                       {'sourceRevision': 'f' * 40}]:
            with tempfile.TemporaryDirectory() as temporary, self.subTest(change=change):
                root = Path(temporary)
                candidate, report, _, ml_digest = self.fixture(root)
                path = candidate / 'manifest.json'
                path.write_text(json.dumps({**json.loads(path.read_text()), **change}))
                report['manifestSha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                (candidate / 'qualification.json').write_text(json.dumps(report))
                with (patch.object(prepare, 'ML_MANIFEST', ml_digest), patch.object(prepare, 'run') as run,
                      self.assertRaises(BuildError)):
                    prepare.admit(candidate, root / 'node.exe', {})
                run.assert_not_called()
