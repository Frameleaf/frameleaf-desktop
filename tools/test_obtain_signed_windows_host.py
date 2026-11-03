import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from build_host_ffmpeg import unpack
from build_runtime import BuildError
from obtain_signed_windows_host import obtain


class SignedWindowsHostTests(unittest.TestCase):
    def policy(self):
        candidate = {'artifactId': 1, 'runId': 5, 'runAttempt': 1, 'headSha': 'a' * 40,
                     'archiveSha256': 'b' * 64, 'workflow': '.github/workflows/windows-host-signing.yml'}
        return {'candidate': candidate, 'evidence': {**candidate, 'artifactId': 2}}

    def producer(self, approved):
        return {'approved': approved, 'artifact': {
            'id': approved['artifactId'], 'expired': False, 'size_in_bytes': 1,
            'created_at': '2026-11-03T06:01:00Z', 'digest': 'sha256:' + approved['archiveSha256'],
            'workflow_run': {'id': approved['runId'], 'head_sha': approved['headSha'],
                             'repository_id': 1421136454, 'head_repository_id': 1421136454}},
            'run': {'id': approved['runId'], 'head_sha': approved['headSha'],
                    'run_attempt': approved['runAttempt'], 'path': approved['workflow'],
                    'head_branch': 'main', 'event': 'workflow_dispatch', 'status': 'completed',
                    'conclusion': 'success', 'run_started_at': '2026-11-03T06:00:00Z',
                    'updated_at': '2026-11-03T06:02:00Z',
                    'repository': {'id': 1421136454, 'full_name': 'Frameleaf/frameleaf-desktop'},
                    'head_repository': {'id': 1421136454, 'full_name': 'Frameleaf/frameleaf-desktop'}}}

    def fixture(self, root, mutate=None, producer_change=None):
        policy = self.policy()
        manifest = {'schemaVersion': 1, 'protocolVersion': 2, 'platform': 'windows',
                    'architecture': 'x86_64', 'epoch': 18, 'certified': False,
                    'sourceRevision': '9118a01fdfb8a8cd20be24290660679b3a7c4de3',
                    'files': {'fixture': {'bytes': 7, 'sha256': hashlib.sha256(b'fixture').hexdigest()}}}
        raw, signature = json.dumps(manifest).encode(), b's' * 64
        unsigned = {'schemaVersion': 1, 'qualification': 'passed', 'sourceRevision': manifest['sourceRevision'],
                    'manifestSha256': hashlib.sha256(raw).hexdigest(), 'manifestBytes': len(raw),
                    'files': 1, 'signaturePresent': False, 'runtimeQualified': False, 'redistributable': False}
        original = {**policy['candidate'], 'artifactId': 3, 'runId': 6, 'headSha': 'c' * 40,
                    'workflow': '.github/workflows/windows-host-assembly.yml'}
        signed = {'keyId': 'unit-fixture-not-trust-authority', 'manifestSha256': unsigned['manifestSha256'],
                  'signatureSha256': hashlib.sha256(signature).hexdigest(),
                  'sourceRevision': manifest['sourceRevision'], 'epoch': 18, 'certified': False}
        proof = {'schemaVersion': 1, **signed, 'approvedProducer': original, 'signaturePresent': True,
                 'runtimeQualified': False, 'redistributable': False,
                 'installedPlatformQualified': False, 'fullMediaConformance': False}
        controls = {'manifest.json': raw, 'manifest.sig': signature,
                    'qualification.json': json.dumps(unsigned).encode()}
        candidate = {'payload/fixture': b'fixture', **controls}
        evidence = {'candidate/' + k: v for k, v in controls.items()}
        evidence.update({'signature.json': json.dumps(signed).encode(),
                         'signature-verification.json': json.dumps(proof).encode(),
                         'producer.json': json.dumps(self.producer(original)).encode()})
        if mutate:
            mutate(candidate, evidence)
        tar_bytes = io.BytesIO()
        with tarfile.open(fileobj=tar_bytes, mode='w:gz') as tar:
            for name, data in candidate.items():
                item = tarfile.TarInfo(name); item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
        zipped = {}
        for role, files in [('candidate', {'windows-complete-host-signed.tar.gz': tar_bytes.getvalue()}),
                            ('evidence', evidence)]:
            path = root / (role + '.zip')
            with zipfile.ZipFile(path, 'w') as archive:
                for name, data in files.items():
                    archive.writestr(name, data)
            zipped[role] = path

        def acquire(approved, output):
            role = 'candidate' if approved['artifactId'] == 1 else 'evidence'
            self.assertEqual(approved, policy[role])
            output.mkdir(); (output / 'component').mkdir()
            unpack(zipped[role], output / 'component')
            producer = self.producer(approved)
            if producer_change:
                producer_change(producer)
            (output / 'producer.json').write_text(json.dumps(producer))
        return policy, acquire, candidate, evidence

    def test_actual_zip_tar_pair_preserves_original_controls_and_stages_without_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            policy, acquire, candidate, evidence = self.fixture(root)
            with patch('obtain_signed_windows_host.obtain_component', side_effect=acquire) as mocked:
                obtain(policy, root / 'out')
            self.assertEqual(mocked.call_count, 2)
            for name, data in candidate.items():
                self.assertEqual((root / 'out/candidate' / name).read_bytes(), data)
            for name, data in evidence.items():
                self.assertEqual((root / 'out/signature-evidence' / name).read_bytes(), data)
            staged = json.loads((root / 'out/qualification.json').read_bytes())
            self.assertEqual(staged['state'], 'signed-resources-staged')
            self.assertFalse(staged['runtimeQualified'])
            self.assertNotIn('hostSignatureVerified', staged)
            self.assertEqual({p.name for p in (root / 'out').iterdir()}, {
                'candidate', 'signature-evidence', 'candidate-producer.json',
                'evidence-producer.json', 'qualification.json'})

    def test_mismatched_pair_policy_is_refused_before_requests_or_output_creation(self):
        policies = [None, {}, {'candidate': self.policy()['candidate']}]
        for field, value in [('artifactId', 1), ('runId', 7), ('runAttempt', 2), ('headSha', 'd' * 40),
                             ('workflow', '.github/workflows/other.yml'), ('archiveSha256', 'bad')]:
            policy = copy.deepcopy(self.policy()); policy['evidence'][field] = value
            policies.append(policy)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for policy in policies:
                with self.subTest(policy=policy), patch('obtain_signed_windows_host.obtain_component') as acquire:
                    with self.assertRaises(BuildError): obtain(policy, root / 'out')
                    acquire.assert_not_called(); self.assertFalse((root / 'out').exists())

    def test_changed_evidence_controls_flags_or_unsafe_entries_are_refused_and_cleaned(self):
        def proof_field(field, value):
            def change(candidate, evidence):
                proof = json.loads(evidence['signature-verification.json'])
                proof[field] = value; evidence['signature-verification.json'] = json.dumps(proof).encode()
            return change
        changes = [proof_field(k, v) for k, v in [
            ('manifestSha256', 'f' * 64), ('signatureSha256', 'f' * 64), ('epoch', 19),
            ('sourceRevision', 'c' * 40), ('schemaVersion', True), ('signaturePresent', False),
            ('runtimeQualified', True), ('redistributable', True), ('installedPlatformQualified', True),
            ('fullMediaConformance', True), ('approvedProducer', self.policy()['candidate']),
            ('approvedProducer', {**self.policy()['candidate'], 'artifactId': 3, 'runId': 6,
                'headSha': 'c' * 40, 'workflow': '.github/workflows/windows-host-assembly.yml',
                'runAttempt': True})]]
        changes += [lambda c, e: c.update({'manifest.sig': b'x' * 64}),
                    lambda c, e: e.pop('candidate/manifest.json'),
                    lambda c, e: e.update({'extra': b'foreign'}),
                    lambda c, e: c.update({'../escape': b'foreign'}),
                    lambda c, e: c.update({'payload/FIXTURE': b'foreign'}),
                    lambda c, e: e.update({'signature-verification.json': b'x' * 16385})]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                policy, acquire, _, _ = self.fixture(root, change)
                with patch('obtain_signed_windows_host.obtain_component', side_effect=acquire), self.assertRaises(BuildError):
                    obtain(policy, root / 'out')
                self.assertFalse((root / 'out').exists()); self.assertFalse((root / 'escape').exists())

    def test_wrong_producer_branch_or_event_is_refused(self):
        for field, value in [('head_branch', 'unreviewed'), ('event', 'pull_request'), ('conclusion', 'failure')]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                policy, acquire, _, _ = self.fixture(root, producer_change=lambda p: p['run'].update({field: value}))
                with patch('obtain_signed_windows_host.obtain_component', side_effect=acquire), self.assertRaises(BuildError):
                    obtain(policy, root / 'out')
                self.assertFalse((root / 'out').exists())

    def test_foreign_output_is_preserved_and_cleanup_failure_keeps_primary_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); out = root / 'out'; out.mkdir()
            (out / 'foreign').write_bytes(b'preserve')
            with patch('obtain_signed_windows_host.obtain_component') as acquire, self.assertRaises(BuildError):
                obtain(self.policy(), out)
            acquire.assert_not_called(); self.assertEqual((out / 'foreign').read_bytes(), b'preserve')
            primary = BuildError('host_component_producer_mismatch')
            with patch('obtain_signed_windows_host.obtain_component', side_effect=primary), patch(
                'obtain_signed_windows_host.shutil.rmtree', side_effect=OSError('cleanup unavailable')
            ), self.assertRaises(BuildError) as caught:
                obtain(self.policy(), root / 'new')
            self.assertIs(caught.exception, primary)
            self.assertIn('cleanup unavailable', '\n'.join(primary.__notes__))
