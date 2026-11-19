import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from build_runtime import BuildError
from build_host_ffmpeg import unpack
from obtain_windows_host_candidate import obtain


class WindowsHostCandidateTests(unittest.TestCase):
    def fixture(self, root, change=None, extra=None, payload_file=False):
        manifest = {'platform': 'windows', 'architecture': 'x86_64',
                    'sourceRevision': '9f22a57adb7a271d97ead305103c094fb3d25ad2',
                    'files': {'fixture': {'bytes': 7, 'sha256': hashlib.sha256(b'fixture').hexdigest()}}}
        raw = json.dumps(manifest).encode()
        receipt = {'schemaVersion': 1, 'qualification': 'passed',
                   'sourceRevision': manifest['sourceRevision'], 'files': 1,
                   'manifestBytes': len(raw), 'manifestSha256': hashlib.sha256(raw).hexdigest(),
                   'signaturePresent': False, 'runtimeQualified': False, 'redistributable': False}
        if change:
            receipt.update(change)
        archive = root / 'windows-complete-host.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            files = {'payload/fixture': b'fixture', 'manifest.json': raw,
                     'qualification.json': json.dumps(receipt).encode()}
            if payload_file:
                del files['payload/fixture']
                files['payload'] = b'fixture'
            if extra:
                files.update(extra)
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return archive, raw, receipt

    def test_refuses_file_as_payload_before_signing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive, _, _ = self.fixture(root, payload_file=True)
            pin = {'artifactId': 123, 'runId': 456, 'runAttempt': 1, 'headSha': 'a' * 40,
                   'archiveSha256': 'b' * 64, 'workflow': '.github/workflows/windows-host-assembly.yml'}
            def acquire(_, target):
                target.mkdir()
                (target / 'component').mkdir()
                shutil.copyfile(archive, target / 'component' / archive.name)
                (target / 'producer.json').write_text('{}')
            with patch('obtain_windows_host_candidate.obtain_component', side_effect=acquire), self.assertRaisesRegex(BuildError, 'host_candidate_files_invalid'):
                obtain(pin, root / 'out')
            self.assertFalse((root / 'out').exists())

    def test_cleanup_failure_does_not_replace_primary_acquisition_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            pin = {'artifactId': 123, 'runId': 456, 'runAttempt': 1, 'headSha': 'a' * 40,
                   'archiveSha256': 'b' * 64, 'workflow': '.github/workflows/windows-host-assembly.yml'}
            primary = BuildError('host_component_producer_mismatch')
            with patch('obtain_windows_host_candidate.obtain_component', side_effect=primary), patch(
                'obtain_windows_host_candidate.shutil.rmtree', side_effect=OSError('synthetic cleanup failure')
            ), self.assertRaises(BuildError) as caught:
                obtain(pin, root / 'out')
            self.assertIs(caught.exception, primary)
            self.assertIn('synthetic cleanup failure', '\n'.join(primary.__notes__))

    def test_preserves_original_manifest_payload_unsigned_receipt_and_producer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive, raw, receipt = self.fixture(root)
            pin = {'artifactId': 123, 'runId': 456, 'runAttempt': 1, 'headSha': 'a' * 40,
                   'archiveSha256': 'b' * 64, 'workflow': '.github/workflows/windows-host-assembly.yml'}
            zipped = root / 'artifact.zip'
            with zipfile.ZipFile(zipped, 'w') as zip_archive:
                zip_archive.write(archive, archive.name)
            def acquire(approved, target):
                self.assertEqual(approved, pin)
                target.mkdir()
                (target / 'component').mkdir()
                unpack(zipped, target / 'component')
                (target / 'producer.json').write_bytes(b'{"original":"producer"}\n')
            with patch('obtain_windows_host_candidate.obtain_component', side_effect=acquire) as acquired:
                obtain(pin, root / 'out')
            acquired.assert_called_once()
            candidate = root / 'out/candidate'
            self.assertEqual((candidate / 'manifest.json').read_bytes(), raw)
            self.assertEqual((candidate / 'payload/fixture').read_bytes(), b'fixture')
            self.assertEqual(json.loads((candidate / 'qualification.json').read_bytes()), receipt)
            self.assertEqual((root / 'out/producer.json').read_bytes(), b'{"original":"producer"}\n')
            self.assertEqual({p.name for p in (root / 'out').iterdir()}, {'candidate', 'producer.json'})

    def test_rejects_changed_unsigned_receipts_and_unsafe_or_extra_candidate_entries(self):
        cases = [{'qualification': 'failed'}, {'schemaVersion': True}, {'signaturePresent': True},
                 {'runtimeQualified': True}, {'redistributable': True}, {'sourceRevision': 'c' * 40},
                 {'manifestSha256': 'f' * 64}, {'manifestBytes': 0}, {'files': 2}, {'files': True}]
        extras = [{'manifest.sig': b'existing signature'}, {'../escape': b'x'}, {'payload/FIXTURE': b'x'}]
        for change, extra in [(c, None) for c in cases] + [(None, e) for e in extras]:
            with self.subTest(change=change, extra=extra), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                archive, _, _ = self.fixture(root, change, extra)
                pin = {'artifactId': 123, 'runId': 456, 'runAttempt': 1, 'headSha': 'a' * 40,
                       'archiveSha256': 'b' * 64, 'workflow': '.github/workflows/windows-host-assembly.yml'}
                def acquire(_, target):
                    target.mkdir()
                    (target / 'component').mkdir()
                    shutil.copyfile(archive, target / 'component' / archive.name)
                    (target / 'producer.json').write_text('{}')
                with patch('obtain_windows_host_candidate.obtain_component', side_effect=acquire), self.assertRaises(BuildError):
                    obtain(pin, root / 'out')
                self.assertFalse((root / 'out').exists())
                self.assertFalse((root / 'escape').exists())

    def test_refuses_wrong_producer_policy_before_requests_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            pin = {'artifactId': 123, 'runId': 456, 'runAttempt': 1, 'headSha': 'a' * 40,
                   'archiveSha256': 'b' * 64, 'workflow': '.github/workflows/other.yml'}
            with patch('obtain_windows_host_candidate.obtain_component') as acquire:
                with self.assertRaises(BuildError):
                    obtain(pin, root / 'out')
                acquire.assert_not_called()
            (root / 'out').mkdir()
            (root / 'out/owned').write_bytes(b'preserve')
            with self.assertRaises(BuildError):
                obtain(pin, root / 'out')
            self.assertEqual((root / 'out/owned').read_bytes(), b'preserve')
