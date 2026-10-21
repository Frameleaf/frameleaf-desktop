import hashlib
import io
import json
import zipfile
import tempfile
import unittest
from urllib.error import HTTPError
from pathlib import Path
from unittest.mock import patch

import assemble_windows_host_candidate as assembler
from build_runtime import BuildError, inventory


class WindowsHostAssemblyTests(unittest.TestCase):
    def test_geodata_capture_preserves_checksum_and_removes_failed_partial_files(self):
        content = b'pinned geodata'
        digest = hashlib.sha256(content).hexdigest()
        capture = 'https://web.archive.org/web/pinnedid_/https://download.geonames.org/asset'
        for primary in ['forbidden', 'wrong-checksum', 'correct']:
            with tempfile.TemporaryDirectory() as temporary, self.subTest(primary=primary):
                destination = Path(temporary) / 'cities500.zip'
                first = HTTPError('primary', 403, 'Forbidden', {}, None) if primary == 'forbidden' else io.BytesIO(content if primary == 'correct' else b'wrong')
                with patch('build_host_database.urllib.request.urlopen', side_effect=[first, io.BytesIO(content)]) as request:
                    source = assembler.download_geodata(destination, digest, capture)
                self.assertEqual(destination.read_bytes(), content)
                self.assertEqual(len(list(Path(temporary).iterdir())), 1)
                self.assertEqual(request.call_count, 1 if primary == 'correct' else 2)
                self.assertEqual(source, request.call_args.args[0])
                self.assertEqual(source, 'https://static.frameleaf.cloud/geodata/2026-10-11/cities500.zip' if primary == 'correct' else capture)

    def test_geodata_never_accepts_wrong_bytes_or_replaces_existing_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / 'cities500.zip'
            capture = 'https://web.archive.org/web/pinnedid_/https://download.geonames.org/asset'
            with (patch('build_host_database.urllib.request.urlopen', side_effect=[io.BytesIO(b'wrong'), io.BytesIO(b'wrong')]),
                  self.assertRaises(BuildError)):
                assembler.download_geodata(destination, 'a' * 64, capture)
            self.assertEqual(list(root.iterdir()), [])
            destination.write_bytes(b'keep')
            with patch('build_host_database.urllib.request.urlopen') as request, self.assertRaises(BuildError):
                assembler.download_geodata(destination, 'a' * 64, capture)
            request.assert_not_called()
            self.assertEqual(destination.read_bytes(), b'keep')
            destination.unlink()
            partial = destination.with_name(destination.name + '.part')
            partial.write_bytes(b'keep partial')
            with patch('build_host_database.urllib.request.urlopen') as request, self.assertRaises(BuildError):
                assembler.download_geodata(destination, 'a' * 64, capture)
            request.assert_not_called()
            self.assertEqual(partial.read_bytes(), b'keep partial')
            partial.unlink()
            for capture in ['http://other.invalid/asset', 'https://user:password@web.archive.org/asset']:
                with patch('build_host_database.urllib.request.urlopen') as request, self.assertRaises(BuildError):
                    assembler.download_geodata(destination, 'a' * 64, capture)
                request.assert_not_called()

    def test_component_must_match_passed_source_and_every_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'component').mkdir()
            asset = root / 'component/asset'
            asset.write_bytes(b'original')
            record = {'qualification': 'passed', 'sourceRevision': assembler.SOURCE,
                      'files': inventory(root / 'component')}
            receipt = root / 'qualification.json'
            receipt.write_text(json.dumps(record))
            self.assertEqual(assembler.qualified_files(root, 'component'), record)
            asset.write_bytes(b'changed')
            with self.assertRaisesRegex(BuildError, 'component_changed'):
                assembler.qualified_files(root, 'component')
            for changed in [{**record, 'qualification': 'failed'},
                            {**record, 'sourceRevision': 'a' * 40}]:
                receipt.write_text(json.dumps(changed))
                with self.assertRaisesRegex(BuildError, 'component_unqualified'):
                    assembler.qualified_files(root, 'component')

    def test_artifact_provenance_is_rejected_before_download(self):
        metadata = {'workflow_run': {'id': 55, 'head_sha': 'a' * 40},
                    'expired': False, 'size_in_bytes': 100}
        producer = {'head_sha': 'a' * 40, 'status': 'completed', 'conclusion': 'success'}
        cases = [({**metadata, 'expired': True}, producer),
                 ({**metadata, 'size_in_bytes': 0}, producer),
                 ({**metadata, 'workflow_run': {'id': 56, 'head_sha': 'a' * 40}}, producer),
                 ({**metadata, 'workflow_run': {'id': 55, 'head_sha': 'b' * 40}}, producer),
                 (metadata, {**producer, 'head_sha': 'b' * 40}),
                 (metadata, {**producer, 'status': 'in_progress'}),
                 (metadata, {**producer, 'conclusion': 'failure'})]
        with tempfile.TemporaryDirectory() as temporary:
            for candidate, run in cases:
                with (self.subTest(metadata=candidate, producer=run),
                      patch.object(assembler, 'api', side_effect=[candidate, run]),
                      patch.object(assembler.subprocess, 'run') as download,
                      self.assertRaisesRegex(BuildError, 'producer_mismatch')):
                    assembler.obtain(Path(temporary), 'component', 1, 'c' * 64, 55, 'a' * 40)
                download.assert_not_called()
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_exact_archive_is_verified_before_unpack_and_provenance_is_retained(self):
        metadata = {'workflow_run': {'id': 55, 'head_sha': 'a' * 40},
                    'expired': False, 'size_in_bytes': 100}
        producer = {'head_sha': 'a' * 40, 'status': 'completed', 'conclusion': 'success'}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('component/asset', b'verified bytes')
        content = buffer.getvalue()
        def download(arguments, *, stdout, check):
            self.assertEqual(arguments[-1], assembler.REPOSITORY + 'actions/artifacts/1/zip')
            stdout.write(content)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label, digest in [('valid', hashlib.sha256(content).hexdigest()), ('changed', 'c' * 64)]:
                work = root / label
                work.mkdir()
                with (patch.object(assembler, 'api', side_effect=[metadata, producer]),
                      patch.object(assembler.subprocess, 'run', side_effect=download)):
                    if label == 'valid':
                        result = assembler.obtain(work, 'input', 1, digest, 55, 'a' * 40)
                        self.assertEqual((result / 'component/asset').read_bytes(), b'verified bytes')
                        self.assertFalse((work / 'input.zip').exists())
                        receipt = json.loads((work / 'input-producer.json').read_text())
                        self.assertEqual(receipt, {'artifact': metadata, 'run': producer, 'archiveSha256': digest})
                    else:
                        with self.assertRaisesRegex(BuildError, 'archive_changed'):
                            assembler.obtain(work, 'input', 1, digest, 55, 'a' * 40)
                        self.assertFalse((work / 'input').exists())
