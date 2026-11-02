import bz2
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from unittest.mock import patch
import zipfile

from build_host_backup import artifact, unpack, build
from build_runtime import BuildError


class BackupEngineTests(unittest.TestCase):
    @staticmethod
    def workflow_archive():
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/native-backup.yml').read_text()
        return textwrap.dedent(workflow.split(
            '      - name: Archive the qualified backup component with executable modes\n', 1
        )[1].split('        run: |\n', 1)[1].split('      - name:', 1)[0])

    def test_workflow_archive_preserves_executable_bytes_and_mode_after_artifact_download(self):
        """Run the real archive step through ZIP transfer so executable mode cannot be lost silently."""
        for binary_name in ['restic', 'restic.exe']:
            with self.subTest(binary=binary_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                component = root / 'frameleaf-backup-engine/backup'
                component.mkdir(parents=True)
                binary = component / binary_name
                binary.write_bytes(b'#!/bin/sh\nprintf recovered-backup-engine\n')
                binary.chmod(0o755)
                (component / 'LICENSE').write_bytes(b'synthetic license')
                receipt = json.dumps({'qualification': 'passed'})
                (component / 'component.json').write_text(receipt)
                (component.parent / 'qualification.json').write_text(receipt)
                subprocess.run([sys.executable, '-c', self.workflow_archive()], check=True,
                               env=os.environ | {'RUNNER_TEMP': temporary}, capture_output=True)
                archive = component.parent / 'backup-component.tar.gz'
                with zipfile.ZipFile(root / 'artifact.zip', 'w') as upload:
                    upload.write(archive, archive.name)
                with zipfile.ZipFile(root / 'artifact.zip') as download:
                    download.extractall(root / 'download')
                with tarfile.open(root / 'download' / archive.name) as restored:
                    self.assertEqual(restored.getmember('backup/' + binary_name).mode,
                                     stat.S_IMODE(binary.stat().st_mode))
                    restored.extractall(root / 'restored', filter='data')
                result = root / 'restored/backup' / binary_name
                self.assertEqual(result.read_bytes(), binary.read_bytes())
                self.assertEqual((result.parent / 'LICENSE').read_bytes(), b'synthetic license')
                self.assertEqual((result.parent / 'component.json').read_text(), receipt)
                self.assertEqual((root / 'restored/qualification.json').read_text(), receipt)
                if os.name != 'nt':
                    self.assertTrue(os.access(result, os.X_OK))
                    output = subprocess.check_output([str(result)])
                    self.assertEqual(output, b'recovered-backup-engine')

    def test_workflow_archive_refuses_failed_missing_or_mismatched_component_receipts(self):
        """Unqualified output must stay diagnostic data rather than becoming a component archive."""
        for state, component in [('failed', {'qualification': 'failed'}), ('passed', None),
                                 ('passed', {'qualification': 'passed', 'changed': True})]:
            with self.subTest(state=state, component=component), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / 'frameleaf-backup-engine'
                (root / 'backup').mkdir(parents=True)
                (root / 'qualification.json').write_text(json.dumps({'qualification': state}))
                if component is not None:
                    (root / 'backup/component.json').write_text(json.dumps(component))
                result = subprocess.run([sys.executable, '-c', self.workflow_archive()],
                                        env=os.environ | {'RUNNER_TEMP': temporary}, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / 'backup-component.tar.gz').exists())

    def test_supported_targets_have_fixed_upstream_digests(self):
        for system, machine in [('Darwin', 'arm64'), ('Darwin', 'x86_64'), ('Linux', 'aarch64'), ('Linux', 'x86_64'), ('Windows', 'AMD64')]:
            pin = artifact(system, machine)
            self.assertRegex(pin['sha256'], r'^[a-f0-9]{64}$')
            self.assertRegex(pin['binarySha256'], r'^[a-f0-9]{64}$')
            self.assertTrue(pin['url'].startswith('https://github.com/restic/restic/releases/download/v0.18.1/restic_0.18.1_'))
        for system, machine in [('Windows', 'ARM64'), ('Linux', 'i686'), ('Other', 'x86_64')]:
            with self.assertRaises(BuildError):
                artifact(system, machine)

    def test_changed_executable_is_rejected_before_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive = root / 'source.bz2'
            archive.write_bytes(bz2.compress(b'changed engine'))
            pin = {'url': 'https://github.com/restic/restic/releases/download/v0.18.1/restic.bz2',
                   'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'binarySha256': '0' * 64}

            def downloaded(_url, destination, _digest):
                destination.write_bytes(archive.read_bytes())

            with patch('build_host_backup.artifact', return_value=pin), patch('build_host_backup.download', side_effect=downloaded), patch('build_host_backup.qualify') as qualify:
                with self.assertRaisesRegex(BuildError, 'host_backup_binary_digest_mismatch'):
                    build(root / 'candidate')
                qualify.assert_not_called()

    def test_digest_is_checked_before_decompression_or_destination_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'restic.bz2'
            archive.write_bytes(b'not compressed')
            with self.assertRaisesRegex(BuildError, 'digest_mismatch'):
                unpack(archive, root / 'restic', '0' * 64)
            self.assertFalse((root / 'restic').exists())

    def test_bzip_binary_is_bounded_and_nonempty(self):
        for content, limit, valid in [(b'engine', 64, True), (b'', 64, False), (b'x' * 65, 64, False)]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / 'restic.bz2'
                archive.write_bytes(bz2.compress(content))
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                with patch('build_host_backup.MAX_BINARY_BYTES', limit):
                    if valid:
                        unpack(archive, root / 'restic', digest)
                        self.assertEqual((root / 'restic').read_bytes(), content)
                    else:
                        with self.assertRaises(BuildError):
                            unpack(archive, root / 'restic', digest)

    def test_zip_allows_one_exact_regular_executable_only(self):
        for names, mode, valid in [(['restic.exe'], stat.S_IFREG, True), (['../restic.exe'], stat.S_IFREG, False), (['restic.exe', 'extra'], stat.S_IFREG, False), (['restic.exe'], stat.S_IFLNK, False)]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / 'restic.zip'
                with zipfile.ZipFile(archive, 'w') as output:
                    for name in names:
                        entry = zipfile.ZipInfo(name)
                        entry.external_attr = (mode | 0o755) << 16
                        output.writestr(entry, b'engine')
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                if valid:
                    unpack(archive, root / 'engine.exe', digest)
                    self.assertEqual((root / 'engine.exe').read_bytes(), b'engine')
                else:
                    with self.assertRaises(BuildError):
                        unpack(archive, root / 'engine.exe', digest)


if __name__ == '__main__':
    unittest.main()
