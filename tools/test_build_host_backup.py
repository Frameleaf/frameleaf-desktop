import bz2
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from build_host_backup import artifact, unpack, build
from build_runtime import BuildError


class BackupEngineTests(unittest.TestCase):
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

    def test_license_bytes_must_match_before_engine_qualification(self):
        expected = (Path(__file__).resolve().parent.parent / 'runtime/host-backup-LICENSE.txt').read_bytes()
        for license_bytes, valid in [(expected, True), (expected.replace(b'\n', b'\r\n'), False), (expected + b'changed', False)]:
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                (root / 'runtime').mkdir()
                (root / 'runtime/host-backup-LICENSE.txt').write_bytes(license_bytes)
                archive = bz2.compress(b'engine fixture')
                pin = {'url': 'https://github.com/restic/restic/releases/download/v0.18.1/restic.bz2',
                       'sha256': hashlib.sha256(archive).hexdigest(),
                       'binarySha256': hashlib.sha256(b'engine fixture').hexdigest()}

                def downloaded(_url, destination, _digest):
                    destination.write_bytes(archive)

                output = root / 'candidate'
                with patch('build_host_backup.ROOT', root), patch('build_host_backup.artifact', return_value=pin), patch('build_host_backup.download', side_effect=downloaded), patch('build_host_backup.qualify', return_value={}) as qualify:
                    if valid:
                        build(output)
                        qualify.assert_called_once()
                        self.assertEqual((output / 'backup/LICENSE').read_bytes(), expected)
                    else:
                        with self.assertRaisesRegex(BuildError, 'host_backup_license_digest_mismatch'):
                            build(output)
                        qualify.assert_not_called()
                        self.assertEqual(json.loads((output / 'qualification.json').read_text())['qualification'], 'failed')
                        self.assertFalse((output / 'backup/component.json').exists())

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
