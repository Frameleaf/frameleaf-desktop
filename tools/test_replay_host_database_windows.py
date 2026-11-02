import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from replay_host_database_windows import extract_candidate
from build_runtime import BuildError


class DatabaseReplayTests(unittest.TestCase):
    def fixture(self, root, extra=(), changes=None):
        archive = root / 'candidate.zip'
        receipt = {'pins': {'fixture': True}, 'sourceRevision': 'a' * 40,
                   'platform': 'windows-x86_64', 'redistributable': False}
        receipt.update(changes or {})
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('qualification.json', json.dumps(receipt))
            bundle.writestr('postgres/bin/initdb.exe', b'fixture')
            for name, value in extra:
                if isinstance(name, str):
                    raw_name = zipfile.ZipInfo(name)
                    raw_name.filename = name
                    name = raw_name
                bundle.writestr(name, value)
        return archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    def test_extracts_only_component_after_digest_and_provenance_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, digest = self.fixture(root, [('private-build.log', b'not part of replay')])
            receipt = extract_candidate(archive, root / 'out', digest, 'a' * 40, {'fixture': True})
            self.assertEqual(receipt['platform'], 'windows-x86_64')
            self.assertEqual((root / 'out/postgres/bin/initdb.exe').read_bytes(), b'fixture')
            self.assertFalse((root / 'out/private-build.log').exists())

    def test_digest_or_wrong_receipt_refuses_before_creating_output(self):
        for changes in [{}, {'platform': 'linux-x86_64'}, {'sourceRevision': 'b' * 40},
                        {'pins': {}}, {'redistributable': True}]:
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive, digest = self.fixture(root, changes=changes)
                with self.assertRaises(BuildError):
                    extract_candidate(archive, root / 'out', '0' * 64 if not changes else digest,
                                      'a' * 40, {'fixture': True})
                self.assertFalse((root / 'out').exists())

    def test_unsafe_or_ambiguous_component_paths_refuse_before_writes(self):
        for name in ['postgres/../../escape', 'postgres/C:/escape', 'postgres/bin/CON',
                     'postgres/bin/INITDB.exe', 'postgres/bin/bad.', 'postgres/bin/a\\b']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive, digest = self.fixture(root, [(name, b'unsafe')])
                with self.assertRaises(BuildError):
                    extract_candidate(archive, root / 'out', digest, 'a' * 40, {'fixture': True})
                self.assertFalse((root / 'out').exists())

    def test_symlink_and_existing_output_are_never_adopted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            link = zipfile.ZipInfo('postgres/bin/link')
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive, digest = self.fixture(root, [(link, b'outside')])
            with self.assertRaises(BuildError):
                extract_candidate(archive, root / 'out', digest, 'a' * 40, {'fixture': True})
            archive, digest = self.fixture(root)
            output = root / 'out'
            output.mkdir()
            (output / 'keep').write_bytes(b'existing')
            with self.assertRaises(FileExistsError):
                extract_candidate(archive, output, digest, 'a' * 40, {'fixture': True})
            self.assertEqual((output / 'keep').read_bytes(), b'existing')
