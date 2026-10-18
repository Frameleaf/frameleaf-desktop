import hashlib
import json
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bind_host_raw import build
from build_runtime import BuildError, inventory


class RawBindingTests(unittest.TestCase):
    def inputs(self, root):
        patches = {name: b'fixture patch' for name in ['patch-darktable-lens.py', 'patch-darktable-mask-geometry.py']}
        repositories = {'darktable': ('darktable-org/darktable', '.'),
                        'rawspeed': ('darktable-org/rawspeed', 'src/external/rawspeed'),
                        'whereami': ('gpakosz/whereami', 'src/external/whereami'),
                        'opencl': ('KhronosGroup/OpenCL-Headers', 'src/external/OpenCL'),
                        'lensfun': ('lensfun/lensfun', 'lensfun')}
        pin = {'name': 'darktable', 'repository': 'darktable-org/darktable', 'version': '5.6.2',
               'lensfunVersion': '0.3.4', 'revision': 'a' * 40,
               'patches': {n: hashlib.sha256(v).hexdigest() for n, v in patches.items()},
               'inputs': [{'name': n, 'repository': repo, 'path': path, 'revision': 'a' * 40,
                           'sha256': 'b' * 64, 'url': f'https://codeload.github.com/{repo}/tar.gz/' + 'a' * 40}
                          for n, (repo, path) in repositories.items()]}
        libraw = {'name': 'libraw', 'repository': 'LibRaw/LibRaw', 'revision': 'c' * 40}
        blobs = {'server/base-image/sources/darktable.json': json.dumps(pin).encode(),
                 'server/base-image/sources/libraw.json': json.dumps(libraw).encode(),
                 **{'server/test/native/' + n: v for n, v in patches.items()}}
        target = platform.system() + '-' + platform.machine()
        for name, revision in [('server', 'd' * 40), ('raw', 'e' * 40)]:
            folder = root / name
            (folder / name).mkdir(parents=True)
            (folder / name / 'fixture').write_text(name)
            report = {'qualification': 'passed', 'platform': target, 'sourceRevision': revision,
                      'files': inventory(folder / name)}
            if name == 'raw':
                report.update(source=pin, librawSource=libraw)
            (folder / 'qualification.json').write_text(json.dumps(report))
        return blobs

    def test_different_server_revision_requires_exact_engine_and_patch_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            blobs = self.inputs(root)
            with patch('bind_host_raw.git_blob', side_effect=lambda git, source, revision, name, env: blobs[name]):
                build(root, root / 'server', root / 'raw', root / 'output')
            result = json.loads((root / 'output/qualification.json').read_text())
            self.assertEqual(result['qualification'], 'passed')
            self.assertEqual(result['sourceRevision'], 'd' * 40)
            self.assertEqual(result['rawEngineSourceRevision'], 'e' * 40)
            self.assertEqual((root / 'output/raw/fixture').read_text(), 'raw')
            self.assertEqual(result['files']['server'], inventory(root / 'server/server'))

    def test_changed_engine_or_patches_are_refused(self):
        for problem in ['engine', 'patch']:
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                blobs = self.inputs(root)
                if problem == 'patch':
                    blobs['server/test/native/patch-darktable-lens.py'] += b'changed'
                else:
                    receipt = root / 'raw/qualification.json'
                    value = json.loads(receipt.read_text()); value['source']['revision'] = 'f' * 40
                    receipt.write_text(json.dumps(value))
                with patch('bind_host_raw.git_blob', side_effect=lambda git, source, revision, name, env: blobs[name]):
                    with self.assertRaises(BuildError):
                        build(root, root / 'server', root / 'raw', root / 'output')
                self.assertEqual(json.loads((root / 'output/qualification.json').read_text())['qualification'], 'failed')

    def test_failed_or_foreign_platform_input_is_refused(self):
        for field, value in [('qualification', 'failed'), ('platform', 'other-platform')]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(); self.inputs(root)
                receipt = root / 'server/qualification.json'
                report = json.loads(receipt.read_text()); report[field] = value
                receipt.write_text(json.dumps(report))
                with self.assertRaises(BuildError):
                    build(root, root / 'server', root / 'raw', root / 'output')
                self.assertFalse((root / 'output').exists())

    def test_changed_payload_is_refused_after_contract_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); blobs = self.inputs(root)
            (root / 'raw/raw/fixture').write_text('changed')
            with patch('bind_host_raw.git_blob', side_effect=lambda git, source, revision, name, env: blobs[name]):
                with self.assertRaisesRegex(BuildError, 'inventory_mismatch'):
                    build(root, root / 'server', root / 'raw', root / 'output')
