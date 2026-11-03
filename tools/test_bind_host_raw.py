import hashlib
import io
import runpy
import subprocess
import sys
from contextlib import redirect_stderr
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

    def test_cli_identity_process_failures_use_stable_diagnostic_without_creating_output(self):
        for error in [subprocess.CalledProcessError(1, 'whoami.exe'),
                      subprocess.TimeoutExpired('whoami.exe', 10)]:
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                self.inputs(root)
                script = Path(__file__).with_name('bind_host_raw.py')
                arguments = [str(script), '--source', str(root), '--server', str(root / 'server'),
                             '--raw', str(root / 'raw'), '--output', str(root / 'output')]
                stderr = io.StringIO()
                with patch.object(sys, 'argv', arguments), redirect_stderr(stderr), patch(
                    'windows_private_directory.create_private_directory', side_effect=error
                ), self.assertRaises(SystemExit) as exited:
                    runpy.run_path(str(script), run_name='__main__')
                self.assertEqual(exited.exception.code, 1)
                self.assertEqual(stderr.getvalue(), 'host_raw_binding_failed')
                self.assertFalse((root / 'output').exists())

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

    def test_utf8_inventory_names_survive_receipt_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            blobs = self.inputs(root)
            for name in ['server', 'raw']:
                folder = root / name
                (folder / name / 'fixture').rename(folder / name / 'café-原本')
                receipt = folder / 'qualification.json'
                report = json.loads(receipt.read_text())
                report['files'] = inventory(folder / name)
                receipt.write_text(json.dumps(report, ensure_ascii=False), encoding='utf-8')
            with patch('bind_host_raw.git_blob', side_effect=lambda git, source, revision, name, env: blobs[name]):
                build(root, root / 'server', root / 'raw', root / 'output')
            result = json.loads((root / 'output/qualification.json').read_text(encoding='utf-8'))
            for name in ['server', 'raw']:
                self.assertEqual(result['files'][name], inventory(root / 'output' / name))
                self.assertTrue((root / 'output' / name / 'café-原本').is_file())

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

    def metadata_inputs(self, root, problem=None):
        blobs = self.inputs(root)
        server = root / 'server'
        module = server / 'server/node_modules/exiftool-vendored/dist/ExiftoolPath.js'
        module.parent.mkdir(parents=True)
        module.write_bytes(b'original vendor module')
        original_sha = hashlib.sha256(module.read_bytes()).hexdigest()
        receipt = json.loads((server / 'qualification.json').read_text())
        receipt.update(platform='Windows-AMD64', files=inventory(server / 'server'))
        (server / 'server-qualification.json').write_text(json.dumps(receipt))
        module.write_bytes(b'private runtime adaptation')
        adapted = {'qualification': 'passed', 'platform': 'Windows-AMD64',
                   'sourceRevision': receipt['sourceRevision'], 'originalModuleSha256': original_sha,
                   'adaptedModuleSha256': hashlib.sha256(module.read_bytes()).hexdigest(),
                   'vendorVersion': '39.0.1', 'executableVendorVersion': '13.59.3',
                   'files': {'server': inventory(server / 'server')}}
        metadata = {'qualification': 'passed', 'sourceRevision': receipt['sourceRevision'],
                    'vendorVersion': '39.0.1', 'executableVendorVersion': '13.59.3',
                    **{key: True for key in ['metadataReadWrite', 'unicodeMetadata', 'locationFreeCopy',
                       'originalUnchanged', 'decodedPixelsUnchanged', 'missingPrivateExecutableRefused']}}
        if problem == 'extra-change':
            (server / 'server/fixture').write_text('unexpected change')
            adapted['files']['server'] = inventory(server / 'server')
        elif problem == 'original-hash': adapted['originalModuleSha256'] = '0' * 64
        elif problem == 'adapted-hash': adapted['adaptedModuleSha256'] = '0' * 64
        elif problem == 'source': metadata['sourceRevision'] = 'f' * 40
        elif problem == 'flag': metadata['missingPrivateExecutableRefused'] = False
        elif problem == 'vendor': metadata['vendorVersion'] = '0.0.0'
        elif problem == 'payload': module.write_bytes(b'unrecorded tampering')
        elif problem == 'forged-adaptation':
            module.write_bytes(b'forged executable code')
            adapted['files']['server'] = inventory(server / 'server')
            adapted['adaptedModuleSha256'] = hashlib.sha256(module.read_bytes()).hexdigest()
        elif problem == 'original-source':
            receipt['sourceRevision'] = 'f' * 40
            (server / 'server-qualification.json').write_text(json.dumps(receipt))
        (server / 'qualification.json').write_text(json.dumps(adapted))
        metadata['componentReceiptSha256'] = hashlib.sha256((server / 'qualification.json').read_bytes()).hexdigest()
        if problem == 'missing-binding':
            del metadata['componentReceiptSha256']
        (server / 'metadata-qualification.json').write_bytes(b'\xef\xbb\xbf' + json.dumps(metadata).encode())
        raw = root / 'raw/qualification.json'
        record = json.loads(raw.read_text()); record['platform'] = 'Windows-AMD64'; raw.write_text(json.dumps(record))
        return blobs, original_sha

    def test_windows_metadata_adaptation_binds_without_rewriting_original_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            blobs, original_sha = self.metadata_inputs(root)
            originals = {p: p.read_bytes() for p in (root / 'server').glob('*.json')}
            with patch('bind_host_raw.platform.system', return_value='Windows'), \
                    patch('bind_host_raw.platform.machine', return_value='AMD64'), \
                    patch('bind_host_raw.git_blob', side_effect=lambda git, source, revision, name, env: blobs[name]), \
                    patch('bind_host_raw.VENDOR_MODULE_SHA256', original_sha), \
                    patch('bind_host_raw.ADAPTED_MODULE_SHA256', hashlib.sha256(b'private runtime adaptation').hexdigest()):
                build(root, root / 'server', root / 'raw', root / 'output')
            result = json.loads((root / 'output/qualification.json').read_text())
            self.assertEqual(result['qualification'], 'passed')
            self.assertEqual(result['files']['server'], inventory(root / 'server/server'))
            self.assertEqual(result['metadataQualificationSha256'], hashlib.sha256(
                (root / 'server/metadata-qualification.json').read_bytes()).hexdigest())
            self.assertEqual(result['originalServerReceiptSha256'], hashlib.sha256(
                (root / 'server/server-qualification.json').read_bytes()).hexdigest())
            self.assertEqual({p: p.read_bytes() for p in originals}, originals)

    def test_windows_metadata_binding_refuses_changed_chain_or_payload(self):
        for problem in ['extra-change', 'original-hash', 'adapted-hash', 'source', 'flag', 'vendor', 'payload', 'original-source', 'forged-adaptation', 'missing-binding']:
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                blobs, original_sha = self.metadata_inputs(root, problem)
                with patch('bind_host_raw.platform.system', return_value='Windows'), \
                        patch('bind_host_raw.platform.machine', return_value='AMD64'), \
                        patch('bind_host_raw.git_blob', side_effect=lambda git, source, revision, name, env: blobs[name]), \
                        patch('bind_host_raw.VENDOR_MODULE_SHA256', original_sha), \
                        patch('bind_host_raw.ADAPTED_MODULE_SHA256', hashlib.sha256(b'private runtime adaptation').hexdigest()):
                    expected = 'inventory_mismatch' if problem == 'payload' else 'metadata_invalid'
                    with self.assertRaisesRegex(BuildError, expected):
                        build(root, root / 'server', root / 'raw', root / 'output')

    def test_metadata_result_from_different_same_source_component_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            blobs, original_sha = self.metadata_inputs(root)
            server = root / 'server'
            (server / 'server/fixture').write_text('different same-source server inventory')
            original = json.loads((server / 'server-qualification.json').read_text())
            original['files']['fixture'] = inventory(server / 'server')['fixture']
            (server / 'server-qualification.json').write_text(json.dumps(original))
            adapted = json.loads((server / 'qualification.json').read_text())
            adapted['files']['server'] = inventory(server / 'server')
            (server / 'qualification.json').write_text(json.dumps(adapted))
            with patch('bind_host_raw.platform.system', return_value='Windows'), \
                    patch('bind_host_raw.platform.machine', return_value='AMD64'), \
                    patch('bind_host_raw.git_blob', side_effect=lambda git, source, revision, name, env: blobs[name]), \
                    patch('bind_host_raw.VENDOR_MODULE_SHA256', original_sha), \
                    patch('bind_host_raw.ADAPTED_MODULE_SHA256', hashlib.sha256(b'private runtime adaptation').hexdigest()):
                with self.assertRaisesRegex(BuildError, 'metadata_invalid'):
                    build(root, server, root / 'raw', root / 'output')
            self.assertFalse((root / 'output').exists())
