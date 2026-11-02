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
import zipfile


class WindowsHostAssetsTests(unittest.TestCase):
    def archive_script(self):
        workflow = Path(__file__).resolve().parents[1] / '.github/workflows/windows-host-assets.yml'
        self.assertTrue(workflow.is_file(), 'Windows host assets producer is missing')
        return textwrap.dedent(workflow.read_text().split(
            '      - name: Archive the qualified host assets\n', 1
        )[1].split('        run: |\n', 1)[1].split('      - name:', 1)[0])

    def fixture(self, root):
        source = root / 'application-source'
        (source / 'studio').mkdir(parents=True)
        (source / 'pnpm-lock.yaml').write_bytes(b'workspace lock')
        (source / 'studio/engine-package-lock.json').write_bytes(b'studio lock')
        (source / 'studio/engine-build.json').write_text(json.dumps({'node': '26.11.1', 'npm': '13.0.0'}))
        node = root / 'node.exe'
        node.write_bytes(b'synthetic Node identity; never executed')
        receipts = {}
        for name, directory in [('web', 'www'), ('plugin', 'plugin'), ('studio', 'studio-worker')]:
            output = root / 'fl-windows-assets' / name
            payload = output / directory
            payload.mkdir(parents=True)
            content = ('qualified ' + name).encode()
            (payload / 'payload').write_bytes(content)
            (payload / 'payload').chmod(0o755)
            (output / 'work').mkdir()
            (output / 'work/private-state').write_text('never archive')
            receipt = {
                'schemaVersion': 1, 'sourceRevision': 'a' * 40,
                'sourceArchiveSha256': 'b' * 64,
                'nodeSha256': hashlib.sha256(node.read_bytes()).hexdigest(),
                'qualification': 'passed', 'runtimeQualified': False, 'redistributable': False,
                'files': {'payload': {'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}},
            }
            if name in ['web', 'plugin']:
                receipt.update(pnpmVersion='12.11.2', lockfileSha256=hashlib.sha256(b'workspace lock').hexdigest())
            if name in ['web', 'studio']:
                receipt.update(npmVersion='13.0.0', studioLockfileSha256=hashlib.sha256(b'studio lock').hexdigest())
            if name == 'studio': receipt['browserIncluded'] = False
            (output / 'qualification.json').write_text(json.dumps(receipt))
            receipts[name] = receipt
        return receipts, os.environ | {'RUNNER_TEMP': str(root), 'GITHUB_WORKSPACE': str(root),
                                      'HOST_SOURCE_REVISION': 'a' * 40, 'NODE_BINARY': str(node)}

    def test_archive_transports_all_three_exact_payloads_without_build_state(self):
        """Losing a component, receipt, byte or executable mode during artifact transfer must fail."""
        script = self.archive_script()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            receipts, environment = self.fixture(root)
            subprocess.run([sys.executable, '-c', script], env=environment, check=True,
                           cwd=Path(__file__).resolve().parents[1], capture_output=True)
            archive = root / 'fl-windows-assets/host-assets.tar.gz'
            with zipfile.ZipFile(root / 'artifact.zip', 'w') as upload:
                upload.write(archive, archive.name)
            with zipfile.ZipFile(root / 'artifact.zip') as download:
                download.extractall(root / 'download')
            with tarfile.open(root / 'download' / archive.name) as downloaded:
                names = [entry.name for entry in downloaded.getmembers()]
                self.assertFalse(any('private-state' in name or '/work' in name for name in names))
                downloaded.extractall(root / 'restored', filter='data')
            for name, directory in [('web', 'www'), ('plugin', 'plugin'), ('studio', 'studio-worker')]:
                payload = root / 'restored' / name / directory / 'payload'
                self.assertEqual(payload.read_bytes(), ('qualified ' + name).encode())
                self.assertEqual(json.loads((root / 'restored' / name / 'qualification.json').read_text()), receipts[name])
                if os.name != 'nt': self.assertEqual(stat.S_IMODE(payload.stat().st_mode), 0o755)

    def test_archive_refuses_any_failed_stale_or_changed_component_before_creating_tar(self):
        """Each component must be qualified and bound; a valid neighbour cannot hide changed output."""
        script = self.archive_script()
        for name, directory in [('web', 'www'), ('plugin', 'plugin'), ('studio', 'studio-worker')]:
            failures = ['failed', 'source', 'node', 'runtime', 'redistribution', 'archive',
                        'payload', 'extra', 'lock', 'schema', 'package-manager']
            if name == 'studio': failures.append('browser')
            for damage in failures:
                with self.subTest(component=name, damage=damage), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    receipts, environment = self.fixture(root)
                    output = root / 'fl-windows-assets' / name
                    receipt = receipts[name]
                    if damage == 'failed': receipt['qualification'] = 'failed'
                    elif damage == 'source': receipt['sourceRevision'] = 'd' * 40
                    elif damage == 'node': receipt['nodeSha256'] = 'd' * 64
                    elif damage == 'runtime': receipt['runtimeQualified'] = True
                    elif damage == 'redistribution': receipt['redistributable'] = True
                    elif damage == 'archive': receipt['sourceArchiveSha256'] = 'invalid'
                    elif damage == 'payload': (output / directory / 'payload').write_bytes(b'changed')
                    elif damage == 'extra': (output / directory / 'extra').write_bytes(b'changed')
                    elif damage == 'lock': receipt['studioLockfileSha256' if name == 'studio' else 'lockfileSha256'] = 'd' * 64
                    elif damage == 'schema': receipt['schemaVersion'] = True
                    elif damage == 'package-manager': receipt['pnpmVersion' if name == 'plugin' else 'npmVersion'] = '0.0.0'
                    elif damage == 'browser': receipt['browserIncluded'] = True
                    (output / 'qualification.json').write_text(json.dumps(receipt))
                    result = subprocess.run([sys.executable, '-c', script], env=environment,
                                            cwd=Path(__file__).resolve().parents[1], capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((root / 'fl-windows-assets/host-assets.tar.gz').exists())
