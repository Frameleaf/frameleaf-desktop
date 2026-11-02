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
from unittest import mock
import zipfile

import build_host_studio
import build_host_web
from build_runtime import BuildError, run


class WindowsHostAssetsTests(unittest.TestCase):
    def test_builders_reach_npm_using_the_unchanged_source_pinned_studio_node(self):
        """Exercise Git archive and toolchain admission, stopping before any dependency install."""
        for builder in [build_host_web, build_host_studio]:
            with self.subTest(builder=builder.__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                _, environment = self.fixture(root)
                source = root / 'application-source'
                configuration = {'node': '22.23.4', 'npm': '12.2.0',
                                 'upstreamCommit': 'a' * 40, 'sourceSha256': 'b' * 64,
                                 'lockfileSha256': hashlib.sha256(b'studio lock\n').hexdigest()}
                (source / 'studio/engine-build.json').write_text(json.dumps(configuration))
                files = ['package.json', 'pnpm-workspace.yaml', '.pnpmfile.cjs', 'LICENSE',
                         'packages/sdk/package.json', 'packages/ui/package.json',
                         'packages/justified-layout-wasm/package.json', 'packages/patches/example',
                         'web/package.json', 'i18n/example', 'licenses/example',
                         'scripts/frameleaf-studio-contracts.mjs', 'scripts/frameleaf-studio-rights.mjs',
                         'server/resources/studio-fonts/example', 'server/src/utils/studio-fonts.generated.ts']
                for name in files:
                    target = source / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(json.dumps({'packageManager': 'pnpm@12.11.2'}))
                git_environment = {key: value for key, value in environment.items()
                                   if not key.upper().startswith('GIT_')}
                git_environment.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
                subprocess.run(['git', '-c', 'core.autocrlf=false', 'add', '.'], cwd=source,
                               env=git_environment, check=True, capture_output=True)
                subprocess.run(['git', '-c', 'user.name=AJ Taylor', '-c', 'user.email=aj@ajtaylor.net',
                                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Pinned Studio build toolchain'],
                               cwd=source, env=git_environment, check=True, capture_output=True)
                revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source,
                                                   env=git_environment, text=True).strip()
                node = Path(environment['NODE_BINARY'])
                tar = root / ('archive-tools/tar.exe' if os.name == 'nt' else 'archive-tools/tar')
                tar.parent.mkdir()
                tar.write_bytes(b'test tar identity; not executed')
                tar.chmod(0o755)
                output = root / 'build-output'
                def command(arguments, **kwargs):
                    if arguments == [node, '--version']: return 'v22.23.4'
                    if arguments[-1] == '--version': return '12.11.2'
                    if arguments[1] == 'install':
                        self.assertEqual(real_which('tar', path=kwargs['env']['PATH']), str(tar))
                        self.assertEqual(real_which('git', path=kwargs['env']['PATH']), real_which('git'))
                        raise BuildError('test_dependency_install_boundary')
                    return run(arguments, **kwargs)
                real_which = builder.shutil.which
                with mock.patch.object(builder, 'run', side_effect=command), mock.patch.object(
                    builder.shutil, 'which', side_effect=lambda name: real_which('git') if name == 'git' else str(tar if name == 'tar' else node)
                ):
                    with self.assertRaisesRegex(BuildError, '^test_dependency_install_boundary$'):
                        builder.build(source, revision, node, output)
                receipt = json.loads((output / 'qualification.json').read_text())
                self.assertEqual(receipt['qualification'], 'failed')
                self.assertEqual(receipt['npmVersion'], '12.2.0')
                self.assertEqual(json.loads((output / 'work/source/studio/engine-build.json').read_text()), configuration)

    def archive_script(self):
        workflow = Path(__file__).resolve().parents[1] / '.github/workflows/windows-host-assets.yml'
        self.assertTrue(workflow.is_file(), 'Windows host assets producer is missing')
        return textwrap.dedent(workflow.read_text().split(
            '      - name: Archive the qualified host assets\n', 1
        )[1].split('        run: |\n', 1)[1].split('      - name:', 1)[0])

    def fixture(self, root):
        source = root / 'application-source'
        (source / 'studio').mkdir(parents=True)
        (source / 'pnpm-lock.yaml').write_bytes(b'workspace lock\n')
        (source / 'studio/engine-package-lock.json').write_bytes(b'studio lock\n')
        (source / 'studio/engine-build.json').write_text(json.dumps({'node': '22.23.4', 'npm': '12.2.0'}))
        git_environment = {key: value for key, value in os.environ.items() if not key.upper().startswith('GIT_')}
        git_environment.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
        subprocess.run(['git', 'init', '-q', str(source)], env=git_environment, check=True, capture_output=True)
        subprocess.run(['git', '-c', 'core.autocrlf=false', 'add', '.'], cwd=source,
                       env=git_environment, check=True, capture_output=True)
        subprocess.run(['git', '-c', 'user.name=AJ Taylor', '-c', 'user.email=aj@ajtaylor.net',
                        '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Synthetic source fixture'],
                       cwd=source, env=git_environment, check=True, capture_output=True)
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source,
                                           env=git_environment, text=True).strip()
        node = root / 'node.exe'
        node.write_bytes(b'synthetic Node 26 identity; never executed')
        studio_node = root / 'studio-node.exe'
        studio_node.write_bytes(b'synthetic Node 22 identity; never executed')
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
                'schemaVersion': 1, 'sourceRevision': revision,
                'sourceArchiveSha256': 'b' * 64,
                'nodeSha256': hashlib.sha256((node if name == 'plugin' else studio_node).read_bytes()).hexdigest(),
                'qualification': 'passed', 'runtimeQualified': False, 'redistributable': False,
                'files': {'payload': {'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}},
            }
            if name in ['web', 'plugin']:
                receipt.update(pnpmVersion='12.11.2', lockfileSha256=hashlib.sha256(b'workspace lock\n').hexdigest())
            if name in ['web', 'studio']:
                receipt.update(npmVersion='12.2.0', studioLockfileSha256=hashlib.sha256(b'studio lock\n').hexdigest())
            if name == 'studio': receipt['browserIncluded'] = False
            (output / 'qualification.json').write_text(json.dumps(receipt))
            receipts[name] = receipt
        return receipts, os.environ | {'RUNNER_TEMP': str(root), 'GITHUB_WORKSPACE': str(root),
                                      'HOST_SOURCE_REVISION': revision, 'NODE_BINARY': str(node),
                                      'STUDIO_NODE_BINARY': str(studio_node)}

    def test_archive_uses_selected_git_lock_bytes_despite_crlf_checkout_conversion(self):
        """A Windows checkout must not redefine the canonical lock hashes consumed by the builders."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            _, environment = self.fixture(root)
            (root / 'application-source/pnpm-lock.yaml').write_bytes(b'workspace lock\r\n')
            (root / 'application-source/studio/engine-package-lock.json').write_bytes(b'studio lock\r\n')
            result = subprocess.run([sys.executable, '-c', self.archive_script()], env=environment,
                                    cwd=Path(__file__).resolve().parents[1], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertTrue((root / 'fl-windows-assets/host-assets.tar.gz').is_file())

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
            failures = ['failed', 'source', 'node', 'node-swap', 'runtime', 'redistribution', 'archive',
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
                    elif damage == 'node-swap':
                        receipt['nodeSha256'] = hashlib.sha256(Path(environment[
                            'STUDIO_NODE_BINARY' if name == 'plugin' else 'NODE_BINARY']).read_bytes()).hexdigest()
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
