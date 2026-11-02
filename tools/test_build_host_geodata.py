import hashlib
import io
import json
import os
import ssl
from http.client import IncompleteRead
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import zipfile

from build_host_geodata import build
from build_runtime import BuildError, inventory


class HostGeodataTests(unittest.TestCase):
    def fixture(self, root, *, damage=None):
        source = root / 'source'
        directory = source / 'server/base-image/geodata'
        directory.mkdir(parents=True)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('cities500.txt', b'synthetic city data\n')
            if damage == 'zip':
                archive.writestr('../escape', b'not allowed')
        content = {name: ('synthetic ' + name).encode() for name in [
            'admin1CodesASCII.txt', 'admin2Codes.txt', 'countryInfo.txt',
            'ne_10m_admin_0_countries.geojson', 'landmarks.ndjson.gz']}
        content['cities500.zip'] = stream.getvalue()
        lines = ['# Synthetic attribution record; preserve verbatim.']
        for name, data in content.items():
            digest = hashlib.sha256(data).hexdigest()
            url = 'https://raw.githubusercontent.com/Frameleaf/fixtures/fixed/' + name
            if damage == 'url':
                url = 'https://unapproved.invalid/' + name
            lines.append(f'{digest}  {name}  {url}')
        if damage == 'duplicate':
            lines.append(lines[-1])
        if damage == 'missing':
            lines.pop()
        lock = ('\n'.join(lines) + '\n').encode()
        (directory / 'geodata.lock').write_bytes(lock)
        docker = source / 'server/Dockerfile'
        docker.write_bytes(b'ARG GEODATA_SNAPSHOT=2026-10-11\nARG GEODATA_DATE=2026-10-10T00:00:00+00:00\n')
        if damage == 'date':
            docker.write_bytes(b'ARG GEODATA_SNAPSHOT=2026-10-11\nARG GEODATA_DATE=2026-10-12T00:00:00+00:00\n')
        if damage == 'crlf':
            docker.write_bytes(docker.read_bytes().replace(b'\n', b'\r\n'))
        env = {key: value for key, value in os.environ.items() if not key.upper().startswith('GIT_')}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', GIT_NO_REPLACE_OBJECTS='1')
        subprocess.run(['git', 'init', '-q', str(source)], check=True, capture_output=True, env=env)
        subprocess.run(['git', '-c', 'core.autocrlf=false', 'add', '.'], cwd=source, check=True, capture_output=True, env=env)
        subprocess.run(['git', '-c', 'user.name=AJ Taylor', '-c', 'user.email=aj@ajtaylor.net',
                        '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Synthetic geodata source'],
                       cwd=source, check=True, capture_output=True, env=env)
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True, env=env).strip()
        return source, revision, lock, content

    def test_selected_git_bytes_dates_and_attribution_survive_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, revision, lock, content = self.fixture(root)
            (source / 'server/base-image/geodata/geodata.lock').write_text('dirty checkout must not be used')
            def download(url, destination, digest):
                data = content[url.rsplit('/', 1)[1]]
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
                destination.write_bytes(data)
            output = root / 'output'
            with patch('build_host_geodata.download', side_effect=download):
                build(source, revision, output)
            report = json.loads((output / 'qualification.json').read_text())
            self.assertEqual(report['qualification'], 'passed')
            self.assertEqual(report['sourceRevision'], revision)
            self.assertFalse(report['runtimeQualified'])
            self.assertFalse(report['redistributable'])
            self.assertEqual(report['files'], inventory(output / 'geodata'))
            self.assertEqual(len(report['files']), 8)
            self.assertEqual((output / 'geodata/geodata.lock').read_bytes(), lock)
            self.assertEqual((output / 'geodata/geodata-date.txt').read_bytes(), b'2026-10-10T00:00:00+00:00')
            self.assertEqual((output / 'geodata/cities500.txt').read_bytes(), b'synthetic city data\n')
            self.assertFalse((output / 'geodata/cities500.zip').exists())
            self.assertFalse((output / 'work').exists())

    def test_invalid_source_contract_is_refused_before_network_or_output(self):
        for damage in ['url', 'duplicate', 'missing', 'date']:
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                source, revision, _, _ = self.fixture(root, damage=damage)
                with patch('build_host_geodata.download') as download, self.assertRaises(BuildError):
                    build(source, revision, root / 'output')
                download.assert_not_called()
                self.assertFalse((root / 'output').exists())

    def test_failed_primary_is_removed_before_verified_capture_fallback(self):
        for error in [BuildError('checksum mismatch'), ConnectionResetError('reset'),
                      ssl.SSLError('interrupted TLS'), IncompleteRead(b'partial', 10)]:
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                source, revision, _, content = self.fixture(root)
                def download(url, destination, digest):
                    self.assertFalse(destination.exists())
                    if url.startswith('https://static.frameleaf.cloud/'):
                        destination.write_bytes(b'wrong primary bytes')
                        raise error
                    data = content[url.rsplit('/', 1)[1]]
                    self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
                    destination.write_bytes(data)
                with patch('build_host_geodata.download', side_effect=download):
                    build(source, revision, root / 'output')
                report = json.loads((root / 'output/qualification.json').read_text())
                self.assertTrue(all(url.startswith('https://raw.githubusercontent.com/') for url in report['sources'].values()))
                self.assertFalse(list((root / 'output').rglob('*.part')))

    def test_committed_crlf_docker_arguments_keep_their_original_source_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, revision, _, content = self.fixture(root, damage='crlf')
            original = (source / 'server/Dockerfile').read_bytes()
            with patch('build_host_geodata.download', side_effect=lambda url, path, digest:
                       path.write_bytes(content[url.rsplit('/', 1)[1]])):
                build(source, revision, root / 'output')
            report = json.loads((root / 'output/qualification.json').read_text())
            self.assertEqual(report['sourceDockerfileSha256'], hashlib.sha256(original).hexdigest())
            self.assertEqual(report['date'], '2026-10-10T00:00:00+00:00')

    def test_fixture_git_is_isolated_from_inherited_repository_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            outer = root / 'outer'
            env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
            env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
            subprocess.run(['git', 'init', '-q', str(outer)], env=env, check=True, capture_output=True)
            (outer / 'existing').write_bytes(b'preserve caller repository')
            subprocess.run(['git', 'add', '.'], cwd=outer, env=env, check=True, capture_output=True)
            subprocess.run(['git', '-c', 'user.name=AJ Taylor', '-c', 'user.email=aj@ajtaylor.net',
                            '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Caller fixture'],
                           cwd=outer, env=env, check=True, capture_output=True)
            before = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=outer, env=env)
            with patch.dict(os.environ, {'GIT_DIR': str(outer / '.git'),
                                         'GIT_WORK_TREE': str(outer),
                                         'GIT_INDEX_FILE': str(outer / '.git/alternate-index')}):
                source, revision, _, _ = self.fixture(root)
            self.assertEqual(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=outer, env=env), before)
            self.assertEqual(subprocess.check_output(['git', 'status', '--porcelain'], cwd=outer, env=env), b'')
            self.assertFalse((outer / '.git/alternate-index').exists())
            self.assertEqual(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, env=env,
                                                    text=True).strip(), revision)

    def test_bad_archive_and_unavailable_sources_leave_only_failed_receipt(self):
        for damage in ['zip', 'unavailable']:
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                source, revision, _, content = self.fixture(root, damage=damage)
                def download(url, destination, digest):
                    if damage == 'unavailable':
                        destination.write_bytes(b'partial')
                        raise BuildError('unavailable')
                    destination.write_bytes(content[url.rsplit('/', 1)[1]])
                output = root / 'output'
                with patch('build_host_geodata.download', side_effect=download), self.assertRaises(BuildError):
                    build(source, revision, output)
                self.assertEqual({p.name for p in output.iterdir()}, {'qualification.json'})
                self.assertEqual(json.loads((output / 'qualification.json').read_text())['qualification'], 'failed')
                self.assertFalse((root / 'escape').exists())

    def test_existing_output_is_preserved_without_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, revision, _, _ = self.fixture(root)
            output = root / 'output'
            output.mkdir()
            (output / 'existing').write_bytes(b'preserve')
            with patch('build_host_geodata.download') as download, self.assertRaises(BuildError):
                build(source, revision, output)
            download.assert_not_called()
            self.assertEqual((output / 'existing').read_bytes(), b'preserve')

    def test_cleanup_failure_cannot_leave_a_successful_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, revision, _, content = self.fixture(root)
            output = root / 'output'
            with patch('build_host_geodata.download', side_effect=lambda url, path, digest:
                       path.write_bytes(content[url.rsplit('/', 1)[1]])), \
                 patch('build_host_geodata.shutil.rmtree', side_effect=PermissionError('cleanup blocked')), \
                 self.assertRaises(PermissionError):
                build(source, revision, output)
            self.assertEqual(json.loads((output / 'qualification.json').read_text())['qualification'], 'failed')
