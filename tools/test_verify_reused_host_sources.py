from copy import deepcopy
import hashlib
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from build_runtime import BuildError
from verify_reused_host_sources import verify


class ReusedHostSourceTests(unittest.TestCase):
    def fixture(self):
        blobs = {'.nvmrc': b'22.23.4\n',
                 'server/native/image-hdr.cc': b'production native code',
                 'server/native/CMakeLists.txt': b'production build recipe',
                 'server/test/native/fixtures/image.bin': b'fixture pixels',
                 'server/test/native/fixtures/café.bin': b'Unicode fixture pixels',
                 'server/test/native/image-hdr.test.mjs': b'current runtime fixture'}
        database = json.loads((Path(__file__).parents[1] / 'runtime/host-database.json').read_text())
        blobs['docker/postgres/Dockerfile'] = (f"ARG POSTGRES_IMAGE={database['postgresImage']}\n"
            f"ARG PGVECTOR_VERSION={database['pgvectorVersion']}\n"
            f"ARG PGVECTOR_SHA256={database['pgvectorSourceSha256']}\n").encode()
        patches = {name: b'approved patch' for name in ['patch-darktable-lens.py', 'patch-darktable-mask-geometry.py']}
        repositories = {'darktable': ('darktable-org/darktable', '.'),
                        'rawspeed': ('darktable-org/rawspeed', 'src/external/rawspeed'),
                        'whereami': ('gpakosz/whereami', 'src/external/whereami'),
                        'opencl': ('KhronosGroup/OpenCL-Headers', 'src/external/OpenCL'),
                        'lensfun': ('lensfun/lensfun', 'lensfun')}
        raw = {'name': 'darktable', 'repository': 'darktable-org/darktable', 'version': '5.6.2',
               'revision': 'b' * 40, 'lensfunVersion': '0.3.4',
               'patches': {name: hashlib.sha256(value).hexdigest() for name, value in patches.items()},
               'inputs': [{'name': name, 'repository': repo, 'path': path, 'revision': 'b' * 40,
                           'sha256': 'c' * 64, 'url': f'https://codeload.github.com/{repo}/tar.gz/' + 'b' * 40}
                          for name, (repo, path) in repositories.items()]}
        libraw = {'name': 'libraw', 'repository': 'LibRaw/LibRaw', 'revision': 'c' * 40}
        for name, value in patches.items(): blobs['server/test/native/' + name] = value
        blobs['server/base-image/sources/darktable.json'] = json.dumps(raw).encode()
        blobs['server/base-image/sources/libraw.json'] = json.dumps(libraw).encode()
        archive = {'url': 'https://github.com/jellyfin/jellyfin-ffmpeg/releases/download/v8.1.3-1/media.zip',
                   'checksum': 'sha256:' + 'd' * 64}
        blobs['mise.lock'] = ('[[tools."github:jellyfin/jellyfin-ffmpeg"]]\nversion="8.1.3-1"\n'
            '[tools."github:jellyfin/jellyfin-ffmpeg"."platforms.windows-x64"]\n'
            f'url="{archive["url"]}"\nchecksum="{archive["checksum"]}"\n').encode()
        blobs['server/base-image/packages/ffmpeg.json'] = b'{"name":"ffmpeg","version":"8.1.3-1"}'
        codecs = {}
        for name, repo in [('libheif', 'strukturag/libheif'), ('libultrahdr', 'google/libultrahdr')]:
            codecs[name] = {'name': name, 'repository': repo, 'revision': 'd' * 40,
                            'patchChecksum': hashlib.sha256(b'codec patch').hexdigest()}
            blobs[f'server/base-image/sources/{name}.json'] = json.dumps(codecs[name]).encode()
            blobs[f'server/base-image/sources/{name}-hdr.patch'] = b'codec patch'
        snapshot = {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                    for name, data in blobs.items() if name.startswith(('server/native/', 'server/test/native/fixtures/'))}
        snapshot['server/test/native/image-hdr.test.mjs'] = {'bytes': 3, 'sha256': hashlib.sha256(b'old').hexdigest()}
        receipts = {role: {'qualification': 'passed', 'sourceRevision': 'a' * 40} for role in ['database', 'raw', 'media', 'hdr']}
        receipts['database']['pins'] = database
        receipts['raw'].update(source=raw, librawSource=libraw)
        receipts['media'].update(archive=archive, version='8.1.3-1')
        receipts['hdr'].update(codecs=codecs, nodeVersion='26.11.1', sourceFiles=snapshot)
        return blobs, receipts

    def check(self, blobs, receipts):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td).resolve()
            def blob(git, root, revision, name, env):
                self.assertEqual((root, revision), (source, 'e' * 40))
                self.assertNotIn('GIT_DIR', env)
                return blobs[name]
            names = '\0'.join(name for name in blobs if name.startswith(('server/native/', 'server/test/native/')))
            with patch('verify_reused_host_sources.git_blob', side_effect=blob), \
                    patch('verify_reused_host_sources.subprocess.check_output', return_value=names):
                return verify(source, 'e' * 40, receipts)

    def test_original_receipts_unchanged_and_test_drift_requires_runtime_qualification(self):
        blobs, receipts = self.fixture()
        original = deepcopy(receipts)
        result = self.check(blobs, receipts)
        self.assertEqual(receipts, original)
        self.assertTrue(result['sourceContractsMatch'])
        self.assertEqual(result['hdr']['changedFixturePaths'], ['server/test/native/image-hdr.test.mjs'])
        self.assertEqual(result['hdr']['currentBuildControlNode'], '22.23.4')
        self.assertEqual(result['hdr']['originalBuildNode'], '26.11.1')
        self.assertFalse(result['runtimeQualified'])
        self.assertFalse(result['redistributable'])

    def test_source_and_receipt_contract_drift_is_refused(self):
        expected = {
            'database': 'host_reused_database_pin_changed',
            'raw-patch': 'host_raw_source_contract_invalid',
            'raw-source': 'host_reused_raw_source_changed',
            'media': 'host_reused_media_pin_changed',
            'codec': 'host_media_source_pin_invalid',
            'native': 'host_reused_hdr_snapshot_changed:server/native/image-hdr.cc',
            'fixture': 'host_reused_hdr_snapshot_changed:server/test/native/fixtures/image.bin',
            'missing': 'host_reused_hdr_snapshot_paths_changed',
            'added': 'host_reused_hdr_snapshot_paths_changed',
            'failed': 'host_reused_receipt_invalid',
            'revision': 'host_reused_receipt_invalid',
            'node': 'host_reused_hdr_host_node_changed',
            'malformed-snapshot': 'host_reused_hdr_snapshot_invalid',
        }
        for damage in expected:
            with self.subTest(damage=damage):
                blobs, receipts = self.fixture()
                if damage == 'database': receipts['database']['pins']['postgresSourceSha256'] = '0' * 64
                elif damage == 'raw-patch': blobs['server/test/native/patch-darktable-lens.py'] += b'drift'
                elif damage == 'raw-source': receipts['raw']['librawSource']['revision'] = 'f' * 40
                elif damage == 'media': receipts['media']['archive']['checksum'] = 'sha256:' + 'f' * 64
                elif damage == 'codec': blobs['server/base-image/sources/libheif-hdr.patch'] += b'drift'
                elif damage == 'native': blobs['server/native/image-hdr.cc'] += b'drift'
                elif damage == 'fixture': blobs['server/test/native/fixtures/image.bin'] += b'drift'
                elif damage == 'missing': del blobs['server/native/image-hdr.cc']
                elif damage == 'added': blobs['server/native/new.cc'] = b'unaccounted'
                elif damage == 'failed': receipts['raw']['qualification'] = 'failed'
                elif damage == 'revision': receipts['hdr']['sourceRevision'] = 'main'
                elif damage == 'node': receipts['hdr']['nodeVersion'] = '22.23.4'
                elif damage == 'malformed-snapshot': receipts['hdr']['sourceFiles']['server/test/native/image-hdr.test.mjs']['sha256'] = 'invalid'
                with self.assertRaises(BuildError) as refused:
                    self.check(blobs, receipts)
                self.assertEqual(str(refused.exception), expected[damage])

    def test_real_git_objects_are_used_despite_dirty_worktree(self):
        blobs, receipts = self.fixture()
        with tempfile.TemporaryDirectory() as td:
            source = Path(td).resolve()
            for name, data in blobs.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
            env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', GIT_NO_REPLACE_OBJECTS='1')
            subprocess.run(['git', 'init', '-q'], cwd=source, env=env, check=True, capture_output=True)
            subprocess.run(['git', '-c', 'core.autocrlf=false', 'add', '.'], cwd=source, env=env, check=True, capture_output=True)
            subprocess.run(['git', '-c', 'user.name=AJ Taylor', '-c', 'user.email=aj@ajtaylor.net',
                            '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Synthetic native inputs'],
                           cwd=source, env=env, check=True, capture_output=True)
            revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, env=env, text=True).strip()
            (source / 'server/native/image-hdr.cc').write_bytes(b'dirty checkout must not be consumed')
            with patch.dict(os.environ, {'GIT_DIR': str(source / 'nonexistent')}):
                result = verify(source, revision, receipts)
            self.assertTrue(result['sourceContractsMatch'])
            self.assertEqual(result['sourceRevision'], revision)
            self.assertEqual(result['consumedInputs']['server/native/image-hdr.cc']['sha256'],
                             hashlib.sha256(blobs['server/native/image-hdr.cc']).hexdigest())
