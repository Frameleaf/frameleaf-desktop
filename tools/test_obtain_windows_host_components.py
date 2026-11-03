import copy
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from build_runtime import BuildError, inventory
from obtain_windows_host_components import obtain, WORKFLOWS, SOURCE_REVISION, SOURCE_ARCHIVES


class WindowsComponentSetTests(unittest.TestCase):
    def fixture(self, root):
        approvals = {role: {'artifactId': i + 1, 'runId': i + 100, 'runAttempt': 1,
                     'headSha': 'a' * 40, 'workflow': workflow, 'archiveSha256': 'b' * 64}
                     for i, (role, workflow) in enumerate(WORKFLOWS.items())}
        payloads = {'web': ('www', None), 'plugin': ('plugin', 'windows-x64'),
                    'studio': ('studio-worker', 'Windows-AMD64'),
                    'server': ('server', 'Windows-AMD64'), 'manager': ('manager', None),
                    'database': ('postgres', 'windows-x86_64'), 'raw': ('raw', 'Windows-AMD64'),
                    'media': ('media', 'windows-x64'), 'hdr': ('media', 'windows-AMD64'),
                    'backup': ('backup', None)}
        records = {}
        for name, (directory, target) in payloads.items():
            path = root / name
            (path / directory).mkdir(parents=True)
            (path / directory / 'café-原本').write_bytes(name.encode())
            records[name] = {'schemaVersion': 1, 'qualification': 'passed', 'sourceRevision': SOURCE_REVISION,
                            'files': inventory(path / directory), 'redistributable': False}
            if target: records[name]['platform'] = target
            if name in SOURCE_ARCHIVES:
                records[name].update(sourceArchiveSha256=SOURCE_ARCHIVES[name],
                                     nodeSha256='c' * 64, lockfileSha256='d' * 64,
                                     studioLockfileSha256='e' * 64, pnpmVersion='12.11.2',
                                     npmVersion='12.2.0', runtimeQualified=False)
            if name in ['server', 'manager']: records[name]['nodeVersion'] = '26.11.1'
            if name == 'studio': records[name]['browserIncluded'] = False
            if name == 'backup':
                del records[name]['sourceRevision']
                (path / directory / 'component.json').write_text(json.dumps(records[name]))
            (path / 'qualification.json').write_text(json.dumps(records[name]), encoding='utf-8')
        server = root / 'server'
        (server / 'server-qualification.json').write_bytes((server / 'qualification.json').read_bytes())
        records['server'] = {**records['server'], 'files': {'server': records['server']['files']}}
        (server / 'qualification.json').write_text(json.dumps(records['server']), encoding='utf-8')
        ml = root / 'ml'
        (ml / 'payload').mkdir(parents=True)
        (ml / 'payload/model').write_bytes(b'not executable fixture')
        (ml / 'manifest.json').write_text(json.dumps({'platform': 'windows', 'architecture': 'x86_64',
                                                    'files': inventory(ml / 'payload')}))
        (ml / 'manifest.sig').write_bytes(b'not a genuine signature')
        return approvals

    def acquired(self, fixture, approved, output):
        role = next(k for k, v in self.approvals.items() if v == approved)
        output.mkdir()
        component = output / 'component'
        component.mkdir()
        # Use the actual nested TAR layout so extraction is exercised, not mocked.
        names = {'assets': ('host-assets.tar.gz', {'web': fixture / 'web', 'plugin': fixture / 'plugin', 'studio': fixture / 'studio'}),
                 'server': ('windows-server-candidate.tar.gz', {'server-candidate': fixture / 'server'}),
                 'manager': ('manager-component.tar.gz', {'': fixture / 'manager'}),
                 'raw': ('windows-raw-component.tar.gz', {'raw-candidate': fixture / 'raw'}),
                 'backup': ('backup-component.tar.gz', {'': fixture / 'backup'}),
                 'ml': ('runtime.tar', {'': fixture / 'ml'})}
        if role in names:
            filename, paths = names[role]
            with tarfile.open(component / filename, 'w') as archive:
                for prefix, source in paths.items():
                    for child in source.iterdir():
                        archive.add(child, arcname='/'.join(x for x in [prefix, child.name] if x))
        else:
            import shutil
            shutil.copytree(fixture / role, component, dirs_exist_ok=True)
        (output / 'producer.json').write_text(json.dumps({'approved': approved}))

    def run_set(self, root, fixture, approvals):
        self.approvals = approvals
        # Existing source, metadata-chain and Restic validators have their own tests; exercise their composition here.
        def bind(source, server, raw, destination):
            destination.mkdir()
            (destination / 'qualification.json').write_text('{"qualification":"passed"}')
        with patch('obtain_windows_host_components.platform.system', return_value='Windows'), \
                patch('obtain_windows_host_components.platform.machine', return_value='AMD64'), \
                patch('obtain_windows_host_components.backup_component', side_effect=lambda p: json.loads((p / 'component.json').read_text())), \
                patch('obtain_windows_host_components.obtain_component', side_effect=lambda a, p: self.acquired(fixture, a, p)), \
                patch('obtain_windows_host_components.verify_reused', return_value={'sourceContractsMatch': True, 'runtimeQualified': False}), \
                patch('obtain_windows_host_components.bind_raw', side_effect=bind), \
                patch('obtain_windows_host_components.git_blob', side_effect=lambda git, source, rev, name, env: {
                    'package.json': b'{"packageManager":"pnpm@12.11.2"}',
                    'pnpm-lock.yaml': b'workspace', 'manager/package-lock.json': b'manager',
                    'studio/engine-package-lock.json': b'studio',
                    'studio/engine-build.json': b'{"npm":"12.2.0"}',
                }[name]), \
                patch('obtain_windows_host_components.NODE_EXE_SHA', 'c' * 64), \
                patch('obtain_windows_host_components.BUILD_NODE_SHA', 'c' * 64):
            return obtain(root / 'source', approvals, root / 'result')

    def prepare(self, root):
        (root / 'source').mkdir()
        fixture = root / 'fixtures'
        approvals = self.fixture(fixture)
        for name in ['web', 'plugin', 'studio', 'server', 'manager']:
            filename = fixture / name / ('server-qualification.json' if name == 'server' else 'qualification.json')
            record = json.loads(filename.read_text())
            record['lockfileSha256'] = hashlib.sha256(b'manager' if name == 'manager' else b'workspace').hexdigest()
            record['studioLockfileSha256'] = hashlib.sha256(b'studio').hexdigest()
            filename.write_text(json.dumps(record))
        return fixture, approvals

    def test_fixed_set_is_staged_with_original_receipts_and_explicit_unsigned_limits(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve(); fixture, approvals = self.prepare(root)
            originals = {str(f.relative_to(fixture)): f.read_bytes() for f in fixture.rglob('*.json')}
            self.run_set(root, fixture, approvals)
            result = json.loads((root / 'result/qualification.json').read_text())
            self.assertEqual(result['qualification'], 'passed')
            self.assertEqual(set(result['components']), set(WORKFLOWS))
            self.assertFalse(result['runtimeQualified'])
            self.assertFalse(result['redistributable'])
            self.assertFalse(result['mlSignatureVerified'])
            self.assertTrue(result['requiresCurrentWindowsConsumers'])
            self.assertEqual((root / 'result/inputs/assets/expanded/web/www/café-原本').read_bytes(), b'web')
            self.assertTrue((root / 'result/bound-server-raw/qualification.json').is_file())
            self.assertEqual({str(f.relative_to(fixture)): f.read_bytes() for f in fixture.rglob('*.json')}, originals)
            for name, original in originals.items():
                role, path = name.split('/', 1)
                component = 'assets' if role in {'web', 'plugin', 'studio'} else role
                staged = root / 'result' / result['components'][component]['root']
                if component == 'assets': staged /= role
                self.assertEqual((staged / path).read_bytes(), original, name)

    def test_bad_role_policy_refuses_before_any_download(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve(); fixture, approvals = self.prepare(root)
            for damage in ['missing', 'extra', 'workflow', 'duplicate', 'bool']:
                broken = copy.deepcopy(approvals)
                if damage == 'missing': del broken['hdr']
                elif damage == 'extra': broken['unexpected'] = broken['hdr']
                elif damage == 'workflow': broken['hdr']['workflow'] = broken['media']['workflow']
                elif damage == 'duplicate': broken['hdr']['artifactId'] = broken['media']['artifactId']
                else: broken['hdr']['artifactId'] = True
                with self.subTest(damage=damage), patch('obtain_windows_host_components.obtain_component') as download:
                    with self.assertRaisesRegex(BuildError, '^host_windows_component_policy_invalid$'):
                        obtain(root / 'source', broken, root / 'result')
                    download.assert_not_called()
                self.assertFalse((root / 'result').exists())

    def test_mutated_payload_and_wrong_source_platform_or_build_contract_remove_owned_output(self):
        expected = {
            'bytes': 'host_windows_component_inventory_mismatch:plugin',
            'source': 'host_windows_component_source_mismatch:plugin',
            'platform': 'host_windows_component_receipt_invalid',
            'archive': 'host_windows_component_source_mismatch:plugin',
            'lock': 'host_windows_component_source_mismatch:plugin',
            'node': 'host_windows_component_source_mismatch:plugin',
            'failed': 'host_windows_component_receipt_invalid',
            'release': 'host_windows_component_receipt_invalid',
            'ml-target': 'host_windows_component_ml_candidate_invalid',
            'ml-bytes': 'host_windows_component_ml_candidate_invalid',
        }
        for damage in expected:
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as td:
                root = Path(td).resolve(); fixture, approvals = self.prepare(root)
                p = fixture / 'plugin/qualification.json'
                record = json.loads(p.read_text())
                if damage == 'bytes': (fixture / 'plugin/plugin/café-原本').write_bytes(b'tampered')
                elif damage == 'source': record['sourceRevision'] = 'f' * 40
                elif damage == 'platform': record['platform'] = 'linux-x64'
                elif damage == 'archive': record['sourceArchiveSha256'] = 'f' * 64
                elif damage == 'lock': record['lockfileSha256'] = 'f' * 64
                elif damage == 'node': record['nodeSha256'] = 'f' * 64
                elif damage == 'failed': record['qualification'] = 'failed'
                elif damage == 'release': record['redistributable'] = True
                elif damage == 'ml-target':
                    m = fixture / 'ml/manifest.json'; v = json.loads(m.read_text()); v['platform'] = 'linux'; m.write_text(json.dumps(v))
                elif damage == 'ml-bytes': (fixture / 'ml/payload/model').write_bytes(b'tampered')
                p.write_text(json.dumps(record))
                with self.assertRaises(BuildError) as refused:
                    self.run_set(root, fixture, approvals)
                self.assertEqual(str(refused.exception), expected[damage])
                self.assertFalse((root / 'result').exists())

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve(); fixture, approvals = self.prepare(root)
            (root / 'result').mkdir(); (root / 'result/keep').write_bytes(b'unrelated')
            with self.assertRaisesRegex(BuildError, '^host_windows_component_paths_invalid$'):
                self.run_set(root, fixture, approvals)
            self.assertEqual((root / 'result/keep').read_bytes(), b'unrelated')

    def test_dependency_refusal_and_receipt_publication_failure_leave_no_candidate(self):
        for target in ['verify_reused', 'bind_raw', 'publication']:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as td:
                root = Path(td).resolve(); fixture, approvals = self.prepare(root)
                if target == 'publication':
                    real_replace = Path.replace
                    def replace(path, destination):
                        if path.name == 'qualification.json.part': raise OSError('synthetic publication failure')
                        return real_replace(path, destination)
                    error_patch = patch('pathlib.Path.replace', replace)
                else:
                    # run_set patches the real dependency boundary; refuse at the point it is invoked.
                    def fail_at_call(*args, **kwargs):
                        raise BuildError('synthetic dependency refusal')
                    # Wrap the actual top-level obtain call so the injected dependency wins its inner patch.
                    from obtain_windows_host_components import obtain as real_obtain
                    def refused_obtain(*args):
                        with patch('obtain_windows_host_components.' + target, side_effect=fail_at_call):
                            return real_obtain(*args)
                    error_patch = patch(__name__ + '.obtain', side_effect=refused_obtain)
                with error_patch, self.assertRaises((BuildError, OSError)):
                    self.run_set(root, fixture, approvals)
                self.assertFalse((root / 'result').exists())

    def test_nested_links_and_unexpected_outer_layout_are_refused_by_real_unpack(self):
        for damage in ['link', 'outer-layout']:
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as td:
                root = Path(td).resolve(); fixture, approvals = self.prepare(root)
                original = self.acquired
                def acquire(*args):
                    original(*args)
                    approved, output = args[1:]
                    if approved['workflow'] != WORKFLOWS['assets']: return
                    if damage == 'outer-layout':
                        (output / 'component/unexpected').write_bytes(b'extra')
                    else:
                        with tarfile.open(output / 'component/host-assets.tar.gz', 'a') as archive:
                            link = tarfile.TarInfo('web/www/unsafe')
                            link.type = tarfile.SYMTYPE
                            link.linkname = '../outside'
                            archive.addfile(link)
                with patch.object(self, 'acquired', side_effect=acquire), self.assertRaises(BuildError) as refused:
                    self.run_set(root, fixture, approvals)
                expected = 'host_ffmpeg_archive_entry_invalid' if damage == 'link' else 'host_windows_component_archive_layout_invalid:assets'
                self.assertEqual(str(refused.exception), expected)
                self.assertFalse((root / 'result').exists())

    def test_foreign_host_is_refused_before_download(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve(); fixture, approvals = self.prepare(root)
            with patch('obtain_windows_host_components.platform.system', return_value='Linux'), \
                    patch('obtain_windows_host_components.obtain_component') as download:
                with self.assertRaisesRegex(BuildError, '^host_windows_component_target_unsupported$'):
                    obtain(root / 'source', approvals, root / 'result')
                download.assert_not_called()
            self.assertFalse((root / 'result').exists())
