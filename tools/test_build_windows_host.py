import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from build_runtime import BuildError, inventory, sha256
from build_windows_host import build


class WindowsHostAssemblyTests(unittest.TestCase):
    def file(self, root, name, data=b'fixture'):
        p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data)

    def stage(self, source, approvals, output):
        output.mkdir()
        roots = {}
        for role in ['assets', 'server', 'manager', 'database', 'raw', 'media', 'hdr', 'backup', 'ml']:
            root = output / 'inputs' / role; root.mkdir(parents=True)
            roots[role] = {'root': 'inputs/' + role}
            self.file(root, 'producer.json', b'{"approved":"synthetic"}')
            self.file(root, 'qualification.json', b'{"qualification":"passed"}')
        assets = output / roots['assets']['root']
        for name in ['web/www/index.html', 'plugin/plugin/dist/plugin.wasm',
                     'studio/studio-worker/studio/tools/bundled-worker.mjs',
                     'studio/studio-worker/studio/tools/bundled-worker-renderer.mjs',
                     'studio/studio-worker/fonts/font.ttf', 'studio/studio-worker/LICENSE']:
            self.file(assets, name)
        for name in ['web', 'plugin', 'studio']:
            self.file(assets, name + '/qualification.json', b'{"qualification":"passed"}')
        for role, name in [('database', 'postgres/bin/postgres.exe'), ('media', 'media/ffmpeg.exe'),
                           ('media', 'media/ffprobe.exe'), ('hdr', 'media/image-hdr.node'),
                           ('manager', 'manager/component.json'), ('backup', 'backup/component.json'),
                           ('raw', 'raw/bin/dcraw_emu.exe'), ('ml', 'payload/model')]:
            self.file(output / roots[role]['root'], name)
        self.file(output / roots['ml']['root'], 'manifest.json', b'{"synthetic":true}')
        self.file(output / roots['ml']['root'], 'manifest.sig', b'synthetic-signature')
        server = output / roots['server']['root']
        self.file(server, 'server-qualification.json', b'{"qualification":"passed"}')
        self.file(server, 'metadata-qualification.json', b'{"qualification":"passed"}')
        self.file(server, 'qualification.json', json.dumps({'qualification':'passed',
            'adaptedModuleSha256':'a'*64,'originalModuleSha256':'b'*64,
            'vendorVersion':'39.0.1','executableVendorVersion':'13.59.3'}).encode())
        host = output / 'bound-server-raw'
        self.file(host, 'server/dist/main.js')
        self.file(host, 'raw/bin/darktable-cli.exe')
        self.file(host, 'raw/bin/dcraw_emu.exe')
        self.file(host, 'work/home/fixture', b'private authoring scratch')
        binding = {'qualification':'passed','sourceRevision':'9118a01fdfb8a8cd20be24290660679b3a7c4de3',
                   'rawSource':{'fixture':True},'librawSource':{'fixture':True},
                   'files':{name:inventory(host/name) for name in ['server','raw']}}
        self.file(host, 'qualification.json', json.dumps(binding).encode())
        self.file(output, 'qualification.json', json.dumps({'qualification':'passed','components':roots}).encode())

    def support(self, source, revision, studio, output):
        self.assertTrue((studio / 'tools/bundled-worker-renderer.mjs').is_file())
        self.file(output, 'support/node/node.exe', b'private-node')
        self.file(output, 'support/node/LICENSE', b'node-license')
        self.file(output, 'support/browser/chrome-headless-shell.exe', b'private-browser')
        self.file(output, 'support/browser/LICENSE.headless_shell', b'browser-license')
        self.file(output, 'qualification.json', json.dumps({'qualification':'passed','sourceRevision':revision,
                  'files':inventory(output/'support')}).encode())

    def geodata(self, source, revision, output):
        self.file(output, 'geodata/cities500.txt', b'geodata')
        self.file(output, 'qualification.json', json.dumps({'qualification':'passed','sourceRevision':revision,
                  'files':inventory(output/'geodata')}).encode())

    def run_fixture(self, root, failure=None):
        commands = []
        def command(args, *, cwd, env):
            commands.append([str(x) for x in args])
            self.assertNotIn('GH_TOKEN', env)
            self.assertNotIn('GIT_DIR', env)
            if '--version' in args: return 'v26.11.1'
            if 'archive' in args:
                import tarfile
                archive = Path(args[args.index('--output')+1])
                with tarfile.open(archive, 'w') as tar:
                    tar.add(root/'source/server/test/native', arcname='server/test/native')
                return ''
            if '--test' in args:
                if failure == 'hdr': raise BuildError('synthetic hdr refusal')
                return 'TAP version 13\n1..1\n# pass 1\n# fail 0'
            if '--eval' in args:
                if 'hostEnvironment' in args[args.index('--eval')+1]:
                    return json.dumps({'PATH':'private-component-path','HOME':str(cwd/'home')})
                if failure == 'studio': raise BuildError('synthetic studio refusal')
                return json.dumps({'qualification':'passed','formats':['mp4-h264'],'softwareRenderer':True})
            name = Path(args[1]).name
            if failure == name: raise BuildError('synthetic consumer refusal')
            result = {'qualification':'passed','sourceRevision':'9118a01fdfb8a8cd20be24290660679b3a7c4de3'}
            if name == 'qualify_host_exiftool.mjs':
                result['componentReceiptSha256'] = sha256(Path(args[2])/'qualification.json')
            return json.dumps(result)
        def assemble(host, ml, manager, backup, output, revision, epoch):
            self.assertTrue((host/'server/dist/main.js').is_file())
            self.assertTrue((host/'raw/bin/darktable-cli.exe').is_file())
            self.assertTrue((host/'build/plugins/immich-plugin-core/dist/plugin.wasm').is_file())
            self.assertEqual((host/'licenses/Node-LICENSE').read_bytes(), b'node-license')
            self.assertFalse((host/'libraries').exists())
            self.assertTrue((ml/'payload/model').is_file())
            if failure == 'assembly': raise BuildError('synthetic signed ML refusal')
            self.file(output, 'payload/fixture', b'complete unsigned inventory fixture')
            self.file(output, 'work/home/private', b'must not retain')
            self.file(output, 'manifest.json', b'{"synthetic":true}')
            self.file(output, 'qualification.json', b'{"qualification":"passed","signaturePresent":false,"runtimeQualified":false,"redistributable":false}')
        from contextlib import ExitStack
        with ExitStack() as stack:
            for target, value in [('platform.system','Windows'), ('platform.machine','AMD64'),
                                  ('NODE_EXE_SHA',hashlib.sha256(b'private-node').hexdigest())]:
                stack.enter_context(patch('build_windows_host.'+target, return_value=value) if target.startswith('platform') else patch('build_windows_host.'+target,value))
            stack.enter_context(patch('build_windows_host.obtain_components', side_effect=self.stage))
            stack.enter_context(patch('build_windows_host.build_support', side_effect=self.support))
            stack.enter_context(patch('build_windows_host.build_geodata', side_effect=self.geodata))
            stack.enter_context(patch('build_windows_host.qualify_database', return_value={'physicalChecksumsVerified':True}))
            stack.enter_context(patch('build_windows_host.qualify_media', return_value={'qualification':'passed'}))
            stack.enter_context(patch('build_windows_host.verify_source_archive'))
            stack.enter_context(patch('build_windows_host.run', side_effect=command))
            stack.enter_context(patch('build_windows_host.git_blob', return_value=b'Frameleaf upstream license'))
            stack.enter_context(patch('build_windows_host.assemble', side_effect=assemble))
            stack.enter_context(patch.dict('os.environ',{'GH_TOKEN':'synthetic-must-not-reach-consumers','GIT_DIR':'synthetic-ignore'}))
            build(root/'source', {}, root/'output', 18)
        return commands

    def source(self, root):
        self.file(root/'source', 'server/test/native/image-hdr.test.mjs', b'current HDR fixture')
        self.file(root/'source', 'server/test/native/fixtures/pixels', b'synthetic fixture')

    def test_complete_authoring_path_runs_every_current_consumer_and_keeps_evidence_outside_payload(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();self.source(root)
            commands=self.run_fixture(root)
            result=json.loads((root/'output/qualification.json').read_text())
            self.assertEqual(result['qualification'],'passed')
            self.assertFalse(result['runtimeQualified']);self.assertFalse(result['redistributable'])
            self.assertFalse((root/'output/work').exists())
            self.assertFalse((root/'output/candidate/work').exists())
            self.assertEqual(set(result['consumers']),{'database','media','raw','metadata','plugin','hdr','studio'})
            self.assertTrue((root/'output/evidence/source-components/server/server-qualification.json').exists())
            for name in ['qualify_host_raw.mjs','qualify_host_exiftool.mjs','qualify_host_plugin.mjs']:
                self.assertTrue(any(name in ' '.join(c) for c in commands),name)
            self.assertTrue(any('--test' in c and c[-1].endswith('server/test/native/image-hdr.test.mjs') for c in commands))

    def test_consumer_and_signature_refusals_remove_all_executable_candidates_and_private_work(self):
        for failure in ['qualify_host_raw.mjs','qualify_host_exiftool.mjs','qualify_host_plugin.mjs','hdr','studio','assembly']:
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as td:
                root=Path(td).resolve();self.source(root)
                with self.assertRaises(BuildError): self.run_fixture(root,failure)
                self.assertFalse((root/'output/work').exists())
                self.assertFalse((root/'output/candidate').exists())
                self.assertEqual(json.loads((root/'output/qualification.json').read_text())['qualification'],'failed')

    def test_existing_output_and_bad_epoch_are_refused_without_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();self.source(root)
            self.file(root/'output','keep',b'unrelated')
            with self.assertRaises(BuildError): self.run_fixture(root)
            self.assertEqual((root/'output/keep').read_bytes(),b'unrelated')
            shutil.rmtree(root/'output')
            with self.assertRaises(BuildError): build(root/'source',{},root/'output',True)
            self.assertFalse((root/'output').exists())
