import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import build_host_plugin
import build_host_studio
import build_host_web
from build_runtime import BuildError, run as checked_run


class HostSourceArchiveTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('git'), 'requires Git')
    def test_source_and_license_bytes_survive_windows_git_settings(self):
        git = shutil.which('git')
        for builder in [build_host_web, build_host_plugin, build_host_studio]:
            with self.subTest(builder=builder.__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                source = root / 'source'
                source.mkdir()
                fixtures = {'package.json': b'{"packageManager":"pnpm@12.11.2"}\n',
                            'pnpm-lock.yaml': b'canonical lock\n', 'LICENSE': b'fixture license\n',
                            'studio/engine-package-lock.json': b'{}\n'}
                for name in ['pnpm-workspace.yaml', '.pnpmfile.cjs', 'mise.lock',
                             'packages/sdk/fixture', 'packages/ui/fixture',
                             'packages/justified-layout-wasm/fixture', 'packages/patches/fixture',
                             'packages/plugin-sdk/fixture', 'packages/plugin-core/fixture',
                             'web/fixture', 'i18n/fixture', 'licenses/fixture',
                             'studio/engine-build.json', 'server/resources/studio-fonts/fixture',
                             'server/src/utils/studio-fonts.generated.ts',
                             'scripts/frameleaf-studio-contracts.mjs', 'scripts/frameleaf-studio-rights.mjs']:
                    fixtures[name] = b'fixture\n'
                for name, content in fixtures.items():
                    path = source / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(content)
                for arguments in [['init', '-q'], ['add', '.'],
                                  ['-c', 'user.name=AJ Taylor', '-c', 'user.email=aj@ajtaylor.net',
                                   '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=' + str(root / 'no-hooks'),
                                   'commit', '-q', '-m', 'fixture'],
                                  ['config', 'core.autocrlf', 'true'], ['config', 'core.eol', 'crlf']]:
                    subprocess.run([git, *arguments], cwd=source, check=True, capture_output=True)
                revision = subprocess.check_output([git, 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
                node = root / 'node'
                node.write_bytes(b'fixture')

                def command(arguments, *, cwd, env):
                    if arguments[0] == node:
                        return 'v26.11.1'
                    self.assertIn('archive', arguments)
                    checked_run(arguments, cwd=cwd, env=env)
                    with tarfile.open(arguments[arguments.index('--output') + 1]) as archive:
                        lock = 'studio/engine-package-lock.json' if builder is build_host_studio else 'pnpm-lock.yaml'
                        for name in ['LICENSE', lock]:
                            self.assertEqual(archive.extractfile(name).read(), fixtures[name])
                    raise BuildError('canonical_archive_checked_before_build')

                with (patch.object(builder.shutil, 'which', side_effect=lambda name: git if name == 'git' else str(root / name)),
                      patch.object(builder, 'run', side_effect=command),
                      self.assertRaisesRegex(BuildError, 'canonical_archive_checked_before_build')):
                    builder.build(source, revision, node, root / 'output')
