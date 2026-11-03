import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from build_runtime import BuildError, build_environment, run
from source_archive import verify_source_archive


class ArchiveReady(Exception):
    pass


class HostSourceArchiveTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "requires Git")
    def test_every_builder_archives_committed_bytes_under_crlf_settings(self):
        git = shutil.which("git")
        canonical = b"Synthetic source license fixture $Format:%H$\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            env = build_environment(root, os.environ)
            source = root / "source"
            source.mkdir()
            names = [
                "LICENSE", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml",
                ".pnpmfile.cjs", "mise.lock", "cosign.pub", "manager/fixture",
                ".github/frameleaf-release.cjs", ".github/verify-release-bundle.cjs",
                "packages/sdk/fixture", "packages/plugin-sdk/fixture", "packages/sql-tools/fixture",
                "packages/locked-crypto/dist/fixture.js",
                "packages/patches/fixture", "packages/plugin-core/fixture", "packages/ui/fixture",
                "packages/justified-layout-wasm/fixture", "web/fixture", "i18n/fixture", "licenses/fixture",
                "studio/runtime/fixture", "studio/tools/fixture", "server/resources/studio-fonts/fixture",
                "server/src/utils/studio-fonts.generated.ts", "docker/scripts/verify-server-package.mjs",
                "scripts/frameleaf-studio-contracts.mjs", "scripts/frameleaf-studio-rights.mjs",
            ]
            for folder in ['server', 'manager', 'web', 'packages/plugin-core', 'studio']:
                names.extend([folder + '/excluded.txt', folder + '/ignored/child.txt'])
            for name in names:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(canonical)
            (source / "package.json").write_text(json.dumps({"packageManager": "pnpm@12.11.2"}))
            for arguments in [
                ["init", "-q"], ["-c", "core.autocrlf=false", "add", "."],
                ["-c", "user.name=Frameleaf fixture", "-c", "user.email=fixture@invalid",
                 "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + str(root / "no-hooks"),
                 "commit", "-q", "-m", "fixture"],
                ["config", "core.autocrlf", "true"], ["config", "core.eol", "crlf"],
            ]:
                subprocess.run([git, *arguments], cwd=source, env=env, check=True, capture_output=True)
            revision = subprocess.check_output([git, "rev-parse", "HEAD"], cwd=source, env=env, text=True).strip()
            node = root / "node"
            node.write_bytes(b"fixture")

            def command(arguments, *, cwd, env):
                if arguments == [node, "--version"]:
                    return "v22.23.4" if name in {"web", "studio"} else "v26.11.1"
                self.assertIn("archive", arguments)
                return run(arguments, cwd=cwd, env=env)

            def validated(*arguments):
                verify_source_archive(*arguments)
                raise ArchiveReady()

            for attribute in [None, 'crlf', 'lf', 'export-ignore', 'export-subst']:
                info = source / '.git/info/attributes'
                if attribute == 'export-ignore':
                    info.write_text('**/excluded.txt text eol=crlf export-ignore\n**/ignored export-ignore\n**/ignored/*.txt text eol=crlf\n', encoding='utf-8')
                elif attribute == 'export-subst':
                    info.write_text('LICENSE export-subst\n', encoding='utf-8')
                elif attribute:
                    info.write_text('LICENSE text eol=' + attribute + '\n', encoding='utf-8')
                elif info.exists():
                    info.unlink()
                for name in ["server", "manager", "web", "plugin", "studio"]:
                    with self.subTest(builder=name, attribute=attribute):
                        module = importlib.import_module("build_host_" + name)
                        output = root / f'{name}-{attribute}'
                        expected = self.assertRaisesRegex(BuildError, 'source_archive_not_canonical') if attribute in {'crlf', 'export-subst'} else self.assertRaises(ArchiveReady)
                        with (
                            patch.object(module.shutil, "which", side_effect=lambda tool: git if tool == "git" else str(root / tool)),
                            patch.object(module, "run", side_effect=command),
                            patch.object(module, "verify_source_archive", side_effect=validated),
                            expected,
                        ):
                            module.build(source, revision, node, output)
                        if attribute in {'crlf', 'export-subst'}:
                            self.assertFalse((output / 'work/source.tar').exists())
                        else:
                            with tarfile.open(output / "work/source.tar") as archive:
                                self.assertEqual(archive.extractfile("LICENSE").read(), canonical)
                                if attribute == 'export-ignore':
                                    self.assertFalse(any(name.endswith('/excluded.txt') or '/ignored/' in name for name in archive.getnames()))

    @unittest.skipUnless(shutil.which("git"), "requires Git")
    def test_committed_attributes_take_precedence_over_uncommitted_worktree_attributes(self):
        git = shutil.which("git")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            env = build_environment(root, os.environ)
            source = root / 'source'
            source.mkdir()
            name = 'source with spaces.txt' if os.name == 'nt' else 'source with spaces\nand newline.txt'
            (source / name).write_bytes(b'committed bytes\n')
            (source / '.gitattributes').write_text('*.txt text eol=crlf\n', encoding='utf-8')
            for arguments in [
                ['init', '-q'], ['-c', 'core.autocrlf=false', 'add', '.'],
                ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid', '-c', 'commit.gpgsign=false',
                 '-c', 'core.hooksPath=' + str(root / 'no-hooks'), 'commit', '-qm', 'fixture'],
            ]:
                subprocess.run([git, *arguments], cwd=source, env=env, check=True, capture_output=True)
            revision = subprocess.check_output([git, 'rev-parse', 'HEAD'], cwd=source, env=env, text=True).strip()
            (source / '.gitattributes').write_text('*.txt text eol=lf\n', encoding='utf-8')
            archive = root / 'source.tar'
            def create_archive():
                run([git, '-c', 'core.autocrlf=false', '-c', 'core.eol=lf', 'archive', '--format=tar', '--output', archive, revision, name], cwd=source, env=env)
            create_archive()
            with self.assertRaisesRegex(BuildError, 'source_archive_not_canonical'):
                verify_source_archive(git, source, revision, [name], archive, env)
            self.assertFalse(archive.exists())
            (source / '.git/info/attributes').write_text('*.txt text eol=lf\n', encoding='utf-8')
            create_archive()
            verify_source_archive(git, source, revision, [name], archive, env)
            with tarfile.open(archive) as contents:
                self.assertEqual(contents.extractfile(name).read(), b'committed bytes\n')
