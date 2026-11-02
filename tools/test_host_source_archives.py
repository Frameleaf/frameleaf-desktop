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
from source_archive import require_lf_archive


class ArchiveReady(Exception):
    pass


class HostSourceArchiveTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "requires Git")
    def test_every_builder_archives_committed_bytes_under_crlf_settings(self):
        git = shutil.which("git")
        canonical = b"Synthetic source license fixture\n"
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
                    return "v26.11.1"
                self.assertIn("archive", arguments)
                run(arguments, cwd=cwd, env=env)
                raise ArchiveReady()

            for attribute in [None, 'crlf', 'lf']:
                info = source / '.git/info/attributes'
                if attribute:
                    info.write_text('LICENSE text eol=' + attribute + '\n', encoding='utf-8')
                elif info.exists():
                    info.unlink()
                for name in ["server", "manager", "web", "plugin", "studio"]:
                    with self.subTest(builder=name, attribute=attribute):
                        module = importlib.import_module("build_host_" + name)
                        output = root / f'{name}-{attribute}'
                        expected = self.assertRaisesRegex(BuildError, 'source_archive_eol') if attribute == 'crlf' else self.assertRaises(ArchiveReady)
                        with (
                            patch.object(module.shutil, "which", side_effect=lambda tool: git if tool == "git" else str(root / tool)),
                            patch.object(module, "run", side_effect=command),
                            expected,
                        ):
                            module.build(source, revision, node, output)
                        if attribute == 'crlf':
                            self.assertFalse((output / 'work/source.tar').exists())
                        else:
                            with tarfile.open(output / "work/source.tar") as archive:
                                self.assertEqual(archive.extractfile("LICENSE").read(), canonical)

    @unittest.skipUnless(shutil.which("git"), "requires Git")
    def test_committed_attributes_take_precedence_over_uncommitted_worktree_attributes(self):
        git = shutil.which("git")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            env = build_environment(root, os.environ)
            source = root / 'source'
            source.mkdir()
            name = 'source with spaces\nand newline.txt'
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
            with self.assertRaisesRegex(BuildError, 'source_archive_eol'):
                require_lf_archive(git, source, revision, [name], env)
            (source / '.git/info/attributes').write_text('*.txt text eol=lf\n', encoding='utf-8')
            require_lf_archive(git, source, revision, [name], env)
            archive = root / 'source.tar'
            run([git, '-c', 'core.autocrlf=false', '-c', 'core.eol=lf', 'archive', '--format=tar', '--output', archive, revision, name], cwd=source, env=env)
            with tarfile.open(archive) as contents:
                self.assertEqual(contents.extractfile(name).read(), b'committed bytes\n')
