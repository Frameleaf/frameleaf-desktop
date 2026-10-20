import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import build_host_server
from build_host_server import build, stage_server
from build_runtime import BuildError, run as checked_run


class HostServerTests(unittest.TestCase):
    def test_runtime_metadata_keeps_versions_without_build_machine_paths(self):
        for origin in ["file:///developer/private-build", "file:///C:/Users/builder/private-build"]:
            with self.subTest(origin=origin), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                dependencies = {}
                for name in ["@frameleaf/plugin-sdk", "@frameleaf/sql-tools"]:
                    package = root / "node_modules" / name / "package.json"
                    package.parent.mkdir(parents=True)
                    package.write_text(json.dumps({"name": name, "version": "1.2.3-beta.1"}))
                    dependencies[name] = name + "@" + origin + "/" + name
                original = {"name": "frameleaf", "type": "module", "exports": {".": "./dist/main.js"}, "dependencies": dependencies}
                (root / "package.json").write_text(json.dumps(original))
                for name in ["pnpm-lock.yaml", "pnpm-workspace.yaml", "dist/tsconfig.build.tsbuildinfo"]:
                    path = root / name
                    path.parent.mkdir(exist_ok=True)
                    path.write_text("private build-only state")
                (root / "dist/main.js").write_text("export const value = 42;")
                retained = root / "node_modules/@frameleaf/plugin-sdk/pnpm-lock.yaml"
                retained.write_text("dependency source provenance")
                build_host_server.clean_runtime_metadata(root)
                actual = json.loads((root / "package.json").read_text())
                self.assertEqual(actual, {**original, "dependencies": {name: "1.2.3-beta.1" for name in dependencies}})
                for name in ["pnpm-lock.yaml", "pnpm-workspace.yaml", "dist/tsconfig.build.tsbuildinfo"]:
                    self.assertFalse((root / name).exists())
                self.assertEqual((root / "dist/main.js").read_text(), "export const value = 42;")
                self.assertEqual(retained.read_text(), "dependency source provenance")

    def test_runtime_metadata_refuses_wrong_or_unversioned_workspace_packages(self):
        for invalid in [None, {"name": "other", "version": "1.2.3"}, {"name": "@frameleaf/plugin-sdk", "version": "file:///private-build"}]:
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = {"dependencies": {"@frameleaf/plugin-sdk": "workspace:*", "@frameleaf/sql-tools": "workspace:*"}}
                (root / "package.json").write_text(json.dumps(original))
                package = root / "node_modules/@frameleaf/plugin-sdk/package.json"
                package.parent.mkdir(parents=True)
                package.write_text(json.dumps(invalid))
                with self.assertRaises(BuildError):
                    build_host_server.clean_runtime_metadata(root)
                self.assertEqual(json.loads((root / "package.json").read_text()), original)

    @unittest.skipUnless(shutil.which("git"), "requires Git")
    def test_source_archive_preserves_canonical_bytes_with_windows_git_settings(self):
        git = shutil.which("git")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            canonical = b'{"canonical":true}\n'
            fixtures = {
                "package.json": b'{"packageManager":"pnpm@12.11.2"}\n',
                "pnpm-lock.yaml": b"fixture\n", "pnpm-workspace.yaml": b"fixture\n",
                ".pnpmfile.cjs": b"fixture\n", "LICENSE": b"fixture\n",
                "packages/sdk/fixture": b"fixture", "packages/plugin-sdk/fixture": b"fixture",
                "packages/sql-tools/fixture": b"fixture", "packages/patches/fixture": b"fixture",
                "server/src/schema/catalog/fixture.json": canonical,
                "studio/runtime/fixture": b"fixture", "studio/tools/fixture": b"fixture",
                "docker/scripts/verify-server-package.mjs": b"fixture",
            }
            for name, data in fixtures.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            for arguments in [
                ["init", "-q"], ["add", "."],
                ["-c", "user.name=Frameleaf fixture", "-c", "user.email=fixture@invalid",
                 "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + str(root / "no-hooks"),
                 "commit", "-q", "-m", "fixture"],
                ["config", "core.autocrlf", "true"], ["config", "core.eol", "crlf"],
            ]:
                subprocess.run([git, *arguments], cwd=source, check=True, capture_output=True)
            revision = subprocess.check_output([git, "rev-parse", "HEAD"], cwd=source, text=True).strip()
            node = root / "node"
            node.write_bytes(b"fixture")
            output = root / "output"

            def command(arguments, *, cwd, env):
                if arguments[0] == node:
                    return "v26.11.1"
                if "archive" in arguments:
                    return checked_run(arguments, cwd=cwd, env=env)
                self.assertEqual(
                    (output / "work/source/server/src/schema/catalog/fixture.json").read_bytes(), canonical
                )
                raise BuildError("canonical_archive_checked_before_build")

            with (
                patch("build_host_server.shutil.which", side_effect=lambda name: git if name == "git" else str(root / "pnpm")),
                patch("build_host_server.run", side_effect=command),
                self.assertRaisesRegex(BuildError, "canonical_archive_checked_before_build"),
            ):
                build(source, revision, node, output)

    def test_compiler_has_bounded_heap_without_inheriting_node_injection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            node = root / "node"
            node.write_text("fixture")

            def inspect_environment(git, source, revision, name, env):
                self.assertEqual(env.get("NODE_OPTIONS"), "--max-old-space-size=3072")
                raise BuildError("fixture_environment_checked")

            with (
                patch("build_host_server.shutil.which", return_value="/fixture/tool"),
                patch("build_host_server.git_blob", side_effect=inspect_environment),
                patch.dict(os.environ, {"NODE_OPTIONS": "--require=/untrusted.js"}),
                self.assertRaisesRegex(BuildError, "fixture_environment_checked"),
            ):
                build(root, "a" * 40, node, root / "output")

    def test_staged_runtime_has_regular_dependencies_without_package_manager_links(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "dist").mkdir(parents=True)
            (source / "dist/main.js").write_text("export const value = 42;")
            package = source / "node_modules/example"
            package.mkdir(parents=True)
            (package / "index.js").write_text("module.exports = 42;")
            for name in [".bin", ".pnpm"]:
                folder = source / "node_modules" / name
                folder.mkdir()
                (folder / "unused").write_text("package-manager-only executable")
            (source / "node_modules/.modules.yaml").write_text(
                "storeDir: /developer/store"
            )
            (source / "node_modules/.pnpm-workspace-state-v1.json").write_text(
                '{"lastValidatedTimestamp":123,"projects":{"/developer/workspace":{}}}'
            )
            destination = root / "runtime"
            files = stage_server(source, destination)
            self.assertEqual(
                (destination / "node_modules/example/index.js").read_text(),
                "module.exports = 42;",
            )
            self.assertIn("dist/main.js", files)
            self.assertFalse((destination / "node_modules/.bin").exists())
            self.assertFalse((destination / "node_modules/.pnpm").exists())
            self.assertFalse((destination / "node_modules/.modules.yaml").exists())
            self.assertFalse((destination / "node_modules/.pnpm-workspace-state-v1.json").exists())
            self.assertNotIn("node_modules/.pnpm-workspace-state-v1.json", files)
            with self.assertRaises(BuildError):
                stage_server(source, destination)
            with self.assertRaises(BuildError):
                stage_server(source, source / "nested-output")
            self.assertFalse((source / "nested-output").exists())

    @unittest.skipIf(
        os.name == "nt",
        "Unix link fixture; Windows reparse acceptance remains separate",
    )
    def test_runtime_links_cannot_read_external_files_or_follow_directory_cycles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "private"
            outside.write_text("must not be copied")
            for name, target in [("file", outside), ("directory", root)]:
                source = root / name
                source.mkdir()
                (source / "escape").symlink_to(
                    target, target_is_directory=target.is_dir()
                )
                destination = root / (name + "-output")
                with self.assertRaises(BuildError):
                    stage_server(source, destination)
                self.assertFalse(destination.exists())
