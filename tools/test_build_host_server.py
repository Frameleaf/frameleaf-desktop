import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import build_host_server
from build_host_server import build, stage_server
from build_runtime import BuildError


class HostServerTests(unittest.TestCase):
    def test_runtime_metadata_keeps_versions_without_build_machine_paths(self):
        for origin, version in [("file:///developer/private-build", "0.0.0"), ("file:///C:/Users/builder/private-build", "1.2.3-beta.1"), ("file:///developer/private-build", "1.2.3-alpha-beta.1+build.001")]:
            with self.subTest(origin=origin, version=version), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                dependencies = {}
                for name in ["@frameleaf/plugin-sdk", "@frameleaf/sql-tools"]:
                    package = root / "node_modules" / name / "package.json"
                    package.parent.mkdir(parents=True)
                    package.write_text(json.dumps({"name": name, "version": version}))
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
                self.assertEqual(actual, {**original, "dependencies": {name: version for name in dependencies}})
                for name in ["pnpm-lock.yaml", "pnpm-workspace.yaml", "dist/tsconfig.build.tsbuildinfo"]:
                    self.assertFalse((root / name).exists())
                self.assertEqual((root / "dist/main.js").read_text(), "export const value = 42;")
                self.assertEqual(retained.read_text(), "dependency source provenance")

    def test_runtime_metadata_refuses_wrong_or_unversioned_workspace_packages(self):
        for invalid in [None, {"name": "other", "version": "1.2.3"}, *[{"name": "@frameleaf/plugin-sdk", "version": value} for value in ["file:///private-build", "1.2.3-alpha..1", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01", "1.2.3+build..meta", "١.2.3"]]]:
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = {"dependencies": {"@frameleaf/plugin-sdk": "workspace:*", "@frameleaf/sql-tools": "workspace:*"}}
                (root / "package.json").write_text(json.dumps(original))
                for name in original["dependencies"]:
                    manifest = root / "node_modules" / name / "package.json"
                    manifest.parent.mkdir(parents=True)
                    manifest.write_text(json.dumps({"name": name, "version": "1.2.3"}))
                package = root / "node_modules/@frameleaf/plugin-sdk/package.json"
                package.write_text(json.dumps(invalid))
                with self.assertRaises(BuildError):
                    build_host_server.clean_runtime_metadata(root)
                self.assertEqual(json.loads((root / "package.json").read_text()), original)

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
