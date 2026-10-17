import os
import tempfile
import unittest
from pathlib import Path

from build_host_server import stage_server
from build_runtime import BuildError


class HostServerTests(unittest.TestCase):
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
