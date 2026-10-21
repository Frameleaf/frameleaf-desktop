import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from build_host_manager import stage_manager, build
from build_runtime import BuildError, run as checked_run


class HostManagerTests(unittest.TestCase):
    def fixture(self, root):
        source = root / "source"
        (source / "build").mkdir(parents=True)
        (source / "build/main.js").write_text("export const fixture = true;")
        (source / "ui/dist").mkdir(parents=True)
        (source / "ui/dist/index.html").write_text("<main>Manager</main>")
        (source / "src").mkdir()
        (source / "src/private.ts").write_text("not runtime code")
        (source / "test").mkdir()
        (source / "test/private.ts").write_text("not runtime code")
        (source / "LICENSE").write_text("fixture license")
        (source / "release-worker.cjs").write_text("module.exports = {};")
        (source / "media-copy.cjs").write_text("module.exports = {};")
        (root / ".github").mkdir()
        for name in ["frameleaf-release.cjs", "verify-release-bundle.cjs"]:
            (root / ".github" / name).write_text("module.exports = {};")
        (root / "cosign.pub").write_text("fixture public key")
        (source / "package.json").write_text(
            json.dumps(
                {
                    "name": "@frameleaf/manager",
                    "type": "module",
                    "dependencies": {"example": "1.0.0"},
                    "devDependencies": {"compiler": "1.0.0"},
                }
            )
        )
        (source / "package-lock.json").write_text("{}")
        dependency = source / "node_modules/example"
        dependency.mkdir(parents=True)
        (dependency / "package.json").write_text('{"name":"example","version":"1.0.0"}')
        (dependency / "index.js").write_text("export const value = true;")
        return source

    @unittest.skipUnless(shutil.which("git"), "requires Git")
    def test_source_archive_preserves_lockfile_and_license_under_windows_git_settings(self):
        git = shutil.which("git")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            canonical = b'{"lockfileVersion":3}\n'
            fixtures = {"manager/package.json": b'{}\n', "manager/package-lock.json": canonical,
                        "LICENSE": b"fixture license\n", ".github/frameleaf-release.cjs": b"fixture\n",
                        ".github/verify-release-bundle.cjs": b"fixture\n", "cosign.pub": b"fixture\n"}
            for name, content in fixtures.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            for arguments in [["init", "-q"], ["add", "."],
                              ["-c", "user.name=AJ Taylor", "-c", "user.email=aj@ajtaylor.net",
                               "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + str(root / "no-hooks"),
                               "commit", "-q", "-m", "fixture"],
                              ["config", "core.autocrlf", "true"], ["config", "core.eol", "crlf"]]:
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
                for name in ["manager/package-lock.json", "LICENSE"]:
                    self.assertEqual((output / "work/source" / name).read_bytes(), fixtures[name])
                raise BuildError("canonical_archive_checked_before_build")

            with (patch("build_host_manager.shutil.which", side_effect=lambda name: git if name == "git" else str(root / "npm")),
                  patch("build_host_manager.run", side_effect=command),
                  self.assertRaisesRegex(BuildError, "canonical_archive_checked_before_build")):
                build(source, revision, node, output)

    def test_stages_only_production_manager_with_bound_source_and_licenses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = self.fixture(root)
            output = root / "runtime"
            receipt = stage_manager(source, output, "a" * 40)
            self.assertEqual(receipt["sourceRevision"], "a" * 40)
            self.assertEqual(receipt["nodeVersion"], "26.11.1")
            self.assertFalse(receipt["runtimeQualified"])
            self.assertEqual(
                json.loads((output / "component.json").read_text()), receipt
            )
            for name in [
                "app/build/main.js",
                "app/ui/dist/index.html",
                "node_modules/example/index.js",
                "LICENSE",
                ".github/frameleaf-release.cjs",
                ".github/verify-release-bundle.cjs",
                "app/release-worker.cjs",
                "app/media-copy.cjs",
                "cosign.pub",
            ]:
                self.assertTrue((output / name).is_file(), name)
            for name in ["src", "test", "package-lock.json"]:
                self.assertFalse((output / name).exists(), name)
            with self.assertRaises(BuildError):
                stage_manager(source, output, "a" * 40)
            with self.assertRaises(BuildError):
                stage_manager(source, source / "nested", "a" * 40)

    def test_missing_ui_dependency_or_backend_cannot_be_packaged(self):
        for missing in [
            "build/main.js",
            "ui/dist/index.html",
            "node_modules/example/package.json",
            "LICENSE",
            "release-worker.cjs",
            "media-copy.cjs",
        ]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                source = self.fixture(root)
                (source / missing).unlink()
                with self.assertRaises((BuildError, FileNotFoundError)):
                    stage_manager(source, root / "runtime", "a" * 40)

    @unittest.skipIf(
        os.name == "nt",
        "Unix link fixture; Windows reparse qualification remains separate",
    )
    def test_cannot_copy_symlinks_or_private_source_as_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = self.fixture(root)
            outside = root / "outside"
            outside.write_text("private input")
            (source / "build/escape").symlink_to(outside)
            with self.assertRaises(BuildError):
                stage_manager(source, root / "runtime", "a" * 40)

    def test_invalid_revision_or_package_identity_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = self.fixture(root)
            with self.assertRaises(BuildError):
                stage_manager(source, root / "runtime", "bad")
            (source / "package.json").write_text(
                '{"name":"other","type":"module","dependencies":{}}'
            )
            with self.assertRaises(BuildError):
                stage_manager(source, root / "runtime", "a" * 40)
