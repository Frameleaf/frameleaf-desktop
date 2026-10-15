import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "builder", Path(__file__).with_name("build_runtime.py")
)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class RuntimeBuilderTests(unittest.TestCase):
    def test_inventory_is_stable_and_binds_every_byte(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "python").write_bytes(b"fixture")
            first = builder.inventory(root)
            self.assertEqual(first, builder.inventory(root))
            self.assertEqual(first["python"]["bytes"], 7)
            (root / "python").write_bytes(b"changed")
            self.assertNotEqual(first, builder.inventory(root))

    def test_flattened_links_cannot_escape_the_downloaded_python(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "binary").write_bytes(b"python")
            try:
                (source / "alias").symlink_to("binary")
            except OSError:
                self.skipTest("symlink creation unavailable")
            builder.copy_python(source, root / "copy")
            self.assertFalse((root / "copy" / "alias").is_symlink())
            self.assertEqual((root / "copy" / "alias").read_bytes(), b"python")
            (source / "alias").unlink()
            (root / "private").write_bytes(b"do not copy")
            (source / "alias").symlink_to(root / "private")
            with self.assertRaises(builder.BuildError):
                builder.copy_python(source, root / "bad")

    def test_manifest_matches_supervisor_contract_and_rejects_unsupported_platform(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "python").write_bytes(b"fixture")
            value = builder.manifest(
                root, "python", "a" * 40, 7, "macos", "aarch64", "CPUExecutionProvider"
            )
            self.assertEqual(value["schemaVersion"], 1)
            self.assertEqual(value["sourceRevision"], "a" * 40)
            self.assertEqual(value["files"], builder.inventory(root))
            with self.assertRaises(builder.BuildError):
                builder.manifest(
                    root,
                    "../python",
                    "a" * 40,
                    7,
                    "macos",
                    "aarch64",
                    "CPUExecutionProvider",
                )

    def test_python_download_alias_does_not_count_as_another_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / "cpython-3.12.13-macos-aarch64-none"
            actual.mkdir()
            try:
                (root / "cpython-3.12-macos-aarch64-none").symlink_to(
                    actual, target_is_directory=True
                )
            except OSError:
                self.skipTest("directory symlink unavailable")
            self.assertEqual(builder.downloaded_python(root), actual)
            (root / "cpython-other").mkdir()
            with self.assertRaises(builder.BuildError):
                builder.downloaded_python(root)

    def test_build_tools_keep_the_exact_exported_hashes(self):
        value = (
            "setuptools==80.9.0 \\\n    --hash=sha256:"
            + "a" * 64
            + "\n# note\nother==1\n"
        )
        self.assertEqual(
            builder.requirement_block(value, "setuptools"), value.split("# note")[0]
        )
        with self.assertRaises(builder.BuildError):
            builder.requirement_block("setuptools>=1\n", "setuptools")

    def test_git_source_bytes_are_canonical_despite_checkout_line_endings(self):
        import shutil

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git = shutil.which("git")
            env = builder.build_environment(root, {})
            for arguments in (["init"], ["config", "core.autocrlf", "true"]):
                builder.run([git, *arguments], cwd=root, env=env)
            (root / "module.py").write_bytes(b"value = 1\n")
            builder.run([git, "add", "module.py"], cwd=root, env=env)
            builder.run(
                [
                    git,
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-m",
                    "fixture",
                ],
                cwd=root,
                env=env,
            )
            revision = builder.run([git, "rev-parse", "HEAD"], cwd=root, env=env)
            (root / "module.py").write_bytes(b"value = 1\r\n")
            self.assertEqual(
                builder.git_blob(git, root, revision, "module.py", env), b"value = 1\n"
            )

    def test_build_environment_does_not_inherit_cloud_or_python_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            environment = builder.build_environment(
                Path(temporary),
                {
                    "PATH": "/bin",
                    "HOME": "private",
                    "AWS_SECRET_ACCESS_KEY": "secret",
                    "PYTHONPATH": "external",
                    "UV_INDEX_URL": "https://other.invalid",
                },
            )
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
            self.assertNotIn("PYTHONPATH", environment)
            self.assertNotIn("UV_INDEX_URL", environment)
            self.assertNotEqual(environment["HOME"], "private")


if __name__ == "__main__":
    unittest.main()


class RuntimeFailureReceiptTests(unittest.TestCase):
    def test_inventory_reports_the_exact_case_collision(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        import stat

        root = Path("fixture")
        with (
            patch.object(
                Path, "rglob", return_value=[root / "Python.h", root / "python.h"]
            ),
            patch.object(
                builder,
                "regular",
                return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_size=1),
            ),
            patch.object(builder, "sha256", return_value="a" * 64),
        ):
            with self.assertRaisesRegex(
                builder.BuildError, "runtime_case_collision.*python.h"
            ):
                builder.inventory(root)

    def test_private_headless_python_omits_terminal_database_but_keeps_licences(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "share" / "terminfo" / "E").mkdir(parents=True)
            (source / "share" / "terminfo" / "E" / "Eterm").write_bytes(b"terminal")
            (source / "share" / "doc").mkdir()
            (source / "share" / "doc" / "LICENSE").write_bytes(b"licence")
            (source / "python").write_bytes(b"interpreter")
            builder.copy_python(source, root / "copy")
            self.assertFalse((root / "copy" / "share" / "terminfo").exists())
            self.assertEqual(
                (root / "copy" / "share" / "doc" / "LICENSE").read_bytes(), b"licence"
            )
            self.assertEqual((root / "copy" / "python").read_bytes(), b"interpreter")

    def test_dependency_sources_match_the_locked_platform_markers(self):
        self.assertIn(
            "https://download.pytorch.org/whl/cpu",
            builder.dependency_indexes("linux", "x86_64"),
        )
        for system, architecture in [
            ("windows", "x86_64"),
            ("macos", "aarch64"),
            ("linux", "aarch64"),
        ]:
            self.assertEqual(
                builder.dependency_indexes(system, architecture),
                ["--default-index", "https://pypi.org/simple"],
            )
