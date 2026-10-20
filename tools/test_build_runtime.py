import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "builder", Path(__file__).with_name("build_runtime.py")
)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class RuntimeBuilderTests(unittest.TestCase):
    def test_metal_component_staging_checks_hashes_and_keeps_entrypoint_in_private_package(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            component = root / "component"
            component.mkdir()
            fields = {
                "__init__.py": "packageInitSha256",
                "entry.py": "entrySha256",
                "metal_observer.py": "loaderSha256",
                "metal_inference.py": "adapterSha256",
                "_frameleaf_coreml_observer.dylib": "librarySha256",
            }
            provenance = {}
            for name, field in fields.items():
                (component / name).write_bytes(b"owned fixture")
                provenance[field] = builder.sha256(component / name)
            (component / "provenance.json").write_text(json.dumps(provenance))
            payload = root / "payload"
            payload.mkdir()
            builder.stage_metal_observer(payload, component)
            self.assertEqual(
                set(builder.inventory(payload)),
                {"private/frameleaf_desktop_ml/" + name for name in fields},
            )
            self.assertEqual(
                (payload / "private/frameleaf_desktop_ml/entry.py").read_bytes(),
                b"owned fixture",
            )
            (component / "entry.py").write_bytes(b"changed")
            fresh = root / "fresh"
            fresh.mkdir()
            with self.assertRaises(builder.BuildError):
                builder.stage_metal_observer(fresh, component)
            self.assertFalse((fresh / "private").exists())

    def test_metal_manifest_requires_fixed_signed_entrypoint_files_and_namespace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "python").write_bytes(b"fixture")
            names = [
                "__init__.py",
                "entry.py",
                "metal_observer.py",
                "metal_inference.py",
                "_frameleaf_coreml_observer.dylib",
            ]
            package = root / "private/frameleaf_desktop_ml"
            package.mkdir(parents=True)
            for name in names:
                (package / name).write_bytes(b"fixture")
            value = builder.manifest(
                root,
                "python",
                "a" * 40,
                7,
                "macos",
                "aarch64",
                "CoreMLExecutionProvider",
                "frameleaf_ml",
                metal_observer=True,
            )
            self.assertEqual(value["deviceObserver"], {"kind": "metal-v1"})
            for provider, namespace in [
                ("CPUExecutionProvider", "frameleaf_ml"),
                ("CoreMLExecutionProvider", "immich_ml"),
            ]:
                with self.assertRaises(builder.BuildError):
                    builder.manifest(
                        root,
                        "python",
                        "a" * 40,
                        7,
                        "macos",
                        "aarch64",
                        provider,
                        namespace,
                        metal_observer=True,
                    )
            (package / "entry.py").unlink()
            with self.assertRaises(builder.BuildError):
                builder.manifest(
                    root,
                    "python",
                    "a" * 40,
                    7,
                    "macos",
                    "aarch64",
                    "CoreMLExecutionProvider",
                    "frameleaf_ml",
                    metal_observer=True,
                )

    def test_source_build_exception_is_only_used_by_the_locked_legacy_dependency(self):
        setuptools = "setuptools==80.9.0 --hash=sha256:" + "a" * 64 + "\n"
        antlr = "antlr4-python3-runtime==4.9.3 --hash=sha256:" + "b" * 64 + "\n"
        self.assertEqual(builder.source_build_requirements(setuptools), "")
        self.assertEqual(
            builder.source_build_requirements(antlr + setuptools), setuptools
        )
        for invalid in [antlr, antlr.replace("4.9.3", "4.9.4") + setuptools]:
            with self.assertRaises(builder.BuildError):
                builder.source_build_requirements(invalid)

    def test_source_package_is_exact_complete_and_never_ambiguous(self):
        def files(namespace):
            return [
                f"machine-learning/{namespace}/{name}"
                for name in [
                    "__init__.py",
                    "native_runtime.py",
                    "native_qualification.py",
                ]
            ]

        for namespace in ["immich_ml", "frameleaf_ml"]:
            self.assertEqual(builder.source_package(files(namespace)), namespace)
        for invalid in [
            [],
            files("foreign"),
            files("frameleaf_ml")[:-1],
            files("frameleaf_ml") + files("immich_ml"),
        ]:
            with self.assertRaises(builder.BuildError):
                builder.source_package(invalid)

    def test_manifest_binds_only_supported_module_namespaces(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "python").write_bytes(b"fixture")
            for namespace in ["immich_ml", "frameleaf_ml"]:
                result = builder.manifest(
                    root,
                    "python",
                    "a" * 40,
                    7,
                    "macos",
                    "aarch64",
                    "CPUExecutionProvider",
                    namespace,
                )
                self.assertEqual(result.get("moduleNamespace", "immich_ml"), namespace)
                self.assertEqual(
                    "moduleNamespace" in result, namespace == "frameleaf_ml"
                )
            with self.assertRaises(builder.BuildError):
                builder.manifest(
                    root,
                    "python",
                    "a" * 40,
                    7,
                    "macos",
                    "aarch64",
                    "CPUExecutionProvider",
                    "foreign",
                )

    def test_cuda_manifest_is_limited_to_windows_and_linux_x86_64(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "python").write_bytes(b"fixture")
            for system in ["windows", "linux"]:
                value = builder.manifest(
                    root,
                    "python",
                    "a" * 40,
                    7,
                    system,
                    "x86_64",
                    "CUDAExecutionProvider",
                )
                self.assertEqual(value["provider"], "CUDAExecutionProvider")
                self.assertEqual(value["files"], builder.inventory(root))
            for system, architecture in [
                ("macos", "aarch64"),
                ("macos", "x86_64"),
                ("windows", "aarch64"),
                ("linux", "aarch64"),
            ]:
                with self.assertRaises(builder.BuildError):
                    builder.manifest(
                        root,
                        "python",
                        "a" * 40,
                        7,
                        system,
                        architecture,
                        "CUDAExecutionProvider",
                    )

    def test_cuda_dependency_sources_do_not_substitute_linux_cpu_wheels(self):
        for system in ["windows", "linux"]:
            self.assertEqual(
                builder.dependency_indexes(system, "x86_64", "cuda"),
                ["--default-index", "https://pypi.org/simple"],
            )
        with self.assertRaises(builder.BuildError):
            builder.dependency_indexes("linux", "x86_64", "foreign")

    def test_coreml_manifest_is_limited_to_apple_silicon_macos(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "python").write_bytes(b"fixture")
            value = builder.manifest(
                root,
                "python",
                "a" * 40,
                7,
                "macos",
                "aarch64",
                "CoreMLExecutionProvider",
            )
            self.assertEqual(value["provider"], "CoreMLExecutionProvider")
            for system, architecture in [
                ("windows", "x86_64"),
                ("linux", "aarch64"),
                ("macos", "x86_64"),
            ]:
                with self.assertRaises(builder.BuildError):
                    builder.manifest(
                        root,
                        "python",
                        "a" * 40,
                        7,
                        system,
                        architecture,
                        "CoreMLExecutionProvider",
                    )

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
        import stat
        from types import SimpleNamespace
        from unittest.mock import patch

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
            self.assertRaisesRegex(
                builder.BuildError, "runtime_case_collision.*python.h"
            ),
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
        for architecture in ["x86_64", "aarch64"]:
            self.assertIn(
                "https://download.pytorch.org/whl/cpu",
                builder.dependency_indexes("linux", architecture),
            )
        for system, architecture in [
            ("windows", "x86_64"),
            ("macos", "aarch64"),
        ]:
            self.assertEqual(
                builder.dependency_indexes(system, architecture),
                ["--default-index", "https://pypi.org/simple"],
            )

    def test_windows_system_root_survives_uppercase_environment_keys(self):
        import os
        from types import SimpleNamespace
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            system = str(root / "Windows")
            with patch.object(
                builder, "os", SimpleNamespace(name="nt", defpath=os.defpath)
            ):
                for key in ("SYSTEMROOT", "SystemRoot"):
                    environment = builder.build_environment(
                        root, {key: system, "AWS_SECRET_ACCESS_KEY": "secret"}
                    )
                    self.assertEqual(environment["SystemRoot"], system)
                    self.assertEqual(
                        environment["PATH"], str(Path(system) / "System32")
                    )
                    self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
