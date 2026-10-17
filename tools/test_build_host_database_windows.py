import tempfile
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from build_host_database_windows import build, qualify, stage_dependencies
from build_runtime import BuildError


class WindowsDatabaseTests(unittest.TestCase):
    def test_private_pkgconf_wins_over_strawberry_pkg_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            dependencies = root / "dependencies"
            private = dependencies / "tools/pkgconf/pkgconf.exe"

            def which(name, *, path=None):
                if name == "pkg-config":
                    return str(root / "Strawberry/perl/bin/pkg-config.BAT")
                if name == "pkgconf":
                    return str(private) if path == str(private.parent) else None
                return str(root / "build-tools" / name)

            def inspect_environment(git, source, revision, name, env):
                self.assertEqual(env["PKG_CONFIG"], str(private))
                self.assertIn(str(private.parent), env["PATH"].split(os.pathsep))
                raise BuildError("synthetic_before_source_download")

            with (
                patch("build_host_database_windows.platform.system", return_value="Windows"),
                patch("build_host_database_windows.platform.machine", return_value="AMD64"),
                patch("build_host_database_windows.shutil.which", side_effect=which),
                patch("build_host_database_windows.git_blob", side_effect=inspect_environment),
                self.assertRaisesRegex(BuildError, "synthetic_before_source_download"),
            ):
                build(root, "a" * 40, dependencies, root / "output")

    def test_invalid_source_cannot_create_a_build_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / "output"
            with (
                patch("build_host_database_windows.platform.system", return_value="Windows"),
                patch("build_host_database_windows.platform.machine", return_value="AMD64"),
                self.assertRaisesRegex(BuildError, "host_database_source_invalid"),
            ):
                build(root, "untrusted-branch", root, output)
            self.assertFalse(output.exists())

    def test_private_dll_closure_rejects_an_unbundled_non_system_dependency(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix, dependencies = root / "pg", root / "dependencies"
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin/postgres.exe").write_bytes(b"synthetic PE")
            (dependencies / "bin").mkdir(parents=True)
            (dependencies / "bin/icu.dll").write_bytes(b"synthetic ICU")
            (dependencies / "share/icu").mkdir(parents=True)
            (dependencies / "share/icu/copyright").write_text("synthetic notice")
            for extra in ["KERNEL32.dll\n  api-ms-win-crt-runtime-l1-1-0.dll", "missing.dll"]:
                with self.subTest(extra=extra), patch(
                    "build_host_database_windows.run", return_value="  icu.dll\n  " + extra
                ):
                    if extra == "missing.dll":
                        with self.assertRaisesRegex(BuildError, "host_database_dll_missing"):
                            stage_dependencies(prefix, dependencies, "dumpbin", {})
                    else:
                        stage_dependencies(prefix, dependencies, "dumpbin", {})
                        self.assertEqual((prefix / "bin/icu.dll").read_bytes(), b"synthetic ICU")
                        self.assertTrue((prefix / "licenses/icu/copyright").is_file())

    def test_linked_dependency_is_refused_before_copying(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix, dependencies = root / "pg", root / "dependencies"
            (prefix / "bin").mkdir(parents=True)
            (dependencies / "bin").mkdir(parents=True)
            original = root / "outside.dll"
            original.write_bytes(b"outside")
            try:
                (dependencies / "bin/linked.dll").symlink_to(original)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(BuildError, "runtime_link_forbidden"):
                stage_dependencies(prefix, dependencies, "dumpbin", {})
            self.assertFalse((prefix / "bin/linked.dll").exists())

    def test_qualification_drains_owned_state_and_erases_the_password_on_failure(self):
        lock = {"postgresVersion": "19beta4", "pgvectorVersion": "0.8.7"}
        expected = {
            "serverVersion": "19beta4", "vectorVersion": "0.8.7",
            "extensions": ["cube", "earthdistance", "pg_trgm", "unaccent", "uuid-ossp", "vector"],
            "checksums": "on", "neighbor": 1,
        }
        for failure in [None, "initdb", "facts"]:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                prefix = output / "postgres"
                calls = []

                def command(arguments, *, cwd, env):
                    calls.append([str(arg) for arg in arguments])
                    self.assertEqual(len(env["PGPASSWORD"]), 64)
                    if Path(arguments[0]).name == "initdb.exe":
                        self.assertTrue((output / "fixture-password").exists())
                        if failure == "initdb":
                            raise BuildError("synthetic_initdb_failure")
                        (output / "fixture-data").mkdir()
                        (output / "fixture-data/PG_VERSION").write_text("19")
                    if "--file" in arguments:
                        Path(arguments[arguments.index("--file") + 1]).write_bytes(b"synthetic dump")
                    if "-c" in arguments and str(arguments[-1]).startswith("SELECT json_build_object"):
                        return json.dumps({**expected, "neighbor": 2} if failure == "facts" else expected)
                    return ""

                with patch("build_host_database_windows.run", side_effect=command):
                    if failure:
                        with self.assertRaisesRegex(BuildError, "synthetic_initdb_failure|host_database_fixture_mismatch"):
                            qualify(prefix, output, lock, {})
                    else:
                        result = qualify(prefix, output, lock, {})
                        self.assertEqual(result["fresh"], result["restored"])
                        self.assertEqual(result["fresh"], result["restarted"])
                        self.assertTrue(result["physicalChecksumsVerified"])
                self.assertFalse((output / "fixture-password").exists())
                stops = [args for args in calls if args[-1] == "stop"]
                self.assertEqual(len(stops), 0 if failure == "initdb" else 1 if failure else 2)
