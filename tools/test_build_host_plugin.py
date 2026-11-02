import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import tomllib
import unittest
from unittest.mock import patch

import build_host_plugin
from build_host_plugin import tool_pin
from build_runtime import BuildError


class PluginToolPinTests(unittest.TestCase):
    def test_known_folder_verification_refuses_runner_or_malformed_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            folders = {}
            for key, directory in [("APPDATA", "Roaming"), ("LOCALAPPDATA", "Local")]:
                location = work / "home/AppData" / directory
                location.mkdir(parents=True)
                folders[key] = str(location)
            with patch.object(build_host_plugin, "run", return_value=json.dumps(folders)):
                self.assertEqual(build_host_plugin.windows_compiler_cache(work, {}), folders)
            for value in [None, {}, {**folders, "APPDATA": str(work)},
                          {**folders, "LOCALAPPDATA": "relative"}, {**folders, "APPDATA": 3}]:
                with self.subTest(value=value), \
                     patch.object(build_host_plugin, "run", return_value=json.dumps(value)), \
                     self.assertRaises(BuildError):
                    build_host_plugin.windows_compiler_cache(work, {})

    @unittest.skipUnless(os.name == "nt", "requires Windows Known Folder API")
    def test_real_windows_known_folders_stay_in_the_private_compiler_profile(self):
        from build_runtime import build_environment
        with tempfile.TemporaryDirectory(prefix="compiler-cache-é-") as temporary:
            work = Path(temporary).resolve()
            env = build_environment(work, os.environ)
            expected = {}
            for key, directory in [("APPDATA", "Roaming"), ("LOCALAPPDATA", "Local")]:
                location = work / "home/AppData" / directory
                location.mkdir(parents=True)
                env[key] = str(location)
                expected[key] = location
            found = build_host_plugin.windows_compiler_cache(work, env)
            self.assertEqual({key: Path(value).resolve() for key, value in found.items()}, expected)

    def test_windows_compiler_has_private_existing_appdata_before_any_tool_runs(self):
        class EnvironmentChecked(Exception):
            pass
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            node = root / "node.exe"
            node.write_bytes(b"not executed")
            output = root / "output"
            def command(arguments, *, cwd, env):
                self.assertEqual(arguments, [node, "--version"])
                for key, directory in [("APPDATA", "Roaming"), ("LOCALAPPDATA", "Local")]:
                    self.assertEqual(Path(env[key]), output / "work/home/AppData" / directory)
                    self.assertTrue(Path(env[key]).is_dir())
                self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
                raise EnvironmentChecked()
            with patch.object(build_host_plugin, "os", SimpleNamespace(
                    name="nt", pathsep=os.pathsep, defpath=os.defpath,
                    environ={**os.environ, "AWS_SECRET_ACCESS_KEY": "not inherited"})), \
                 patch.object(build_host_plugin.shutil, "which", return_value="fixture-tool"), \
                 patch.object(build_host_plugin, "git_blob", return_value=json.dumps({"packageManager":"pnpm@12.11.2"}).encode()), \
                 patch.object(build_host_plugin, "run", side_effect=command), \
                 self.assertRaises(EnvironmentChecked):
                build_host_plugin.build(root, "a" * 40, node, output)

    def test_only_exact_source_locked_github_tool_archives_are_admitted(self):
        lock = tomllib.loads("""
[[tools."github:extism/js-pdk"]]
version = "1.7.0"
[tools."github:extism/js-pdk"."platforms.macos-arm64"]
url = "https://github.com/extism/js-pdk/releases/download/v1.7.0/compiler.gz"
checksum = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
""")
        entry = lock["tools"]["github:extism/js-pdk"][0]
        self.assertEqual(
            tool_pin(lock, "extism/js-pdk", "macos-arm64"),
            entry["platforms.macos-arm64"],
        )
        other = {
            "version": "1.7.0",
            "platforms.windows-x64": entry["platforms.macos-arm64"],
        }
        self.assertEqual(
            tool_pin(
                {"tools": {"github:extism/js-pdk": [other, entry]}},
                "extism/js-pdk",
                "macos-arm64",
            ),
            entry["platforms.macos-arm64"],
        )
        for key, value in [
            (
                "url",
                "http://github.com/extism/js-pdk/releases/download/v1.7.0/compiler.gz",
            ),
            (
                "url",
                "https://github.com/other/project/releases/download/v1.7.0/compiler.gz",
            ),
            (
                "url",
                "https://github.com/extism/js-pdk/releases/download/v1.7.0/compiler.gz?secret=x",
            ),
            ("checksum", "sha256:bad"),
        ]:
            changed = {
                "tools": {
                    "github:extism/js-pdk": [
                        {
                            **entry,
                            "platforms.macos-arm64": {
                                **entry["platforms.macos-arm64"],
                                key: value,
                            },
                        }
                    ]
                }
            }
            with self.assertRaises(BuildError):
                tool_pin(changed, "extism/js-pdk", "macos-arm64")
        with self.assertRaises(BuildError):
            tool_pin(lock, "extism/js-pdk", "windows-arm64")
        with self.assertRaises(BuildError):
            tool_pin(
                {"tools": {"github:extism/js-pdk": [entry, entry]}},
                "extism/js-pdk",
                "macos-arm64",
            )
