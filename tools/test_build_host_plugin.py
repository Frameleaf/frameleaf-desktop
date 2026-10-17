import tomllib
import unittest

from build_host_plugin import tool_pin
from build_runtime import BuildError


class PluginToolPinTests(unittest.TestCase):
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
