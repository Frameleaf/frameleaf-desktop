import io
import json
import plistlib
import re
import struct
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import check_macos_minimum as check

ROOT = Path(__file__).resolve().parent.parent


def version(major, minor, patch=0):
    return (major << 16) | (minor << 8) | patch


def build_version(minimum, platform=1):
    return struct.pack("<IIIIII", check.LC_BUILD_VERSION, 24, platform, minimum, version(15, 0), 0)


def version_min(minimum):
    return struct.pack("<IIII", check.LC_VERSION_MIN_MACOSX, 16, minimum, version(10, 15))


def macho(*commands, file_type=2):
    body = b"".join(commands)
    return b"\xcf\xfa\xed\xfe" + struct.pack("<IIIIIII", 0x0100000C, 0, file_type, len(commands), len(body), 0, 0) + body


def fat(*images):
    offset = 4096
    table, payload = b"", b""
    for image in images:
        table += struct.pack(">IIIII", 0x0100000C, 0, offset + len(payload), len(image), 0)
        payload += image
    header = b"\xca\xfe\xba\xbe" + struct.pack(">I", len(images)) + table
    return header + b"\0" * (offset - len(header)) + payload


class CheckMacosMinimum(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "tauri.conf.json"
        self.declare("13.0")
        self.app = self.root / "Frameleaf.app"
        (self.app / "Contents" / "MacOS").mkdir(parents=True)

    def declare(self, minimum):
        self.config.write_text(json.dumps({"bundle": {"macOS": {"minimumSystemVersion": minimum}} if minimum else {}}))

    def binary(self, name, data):
        path = self.app / "Contents" / "MacOS" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def run_check(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = check.main(["--config", str(self.config), str(self.app), *extra])
        return code, out.getvalue(), err.getvalue()

    def test_accepts_binaries_at_or_below_the_declared_minimum(self):
        self.binary("app", macho(build_version(version(13, 0))))
        self.binary("old", macho(version_min(version(10, 12))))
        self.binary("notes.txt", b"not a binary")
        code, out, _ = self.run_check("--deployment-target", "13.0")
        self.assertEqual(code, 0)
        self.assertIn("2 Mach-O files checked; highest requirement macOS 13.0", out)

    def test_refuses_a_binary_that_needs_a_newer_macos(self):
        self.binary("app", macho(build_version(version(11, 0))))
        newer = self.binary("lib/orjson.so", macho(build_version(version(15, 0)), file_type=8))
        code, _, err = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn(f"{newer} requires macOS 15.0, newer than the declared 13.0", err)

    def test_checks_every_architecture_of_a_universal_binary(self):
        self.binary("universal", fat(macho(build_version(version(11, 0))), macho(build_version(version(14, 2)))))
        code, _, err = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("requires macOS 14.2", err)

    def test_other_platform_versions_do_not_count_as_a_macos_minimum(self):
        self.binary("catalyst", macho(build_version(version(17, 0), platform=6)))
        code, _, err = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("records no minimum macOS version", err)

    def test_unknown_or_damaged_binaries_fail_instead_of_passing(self):
        self.binary("app", macho(build_version(version(13, 0))))
        self.binary("bare", macho())
        code, _, err = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("records no minimum macOS version", err)
        (self.app / "Contents" / "MacOS" / "bare").write_bytes(macho(build_version(version(13, 0)))[:40])
        code, _, err = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("could not be read as Mach-O", err)

    def test_object_files_without_a_minimum_are_not_loaded_binaries(self):
        self.binary("app", macho(build_version(version(13, 0))))
        self.binary("unit.o", macho(file_type=1))
        self.assertEqual(self.run_check()[0], 0)

    def test_requires_a_declaration_binaries_and_a_matching_deployment_target(self):
        self.assertEqual(self.run_check()[0], 2)
        self.binary("app", macho(build_version(version(13, 0))))
        code, _, err = self.run_check("--deployment-target", "12.0")
        self.assertEqual(code, 1)
        self.assertIn("MACOSX_DEPLOYMENT_TARGET 12.0 differs from the declared minimum 13.0", err)
        self.assertEqual(self.run_check("--deployment-target", "latest")[0], 2)
        self.declare(None)
        code, _, err = self.run_check()
        self.assertEqual(code, 2)
        self.assertIn("declares no bundle.macOS.minimumSystemVersion", err)

    def test_the_bundle_must_carry_the_declared_minimum(self):
        self.binary("app", macho(build_version(version(13, 0))))
        plist = self.app / "Contents" / "Info.plist"
        plist.write_bytes(plistlib.dumps({"LSMinimumSystemVersion": "13.0"}))
        self.assertEqual(self.run_check()[0], 0)
        plist.write_bytes(plistlib.dumps({"LSMinimumSystemVersion": "10.13"}))
        code, _, err = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("declares macOS 10.13, expected 13.0", err)
        plist.write_bytes(plistlib.dumps({}))
        self.assertEqual(self.run_check()[0], 1)

    def test_workflows_build_macos_with_the_declared_minimum(self):
        declared = check.format_version(check.declared_minimum(ROOT / "src-tauri" / "tauri.conf.json"))
        targets = {}
        for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            values = re.findall(r"^\s*MACOSX_DEPLOYMENT_TARGET:\s*['\"]?([0-9.]+)['\"]?\s*$", workflow.read_text(encoding="utf-8"), re.MULTILINE)
            if values:
                targets[workflow.name] = set(values)
        # The workflows that compile the macOS app must pin the target; any other that sets it must agree.
        for name in ("desktop.yml", "release.yml"):
            self.assertIn(name, targets)
        for name, values in targets.items():
            self.assertEqual(values, {declared}, name)


if __name__ == "__main__":
    unittest.main()
