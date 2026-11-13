import io
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import check_linux_glibc as check

ROOT = Path(__file__).resolve().parent.parent

# `readelf --version-info --wide` for a binary linked on Ubuntu 24.04 and for glibc itself.
BUILT_ON_NOBLE = """
Version symbols section '.gnu.version' contains 4 entries:
 Addr: 0x0000000000000a10  Offset: 0x00000a10  Link: 6 (.dynsym)
  000:   0 (*local*)       2 (GLIBC_2.39)    3 (GLIBC_2.2.5)   4 (GCC_3.0)

Version needs section '.gnu.version_r' contains 2 entries:
 Addr: 0x0000000000000a40  Offset: 0x00000a40  Link: 7 (.dynstr)
  000000: Version: 1  File: libgcc_s.so.1  Cnt: 1
  0x0010:   Name: GCC_3.0  Flags: none  Version: 4
  0x0020: Version: 1  File: libc.so.6  Cnt: 3
  0x0030:   Name: GLIBC_2.2.5  Flags: none  Version: 3
  0x0040:   Name: GLIBC_2.39  Flags: none  Version: 2
  0x0050:   Name: GLIBC_2.9  Flags: none  Version: 5
"""
LIBC_ITSELF = """
Version definition section '.gnu.version_d' contains 2 entries:
 Addr: 0x0000000000023f08  Offset: 0x00023f08  Link: 5 (.dynstr)
  000000: Rev: 1  Flags: BASE  Index: 1  Cnt: 1  Name: libc.so.6
  0x001c: Rev: 1  Flags: none  Index: 2  Cnt: 1  Name: GLIBC_2.41

Version needs section '.gnu.version_r' contains 1 entry:
 Addr: 0x0000000000024318  Offset: 0x00024318  Link: 5 (.dynstr)
  000000: Version: 1  File: ld-linux-x86-64.so.2  Cnt: 1
  0x0010:   Name: GLIBC_2.35  Flags: none  Version: 3
"""
STATIC = "\nNo version information found in this file.\n"


class CheckLinuxGlibc(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def elf(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF" + b"\0" * 60)
        return path

    def run_check(self, outputs, *arguments):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(check, "read_version_info", lambda path: outputs[path.name]), redirect_stdout(out), redirect_stderr(err):
            code = check.main([*arguments])
        return code, out.getvalue(), err.getvalue()

    def test_only_needed_versions_count_and_they_compare_as_numbers(self):
        self.assertEqual(check.needed_versions(BUILT_ON_NOBLE), {(2, 2, 5), (2, 39), (2, 9)})
        # 2.9 is older than 2.39: versions are numbers, not text.
        self.assertEqual(max(check.needed_versions(BUILT_ON_NOBLE)), (2, 39))
        # What a library defines is not what it needs.
        self.assertEqual(check.needed_versions(LIBC_ITSELF), {(2, 35)})
        self.assertEqual(check.needed_versions(STATIC), set())
        self.assertEqual(check.parse_version("2.35"), (2, 35))
        for bad in ("2", "two", "2.x", ""):
            with self.assertRaises(ValueError):
                check.parse_version(bad)

    def test_a_binary_built_on_a_newer_system_fails_and_names_the_file(self):
        self.elf("usr/bin/frameleaf-desktop")
        self.elf("usr/bin/frameleaf-native-host")
        (self.root / "usr/share").mkdir(parents=True)
        (self.root / "usr/share/readme.txt").write_text("not a binary")
        outputs = {"frameleaf-desktop": BUILT_ON_NOBLE, "frameleaf-native-host": LIBC_ITSELF}
        code, out, err = self.run_check(outputs, str(self.root))
        self.assertEqual(code, 1)
        self.assertIn("2 ELF files need glibc; the newest version needed is 2.39 (limit 2.35).", out)
        self.assertIn("::error::usr/bin/frameleaf-desktop needs GLIBC_2.39, newer than 2.35", out)
        self.assertNotIn("frameleaf-native-host needs", out)
        self.assertIn("Ubuntu 22.04", err)
        # The same findings as a report never fail.
        code, out, _ = self.run_check(outputs, "--report-only", str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("::warning::usr/bin/frameleaf-desktop needs GLIBC_2.39", out)
        # A limit that covers the build machine passes.
        self.assertEqual(self.run_check(outputs, "--max", "2.39", str(self.root))[0], 0)

    def test_binaries_within_the_limit_pass(self):
        self.elf("frameleaf-desktop")
        code, out, _ = self.run_check({"frameleaf-desktop": LIBC_ITSELF}, str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("the newest version needed is 2.35 (limit 2.35)", out)
        self.assertNotIn("::error::", out)

    def test_a_path_with_nothing_to_check_is_an_error_not_a_pass(self):
        (self.root / "empty").mkdir()
        with self.assertRaises(FileNotFoundError):
            check.measure([self.root / "empty"], lambda path: STATIC)
        with self.assertRaises(FileNotFoundError):
            check.measure([self.root / "absent"], lambda path: STATIC)

    def test_linux_build_jobs_use_a_system_within_the_limit_and_run_the_check(self):
        workflows = ROOT / ".github" / "workflows"
        self.assertEqual(check.parse_version(check.DEFAULT_MAXIMUM), (2, 35))
        # Ubuntu 22.04 has glibc 2.35; 24.04 has 2.39.
        desktop = (workflows / "desktop.yml").read_text(encoding="utf-8")
        check_job = desktop[desktop.index("\n  check:"):desktop.index("\n  directory-probe:")]
        self.assertRegex(check_job, r"os: \[macos-latest, windows-latest, ubuntu-22\.04\]")
        self.assertNotIn("ubuntu-24.04", check_job)
        checked = r'packages=\(src-tauri/target/%s/bundle/deb/\*\.deb\)\n[^\n]*\n\s*python tools/check_linux_glibc\.py --max 2\.35 "\$\{packages\[0\]\}"'
        self.assertRegex(check_job, checked % "debug")
        matrix = (ROOT / "tools" / "release_inputs.mjs").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r'os: "(ubuntu-[^"]+)"', matrix), ["ubuntu-22.04", "ubuntu-22.04-arm"])
        for name in ("release.yml", "installer-candidates.yml"):
            text = (workflows / name).read_text(encoding="utf-8")
            self.assertRegex(text, checked % "release", name)
        # Each container runs the installed binaries, so a C library that is too old fails the job.
        install = (ROOT / "tools" / "qualify_linux_deb_install.sh").read_text(encoding="utf-8")
        self.assertIn('"$file" --version', install)
        self.assertNotIn("without failing", install)


if __name__ == "__main__":
    unittest.main()
