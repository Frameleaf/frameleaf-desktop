import hashlib
import shutil
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from build_host_raw import build, raw_contract, stage_raw
from build_runtime import BuildError
from test_relocate_windows import pe


class NativeRawContractTests(unittest.TestCase):
    def test_windows_stages_patched_pe_plugins_data_and_private_licenses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            work, output, dependencies = root / 'work', root / 'output', root / 'ucrt64'
            prefix = work / 'prefix'
            for name, marker in {
                'bin/darktable-cli.exe': b'', 'bin/dcraw_emu.exe': b'',
                'lib/darktable/plugins/liblens.dll': b'frameleaf-lens-calibration:',
                'lib/darktable/plugins/librotatepixels.dll': b'frameleaf-native-mask-geometry:rotatepixels:1',
            }.items():
                path = prefix / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(pe() + marker)
            for name in ['darktable', 'lensfun']:
                path = prefix / 'share' / name
                path.mkdir(parents=True)
                (path / 'data').write_text('fixture')
            for name in ['darktable/LICENSE', 'darktable/src/external/rawspeed/LICENSE',
                         'darktable/src/external/whereami/LICENSE.MIT', 'darktable/src/external/OpenCL/LICENSE',
                         'lensfun/docs/lgpl-3.0.txt', 'lensfun/docs/cc-by-sa-3.0.txt',
                         'libraw/LICENSE.LGPL', 'libraw/LICENSE.CDDL']:
                path = work / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture notice')
            (dependencies / 'bin').mkdir(parents=True)
            (dependencies / 'share/licenses/fixture').mkdir(parents=True)
            (dependencies / 'share/licenses/fixture/LICENSE').write_text('private dependency notice')
            output.mkdir()

            def command(arguments, runtime_root=None):
                if '-p' in arguments:
                    return 'DLL Name: KERNEL32.dll'
                self.assertFalse(prefix.exists())
                self.assertEqual(runtime_root, output / 'raw')
                self.assertEqual(arguments, [output / 'raw/bin/darktable-cli.exe', '--version'])
                return 'darktable 5.6.2'

            with patch('build_host_raw.platform.system', return_value='Windows'):
                report = stage_raw(prefix, work, output, command, dependencies)
            self.assertEqual(len(report['nativeClosure']['objects']), 4)
            self.assertFalse(report['nativeClosure']['posixRuntimeRequired'])
            self.assertIn('share/lensfun/data', report['files'])
            self.assertIn('licenses-toolchain/fixture/LICENSE', report['files'])
            self.assertIn('licenses/darktable-LICENSE', report['files'])

    def test_windows_enters_the_pinned_builder(self):
        with (
            patch("build_host_raw.platform.system", return_value="Windows"),
            patch("build_host_raw.platform.machine", return_value="AMD64"),
            self.assertRaisesRegex(BuildError, "host_raw_output_invalid"),
        ):
            build(Path("/source"), "bad", Path("/ucrt64"), Path("/output"))

    def test_linux_enters_the_same_pinned_builder(self):
        with (
            patch("build_host_raw.platform.system", return_value="Linux"),
            self.assertRaisesRegex(BuildError, "host_raw_output_invalid"),
        ):
            build(Path("/source"), "bad", Path("/usr"), Path("/output"))

    def test_linux_stages_elf_plugins_and_retains_data_and_notices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"
            prefix = work / "prefix"
            entries = {
                "bin/darktable-cli": b"\x7fELFfixture",
                "lib/darktable/plugins/liblens.so": b"\x7fELFframeleaf-lens-calibration:",
                "lib/darktable/plugins/librotatepixels.so": b"\x7fELFframeleaf-native-mask-geometry:rotatepixels:1",
            }
            for name, value in entries.items():
                target = prefix / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(value)
            for name in ["darktable", "lensfun"]:
                folder = prefix / "share" / name
                folder.mkdir(parents=True)
                (folder / "data").write_text("fixture")
            for name in [
                "darktable/LICENSE",
                "darktable/src/external/rawspeed/LICENSE",
                "darktable/src/external/whereami/LICENSE.MIT",
                "darktable/src/external/OpenCL/LICENSE",
                "lensfun/docs/lgpl-3.0.txt",
                "lensfun/docs/cc-by-sa-3.0.txt",
                "libraw/LICENSE.LGPL",
                "libraw/LICENSE.CDDL",
            ]:
                target = work / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("fixture notice")
            output = root / "output"
            output.mkdir()

            def stage(found, directories, destination):
                self.assertEqual(set(found), set(entries))
                self.assertIn(prefix / "lib", directories)
                for name, source in found.items():
                    target = destination / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
                return {"qualification": "passed"}

            def command(arguments):
                self.assertFalse(prefix.exists())
                self.assertEqual(
                    arguments, [output / "raw/bin/darktable-cli", "--version"]
                )
                return "darktable 5.6.2"

            with (
                patch("build_host_raw.platform.system", return_value="Linux"),
                patch("build_host_raw.elf_closure", side_effect=stage),
                patch(
                    "build_host_raw.closure",
                    side_effect=AssertionError("Mach-O on Linux"),
                ),
            ):
                report = stage_raw(prefix, work, output, command, root / "dependencies")
            self.assertEqual(report["nativeClosure"]["qualification"], "passed")
            self.assertIn("share/darktable/data", report["files"])
            self.assertIn("share/lensfun/data", report["files"])
            self.assertIn("licenses/libraw-LICENSE.LGPL", report["files"])
            self.assertEqual(report["rpathAdjustments"], {})

    def test_only_pinned_sources_and_exact_frameleaf_patches_are_accepted(self):
        repositories = {
            "darktable": ("darktable-org/darktable", "."),
            "rawspeed": ("darktable-org/rawspeed", "src/external/rawspeed"),
            "whereami": ("gpakosz/whereami", "src/external/whereami"),
            "opencl": ("KhronosGroup/OpenCL-Headers", "src/external/OpenCL"),
            "lensfun": ("lensfun/lensfun", "lensfun"),
        }
        patches = {
            name: b"fixture"
            for name in ["patch-darktable-lens.py", "patch-darktable-mask-geometry.py"]
        }
        pin = {
            "name": "darktable",
            "repository": "darktable-org/darktable",
            "version": "5.6.2",
            "revision": "a" * 40,
            "lensfunVersion": "0.3.4",
            "inputs": [
                {
                    "name": name,
                    "repository": repo,
                    "revision": "a" * 40,
                    "sha256": "b" * 64,
                    "path": path,
                    "url": f"https://codeload.github.com/{repo}/tar.gz/" + "a" * 40,
                }
                for name, (repo, path) in repositories.items()
            ],
            "patches": {
                name: hashlib.sha256(value).hexdigest()
                for name, value in patches.items()
            },
        }
        libraw = {
            "name": "libraw",
            "repository": "LibRaw/LibRaw",
            "version": "0.22.0-dev.7bfffe2e",
            "revision": "c" * 40,
        }
        self.assertEqual(raw_contract(pin, patches, libraw), pin)
        for change in ["path", "url", "digest", "patch", "missing", "version"]:
            bad = deepcopy(pin)
            if change == "path":
                bad["inputs"][1]["path"] = "../outside"
            if change == "url":
                bad["inputs"][1]["url"] += "?token=x"
            if change == "digest":
                bad["inputs"][1]["sha256"] = "bad"
            if change == "patch":
                bad["patches"]["patch-darktable-lens.py"] = "0" * 64
            if change == "missing":
                bad["inputs"].pop()
            if change == "version":
                bad["version"] = "5.6.1"
            with self.subTest(change=change), self.assertRaises(BuildError):
                raw_contract(bad, patches, libraw)
        with self.assertRaises(BuildError):
            raw_contract(pin, patches, {**libraw, "repository": "someone/LibRaw"})
