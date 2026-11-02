import hashlib
import shutil
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from build_host_raw import build, raw_contract, stage_raw, use_pinned_windows_lensfun_database
from build_runtime import BuildError
from test_relocate_windows import pe


UPSTREAM_WINDOWS_LENSFUN = '  # Add lensfun libraries\n  if(LensFun_FOUND)\n    set(LENSFUN_DB_GLOBAL "${MINGW_PATH}/../share/lensfun/version_1")\n    set(LENSFUN_DB_UPDATES "${MINGW_PATH}/../var/lib/lensfun-updates/version_1")\n    set(LENSFUN_DB "${LENSFUN_DB_GLOBAL}")\n    if(EXISTS "${LENSFUN_DB_UPDATES}")\n      file(READ "${LENSFUN_DB_GLOBAL}/timestamp.txt" LENSFUN_TS)\n      file(READ "${LENSFUN_DB_UPDATES}/timestamp.txt" LENSFUN_TS_UPDATE)\n      if(LENSFUN_TS LESS LENSFUN_TS_UPDATE)\n        set(LENSFUN_DB "${LENSFUN_DB_UPDATES}")\n      endif()\n    endif()\n    message(STATUS "Installing lensfun database from ${LENSFUN_DB}")\n    install(DIRECTORY\n        "${LENSFUN_DB}"\n        DESTINATION share/lensfun/\n        COMPONENT DTApplication)\n  endif(LensFun_FOUND)\n'


class NativeRawContractTests(unittest.TestCase):
    def test_windows_decoder_adaptation_preserves_original_wide_input_and_refuses_drift(self):
        from build_host_raw import use_windows_libraw_wide_input
        original = '#include <windows.h>\n// UTF-8 source café 原本\n' + '        ret = RawProcessor.open_file(argv[arg]);\n'
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / "dcraw_emu.cpp"
                source.write_bytes(original.replace("\n", newline).encode())
                before = source.read_bytes()
                report = use_windows_libraw_wide_input(source)
                adapted = source.read_text(encoding="utf-8")
                self.assertIn('CommandLineToArgvW(GetCommandLineW(), &wide_argc)', adapted)
                self.assertIn('RawProcessor.open_file(wide_argv.get()[arg])', adapted)
                self.assertIn('wide_argc != argc', adapted)
                self.assertIn('// UTF-8 source café 原本', adapted)
                self.assertIn('decltype(&LocalFree)', adapted)
                self.assertIn('#error Windows RAW input requires wide-path support', adapted)
                self.assertEqual(report['originalSha256'], hashlib.sha256(before).hexdigest())
                self.assertEqual(report['adaptedSha256'], hashlib.sha256(source.read_bytes()).hexdigest())
                saved = source.read_bytes()
                with self.assertRaisesRegex(BuildError, 'host_raw_libraw_entrypoint_changed'):
                    use_windows_libraw_wide_input(source)
                self.assertEqual(source.read_bytes(), saved)
                for changed in (original.replace('argv[arg]', 'other'), original + original):
                    source.write_text(changed, encoding="utf-8")
                    with self.assertRaisesRegex(BuildError, 'host_raw_libraw_entrypoint_changed'):
                        use_windows_libraw_wide_input(source)
                    self.assertEqual(source.read_text(encoding="utf-8"), changed)

    def test_windows_installs_only_its_source_pinned_lensfun_database(self):
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                prefix = root / "prefix"
                database = prefix / "share/lensfun/version_1"
                database.mkdir(parents=True)
                (database / "timestamp.txt").write_text("source-pinned timestamp")
                (database / "calibration.xml").write_text("source-pinned calibration")
                macro = root / "windows-macros.cmake"
                remainder = 'file(WRITE "${CMAKE_INSTALL_PREFIX}/other-runtime-data" "preserved")\n'
                macro.write_bytes((UPSTREAM_WINDOWS_LENSFUN + remainder).replace("\n", newline).encode())
                original_bytes = macro.read_bytes()
                report = use_pinned_windows_lensfun_database(macro, prefix)
                self.assertEqual(report["originalSha256"], hashlib.sha256(original_bytes).hexdigest())
                self.assertEqual(report["adaptedSha256"], hashlib.sha256(macro.read_bytes()).hexdigest())
                (root / "CMakeLists.txt").write_text(
                    'cmake_minimum_required(VERSION 3.16)\nproject(fixture NONE)\n'
                    'set(LensFun_FOUND TRUE)\nset(MINGW_PATH "${CMAKE_BINARY_DIR}/missing-toolchain/bin")\n'
                    'include("${CMAKE_SOURCE_DIR}/windows-macros.cmake")\n')
                for arguments in [
                    ["cmake", "-S", str(root), "-B", str(root / "build"), "-DCMAKE_INSTALL_PREFIX=" + str(prefix)],
                    ["cmake", "--install", str(root / "build")],
                ]:
                    subprocess.run(arguments, check=True, capture_output=True, text=True)
                self.assertEqual((database / "calibration.xml").read_text(), "source-pinned calibration")
                self.assertEqual((prefix / "other-runtime-data").read_text(), "preserved")
                self.assertNotIn("LENSFUN_DB_UPDATES", macro.read_text())

    def test_windows_lensfun_packaging_refuses_missing_data_or_changed_upstream(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            macro = root / "windows-macros.cmake"
            macro.write_text(UPSTREAM_WINDOWS_LENSFUN)
            with self.assertRaisesRegex(BuildError, "host_raw_lensfun_database_missing"):
                use_pinned_windows_lensfun_database(macro, root / "prefix")
            data = root / "prefix/share/lensfun/version_1"
            data.mkdir(parents=True)
            (data / "timestamp.txt").write_text("pinned")
            (data / "calibration.xml").write_text("pinned")
            changed = UPSTREAM_WINDOWS_LENSFUN.replace("# Add lensfun libraries", "# Changed upstream")
            macro.write_text(changed)
            with self.assertRaisesRegex(BuildError, "host_raw_lensfun_packaging_changed"):
                use_pinned_windows_lensfun_database(macro, root / "prefix")
            self.assertEqual(macro.read_text(), changed)

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
            debug = prefix / 'lib/darktable/views/.debug/libslideshow.dll.dbg'
            debug.parent.mkdir(parents=True)
            debug.write_bytes(pe())
            for name in ['darktable', 'lensfun']:
                path = prefix / 'share' / name
                path.mkdir(parents=True)
                (path / 'data').write_text('fixture')
            for name in ['darktable/LICENSE', 'darktable/src/external/rawspeed/LICENSE',
                         'darktable/src/external/whereami/LICENSE.MIT', 'darktable/src/external/OpenCL/LICENSE',
                         'lensfun/docs/lgpl-3.0.txt', 'lensfun/docs/cc-by-sa-3.0.txt',
                         'libraw/LICENSE.LGPL', 'libraw/LICENSE.CDDL', 'lensfun/include/regex/regex.h']:
                path = work / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture notice')
            (dependencies / 'bin').mkdir(parents=True)
            (dependencies / 'share/licenses/fixture').mkdir(parents=True)
            (dependencies / 'share/licenses/fixture/LICENSE').write_text('private dependency notice')
            output.mkdir()

            def command(arguments, runtime_root=None):
                if '-p' in arguments:
                    if Path(arguments[-1]).suffix.casefold() == '.dbg':
                        return 'There is an import table in .idata, but that section has no contents'
                    return 'DLL Name: KERNEL32.dll'
                self.assertFalse(prefix.exists())
                self.assertEqual(runtime_root, output / 'raw')
                self.assertEqual(arguments, [output / 'raw/bin/darktable-cli.exe', '--version'])
                return 'darktable 5.6.2'

            with patch('build_host_raw.platform.system', return_value='Windows'):
                report = stage_raw(prefix, work, output, command, dependencies)
            self.assertEqual(len(report['nativeClosure']['objects']), 4)
            self.assertFalse(any(name.casefold().endswith('.dbg') for name in report['files']))
            self.assertTrue((work / 'original-install-unavailable/lib/darktable/views/.debug/libslideshow.dll.dbg').is_file())
            self.assertFalse(report['nativeClosure']['posixRuntimeRequired'])
            self.assertIn('share/lensfun/data', report['files'])
            self.assertIn('licenses-toolchain/fixture/LICENSE', report['files'])
            self.assertIn('licenses/darktable-LICENSE', report['files'])
            self.assertIn('licenses/lensfun-tre-regex.h', report['files'])

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
