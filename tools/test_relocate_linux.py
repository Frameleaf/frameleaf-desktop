import os
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_runtime import BuildError


class LinuxRelocationTests(unittest.TestCase):
    def test_refuses_patchelf_versions_with_broken_init_relocation(self):
        from relocate_linux import closure

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for version in ["patchelf 0.18.0\n", "patchelf 0.17.2\n", "unknown\n"]:
                with self.subTest(version=version), patch(
                    "relocate_linux.platform.system", return_value="Linux"
                ), patch(
                    "relocate_linux.platform.machine", return_value="x86_64"
                ), patch(
                    "relocate_linux.shutil.which", side_effect=lambda name: "/tools/" + name
                ), patch(
                    "relocate_linux.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, version, ""),
                ):
                    output = root / "payload"
                    with self.assertRaisesRegex(
                        BuildError, "host_elf_patchelf_version_unsupported"
                    ):
                        closure({"bin/app": root / "app"}, [], output)
                    self.assertFalse(output.exists())

    @unittest.skipUnless(
        platform.system() == "Linux"
        and all(shutil.which(tool) for tool in ["gcc", "readelf", "patchelf"]),
        "requires Linux ELF linker tools",
    )
    def test_static_executable_runs_unchanged_after_source_removal(self):
        from relocate_linux import closure

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "main.c"
            source.write_text("int main(void) {return 0;}")
            executable = root / "static-app"
            subprocess.run(
                ["gcc", "-static", source, "-o", executable],
                check=True,
                capture_output=True,
            )
            executable.chmod(0o555)
            original = executable.read_bytes()
            output = root / "moved payload"
            report = closure({"bin/app": executable}, [], output)
            executable.unlink()
            self.assertEqual(report["qualification"], "passed")
            self.assertEqual(len(report["objects"]), 1)
            self.assertEqual((output / "bin/app").read_bytes(), original)
            self.assertEqual((output / "bin/app").stat().st_mode & 0o777, 0o555)
            subprocess.run([output / "bin/app"], check=True, env={"PATH": os.defpath})

    @unittest.skipUnless(
        platform.system() == "Linux"
        and all(shutil.which(tool) for tool in ["gcc", "readelf", "patchelf"]),
        "requires Linux ELF linker tools",
    )
    def test_library_without_dependencies_loses_its_build_search_path(self):
        from relocate_linux import closure, dynamic

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "answer.c"
            source.write_text("int answer(void) {return 42;}")
            library = root / "answer.so"
            subprocess.run(
                [
                    "gcc",
                    "-shared",
                    "-fPIC",
                    "-nostdlib",
                    source,
                    "-Wl,-rpath,/unavailable-build-directory",
                    "-o",
                    library,
                ],
                check=True,
                capture_output=True,
            )
            output = root / "payload"
            report = closure({"answer.so": library}, [], output)
            metadata = subprocess.check_output(
                ["readelf", "-dW", output / "answer.so"], text=True
            )
            self.assertEqual(report["qualification"], "passed")
            self.assertEqual(dynamic(metadata), ([], []))

    def test_dynamic_metadata_refuses_hidden_loader_features(self):
        from relocate_linux import dynamic

        needed, paths = dynamic(
            " 0x1 (NEEDED) Shared library: [libanswer.so.1]\n"
            " 0x1d (RUNPATH) Library runpath: [$ORIGIN/../lib:/build/lib]\n"
        )
        self.assertEqual(needed, ["libanswer.so.1"])
        self.assertEqual(paths, ["$ORIGIN/../lib", "/build/lib"])
        for tag in ["AUDIT", "DEPAUDIT", "FILTER", "AUXILIARY"]:
            with self.assertRaises(BuildError):
                dynamic(f" 0x1 ({tag}) library: [hidden.so]")
        for value in ["/build/libanswer.so", "../libanswer.so", "$ORIGIN/evil"]:
            with self.assertRaises(BuildError):
                dynamic(f" 0x1 (NEEDED) Shared library: [{value}]")
        with self.assertRaises(BuildError):
            dynamic(" 0x1d (RUNPATH) Library runpath: [$ORIGIN::/build]")

    def test_elf_header_requires_supported_64_bit_little_endian_machine(self):
        from relocate_linux import elf_architecture

        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", header, 16, 3, 183)
        self.assertEqual(elf_architecture(bytes(header)), "aarch64")
        struct.pack_into("<H", header, 18, 62)
        self.assertEqual(elf_architecture(bytes(header)), "x86_64")
        for offset, value in [(4, 1), (5, 2), (16, 1), (18, 40)]:
            invalid = bytearray(header)
            invalid[offset] = value
            with self.assertRaises(BuildError):
                elf_architecture(bytes(invalid))

    def test_resolution_uses_explicit_loader_context_and_refuses_unknown_tokens(self):
        from relocate_linux import resolve_dependency

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "lib").mkdir()
            library = root / "lib/libanswer.so"
            library.write_bytes(b"library")
            self.assertEqual(
                resolve_dependency("libanswer.so", root / "app", ["$ORIGIN/lib"], []),
                library.resolve(),
            )
            for paths in [[], ["relative"], ["$LIB"], ["${PLATFORM}"], ["$ORIGINevil"]]:
                with self.assertRaises(BuildError):
                    resolve_dependency("libanswer.so", root / "app", paths, [])
            (root / "loaderevil").mkdir()
            (root / "loaderevil/libanswer.so").write_bytes(b"wrong token expansion")
            with self.assertRaises(BuildError):
                resolve_dependency(
                    "libanswer.so", root / "loader/app", ["$ORIGINevil"], []
                )

    @unittest.skipUnless(
        platform.system() == "Linux"
        and all(shutil.which(tool) for tool in ["gcc", "readelf", "patchelf"]),
        "requires Linux ELF linker tools",
    )
    def test_transitive_private_libraries_run_after_source_removal_and_payload_move(
        self,
    ):
        from relocate_linux import closure, dynamic

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            (source / "base.c").write_text("int base(void) {return 42;}")
            (source / "answer.c").write_text(
                "extern int base(void); int answer(void) {return base();}"
            )
            (source / "wrapper.c").write_text(
                "extern int answer(void); int wrapper(void) {return answer();}"
            )
            (source / "main.c").write_text(
                '#include <stdio.h>\nextern int wrapper(void); int main(void) {printf("%d\\n", wrapper());}'
            )
            for command in [
                [
                    "gcc",
                    "-shared",
                    "-fPIC",
                    "base.c",
                    "-Wl,-soname,libbase.so.1",
                    "-o",
                    "libbase.so.1",
                ],
                [
                    "gcc",
                    "-shared",
                    "-fPIC",
                    "answer.c",
                    "-L.",
                    "-l:libbase.so.1",
                    "-Wl,-soname,libanswer.so.1",
                    "-o",
                    "libanswer.so.1",
                ],
                [
                    "gcc",
                    "-shared",
                    "-fPIC",
                    "wrapper.c",
                    "-L.",
                    "-l:libanswer.so.1",
                    "-Wl,-soname,libwrapper.so.1",
                    "-o",
                    "libwrapper.so.1",
                ],
                [
                    "gcc",
                    "main.c",
                    "-L.",
                    "-l:libwrapper.so.1",
                    "-Wl,--disable-new-dtags",
                    "-Wl,-rpath,$ORIGIN",
                    "-o",
                    "main",
                ],
            ]:
                subprocess.run(command, cwd=source, check=True, capture_output=True)
            fallback = root / "fallback"
            fallback.mkdir()
            (fallback / "base.c").write_text("int base(void) {return 99;}")
            subprocess.run(
                [
                    "gcc",
                    "-shared",
                    "-fPIC",
                    "base.c",
                    "-Wl,-soname,libbase.so.1",
                    "-o",
                    "libbase.so.1",
                ],
                cwd=fallback,
                check=True,
                capture_output=True,
            )
            output = root / "payload"
            (source / "libanswer.so.1").chmod(0o555)
            for index, entries in enumerate(
                [
                    {"libraries/app": source / "main"},
                    {"receipt.json": source / "main"},
                    {"bin": source / "main", "bin/main": source / "main"},
                ]
            ):
                refused = root / f"refused-{index}"
                with self.assertRaises(BuildError):
                    closure(entries, [], refused)
                self.assertFalse(refused.exists())
            report = closure({"bin/main": source / "main"}, [fallback], output)
            self.assertEqual(report["qualification"], "passed")
            self.assertFalse(report["redistributable"])
            self.assertEqual(len(report["objects"]), 4)
            self.assertIn("sourceSha256", report["objects"]["bin/main"])
            subprocess.run(
                ["patchelf", "--set-rpath", "$ORIGIN", source / "main"], check=True
            )
            refused = root / "runpath-is-not-inherited"
            with self.assertRaisesRegex(BuildError, "dependency_missing:libanswer"):
                closure({"bin/main": source / "main"}, [], refused)
            self.assertFalse(refused.exists())
            subprocess.run(
                [
                    "patchelf",
                    "--force-rpath",
                    "--set-rpath",
                    "$ORIGIN",
                    source / "main",
                ],
                check=True,
            )
            alternate = root / "alternate"
            alternate.mkdir()
            shutil.copy2(source / "main", alternate / "main")
            (alternate / "libanswer.so.1").symlink_to(source / "libanswer.so.1")
            (alternate / "libwrapper.so.1").symlink_to(source / "libwrapper.so.1")
            shutil.copy2(fallback / "libbase.so.1", alternate / "libbase.so.1")
            refused = root / "conflicting-loader-contexts"
            with self.assertRaisesRegex(BuildError, "loader_context_ambiguous"):
                closure(
                    {"bin/first": source / "main", "bin/second": alternate / "main"},
                    [],
                    refused,
                )
            self.assertFalse(refused.exists())
            shutil.rmtree(source)
            moved = root / "moved payload"
            output.rename(moved)
            readonly = next(
                name for name in report["objects"] if name.endswith("/libanswer.so.1")
            )
            self.assertEqual((moved / readonly).stat().st_mode & 0o777, 0o555)
            result = subprocess.check_output(
                [moved / "bin/main"], env={"PATH": os.defpath}, text=True
            )
            self.assertEqual(result, "42\n")
            for name in report["objects"]:
                raw = subprocess.check_output(
                    ["readelf", "-dW", moved / name], text=True
                )
                _, paths = dynamic(raw)
                self.assertTrue(all(path.startswith("$ORIGIN/") for path in paths))


if __name__ == "__main__":
    unittest.main()
