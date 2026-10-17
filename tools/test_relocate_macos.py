import os
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from build_runtime import BuildError
from relocate_macos import closure, load_commands, resolve_dependency


class RelocationTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Darwin" and shutil.which("clang"),
        "requires macOS linker tools",
    )
    def test_identical_libraries_in_different_loader_contexts_do_not_overwrite_each_other(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "wrapper.c").write_text(
                "extern int answer(void); int wrapper(void) {return answer();}"
            )
            (root / "main.c").write_text(
                '#include <stdio.h>\nextern int wrapper(void); int main(void) {printf("%d\\n", wrapper());}'
            )
            entries = {}
            for label, answer in [("first", 42), ("second", 84)]:
                folder = root / label
                folder.mkdir()
                (folder / "answer.c").write_text(
                    f"int answer(void) {{return {answer};}}"
                )
                subprocess.run(
                    [
                        "clang",
                        "-Wl,-headerpad_max_install_names",
                        "-dynamiclib",
                        folder / "answer.c",
                        "-o",
                        folder / "libanswer.dylib",
                        "-Wl,-install_name,@loader_path/libanswer.dylib",
                    ],
                    check=True,
                )
                if label == "first":
                    subprocess.run(
                        [
                            "clang",
                            "-Wl,-headerpad_max_install_names",
                            "-dynamiclib",
                            root / "wrapper.c",
                            folder / "libanswer.dylib",
                            "-o",
                            folder / "libwrapper.dylib",
                            "-Wl,-install_name,@loader_path/libwrapper.dylib",
                        ],
                        check=True,
                    )
                    subprocess.run(
                        [
                            "clang",
                            "-Wl,-headerpad_max_install_names",
                            root / "main.c",
                            folder / "libwrapper.dylib",
                            "-o",
                            folder / "main",
                        ],
                        check=True,
                    )
                else:
                    shutil.copyfile(
                        root / "first/libwrapper.dylib", folder / "libwrapper.dylib"
                    )
                    shutil.copy2(root / "first/main", folder / "main")
                entries[f"{label}/main"] = folder / "main"
            output = root / "payload"
            closure(entries, output)
            for label, expected in [("first", "42\n"), ("second", "84\n")]:
                self.assertEqual(
                    subprocess.check_output(
                        [output / label / "main"], env={"PATH": os.defpath}, text=True
                    ),
                    expected,
                )

    def test_load_commands_keep_ids_dependencies_and_search_paths_separate(self):
        commands = """Load command 0
          cmd LC_ID_DYLIB
         name /build/libsame.dylib (offset 24)
Load command 1
          cmd LC_LOAD_DYLIB
         name @rpath/libsame.dylib (offset 24)
Load command 2
          cmd LC_RPATH
         path /build/with spaces/lib (offset 12)
"""
        identity, dependencies, paths = load_commands(commands)
        self.assertEqual(identity, "/build/libsame.dylib")
        self.assertEqual(dependencies, ["@rpath/libsame.dylib"])
        self.assertEqual(paths, ["/build/with spaces/lib"])

    def test_resolution_refuses_missing_ambiguous_and_executable_relative_libraries(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ["first", "second"]:
                (root / name).mkdir()
                (root / name / "libsame.dylib").write_bytes(b"library")
            binary = root / "loader"
            self.assertEqual(
                resolve_dependency("@loader_path/first/libsame.dylib", binary, []),
                (root / "first/libsame.dylib").resolve(),
            )
            for reference, paths in [
                ("@rpath/libsame.dylib", []),
                ("@rpath/libsame.dylib", [str(root / "first"), str(root / "second")]),
                ("@executable_path/libsame.dylib", []),
            ]:
                with self.assertRaises(BuildError):
                    resolve_dependency(reference, binary, paths)

    @unittest.skipUnless(
        platform.system() == "Darwin" and shutil.which("clang"),
        "requires macOS linker tools",
    )
    def test_real_binary_runs_after_source_is_removed_and_payload_moves(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            (source / "base.c").write_text("int base(void) {return 42;}")
            (source / "answer.c").write_text(
                "extern int base(void); int answer(void) {return base();}"
            )
            (source / "main.c").write_text(
                '#include <stdio.h>\nextern int answer(void); int main(void) {printf("%d\\n", answer());}'
            )
            library = source / "libanswer.dylib"
            base = source / "libbase.dylib"
            subprocess.run(
                [
                    "clang",
                    "-dynamiclib",
                    str(source / "base.c"),
                    "-o",
                    str(base),
                    "-Wl,-install_name,@rpath/libbase.dylib",
                ],
                check=True,
            )
            subprocess.run(
                [
                    "clang",
                    "-dynamiclib",
                    str(source / "answer.c"),
                    str(base),
                    "-o",
                    str(library),
                    "-Wl,-install_name,@rpath/libanswer.dylib",
                ],
                check=True,
            )
            executable = source / "answer"
            subprocess.run(
                [
                    "clang",
                    str(source / "main.c"),
                    str(library),
                    "-Wl,-rpath," + str(source),
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            output = root / "payload"
            clone = source / "second-executable"
            shutil.copy2(executable, clone)
            unicode_output = root / "unicode-collision"
            with self.assertRaisesRegex(BuildError, "entry_invalid"):
                closure({"é/node": executable, "e\u0301/node": clone}, unicode_output)
            self.assertFalse(unicode_output.exists())
            for index, name in enumerate(
                [
                    "linkage-receipt.json",
                    "LINKAGE-RECEIPT.JSON",
                    "linkage-error.log",
                    "LiBrArIeS/node",
                ]
            ):
                refused = root / f"refused-{index}"
                with self.assertRaisesRegex(BuildError, "entry_invalid"):
                    closure({name: executable}, refused)
                self.assertFalse(refused.exists())
            report = closure({"bin/answer": executable}, output)
            self.assertEqual(report["qualification"], "passed")
            self.assertFalse(report["releaseSigned"])
            self.assertEqual(len(report["objects"]), 3)
            self.assertIn("sourceSha256", report["objects"]["bin/answer"])
            with self.assertRaises(BuildError):
                closure({"bin/answer": executable}, output)
            shutil.rmtree(source)
            moved = root / "moved payload"
            output.rename(moved)
            result = subprocess.check_output(
                [moved / "bin/answer"], env={"PATH": os.defpath}, text=True
            )
            self.assertEqual(result, "42\n")
            for item in report["objects"]:
                raw = subprocess.check_output(["otool", "-l", moved / item], text=True)
                _, dependencies, paths = load_commands(raw)
                self.assertEqual(paths, [])
                self.assertTrue(
                    all(
                        p.startswith(("/usr/lib/", "/System/Library/", "@loader_path/"))
                        for p in dependencies
                    )
                )
