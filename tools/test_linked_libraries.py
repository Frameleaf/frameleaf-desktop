import os
import tempfile
import unittest
from pathlib import Path

from linked_libraries import DRIVER, check_linked


@unittest.skipIf(os.name == "nt", "the CUDA pack and its linker listing are Linux only")
class LinkedLibraries(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.pack = Path(temporary.name).resolve() / "site-packages"
        self.pack.mkdir()

    def listing(self, *, driver=None, cublas=None, cudart="pack"):
        inside = self.pack / "nvidia/lib"
        lines = [
            "\tlinux-vdso.so.1 (0x00007ffd)",
            "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1)",
            f"\tlibcublas.so.12 => {cublas or inside / 'libcublas.so.12'} (0x2)",
            f"\tlibcublasLt.so.12 => {inside / 'libcublasLt.so.12'} (0x3)",
            f"\tlibcurand.so.10 => {inside / 'libcurand.so.10'} (0x4)",
        ]
        if cudart == "pack":
            lines.append(f"\tlibcudart.so.12 => {inside / 'libcudart.so.12'} (0x5)")
        elif cudart == "missing":
            lines.append("\tlibcudart.so.12 => not found")
        lines.append(f"\t{DRIVER} => {driver} (0x6)" if driver else f"\t{DRIVER} => not found")
        return "\n".join(lines) + "\n"

    def test_a_driver_on_the_computer_resolves_from_the_system_and_is_not_expected_in_the_pack(self):
        resolved = check_linked(
            self.listing(driver="/usr/lib/x86_64-linux-gnu/libcuda.so.1"), self.pack, True
        )
        self.assertIn(DRIVER, resolved)
        self.assertIn("libcublas.so.12", resolved)

    def test_without_a_driver_only_the_driver_library_may_be_missing(self):
        resolved = check_linked(self.listing(), self.pack, False)
        self.assertNotIn(DRIVER, resolved)
        # A driver that is said to be present must actually resolve.
        with self.assertRaisesRegex(ValueError, "unresolved"):
            check_linked(self.listing(), self.pack, True)
        # And a driver library that resolves where none was detected is not the expected state.
        with self.assertRaisesRegex(ValueError, "unresolved"):
            check_linked(self.listing(driver="/usr/lib/libcuda.so.1"), self.pack, False)

    def test_a_missing_or_foreign_bundled_dependency_fails(self):
        for driver, present in ((None, False), ("/usr/lib/libcuda.so.1", True)):
            with self.assertRaisesRegex(ValueError, "unresolved"):
                check_linked(self.listing(driver=driver, cudart="missing"), self.pack, present)
            with self.assertRaisesRegex(ValueError, "outside the pack"):
                check_linked(
                    self.listing(driver=driver, cublas="/usr/local/cuda/lib64/libcublas.so.12"),
                    self.pack,
                    present,
                )
        with self.assertRaisesRegex(ValueError, "cuBLAS"):
            check_linked(f"\t{DRIVER} => not found\n", self.pack, False)


if __name__ == "__main__":
    unittest.main()
