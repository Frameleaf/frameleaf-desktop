import struct
import tempfile
import unittest
from pathlib import Path

import check_windows_cuda_libraries as check


def library(path: Path, imported: list[str] = (), named: list[str] = ()) -> None:
    """A minimal 64-bit Windows library: an import table naming `imported`, and `named` in its data."""
    base = 0x1000  # the one section: file offset 0x200, address 0x1000
    descriptors = 20 * (len(imported) + 1)
    body = bytearray(descriptors + 16)  # then one empty lookup table
    lookup = base + descriptors
    for index, name in enumerate(imported):
        struct.pack_into("<IIIII", body, 20 * index, lookup, 0, 0, base + len(body), lookup)
        body += name.encode() + b"\0"
    for name in named:
        body += b"\0" + name.encode() + b"\0"
    header = bytearray(0x200)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    header[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", header, 0x84, 0x8664, 1)  # machine, one section
    struct.pack_into("<H", header, 0x94, 240)  # size of the optional header
    optional = 0x98
    struct.pack_into("<H", header, optional, 0x20B)
    struct.pack_into("<I", header, optional + 108, 16)  # number of data directories
    struct.pack_into("<II", header, optional + 112 + 8, base, descriptors if imported else 0)
    section = optional + 240
    header[section : section + 6] = b".rdata"
    struct.pack_into("<IIII", header, section + 8, len(body), base, len(body), 0x200)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(header) + bytes(body))


class Table(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.site = Path(self.temporary.name) / "payload" / "python" / "Lib" / "site-packages"
        self.addCleanup(self.temporary.cleanup)

    def pack(self, layout: dict[str, tuple[list[str], list[str]]]) -> None:
        for name, (imported, named) in layout.items():
            library(self.site / name, imported, named)

    def test_the_fixture_is_read_as_a_windows_library(self) -> None:
        self.pack({"onnxruntime/capi/a.dll": (["cublas64_12.dll", "KERNEL32.dll"], ["cudnn64_9.dll", "other.dll"])})
        found = check.references(self.site / "onnxruntime/capi/a.dll")
        self.assertEqual(found["imported"], ["cublas64_12.dll", "KERNEL32.dll"])
        # Only NVIDIA names are followed from a library's data.
        self.assertEqual(found["named"], ["cudnn64_9.dll"])

    def test_every_library_reached_by_import_or_by_name_must_be_in_the_pack(self) -> None:
        self.pack(
            {
                "onnxruntime/capi/onnxruntime_providers_cuda.dll": (["cublas64_12.dll"], ["cudnn64_9.dll", "nvcuda.dll"]),
                "nvidia/cublas/bin/cublas64_12.dll": ([], []),
                "nvidia/cudnn/bin/cudnn64_9.dll": ([], ["cudnn_cnn64_9.dll"]),
                # Reached only by name, two steps from the provider.
                "nvidia/cudnn/bin/cudnn_cnn64_9.dll": (["cudnn_ops64_9.dll"], []),
            }
        )
        rows, problems = check.table(self.site, ["onnxruntime_providers_cuda.dll"])
        self.assertEqual(problems, ["cudnn_cnn64_9.dll needs cudnn_ops64_9.dll (imported), which is not in the pack"])
        self.assertIn(
            {"library": "cudnn64_9.dll", "reference": "named", "needs": "cudnn_cnn64_9.dll", "pack": "nvidia/cudnn/bin"},
            rows,
        )
        # The driver's library is the one thing a pack never has.
        driver = next(row for row in rows if row["needs"] == "nvcuda.dll")
        self.assertTrue(driver["pack"].startswith("absent by design"))
        library(self.site / "nvidia/cudnn/bin/cudnn_ops64_9.dll")
        self.assertEqual(check.table(self.site, ["onnxruntime_providers_cuda.dll"])[1], [])

    def test_a_library_named_but_absent_fails_unless_it_is_absent_by_design(self) -> None:
        self.pack({"onnxruntime/capi/onnxruntime_providers_cuda.dll": ([], ["nvrtc64_120_0.dll", "zlibwapi.dll"])})
        _, problems = check.table(self.site, ["onnxruntime_providers_cuda.dll"])
        self.assertEqual(
            problems, ["onnxruntime_providers_cuda.dll needs nvrtc64_120_0.dll (named), which is not in the pack"]
        )

    def test_an_imported_library_is_never_absent_by_design(self) -> None:
        self.pack({"onnxruntime/capi/onnxruntime_providers_cuda.dll": (["zlibwapi.dll"], [])})
        _, problems = check.table(self.site, ["onnxruntime_providers_cuda.dll"])
        self.assertEqual(len(problems), 1)

    def test_a_starting_library_must_be_in_the_pack_unless_optional(self) -> None:
        self.pack({"onnxruntime/capi/onnxruntime_providers_cuda.dll": ([], [])})
        start = ["onnxruntime_providers_cuda.dll", "cudnn64_9.dll", "cudnn_engines_tensor_ir64_9.dll"]
        _, problems = check.table(self.site, start, frozenset({"cudnn_engines_tensor_ir64_9.dll"}))
        self.assertEqual(problems, ["cudnn64_9.dll is not in the pack"])

    def test_search_folders_are_the_nvidia_library_folders_the_app_adds(self) -> None:
        # The same cases as `a_cuda_pack_puts_the_folders_of_its_nvidia_libraries_on_the_search_path`
        # in src-tauri/src/native_runtime.rs.
        self.pack({"nvidia/cudnn/bin/cudnn64_9.dll": ([], []), "nvidia/cuda_nvrtc/bin/nvrtc64_120_0.DLL": ([], [])})
        (self.site / "nvidia/cudnn/include").mkdir(parents=True)
        (self.site / "nvidia/cudnn/include/cudnn.h").write_text("")
        library(self.site / "other/nvidia/x/bin/planted.dll")
        folders = [folder.relative_to(self.site).as_posix() for folder in check.library_folders(self.site)]
        self.assertEqual(folders, ["nvidia/cuda_nvrtc/bin", "nvidia/cudnn/bin"])

    def test_the_path_budget_is_what_an_installed_pack_leaves_below_260(self) -> None:
        prefix = (
            "C:\\Users\\" + "u" * 20 + "\\AppData\\Local\\app.frameleaf.desktop\\gpu\\releases\\" + "a" * 64 + "\\payload\\"
        )
        self.assertEqual(check.PATH_BUDGET, 259 - len(prefix))
        fits, deep = "p" * check.PATH_BUDGET, "p" * (check.PATH_BUDGET + 1)
        self.assertEqual(check.over_budget([fits, deep]), [deep])


if __name__ == "__main__":
    unittest.main()
