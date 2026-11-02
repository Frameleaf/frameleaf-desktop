import io
import os
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from build_host_ffmpeg import ffmpeg_contract, unpack
from build_runtime import BuildError


class FfmpegPackageTests(unittest.TestCase):
    def test_tar_preserves_nested_bytes_and_executable_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "safe.tar.gz"
            with tarfile.open(archive, "w:gz") as contents:
                entry = tarfile.TarInfo("bin/tool")
                entry.size, entry.mode = 7, 0o755
                contents.addfile(entry, io.BytesIO(b"payload"))
            destination = root / "output"
            destination.mkdir()
            unpack(archive, destination)
            self.assertEqual((destination / "bin/tool").read_bytes(), b"payload")
            if os.name != "nt":
                self.assertEqual((destination / "bin/tool").stat().st_mode & 0o777, 0o755)

    def test_refuses_occupied_destination_without_overwriting_existing_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "safe.zip"
            with zipfile.ZipFile(archive, "w") as contents:
                contents.writestr("existing", b"replacement")
            destination = root / "output"
            destination.mkdir()
            (destination / "existing").write_bytes(b"original")
            with self.assertRaisesRegex(BuildError, "archive_paths_invalid"):
                unpack(archive, destination)
            self.assertEqual((destination / "existing").read_bytes(), b"original")

    def test_tar_refuses_unsafe_entries_before_extracting_any_file(self):
        cases = [
            [("good", "file"), (name, "file")]
            for name in ["../escape", "/absolute", "C:/drive", "file:stream", "CON.txt",
                         "folder/../escape", "trailing.", "folder\\name", " CON.txt", "bin/ NUL.data",
                         " bin/tool", "bin/ ordinary.txt"]
        ] + [
            [("bin/tool", "file"), ("BIN/tool", "file")],
            [("file", "file"), ("file/child", "file")],
            [("file/child", "file"), ("file", "file")],
        ]
        cases.extend([[("good", "file"), ("link", kind)] for kind in ["symlink", "hardlink", "fifo"]])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, entries in enumerate(cases):
                with self.subTest(entries=entries):
                    archive = root / f"{index}.tar.gz"
                    with tarfile.open(archive, "w:gz") as contents:
                        for name, kind in entries:
                            entry = tarfile.TarInfo(name)
                            if kind == "file":
                                entry.size = 1
                                contents.addfile(entry, io.BytesIO(b"x"))
                            else:
                                entry.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                                              "fifo": tarfile.FIFOTYPE}[kind]
                                entry.linkname = "good"
                                contents.addfile(entry)
                    destination = root / f"out-{index}"
                    destination.mkdir()
                    with self.assertRaises((BuildError, tarfile.FilterError)):
                        unpack(archive, destination)
                    self.assertEqual(list(destination.iterdir()), [])

    def test_portable_pin_must_match_the_selected_server_release(self):
        pin = {
            "url": "https://github.com/jellyfin/jellyfin-ffmpeg/releases/download/v8.1.3-1/media.zip",
            "checksum": "sha256:" + "a" * 64,
        }
        entry = {"version": "8.1.3-1", "platforms.windows-x64": pin}
        lock = {"tools": {"github:jellyfin/jellyfin-ffmpeg": [entry]}}
        descriptor = {"name": "ffmpeg", "version": "8.1.3-1"}
        self.assertEqual(ffmpeg_contract(lock, descriptor, "windows-x64"), pin)
        for changed in [
            {**descriptor, "version": "8.1.2-1"},
            {**descriptor, "name": "other"},
        ]:
            with self.assertRaises(BuildError):
                ffmpeg_contract(lock, changed, "windows-x64")

    def test_zip_rejects_traversal_links_and_duplicates_before_extracting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, names in enumerate(
                [
                    ["../outside"],
                    ["/absolute"],
                    ["C:/outside"],
                    ["ffmpeg.exe", "FFMPEG.exe"],
                    ["link"],
                    *[[f"bin/ff{character}mpeg.exe", "bin/ff_mpeg.exe"]
                      for character in '<>"|?*'],
                    *[["bin/good", f"bin/{device}.txt"] for device in ["CONIN$", "CONOUT$",
                       *[f"{prefix}{digit}" for prefix in ["COM", "LPT"] for digit in "¹²³"]]],
                    ["bin/good", "bin/CON .txt"],
                    ["bin/good", "bin/LPT³   .data"],
                    ["bin/good", " CON.txt"],
                    ["bin/good", "bin/ NUL.data"],
                    ["bin/good", " bin/tool"],
                    ["bin/good", "bin/ ordinary.txt"],
                ]
            ):
                archive = root / f"{index}.zip"
                with zipfile.ZipFile(archive, "w") as output:
                    for name in names:
                        info = zipfile.ZipInfo(name)
                        if name == "link":
                            info.create_system = 3
                            info.external_attr = (stat.S_IFLNK | 0o777) << 16
                        output.writestr(info, b"fixture")
                destination = root / f"output-{index}"
                destination.mkdir()
                with self.assertRaises(BuildError):
                    unpack(archive, destination)
                self.assertEqual(list(destination.iterdir()), [])
            archive = root / "safe.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("bin/ffmpeg.exe", b"regular fixture")
            destination = root / "safe"
            destination.mkdir()
            unpack(archive, destination)
            self.assertEqual(
                (destination / "bin/ffmpeg.exe").read_bytes(), b"regular fixture"
            )
