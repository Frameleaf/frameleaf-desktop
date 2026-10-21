import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from build_host_ffmpeg import ffmpeg_contract, unpack
from build_runtime import BuildError


class FfmpegPackageTests(unittest.TestCase):
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

    def test_expanded_limit_is_explicit_bounded_and_checked_before_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / 'input.zip'
            with zipfile.ZipFile(archive, 'w') as bundle:
                bundle.writestr('asset', b'four')
            for index, maximum in enumerate([3, 0, -1, 12 * 1024**3 + 1, True]):
                destination = root / str(index)
                with self.subTest(maximum=maximum), self.assertRaises(BuildError):
                    unpack(archive, destination, maximum_bytes=maximum)
                self.assertFalse(destination.exists())
            unpack(archive, root / 'valid', maximum_bytes=4)
            self.assertEqual((root / 'valid/asset').read_bytes(), b'four')

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
