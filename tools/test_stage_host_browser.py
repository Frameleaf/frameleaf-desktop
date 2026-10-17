import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from build_runtime import BuildError
from stage_host_browser import stage_browser


class BrowserStageTests(unittest.TestCase):
    def fixture(self, root):
        source = root / "source"
        (source / "Versions/1/Resources").mkdir(parents=True)
        (source / "Versions/1/browser").write_bytes(b"browser fixture")
        (source / "Versions/1/browser").chmod(0o755)
        (source / "Versions/1/Resources/notice").write_text("licence fixture")
        (source / "Versions/Current").symlink_to("1", target_is_directory=True)
        (source / "browser").symlink_to("Versions/Current/browser")
        return source

    def test_materializes_internal_framework_aliases_and_inventories_every_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            files = stage_browser(source, root / "staged", "browser")
            self.assertEqual(len(files), 5)
            self.assertEqual((root / "staged/browser").read_bytes(), b"browser fixture")
            self.assertTrue((root / "staged/browser").stat().st_mode & 0o111)
            self.assertFalse(
                any(path.is_symlink() for path in (root / "staged").rglob("*"))
            )
            self.assertEqual(
                files["browser"]["sha256"], files["Versions/1/browser"]["sha256"]
            )

    def test_refuses_escape_cycle_and_broken_link_before_copy(self):
        for kind in ["escape", "cycle", "broken"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = self.fixture(root)
                outside = root / "outside"
                outside.write_text("outside")
                target = (
                    outside
                    if kind == "escape"
                    else (source if kind == "cycle" else source / "absent")
                )
                (source / "bad").symlink_to(target)
                with self.assertRaises((BuildError, FileNotFoundError)):
                    stage_browser(source, root / "staged", "browser")
                self.assertFalse((root / "staged").exists())

    def test_refuses_invalid_entry_and_existing_or_nested_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            for entry in ["../outside", "absent", "Versions/1/Resources"]:
                with self.subTest(entry=entry), self.assertRaises(BuildError):
                    stage_browser(source, root / "staged", entry)
            for destination in [root, source / "nested"]:
                with (
                    self.subTest(destination=destination),
                    self.assertRaises(BuildError),
                ):
                    stage_browser(source, destination, "browser")

    def test_receipt_cannot_add_uninventoried_files_or_modify_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            for receipt in [source / "receipt.json", root / "staged/receipt.json"]:
                result = subprocess.run(
                    [
                        sys.executable,
                        str(Path(__file__).with_name("stage_host_browser.py")),
                        "--source",
                        str(source),
                        "--destination",
                        str(root / "staged"),
                        "--executable",
                        "browser",
                        "--receipt",
                        str(receipt),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("host_browser_receipt_invalid", result.stderr)
                self.assertFalse((root / "staged").exists())
                self.assertFalse(receipt.exists())
