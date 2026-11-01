import tempfile
import unittest
from pathlib import Path

from build_host_web import stage_web
from build_runtime import BuildError


class WebPackageTests(unittest.TestCase):
    def test_studio_entries_must_travel_with_the_photo_ui(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "build"
            source.mkdir()
            (source / "index.html").write_text("<html>photos</html>")
            with self.assertRaises(BuildError):
                stage_web(source, root / "incomplete")
            (source / "studio-engine").mkdir()
            for name in ["editor.html", "commands.html"]:
                (source / "studio-engine" / name).write_text("<html>studio</html>")
            files = stage_web(source, root / "complete")
            self.assertIn("index.html", files)
            self.assertIn("studio-engine/editor.html", files)
            self.assertIn("studio-engine/commands.html", files)
            self.assertEqual(
                (root / "complete/index.html").read_text(), "<html>photos</html>"
            )
