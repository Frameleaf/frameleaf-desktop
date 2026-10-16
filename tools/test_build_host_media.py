import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_host_media import BuildError, build, codec_pin


class HostMediaTests(unittest.TestCase):
    def test_preflight_refuses_unqualified_targets_or_unpinned_sources_before_creating_output(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            with (
                patch("build_host_media.platform.system", return_value="Windows"),
                self.assertRaisesRegex(BuildError, "target_unsupported"),
            ):
                build(root, "a" * 40, root, root, output)
            with patch("build_host_media.platform.system", return_value="Darwin"):
                with self.assertRaisesRegex(BuildError, "revision_invalid"):
                    build(root, "main", root, root, output)
                with self.assertRaisesRegex(BuildError, "absolute_path_required"):
                    build(Path("relative"), "a" * 40, root, root, output)
            self.assertFalse(output.exists())

    def test_only_release_pinned_codec_sources_and_exact_patches_are_built(self):
        patch = b"approved patch"
        for name, repository in [
            ("libheif", "strukturag/libheif"),
            ("libultrahdr", "google/libultrahdr"),
        ]:
            manifest = {
                "name": name,
                "repository": repository,
                "version": "1.2.3",
                "revision": "a" * 40,
                "patchChecksum": hashlib.sha256(patch).hexdigest(),
            }
            self.assertEqual(codec_pin(name, manifest, patch), manifest)
            for field, value in [
                ("name", "other"),
                ("repository", "foreign/code"),
                ("revision", "main"),
                ("patchChecksum", "0" * 64),
            ]:
                with (
                    self.subTest(name=name, field=field),
                    self.assertRaises(BuildError),
                ):
                    codec_pin(name, {**manifest, field: value}, patch)
            with self.assertRaises(BuildError):
                codec_pin(name, manifest, patch + b"changed")
