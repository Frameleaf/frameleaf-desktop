import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_host_media import BuildError, build, codec_pin, windows_binding_project


class WindowsBindingProjectTests(unittest.TestCase):
    SOURCE = (
        "add_library(image-hdr MODULE image-hdr.cc)\n"
        "target_compile_options(image-hdr PRIVATE -Wall -Wextra -Werror)\n"
    )

    def test_adapter_binds_original_source_and_required_node_import_library(self):
        result = windows_binding_project(self.SOURCE)
        self.assertIn('add_library(image-hdr MODULE "${FRAMELEAF_HDR_SOURCE}")', result)
        self.assertIn("target_compile_options(image-hdr PRIVATE /W4 /WX)", result)
        self.assertIn("find_library(NODE_API_LIBRARY node REQUIRED)", result)
        self.assertIn('target_link_libraries(image-hdr PRIVATE "${NODE_API_LIBRARY}")', result)

    def test_changed_or_ambiguous_source_recipe_is_refused(self):
        for source in [self.SOURCE.replace("image-hdr.cc", "renamed.cc"), self.SOURCE * 2]:
            with self.subTest(source=source), self.assertRaisesRegex(BuildError, "cmake_source_changed"):
                windows_binding_project(source)


class HostMediaTests(unittest.TestCase):
    def test_windows_cmake_gets_verified_processor_identity_without_inherited_overrides(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for name in ["bin/node.exe", "lib/node.lib", "include/node/node_api.h"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture")

            def inspect_environment(git, source, revision, name, env):
                self.assertEqual(env.get("PROCESSOR_ARCHITECTURE"), "AMD64")
                self.assertNotIn("PROCESSOR_ARCHITEW6432", env)
                self.assertNotIn("NODE_OPTIONS", env)
                raise BuildError("verified_architecture_checked_before_source_build")

            with (
                patch("build_host_media.platform.system", return_value="Windows"),
                patch("build_host_media.platform.machine", return_value="AMD64"),
                patch("build_host_media.shutil.which", return_value=str(root / "tools/tool.exe")),
                patch("build_host_media.git_blob", side_effect=inspect_environment),
                patch.dict(os.environ, {"PROCESSOR_ARCHITECTURE": "untrusted", "PROCESSOR_ARCHITEW6432": "ARM64", "NODE_OPTIONS": "--require=untrusted.js"}),
                self.assertRaisesRegex(BuildError, "verified_architecture_checked"),
            ):
                build(root, "a" * 40, root, root, root / "output")

    def test_windows_rejects_unpinned_revision_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            with (
                patch("build_host_media.platform.system", return_value="Windows"),
                self.assertRaisesRegex(BuildError, "revision_invalid"),
            ):
                build(root, "main", root, root, output)
            self.assertFalse(output.exists())

    def test_linux_rejects_unpinned_revision_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            with (
                patch("build_host_media.platform.system", return_value="Linux"),
                self.assertRaisesRegex(BuildError, "revision_invalid"),
            ):
                build(root, "main", root, root, output)
            self.assertFalse(output.exists())

    def test_preflight_refuses_unqualified_targets_or_unpinned_sources_before_creating_output(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            with (
                patch("build_host_media.platform.system", return_value="FreeBSD"),
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
