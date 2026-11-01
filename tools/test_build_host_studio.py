import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from build_host_studio import stage_studio
from build_runtime import BuildError


class StudioPackageTests(unittest.TestCase):
    def test_worker_harness_dependencies_attestation_and_fonts_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            names = [
                "LICENSE",
                "studio/engine-build.json",
                "studio/runtime/subtitle-sidecar.mjs",
                "studio/runtime/admission-font.ttf",
                "studio/runtime/admission-font.json",
                "studio/engine/package.json",
                "studio/engine/LICENSE",
                "studio/engine/frameleaf-build.json",
                "studio/engine/dist/headless.html",
                "studio/engine/headless/server.mjs",
                "studio/engine/headless/lib/cli.mjs",
                "studio/engine/headless/lib/render-core.mjs",
                "studio/guard/studio-browser-guard",
                "studio/guard/studio-browser-guard.mjs",
                *[
                    "studio/tools/" + name + ".mjs"
                    for name in [
                        "bundled-worker",
                        "bundled-worker-client",
                        "bundled-worker-executor",
                        "bundled-worker-formats",
                        "bundled-worker-fonts",
                        "render-worker-font-inputs",
                        "bundled-worker-recipe",
                        "bundled-worker-renderer",
                    ]
                ],
                *[
                    "studio/engine/node_modules/" + name + "/package.json"
                    for name in [
                        "playwright",
                        "playwright-core",
                        "zod",
                    ]
                ],
            ]
            for name in names:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture")
            (source / "studio/guard/studio-browser-guard").chmod(0o755)
            font = source / "fonts/title.ttf"
            font.parent.mkdir()
            font.write_bytes(b"\x00\x01\x00\x00fixture")
            admission = source / "studio/runtime/admission-font.ttf"
            admission.write_bytes(font.read_bytes())
            identity = source / "studio/runtime/admission-font.json"
            identity.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "sourceFile": "inter-latin-400-normal.ttf",
                        "sha256": hashlib.sha256(admission.read_bytes()).hexdigest(),
                    }
                )
            )
            files = stage_studio(source, root / "valid")
            self.assertEqual(len(files), len(names) + 1)
            for index, name in enumerate(
                [
                    "studio/runtime/admission-font.ttf",
                    "studio/runtime/admission-font.json",
                    "studio/tools/bundled-worker-executor.mjs",
                    "studio/tools/bundled-worker-fonts.mjs",
                    "studio/tools/render-worker-font-inputs.mjs",
                    "studio/engine/dist/headless.html",
                    "studio/engine/frameleaf-build.json",
                    "studio/engine/node_modules/playwright-core/package.json",
                    "studio/guard/studio-browser-guard.mjs",
                    "fonts/title.ttf",
                ]
            ):
                path = source / name
                content = path.read_bytes()
                path.unlink()
                with self.assertRaisesRegex(BuildError, "host_studio_entries_missing"):
                    stage_studio(source, root / f"missing-{index}")
                path.write_bytes(content)
                if name.endswith("studio-browser-guard"):
                    path.chmod(0o755)
            original_identity = identity.read_text()
            identity.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "sourceFile": "inter-latin-400-normal.ttf",
                        "sha256": "0" * 64,
                    }
                )
            )
            with self.assertRaisesRegex(
                BuildError, "host_studio_admission_font_invalid"
            ):
                stage_studio(source, root / "wrong-admission-font")
            identity.write_text(original_identity)
            font.write_text("version https://git-lfs.github.com/spec/v1\n")
            with self.assertRaisesRegex(BuildError, "host_studio_font_invalid"):
                stage_studio(source, root / "font-pointer")
            font.write_bytes(b"\x00\x01\x00\x00fixture")
            if os.name != "nt":
                (source / "studio/guard/studio-browser-guard").chmod(0o600)
                with self.assertRaisesRegex(
                    BuildError, "host_studio_guard_not_executable"
                ):
                    stage_studio(source, root / "non-executable-guard")
