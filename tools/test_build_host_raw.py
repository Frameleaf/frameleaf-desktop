import hashlib
import unittest
from copy import deepcopy

from build_host_raw import raw_contract
from build_runtime import BuildError


class NativeRawContractTests(unittest.TestCase):
    def test_only_pinned_sources_and_exact_frameleaf_patches_are_accepted(self):
        repositories = {
            "darktable": ("darktable-org/darktable", "."),
            "rawspeed": ("darktable-org/rawspeed", "src/external/rawspeed"),
            "whereami": ("gpakosz/whereami", "src/external/whereami"),
            "opencl": ("KhronosGroup/OpenCL-Headers", "src/external/OpenCL"),
            "lensfun": ("lensfun/lensfun", "lensfun"),
        }
        patches = {
            name: b"fixture"
            for name in ["patch-darktable-lens.py", "patch-darktable-mask-geometry.py"]
        }
        pin = {
            "name": "darktable",
            "repository": "darktable-org/darktable",
            "version": "5.6.2",
            "revision": "a" * 40,
            "lensfunVersion": "0.3.4",
            "inputs": [
                {
                    "name": name,
                    "repository": repo,
                    "revision": "a" * 40,
                    "sha256": "b" * 64,
                    "path": path,
                    "url": f"https://codeload.github.com/{repo}/tar.gz/" + "a" * 40,
                }
                for name, (repo, path) in repositories.items()
            ],
            "patches": {
                name: hashlib.sha256(value).hexdigest()
                for name, value in patches.items()
            },
        }
        libraw = {
            "name": "libraw",
            "repository": "LibRaw/LibRaw",
            "version": "0.22.0-dev.7bfffe2e",
            "revision": "c" * 40,
        }
        self.assertEqual(raw_contract(pin, patches, libraw), pin)
        for change in ["path", "url", "digest", "patch", "missing", "version"]:
            bad = deepcopy(pin)
            if change == "path":
                bad["inputs"][1]["path"] = "../outside"
            if change == "url":
                bad["inputs"][1]["url"] += "?token=x"
            if change == "digest":
                bad["inputs"][1]["sha256"] = "bad"
            if change == "patch":
                bad["patches"]["patch-darktable-lens.py"] = "0" * 64
            if change == "missing":
                bad["inputs"].pop()
            if change == "version":
                bad["version"] = "5.6.1"
            with self.subTest(change=change), self.assertRaises(BuildError):
                raw_contract(bad, patches, libraw)
        with self.assertRaises(BuildError):
            raw_contract(pin, patches, {**libraw, "repository": "someone/LibRaw"})
