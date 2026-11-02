"""Run the workflow's actual package-inventory gate without compiling engines."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest


class WindowsRawToolchainTests(unittest.TestCase):
    def test_only_the_complete_reviewed_inventory_authorizes_compilation(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/windows-host-raw.yml").read_text()
        gate = workflow.split(
            "      - name: Reject toolchain drift before any probe or engine compilation\n", 1
        )[1].split("        run: |\n", 1)[1].split("      - name:", 1)[0]
        gate = textwrap.dedent(gate)
        cases = [
            ("matching", "gcc 1\nzlib 2\n", "gcc 1\nzlib 2\n", True),
            ("checkout-newlines", "gcc 1\r\nzlib 2\r\n", "gcc 1\nzlib 2\n", True),
            ("version-drift", "gcc 1\nzlib 2\n", "gcc 3\nzlib 2\n", False),
            ("removed-package", "gcc 1\nzlib 2\n", "gcc 1\n", False),
            ("added-package", "gcc 1\nzlib 2\n", "gcc 1\nnew 1\nzlib 2\n", False),
            ("empty", "", "", False),
            ("unsorted", "zlib 2\ngcc 1\n", "zlib 2\ngcc 1\n", False),
            ("missing", None, "gcc 1\n", False),
        ]
        for name, expected, actual, allowed in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "tools").mkdir()
                if expected is not None:
                    (root / "tools/windows-raw-toolchain.txt").write_bytes(expected.encode())
                (root / "fl-raw-toolchain.txt").write_bytes(actual.encode())
                result = subprocess.run(
                    [sys.executable, "-c", gate], capture_output=True, text=True,
                    env=os.environ | {"RUNNER_TEMP": temporary,
                                      "GITHUB_WORKSPACE": temporary, "GITHUB_SHA": "a" * 40},
                )
                self.assertEqual(result.returncode == 0, allowed, result.stderr)
                receipt = root / "fl-raw-toolchain-lock.json"
                self.assertEqual(receipt.exists(), allowed)
                if allowed:
                    self.assertEqual(json.loads(receipt.read_text()), {
                        "desktopSourceRevision": "a" * 40,
                        "packageInventorySha256": hashlib.sha256(b"gcc 1\nzlib 2\n").hexdigest(),
                        "packageCount": 2,
                    })

    def test_archive_requires_passed_consumer_and_retains_the_toolchain_lock(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/windows-host-raw.yml").read_text()
        archive = workflow.split(
            "      - name: Archive the qualified RAW component with consumer evidence\n", 1
        )[1].split("        run: |\n", 1)[1].split("      - name:", 1)[0]
        archive = textwrap.dedent(archive)
        for state, lock_present in [("passed", True), ("failed", True), ("passed", False)]:
            with self.subTest(state=state, lock_present=lock_present), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for name in ["fl-windows-raw/raw", "fl-raw-runtime", "fl-raw-server"]:
                    (root / name).mkdir(parents=True)
                for name in ["fl-windows-raw/qualification.json", "fl-raw-runtime/qualification.json",
                             "fl-raw-server/qualification.json", "fl-raw-pe-qualification.json"]:
                    (root / name).write_text("{}")
                (root / "fl-raw-runtime/raw-qualification.json").write_text(json.dumps({"qualification": state}))
                (root / "fl-raw-toolchain.txt").write_text("gcc 1\n")
                if lock_present:
                    (root / "fl-raw-toolchain-lock.json").write_text('{"packageCount":1}')
                result = subprocess.run([sys.executable, "-c", archive], capture_output=True, text=True,
                                        env=os.environ | {"RUNNER_TEMP": temporary})
                allowed = state == "passed" and lock_present
                self.assertEqual(result.returncode == 0, allowed, result.stderr)
                output = root / "windows-raw-component.tar.gz"
                self.assertEqual(output.exists(), allowed)
                if allowed:
                    with tarfile.open(output) as bundle:
                        self.assertEqual(bundle.extractfile("raw-candidate/toolchain-lock.json").read(),
                                         b'{"packageCount":1}')


if __name__ == "__main__":
    unittest.main()
