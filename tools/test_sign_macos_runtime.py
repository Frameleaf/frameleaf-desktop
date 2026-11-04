import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_runtime import inventory
from sign_macos_runtime import sign_runtime


class MacRuntimeSigningTests(unittest.TestCase):
    def test_only_signable_code_changes_and_manifest_matches(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / "payload"
            payload.mkdir()
            executable = payload / "python"
            executable.write_bytes(bytes.fromhex("cffaedfe") + b"native")
            (payload / "model").write_bytes(b"model data")
            manifest = {"python": "python", "files": inventory(payload)}
            (root / "manifest.json").write_text(json.dumps(manifest))

            def mock_codesign(args, **kwargs):
                if args[0] == "/usr/bin/file":
                    from subprocess import CompletedProcess
                    return CompletedProcess(args, 0, "Mach-O 64-bit executable arm64")
                self.assertEqual(Path(args[-1]), executable)
                if "--force" in args:
                    executable.write_bytes(b"signed executable")

            with patch("sign_macos_runtime.subprocess.run", side_effect=mock_codesign):
                sign_runtime(root, "Developer ID Application: Example")
            result = json.loads((root / "manifest.json").read_text())
            self.assertEqual(result["files"], inventory(payload))
            self.assertEqual(result["files"]["python"]["sha256"], hashlib.sha256(b"signed executable").hexdigest())
