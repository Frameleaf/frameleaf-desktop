import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

from obtain_host_component import obtain, validate_producer
from build_runtime import BuildError


class ComponentAcquisitionTests(unittest.TestCase):
    def fixture(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("qualification.json", json.dumps({"sourceRevision": "b" * 40}))
            archive.writestr("payload/component", b"original component bytes")
        data = stream.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        pin = {"artifactId": 123, "runId": 456, "runAttempt": 2, "headSha": "a" * 40,
               "workflow": ".github/workflows/windows-host-server.yml", "archiveSha256": digest}
        artifact = {"id": 123, "expired": False, "size_in_bytes": len(data),
                    "created_at": "2026-11-02T20:02:00Z",
                    "digest": "sha256:" + digest, "workflow_run": {"id": 456,
                    "head_sha": "a" * 40, "repository_id": 1421136454,
                    "head_repository_id": 1421136454}}
        run = {"id": 456, "head_sha": "a" * 40, "path": pin["workflow"], "run_attempt": 2,
               "run_started_at": "2026-11-02T20:01:00Z", "updated_at": "2026-11-02T20:03:00Z",
               "status": "completed", "conclusion": "success",
               "repository": {"id": 1421136454, "full_name": "Frameleaf/frameleaf-desktop"},
               "head_repository": {"id": 1421136454, "full_name": "Frameleaf/frameleaf-desktop"}}
        return data, pin, artifact, run

    def test_producer_admission_rejects_failed_stale_or_mismatched_identity(self):
        _, pin, artifact, run = self.fixture()
        validate_producer(pin, artifact, run)
        cases = [
            ("artifact", "id", 124), ("artifact", "expired", True),
            ("artifact", "expired", 0), ("artifact", "size_in_bytes", True),
            ("artifact", "size_in_bytes", 0), ("artifact", "size_in_bytes", 2 * 1024**3 + 1),
            ("artifact", "digest", "sha256:" + "f" * 64),
            ("run", "id", 457), ("run", "head_sha", "c" * 40),
            ("run", "path", ".github/workflows/other.yml"),
            ("run", "status", "in_progress"), ("run", "conclusion", "failure"),
            ("run", "conclusion", "cancelled"),
            ("run", "run_attempt", 1),
            ("run", "run_attempt", True),
            ("artifact", "created_at", "2026-11-02T20:00:00Z"),
            ("artifact", "created_at", "2026-11-02T20:01:00Z"),
            ("artifact", "created_at", "2026-11-02T20:04:00Z"),
            ("artifact", "created_at", None),
            ("artifact", "workflow_run", {}), ("run", "repository", {}),
            ("run", "head_repository", {"id": 1, "full_name": "other/fork"}),
        ]
        for target, key, value in cases:
            with self.subTest(target=target, key=key, value=value):
                a, r = copy.deepcopy(artifact), copy.deepcopy(run)
                (a if target == "artifact" else r)[key] = value
                with self.assertRaises(BuildError):
                    validate_producer(pin, a, r)
        for key, value in [("artifactId", True), ("runId", 0), ("headSha", "main"),
                           ("archiveSha256", "x" * 64), ("workflow", "../other.yml")]:
            with self.subTest(pin=key), self.assertRaises(BuildError):
                validate_producer({**pin, key: value}, artifact, run)

    def test_actual_download_bytes_are_bound_before_extraction_and_original_receipt_is_preserved(self):
        data, pin, artifact, run = self.fixture()
        real_popen = subprocess.Popen
        for suffix, downloaded, succeeds in [("good", data, True), ("changed", data[:-1] + b"x", False),
                                              ("oversized", data + b"x", False)]:
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "result"
                def fake_process(arguments, **kwargs):
                    self.assertEqual(arguments, ["gh", "api", "repos/Frameleaf/frameleaf-desktop/actions/artifacts/123/zip"])
                    encoded = base64.b64encode(downloaded).decode()
                    return real_popen([sys.executable, "-c",
                        "import base64,sys;sys.stdout.buffer.write(base64.b64decode(" + repr(encoded) + "))"], **kwargs)
                with patch("obtain_host_component.api", side_effect=[artifact, run]) as api_mock, \
                     patch("obtain_host_component.subprocess.Popen", side_effect=fake_process):
                    if succeeds:
                        obtain(pin, output)
                        self.assertEqual((output / "component/payload/component").read_bytes(), b"original component bytes")
                        self.assertEqual(json.loads((output / "component/qualification.json").read_text()),
                                         {"sourceRevision": "b" * 40})
                        self.assertEqual(json.loads((output / "producer.json").read_text())["approved"], pin)
                        self.assertFalse((output / "archive.zip").exists())
                        self.assertEqual(api_mock.call_args_list[1].args,
                                         ("actions/runs/456/attempts/2",))
                    else:
                        with self.assertRaises(BuildError):
                            obtain(pin, output)
                        self.assertFalse(output.exists())

    def test_download_deadline_kills_the_process_and_removes_partial_output(self):
        _, pin, artifact, run = self.fixture()
        real_popen, real_timer = subprocess.Popen, threading.Timer
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result"
            def deadline(seconds, callback):
                self.assertEqual(seconds, 300)
                return real_timer(0.05, callback)
            with patch("obtain_host_component.api", side_effect=[artifact, run]), \
                 patch("obtain_host_component.subprocess.Popen", side_effect=lambda _, **kwargs:
                       real_popen([sys.executable, "-c", "import time;time.sleep(10)"], **kwargs)), \
                 patch("obtain_host_component.threading.Timer", side_effect=deadline):
                with self.assertRaisesRegex(BuildError, "download_failed"):
                    obtain(pin, output)
                self.assertFalse(output.exists())

    def test_identity_bound_archive_still_cannot_escape_extraction_or_replace_existing_output(self):
        _, pin, artifact, run = self.fixture()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("good", b"fixture")
            archive.writestr("../outside", b"escape")
        data = stream.getvalue()
        pin["archiveSha256"] = hashlib.sha256(data).hexdigest()
        artifact.update(digest="sha256:" + pin["archiveSha256"], size_in_bytes=len(data))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "result"
            with patch("obtain_host_component.api", side_effect=[artifact, run]), \
                 patch("obtain_host_component.download", side_effect=lambda _, archive, __: archive.write_bytes(data)):
                with self.assertRaises(BuildError):
                    obtain(pin, output)
            self.assertFalse(output.exists())
            self.assertFalse((root / "outside").exists())
            output.mkdir()
            (output / "existing").write_bytes(b"preserved")
            with patch("obtain_host_component.api") as api_mock:
                with self.assertRaisesRegex(BuildError, "output_invalid"):
                    obtain(pin, output)
                api_mock.assert_not_called()
            self.assertEqual((output / "existing").read_bytes(), b"preserved")
