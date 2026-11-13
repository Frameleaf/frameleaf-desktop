import ctypes
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


class MetalObserverTests(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).resolve().parent.parent / "runtime/metal_observer.py"
        self.assertTrue(source.is_file(), "private verified observer loader is missing")
        spec = importlib.util.spec_from_file_location("metal_observer", source)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.library = self.root / "_frameleaf_coreml_observer.dylib"
        self.library.write_bytes(b"owned fixture library")
        self.digest = hashlib.sha256(self.library.read_bytes()).hexdigest()
        self.device = {
            "abiVersion": 1,
            "osBuild": "Version 27.2 (Build 26B5101f)",
            "devices": [{"name": "Test GPU", "registryId": "00000000000000ab"}],
        }
        self.raw_report = {
            "abiVersion": 1,
            "diagnosticOnly": True,
            "positiveDirectDispatchRequired": True,
            "scopes": [],
        }
        self.native = Mock()
        self.native.fl_gpu_abi_version.return_value = 1
        self.native.fl_gpu_install.return_value = 0
        self.native.fl_gpu_begin.return_value = 0
        self.native.fl_gpu_end.return_value = 0
        self.native.fl_gpu_reset.return_value = 0
        self.native.fl_gpu_device_report.side_effect = lambda out, size: self.write(
            self.device, out, size
        )
        self.native.fl_gpu_report.side_effect = lambda out, size: self.write(
            self.raw_report, out, size
        )
        self.addCleanup(patch.stopall)
        patch.object(self.module.platform, "system", return_value="Darwin").start()
        patch.object(self.module.platform, "machine", return_value="arm64").start()
        self.load = patch.object(
            self.module.ctypes, "CDLL", return_value=self.native
        ).start()

    @staticmethod
    def write(value, out, capacity):
        raw = json.dumps(value).encode() + b"\0"
        if out is not None and capacity >= len(raw):
            ctypes.memmove(out, raw, len(raw))
        return len(raw)

    def observer(self):
        return self.module.MetalObserver(self.root, self.digest)

    def test_facts_bind_library_actual_device_and_os_without_installing_hooks(self):
        facts = self.observer().facts()
        self.assertEqual(facts["collectorSha256"], self.digest)
        self.assertEqual(facts["osBuild"], self.device["osBuild"])
        self.assertEqual(
            facts["devices"],
            [
                {
                    "name": "Test GPU",
                    "identitySha256": hashlib.sha256(b"00000000000000ab").hexdigest(),
                }
            ],
        )
        self.assertNotIn("registryId", json.dumps(facts))
        self.native.fl_gpu_install.assert_not_called()

    def test_bad_hash_or_symlink_is_refused_before_loading_native_code(self):
        for digest in ["f" * 64, "bad", "A" * 64, None, True]:
            with self.assertRaises(ValueError):
                self.module.MetalObserver(self.root, digest)
        self.library.rename(self.root / "real")
        self.library.symlink_to(self.root / "real")
        with self.assertRaises(ValueError):
            self.observer()
        self.load.assert_not_called()

    def test_file_growth_is_rejected_with_a_bounded_read(self):
        initial = self.library.stat().st_size
        stream = io.BytesIO(b"x" * (initial + 10000))
        with (
            patch.object(Path, "open", return_value=stream),
            self.assertRaises(ValueError),
        ):
            self.module.file_hash(self.library, 4 * 1024 * 1024)

    def test_unsupported_host_never_loads_native_code(self):
        for system, machine in [
            ("Windows", "arm64"),
            ("Linux", "arm64"),
            ("Darwin", "x86_64"),
        ]:
            with (
                patch.object(self.module.platform, "system", return_value=system),
                patch.object(self.module.platform, "machine", return_value=machine),
                self.assertRaises(ValueError),
            ):
                self.observer()
        self.load.assert_not_called()

    def test_changed_bytes_and_wrong_abi_are_refused(self):
        self.native.fl_gpu_abi_version.return_value = 2
        with self.assertRaises(ValueError):
            self.observer()
        self.native.fl_gpu_abi_version.return_value = 1
        observer = self.observer()
        self.library.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            observer.facts()

    def test_invalid_device_identity_or_oversized_native_output_is_refused(self):
        for identity in ["0" * 16, "not-hex", 12]:
            self.device["devices"][0]["registryId"] = identity
            with self.assertRaises(ValueError):
                self.observer().facts()
        self.native.fl_gpu_device_report.side_effect = lambda out, size: 2**32
        with self.assertRaises(ValueError):
            self.observer().facts()

    def test_observation_binds_model_hash_and_actual_dispatch_device(self):
        model = self.root / "model.onnx"
        model.write_bytes(b"approved fixture")
        digest = hashlib.sha256(model.read_bytes()).hexdigest()
        observer = self.observer()
        with observer.observe(model, digest):
            self.raw_report["scopes"].append(
                {
                    "callId": 1,
                    "valid": True,
                    "computeBuffers": 2,
                    "computeDispatches": 4,
                    "gpuNanoseconds": 10.0,
                    "pending": 0,
                    "unverifiedIndirectBuffers": 0,
                    "deviceNames": ["Test GPU"],
                    "deviceRegistryIds": ["00000000000000ab"],
                }
            )
        evidence = observer.evidence()
        self.assertEqual(evidence["calls"][0]["modelSha256"], digest)
        self.assertEqual(evidence["calls"][0]["computeDispatches"], 4)
        self.assertNotIn("00000000000000ab", json.dumps(evidence))
        self.raw_report["scopes"][0]["deviceRegistryIds"] = ["00000000000000ac"]
        with self.assertRaises(ValueError):
            observer.evidence()

    def test_nested_calls_and_changed_model_fail_closed(self):
        model = self.root / "model.onnx"
        model.write_bytes(b"fixture")
        digest = hashlib.sha256(model.read_bytes()).hexdigest()
        observer = self.observer()
        with (
            self.assertRaises(ValueError),
            observer.observe(model, digest),
            observer.observe(model, digest),
        ):
            pass
        self.native.fl_gpu_end.assert_called_once_with(1)
        self.native.fl_gpu_begin.reset_mock()
        with self.assertRaises(ValueError), observer.observe(model, "f" * 64):
            pass
        self.native.fl_gpu_begin.assert_not_called()

    def test_zero_work_invalid_scopes_and_nonfinite_time_cannot_be_evidence(self):
        model = self.root / "model.onnx"
        model.write_bytes(b"fixture")
        digest = hashlib.sha256(model.read_bytes()).hexdigest()
        observer = self.observer()
        with observer.observe(model, digest):
            pass
        valid = {
            "callId": 1,
            "valid": True,
            "computeBuffers": 2,
            "computeDispatches": 4,
            "gpuNanoseconds": 10.0,
            "pending": 0,
            "unverifiedIndirectBuffers": 0,
            "deviceNames": ["Test GPU"],
            "deviceRegistryIds": ["00000000000000ab"],
        }
        for key, value in [
            ("valid", False),
            ("callId", True),
            ("pending", 1),
            ("computeBuffers", 0),
            ("computeDispatches", True),
            ("gpuNanoseconds", float("nan")),
            ("unverifiedIndirectBuffers", 1),
        ]:
            self.raw_report["scopes"] = [dict(valid, **{key: value})]
            with self.assertRaises(ValueError):
                observer.evidence()
        self.raw_report["scopes"] = [valid, valid]
        with self.assertRaises(ValueError):
            observer.evidence()

    def test_model_changes_during_compute_invalidate_the_observer(self):
        model = self.root / "model.onnx"
        model.write_bytes(b"fixture")
        digest = hashlib.sha256(model.read_bytes()).hexdigest()
        observer = self.observer()
        with self.assertRaises(ValueError), observer.observe(model, digest):
            model.write_bytes(b"changed")
        self.native.fl_gpu_end.assert_called_once_with(1)
        with self.assertRaises(ValueError):
            observer.evidence()

    def test_drain_validates_before_reset_and_continues_with_unique_call_ids(self):
        model = self.root / "model.onnx"
        model.write_bytes(b"fixture")
        digest = hashlib.sha256(model.read_bytes()).hexdigest()
        observer = self.observer()

        def reset():
            self.raw_report["scopes"].clear()
            return 0

        self.native.fl_gpu_reset.side_effect = reset
        for identifier in range(1, 131):
            with observer.observe(model, digest):
                self.raw_report["scopes"].append(
                    {
                        "callId": identifier,
                        "valid": True,
                        "computeBuffers": 1,
                        "computeDispatches": 1,
                        "gpuNanoseconds": 10.0,
                        "pending": 0,
                        "unverifiedIndirectBuffers": 0,
                        "deviceNames": ["Test GPU"],
                        "deviceRegistryIds": ["00000000000000ab"],
                    }
                )
            value = observer.evidence(drain=True)
            self.assertEqual(value["calls"][0]["callId"], identifier)
            self.assertEqual(len(observer.calls), 0)
        self.assertEqual(self.native.fl_gpu_reset.call_count, 130)

    def test_failed_reset_permanently_refuses_more_work(self):
        model = self.root / "model.onnx"
        model.write_bytes(b"fixture")
        digest = hashlib.sha256(model.read_bytes()).hexdigest()
        observer = self.observer()
        with observer.observe(model, digest):
            self.raw_report["scopes"].append(
                {
                    "callId": 1,
                    "valid": True,
                    "computeBuffers": 1,
                    "computeDispatches": 1,
                    "gpuNanoseconds": 10.0,
                    "pending": 0,
                    "unverifiedIndirectBuffers": 0,
                    "deviceNames": ["Test GPU"],
                    "deviceRegistryIds": ["00000000000000ab"],
                }
            )
        self.native.fl_gpu_reset.return_value = -1
        with self.assertRaises(ValueError):
            observer.evidence(drain=True)
        with self.assertRaises(ValueError), observer.observe(model, digest):
            pass

    def test_unproved_cpu_work_cannot_be_discarded_by_drain(self):
        model = self.root / "model.onnx"
        model.write_bytes(b"fixture")
        digest = hashlib.sha256(model.read_bytes()).hexdigest()
        observer = self.observer()
        with observer.observe(model, digest):
            self.raw_report["scopes"].append(
                {
                    "callId": 1,
                    "valid": True,
                    "computeBuffers": 0,
                    "computeDispatches": 0,
                    "gpuNanoseconds": 0.0,
                    "pending": 0,
                    "unverifiedIndirectBuffers": 0,
                    "deviceNames": [],
                    "deviceRegistryIds": [],
                }
            )
        with self.assertRaises(ValueError):
            observer.evidence(drain=True)
        self.native.fl_gpu_reset.assert_not_called()

    def test_missing_reset_capability_refuses_an_older_library(self):
        del self.native.fl_gpu_reset
        with self.assertRaises(ValueError):
            self.observer()
        self.native.fl_gpu_install.assert_not_called()

    def test_active_scope_cannot_drain(self):
        model = self.root / "model.onnx"
        model.write_bytes(b"fixture")
        digest = hashlib.sha256(model.read_bytes()).hexdigest()
        observer = self.observer()
        with observer.observe(model, digest), self.assertRaises(ValueError):
            observer.evidence(drain=True)
        self.native.fl_gpu_reset.assert_not_called()

    def test_contents_changed_between_runs_stop_the_next_run(self):
        model = self.root / "model.onnx"
        model.write_bytes(b"fixture")
        digest = hashlib.sha256(model.read_bytes()).hexdigest()
        observer = self.observer()
        hashed = []
        real = self.module.file_hash

        def counting(path, limit):
            if path == model:
                hashed.append(path)
            return real(path, limit)

        patch.object(self.module, "file_hash", side_effect=counting).start()
        for _ in range(2):
            with observer.observe(model, digest):
                pass
        # Every byte is read before and after every run: nothing is remembered between them.
        self.assertEqual(len(hashed), 4)
        # The same size, and the old modification time put back, do not hide a change.
        before = model.stat()
        with model.open("r+b") as stream:
            stream.write(b"changed")
        os.utime(model, ns=(before.st_atime_ns, before.st_mtime_ns))
        with self.assertRaises(ValueError), observer.observe(model, digest):
            pass
        self.assertEqual(self.native.fl_gpu_begin.call_count, 2)
        # Binding a session reads the bytes too.
        model.write_bytes(b"fixture")
        other = self.observer()
        other.verify(model, digest)
        with self.assertRaises(ValueError):
            other.verify(model, "f" * 64)
        model.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            other.verify(model, digest)

    @unittest.skipIf(os.name == "nt", "the collector runs on macOS; POSIX links")
    def test_a_parent_replaced_by_a_link_is_refused_on_every_call(self):
        real = self.root / "real"
        real.mkdir()
        model = real / "model.onnx"
        model.write_bytes(b"fixture")
        digest = hashlib.sha256(model.read_bytes()).hexdigest()
        observer = self.observer()
        with observer.observe(model, digest):
            pass
        # The same file with the same bytes, now reached through a link.
        real.rename(self.root / "moved")
        real.symlink_to(self.root / "moved")
        self.assertEqual(model.read_bytes(), b"fixture")
        with self.assertRaises(ValueError), observer.observe(model, digest):
            pass
        self.assertEqual(self.native.fl_gpu_begin.call_count, 1)
        with self.assertRaises(ValueError):
            self.observer().verify(model, digest)

if __name__ == "__main__":
    unittest.main()
