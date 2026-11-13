import importlib.util
import os
import unittest
from contextlib import contextmanager
from pathlib import Path


class Collector:
    def __init__(self):
        self.identifier = 0
        self.expected = None
        self.spoof = False
        self.verified = []
        self.changed = False

    def facts(self):
        return {
            "abiVersion": 1,
            "collectorSha256": "a" * 64,
            "osBuild": "OS build",
            "devices": [{"name": "GPU", "identitySha256": "b" * 64}],
        }

    def verify(self, path, digest):
        if self.changed:
            raise ValueError("metal_model_changed")
        self.verified.append((path, digest))

    @contextmanager
    def observe(self, path, digest):
        self.expected = digest
        self.identifier += 1
        yield

    def evidence(self, *, drain):
        assert drain is True
        return {
            "facts": self.facts(),
            "calls": [
                {
                    "callId": self.identifier,
                    "modelSha256": "f" * 64 if self.spoof else self.expected,
                    "computeBuffers": 1,
                    "computeDispatches": 4,
                    "gpuNanoseconds": 20.0,
                }
            ],
        }


# The adapter only ever runs on macOS; its fixtures use POSIX absolute model paths.
@unittest.skipIf(os.name == "nt", "the CoreML adapter binds POSIX model paths")
class MetalInferenceTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parent.parent / "runtime/metal_inference.py"
        self.assertTrue(path.is_file(), "owned inference adapter is missing")
        spec = importlib.util.spec_from_file_location("metal_inference", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.collector = Collector()
        self.adapter = module.MetalInference(self.collector)
        self.model = Path("/owned/model.onnx")

    def test_unbound_models_and_conflicting_bindings_are_refused(self):
        with self.assertRaises(ValueError), self.adapter.observe(self.model):
            pass
        self.assertEqual(self.collector.identifier, 0)
        # A failed execution requires a fresh owned process.
        self.setUp()
        self.adapter.bind({self.model: "c" * 64})
        self.adapter.bind({self.model: "c" * 64})
        with self.assertRaises(ValueError):
            self.adapter.bind({self.model: "d" * 64})

    def test_every_call_drains_and_summary_stays_bounded_by_models(self):
        self.adapter.bind({self.model: "c" * 64})
        for _ in range(130):
            with self.adapter.observe(self.model):
                pass
        report = self.adapter.evidence()
        self.assertEqual(report["provider"], "CoreMLExecutionProvider")
        self.assertEqual(
            report["models"],
            [
                {
                    "sha256": "c" * 64,
                    "calls": 130,
                    "computeBuffers": 130,
                    "computeDispatches": 520,
                    "gpuNanoseconds": 2600.0,
                }
            ],
        )

    def test_wrong_model_proof_refuses_output_and_further_calls(self):
        self.adapter.bind({self.model: "c" * 64})
        self.collector.spoof = True
        with self.assertRaises(ValueError), self.adapter.observe(self.model):
            pass
        with self.assertRaises(ValueError), self.adapter.observe(self.model):
            pass
        self.assertEqual(self.collector.identifier, 1)

    def test_parallel_scopes_are_refused_before_collector_entry(self):
        self.adapter.bind({self.model: "c" * 64})
        with (
            self.adapter.observe(self.model),
            self.assertRaises(ValueError),
            self.adapter.observe(self.model),
        ):
            pass
        self.assertEqual(self.collector.identifier, 1)

    def test_binding_hashes_every_model_and_a_changed_model_is_never_bound(self):
        self.adapter.bind({self.model: "c" * 64})
        self.assertEqual(self.collector.verified, [(self.model, "c" * 64)])
        # Binding again reads the bytes again; nothing remembered stands in for it.
        self.adapter.bind({self.model: "c" * 64})
        self.assertEqual(len(self.collector.verified), 2)
        other = self.model.with_name("other.onnx")
        self.collector.changed = True
        with self.assertRaises(ValueError):
            self.adapter.bind({other: "d" * 64})
        self.assertNotIn(other, self.adapter.bindings)
        with self.assertRaises(ValueError), self.adapter.observe(self.model):
            pass


if __name__ == "__main__":
    unittest.main()
