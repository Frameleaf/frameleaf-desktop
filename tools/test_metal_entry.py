import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


class MetalEntryTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parent.parent / "runtime/metal_entry.py"
        self.assertTrue(path.is_file(), "fixed private entrypoint is missing")
        spec = importlib.util.spec_from_file_location("entry_fixture.entry", path)
        self.entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.entry)
        self.events = []
        collector = types.ModuleType("entry_fixture.metal_observer")

        def create(root, digest):
            self.events.append(("collector", root, digest))
            return object()

        collector.MetalObserver = create
        adapter = types.ModuleType("entry_fixture.metal_inference")
        adapter.MetalInference = lambda value: value
        self.modules = {collector.__name__: collector, adapter.__name__: adapter}
        for mode in ["native_runtime", "native_qualification"]:
            module = types.ModuleType("frameleaf_ml." + mode)
            module.main = lambda *, observer, mode=mode: self.events.append(
                (mode, observer)
            )
            self.modules[module.__name__] = module

    def test_only_fixed_modes_reach_public_main_with_owned_observer(self):
        for mode in ["native_runtime", "native_qualification"]:
            self.events.clear()
            with patch.dict(sys.modules, self.modules):
                self.entry.run(mode, "a" * 64)
            self.assertEqual(
                self.events[0],
                ("collector", Path(self.entry.__file__).parent, "a" * 64),
            )
            self.assertEqual(self.events[1][0], mode)

    def test_unknown_mode_is_refused_before_loading_collector_or_public_code(self):
        for mode in ["os", "frameleaf_ml.main", "../native_runtime", ""]:
            with self.assertRaises(ValueError), patch.dict(sys.modules, self.modules):
                self.entry.run(mode, "a" * 64)
            self.assertEqual(self.events, [])


if __name__ == "__main__":
    unittest.main()
