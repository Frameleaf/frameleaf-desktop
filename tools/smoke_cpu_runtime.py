"""Check that a built processor pack runs a model on the computer it was built for.

Run with the pack's own interpreter: `<pack>/payload/python/... -I -B smoke_cpu_runtime.py <architecture>`.

FD-6: the Intel macOS pack installs an older onnxruntime than the runtime source locks (the
locked one publishes no Intel macOS wheel), beside the locked numpy, onnx and protobuf. Importing
it is not enough to show those work together: a session is created and run, and the interpreter
and onnxruntime must be native to the named architecture, not another one under translation.
"""

import importlib
import platform
import sys
import tempfile
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort
from onnx import TensorProto, helper, numpy_helper

architecture = sys.argv[1]
machine = {"arm64": "aarch64", "AMD64": "x86_64"}.get(platform.machine(), platform.machine())
assert machine == architecture, f"the pack's interpreter is {machine}, not {architecture}"
namespace = next(
    name for name in ("frameleaf_ml", "immich_ml") if importlib.util.find_spec(name)
)
importlib.import_module(f"{namespace}.native_runtime")
importlib.import_module(f"{namespace}.native_qualification")
print("onnxruntime", ort.__version__, "numpy", np.__version__, "onnx", onnx.__version__, machine)
assert "CPUExecutionProvider" in ort.get_available_providers(), ort.get_available_providers()

weights = np.arange(8, dtype=np.float32).reshape(2, 4)
model = helper.make_model(
    helper.make_graph(
        [
            helper.make_node("MatMul", ["input", "weights"], ["product"]),
            helper.make_node("Softmax", ["product"], ["output"], axis=1),
        ],
        "smoke",
        [helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 2])],
        [helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 4])],
        [numpy_helper.from_array(weights, name="weights")],
    ),
    opset_imports=[helper.make_opsetid("", 17)],
    ir_version=9,
)
feed = {"input": np.array([[1.0, 2.0]], dtype=np.float32)}
product = feed["input"] @ weights
expected = np.exp(product - product.max()) / np.exp(product - product.max()).sum()
with tempfile.TemporaryDirectory() as temporary:
    path = Path(temporary) / "model.onnx"
    onnx.save(model, path)
    session = ort.InferenceSession(path.as_posix(), providers=["CPUExecutionProvider"])
    assert session.get_providers() == ["CPUExecutionProvider"], session.get_providers()
    assert np.allclose(session.run(None, feed)[0], expected, atol=1e-6)
print("smoke ok")
