"""Check that a built CUDA or OpenVINO pack loads its provider, without a GPU.

Run with the pack's own interpreter: `<pack>/payload/python/... -I -B smoke_accelerated_runtime.py <provider>`.

OpenVINO also runs on a processor, so a session on its CPU device proves the provider and its
libraries initialise. That is not an accelerator qualification: the runtime refuses to qualify
OpenVINO without one of its graphics devices. CUDA cannot create a session without an NVIDIA
card, so only its libraries are loaded and the outcome of a session attempt is printed.
"""

import sys
import tempfile
from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

provider = sys.argv[1]
if provider not in {"CUDAExecutionProvider", "OpenVINOExecutionProvider"}:
    raise SystemExit("unsupported provider")

from frameleaf_ml import native_hardware, native_ort  # noqa: E402
from frameleaf_ml.native_qualification import accelerator_present  # noqa: E402

# The runtime's own entry: checks the provider is built in and loads the device libraries the
# pack carries (CUDA and cuDNN wheels; on Windows the OpenVINO wheel).
native_ort.configure(provider)
import onnxruntime as ort  # noqa: E402

facts = native_hardware.snapshot()["facts"]
print("onnxruntime", ort.__version__, facts["packages"], facts["providers"])
print("openvinoDevices", facts.get("openvinoDevices"), "gpus", len(facts["gpus"]))
assert provider in facts["providers"]

weights = numpy_helper.from_array(np.arange(8, dtype=np.float32).reshape(2, 4), name="weights")
model = helper.make_model(
    helper.make_graph(
        [helper.make_node("MatMul", ["input", "weights"], ["output"])],
        "smoke",
        [helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 2])],
        [helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 4])],
        [weights],
    ),
    opset_imports=[helper.make_opsetid("", 17)],
    ir_version=9,
)
feed = {"input": np.array([[1.0, 2.0]], dtype=np.float32)}
expected = feed["input"] @ np.arange(8, dtype=np.float32).reshape(2, 4)
with tempfile.TemporaryDirectory() as temporary:
    path = Path(temporary) / "model.onnx"
    onnx.save(model, path)
    if provider == "OpenVINOExecutionProvider":
        assert "CPU" in facts["openvinoDevices"], facts["openvinoDevices"]
        session = ort.InferenceSession(
            path.as_posix(),
            providers=[provider, "CPUExecutionProvider"],
            provider_options=[{"device_type": "CPU"}, {}],
        )
        session.disable_fallback()
        assert provider in session.get_providers(), session.get_providers()
        assert np.allclose(session.run(None, feed)[0], expected)
        print("OpenVINO session on its CPU device: ok")
        # A hosted runner has no Intel graphics device: this is not an accelerator.
        print("accelerator present:", accelerator_present(provider, facts))
    else:
        try:
            session = ort.InferenceSession(
                path.as_posix(), providers=[provider, "CPUExecutionProvider"]
            )
            print("CUDA session providers:", session.get_providers())
        except Exception as error:  # no NVIDIA card on a hosted runner
            print("CUDA session not created (expected without a card):", str(error)[:300])
        assert not accelerator_present(provider, facts) or facts["gpus"]
print("smoke ok")
