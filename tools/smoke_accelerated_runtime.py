"""Check that a built CUDA or OpenVINO pack loads its provider, without a GPU.

Run with the pack's own interpreter: `<pack>/payload/python/... -I -B smoke_accelerated_runtime.py <provider>`.

OpenVINO also runs on a processor, so a session on its CPU device proves the provider and its
libraries initialise. That is not an accelerator qualification: the runtime refuses to qualify
OpenVINO without one of its graphics devices.

CUDA (Linux) cannot create a session without an NVIDIA card. What is checked without one: every
CUDA and cuDNN library onnxruntime lists is in the pack and opens on its own; onnxruntime's CUDA
provider library is in the pack and the dynamic linker resolves everything it links against
from the pack except the NVIDIA driver library `libcuda.so.1`, which only a computer with the
driver has. Any other unresolved library fails. With a device the session must be on CUDA;
without one, the only accepted outcome is that the driver library is the one thing missing.
Nothing here shows a CUDA session or inference on a card.
"""

import ctypes
import platform
import shutil
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
        if platform.system() != "Linux":
            raise SystemExit("Desktop builds a CUDA pack for Linux only")
        import os
        import subprocess

        site = Path(ort.__file__).resolve().parent.parent
        driver = "libcuda.so.1"
        try:
            ctypes.CDLL(driver)
            driver_present = True
        except OSError:
            driver_present = False
        device = bool(facts["gpus"]) or driver_present or shutil.which("nvidia-smi") is not None
        print("NVIDIA device or driver present:", device)
        # onnxruntime's own lists of what it preloads from the wheels: every one must be in the
        # pack and open on its own.
        libraries = [site.joinpath(*parts) for parts in ort._get_nvidia_dll_paths(False, True, True)]
        assert len(libraries) >= 7, libraries
        for library in libraries:
            assert library.is_file(), f"missing from the pack: {library}"
            ctypes.CDLL(str(library))  # raises when it or one of its dependencies does not load
        print(f"CUDA: {len(libraries)} bundled CUDA and cuDNN libraries are in the pack and load")
        # The provider library and what it links against: with the pack's own library folders on
        # the search path, the dynamic linker may fail to find the NVIDIA driver library and
        # nothing else. That one library belongs to the driver, which a computer without a card
        # does not have.
        capi = site / "onnxruntime" / "capi"
        provider_library = capi / "libonnxruntime_providers_cuda.so"
        assert provider_library.is_file() and (capi / "libonnxruntime_providers_shared.so").is_file()
        folders = sorted({str(library.parent) for library in libraries} | {str(capi)})
        listing = subprocess.run(
            ["ldd", str(provider_library)],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "LD_LIBRARY_PATH": ":".join(folders)},
        ).stdout
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from linked_libraries import check_linked

        # Raises unless every NVIDIA library it links against resolves inside the pack and the
        # driver library is the one thing missing (or, with a driver, resolves from the system).
        resolved = check_linked(listing, site, driver_present)
        unresolved = [] if driver_present else [driver]
        print("CUDA provider library resolves", resolved, "unresolved:", unresolved)
        session = ort.InferenceSession(path.as_posix(), providers=[provider, "CPUExecutionProvider"])
        used = session.get_providers()
        print("session providers:", used)
        if device:
            # With a card the session must really be on CUDA, not quietly on the processor.
            assert provider in used, used
        else:
            # Without the driver onnxruntime leaves CUDA out; that is the only reason accepted.
            assert unresolved == [driver] and provider not in used, (unresolved, used)
            print("CUDA session not created: the NVIDIA driver library is absent (no card here)")
        assert not accelerator_present(provider, facts) or facts["gpus"]
print("smoke ok")
