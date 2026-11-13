"""Check that a built CUDA or OpenVINO pack loads its provider, without a GPU.

Run with the pack's own interpreter: `<pack>/payload/python/... -I -B smoke_accelerated_runtime.py <provider>`.

OpenVINO also runs on a processor, so a session on its CPU device proves the provider and its
libraries initialise. That is not an accelerator qualification: the runtime refuses to qualify
OpenVINO without one of its graphics devices.

CUDA cannot create a session without an NVIDIA card. What is checked without one: the CUDA
libraries onnxruntime lists and cuDNN's main library are in the pack and every bundled one opens
on its own; the CUDA provider library is in the pack and everything it needs is there. On
Windows its import table is read: every library it imports is found and exports every imported
function, and the library then loads (it does not import the driver's library). On Linux the
dynamic linker resolves everything it links against from the pack except the NVIDIA driver
library `libcuda.so.1`, which only a computer with the driver has. With a device the session
must be on CUDA and run; without one, the only accepted outcome is that the driver is absent.
On a computer without a card nothing here shows a CUDA session or inference.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
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
        if platform.system() == "Windows":
            import os

            from pe_imports import unsatisfied

            # The Windows wheel loads OpenVINO from the `openvino` package: name what is missing.
            capi = Path(ort.__file__).resolve().parent / "capi"
            libraries = Path(ort.__file__).resolve().parent.parent / "openvino" / "libs"
            assert (libraries / "openvino.dll").is_file(), "openvino.dll is not in the pack"
            system = Path(os.environ["SystemRoot"]) / "System32"
            problems = unsatisfied(
                capi / "onnxruntime_providers_openvino.dll", [capi, libraries, Path(sys.executable).parent, system]
            )
            assert not problems, f"the provider library's imports are not satisfied: {problems}"
            print("OpenVINO provider library imports are satisfied by the pack")
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
        import os
        import subprocess

        windows = platform.system() == "Windows"
        site = Path(ort.__file__).resolve().parent.parent
        driver = "nvcuda.dll" if windows else "libcuda.so.1"
        try:
            ctypes.CDLL(driver)
            driver_present = True
        except OSError:
            driver_present = False
        device = bool(facts["gpus"]) or driver_present or shutil.which("nvidia-smi") is not None
        print("NVIDIA device or driver present:", device)
        # onnxruntime's own lists of what it preloads from the wheels. The CUDA libraries and
        # cuDNN's main library must be in the pack; every one that is there must open on its own.
        # (onnxruntime treats a cuDNN engine library the wheel does not have as optional.)
        cuda = [site.joinpath(*parts) for parts in ort._get_nvidia_dll_paths(windows, True, False)]
        cudnn = [site.joinpath(*parts) for parts in ort._get_nvidia_dll_paths(windows, False, True)]
        assert len(cuda) >= 4 and cudnn, (cuda, cudnn)
        for library in cuda:
            assert library.is_file(), f"missing from the pack: {library}"
        main = "cudnn64_9.dll" if windows else "libcudnn.so.9"
        assert any(library.name == main and library.is_file() for library in cudnn), f"{main} is not in the pack"
        bundled = [library for library in cuda + cudnn if library.is_file()]
        for library in bundled:
            ctypes.CDLL(str(library))  # raises when it or one of its dependencies does not load
        print(f"CUDA: {len(cuda)} CUDA and {len(bundled) - len(cuda)} of {len(cudnn)} cuDNN libraries are in the pack and load")
        capi = site / "onnxruntime" / "capi"
        folders = sorted({library.parent for library in bundled} | {capi})
        if windows:
            from pe_imports import PortableExecutable, unsatisfied

            provider_library = capi / "onnxruntime_providers_cuda.dll"
            assert provider_library.is_file() and (capi / "onnxruntime_providers_shared.dll").is_file()
            # Every library the provider imports is found, and exports every function imported
            # from it. (Its failure to load names neither: error 126 or 127.) The driver's own
            # library is not among its imports, so nothing here depends on a card.
            system = Path(os.environ["SystemRoot"]) / "System32"
            problems = unsatisfied(provider_library, [*folders, Path(sys.executable).parent, system])
            imported = sorted(PortableExecutable(provider_library).imports())
            print("CUDA provider library imports", [name for name in imported if not name.lower().startswith("api-ms-")])
            assert not problems, f"the provider library's imports are not satisfied: {problems}"
            assert driver not in [name.lower() for name in imported]
            ctypes.CDLL(str(capi / "onnxruntime_providers_shared.dll"))
            ctypes.CDLL(str(provider_library))  # the real loader agrees
            print("CUDA provider library loaded")
            unresolved = [] if driver_present else [driver]
        else:
            provider_library = capi / "libonnxruntime_providers_cuda.so"
            assert provider_library.is_file() and (capi / "libonnxruntime_providers_shared.so").is_file()
            listing = subprocess.run(
                ["ldd", str(provider_library)],
                capture_output=True,
                text=True,
                check=True,
                env={**os.environ, "LD_LIBRARY_PATH": ":".join(str(folder) for folder in folders)},
            ).stdout
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
            assert np.allclose(session.run(None, feed)[0], expected)
            print("CUDA session ran on the card")
        else:
            # Without the driver onnxruntime leaves CUDA out; that is the only reason accepted.
            assert unresolved == [driver] and provider not in used, (unresolved, used)
            print("CUDA session not created: the NVIDIA driver library is absent (no card here)")
        assert not accelerator_present(provider, facts) or facts["gpus"]
print("smoke ok")
