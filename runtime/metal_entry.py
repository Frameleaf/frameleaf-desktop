"""Fixed entrypoint selected by the signed desktop runtime manifest."""

import importlib
from pathlib import Path


def run(mode: str, expected_sha256: str) -> None:
    if mode not in {"native_runtime", "native_qualification"}:
        raise ValueError("native_device_entrypoint_invalid")
    from .metal_inference import MetalInference
    from .metal_observer import MetalObserver

    observer = MetalInference(MetalObserver(Path(__file__).parent, expected_sha256))
    module = importlib.import_module("frameleaf_ml." + mode)
    module.main(observer=observer)
