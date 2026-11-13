"""Owned native inference adapter; model authority is supplied by the verified binding."""

from __future__ import annotations

import math
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .metal_observer import MetalObserver


class MetalInference:
    provider = "CoreMLExecutionProvider"

    def __init__(self, collector: MetalObserver) -> None:
        self.collector = collector
        self.initial_facts = collector.facts()
        self.bindings: dict[Path, str] = {}
        self.totals: dict[str, dict] = {}
        self.failed = False
        self.lock = Lock()

    def facts(self) -> dict:
        facts = self.collector.facts()
        if self.failed or facts != self.initial_facts:
            raise ValueError("native_device_observer_invalidated")
        return facts

    def bind(self, models: Mapping[Path, str]) -> None:
        if not self.lock.acquire(blocking=False):
            raise ValueError("native_device_parallel_call_refused")
        try:
            if self.failed or not models or len(self.bindings | dict(models)) > 4096:
                raise ValueError("native_device_model_bindings_invalid")
            for path, digest in models.items():
                if (
                    not isinstance(path, Path)
                    or not path.is_absolute()
                    or not isinstance(digest, str)
                    or not re.fullmatch(r"[a-f0-9]{64}", digest)
                    or path in self.bindings
                    and self.bindings[path] != digest
                ):
                    raise ValueError("native_device_model_bindings_invalid")
            # Binding reads every byte, before any run is observed.
            for path, digest in models.items():
                self.collector.verify(path, digest)
            self.bindings.update(models)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.lock.release()

    @contextmanager
    def observe(self, model: Path) -> Iterator[None]:
        if not self.lock.acquire(blocking=False):
            raise ValueError("native_device_parallel_call_refused")
        try:
            if self.failed or model not in self.bindings:
                raise ValueError("native_device_model_not_bound")
            digest = self.bindings[model]
            with self.collector.observe(model, digest):
                yield
            proof = self.collector.evidence(drain=True)
            if proof["facts"] != self.facts() or len(proof["calls"]) != 1:
                raise ValueError("native_device_evidence_invalid")
            call = proof["calls"][0]
            if call["modelSha256"] != digest:
                raise ValueError("native_device_model_not_bound")
            previous = self.totals.get(
                digest,
                {
                    "calls": 0,
                    "computeBuffers": 0,
                    "computeDispatches": 0,
                    "gpuNanoseconds": 0.0,
                },
            )
            current = {
                "calls": previous["calls"] + 1,
                **{
                    key: previous[key] + call[key]
                    for key in ("computeBuffers", "computeDispatches", "gpuNanoseconds")
                },
            }
            if any(
                not 0 < current[key] < 2**63
                for key in ("calls", "computeBuffers", "computeDispatches")
            ) or not math.isfinite(current["gpuNanoseconds"]):
                raise ValueError("native_device_evidence_overflow")
            self.totals[digest] = current
        except BaseException:
            self.failed = True
            raise
        finally:
            self.lock.release()

    def evidence(self) -> dict:
        if not self.lock.acquire(blocking=False):
            raise ValueError("native_device_parallel_call_refused")
        try:
            if self.failed or not self.totals:
                raise ValueError("native_device_evidence_missing")
            return {
                "provider": self.provider,
                "facts": self.facts(),
                "models": [
                    {"sha256": digest, **totals}
                    for digest, totals in sorted(self.totals.items())
                ],
            }
        finally:
            self.lock.release()
