"""Private process-local Metal evidence; the expected library hash must come from the signed runtime."""

from __future__ import annotations

import ctypes
import hashlib
import json
import math
import platform
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock


def checked_parents(path: Path) -> None:
    """An absolute path none of whose directories is a link."""
    if not path.is_absolute():
        raise ValueError("metal_path_invalid")
    try:
        for parent in path.parents:
            if not stat.S_ISDIR(parent.lstat().st_mode):
                raise ValueError("metal_path_invalid")
    except OSError as error:
        raise ValueError("metal_file_unavailable") from error


def file_hash(path: Path, limit: int) -> str:
    try:
        checked_parents(path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("metal_file_invalid")
        digest = hashlib.sha256()
        count = 0
        with path.open("rb") as stream:
            while data := stream.read(min(1024 * 1024, info.st_size - count + 1)):
                count += len(data)
                if count > info.st_size:
                    raise ValueError("metal_file_changed")
                digest.update(data)
        if count != info.st_size:
            raise ValueError("metal_file_changed")
        return digest.hexdigest()
    except OSError as error:
        raise ValueError("metal_file_unavailable") from error


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("metal_report_duplicate_key")
        value[key] = item
    return value


def read_report(function, limit: int) -> dict:
    size = function(None, 0)
    if type(size) is not int or not 1 < size <= limit:
        raise ValueError("metal_report_size_invalid")
    buffer = ctypes.create_string_buffer(size)
    if (
        function(buffer, size) != size
        or buffer.raw[-1:] != b"\0"
        or b"\0" in buffer.raw[:-1]
    ):
        raise ValueError("metal_report_changed")
    try:
        value = json.loads(buffer.raw[:-1], object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("metal_report_invalid") from error
    if not isinstance(value, dict):
        raise ValueError("metal_report_invalid")  # noqa: TRY004 - malformed native data
    return value


class MetalObserver:
    def __init__(self, component: Path, expected_sha256: str) -> None:
        if platform.system() != "Darwin" or platform.machine().lower() not in {
            "arm64",
            "aarch64",
        }:
            raise ValueError("metal_target_unsupported")
        if not isinstance(expected_sha256, str) or not re.fullmatch(
            r"[a-f0-9]{64}", expected_sha256
        ):
            raise ValueError("metal_library_hash_invalid")
        self.path = component / "_frameleaf_coreml_observer.dylib"
        self.sha256 = expected_sha256
        self.check_library()
        try:
            self.library = ctypes.CDLL(str(self.path), mode=ctypes.RTLD_LOCAL)
            self.library.fl_gpu_abi_version.argtypes = []
            self.library.fl_gpu_abi_version.restype = ctypes.c_uint32
            self.library.fl_gpu_install.argtypes = []
            self.library.fl_gpu_install.restype = ctypes.c_int
            self.library.fl_gpu_reset.argtypes = []
            self.library.fl_gpu_reset.restype = ctypes.c_int
            for function in [self.library.fl_gpu_begin, self.library.fl_gpu_end]:
                function.argtypes = [ctypes.c_uint64]
                function.restype = ctypes.c_int
            for function in [
                self.library.fl_gpu_report,
                self.library.fl_gpu_device_report,
            ]:
                function.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                function.restype = ctypes.c_size_t
            if self.library.fl_gpu_abi_version() != 1:
                raise ValueError("metal_abi_unsupported")
        except (OSError, AttributeError) as error:
            raise ValueError("metal_library_invalid") from error
        self.check_library()
        self.lock = Lock()
        self.calls: list[tuple[int, str]] = []
        self.next_identifier = 1
        self.failed = False
        self.installed = False
        self.initial_facts = self.device_facts()

    def check_library(self) -> None:
        if file_hash(self.path, 4 * 1024 * 1024) != self.sha256:
            raise ValueError("metal_library_changed")

    def check_model(self, model: Path, expected_sha256: str) -> None:
        """Hash every byte of the model, through a path none of whose directories is a link.

        This is what proves the model of a session that was created from a file: hashing around
        every run is then deliberate, because no file identity or timestamp the platform offers
        guarantees the contents are unchanged since an earlier hash (coarse or adjustable clocks,
        filesystems that differ). A session created from memory needs none of it: see
        `check_run`."""
        checked_parents(model)
        if file_hash(model, 16 * 1024**3) != expected_sha256:
            raise ValueError("metal_model_changed")

    def check_run(
        self, model: Path, expected_sha256: str, loaded_sha256: str | None
    ) -> None:
        """The model that a run uses is the approved one.

        `loaded_sha256` is the digest the runtime took of the very bytes it created the session
        from, in memory. Those bytes cannot change under the session, so comparing digests is the
        whole proof and the file is not read again. Without it the session reads a file, and
        only hashing that file around the run says what ran."""
        if loaded_sha256 is None:
            self.check_model(model, expected_sha256)
        elif (
            not isinstance(loaded_sha256, str)
            or not re.fullmatch(r"[a-f0-9]{64}", loaded_sha256)
            or loaded_sha256 != expected_sha256
        ):
            raise ValueError("metal_model_changed")

    def verify(self, model: Path, expected_sha256: str) -> None:
        """The same check when a session is bound, before any run is observed."""
        self.check_model(model, expected_sha256)

    def device_facts(self) -> dict:
        self.check_library()
        value = read_report(self.library.fl_gpu_device_report, 16384)
        devices = value.get("devices")
        if (
            type(value.get("abiVersion")) is not int
            or value["abiVersion"] != 1
            or not isinstance(value.get("osBuild"), str)
            or not 1 <= len(value["osBuild"]) <= 256
            or not isinstance(devices, list)
            or len(devices) != 1
            or not isinstance(devices[0], dict)
            or not isinstance(devices[0].get("name"), str)
            or not 1 <= len(devices[0]["name"]) <= 256
            or not isinstance(devices[0].get("registryId"), str)
            or not re.fullmatch(r"[a-f0-9]{16}", devices[0]["registryId"])
            or devices[0]["registryId"] == "0" * 16
        ):
            raise ValueError("metal_device_report_invalid")
        return {
            "abiVersion": 1,
            "collectorSha256": self.sha256,
            "osBuild": value["osBuild"],
            "devices": [
                {
                    "name": devices[0]["name"],
                    "identitySha256": hashlib.sha256(
                        devices[0]["registryId"].encode()
                    ).hexdigest(),
                }
            ],
        }

    def facts(self) -> dict:
        value = self.device_facts()
        if value != self.initial_facts:
            raise ValueError("metal_device_changed")
        return value

    @contextmanager
    def observe(
        self, model: Path, expected_sha256: str, loaded_sha256: str | None = None
    ) -> Iterator[None]:
        if not self.lock.acquire(blocking=False):
            raise ValueError("metal_parallel_call_refused")
        try:
            if self.failed or len(self.calls) >= 64 or self.next_identifier >= 2**64:
                raise ValueError("metal_observer_unavailable")
            self.check_run(model, expected_sha256, loaded_sha256)
            self.facts()
            if not self.installed:
                if self.library.fl_gpu_install() != 0:
                    raise ValueError("metal_install_failed")
                self.installed = True
            identifier = self.next_identifier
            if self.library.fl_gpu_begin(identifier) != 0:
                raise ValueError("metal_scope_begin_failed")
            self.next_identifier += 1
            try:
                yield
            finally:
                if self.library.fl_gpu_end(identifier) != 0:
                    raise ValueError("metal_scope_end_failed")
            if loaded_sha256 is None:
                self.check_model(model, expected_sha256)
            self.facts()
            self.calls.append((identifier, expected_sha256))
        except BaseException:
            self.failed = True
            raise
        finally:
            self.lock.release()

    def evidence(self, *, drain: bool = False) -> dict:
        if not self.lock.acquire(blocking=False):
            raise ValueError("metal_parallel_call_refused")
        try:
            if self.failed or not self.calls:
                raise ValueError("metal_evidence_missing")
            facts = self.facts()
            report = read_report(self.library.fl_gpu_report, 1024 * 1024)
            scopes = report.get("scopes")
            if (
                type(report.get("abiVersion")) is not int
                or report["abiVersion"] != 1
                or report.get("diagnosticOnly") is not True
                or report.get("positiveDirectDispatchRequired") is not True
                or not isinstance(scopes, list)
                or len(scopes) != len(self.calls)
            ):
                raise ValueError("metal_evidence_invalid")
            calls = []
            device = facts["devices"][0]
            for scope, (identifier, digest) in zip(scopes, self.calls, strict=True):
                if not isinstance(scope, dict):
                    raise ValueError("metal_evidence_invalid")  # noqa: TRY004 - malformed native data
                identities = scope.get("deviceRegistryIds")
                nanos = scope.get("gpuNanoseconds")
                if (
                    type(scope.get("callId")) is not int
                    or scope["callId"] != identifier
                    or scope.get("valid") is not True
                    or type(scope.get("pending")) is not int
                    or scope["pending"] != 0
                    or type(scope.get("unverifiedIndirectBuffers")) is not int
                    or scope["unverifiedIndirectBuffers"] != 0
                    or any(
                        type(scope.get(key)) is not int or not 0 < scope[key] <= 200_000
                        for key in ["computeBuffers", "computeDispatches"]
                    )
                    or type(nanos) not in {int, float}
                    or not math.isfinite(nanos)
                    or not 0 < nanos <= 600_000_000_000
                    or scope.get("deviceNames") != [device["name"]]
                    or not isinstance(identities, list)
                    or len(identities) != 1
                    or not isinstance(identities[0], str)
                    or hashlib.sha256(identities[0].encode()).hexdigest()
                    != device["identitySha256"]
                ):
                    raise ValueError("metal_evidence_invalid")
                calls.append(
                    {
                        "callId": identifier,
                        "modelSha256": digest,
                        "deviceIdentitySha256": device["identitySha256"],
                        **{
                            key: scope[key]
                            for key in [
                                "computeBuffers",
                                "computeDispatches",
                                "gpuNanoseconds",
                            ]
                        },
                    }
                )
            value = {"diagnosticOnly": True, "facts": facts, "calls": calls}
            if drain:
                if self.library.fl_gpu_reset() != 0:
                    self.failed = True
                    raise ValueError("metal_reset_failed")
                self.calls.clear()
            return value
        finally:
            self.lock.release()
