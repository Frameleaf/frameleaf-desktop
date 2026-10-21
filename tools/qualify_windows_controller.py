"""Qualify an x64 Windows controller without a private CRT or ambient launch paths."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import platform
import re
import subprocess
from pathlib import Path

from build_runtime import BuildError, regular, sha256
from relocate_windows import PLATFORM_DLLS, pe_imports


def nsis_gui_sha256(image: bytes) -> str:
    # Tauri 2.12.3 patches this marker for NSIS, then restores the loose executable.
    marker = b"__TAURI_BUNDLE_TYPE_VAR_UNK"
    if image.count(marker) != 1:
        raise BuildError("desktop_bundle_marker_invalid")
    return hashlib.sha256(image.replace(marker, b"__TAURI_BUNDLE_TYPE_VAR_NSS", 1)).hexdigest()


def system_directory() -> Path:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_directory = kernel.GetSystemDirectoryW
    get_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    get_directory.restype = ctypes.c_uint32
    value = ctypes.create_unicode_buffer(32768)
    size = get_directory(value, len(value))
    if not 0 < size < len(value):
        raise BuildError("controller_system_directory_unavailable")
    directory = Path(value.value)
    if not directory.is_absolute() or not directory.is_dir():
        raise BuildError("controller_system_directory_unavailable")
    return directory


def qualify(binary: Path, inspector: Path) -> dict:
    if platform.system() != "Windows":
        raise BuildError("controller_platform_unsupported")
    for path in [binary, inspector]:
        info = regular(path)
        if not path.is_absolute() or not path.is_file() or not 0 < info.st_size <= 512 * 1024 * 1024:
            raise BuildError("controller_input_invalid")
    image = binary.read_bytes()
    if not pe_imports(image):
        raise BuildError("controller_imports_missing")
    header = int.from_bytes(image[60:64], "little")
    if int.from_bytes(image[header + 22:header + 24], "little") & 0x2000:
        raise BuildError("controller_executable_required")
    system = system_directory()
    env = {"SystemRoot": str(system.parent), "WINDIR": str(system.parent), "PATH": str(system)}
    try:
        result = subprocess.run([str(inspector), "/nologo", "/dependents", str(binary)],
                                cwd=system, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=30, check=False)
        if result.returncode or result.stderr or len(result.stdout) > 65536:
            raise BuildError("controller_inspection_failed")
        output = result.stdout.decode("utf-8", errors="replace")
        if "File Type: EXECUTABLE IMAGE" not in output:
            raise BuildError("controller_inspection_failed")
        lines = [line.strip() for line in output.splitlines()]
        heading = "Image has the following dependencies:"
        if lines.count(heading) != 1 or lines.count("Summary") != 1:
            raise BuildError("controller_inspection_failed")
        start, end = lines.index(heading), lines.index("Summary")
        if end <= start:
            raise BuildError("controller_inspection_failed")
        names = [line for line in lines[start + 1:end] if line]
        if any(not re.fullmatch(r"[A-Za-z0-9_.+-]+\.dll", name, re.IGNORECASE) for name in names):
            raise BuildError("controller_inspection_failed")
        imports = {name.lower() for name in names}
        if not imports or len(imports) > 128:
            raise BuildError("controller_imports_missing")
        for name in imports:
            if name.startswith(("api-ms-win-", "ext-ms-win-")):
                continue
            if name not in PLATFORM_DLLS:
                raise BuildError("controller_dependency_forbidden:" + name)
            if not (system / name).is_file():
                raise BuildError("controller_dependency_missing:" + name)
            regular(system / name)
        # An unknown command reaches only the bounded error receipt, never installer filesystem work.
        probe = subprocess.run([str(binary), "--controller-dependency-probe"],
                               cwd=system, env=env, stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=30, check=False)
        if probe.returncode != 1 or probe.stderr or len(probe.stdout) > 4096:
            raise BuildError("controller_entrypoint_failed")
        try:
            receipt = json.loads(probe.stdout)
        except (ValueError, UnicodeError):
            raise BuildError("controller_entrypoint_failed") from None
        if receipt != {"protocolVersion": 1, "state": "failed", "code": "host_control_arguments_invalid"}:
            raise BuildError("controller_entrypoint_failed")
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        raise BuildError("controller_inspection_or_launch_failed") from None
    return {"schemaVersion": 1, "controllerSha256": sha256(binary),
            "inspectorSha256": sha256(inspector), "imports": sorted(imports),
            "systemOnlyDependencies": True, "sanitizedEntrypointQualified": True,
            "installedPlatformQualified": False, "uacQualified": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("inspector", type=Path)
    options = parser.parse_args()
    try:
        print(json.dumps(qualify(options.binary, options.inspector), sort_keys=True))
    except (BuildError, OSError) as error:
        parser.exit(1, (str(error) if isinstance(error, BuildError) else "controller_qualification_failed") + "\n")
