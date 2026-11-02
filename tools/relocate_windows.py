"""Stage an audited x64 PE dependency closure without a build-toolchain runtime."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from build_host_database_windows import SYSTEM_DLLS
from build_runtime import BuildError, regular, relative, sha256

PLATFORM_DLLS = SYSTEM_DLLS | {
    "comctl32.dll",
    "credui.dll", "dwmapi.dll", "dwrite.dll", "gdiplus.dll", "glu32.dll", "hid.dll", "imm32.dll",
    "msimg32.dll", "opengl32.dll", "propsys.dll", "shcore.dll", "urlmon.dll",
    "usp10.dll", "uxtheme.dll", "winhttp.dll", "wininet.dll", "winspool.drv",
    "wldap32.dll", "wsock32.dll",
}


def inspect_pe(tool: Path, source: Path, *, cwd: Path, env: dict[str, str]) -> str:
    try:
        result = subprocess.run([tool, "-p", source], cwd=cwd, env=env,
                                text=True, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BuildError("host_pe_inspection_failed") from error
    # Require a clean inspection before trusting a potentially partial listing.
    if result.returncode or result.stderr.strip():
        if error_log := env.get("FRAMELEAF_BUILD_ERROR_LOG"):
            Path(error_log).write_text((result.stderr or result.stdout)[-32768:], encoding="utf-8")
        raise BuildError("host_pe_inspection_failed")
    listed = [line.split("DLL Name:", 1)[1].strip().casefold()
              for line in result.stdout.splitlines() if "DLL Name:" in line]
    if sorted(listed) != sorted(_import_names(source)):
        raise BuildError("host_pe_imports_missing")
    return result.stdout.strip()


def _import_names(source: Path) -> list[str]:
    """Bound import descriptors to file-backed sections independently of objdump output."""
    try:
        with source.open("rb") as stream:
            size = stream.seek(0, 2)
            stream.seek(0)
            header = stream.read(69656)
            if not pe_imports(header):
                return []
            pe = int.from_bytes(header[60:64], "little")
            count = int.from_bytes(header[pe + 6:pe + 8], "little")
            optional = pe + 24
            table = optional + int.from_bytes(header[pe + 20:pe + 22], "little")
            if not 1 <= count <= 96 or table + count * 40 > size:
                raise ValueError("invalid sections")
            stream.seek(table)
            sections = []
            for _ in range(count):
                entry = stream.read(40)
                if len(entry) != 40:
                    raise ValueError("truncated section")
                address = int.from_bytes(entry[12:16], "little")
                length = int.from_bytes(entry[16:20], "little")
                offset = int.from_bytes(entry[20:24], "little")
                if offset + length > size or address + length > 2**32:
                    raise ValueError("section outside file")
                sections.append((address, length, offset))
            def location(address, length):
                matches = [(offset + address - start, size - (address - start))
                           for start, size, offset in sections
                           if start <= address and address - start + length <= size]
                if len(matches) != 1:
                    raise ValueError("import outside a unique file-backed section")
                return matches[0]
            address = int.from_bytes(header[optional + 120:optional + 124], "little")
            length = int.from_bytes(header[optional + 124:optional + 128], "little")
            location(address, length)
            names = []
            for index in range(min(length // 20, 513)):
                offset, _ = location(address + index * 20, 20)
                stream.seek(offset)
                descriptor = stream.read(20)
                if len(descriptor) != 20:
                    raise ValueError("truncated import descriptor")
                if descriptor == b"\0" * 20:
                    return names
                name = int.from_bytes(descriptor[12:16], "little")
                offset, available = location(name, 1)
                stream.seek(offset)
                encoded = stream.read(min(available, 260))
                end = encoded.find(b"\0")
                if end < 0:
                    raise ValueError("unterminated import name")
                reference = encoded[:end].decode("ascii")
                if not re.fullmatch(r"[A-Za-z0-9_.+-]+\.(?:dll|drv)", reference, re.IGNORECASE):
                    raise ValueError("invalid import name")
                names.append(reference.casefold())
            raise ValueError("unterminated import descriptors")
    except (OSError, ValueError) as error:
        raise BuildError("host_pe_dependency_invalid") from error


def pe_imports(data: bytes) -> bool:
    if len(data) < 64 or data[:2] != b"MZ":
        raise BuildError("host_pe_header_unsupported")
    offset = int.from_bytes(data[60:64], "little")
    if not 64 <= offset <= 65536 or len(data) < offset + 24:
        raise BuildError("host_pe_header_unsupported")
    header = data[offset:offset + 24]
    size = int.from_bytes(header[20:22], "little")
    optional = data[offset + 24:offset + 24 + size]
    count = int.from_bytes(optional[108:112], "little")
    if (header[:6] != b"PE\0\0\x64\x86" or not int.from_bytes(header[22:24], "little") & 2
            or not 128 <= size <= 4096 or len(optional) != size or optional[:2] != b"\x0b\x02"
            or not 2 <= count <= 16 or len(optional) < 112 + count * 8):
        raise BuildError("host_pe_header_unsupported")
    if count >= 14 and optional[216:224] != b"\0" * 8:
        raise BuildError("host_pe_delay_imports_unsupported")
    address = int.from_bytes(optional[120:124], "little")
    length = int.from_bytes(optional[124:128], "little")
    if bool(address) != bool(length):
        raise BuildError("host_pe_import_directory_invalid")
    if not address and (optional[4:8] != b"\0" * 4 or optional[16:20] != b"\0" * 4):
        raise BuildError("host_pe_imports_missing")
    return bool(address)


def closure(entries: dict[str, Path], library_dirs: list[Path], output: Path, inspect) -> dict:
    if not output.is_absolute() or output.exists() or output.is_symlink() or not entries:
        raise BuildError("host_pe_output_invalid")
    if any(not p.is_absolute() or not p.is_dir() for p in library_dirs):
        raise BuildError("host_pe_library_directory_invalid")
    pending, targets, objects, system = [], {}, {}, set()

    def enqueue(name: str, source: Path) -> None:
        relative(name)
        if Path(name).name.casefold() in {"msys-2.0.dll", "cygwin1.dll"}:
            raise BuildError("host_pe_posix_runtime_forbidden")
        if not source.is_absolute():
            raise BuildError("host_pe_source_invalid")
        regular(source)
        folded = name.casefold()
        if folded in targets:
            previous_name, previous_source = targets[folded]
            if previous_name != name or sha256(previous_source) != sha256(source):
                raise BuildError("host_pe_output_collision")
            return
        if len(targets) >= 512:
            raise BuildError("host_pe_inventory_limit")
        targets[folded] = (name, source)
        pending.append((name, source))

    for name, source in entries.items():
        enqueue(name, source)
    output.mkdir(mode=0o700)
    while pending:
        name, source = pending.pop()
        with source.open("rb") as stream:
            has_imports = pe_imports(stream.read(69656))
        text = inspect(source)
        imports = []
        for line in text.splitlines():
            if "DLL Name:" not in line:
                continue
            reference = line.split("DLL Name:", 1)[1].strip()
            if not re.fullmatch(r"[A-Za-z0-9_.+-]+\.(?:dll|drv)", reference, re.IGNORECASE):
                raise BuildError("host_pe_dependency_invalid")
            folded = reference.casefold()
            if folded in {"msys-2.0.dll", "cygwin1.dll"}:
                raise BuildError("host_pe_posix_runtime_forbidden")
            imports.append(folded)
            if folded in PLATFORM_DLLS or folded.startswith(("api-ms-win-", "ext-ms-win-")):
                system.add(folded)
                continue
            candidates = []
            for directory in dict.fromkeys([source.parent, *library_dirs]):
                for candidate in directory.iterdir():
                    if candidate.name.casefold() == folded:
                        regular(candidate)
                        candidates.append(candidate)
            if not candidates:
                raise BuildError("host_pe_dependency_missing:" + reference)
            if len({sha256(candidate) for candidate in candidates}) != 1:
                raise BuildError("host_pe_dependency_ambiguous:" + reference)
            dependency = candidates[0]
            target = targets.get("bin/" + folded)
            enqueue(target[0] if target else "bin/" + dependency.name, dependency)
        if has_imports != bool(imports):
            raise BuildError("host_pe_imports_missing")
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        objects[name] = {"sha256": sha256(destination), "imports": imports}
    return {"objects": objects, "systemLibraries": sorted(system), "posixRuntimeRequired": False}
