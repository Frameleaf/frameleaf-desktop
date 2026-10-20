"""Stage an audited x64 PE dependency closure without a build-toolchain runtime."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from build_host_database_windows import SYSTEM_DLLS
from build_runtime import BuildError, regular, relative, sha256

PLATFORM_DLLS = SYSTEM_DLLS | {
    # Cloud Files and Windows Runtime APIs ship with the supported Windows desktop OS.
    "cldapi.dll", "combase.dll",
    "avicap32.dll", "cfgmgr32.dll",
    "bthprops.cpl", "d3d11.dll", "d3d12.dll", "dcomp.dll", "dhcpcsvc.dll", "dxgi.dll",
    "mf.dll", "mfplat.dll", "mfreadwrite.dll", "mmdevapi.dll", "oleacc.dll", "pdh.dll",
    "tbs.dll", "uiautomationcore.dll", "winusb.dll",
    "comctl32.dll",
    "credui.dll", "dwmapi.dll", "dwrite.dll", "gdiplus.dll", "glu32.dll", "hid.dll", "imm32.dll",
    "msimg32.dll", "opengl32.dll", "propsys.dll", "shcore.dll", "urlmon.dll",
    "usp10.dll", "uxtheme.dll", "winhttp.dll", "wininet.dll", "winspool.drv",
    "wldap32.dll", "wsock32.dll",
}


def pe_imports(data: bytes, *, allow_delay: bool = False) -> bool:
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
    delayed_address = int.from_bytes(optional[216:220], "little") if count >= 14 else 0
    delayed_length = int.from_bytes(optional[220:224], "little") if count >= 14 else 0
    if bool(delayed_address) != bool(delayed_length):
        raise BuildError("host_pe_import_directory_invalid")
    if delayed_address and not allow_delay:
        raise BuildError("host_pe_delay_imports_unsupported")
    address = int.from_bytes(optional[120:124], "little")
    length = int.from_bytes(optional[124:128], "little")
    if bool(address) != bool(length):
        raise BuildError("host_pe_import_directory_invalid")
    if not (address or delayed_address) and (optional[4:8] != b"\0" * 4 or optional[16:20] != b"\0" * 4):
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
            header = stream.read(69656)
        has_imports = pe_imports(header, allow_delay=True)
        optional = int.from_bytes(header[60:64], "little") + 24
        has_delayed = (int.from_bytes(header[optional + 108:optional + 112], "little") >= 14
                       and header[optional + 216:optional + 224] != b"\0" * 8)
        text = inspect(source)
        # LLVM readobj exposes delayed imports that objdump's private headers omit.
        for kind, reference in re.findall(r"(?m)^(Import|DelayImport) \{\r?\n  Name: ([^\r\n]+)", text):
            text += "\n" + ("Delay DLL Name: " if kind == "DelayImport" else "DLL Name: ") + reference
        imports, normal_imports, delayed_imports = [], [], []
        for line in text.splitlines():
            if "DLL Name:" not in line:
                continue
            reference = line.split("DLL Name:", 1)[1].strip()
            folded = reference.casefold()
            # Bluetooth's known Windows system module has a CPL suffix.
            if folded not in PLATFORM_DLLS and not re.fullmatch(r"[A-Za-z0-9_.+-]+\.(?:dll|drv|exe)", reference, re.IGNORECASE):
                raise BuildError("host_pe_dependency_invalid")
            if folded in {"msys-2.0.dll", "cygwin1.dll"}:
                raise BuildError("host_pe_posix_runtime_forbidden")
            imports.append(folded)
            (delayed_imports if "Delay DLL Name:" in line else normal_imports).append(folded)
            if folded.endswith(".exe"):
                # Node add-ons import their host executable; never discover it in DLL search paths.
                approved = [(n, p) for n, p in entries.items() if Path(n).name.casefold() == folded]
                if len(approved) != 1:
                    raise BuildError("host_pe_executable_import_unapproved:" + reference)
                enqueue(*approved[0])
                continue
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
        if has_imports != bool(normal_imports) or has_delayed != bool(delayed_imports):
            raise BuildError("host_pe_imports_missing")
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        objects[name] = {"sha256": sha256(destination), "imports": imports, "delayImports": delayed_imports}
    return {"objects": objects, "systemLibraries": sorted(system), "posixRuntimeRequired": False}
