#!/usr/bin/env python3
"""Fail when a bundled macOS binary needs a newer macOS than the app declares.

Reads `bundle.macOS.minimumSystemVersion` from tauri.conf.json and the minimum
macOS version recorded in every Mach-O file under the given paths
(LC_BUILD_VERSION, or LC_VERSION_MIN_MACOSX in older binaries). The files are
parsed directly, so the check also runs where Xcode's vtool is not installed.
"""
import argparse
import json
import plistlib
import struct
import sys
from pathlib import Path

THIN = {
    b"\xfe\xed\xfa\xce": (">", 28),
    b"\xce\xfa\xed\xfe": ("<", 28),
    b"\xfe\xed\xfa\xcf": (">", 32),
    b"\xcf\xfa\xed\xfe": ("<", 32),
}
FAT = {b"\xca\xfe\xba\xbe": ">IIIII", b"\xca\xfe\xba\xbf": ">IIQQII"}
LC_VERSION_MIN_MACOSX = 0x24
LC_BUILD_VERSION = 0x32
PLATFORM_MACOS = 1
# Executables, dynamic libraries and loadable bundles are what macOS refuses to load when too new.
LOADED_FILE_TYPES = {2, 6, 8}
MAX_HEADER = 1 << 20


def parse_version(text):
    """`11.0` or `10.13.4` as a comparable tuple; anything else is rejected."""
    parts = text.split(".") if isinstance(text, str) else []
    if not 2 <= len(parts) <= 3 or not all(part.isascii() and part.isdigit() for part in parts):
        raise ValueError(f"not a macOS version: {text!r}")
    return tuple(int(part) for part in parts) + (0,) * (3 - len(parts))


def format_version(version):
    return ".".join(str(part) for part in (version if version[2] else version[:2]))


def _slice_minimum(data):
    """(loaded, minimum) for one thin Mach-O image; minimum is None when it records none."""
    order, header = THIN[data[:4]]
    if len(data) < header:
        raise ValueError("truncated Mach-O header")
    file_type, count, size = struct.unpack_from(order + "III", data, 12)
    if header + size > len(data):
        raise ValueError("truncated Mach-O load commands")
    minimum = None
    offset = header
    for _ in range(count):
        if offset + 8 > header + size:
            raise ValueError("load command outside the header")
        command, length = struct.unpack_from(order + "II", data, offset)
        if length < 8 or offset + length > header + size:
            raise ValueError("invalid load command size")
        packed = None
        if command == LC_BUILD_VERSION and length >= 16:
            platform, value = struct.unpack_from(order + "II", data, offset + 8)
            if platform == PLATFORM_MACOS:
                packed = value
        elif command == LC_VERSION_MIN_MACOSX and length >= 12:
            packed = struct.unpack_from(order + "I", data, offset + 8)[0]
        if packed is not None:
            version = (packed >> 16, (packed >> 8) & 0xFF, packed & 0xFF)
            minimum = version if minimum is None else max(minimum, version)
        offset += length
    return file_type in LOADED_FILE_TYPES, minimum


def macho_minimums(path):
    """[(loaded, minimum)] per architecture, or None when the file is not Mach-O."""
    with open(path, "rb") as handle:
        magic = handle.read(4)
        if magic in THIN:
            handle.seek(0)
            return [_slice_minimum(handle.read(MAX_HEADER))]
        if magic not in FAT:
            return None
        layout = FAT[magic]
        entry = struct.calcsize(layout)
        (count,) = struct.unpack(">I", handle.read(4))
        # Java class files share the fat magic; no real fat binary has this many architectures.
        if not 0 < count <= 16:
            return None
        table = handle.read(count * entry)
        if len(table) != count * entry:
            raise ValueError("truncated fat header")
        slices = []
        for index in range(count):
            offset = struct.unpack_from(layout, table, index * entry)[2]
            handle.seek(offset)
            image = handle.read(MAX_HEADER)
            if image[:4] not in THIN:
                raise ValueError("fat slice is not Mach-O")
            slices.append(_slice_minimum(image))
        return slices


def scan(roots):
    """(found, unknown, unreadable): {path: minimum}, loaded binaries with no minimum, parse failures."""
    found, unknown, unreadable = {}, [], []
    for root in roots:
        root = Path(root)
        if not root.exists():
            raise FileNotFoundError(root)
        files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink())
        for path in files:
            try:
                slices = macho_minimums(path)
            except (OSError, ValueError, struct.error) as error:
                unreadable.append((path, str(error)))
                continue
            if slices is None:
                continue
            versions = [minimum for _, minimum in slices if minimum is not None]
            if versions:
                found[path] = max(versions)
            if any(loaded and minimum is None for loaded, minimum in slices):
                unknown.append(path)
    return found, unknown, unreadable


def declared_minimum(config):
    value = json.loads(Path(config).read_text(encoding="utf-8")).get("bundle", {}).get("macOS", {}).get("minimumSystemVersion")
    if value is None:
        raise ValueError(f"{config} declares no bundle.macOS.minimumSystemVersion")
    return parse_version(value)


def bundle_minimums(roots):
    """{Info.plist: LSMinimumSystemVersion or None} for every app bundle given as a path."""
    declared = {}
    for root in roots:
        plist = Path(root) / "Contents" / "Info.plist"
        if plist.is_file():
            with open(plist, "rb") as handle:
                declared[plist] = plistlib.load(handle).get("LSMinimumSystemVersion")
    return declared


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+", help="app bundles, runtime folders or single binaries")
    parser.add_argument("--config", default=str(Path(__file__).resolve().parent.parent / "src-tauri" / "tauri.conf.json"))
    parser.add_argument("--deployment-target", help="also require this value (MACOSX_DEPLOYMENT_TARGET) to equal the declared minimum")
    options = parser.parse_args(arguments)
    try:
        declared = declared_minimum(options.config)
        target = parse_version(options.deployment_target) if options.deployment_target is not None else declared
        found, unknown, unreadable = scan(options.paths)
        bundles = {plist: None if value is None else parse_version(value) for plist, value in bundle_minimums(options.paths).items()}
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        print(f"macOS minimum check could not run: {error}", file=sys.stderr)
        return 2
    failed = False
    if target != declared:
        print(f"MACOSX_DEPLOYMENT_TARGET {format_version(target)} differs from the declared minimum {format_version(declared)}", file=sys.stderr)
        failed = True
    # macOS reads the bundle's own value, so a build that dropped or changed it is refused here.
    for plist, value in bundles.items():
        if value != declared:
            print(f"{plist} declares macOS {format_version(value) if value else 'no minimum'}, expected {format_version(declared)}", file=sys.stderr)
            failed = True
    for path, minimum in sorted(found.items()):
        if minimum > declared:
            print(f"{path} requires macOS {format_version(minimum)}, newer than the declared {format_version(declared)}", file=sys.stderr)
            failed = True
    # A binary whose requirement cannot be read is not known to run on the declared minimum.
    for path in unknown:
        print(f"{path} records no minimum macOS version", file=sys.stderr)
        failed = True
    for path, reason in unreadable:
        print(f"{path} could not be read as Mach-O: {reason}", file=sys.stderr)
        failed = True
    if not found and not failed:
        print("No Mach-O binaries were found to check", file=sys.stderr)
        return 2
    if failed:
        return 1
    highest = max(found.values())
    print(f"{len(found)} Mach-O files checked; highest requirement macOS {format_version(highest)}, declared minimum {format_version(declared)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
