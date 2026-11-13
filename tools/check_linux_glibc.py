#!/usr/bin/env python3
"""Fail when a shipped Linux binary needs a newer C library than the oldest supported distribution has.

    check_linux_glibc.py [--max 2.35] [--report-only] PATH...

Each PATH is an ELF file, a directory searched for ELF files, or a `.deb` whose contents are
searched. A binary records the newest `GLIBC_x.y` symbol version it needs; a system whose glibc is
older refuses to load it ("version `GLIBC_2.39' not found"). Ubuntu 22.04 has glibc 2.35 and
Debian 12 has 2.36, so the default limit is 2.35. The requirement comes from the machine the binary
was linked on, which is why the Linux build jobs run on Ubuntu 22.04.

`--report-only` prints the same findings and always exits 0.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_MAXIMUM = "2.35"
NEED = re.compile(r"\bName: GLIBC_(\d+(?:\.\d+)+)\b")


def parse_version(text: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\d+(?:\.\d+)+", text):
        raise ValueError(f"not a glibc version: {text!r}")
    return tuple(int(part) for part in text.split("."))


def show(version: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version)


def needed_versions(version_info: str) -> set[tuple[int, ...]]:
    """The GLIBC versions in the "Version needs" sections of `readelf --version-info --wide` output.

    Versions a library defines itself (its "Version definition" section) are not requirements.
    """
    found: set[tuple[int, ...]] = set()
    needs = False
    for line in version_info.splitlines():
        if line.startswith("Version needs section"):
            needs = True
        elif line.startswith(("Version definition section", "Version symbols section")) or not line.strip():
            needs = False
        elif needs:
            found.update(parse_version(match) for match in NEED.findall(line))
    return found


def is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as file:
            return file.read(4) == b"\x7fELF"
    except OSError:
        return False


def elf_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if is_elf(root) else []
    return sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink() and is_elf(path))


def read_version_info(path: Path) -> str:
    result = subprocess.run(["readelf", "--version-info", "--wide", str(path)], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"readelf could not read {path}: {result.stderr.strip()}")
    return result.stdout


def measure(roots: list[Path], read=None) -> dict[str, tuple[int, ...]]:
    """The newest GLIBC version each ELF file under `roots` needs; files that need none are left out."""
    read = read or read_version_info
    measured: dict[str, tuple[int, ...]] = {}
    for root in roots:
        if not root.exists():
            raise FileNotFoundError(f"{root} does not exist")
        files = elf_files(root)
        if not files:
            raise FileNotFoundError(f"{root} holds no ELF file")
        for path in files:
            versions = needed_versions(read(path))
            if versions:
                measured[str(path.relative_to(root)) if root.is_dir() else path.name] = max(versions)
    return measured


def too_new(measured: dict[str, tuple[int, ...]], maximum: tuple[int, ...]) -> dict[str, tuple[int, ...]]:
    return {name: version for name, version in measured.items() if version > maximum}


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--max", default=DEFAULT_MAXIMUM, help="the newest glibc a binary may need (default %(default)s)")
    parser.add_argument("--report-only", action="store_true", help="print the findings without failing")
    parser.add_argument("paths", nargs="+", type=Path)
    options = parser.parse_args(arguments)
    maximum = parse_version(options.max)
    with tempfile.TemporaryDirectory(prefix="frameleaf-glibc-") as scratch:
        roots: list[Path] = []
        for index, path in enumerate(options.paths):
            if path.suffix == ".deb" and path.is_file():
                extracted = Path(scratch) / str(index)
                subprocess.run(["dpkg-deb", "--extract", str(path), str(extracted)], check=True)
                roots.append(extracted)
            else:
                roots.append(path)
        measured = measure(roots)
    highest = max(measured.values(), default=None)
    print(f"{len(measured)} ELF files need glibc; the newest version needed is {show(highest) if highest else 'none'} (limit {show(maximum)}).")
    failures = too_new(measured, maximum)
    for name, version in sorted(failures.items()):
        print(f"{'::warning::' if options.report_only else '::error::'}{name} needs GLIBC_{show(version)}, newer than {show(maximum)}")
    if failures and not options.report_only:
        print(f"Build on a machine whose glibc is {show(maximum)} or older (Ubuntu 22.04).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
