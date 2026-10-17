"""Materialize a private browser into a link-free host component; does not sign it."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
from pathlib import Path

from build_runtime import BuildError, inventory, regular, relative


def stage_browser(source: Path, destination: Path, executable: str) -> dict:
    if (
        not source.is_absolute()
        or not destination.is_absolute()
        or not stat.S_ISDIR(regular(source).st_mode)
        or destination.exists()
        or destination.is_symlink()
        or destination.resolve().is_relative_to(source.resolve())
    ):
        raise BuildError("host_browser_paths_invalid")
    root = source.resolve(strict=True)
    entry = source / relative(executable)
    if not entry.is_file() or (os.name != "nt" and not os.access(entry, os.X_OK)):
        raise BuildError("host_browser_entry_invalid")
    entries = []
    total = 0

    def inspect(path: Path, ancestors: set[Path]) -> None:
        nonlocal total
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise BuildError("host_browser_link_escape")
        if resolved in ancestors:
            raise BuildError("host_browser_link_cycle")
        mode = regular(resolved).st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise BuildError("host_browser_special_file_forbidden")
        name = relative(path.relative_to(source).as_posix())
        entries.append((name, resolved, mode))
        if len(entries) > 100_000:
            raise BuildError("host_browser_inventory_limit")
        if stat.S_ISDIR(mode):
            for child in sorted(path.iterdir()):
                inspect(child, ancestors | {resolved})
        else:
            size = resolved.stat().st_size
            total += size
            if size > 16 * 1024**3 or total > 64 * 1024**3:
                raise BuildError("host_browser_size_invalid")

    for path in sorted(source.iterdir()):
        inspect(path, {root})
    destination.mkdir(mode=0o700)
    for name, resolved, mode in entries:
        target = destination / name
        if stat.S_ISDIR(mode):
            target.mkdir()
        else:
            shutil.copy2(resolved, target)
    return inventory(destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source", "destination", "executable", "receipt"]:
        parser.add_argument("--" + name, required=True)
    options = parser.parse_args()
    try:
        source, destination, receipt = map(
            Path, [options.source, options.destination, options.receipt]
        )
        if (
            not receipt.is_absolute()
            or receipt.exists()
            or receipt.is_symlink()
            or receipt.resolve().is_relative_to(source.resolve())
            or receipt.resolve().is_relative_to(destination.resolve())
        ):
            raise BuildError("host_browser_receipt_invalid")
        files = stage_browser(source, destination, options.executable)
        receipt.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "executable": options.executable,
                    "files": files,
                    "runtimeQualified": False,
                    "redistributable": False,
                    "scope": "Link-free browser component; OS signing and runtime qualification required",
                },
                indent=2,
            )
            + "\n"
        )
    except (BuildError, OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")
