"""Stage a private ELF dependency closure; platform glibc remains external."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import unicodedata
from pathlib import Path

from build_runtime import BuildError, relative, sha256

PLATFORM_LIBRARIES = {
    "libc.so.6",
    "libm.so.6",
    "libdl.so.2",
    "libpthread.so.0",
    "librt.so.1",
    "libresolv.so.2",
    "libutil.so.1",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
}


def elf_architecture(header: bytes) -> str:
    if len(header) < 64 or header[:7] != b"\x7fELF\x02\x01\x01":
        raise BuildError("host_elf_header_unsupported")
    kind, machine = struct.unpack_from("<HH", header, 16)
    if kind not in {2, 3} or machine not in {62, 183}:
        raise BuildError("host_elf_header_unsupported")
    return {62: "x86_64", 183: "aarch64"}[machine]


def dynamic(text: str) -> tuple[list[str], list[str]]:
    needed, search = [], {}
    for line in text.splitlines():
        tag = re.search(r"\(([^)]+)\)", line)
        if not tag:
            continue
        tag = tag[1]
        if tag in {"AUDIT", "DEPAUDIT", "FILTER", "AUXILIARY"}:
            raise BuildError("host_elf_loader_feature_unsupported")
        if tag not in {"NEEDED", "RPATH", "RUNPATH"}:
            continue
        value = re.search(r"\[([^\]]*)\]\s*$", line)
        if not value:
            raise BuildError("host_elf_dynamic_invalid")
        if tag == "NEEDED":
            if not re.fullmatch(r"[A-Za-z0-9_.+-]+", value[1]):
                raise BuildError("host_elf_dependency_invalid")
            needed.append(value[1])
        else:
            if tag in search or not all(value[1].split(":")):
                raise BuildError("host_elf_search_path_invalid")
            search[tag] = value[1].split(":")
    if "RPATH" in search and "RUNPATH" in search:
        raise BuildError("host_elf_search_path_ambiguous")
    return needed, search.get("RUNPATH", search.get("RPATH", []))


def search_directories(loader: Path, paths: list[str]) -> list[Path]:
    directories = []
    for path in paths:
        expanded = re.sub(
            r"\$(?:\{ORIGIN\}|ORIGIN(?=/|$))", lambda _: str(loader.parent), path
        )
        if "$" in expanded or not Path(expanded).is_absolute():
            raise BuildError("host_elf_search_path_unsupported")
        directories.append(Path(expanded))
    return directories


def resolve_dependency(
    reference: str, loader: Path, paths: list[str], library_dirs: list[Path]
) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", reference):
        raise BuildError("host_elf_dependency_invalid")
    for directory in [*search_directories(loader, paths), *library_dirs]:
        candidate = directory / reference
        if candidate.is_file():
            return candidate.resolve(strict=True)
    raise BuildError("host_elf_dependency_missing:" + reference)


def closure(entries: dict[str, Path], library_dirs: list[Path], output: Path) -> dict:
    if platform.system() != "Linux" or platform.machine() not in {"aarch64", "x86_64"}:
        raise BuildError("host_elf_target_unsupported")
    if (
        not output.is_absolute()
        or output.exists()
        or output.is_symlink()
        or not entries
    ):
        raise BuildError("host_elf_output_invalid")
    if any(not path.is_absolute() or not path.is_dir() for path in library_dirs):
        raise BuildError("host_elf_library_directory_invalid")
    tools = {name: shutil.which(name) for name in ["readelf", "patchelf"]}
    if not all(tools.values()):
        raise BuildError("host_elf_tools_missing")

    def run(args: list) -> str:
        result = subprocess.run(
            [str(arg) for arg in args],
            env={"PATH": os.defpath, "LC_ALL": "C"},
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode:
            if output.is_dir():
                (output / "linkage-error.log").write_text(result.stderr[-65536:])
            raise BuildError("host_elf_tool_failed:" + Path(args[0]).name)
        return result.stdout

    roots, names = {}, set()
    for name, source in entries.items():
        relative(name)
        folded = unicodedata.normalize("NFC", name).casefold()
        if (
            folded.split("/")[0]
            in {
                "libraries",
                "receipt.json",
                "linkage-receipt.json",
                "linkage-error.log",
            }
            or folded in names
            or not source.is_absolute()
        ):
            raise BuildError("host_elf_entry_invalid")
        names.add(folded)
        source = source.resolve(strict=True)
        if not source.is_file() or source in roots:
            raise BuildError("host_elf_entry_invalid")
        roots[source] = name
    if any(a != b and b.startswith(a + "/") for a in names for b in names):
        raise BuildError("host_elf_entry_invalid")

    objects, visited, pending = {}, set(), [(source, ()) for source in roots]
    while pending:
        source, inherited = pending.pop()
        context = (source, inherited)
        if context in visited:
            continue
        if len(visited) >= 4096:
            raise BuildError("host_elf_graph_limit")
        visited.add(context)
        if (
            source not in objects and len(objects) >= 512
        ) or source.stat().st_size > 2 * 1024**3:
            raise BuildError("host_elf_graph_limit")
        with source.open("rb") as stream:
            if elf_architecture(stream.read(64)) != platform.machine():
                raise BuildError("host_elf_architecture_mismatch")
        program = run([tools["readelf"], "-lW", source])
        interpreters = re.findall(r"\[Requesting program interpreter: (.+)\]", program)
        expected_interpreter = {
            "aarch64": "/lib/ld-linux-aarch64.so.1",
            "x86_64": "/lib64/ld-linux-x86-64.so.2",
        }[platform.machine()]
        if interpreters and interpreters != [expected_interpreter]:
            raise BuildError("host_elf_interpreter_unsupported")
        raw_dynamic = run([tools["readelf"], "-dW", source])
        needed, paths = dynamic(raw_dynamic)
        own = search_directories(source, paths)
        # RPATH is inherited; RUNPATH applies only to this object's direct dependencies.
        runpath = bool(re.search(r"\(RUNPATH\)", raw_dynamic))
        search = own if runpath else list(dict.fromkeys([*own, *inherited]))
        child_paths = tuple(dict.fromkeys([*([] if runpath else own), *inherited]))
        dependencies = {
            name: resolve_dependency(name, source, [], [*search, *library_dirs])
            for name in needed
            if name not in PLATFORM_LIBRARIES
        }
        if source in objects:
            if objects[source]["dependencies"] != dependencies:
                raise BuildError("host_elf_loader_context_ambiguous")
            pending.extend(
                (dependency, child_paths) for dependency in dependencies.values()
            )
            continue
        digest = sha256(source)
        name = roots.get(
            source, f"libraries/{len(objects):03d}-{digest[:16]}/" + source.name
        )
        relative(name)
        objects[source] = {
            "path": name,
            "mode": source.stat().st_mode & 0o777,
            "sourceSha256": digest,
            "needed": needed,
            "sourceSearchPaths": paths,
            "dependencies": dependencies,
        }
        pending.extend(
            (dependency, child_paths) for dependency in dependencies.values()
        )

    output.mkdir(mode=0o700)
    for source, item in objects.items():
        destination = output / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        if sha256(destination) != item["sourceSha256"]:
            raise BuildError("host_elf_source_changed")
        destination.chmod(item["mode"] | 0o200)
    for item in objects.values():
        destination = output / item["path"]
        search = []
        for reference, dependency in item["dependencies"].items():
            target = output / objects[dependency]["path"]
            run(
                [
                    tools["patchelf"],
                    "--replace-needed",
                    reference,
                    target.name,
                    destination,
                ]
            )
            search.append(
                "$ORIGIN/" + os.path.relpath(target.parent, destination.parent)
            )
        if search:
            run(
                [
                    tools["patchelf"],
                    "--set-rpath",
                    ":".join(dict.fromkeys(search)),
                    destination,
                ]
            )
        elif item["sourceSearchPaths"]:
            run([tools["patchelf"], "--remove-rpath", destination])
        destination.chmod(item["mode"])

    report = {
        "schemaVersion": 1,
        "platform": "linux-" + platform.machine(),
        "scope": "ELF DT_NEEDED closure only; platform glibc external",
        "qualification": "failed",
        "redistributable": False,
        "dynamicLoadingQualified": False,
        "objects": {},
    }
    for item in objects.values():
        destination = output / item["path"]
        needed, paths = dynamic(run([tools["readelf"], "-dW", destination]))
        expected = {
            reference: output / objects[dependency]["path"]
            for reference, dependency in item["dependencies"].items()
        }
        expected_needed = [
            expected[name].name if name in expected else name for name in item["needed"]
        ]
        if needed != expected_needed or any(
            not path.startswith("$ORIGIN/") for path in paths
        ):
            raise BuildError("host_elf_external_reference_remaining")
        for target in expected.values():
            resolved = resolve_dependency(target.name, destination, paths, [])
            if resolved != target or not resolved.is_relative_to(output):
                raise BuildError("host_elf_external_reference_remaining")
        report["objects"][item["path"]] = {
            "sourceSha256": item["sourceSha256"],
            "sha256": sha256(destination),
            "bytes": destination.stat().st_size,
            "needed": needed,
            "runpath": paths,
        }
    report["qualification"] = "passed"
    (output / "linkage-receipt.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=Path, required=True)
    parser.add_argument("--library-dir", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    try:
        entries = json.loads(options.entries.read_text())
        if not isinstance(entries, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in entries.items()
        ):
            raise BuildError("host_elf_entries_invalid")
        receipt = closure(
            {k: Path(v) for k, v in entries.items()},
            options.library_dir,
            options.output,
        )
        print(
            json.dumps(
                {
                    "qualification": receipt["qualification"],
                    "objects": len(receipt["objects"]),
                    "redistributable": False,
                }
            )
        )
    except (BuildError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        parser.exit(
            1, str(error) if isinstance(error, BuildError) else "host_elf_failed"
        )
