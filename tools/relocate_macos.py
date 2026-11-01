"""Copy a thin Mach-O dependency graph into a new private payload; authoring only."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import unicodedata
from pathlib import Path

from build_runtime import BuildError, relative, sha256


def load_commands(text: str) -> tuple[str | None, list[str], list[str]]:
    identity, dependencies, paths = None, [], []
    command = ""
    library_commands = {
        "LC_LOAD_DYLIB",
        "LC_LOAD_WEAK_DYLIB",
        "LC_REEXPORT_DYLIB",
        "LC_LOAD_UPWARD_DYLIB",
        "LC_LAZY_LOAD_DYLIB",
    }
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("cmd "):
            command = line[4:]
            if command == "LC_DYLD_ENVIRONMENT":
                raise BuildError("host_linkage_environment_forbidden")
        match = re.fullmatch(r"(?:name|path) (.+) \(offset \d+\)", line)
        if not match:
            continue
        value = match[1]
        if command == "LC_ID_DYLIB":
            if identity is not None:
                raise BuildError("host_linkage_identity_ambiguous")
            identity = value
        elif command in library_commands:
            dependencies.append(value)
        elif command == "LC_RPATH":
            paths.append(value)
    return identity, dependencies, paths


def apple_library(reference: str) -> bool:
    return (
        reference.startswith(("/usr/lib/", "/System/Library/"))
        and ".." not in Path(reference).parts
    )


def resolve_dependency(reference: str, loader: Path, paths: list[str]) -> Path:
    def expand(value: str) -> Path:
        if value.startswith("@loader_path/"):
            return loader.parent / value[len("@loader_path/") :]
        if value.startswith("/"):
            return Path(value)
        # A shared graph has no single executable-relative or inherited-rpath authority.
        raise BuildError("host_linkage_reference_unsupported")

    if reference.startswith("@rpath/"):
        candidates = {
            expand(path + "/" + reference[len("@rpath/") :]).resolve() for path in paths
        }
    else:
        candidates = {expand(reference).resolve()}
    found = {path for path in candidates if path.is_file()}
    if len(found) != 1:
        raise BuildError("host_linkage_dependency_ambiguous_or_missing")
    return found.pop()


def closure(entries: dict[str, Path], output: Path) -> dict:
    if platform.system() != "Darwin":
        raise BuildError("host_linkage_target_unsupported")
    if (
        not output.is_absolute()
        or output.exists()
        or output.is_symlink()
        or not entries
    ):
        raise BuildError("host_linkage_output_invalid")
    tools = {
        name: shutil.which(name)
        for name in ["otool", "lipo", "install_name_tool", "codesign"]
    }
    if not all(tools.values()):
        raise BuildError("host_linkage_tools_missing")

    def run(args: list) -> str:
        result = subprocess.run(
            [str(a) for a in args],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": os.defpath},
            timeout=120,
        )
        if result.returncode:
            if output.is_dir():
                (output / "linkage-error.log").write_text(result.stderr[-65536:])
            raise BuildError("host_linkage_tool_failed:" + Path(args[0]).name)
        return result.stdout

    roots: dict[Path, str] = {}
    names = set()
    for name, source in entries.items():
        relative(name)
        folded = unicodedata.normalize("NFC", name).casefold()
        if (
            name.split("/")[0].casefold()
            in {"libraries", "linkage-receipt.json", "linkage-error.log"}
            or folded in names
            or not source.is_absolute()
        ):
            raise BuildError("host_linkage_entry_invalid")
        names.add(folded)
        source = source.resolve(strict=True)
        if not source.is_file() or source in roots:
            raise BuildError("host_linkage_entry_invalid")
        roots[source] = name
    if any(a != b and b.startswith(a + "/") for a in names for b in names):
        raise BuildError("host_linkage_entry_invalid")

    objects = {}
    metadata = {}
    pending = [(source, ()) for source in roots]
    while pending:
        source, inherited_paths = pending.pop()
        if len(objects) >= 512 or source.stat().st_size > 2 * 1024**3:
            raise BuildError("host_linkage_graph_limit")
        if source not in metadata:
            architectures = run([tools["lipo"], "-archs", source]).split()
            if architectures != [platform.machine()]:
                raise BuildError("host_linkage_architecture_unsupported")
            metadata[source] = load_commands(run([tools["otool"], "-l", source]))
        identity, dependencies, paths = metadata[source]
        search_paths = []
        # A leaf with only Apple dependencies cannot consume an rpath; all are removed on staging.
        for path in (
            paths if any(not apple_library(value) for value in dependencies) else []
        ):
            if path == "@loader_path":
                path = str(source.parent)
            elif path.startswith("@loader_path/"):
                path = str(source.parent / path[len("@loader_path/") :])
            if not path.startswith("/"):
                raise BuildError("host_linkage_reference_unsupported")
            search_paths.append(str(Path(path).resolve()))
        search_paths = list(dict.fromkeys([*search_paths, *inherited_paths]))
        resolved = {}
        for reference in dependencies:
            if not apple_library(reference):
                resolved[reference] = resolve_dependency(
                    reference, source, search_paths
                )
        if source in objects:
            if objects[source]["dependencies"] != resolved:
                raise BuildError("host_linkage_loader_context_ambiguous")
            continue
        pending.extend(
            (dependency, tuple(search_paths)) for dependency in resolved.values()
        )
        digest = sha256(source)
        # Byte-identical libraries can resolve relative dependencies in different loader contexts.
        name = roots.get(
            source, f"libraries/{len(objects):03d}-{digest[:16]}/" + source.name
        )
        relative(name)
        objects[source] = {
            "path": name,
            "sourceSha256": digest,
            "identity": identity,
            "dependencies": resolved,
            "rpaths": paths,
        }

    output.mkdir(mode=0o700)
    for source, item in objects.items():
        destination = output / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        if sha256(destination) != item["sourceSha256"]:
            raise BuildError("host_linkage_source_changed")
        destination.chmod(source.stat().st_mode & 0o777)
    report = {
        "schemaVersion": 1,
        "platform": "macos-" + platform.machine(),
        "scope": "Mach-O load-command closure only",
        "qualification": "failed",
        "releaseSigned": False,
        "redistributable": False,
        "dynamicLoadingQualified": False,
        "objects": {},
    }
    for source, item in objects.items():
        destination = output / item["path"]
        changes = []
        for reference, dependency in item["dependencies"].items():
            target = output / objects[dependency]["path"]
            changes.extend(
                [
                    "-change",
                    reference,
                    "@loader_path/" + os.path.relpath(target, destination.parent),
                ]
            )
        if item["identity"]:
            changes.extend(["-id", "@loader_path/" + destination.name])
        for path in dict.fromkeys(item["rpaths"]):
            changes.extend(["-delete_rpath", path])
        if changes:
            run([tools["install_name_tool"], *changes, destination])
        # Local ad-hoc signatures permit execution after rewriting; release identity signing follows packaging.
        run(
            [
                tools["codesign"],
                "--force",
                "--sign",
                "-",
                "--timestamp=none",
                destination,
            ]
        )

    for item in objects.values():
        destination = output / item["path"]
        _, dependencies, paths = load_commands(run([tools["otool"], "-l", destination]))
        if paths:
            raise BuildError("host_linkage_search_path_remaining")
        for reference in dependencies:
            if apple_library(reference):
                continue
            if not reference.startswith("@loader_path/"):
                raise BuildError("host_linkage_external_reference_remaining")
            resolved = resolve_dependency(reference, destination, [])
            if not resolved.is_relative_to(output) or resolved not in {
                output / v["path"] for v in objects.values()
            }:
                raise BuildError("host_linkage_external_reference_remaining")
        run([tools["codesign"], "--verify", "--strict", destination])
        report["objects"][item["path"]] = {
            "sourceSha256": item["sourceSha256"],
            "sha256": sha256(destination),
            "bytes": destination.stat().st_size,
        }
    report["qualification"] = "passed"
    (output / "linkage-receipt.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--entries",
        type=Path,
        required=True,
        help="JSON map of payload-relative names to absolute Mach-O source files",
    )
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    try:
        entries = json.loads(options.entries.read_text())
        if not isinstance(entries, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in entries.items()
        ):
            raise BuildError("host_linkage_entries_invalid")
        receipt = closure({k: Path(v) for k, v in entries.items()}, options.output)
        print(
            json.dumps(
                {
                    "qualification": receipt["qualification"],
                    "objects": len(receipt["objects"]),
                    "releaseSigned": False,
                }
            )
        )
    except (BuildError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        parser.exit(
            1, str(error) if isinstance(error, BuildError) else "host_linkage_failed"
        )
