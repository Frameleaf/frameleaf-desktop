"""Build the CoreML device collector that build_runtime.py seals into a coreml-ort pack; unsigned."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from build_runtime import BuildError, regular, sha256
from relocate_macos import apple_library, load_commands

LIBRARY = "_frameleaf_coreml_observer.dylib"
IDENTITY = "@rpath/" + LIBRARY


def verified_linkage(text: str) -> list[str]:
    identity, dependencies, paths = load_commands(text)
    if (
        identity != IDENTITY
        or paths
        or not dependencies
        or any(not apple_library(dep) for dep in dependencies)
    ):
        raise BuildError("coreml_observer_linkage_invalid")
    return dependencies


def build(output: Path) -> None:
    if platform.system() != "Darwin" or platform.machine().lower() not in {
        "arm64",
        "aarch64",
    }:
        raise BuildError("coreml_observer_target_unsupported")
    output = output.absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise BuildError("coreml_observer_output_must_be_new")
    source = Path(__file__).resolve().parent.parent / "native/coreml_observer.m"
    if not stat.S_ISREG(regular(source).st_mode):
        raise BuildError("coreml_observer_source_invalid")
    source_hash = sha256(source)
    loader = source.parent.parent / "runtime/metal_observer.py"
    if not stat.S_ISREG(regular(loader).st_mode):
        raise BuildError("coreml_observer_loader_invalid")
    loader_hash = sha256(loader)
    adapter = loader.with_name("metal_inference.py")
    if not stat.S_ISREG(regular(adapter).st_mode):
        raise BuildError("coreml_observer_adapter_invalid")
    adapter_hash = sha256(adapter)
    entry = loader.with_name("metal_entry.py")
    if not stat.S_ISREG(regular(entry).st_mode):
        raise BuildError("coreml_observer_entry_invalid")
    entry_hash = sha256(entry)
    with tempfile.TemporaryDirectory(
        prefix=f".{output.name}-", dir=output.parent
    ) as temporary:
        work = Path(temporary)
        payload = work / "payload"
        payload.mkdir(mode=0o700)
        snapshot = work / "observer.m"
        snapshot.write_bytes(source.read_bytes())
        if sha256(snapshot) != source_hash:
            raise BuildError("coreml_observer_source_changed")
        loader_snapshot = payload / "metal_observer.py"
        loader_snapshot.write_bytes(loader.read_bytes())
        if sha256(loader_snapshot) != loader_hash:
            raise BuildError("coreml_observer_source_changed")
        adapter_snapshot = payload / "metal_inference.py"
        adapter_snapshot.write_bytes(adapter.read_bytes())
        if sha256(adapter_snapshot) != adapter_hash:
            raise BuildError("coreml_observer_source_changed")
        entry_snapshot = payload / "entry.py"
        entry_snapshot.write_bytes(entry.read_bytes())
        if sha256(entry_snapshot) != entry_hash:
            raise BuildError("coreml_observer_source_changed")
        (payload / "__init__.py").write_text(
            '"""Private Frameleaf desktop inference support."""\n'
        )
        environment = {"PATH": os.defpath, "TMPDIR": str(work)}

        def run(*args: str | Path) -> str:
            try:
                result = subprocess.run(
                    [str(value) for value in args],
                    cwd=work,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                return result.stdout.strip()
            except (OSError, subprocess.SubprocessError) as error:
                raise BuildError(
                    "coreml_observer_build_command_failed:" + str(args[0])
                ) from error

        library = payload / LIBRARY
        compiler = "/usr/bin/xcrun"
        compiler_version = run(compiler, "clang", "--version").splitlines()[0]
        sdk = run(compiler, "--show-sdk-version")
        run(
            compiler,
            "clang",
            "-fobjc-arc",
            "-fblocks",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-arch",
            "arm64",
            "-mmacosx-version-min=12.0",
            "-dynamiclib",
            snapshot,
            "-framework",
            "Foundation",
            "-framework",
            "Metal",
            "-framework",
            "QuartzCore",
            "-Wl,-install_name," + IDENTITY,
            "-o",
            library,
        )
        if run(compiler, "lipo", "-archs", library).split() != ["arm64"]:
            raise BuildError("coreml_observer_architecture_invalid")
        dependencies = verified_linkage(run(compiler, "otool", "-l", library))
        if (
            sha256(source) != source_hash
            or sha256(loader) != loader_hash
            or sha256(adapter) != adapter_hash
            or sha256(entry) != entry_hash
        ):
            raise BuildError("coreml_observer_source_changed")
        provenance = {
            "schemaVersion": 1,
            "platform": "macos",
            "architecture": "aarch64",
            "minimumSystemVersion": "12.0",
            "sourceSha256": source_hash,
            "builderSha256": sha256(Path(__file__)),
            "loaderSha256": loader_hash,
            "adapterSha256": adapter_hash,
            "entrySha256": entry_hash,
            "packageInitSha256": sha256(payload / "__init__.py"),
            "compiler": compiler_version,
            "sdk": sdk,
            "library": LIBRARY,
            "librarySha256": sha256(library),
            "bytes": regular(library).st_size,
            "identity": IDENTITY,
            "dependencies": dependencies,
            "releaseSigned": False,
        }
        (payload / "provenance.json").write_text(
            json.dumps(provenance, indent=2) + "\n"
        )
        if output.exists() or output.is_symlink():
            raise BuildError("coreml_observer_output_must_be_new")
        shutil.move(str(payload), output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    try:
        build(options.output)
    except BuildError as error:
        parser.exit(1, str(error) + "\n")
