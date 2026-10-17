"""Build and exercise the pinned native HDR stack; not a redistributable server bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

from build_runtime import BuildError, build_environment, git_blob, inventory, sha256


def codec_pin(name: str, manifest: dict, patch: bytes) -> dict:
    repositories = {
        "libheif": "strukturag/libheif",
        "libultrahdr": "google/libultrahdr",
    }
    if (
        name not in repositories
        or not isinstance(manifest, dict)
        or manifest.get("name") != name
        or manifest.get("repository") != repositories[name]
        or not isinstance(manifest.get("revision"), str)
        or not re.fullmatch(r"[0-9a-f]{40}", manifest["revision"])
        or manifest.get("patchChecksum") != hashlib.sha256(patch).hexdigest()
    ):
        raise BuildError("host_media_source_pin_invalid")
    return manifest


def build(
    source: Path, revision: str, node_root: Path, dependency_prefix: Path, output: Path
) -> None:
    system = platform.system()
    if system not in {"Darwin", "Linux"}:
        raise BuildError("host_media_feasibility_target_unsupported")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise BuildError("host_media_revision_invalid")
    for path in [source, node_root, dependency_prefix, output]:
        if not path.is_absolute():
            raise BuildError("host_media_absolute_path_required")
    git, cmake = shutil.which("git"), shutil.which("cmake")
    audit = shutil.which("readelf") if system == "Linux" else "/usr/bin/otool"
    node = node_root / "bin/node"
    if (
        not git
        or not cmake
        or not audit
        or not node.is_file()
        or not (node_root / "include/node/node_api.h").is_file()
    ):
        raise BuildError("host_media_build_tools_missing")
    output.mkdir(mode=0o700)
    work, prefix = output / "work", output / "prefix"
    work.mkdir(mode=0o700)
    env = build_environment(work, {})
    env["PATH"] = os.pathsep.join(
        [
            str(node.parent),
            str(Path(cmake).parent),
            str(dependency_prefix / "bin"),
            os.defpath,
        ]
    )
    env["PKG_CONFIG_PATH"] = os.pathsep.join(
        str(p / "lib/pkgconfig") for p in [prefix, dependency_prefix]
    )
    env["FRAMELEAF_BUILD_ERROR_LOG"] = str(output / "source-error.log")
    report = {
        "schemaVersion": 1,
        "scope": "native-hdr-fixtures",
        "sourceRevision": revision,
        "platform": f"{'macos' if system == 'Darwin' else 'linux'}-{platform.machine()}",
        "osRelease": platform.release(),
        "redistributable": False,
        "developmentDependencyPrefix": str(dependency_prefix),
        "qualification": "failed",
        "codecs": {},
    }
    with (output / "build.log").open("w") as log:

        def run(args: list, cwd: Path = work, extra: dict | None = None) -> None:
            result = subprocess.run(
                [str(arg) for arg in args],
                cwd=cwd,
                check=False,
                env={**env, **(extra or {})},
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=1800,
            )
            log.flush()
            if result.returncode:
                raise BuildError(
                    f"host_media_command_failed:{Path(args[0]).name}:{result.returncode}"
                )

        try:
            expected_node = (
                git_blob(git, source, revision, ".nvmrc", env)
                .decode()
                .strip()
                .removeprefix("v")
            )
            actual_node = (
                subprocess.check_output(
                    [node, "--version"], env=env, text=True, timeout=30
                )
                .strip()
                .removeprefix("v")
            )
            if actual_node != expected_node:
                raise BuildError("host_media_node_version_mismatch")
            report["nodeVersion"] = actual_node
            report["nodeSha256"] = sha256(node)
            snapshot = work / "source"
            paths = subprocess.check_output(
                [
                    git,
                    "ls-tree",
                    "-r",
                    "--name-only",
                    revision,
                    "--",
                    "server/native",
                    "server/test/native",
                ],
                cwd=source,
                env=env,
                text=True,
                timeout=30,
            ).splitlines()
            for name in paths:
                if (
                    name.startswith(("server/native/", "server/test/native/fixtures/"))
                    or name == "server/test/native/image-hdr.test.mjs"
                ):
                    target = snapshot / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(git_blob(git, source, revision, name, env))
            report["sourceFiles"] = inventory(snapshot)
            for name in ["libheif", "libultrahdr"]:
                base = f"server/base-image/sources/{name}"
                patch = git_blob(git, source, revision, f"{base}-hdr.patch", env)
                pin = codec_pin(
                    name,
                    json.loads(git_blob(git, source, revision, f"{base}.json", env)),
                    patch,
                )
                report["codecs"][name] = pin
                patch_file = work / f"{name}.patch"
                patch_file.write_bytes(patch)
                checkout = work / name
                run(
                    [
                        git,
                        "clone",
                        "--filter=blob:none",
                        "--no-checkout",
                        f"https://github.com/{pin['repository']}.git",
                        checkout,
                    ]
                )
                run([git, "checkout", "--detach", pin["revision"]], checkout)
                run([git, "apply", patch_file], checkout)
                options = [
                    f"-DCMAKE_INSTALL_PREFIX={prefix}",
                    "-DCMAKE_BUILD_TYPE=Release",
                    f"-DCMAKE_PREFIX_PATH={prefix};{dependency_prefix}",
                ]
                if name == "libheif":
                    options += [
                        "-DWITH_EXPERIMENTAL_GAIN_MAP=ON",
                        "-DWITH_DAV1D=ON",
                        "-DENABLE_PARALLEL_TILE_DECODING=ON",
                        "-DWITH_LIBSHARPYUV=ON",
                        "-DWITH_LIBDE265=ON",
                        "-DWITH_AOM_DECODER=OFF",
                        "-DWITH_AOM_ENCODER=ON",
                        "-DWITH_X265=ON",
                        "-DWITH_EXAMPLES=OFF",
                        "-DBUILD_TESTING=OFF",
                        "-DENABLE_PLUGIN_LOADING=OFF",
                    ]
                else:
                    options += [
                        "-DBUILD_SHARED_LIBS=ON",
                        "-DUHDR_BUILD_DEPS=OFF",
                        "-DUHDR_ENABLE_HEIF=ON",
                        "-DUHDR_WRITE_XMP=ON",
                        "-DUHDR_WRITE_ISO=ON",
                        "-DUHDR_ENABLE_GLES=OFF",
                        "-DUHDR_BUILD_EXAMPLES=OFF",
                        "-DUHDR_ENABLE_INSTALL=ON",
                    ]
                    # A broad JPEG include prefix shadows the patched HEIF headers on Homebrew.
                    jpeg_include = subprocess.check_output(
                        ["pkg-config", "--variable=includedir", "libjpeg"],
                        env=env,
                        text=True,
                        timeout=30,
                    ).strip()
                    options += [f"-DJPEG_INCLUDE_DIR={jpeg_include}"]
                run([cmake, "-S", checkout, "-B", checkout / "build", *options])
                run([cmake, "--build", checkout / "build", "--parallel", "1"])
                run([cmake, "--install", checkout / "build"])
            binding_build = work / "binding"
            run(
                [
                    cmake,
                    "-S",
                    snapshot / "server/native",
                    "-B",
                    binding_build,
                    "-DCMAKE_BUILD_TYPE=Release",
                    f"-DCMAKE_PREFIX_PATH={prefix};{dependency_prefix}",
                    f"-DNODE_API_INCLUDE_DIR={node_root / 'include/node'}",
                    f"-DUHDR_INCLUDE_DIR={prefix / 'include'}",
                    f"-DUHDR_LIBRARY={prefix / 'lib' / ('libuhdr.dylib' if system == 'Darwin' else 'libuhdr.so')}",
                ]
            )
            run([cmake, "--build", binding_build, "--parallel", "1"])
            binding = binding_build / "image-hdr.node"
            report["bindingSha256"] = sha256(binding)
            run([audit, "-L" if system == "Darwin" else "-dW", binding])
            run(
                [node, "--test", snapshot / "server/test/native/image-hdr.test.mjs"],
                extra={
                    "FRAMELEAF_HDR_BINDING": str(binding),
                    "FRAMELEAF_HDR_ISO_TEST": "1",
                },
            )
            report["qualification"] = "passed"
        finally:
            (output / "qualification.json").write_text(
                json.dumps(report, indent=2) + "\n"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ["source", "revision", "node-root", "dependency-prefix", "output"]:
        parser.add_argument(f"--{argument}", required=True)
    args = parser.parse_args()
    build(
        Path(args.source),
        args.revision,
        Path(args.node_root),
        Path(args.dependency_prefix),
        Path(args.output),
    )
