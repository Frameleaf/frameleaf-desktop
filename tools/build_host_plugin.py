"""Build the pinned core workflow WASM for native hosts; authoring only."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import re
import shutil
import tarfile
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

from build_host_database import download
from build_host_server import stage_server
from build_runtime import BuildError, build_environment, git_blob, regular, run, sha256


def tool_pin(lock: dict, repository: str, target: str) -> dict:
    entries = lock.get("tools", {}).get("github:" + repository, [])
    if len(entries) != 1:
        raise BuildError("host_plugin_tool_pin_ambiguous")
    pin = entries[0].get("platforms." + target, {})
    url = urlsplit(pin.get("url", ""))
    if (
        url.scheme != "https"
        or url.netloc != "github.com"
        or not url.path.lower().startswith(
            "/" + repository.lower() + "/releases/download/"
        )
        or url.query
        or url.fragment
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", pin.get("checksum", ""))
    ):
        raise BuildError("host_plugin_tool_pin_invalid")
    return pin


def build(source: Path, revision: str, node: Path, output: Path) -> None:
    if not re.fullmatch("[0-9a-f]{40}", revision) or not all(
        path.is_absolute() for path in [source, node, output]
    ):
        raise BuildError("host_plugin_source_invalid")
    if output.exists() or output.is_symlink():
        raise BuildError("host_plugin_output_invalid")
    git, pnpm = shutil.which("git"), shutil.which("pnpm")
    if not git or not pnpm or not node.is_file():
        raise BuildError("host_plugin_build_tools_missing")
    systems = {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}
    machines = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "AMD64": "x64"}
    if platform.system() not in systems or platform.machine() not in machines:
        raise BuildError("host_plugin_target_unsupported")
    target = systems[platform.system()] + "-" + machines[platform.machine()]
    output.mkdir(mode=0o700)
    work = output / "work"
    work.mkdir(mode=0o700)
    env = build_environment(work, os.environ)
    env["PATH"] = os.pathsep.join(
        [str(node.parent), str(Path(pnpm).parent), os.defpath]
    )
    env["FRAMELEAF_BUILD_ERROR_LOG"] = str(output / "command-error.log")
    package = json.loads(git_blob(git, source, revision, "package.json", env))
    match = re.fullmatch(r"pnpm@(\d+\.\d+\.\d+)", package.get("packageManager", ""))
    if not match or run([node, "--version"], cwd=work, env=env) != "v26.11.1":
        raise BuildError("host_plugin_toolchain_unapproved")
    archive = work / "source.tar"
    run(
        [
            git,
            "archive",
            "--format=tar",
            "--output",
            archive,
            revision,
            "package.json",
            "pnpm-lock.yaml",
            "pnpm-workspace.yaml",
            ".pnpmfile.cjs",
            "LICENSE",
            "mise.lock",
            "packages/sdk",
            "packages/plugin-sdk",
            "packages/plugin-core",
            "packages/patches",
        ],
        cwd=source,
        env=env,
    )
    snapshot = work / "source"
    snapshot.mkdir(mode=0o700)
    with tarfile.open(archive) as contents:
        contents.extractall(snapshot, filter="data")
    if run([pnpm, "--version"], cwd=snapshot, env=env) != match[1]:
        raise BuildError("host_plugin_pnpm_unapproved")
    lock = tomllib.loads((snapshot / "mise.lock").read_text())
    report = {
        "schemaVersion": 1,
        "sourceRevision": revision,
        "sourceArchiveSha256": sha256(archive),
        "nodeSha256": sha256(node),
        "lockfileSha256": sha256(snapshot / "pnpm-lock.yaml"),
        "pnpmVersion": match[1],
        "platform": target,
        "tools": {},
        "qualification": "failed",
        "redistributable": False,
        "runtimeQualified": False,
    }
    with (output / "build.log").open("w") as log:

        def command(arguments: list) -> None:
            log.write(run(arguments, cwd=snapshot, env=env) + "\n")
            log.flush()

        try:
            compiler = work / ("extism-js.exe" if os.name == "nt" else "extism-js")
            pin = tool_pin(lock, "extism/js-pdk", target)
            compressed = work / "extism.gz"
            download(pin["url"], compressed, pin["checksum"][7:])
            with gzip.open(compressed, "rb") as stream:
                content = stream.read(128 * 1024 * 1024 + 1)
            if len(content) > 128 * 1024 * 1024:
                raise BuildError("host_plugin_tool_too_large")
            compiler.write_bytes(content)
            compiler.chmod(0o700)
            report["tools"]["extism"] = {**pin, "sha256": sha256(compiler)}
            pin = tool_pin(lock, "webassembly/binaryen", target)
            compressed = work / "binaryen.tar.gz"
            download(pin["url"], compressed, pin["checksum"][7:])
            binaryen = work / "binaryen"
            binaryen.mkdir(mode=0o700)
            with tarfile.open(compressed) as contents:
                contents.extractall(binaryen, filter="data")
            candidates = list(
                binaryen.rglob("wasm-opt.exe" if os.name == "nt" else "wasm-opt")
            )
            if len(candidates) != 1:
                raise BuildError("host_plugin_binaryen_invalid")
            regular(candidates[0])
            report["tools"]["binaryen"] = {**pin, "sha256": sha256(candidates[0])}
            env["PATH"] = os.pathsep.join(
                [str(work), str(candidates[0].parent), env["PATH"]]
            )
            report["tools"]["extism"]["reportedVersion"] = run(
                [compiler, "--version"], cwd=work, env=env
            )
            report["tools"]["binaryen"]["reportedVersion"] = run(
                [candidates[0], "--version"], cwd=work, env=env
            )
            manager = [pnpm, "--config.verify-deps-before-run=false"]
            for selector in [
                "@frameleaf/sdk",
                "@frameleaf/plugin-sdk",
                "@frameleaf/plugin-core",
            ]:
                command(
                    [*manager, "--filter", selector, "install", "--frozen-lockfile"]
                )
                command([*manager, "--filter", selector, "build"])
            command([*manager, "--filter", "@frameleaf/plugin-core", "test"])
            package = snapshot / "packages/plugin-core"
            wasm = package / "dist/plugin.wasm"
            with wasm.open("rb") as stream:
                if stream.read(8) != b"\x00asm\x01\x00\x00\x00":
                    raise BuildError("host_plugin_wasm_invalid")
            manifest = json.loads((package / "manifest.json").read_text())
            if manifest.get("wasmPath") != "dist/plugin.wasm":
                raise BuildError("host_plugin_manifest_invalid")
            staged = work / "staged"
            staged.mkdir(mode=0o700)
            shutil.copytree(package / "dist", staged / "dist", symlinks=True)
            shutil.copyfile(package / "manifest.json", staged / "manifest.json")
            report["files"] = stage_server(staged, output / "plugin")
            report["qualification"] = "passed"
        finally:
            (output / "qualification.json").write_text(
                json.dumps(report, indent=2) + "\n"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source", "revision", "node", "output"]:
        parser.add_argument("--" + name, required=True)
    options = parser.parse_args()
    try:
        build(
            Path(options.source),
            options.revision,
            Path(options.node),
            Path(options.output),
        )
    except (BuildError, OSError, ValueError, tarfile.TarError) as error:
        parser.exit(
            1,
            str(error) if isinstance(error, BuildError) else "host_plugin_build_failed",
        )
