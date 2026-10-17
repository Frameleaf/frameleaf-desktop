"""Build a pinned, link-free production server package; native closure remains separate."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
import tarfile
from pathlib import Path

from build_runtime import (
    BuildError,
    build_environment,
    git_blob,
    inventory,
    regular,
    run,
    sha256,
)


def ignored(directory: str, names: list[str]) -> set[str]:
    return (
        set(names) & {".bin", ".pnpm", ".modules.yaml"}
        if Path(directory).name == "node_modules"
        else set()
    )


def stage_server(source: Path, destination: Path) -> dict:
    if (
        not source.is_absolute()
        or not destination.is_absolute()
        or destination.exists()
        or destination.is_symlink()
        or destination.resolve().is_relative_to(source.resolve())
    ):
        raise BuildError("host_server_output_invalid")
    if not stat.S_ISDIR(regular(source).st_mode):
        raise BuildError("host_server_source_invalid")
    count = 0
    for directory, directories, files in os.walk(source, followlinks=False):
        skip = ignored(directory, directories + files)
        directories[:] = [name for name in directories if name not in skip]
        for name in [*directories, *(name for name in files if name not in skip)]:
            count += 1
            if count > 100_000:
                raise BuildError("host_server_inventory_limit")
            mode = regular(Path(directory) / name).st_mode
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise BuildError("host_server_special_file_forbidden")
    shutil.copytree(source, destination, symlinks=True, ignore=ignored)
    return inventory(destination)


def build(source: Path, revision: str, node: Path, output: Path) -> None:
    if not re.fullmatch("[0-9a-f]{40}", revision) or not all(
        path.is_absolute() for path in [source, node, output]
    ):
        raise BuildError("host_server_source_invalid")
    if output.exists() or output.is_symlink():
        raise BuildError("host_server_output_invalid")
    git, pnpm = shutil.which("git"), shutil.which("pnpm")
    if not git or not pnpm or not node.is_file():
        raise BuildError("host_server_build_tools_missing")
    output.mkdir(mode=0o700)
    work = output / "work"
    work.mkdir(mode=0o700)
    env = build_environment(work, os.environ)
    env["RAYON_NUM_THREADS"] = "1"
    env["TOKIO_WORKER_THREADS"] = "1"
    env["UV_THREADPOOL_SIZE"] = "1"
    env["PATH"] = os.pathsep.join(
        [str(node.parent), str(Path(pnpm).parent), os.defpath]
    )
    env["FRAMELEAF_BUILD_ERROR_LOG"] = str(output / "command-error.log")
    package = json.loads(git_blob(git, source, revision, "package.json", env))
    match = re.fullmatch(r"pnpm@(\d+\.\d+\.\d+)", package.get("packageManager", ""))
    if not match or run([node, "--version"], cwd=work, env=env) != "v26.11.1":
        raise BuildError("host_server_toolchain_unapproved")
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
            "packages/sdk",
            "packages/plugin-sdk",
            "packages/sql-tools",
            "packages/patches",
            "server",
            "studio/runtime",
            "studio/tools",
            "docker/scripts/verify-server-package.mjs",
        ],
        cwd=source,
        env=env,
    )
    snapshot = work / "source"
    snapshot.mkdir(mode=0o700)
    with tarfile.open(archive) as contents:
        contents.extractall(snapshot, filter="data")
    if run([pnpm, "--version"], cwd=snapshot, env=env) != match[1]:
        raise BuildError("host_server_pnpm_unapproved")
    report = {
        "schemaVersion": 1,
        "sourceRevision": revision,
        "sourceArchiveSha256": sha256(archive),
        "lockfileSha256": sha256(snapshot / "pnpm-lock.yaml"),
        "platform": platform.system() + "-" + platform.machine(),
        "nodeVersion": "26.11.1",
        "nodeSha256": sha256(node),
        "pnpmVersion": match[1],
        "qualification": "failed",
        "redistributable": False,
        "nativeClosureQualified": False,
    }
    with (output / "build.log").open("w") as log:

        def command(arguments: list, cwd: Path = snapshot) -> None:
            log.write(run(arguments, cwd=cwd, env=env) + "\n")
            log.flush()

        manager = [pnpm, "--config.verify-deps-before-run=false"]
        try:
            for selector in ["@frameleaf/sdk", "@frameleaf/plugin-sdk", "frameleaf..."]:
                command(
                    [*manager, "--filter", selector, "install", "--frozen-lockfile"]
                )
                target = "frameleaf" if selector == "frameleaf..." else selector
                command([*manager, "--filter", target, "build"])
            deployed = work / "deployed"
            command(
                [
                    *manager,
                    "--filter",
                    "frameleaf",
                    "--prod",
                    "--config.node-linker=hoisted",
                    "deploy",
                    deployed,
                ]
            )
            runtime = output / "server"
            report["files"] = stage_server(deployed, runtime)
            command(
                [
                    node,
                    snapshot / "docker/scripts/verify-server-package.mjs",
                    runtime,
                    snapshot / "studio/runtime",
                ]
            )
            report["verifierSha256"] = sha256(
                snapshot / "docker/scripts/verify-server-package.mjs"
            )
            report["subtitleRuntimeSha256"] = sha256(
                runtime / "resources/studio/subtitle-sidecar.mjs"
            )
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
            str(error) if isinstance(error, BuildError) else "host_server_build_failed",
        )
