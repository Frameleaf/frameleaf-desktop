"""Build pinned photo UI and Studio assets for a native host; authoring only."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import tarfile
from pathlib import Path

from build_host_server import stage_server
from build_runtime import BuildError, build_environment, git_blob, run, sha256
from source_archive import verify_source_archive


def stage_web(source: Path, destination: Path) -> dict:
    files = stage_server(source, destination)
    required = {
        "index.html",
        "studio-engine/editor.html",
        "studio-engine/commands.html",
    }
    if not required.issubset(files):
        raise BuildError("host_web_entries_missing")
    return files


def build(source: Path, revision: str, node: Path, output: Path) -> None:
    if not re.fullmatch("[0-9a-f]{40}", revision) or not all(
        path.is_absolute() for path in [source, node, output]
    ):
        raise BuildError("host_web_source_invalid")
    if output.exists() or output.is_symlink():
        raise BuildError("host_web_output_invalid")
    git, pnpm, bootstrap, tar = (
        shutil.which(name) for name in ["git", "pnpm", "npm", "tar"]
    )
    if not git or not pnpm or not bootstrap or not tar or not node.is_file():
        raise BuildError("host_web_build_tools_missing")
    output.mkdir(mode=0o700)
    work = output / "work"
    work.mkdir(mode=0o700)
    env = build_environment(work, os.environ)
    env["PATH"] = os.pathsep.join(
        [
            str(node.parent),
            str(Path(pnpm).parent),
            str(Path(bootstrap).parent),
            str(Path(git).parent),
            str(Path(tar).parent),
            os.defpath,
        ]
    )
    env["FRAMELEAF_BUILD_ERROR_LOG"] = str(output / "command-error.log")
    env["FRAMELEAF_BUILD"] = revision
    env["RAYON_NUM_THREADS"] = "2"
    env["TOKIO_WORKER_THREADS"] = "2"
    package = json.loads(git_blob(git, source, revision, "package.json", env))
    match = re.fullmatch(r"pnpm@(\d+\.\d+\.\d+)", package.get("packageManager", ""))
    if not match or run([node, "--version"], cwd=work, env=env) != "v22.23.4":
        raise BuildError("host_web_toolchain_unapproved")
    archive = work / "source.tar"
    archive_paths = [
        "package.json",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        ".pnpmfile.cjs",
        "LICENSE",
        "packages/sdk",
        "packages/ui",
        "packages/justified-layout-wasm",
        "packages/patches",
        "web",
        "i18n",
        "licenses",
        "studio",
        "scripts/frameleaf-studio-contracts.mjs",
        "scripts/frameleaf-studio-rights.mjs",
    ]
    run(
        [
            git,
            "-c", "core.autocrlf=false",
            "-c", "core.eol=lf",
            "archive",
            "--format=tar",
            "--output",
            archive,
            revision,
            *archive_paths,
        ],
        cwd=source,
        env=env,
    )
    verify_source_archive(git, source, revision, archive_paths, archive, env)
    snapshot = work / "source"
    snapshot.mkdir(mode=0o700)
    with tarfile.open(archive) as contents:
        contents.extractall(snapshot, filter="data")
    if run([pnpm, "--version"], cwd=snapshot, env=env) != match[1]:
        raise BuildError("host_web_pnpm_unapproved")
    configuration = json.loads((snapshot / "studio/engine-build.json").read_text())
    if configuration.get("node") != "22.23.4" or not re.fullmatch(
        r"\d+\.\d+\.\d+", configuration.get("npm", "")
    ):
        raise BuildError("host_web_studio_toolchain_invalid")
    report = {
        "schemaVersion": 1,
        "sourceRevision": revision,
        "sourceArchiveSha256": sha256(archive),
        "nodeSha256": sha256(node),
        "lockfileSha256": sha256(snapshot / "pnpm-lock.yaml"),
        "studioLockfileSha256": sha256(snapshot / "studio/engine-package-lock.json"),
        "pnpmVersion": match[1],
        "npmVersion": configuration["npm"],
        "bootstrapNpmSha256": sha256(Path(bootstrap)),
        "qualification": "failed",
        "redistributable": False,
        "runtimeQualified": False,
        "scope": "photo UI and Studio artifact build; source rights/runtime gates unchanged",
    }
    with (output / "build.log").open("w") as log:

        def command(arguments: list, cwd: Path = snapshot) -> None:
            log.write(run(arguments, cwd=cwd, env=env) + "\n")
            log.flush()

        try:
            tools = work / "npm-toolchain"
            tools.mkdir(mode=0o700)
            (tools / "package.json").write_text('{"private":true}\n')
            # The attestation pin is authoritative even when a Docker bootstrap pin differs.
            command(
                [
                    bootstrap,
                    "install",
                    "--prefix",
                    tools,
                    "--save-exact",
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                    "npm@" + configuration["npm"],
                ],
                cwd=work,
            )
            npm = tools / "node_modules/npm/bin/npm-cli.js"
            if (
                run([node, npm, "--version"], cwd=snapshot, env=env)
                != configuration["npm"]
            ):
                raise BuildError("host_web_npm_unapproved")
            report["npmCliSha256"] = sha256(npm)
            report["npmToolchainLockfileSha256"] = sha256(tools / "package-lock.json")
            env["PATH"] = str(tools / "node_modules/.bin") + os.pathsep + env["PATH"]
            command([node, "studio/tools/engine.mjs", "prepare"])
            report["studioSourceSha256"] = json.loads(
                (snapshot / "studio/engine/frameleaf-source.json").read_text()
            )["sourceSha256"]
            command(
                [
                    node,
                    npm,
                    "--prefix",
                    "studio/engine",
                    "ci",
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                ]
            )
            command([node, "studio/tools/adapter.mjs", "build"])
            manager = [pnpm, "--config.verify-deps-before-run=false"]
            command(
                [*manager, "--filter", "@frameleaf/sdk", "install", "--frozen-lockfile"]
            )
            command([*manager, "--filter", "@frameleaf/sdk", "build"])
            command(
                [
                    *manager,
                    "--filter",
                    "frameleaf-web...",
                    "install",
                    "--frozen-lockfile",
                ]
            )
            command([*manager, "--filter", "frameleaf-web", "build"])
            report["files"] = stage_web(snapshot / "web/build", output / "www")
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
            1, str(error) if isinstance(error, BuildError) else "host_web_build_failed"
        )
