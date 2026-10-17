"""Build the native Manager from an exact local commit with a frozen npm dependency graph."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import tarfile
from pathlib import Path

from build_host_server import stage_server
from build_runtime import BuildError, build_environment, inventory, regular, run, sha256


def stage_manager(source: Path, destination: Path, revision: str) -> dict:
    if (
        not re.fullmatch(r"[a-f0-9]{40}", revision)
        or not source.is_absolute()
        or source.resolve() != source
        or not destination.is_absolute()
        or destination.resolve() != destination
        or destination.exists()
        or destination.is_symlink()
        or destination.is_relative_to(source)
    ):
        raise BuildError("host_manager_paths_invalid")
    for name in [
        "package.json",
        "package-lock.json",
        "LICENSE",
        "build/main.js",
        "ui/dist/index.html",
        "release-worker.cjs",
        "media-copy.cjs",
    ]:
        if not stat.S_ISREG(regular(source / name).st_mode):
            raise BuildError("host_manager_component_missing")
    package = json.loads((source / "package.json").read_text())
    if (
        package.get("name") != "@frameleaf/manager"
        or package.get("type") != "module"
        or not package.get("dependencies")
    ):
        raise BuildError("host_manager_package_invalid")
    for name in package["dependencies"]:
        if not re.fullmatch(
            r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+", name
        ) or not stat.S_ISREG(
            regular(source / "node_modules" / name / "package.json").st_mode
        ):
            raise BuildError("host_manager_dependency_missing")
    regular(source.parent / ".github")
    support = [
        ".github/frameleaf-release.cjs",
        ".github/verify-release-bundle.cjs",
        "cosign.pub",
    ]
    for name in support:
        if not stat.S_ISREG(regular(source.parent / name).st_mode):
            raise BuildError("host_manager_component_missing")
    destination.mkdir(mode=0o700)
    for name in ["build", "ui/dist", "node_modules"]:
        target = (
            destination / name if name == "node_modules" else destination / "app" / name
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        stage_server(source / name, target)
    for name in ["package.json", "LICENSE"]:
        shutil.copy2(source / name, destination / name)
    for name in ["release-worker.cjs", "media-copy.cjs"]:
        shutil.copy2(source / name, destination / "app" / name)
    (destination / ".github").mkdir()
    for name in support:
        shutil.copy2(source.parent / name, destination / name)
    receipt = {
        "schemaVersion": 1,
        "sourceRevision": revision,
        "nodeVersion": "26.11.1",
        "lockfileSha256": sha256(source / "package-lock.json"),
        "runtimeQualified": False,
        "redistributable": False,
    }
    (destination / "component.json").write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
    )
    inventory(destination)
    return receipt


def build(source: Path, revision: str, node: Path, output: Path) -> None:
    if (
        not re.fullmatch(r"[a-f0-9]{40}", revision)
        or not all(path.is_absolute() for path in [source, node, output])
        or source.resolve() != source
        or output.resolve() != output
        or output.exists()
        or output.is_symlink()
        or output.is_relative_to(source)
    ):
        raise BuildError("host_manager_paths_invalid")
    git, npm = shutil.which("git"), shutil.which("npm")
    if not git or not npm or not node.is_file():
        raise BuildError("host_manager_build_tools_missing")
    output.mkdir(mode=0o700)
    work = output / "work"
    work.mkdir(mode=0o700)
    env = build_environment(work, os.environ)
    env.update(
        {
            "PATH": os.pathsep.join(
                [str(node.parent), str(Path(npm).parent), os.defpath]
            ),
            "UV_THREADPOOL_SIZE": "1",
            "RAYON_NUM_THREADS": "1",
            "TOKIO_WORKER_THREADS": "1",
            "npm_config_cache": str(work / "npm-cache"),
            "npm_config_ignore_scripts": "true",
            "npm_config_audit": "false",
            "npm_config_fund": "false",
            "npm_config_userconfig": os.devnull,
            "FRAMELEAF_BUILD_ERROR_LOG": str(output / "command-error.log"),
        }
    )
    if run([node, "--version"], cwd=work, env=env) != "v26.11.1":
        raise BuildError("host_manager_toolchain_unapproved")
    archive = work / "source.tar"
    run(
        [
            git,
            "archive",
            "--format=tar",
            "--output",
            archive,
            revision,
            "manager",
            "LICENSE",
            ".github/frameleaf-release.cjs",
            ".github/verify-release-bundle.cjs",
            "cosign.pub",
        ],
        cwd=source,
        env=env,
    )
    snapshot = work / "source"
    snapshot.mkdir(mode=0o700)
    with tarfile.open(archive) as contents:
        contents.extractall(snapshot, filter="data")
    manager = snapshot / "manager"
    shutil.copy2(snapshot / "LICENSE", manager / "LICENSE")
    receipt = {
        "schemaVersion": 1,
        "sourceRevision": revision,
        "sourceArchiveSha256": sha256(archive),
        "lockfileSha256": sha256(manager / "package-lock.json"),
        "nodeVersion": "26.11.1",
        "nodeSha256": sha256(node),
        "npmVersion": run([npm, "--version"], cwd=work, env=env),
        "qualification": "failed",
        "runtimeQualified": False,
        "redistributable": False,
    }
    with (output / "build.log").open("w") as log:

        def command(arguments):
            log.write(run(arguments, cwd=manager, env=env) + "\n")
            log.flush()

        try:
            command([npm, "ci", "--ignore-scripts", "--workspaces=false"])
            command(
                [
                    node,
                    manager / "node_modules/@typescript/native/bin/tsc",
                    "-p",
                    "tsconfig.json",
                ]
            )
            command([node, manager / "node_modules/vite/bin/vite.js", "build"])
            command(
                [npm, "prune", "--omit=dev", "--ignore-scripts", "--workspaces=false"]
            )
            target = output / "manager"
            stage_manager(manager, target, revision)
            # Resolve all declared production imports from the deployed directory, not developer modules.
            probe = "import fs from 'node:fs';import{createRequire}from'node:module';import{pathToFileURL}from'node:url';const require=createRequire(pathToFileURL(process.argv[1]+'/package.json'));const p=JSON.parse(fs.readFileSync(process.argv[1]+'/package.json'));for(const name of Object.keys(p.dependencies))await import(pathToFileURL(require.resolve(name)));for(const name of ['app/build/releases.js','app/build/operations.js','.github/verify-release-bundle.cjs'])await import(pathToFileURL(process.argv[1]+'/'+name));console.log('Manager production and release imports resolved');"
            command([node, "--input-type=module", "--eval", probe, target])
            receipt["files"] = inventory(target)
            receipt["qualification"] = "passed"
        finally:
            (output / "qualification.json").write_text(
                json.dumps(receipt, indent=2) + "\n"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source", "revision", "node", "output"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        build(Path(args.source), args.revision, Path(args.node), Path(args.output))
    except (BuildError, OSError, ValueError, tarfile.TarError) as error:
        parser.exit(
            1,
            str(error)
            if isinstance(error, BuildError)
            else "host_manager_build_failed",
        )
