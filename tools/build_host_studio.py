"""Authoring recipe for the pinned Studio worker; excludes the private browser."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import tarfile
from pathlib import Path

from build_host_server import stage_server
from build_runtime import BuildError, build_environment, run, sha256



# Pin the authoring adapters separately; the prepared engine and its attestation stay unchanged.
_WINDOWS_AUTHORING_INPUTS = {
    "engine.mjs": "d52283295d8437229289c3956679e2daca9cea49d1386dbcd8a63e54f80ae627",
    "adapter.mjs": "d6670c9e97d2176734200f82a6c680e38807578761584f178760332d8d7d9581",
    "vite.config.mjs": "055c98e461916cf58ffcbc93c78f3c50dd72a0f28d35b1dbcdc0f234f26357cb",
}


def adapt_authoring_command(name: str, source: str) -> str:
    replacements = {
        "engine.mjs": [
            ("execFileSync('npm', ['--version'],",
             "execFileSync(process.execPath, [process.env.npm_execpath, '--version'],"),
        ],
        "adapter.mjs": [
            ("path.join(workspace, 'node_modules/.bin/vp')",
             "path.join(workspace, 'node_modules/vite-plus/bin/vp')"),
            ("execFileSync(vp, vpArgs,",
             "execFileSync(process.execPath, [vp, ...vpArgs],"),
        ],
        "vite.config.mjs": [
            ("import path from 'node:path'",
             "import path from 'node:path'\nconst normalizeVitePath = value => value.replaceAll('\\\\', '/')"),
            ("import { fileURLToPath } from 'node:url'",
             "import { fileURLToPath, pathToFileURL } from 'node:url'"),
            ("import(engineRequire.resolve('@tailwindcss/vite'))",
             "import(pathToFileURL(engineRequire.resolve('@tailwindcss/vite')).href)"),
            ("source.startsWith('/')", "path.isAbsolute(source)"),
            ("!importer.startsWith(here) || importer.startsWith(engine)",
             "!normalizeVitePath(importer).startsWith(normalizeVitePath(here)) || normalizeVitePath(importer).startsWith(normalizeVitePath(engine))"),
            ("this.resolve(source, path.join(engine, 'src/main.tsx'),",
             "this.resolve(source, normalizeVitePath(path.join(engine, 'src/main.tsx')),"),
            ("importer === persistenceShim",
             "normalizeVitePath(importer) === normalizeVitePath(persistenceShim)"),
            ("resolved?.id === persistenceModule",
             "resolved && normalizeVitePath(resolved.id) === normalizeVitePath(persistenceModule)"),
            ("resolved?.id === upstreamWorkspaceDouble",
             "resolved && normalizeVitePath(resolved.id) === normalizeVitePath(upstreamWorkspaceDouble)"),
            ("? persistenceShim : null", "? normalizeVitePath(persistenceShim) : null"),
            ("? adapterWorkspaceDouble : null", "? normalizeVitePath(adapterWorkspaceDouble) : null"),
            ("closeBundle() {", "writeBundle() {"),
        ],
    }
    if name not in replacements:
        raise BuildError("host_studio_authoring_source_changed")
    for before, after in replacements[name]:
        if source.count(before) != 1:
            raise BuildError("host_studio_authoring_source_changed")
        source = source.replace(before, after)
    return source


def bind_authoring_commands(snapshot: Path) -> dict:
    staged = {}
    for name, expected in _WINDOWS_AUTHORING_INPUTS.items():
        directory = "studio/adapters/web" if name == "vite.config.mjs" else "studio/tools"
        source = snapshot / directory / name
        if sha256(source) != expected:
            raise BuildError("host_studio_authoring_source_changed")
        staged[name] = (source, adapt_authoring_command(name, source.read_text(encoding="utf-8")).encode("utf-8"))
    report = {}
    for name, (source, data) in staged.items():
        source.write_bytes(data)
        report[name] = {"originalSha256": _WINDOWS_AUTHORING_INPUTS[name],
                        "adaptedSha256": sha256(source)}
    return {"sourceRevision": "9bbe7c64e720fceee2fcba0f72055c945f56b19a", "scripts": report}


def stage_studio(source: Path, destination: Path) -> dict:
    files = stage_server(source, destination)
    required = {
        "LICENSE",
        "studio/engine-build.json",
        "studio/runtime/subtitle-sidecar.mjs",
        "studio/runtime/admission-font.ttf",
        "studio/runtime/admission-font.json",
        "studio/engine/package.json",
        "studio/engine/LICENSE",
        "studio/engine/frameleaf-build.json",
        "studio/engine/dist/headless.html",
        "studio/engine/headless/server.mjs",
        "studio/engine/headless/lib/cli.mjs",
        "studio/engine/headless/lib/render-core.mjs",
        "studio/guard/studio-browser-guard",
        "studio/guard/studio-browser-guard.mjs",
        *{
            "studio/tools/" + name + ".mjs"
            for name in [
                "bundled-worker",
                "bundled-worker-client",
                "bundled-worker-executor",
                "bundled-worker-formats",
                "bundled-worker-fonts",
                "render-worker-font-inputs",
                "bundled-worker-recipe",
                "bundled-worker-renderer",
            ]
        },
        *{
            "studio/engine/node_modules/" + name + "/package.json"
            for name in ["playwright", "playwright-core", "zod"]
        },
    }
    fonts = [
        name
        for name in files
        if name.startswith("fonts/") and Path(name).suffix.lower() in {".ttf", ".otf"}
    ]
    if not required.issubset(files) or not fonts:
        raise BuildError("host_studio_entries_missing")
    if os.name != "nt" and not os.access(
        destination / "studio/guard/studio-browser-guard", os.X_OK
    ):
        raise BuildError("host_studio_guard_not_executable")
    for name in fonts:
        with (destination / name).open("rb") as stream:
            if stream.read(4) not in {b"\x00\x01\x00\x00", b"OTTO", b"ttcf"}:
                raise BuildError("host_studio_font_invalid")
    identity = json.loads(
        (destination / "studio/runtime/admission-font.json").read_text()
    )
    if (
        identity.get("schemaVersion") != 1
        or identity.get("sourceFile") != "inter-latin-400-normal.ttf"
        or identity.get("sha256")
        != sha256(destination / "studio/runtime/admission-font.ttf")
    ):
        raise BuildError("host_studio_admission_font_invalid")
    return files


def build(source: Path, revision: str, node: Path, output: Path) -> None:
    if not re.fullmatch(r"[a-f0-9]{40}", revision) or not all(
        path.is_absolute() for path in [source, node, output]
    ):
        raise BuildError("host_studio_source_invalid")
    if output.exists() or output.is_symlink():
        raise BuildError("host_studio_output_invalid")
    git, bootstrap = shutil.which("git"), shutil.which("npm")
    if not git or not bootstrap or not node.is_file():
        raise BuildError("host_studio_build_tools_missing")
    output.mkdir(mode=0o700)
    work = output / "work"
    work.mkdir(mode=0o700)
    env = build_environment(work, os.environ)
    env["PATH"] = os.pathsep.join(
        [str(node.parent), str(Path(bootstrap).parent), str(Path(git).parent), env["PATH"]]
    )
    env["FRAMELEAF_BUILD_ERROR_LOG"] = str(output / "command-error.log")
    env["PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD"] = "1"
    env["RAYON_NUM_THREADS"] = "1"
    env["TOKIO_WORKER_THREADS"] = "1"
    if run([node, "--version"], cwd=work, env=env) != "v26.11.1":
        raise BuildError("host_studio_node_unapproved")
    archive = work / "source.tar"
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
            "LICENSE",
            "studio",
            "server/resources/studio-fonts",
            "server/src/utils/studio-fonts.generated.ts",
            "scripts/frameleaf-studio-contracts.mjs",
            "scripts/frameleaf-studio-rights.mjs",
        ],
        cwd=source,
        env=env,
    )
    snapshot = work / "source"
    snapshot.mkdir(mode=0o700)
    with tarfile.open(archive) as contents:
        contents.extractall(snapshot, filter="data")
    configuration = json.loads((snapshot / "studio/engine-build.json").read_text())
    if (
        configuration.get("node") != "26.11.1"
        or not re.fullmatch(r"\d+\.\d+\.\d+", configuration.get("npm", ""))
        or not re.fullmatch(r"[a-f0-9]{40}", configuration.get("upstreamCommit", ""))
        or not re.fullmatch(r"[a-f0-9]{64}", configuration.get("sourceSha256", ""))
        or configuration.get("lockfileSha256")
        != sha256(snapshot / "studio/engine-package-lock.json")
    ):
        raise BuildError("host_studio_toolchain_invalid")
    report = {
        "schemaVersion": 1,
        "sourceRevision": revision,
        "sourceArchiveSha256": sha256(archive),
        "nodeSha256": sha256(node),
        "npmVersion": configuration["npm"],
        "studioLockfileSha256": configuration["lockfileSha256"],
        "platform": platform.system() + "-" + platform.machine(),
        "qualification": "failed",
        "runtimeQualified": False,
        "browserIncluded": False,
        "redistributable": False,
        "scope": "Studio worker JavaScript, headless harness, runtime packages and fonts only",
    }
    with (output / "build.log").open("w") as log:

        def command(arguments: list, cwd: Path = snapshot) -> None:
            log.write(run(arguments, cwd=cwd, env=env) + "\n")
            log.flush()

        try:
            tools = work / "npm-toolchain"
            tools.mkdir(mode=0o700)
            (tools / "package.json").write_text('{"private":true}\n')
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
            if run([node, npm, "--version"], cwd=work, env=env) != configuration["npm"]:
                raise BuildError("host_studio_npm_unapproved")
            report["npmCliSha256"] = sha256(npm)
            report["npmToolchainLockfileSha256"] = sha256(tools / "package-lock.json")
            env["PATH"] = str(tools / "node_modules/.bin") + os.pathsep + env["PATH"]
            if os.name == "nt":
                env["npm_execpath"] = str(npm)
                report["windowsAuthoringCommands"] = bind_authoring_commands(snapshot)
            command([node, "studio/tools/engine.mjs", "prepare"])
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
            command([node, npm, "--prefix", "studio/engine", "run", "build"])
            command([node, "studio/tools/engine.mjs", "attest"])
            engine = snapshot / "studio/engine"
            attestation = json.loads((engine / "frameleaf-build.json").read_text())
            for field in [
                "upstreamCommit",
                "sourceSha256",
                "lockfileSha256",
                "patches",
            ]:
                if attestation.get(field) != configuration[field]:
                    raise BuildError("host_studio_attestation_mismatch")
            report["engineAttestationSha256"] = sha256(engine / "frameleaf-build.json")
            packaged = work / "packaged"
            command([node, "studio/tools/bundled-worker-package.mjs", packaged])
            command(
                [
                    node,
                    "--input-type=module",
                    "--eval",
                    "import('./studio/tools/bundled-worker-package.mjs').then(({stageAdmissionFont}) => stageAdmissionFont(process.argv[1]))",
                    packaged,
                ]
            )
            shutil.copyfile(
                engine / "frameleaf-build.json",
                packaged / "studio/engine/frameleaf-build.json",
            )
            shutil.copyfile(snapshot / "LICENSE", packaged / "LICENSE")
            stage_server(snapshot / "server/resources/studio-fonts", packaged / "fonts")
            guardian = packaged / "studio/guard"
            guardian.mkdir(mode=0o700)
            report["guardianSha256"] = {}
            for name in ["studio-browser-guard", "studio-browser-guard.mjs"]:
                helper = Path(__file__).resolve().parent.parent / "runtime" / name
                shutil.copyfile(helper, guardian / name)
                report["guardianSha256"][name] = sha256(guardian / name)
            (guardian / "studio-browser-guard").chmod(0o755)
            report["files"] = stage_studio(packaged, output / "studio-worker")
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
    except (BuildError, OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(
            1,
            str(error) if isinstance(error, BuildError) else "host_studio_build_failed",
        )
