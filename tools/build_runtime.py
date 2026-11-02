"""Construct an unsigned, pinned private ML runtime; release signing is a separate authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


class BuildError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def relative(value: str) -> str:
    if not value or len(value) > 4096 or "\\" in value or ":" in value:
        raise BuildError("runtime_path_invalid")
    for part in value.split("/"):
        stem = part.split(".")[0].upper()
        if (
            part in {"", ".", ".."}
            or part.endswith((".", " "))
            or any(ord(char) < 32 or ord(char) == 127 for char in part)
            or stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
            or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem)
        ):
            raise BuildError("runtime_path_invalid")
    return value


def regular(path: Path) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise BuildError("runtime_link_forbidden")
    return info


def inventory(root: Path) -> dict[str, dict[str, str | int]]:
    files = {}
    folded = set()
    total = 0
    for count, path in enumerate(sorted(root.rglob("*")), 1):
        if count > 100_000:
            raise BuildError("runtime_inventory_limit")
        info = regular(path)
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise BuildError("runtime_special_file_forbidden")
        name = relative(path.relative_to(root).as_posix())
        total += info.st_size
        if name.lower() in folded:
            raise BuildError(f"runtime_case_collision:{name[:256]}")
        if info.st_size > 16 * 1024**3 or total > 64 * 1024**3:
            raise BuildError("runtime_inventory_size_invalid")
        folded.add(name.lower())
        files[name] = {"sha256": sha256(path), "bytes": info.st_size}
    if not files:
        raise BuildError("runtime_inventory_empty")
    return files


def copy_python(source: Path, destination: Path) -> None:
    source = source.resolve(strict=True)
    # Standalone Python's aliases are internal; flatten them so the installer never adopts links.
    for path in source.rglob("*"):
        if path.is_symlink() and (
            not path.resolve(strict=True).is_relative_to(source)
            or not path.resolve().is_file()
        ):
            raise BuildError("runtime_python_link_escape")
    # Linux terminfo contains E/Eterm and e/eterm; this fixed-module headless runtime never uses it.
    shutil.copytree(
        source,
        destination,
        symlinks=False,
        ignore=lambda directory, _names: (
            {"terminfo"} if Path(directory) == source / "share" else set()
        ),
    )


def downloaded_python(root: Path) -> Path:
    prefixes = [
        path
        for path in root.iterdir()
        if path.name.startswith("cpython-")
        and path.is_dir()
        and not path.is_symlink()
        and not getattr(path.lstat(), "st_file_attributes", 0) & 0x400
    ]
    if len(prefixes) != 1:
        raise BuildError("runtime_python_inventory_invalid")
    return prefixes[0]


def source_package(tracked: list[str]) -> str:
    namespaces = {
        name.split("/")[1] for name in tracked if name.startswith("machine-learning/")
    }
    if len(namespaces) != 1 or not namespaces <= {"immich_ml", "frameleaf_ml"}:
        raise BuildError("runtime_source_package_invalid")
    namespace = next(iter(namespaces))
    required = {
        f"machine-learning/{namespace}/{name}"
        for name in ["__init__.py", "native_runtime.py", "native_qualification.py"]
    }
    if not required <= set(tracked):
        raise BuildError("runtime_source_package_invalid")
    return namespace


def manifest(
    root: Path,
    python: str,
    revision: str,
    epoch: int,
    system: str,
    architecture: str,
    provider: str,
    module_namespace: str = "immich_ml",
) -> dict:
    relative(python)
    if (
        not re.fullmatch(r"[a-f0-9]{40}", revision)
        or not 1 <= epoch < 2**63
        or module_namespace not in {"immich_ml", "frameleaf_ml"}
        or system not in {"macos", "windows", "linux"}
        or architecture not in {"aarch64", "x86_64"}
        or not (
            provider == "CPUExecutionProvider"
            or (
                provider == "CoreMLExecutionProvider"
                and system == "macos"
                and architecture == "aarch64"
            )
        )
    ):
        raise BuildError("runtime_manifest_invalid")
    files = inventory(root)
    if python not in files:
        raise BuildError("runtime_interpreter_missing")
    return {
        "schemaVersion": 1,
        "protocolVersion": 1,
        "epoch": epoch,
        "platform": system,
        "architecture": architecture,
        "provider": provider,
        "python": python,
        "sourceRevision": revision,
        **(
            {"moduleNamespace": module_namespace}
            if module_namespace == "frameleaf_ml"
            else {}
        ),
        "files": files,
    }


def build_environment(work: Path, inherited: dict[str, str]) -> dict[str, str]:
    home = work / "home"
    home.mkdir(exist_ok=True, mode=0o700)
    env = {
        "PATH": os.defpath,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "UV_CACHE_DIR": str(work / "uv-cache"),
        "UV_COMPILE_BYTECODE": "0",
        "UV_PYTHON_DOWNLOADS": "manual",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(work),
        "TMP": str(work),
        "TEMP": str(work),
        "HF_HOME": str(work / "huggingface"),
        "HF_HUB_DISABLE_TELEMETRY": "1",
    }
    # Python normalizes Windows environment keys to uppercase.
    system_root = next(
        (value for key, value in inherited.items() if key.upper() == "SYSTEMROOT"), None
    )
    if os.name == "nt" and system_root:
        env["SystemRoot"] = system_root
        env["PATH"] = str(Path(system_root) / "System32")
    return env


def run(arguments: list[str | Path], *, cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(
        arguments, cwd=cwd, env=env, text=True, capture_output=True, timeout=1200
    )
    if result.returncode:
        # Only approved, credential-free sources run here; keep detailed tool diagnostics local.
        Path(
            env.get(
                "FRAMELEAF_BUILD_ERROR_LOG",
                str(Path(env["HOME"]).parent / "command-error.log"),
            )
        ).write_text(result.stderr[-32_768:])
        raise BuildError(
            f"runtime_build_command_failed:{Path(arguments[0]).name}:{result.returncode}"
        )
    return result.stdout.strip()


def git_blob(
    git: str, root: Path, revision: str, name: str, env: dict[str, str]
) -> bytes:
    relative(name)
    mode = run(
        [git, "ls-tree", "--format=%(objectmode)", revision, "--", name],
        cwd=root,
        env=env,
    )
    if mode not in {"100644", "100755"}:
        raise BuildError("runtime_source_file_invalid")
    size = int(run([git, "cat-file", "-s", f"{revision}:{name}"], cwd=root, env=env))
    if size > 16 * 1024 * 1024:
        raise BuildError("runtime_source_file_too_large")
    result = subprocess.run(
        [git, "show", f"{revision}:{name}"],
        cwd=root,
        env=env,
        capture_output=True,
        timeout=30,
    )
    if result.returncode or len(result.stdout) != size:
        raise BuildError("runtime_source_file_invalid")
    return result.stdout


def validate_requirements(text: str) -> None:
    if "--hash=sha256:" not in text or "-e " in text or "file:" in text:
        raise BuildError("runtime_requirements_unpinned")
    for address in re.findall(r"https?://[^\s;\\]+", text):
        parsed = urlsplit(address)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.hostname
            not in {"pypi.org", "files.pythonhosted.org", "download.pytorch.org"}
        ):
            raise BuildError("runtime_dependency_source_unapproved")


def requirement_block(text: str, name: str) -> str:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line.startswith(name + "==")]
    if len(starts) != 1:
        raise BuildError("runtime_build_tool_not_pinned")
    index = starts[0]
    result = [lines[index]]
    while result[-1].rstrip().endswith("\\"):
        index += 1
        if index >= len(lines):
            raise BuildError("runtime_build_tool_not_pinned")
        result.append(lines[index])
    block = "\n".join(result) + "\n"
    if "--hash=sha256:" not in block:
        raise BuildError("runtime_build_tool_not_pinned")
    return block


def source_build_requirements(text: str) -> str:
    if not re.search(r"^antlr4-python3-runtime==", text, re.MULTILINE):
        return ""
    if not requirement_block(text, "antlr4-python3-runtime").startswith(
        "antlr4-python3-runtime==4.9.3 "
    ):
        raise BuildError("runtime_source_build_not_approved")
    return requirement_block(text, "setuptools")


def dependency_indexes(system: str, architecture: str) -> list[str]:
    # Linux CPU wheels use the dedicated feed; keep Windows/macOS on their locked PyPI wheels.
    indexes = ["--default-index", "https://pypi.org/simple"]
    if system == "linux" and architecture in {"x86_64", "aarch64"}:
        indexes += [
            "--index",
            "https://download.pytorch.org/whl/cpu",
            "--index-strategy",
            "unsafe-best-match",
        ]
    return indexes


def build(
    source: Path, output: Path, revision: str, epoch: int, profile_name: str
) -> None:
    source = source.resolve(strict=True)
    output = output.absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise BuildError("runtime_output_must_be_new")
    if not re.fullmatch(r"[a-f0-9]{40}", revision) or not 1 <= epoch < 2**63:
        raise BuildError("runtime_manifest_invalid")
    profile = json.loads(
        (Path(__file__).parent.parent / "runtime/profiles.json").read_text()
    )["profiles"].get(profile_name)
    if not profile:
        raise BuildError("runtime_profile_unknown")
    system = {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}.get(
        platform.system(), "unsupported"
    )
    architecture = {
        "arm64": "aarch64",
        "aarch64": "aarch64",
        "AMD64": "x86_64",
        "x86_64": "x86_64",
    }.get(platform.machine(), "unsupported")
    if f"{system}-{architecture}" not in profile["targets"]:
        raise BuildError("runtime_target_unqualified")
    uv = shutil.which("uv")
    git = shutil.which("git")
    if not uv or not git:
        raise BuildError("runtime_build_tools_missing")
    with tempfile.TemporaryDirectory(
        prefix=f".{output.name}-", dir=output.parent
    ) as temporary:
        work = Path(temporary)
        env = build_environment(work, dict(os.environ))
        env["FRAMELEAF_BUILD_ERROR_LOG"] = str(
            output.parent / f".{output.name}.error.log"
        )
        remote = run([git, "remote", "get-url", "origin"], cwd=source, env=env)
        if remote not in {
            "https://github.com/Frameleaf/frameleaf-app.git",
            "https://github.com/Frameleaf/frameleaf-app",
            "git@github.com:Frameleaf/frameleaf-app.git",
        }:
            raise BuildError("runtime_source_repository_unapproved")
        if (
            not re.fullmatch(r"[a-f0-9]{40}", revision)
            or run([git, "rev-parse", "HEAD"], cwd=source, env=env) != revision
        ):
            raise BuildError("runtime_source_revision_mismatch")
        if run(
            [
                git,
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--",
                "machine-learning",
            ],
            cwd=source,
            env=env,
        ):
            raise BuildError("runtime_source_dirty")
        tracked = run(
            [
                git,
                "ls-tree",
                "-r",
                "--name-only",
                revision,
                "--",
                "machine-learning/immich_ml",
                "machine-learning/frameleaf_ml",
            ],
            cwd=source,
            env=env,
        ).splitlines()
        module_namespace = source_package(tracked)
        uv_version = run([uv, "--version"], cwd=work, env=env)
        if uv_version.split()[1] != profile["uv"]:
            raise BuildError("runtime_uv_version_mismatch")
        bundle = work / "bundle"
        bundle.mkdir()
        payload = bundle / "payload"
        payload.mkdir()
        requirements = payload / "requirements.txt"
        ml = work / "project"
        ml.mkdir()
        for name in ("pyproject.toml", "uv.lock", "README.md"):
            (ml / name).write_bytes(
                git_blob(git, source, revision, f"machine-learning/{name}", env)
            )
        run(
            [
                uv,
                "--no-config",
                "export",
                "--frozen",
                "--extra",
                profile["extra"],
                "--no-dev",
                "--no-emit-project",
                "--no-header",
                "--output-file",
                requirements,
            ],
            cwd=ml,
            env=env,
        )
        validate_requirements(requirements.read_text())
        downloads = work / "python-downloads"
        run(
            [
                uv,
                "--no-config",
                "python",
                "install",
                profile["python"],
                "--install-dir",
                downloads,
                "--no-bin",
                "--no-registry",
            ],
            cwd=work,
            env=env,
        )
        prefix = payload / "python"
        copy_python(downloaded_python(downloads), prefix)
        original_commands = set(
            (prefix / ("Scripts" if os.name == "nt" else "bin")).glob("*")
        )
        executable = prefix / (
            "python.exe"
            if os.name == "nt"
            else f"bin/python{'.'.join(profile['python'].split('.')[:2])}"
        )
        build_tools = payload / "build-requirements.txt"
        build_tools.write_text(source_build_requirements(requirements.read_text()))
        # Only the legacy lock-hashed ANTLR dependency may execute a source backend.
        if build_tools.stat().st_size:
            run(
                [
                    uv,
                    "--no-config",
                    "pip",
                    "install",
                    "--python",
                    executable,
                    "--break-system-packages",
                    "--require-hashes",
                    "--no-deps",
                    "--only-binary",
                    ":all:",
                    "-r",
                    build_tools,
                ],
                cwd=work,
                env=env,
            )
        run(
            [
                uv,
                "--no-config",
                "pip",
                "install",
                "--python",
                executable,
                "--break-system-packages",
                "--require-hashes",
                "--no-deps",
                "--only-binary",
                ":all:",
                *(
                    [
                        "--no-binary",
                        "antlr4-python3-runtime",
                        "--no-build-isolation-package",
                        "antlr4-python3-runtime",
                    ]
                    if build_tools.stat().st_size
                    else []
                ),
                *dependency_indexes(system, architecture),
                "-r",
                requirements,
            ],
            cwd=work,
            env=env,
        )

        commands = prefix / ("Scripts" if os.name == "nt" else "bin")
        # Console entry points embed the build path; the app uses only fixed Python modules.
        for command in commands.glob("*"):
            if command not in original_commands:
                if not command.is_file() or command.is_symlink():
                    raise BuildError("runtime_console_artifact_invalid")
                command.unlink()
        paths = json.loads(
            run(
                [
                    executable,
                    "-I",
                    "-B",
                    "-c",
                    "import json,sys,sysconfig; print(json.dumps({'version':sys.version.split()[0],'site':sysconfig.get_path('purelib')}))",
                ],
                cwd=work,
                env=env,
            )
        )
        if paths["version"] != profile["python"] or not Path(
            paths["site"]
        ).resolve().is_relative_to(prefix.resolve()):
            raise BuildError("runtime_python_prefix_escape")
        site = Path(paths["site"])
        for name in tracked:
            relative(name)
            target = site / Path(name).relative_to("machine-learning")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(git_blob(git, source, revision, name, env))
        notices = payload / "licenses"
        notices.mkdir()
        (notices / "Frameleaf-AGPL-3.0.txt").write_bytes(
            git_blob(git, source, revision, "LICENSE", env)
        )
        third_party = source / "licenses/THIRD-PARTY-NOTICES.md"
        if third_party.is_file():
            (notices / third_party.name).write_bytes(
                git_blob(git, source, revision, "licenses/THIRD-PARTY-NOTICES.md", env)
            )
        receipt = {
            "schemaVersion": 1,
            "sourceRepository": "Frameleaf/frameleaf-app",
            "sourceRevision": revision,
            "uv": uv_version,
            "uvExecutableSha256": sha256(Path(uv).resolve()),
            "python": profile["python"],
            "profile": profile_name,
            "lockSha256": sha256(ml / "uv.lock"),
            "projectSha256": sha256(ml / "pyproject.toml"),
            "requirementsSha256": sha256(requirements),
            "buildRequirementsSha256": sha256(build_tools),
            "sourceBuildAllowlist": ["antlr4-python3-runtime==4.9.3"]
            if build_tools.stat().st_size
            else [],
        }
        (payload / "provenance.json").write_text(
            json.dumps(receipt, sort_keys=True) + "\n"
        )
        relocated = work / "relocated-bundle"
        python_relative = executable.relative_to(payload)
        bundle.rename(relocated)
        bundle = relocated
        payload = bundle / "payload"
        executable = payload / python_relative
        smoke_env = {**env, "MACHINE_LEARNING_MODEL_DOWNLOADS": "false"}
        smoke = json.loads(
            run(
                [
                    executable,
                    "-I",
                    "-B",
                    "-c",
                    "import json,sys,onnxruntime; "
                    f"import {module_namespace}.native_runtime,{module_namespace}.native_qualification; "
                    "print(json.dumps({'prefix':sys.prefix,'providers':onnxruntime.get_available_providers()}))",
                ],
                cwd=work,
                env=smoke_env,
            )
        )
        if (
            Path(smoke["prefix"]).resolve() != (payload / "python").resolve()
            or profile["provider"] not in smoke["providers"]
        ):
            raise BuildError("runtime_relocation_failed")
        value = manifest(
            payload,
            executable.relative_to(payload).as_posix(),
            revision,
            epoch,
            system,
            architecture,
            profile["provider"],
            module_namespace,
        )
        (bundle / "manifest.json").write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        )
        if run([git, "rev-parse", "HEAD"], cwd=source, env=env) != revision:
            raise BuildError("runtime_source_revision_changed")
        # Immutable Git blobs preserve the preprocessing identity on CRLF checkouts too.
        if run(
            [
                git,
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--",
                "machine-learning",
            ],
            cwd=source,
            env=env,
        ):
            raise BuildError("runtime_source_changed_during_build")
        bundle.rename(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--epoch", type=int, required=True)
    parser.add_argument("--profile", default="cpu-ort")
    args = parser.parse_args()
    try:
        build(args.source, args.output, args.revision, args.epoch, args.profile)
    except (BuildError, OSError, subprocess.SubprocessError) as error:
        parser.exit(
            1, f"{error if isinstance(error, BuildError) else 'runtime_build_failed'}\n"
        )
    print(
        "Unsigned private runtime constructed; signing, installation and hardware acceptance remain separate"
    )


if __name__ == "__main__":
    main()
