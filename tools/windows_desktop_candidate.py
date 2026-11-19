"""Stage the approved Windows Desktop candidate for the real companion installer test."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import zipfile

from build_runtime import BuildError
from obtain_host_component import api, download, validate_approval, validate_producer

LEGACY_VERSION = "0.1.5"
LEGACY_RUNTIME_RUN = "42717141687"


def extract_desktop(archive: Path, output: Path, source: str, digest: str, *,
                    version: str = LEGACY_VERSION, runtime_run: str = LEGACY_RUNTIME_RUN,
                    signed: bool = False) -> dict:
    """Stage only the approved installer bytes for the downstream installation test."""
    if (not re.fullmatch(r"[a-f0-9]{40}", source) or not re.fullmatch(r"[a-f0-9]{64}", digest)
            or not re.fullmatch(r"[0-9]{1,8}\.[0-9]{1,8}\.[0-9]{1,8}", version)
            or not re.fullmatch(r"[1-9][0-9]{0,19}", runtime_run)):
        raise BuildError("desktop_candidate_identity_invalid")
    exe = f"Frameleaf_{version}_x64-setup.exe"
    msi = f"Frameleaf_{version}_x64_en-US.msi"
    expected = {exe, msi, "candidate.json", "SHA256SUMS"}
    with tarfile.open(archive, "r:gz") as package:
        files = {}
        for member in package:
            if member.name == "installers" and member.isdir():
                continue
            name = member.name.removeprefix("installers/")
            if (not member.name.startswith("installers/") or name not in expected or name in files
                    or not member.isfile() or not 0 < member.size <= (2 * 1024**3 if name in {exe, msi} else 16384)):
                raise BuildError("desktop_candidate_archive_invalid")
            files[name] = member
        if set(files) != expected:
            raise BuildError("desktop_candidate_archive_invalid")
        receipt = json.load(package.extractfile(files["candidate.json"]))
        if not isinstance(receipt, dict):
            raise BuildError("desktop_candidate_receipt_invalid")
        hashes = receipt.get("files")
        if (receipt.get("sourceRevision") != source or receipt.get("target") != "windows-x86_64"
                or receipt.get("runtimeRunId") != runtime_run or receipt.get("installedQualified") is not (not signed)
                or receipt.get("osSigned") is not signed or not isinstance(hashes, dict) or set(hashes) != {exe, msi}
                or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in hashes.values())
                or hashes[exe] != digest):
            raise BuildError("desktop_candidate_receipt_invalid")
        lines = package.extractfile(files["SHA256SUMS"]).read().decode().splitlines()
        pairs = [line.split() for line in lines]
        if len(pairs) != 2 or any(len(pair) != 2 for pair in pairs) or {pair[1]: pair[0] for pair in pairs} != hashes:
            raise BuildError("desktop_candidate_checksums_invalid")
        with package.extractfile(files[exe]) as binary, output.open("xb") as target:
            shutil.copyfileobj(binary, target)
    with output.open("rb") as binary:
        if hashlib.file_digest(binary, "sha256").hexdigest() != digest:
            raise BuildError("desktop_candidate_executable_changed")
    return receipt


def obtain() -> None:
    """Bind acquisition to a reviewed producer and a Desktop source already on main."""
    raw = os.environ["DESKTOP_APPROVAL"]
    if len(raw) > 16384:
        raise BuildError("desktop_candidate_identity_invalid")
    approved = json.loads(raw)
    source = approved.pop("sourceRevision", None)
    signed = "runtimeRunId" in approved
    runtime_run = approved.pop("runtimeRunId", LEGACY_RUNTIME_RUN)
    if not isinstance(runtime_run, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", runtime_run):
        raise BuildError("desktop_candidate_identity_invalid")
    if not isinstance(source, str) or not re.fullmatch(r"[a-f0-9]{40}", source):
        raise BuildError("desktop_candidate_identity_invalid")
    validate_approval(approved)
    if approved["workflow"] != ".github/workflows/installer-candidates.yml":
        raise BuildError("desktop_candidate_producer_invalid")
    subprocess.run(["git", "merge-base", "--is-ancestor", source, os.environ["GITHUB_SHA"]], check=True)
    artifact = api(f"actions/artifacts/{approved['artifactId']}")
    run = api(f"actions/runs/{approved['runId']}/attempts/{approved['runAttempt']}")
    validate_producer(approved, artifact, run)
    version = LEGACY_VERSION
    if signed:
        if source != approved["headSha"] or run.get("head_branch") != "main" or run.get("event") != "workflow_dispatch":
            raise BuildError("desktop_candidate_producer_invalid")
        package = json.loads(subprocess.check_output(
            ["git", "show", f"{source}:package.json"], timeout=10))
        version = package.get("version")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]{1,8}\.[0-9]{1,8}\.[0-9]{1,8}", version):
            raise BuildError("desktop_candidate_identity_invalid")
    if artifact["name"] != "frameleaf-installer-candidates-windows-x86_64":
        raise BuildError("desktop_candidate_producer_invalid")
    root = Path(os.environ["RUNNER_TEMP"]) / "windows-compiled-host"
    stage = root / "desktop"
    stage.mkdir(mode=0o700)
    archive = stage / "artifact.zip"
    download(approved, archive, artifact["size_in_bytes"])
    tar = stage / "installers.tar.gz"
    with zipfile.ZipFile(archive) as package:
        if package.namelist() != ["installer-candidates.tar.gz"] or not 0 < package.infolist()[0].file_size <= 2 * 1024**3:
            raise BuildError("desktop_candidate_archive_invalid")
        with package.open("installer-candidates.tar.gz") as binary, tar.open("xb") as target:
            shutil.copyfileobj(binary, target)
    receipt = extract_desktop(tar, stage / "setup.exe", source, os.environ["DESKTOP_SHA256"],
                              version=version, runtime_run=runtime_run, signed=signed)
    if signed:
        approved["runtimeRunId"] = runtime_run
    (root / "desktop-producer.json").write_text(json.dumps({
        "approval": {**approved, "sourceRevision": source}, "artifact": artifact,
        "candidate": receipt, "installerSha256": os.environ["DESKTOP_SHA256"],
    }, indent=2) + "\n")
    archive.unlink()
    tar.unlink()
    print("Approved Windows Desktop staged for companion acceptance")


if __name__ == "__main__":
    obtain()
