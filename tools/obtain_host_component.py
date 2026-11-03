"""Download an approved desktop producer artifact; component and installed qualification stay separate."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import threading

from build_host_ffmpeg import unpack
from build_runtime import BuildError, regular, sha256

REPOSITORY = "Frameleaf/frameleaf-desktop"
REPOSITORY_ID = 1421136454
MAX_ARCHIVE_BYTES = 2 * 1024**3


def validate_approval(approved: dict) -> None:
    """Accept only explicit immutable producer and archive identifiers."""
    if (not isinstance(approved, dict)
            or set(approved) != {"artifactId", "runId", "runAttempt", "headSha", "workflow", "archiveSha256"}
            or any(type(approved[key]) is not int or not 0 < approved[key] < 2**63
                   for key in ["artifactId", "runId", "runAttempt"])
            or not isinstance(approved["headSha"], str)
            or not re.fullmatch(r"[a-f0-9]{40}", approved["headSha"])
            or not isinstance(approved["archiveSha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", approved["archiveSha256"])
            or not isinstance(approved["workflow"], str)
            or not re.fullmatch(r"\.github/workflows/[a-z0-9_-]+\.ya?ml", approved["workflow"])):
        raise BuildError("host_component_approval_invalid")


def validate_producer(approved: dict, artifact: dict, run: dict) -> None:
    """Bind a reviewed archive digest to one successful workflow and its exact tool commit."""
    validate_approval(approved)
    if (not isinstance(artifact, dict) or not isinstance(run, dict)
            or not isinstance(artifact.get("workflow_run"), dict)
            or any(not isinstance(run.get(key), dict) for key in ["repository", "head_repository"])):
        raise BuildError("host_component_producer_invalid")
    try:
        started, created, finished = [datetime.fromisoformat(value) for value in [
            run.get("run_started_at"), artifact.get("created_at"), run.get("updated_at")]]
        if any(value.tzinfo is None for value in [started, created, finished]) or not started < created <= finished:
            raise ValueError()
    except (TypeError, ValueError):
        raise BuildError("host_component_artifact_attempt_mismatch") from None
    owner = artifact["workflow_run"]
    if (artifact.get("id") != approved["artifactId"]
            or artifact.get("expired") is not False
            or type(artifact.get("size_in_bytes")) is not int
            or not 0 < artifact["size_in_bytes"] <= MAX_ARCHIVE_BYTES
            or artifact.get("digest") != "sha256:" + approved["archiveSha256"]
            or owner.get("id") != approved["runId"]
            or owner.get("head_sha") != approved["headSha"]
            or owner.get("repository_id") != REPOSITORY_ID
            or owner.get("head_repository_id") != REPOSITORY_ID
            or run.get("id") != approved["runId"]
            or type(run.get("run_attempt")) is not int
            or run.get("run_attempt") != approved["runAttempt"]
            or run.get("head_sha") != approved["headSha"]
            or run.get("path") != approved["workflow"]
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or any(run[key].get("id") != REPOSITORY_ID
                   or run[key].get("full_name") != REPOSITORY for key in ["repository", "head_repository"])):
        raise BuildError("host_component_producer_mismatch")


def api(path: str) -> dict:
    data = subprocess.check_output(["gh", "api", f"repos/{REPOSITORY}/{path}"],
                                   stderr=subprocess.DEVNULL, timeout=30)
    if len(data) > 2 * 1024**2:
        raise BuildError("host_component_metadata_limit")
    return json.loads(data)


def download(approved: dict, archive: Path, size: int) -> None:
    """Bound the actual downloaded stream and deadline before validating its hash."""
    with subprocess.Popen(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{approved['artifactId']}/zip"],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as process:
        deadline = threading.Timer(300, process.kill)
        deadline.start()
        try:
            total = 0
            with archive.open("xb") as output:
                while chunk := process.stdout.read(1024**2):
                    total += len(chunk)
                    if total > size:
                        raise BuildError("host_component_download_size_mismatch")
                    output.write(chunk)
            if process.wait() != 0 or total != size:
                raise BuildError("host_component_download_failed")
        finally:
            deadline.cancel()
            if process.poll() is None:
                process.kill()
    if sha256(archive) != approved["archiveSha256"]:
        raise BuildError("host_component_archive_changed")


def obtain(approved: dict, output: Path) -> None:
    """Stage an identity-bound artifact without changing its original receipts or admitting its roles."""
    if (not output.is_absolute() or output.exists() or output.is_symlink()
            or not stat.S_ISDIR(regular(output.parent).st_mode)):
        raise BuildError("host_component_output_invalid")
    # Validate approval before using its identifiers in external requests.
    validate_approval(approved)
    artifact = api(f"actions/artifacts/{approved['artifactId']}")
    run = api(f"actions/runs/{approved['runId']}/attempts/{approved['runAttempt']}")
    validate_producer(approved, artifact, run)
    output.mkdir(mode=0o700)
    try:
        archive = output / "archive.zip"
        download(approved, archive, artifact["size_in_bytes"])
        component = output / "component"
        component.mkdir(mode=0o700)
        unpack(archive, component)
        archive.unlink()
        (output / "producer.json").write_text(json.dumps(
            {"approved": approved, "artifact": artifact, "run": run}, indent=2) + "\n")
    except Exception:
        shutil.rmtree(output)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if not stat.S_ISREG(regular(args.approval).st_mode) or args.approval.stat().st_size > 16 * 1024:
            raise BuildError("host_component_approval_invalid")
        obtain(json.loads(args.approval.read_text()), args.output)
    except (BuildError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) if isinstance(error, BuildError) else "host_component_acquisition_failed")
