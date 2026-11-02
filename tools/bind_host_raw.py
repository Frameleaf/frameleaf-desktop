"""Combine qualified server and RAW packages with an exact shared engine contract."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
from pathlib import Path

from build_host_raw import raw_contract
from build_host_server import stage_server
from build_runtime import BuildError, build_environment, git_blob, regular, sha256


def build(source: Path, server: Path, raw: Path, output: Path) -> None:
    if not all(p.is_absolute() for p in [source, server, raw, output]) or output.exists() or output.is_symlink():
        raise BuildError("host_raw_binding_output_invalid")
    target = platform.system() + "-" + platform.machine()
    receipts = {}
    for name, root in [("server", server), ("raw", raw)]:
        regular(root / "qualification.json")
        receipt = json.loads((root / "qualification.json").read_text(encoding="utf-8"))
        if (not isinstance(receipt, dict) or receipt.get("qualification") != "passed"
                or not isinstance(receipt.get("files"), dict) or not receipt["files"]
                or not isinstance(receipt.get("sourceRevision"), str)
                or not re.fullmatch(r"[a-f0-9]{40}", receipt["sourceRevision"])):
            raise BuildError("host_raw_binding_input_unqualified")
        if receipt.get("platform") != target:
            raise BuildError("host_raw_binding_platform_mismatch")
        receipts[name] = receipt
    git = shutil.which("git")
    if not git:
        raise BuildError("host_raw_binding_git_missing")
    output.mkdir(mode=0o700)
    work = output / "work"
    work.mkdir(mode=0o700)
    env = build_environment(work, os.environ)
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(Path("NUL") if platform.system() == "Windows" else Path("/dev/null")),
               GIT_TERMINAL_PROMPT="0")
    report = {
        "schemaVersion": 1, "platform": target, "qualification": "failed",
        "sourceRevision": receipts["server"]["sourceRevision"],
        "rawEngineSourceRevision": receipts["raw"]["sourceRevision"],
        "serverReceiptSha256": sha256(server / "qualification.json"),
        "rawReceiptSha256": sha256(raw / "qualification.json"),
        "redistributable": False, "fullRawConformance": False,
        "installedPlatformQualified": False,
    }
    try:
        revision = report["sourceRevision"]
        patches = {name: git_blob(git, source, revision, "server/test/native/" + name, env)
                   for name in ["patch-darktable-lens.py", "patch-darktable-mask-geometry.py"]}
        pin = json.loads(git_blob(git, source, revision, "server/base-image/sources/darktable.json", env))
        libraw = json.loads(git_blob(git, source, revision, "server/base-image/sources/libraw.json", env))
        raw_contract(pin, patches, libraw)
        if receipts["raw"].get("source") != pin or receipts["raw"].get("librawSource") != libraw:
            raise BuildError("host_raw_binding_source_mismatch")
        report["rawSource"], report["librawSource"] = pin, libraw
        report["files"] = {}
        for name, root in [("server", server), ("raw", raw)]:
            files = stage_server(root / name, output / name)
            if files != receipts[name]["files"]:
                raise BuildError("host_raw_binding_inventory_mismatch")
            report["files"][name] = files
        report["qualification"] = "passed"
    finally:
        (output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source", "server", "raw", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    try:
        build(options.source, options.server, options.raw, options.output)
    except (BuildError, OSError, ValueError, KeyError) as error:
        parser.exit(1, str(error) if isinstance(error, BuildError) else "host_raw_binding_failed")
