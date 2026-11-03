"""Combine qualified server and RAW packages with an exact shared engine contract."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
from pathlib import Path

from build_host_exiftool_windows import ADAPTED_MODULE_SHA256, VENDOR_MODULE_SHA256
from build_host_raw import raw_contract
from build_host_server import stage_server
from build_runtime import BuildError, build_environment, git_blob, regular, sha256


def read_receipt(path: Path) -> dict:
    info = regular(path)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 16 * 1024**2:
        raise BuildError("host_raw_binding_input_unqualified")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def build(source: Path, server: Path, raw: Path, output: Path) -> None:
    if not all(p.is_absolute() for p in [source, server, raw, output]) or output.exists() or output.is_symlink():
        raise BuildError("host_raw_binding_output_invalid")
    target = platform.system() + "-" + platform.machine()
    receipts, payload_files, metadata_proofs = {}, {}, {}
    for name, root in [("server", server), ("raw", raw)]:
        receipt = read_receipt(root / "qualification.json")
        if (not isinstance(receipt, dict) or receipt.get("qualification") != "passed"
                or not isinstance(receipt.get("files"), dict) or not receipt["files"]
                or not isinstance(receipt.get("sourceRevision"), str)
                or not re.fullmatch(r"[a-f0-9]{40}", receipt["sourceRevision"])):
            raise BuildError("host_raw_binding_input_unqualified")
        if receipt.get("platform") != target:
            raise BuildError("host_raw_binding_platform_mismatch")
        payload_files[name] = receipt["files"]
        if name == "server" and set(receipt["files"]) == {"server"}:
            original = read_receipt(root / "server-qualification.json")
            metadata = read_receipt(root / "metadata-qualification.json")
            adapted = receipt["files"]["server"]
            module = "node_modules/exiftool-vendored/dist/ExiftoolPath.js"
            try:
                original_files = original["files"]
                if (target != "Windows-AMD64" or original.get("qualification") != "passed"
                        or original.get("platform") != target
                        or original.get("sourceRevision") != receipt["sourceRevision"]
                        or not isinstance(original_files, dict) or not isinstance(adapted, dict)
                        or set(original_files) != set(adapted)
                        or {path for path in original_files if original_files[path] != adapted[path]} != {module}
                        or original_files[module]["sha256"] != VENDOR_MODULE_SHA256
                        or receipt.get("originalModuleSha256") != VENDOR_MODULE_SHA256
                        or adapted[module]["sha256"] != ADAPTED_MODULE_SHA256
                        or receipt.get("adaptedModuleSha256") != ADAPTED_MODULE_SHA256
                        or metadata.get("qualification") != "passed"
                        or metadata.get("componentReceiptSha256") != sha256(root / "qualification.json")
                        or metadata.get("sourceRevision") != receipt["sourceRevision"]
                        or any(record.get("vendorVersion") != "39.0.1"
                               or record.get("executableVendorVersion") != "13.59.3"
                               for record in [receipt, metadata])
                        or any(metadata.get(key) is not True for key in [
                            "metadataReadWrite", "unicodeMetadata", "locationFreeCopy",
                            "originalUnchanged", "decodedPixelsUnchanged", "missingPrivateExecutableRefused"
                        ])):
                    raise BuildError("host_raw_binding_metadata_invalid")
            except (KeyError, TypeError, AttributeError) as error:
                raise BuildError("host_raw_binding_metadata_invalid") from error
            payload_files[name] = adapted
            metadata_proofs = {
                "originalServerReceiptSha256": sha256(root / "server-qualification.json"),
                "metadataQualificationSha256": sha256(root / "metadata-qualification.json"),
            }
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
        "installedPlatformQualified": False, **metadata_proofs,
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
            if files != payload_files[name]:
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
