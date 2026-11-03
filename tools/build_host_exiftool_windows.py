"""Bind a qualified Windows server to its complete private ExifTool runtime."""

from __future__ import annotations

import argparse
import json
import platform
import re
import stat
from pathlib import Path

from build_host_server import stage_server
from build_runtime import BuildError, inventory, regular, sha256

VENDOR_MODULE_SHA256 = "98dd924f2661a18188aae477acb9f74e767a3c1a9ba12d159c8b1ba90361079a"
# Deterministic adapter output for the fixed vendor blob; update both pins after source review.
ADAPTED_MODULE_SHA256 = "d748df3883e322944ce52fd5c764692f8071cddb12740a02a0c3b1fef087c577"


def adapt_exiftool_path(source: str, version: str) -> str:
    start = "async function exiftoolPath(logger) {"
    end = "//# sourceMappingURL=ExiftoolPath.js.map"
    if version != "39.0.1" or source.count(start) != 1 or source.count(end) != 1 or "Private ExifTool" in source:
        raise BuildError("host_exiftool_vendor_source_changed")
    before, body = source.split(start)
    _, after = body.split(end)
    newline = '\r\n' if '\r\n' in source else '\n'
    replacement = '''
    const executable = _path.resolve(__dirname, "../../exiftool-vendored.exe/bin/exiftool.exe");
    if (!_fs.existsSync(executable)) throw new Error("Private ExifTool executable is missing");
    return executable;
}
'''
    return before + start + replacement.replace('\n', newline) + end + after


def build(server: Path, output: Path) -> None:
    if platform.system() != "Windows" or platform.machine() != "AMD64":
        raise BuildError("host_exiftool_target_unsupported")
    if not all(path.is_absolute() for path in [server, output]) or output.exists() or output.is_symlink():
        raise BuildError("host_exiftool_output_invalid")
    regular(server / "qualification.json")
    receipt = json.loads((server / "qualification.json").read_text(encoding="utf-8"))
    if receipt.get("qualification") != "passed" or not receipt.get("files"):
        raise BuildError("host_exiftool_input_unqualified")
    if receipt.get("platform") != "Windows-AMD64":
        raise BuildError("host_exiftool_input_platform_mismatch")
    revision = receipt.get("sourceRevision")
    if not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise BuildError("host_exiftool_input_revision_invalid")
    output.mkdir(mode=0o700)
    report = {
        "schemaVersion": 1, "platform": "Windows-AMD64",
        "sourceRevision": revision, "qualification": "failed",
        "redistributable": False, "fullMediaConformance": False,
    }
    try:
        if stage_server(server / "server", output / "server") != receipt["files"]:
            raise BuildError("host_exiftool_input_inventory_mismatch")
        vendor = output / "server/node_modules/exiftool-vendored"
        executable_vendor = output / "server/node_modules/exiftool-vendored.exe"
        version = json.loads((vendor / "package.json").read_text(encoding="utf-8"))["version"]
        executable_version = json.loads((executable_vendor / "package.json").read_text(encoding="utf-8"))["version"]
        if executable_version != "13.59.3":
            raise BuildError("host_exiftool_executable_version_unapproved")
        for name in ["bin/exiftool.exe", "bin/exiftool_files/perl.exe", "bin/exiftool_files/perl532.dll",
                     "bin/exiftool_files/lib/Image/ExifTool.pm", "LICENSE", "bin/exiftool_files/LICENSE"]:
            if not stat.S_ISREG(regular(executable_vendor / name).st_mode):
                raise BuildError("host_exiftool_runtime_file_invalid")
        module = vendor / "dist/ExiftoolPath.js"
        regular(module)
        report["originalModuleSha256"] = sha256(module)
        if report["originalModuleSha256"] != VENDOR_MODULE_SHA256:
            raise BuildError("host_exiftool_vendor_source_changed")
        module.write_bytes(adapt_exiftool_path(module.read_bytes().decode("utf-8"), version).encode("utf-8"))
        report["adaptedModuleSha256"] = sha256(module)
        report["vendorVersion"] = version
        report["executableVendorVersion"] = executable_version
        report["files"] = {"server": inventory(output / "server")}
        report["qualification"] = "passed"
    finally:
        (output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    try:
        build(options.server, options.output)
    except (BuildError, OSError, ValueError, KeyError) as error:
        parser.exit(1, str(error) if isinstance(error, BuildError) else "host_exiftool_build_failed")
