"""Bind a qualified native server package to its private Unix Perl runtime."""

from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path

from build_host_server import stage_server
from build_runtime import BuildError, inventory, regular, sha256


def adapt_exiftool(source: str, version: str) -> str:
    if version != "39.0.1":
        raise BuildError("host_exiftool_version_unapproved")
    replacements = {
        'const PERL = "/usr/bin/perl";': 'const PERL = require("node:path").resolve(__dirname, "../../../../perl/bin/perl");',
        "const result = await (0, Which_1.which)(PERL);": "const result = _fs.existsSync(PERL) ? PERL : undefined;",
        "const ignoreShebang = o.ignoreShebang ?? _ignoreShebang();": "const ignoreShebang = !(0, IsWin32_1.isWin32)();",
        "Perl must be installed. Please add perl to your $PATH and try again.": "Private ExifTool Perl runtime is missing",
    }
    for before, after in replacements.items():
        if source.count(before) != 1:
            raise BuildError("host_exiftool_vendor_source_changed")
        source = source.replace(before, after)
    return source


def build(server: Path, perl: Path, output: Path) -> None:
    if platform.system() not in {"Darwin", "Linux"}:
        raise BuildError("host_exiftool_target_unsupported")
    if (
        not all(path.is_absolute() for path in [server, perl, output])
        or output.exists()
        or output.is_symlink()
    ):
        raise BuildError("host_exiftool_output_invalid")
    receipts = {}
    for name, root in [("server", server), ("perl", perl)]:
        regular(root / "qualification.json")
        receipt = json.loads((root / "qualification.json").read_text())
        if receipt.get("qualification") != "passed" or not receipt.get("files"):
            raise BuildError("host_exiftool_input_unqualified")
        receipts[name] = receipt
    target = platform.system() + "-" + platform.machine()
    if any(receipt.get("platform") != target for receipt in receipts.values()):
        raise BuildError("host_exiftool_input_platform_mismatch")
    output.mkdir(mode=0o700)
    report = {
        "schemaVersion": 1,
        "platform": target,
        "sourceRevision": receipts["server"]["sourceRevision"],
        "perlSource": receipts["perl"]["source"],
        "qualification": "failed",
        "redistributable": False,
        "fullMediaConformance": False,
    }
    try:
        for name, root in [("server", server), ("perl", perl)]:
            if stage_server(root / name, output / name) != receipts[name]["files"]:
                raise BuildError("host_exiftool_input_inventory_mismatch")
        vendor = output / "server/node_modules/exiftool-vendored"
        version = json.loads((vendor / "package.json").read_text())["version"]
        module = vendor / "dist/ExifTool.js"
        regular(module)
        regular(output / "perl/bin/perl")
        regular(output / "server/node_modules/exiftool-vendored.pl/bin/exiftool")
        report["originalModuleSha256"] = sha256(module)
        module.write_text(adapt_exiftool(module.read_text(), version))
        report["adaptedModuleSha256"] = sha256(module)
        report["vendorVersion"] = version
        report["files"] = {
            name: inventory(output / name) for name in ["server", "perl"]
        }
        report["qualification"] = "passed"
    finally:
        (output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--perl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    try:
        build(options.server, options.perl, options.output)
    except (BuildError, OSError, ValueError, KeyError) as error:
        parser.exit(
            1,
            str(error)
            if isinstance(error, BuildError)
            else "host_exiftool_build_failed",
        )
