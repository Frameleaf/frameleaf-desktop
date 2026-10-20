"""Assemble an unsigned complete host inventory; signing and installed qualification stay separate."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
from pathlib import Path

from build_host_server import stage_server
from build_host_backup import CONTRACT as BACKUP_CONTRACT, artifact as backup_artifact
from build_runtime import BuildError, build_environment, inventory, regular, run, sha256

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_HOST_FILES = (
    "backup/LICENSE",
    "backup/component.json",
    "studio/engine-build.json",
    "studio/guard/studio-browser-guard.mjs",
    "studio/tools/bundled-worker-fonts.mjs",
    "studio/tools/render-worker-font-inputs.mjs",
    "studio/runtime/admission-font.json",
    "studio/runtime/admission-font.ttf",
    "build/geodata/geodata-date.txt",
    "build/geodata/cities500.txt",
    "build/geodata/admin1CodesASCII.txt",
    "build/geodata/admin2Codes.txt",
    "build/geodata/countryInfo.txt",
    "build/geodata/ne_10m_admin_0_countries.geojson",
    "build/geodata/landmarks.ndjson.gz",
    "ml/manifest.sig",
    "manager/app/release-worker.cjs",
    "manager/app/media-copy.cjs",
    "manager/.github/frameleaf-release.cjs",
    "manager/.github/verify-release-bundle.cjs",
    "manager/cosign.pub",
    "manager/component.json",
    "manager/package.json",
    "manager/LICENSE",
    "manager/node_modules/@nestjs/common/package.json",
    "manager/node_modules/@nestjs/core/package.json",
    "manager/node_modules/@nestjs/platform-express/package.json",
    "manager/node_modules/express/package.json",
    "manager/node_modules/js-yaml/package.json",
    "manager/node_modules/reflect-metadata/package.json",
    "manager/node_modules/rxjs/package.json",
    "manager/node_modules/zod/package.json",
)


def host_entries() -> dict[str, str]:
    suffix = ".exe" if os.name == "nt" else ""
    library = {"Darwin": "dylib", "Linux": "so", "Windows": "dll"}[platform.system()]
    return {
        "node": "node" + suffix,
        "server": "server/dist/main.js",
        **{
            role: "pg/bin/" + binary + suffix
            for role, binary in {
                "postgres": "postgres",
                "initdb": "initdb",
                "pgDump": "pg_dump",
                "pgRestore": "pg_restore",
                "pgIsready": "pg_isready",
                "pgChecksums": "pg_checksums",
                "pgCtl": "pg_ctl",
                "createdb": "createdb",
                "psql": "psql",
            }.items()
        },
        # pgvector's Windows Makefile installs into PGROOT/lib.
        "vector": "pg/lib/vector.dll"
        if os.name == "nt"
        else "pg/lib/postgresql/vector." + library,
        "hdr": "media/image-hdr.node",
        "ffmpeg": "media-tools/ffmpeg" + suffix,
        "ffprobe": "media-tools/ffprobe" + suffix,
        "exiftool": "server/node_modules/exiftool-vendored.exe/bin/exiftool.exe"
        if os.name == "nt"
        else "server/node_modules/exiftool-vendored.pl/bin/exiftool",
        "rawRenderer": "raw/bin/darktable-cli" + suffix,
        "rawDecoder": "raw/bin/dcraw_emu" + suffix,
        "webIndex": "build/www/index.html",
        "studio": "studio/tools/bundled-worker.mjs",
        "studioBrowser": "browser/chrome-headless-shell" + suffix,
        "studioBrowserGuard": "studio/guard/studio-browser-guard",
        "corePlugin": "build/plugins/immich-plugin-core/manifest.json",
        "mlManifest": "ml/manifest.json",
        "manager": "manager/app/build/main.js",
        "managerWebIndex": "manager/app/ui/dist/index.html",
        "backupEngine": "backup/restic" + suffix,
    }


def backup_component(root: Path) -> dict:
    metadata = regular(root / "component.json")
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 16 * 1024:
        raise BuildError("host_backup_component_invalid")
    record = json.loads((root / "component.json").read_text())
    pin = backup_artifact(platform.system(), platform.machine())
    binary = "restic.exe" if os.name == "nt" else "restic"
    if (
        not isinstance(record, dict)
        or type(record.get("schemaVersion")) is not int
        or record.get("schemaVersion") != 1
        or record.get("name") != "restic"
        or record.get("version") != BACKUP_CONTRACT["version"]
        or record.get("source") != BACKUP_CONTRACT["source"]
        or record.get("artifact") != pin
        or record.get("qualification") != "passed"
        or record.get("runtimeQualified") is not False
        or record.get("redistributable") is not False
        or not isinstance(record.get("checks"), dict)
        or any(record["checks"].get(key) is not True for key in [
            "encryptedRepository", "wrongKeyRejected", "readDataCheck", "verifiedRestore"
        ])
    ):
        raise BuildError("host_backup_component_invalid")
    files = inventory(root)
    files.pop("component.json", None)
    if (
        set(files) != {binary, "LICENSE"}
        or files != record.get("files")
        or files[binary]["sha256"] != pin["binarySha256"]
        or files["LICENSE"]["sha256"] != BACKUP_CONTRACT["licenseSha256"]
    ):
        raise BuildError("host_backup_component_invalid")
    return record


def host_manifest(payload: Path, revision: str, epoch: int) -> dict:
    policy = json.loads((ROOT / "runtime/release-trust.json").read_text())
    floor = policy.get("minimumHostEpoch") if isinstance(policy, dict) else None
    if type(floor) is not int or floor < 1:
        raise BuildError("release_policy_invalid")
    if (
        not re.fullmatch(r"[a-f0-9]{40}", revision)
        or type(epoch) is not int
        or epoch < floor
    ):
        raise BuildError("host_bundle_identity_invalid")
    files = inventory(payload)
    if "host-agent.mjs" in files:
        raise BuildError("host_bundle_fixture_agent_forbidden")
    entries = host_entries()
    if not (set(entries.values()) | set(REQUIRED_HOST_FILES)).issubset(files):
        raise BuildError("host_bundle_component_missing")
    database = json.loads((ROOT / "runtime/host-database.json").read_text())
    result = {
        "schemaVersion": 1,
        "protocolVersion": 2,
        "epoch": epoch,
        "platform": {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}[
            platform.system()
        ],
        "architecture": {
            "arm64": "aarch64",
            "aarch64": "aarch64",
            "AMD64": "x86_64",
            "x86_64": "x86_64",
        }[platform.machine()],
        "sourceRevision": revision,
        "nodeVersion": "26.11.1",
        "postgresVersion": database["postgresVersion"],
        "vectorVersion": database["pgvectorVersion"],
        "certified": database["certified"],
        "entryPoints": entries,
        "files": files,
    }
    if len(json.dumps(result, separators=(",", ":")).encode()) > 16 * 1024 * 1024:
        raise BuildError("host_bundle_manifest_too_large")
    return result


def assemble(
    host: Path, ml: Path, manager: Path, backup: Path, output: Path, revision: str, epoch: int
) -> None:
    if (
        not all(p.is_absolute() for p in [host, ml, manager, backup, output])
        or output.exists()
        or output.is_symlink()
        or output.resolve().is_relative_to(host.resolve())
        or output.resolve().is_relative_to(ml.resolve())
        or output.resolve().is_relative_to(manager.resolve())
        or output.resolve().is_relative_to(backup.resolve())
    ):
        raise BuildError("host_bundle_paths_invalid")
    regular(host)
    regular(ml)
    regular(manager)
    regular(backup)
    component_file = manager / "component.json"
    metadata = regular(component_file)
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 16 * 1024:
        raise BuildError("host_manager_component_invalid")
    component = json.loads(component_file.read_text())
    if (
        not isinstance(component, dict)
        or set(component)
        != {
            "schemaVersion",
            "sourceRevision",
            "nodeVersion",
            "lockfileSha256",
            "runtimeQualified",
            "redistributable",
        }
        or type(component["schemaVersion"]) is not int
        or component["schemaVersion"] != 1
        or component["nodeVersion"] != "26.11.1"
        or not isinstance(component["sourceRevision"], str)
        or not re.fullmatch(r"[a-f0-9]{40}", component["sourceRevision"])
        or not isinstance(component["lockfileSha256"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", component["lockfileSha256"])
        or component["runtimeQualified"] is not False
        or component["redistributable"] is not False
    ):
        raise BuildError("host_manager_component_invalid")
    backup_record = backup_component(backup)
    output.mkdir(mode=0o700)
    work = output / "work"
    work.mkdir(mode=0o700)
    env = build_environment(work, {})
    node = host / host_entries()["node"]
    if run([node, "--version"], cwd=work, env=env) != "v26.11.1":
        raise BuildError("host_bundle_node_unapproved")
    verify_script = (ROOT / "tools/sign_runtime.mjs").as_uri()
    verifier = [
        node,
        "--input-type=module",
        "--eval",
        f"import({json.dumps(verify_script)}).then(async (m) => {{ const r = await m.verifySignedCandidate(process.argv[1]); console.log(JSON.stringify({{platform:r.manifest.platform,architecture:r.manifest.architecture,epoch:r.manifest.epoch,sourceRevision:r.manifest.sourceRevision,keyId:r.keyId,manifestSha256:r.manifestSha256}})); }})",
    ]
    checked = json.loads(run([*verifier, ml], cwd=work, env=env))
    payload = output / "payload"
    payload.mkdir(mode=0o700)
    directories = [
        "server",
        "pg",
        "libraries",
        "media",
        "build",
        "raw",
        "media-tools",
        "studio",
        "fonts",
        "browser",
    ]
    if os.name != "nt":
        directories.append("perl")
    for name in directories:
        stage_server(host / name, payload / name)
    stage_server(manager, payload / "manager")
    stage_server(backup, payload / "backup")
    if backup_component(payload / "backup") != backup_record:
        raise BuildError("host_backup_component_changed")
    shutil.copy2(node, payload / node.name)
    (payload / "ml").mkdir(mode=0o700)
    stage_server(ml / "payload", payload / "ml/payload")
    for name in ["manifest.json", "manifest.sig"]:
        shutil.copy2(ml / name, payload / "ml" / name)
    if json.loads(run([*verifier, payload / "ml"], cwd=work, env=env)) != checked:
        raise BuildError("host_bundle_ml_changed")
    manifest = host_manifest(payload, revision, epoch)
    if any(checked[key] != manifest[key] for key in ["platform", "architecture"]):
        raise BuildError("host_bundle_ml_target_mismatch")
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    (output / "manifest.json").write_bytes(raw)
    (output / "qualification.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "qualification": "passed",
                "sourceRevision": revision,
                "files": len(manifest["files"]),
                "manifestBytes": len(raw),
                "manifestSha256": sha256(output / "manifest.json"),
                "ml": checked,
                "manager": component,
                "backup": backup_record,
                "signaturePresent": False,
                "runtimeQualified": False,
                "redistributable": False,
                "scope": "Complete unsigned inventory with approved signed nested ML candidate; no installed-host or release acceptance",
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["host", "ml", "manager", "backup", "output", "revision"]:
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--epoch", required=True, type=int)
    args = parser.parse_args()
    try:
        assemble(
            Path(args.host),
            Path(args.ml),
            Path(args.manager),
            Path(args.backup),
            Path(args.output),
            args.revision,
            args.epoch,
        )
    except (BuildError, OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")
