"""Sign the native host's Mach-O code before sealing its link-free inventory."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import plistlib
import posixpath
import stat
import subprocess
import unicodedata
import zipfile

from build_host_bundle import host_manifest
from sign_macos_runtime import native_code


def browser_archive(archive: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if not entries or len(entries) > 10_000 or sum(entry.file_size for entry in entries) > 1024**3:
            raise ValueError("Chromium archive exceeds its bundle limits")
        names, links = set(), set()
        for entry in entries:
            name = unicodedata.normalize("NFC", entry.filename.rstrip("/"))
            parts = name.split("/")
            mode = stat.S_IFMT(entry.external_attr >> 16)
            if (parts[0] != "Chromium.app" or any(part in ("", ".", "..") for part in parts)
                    or "\\" in name or name.casefold() in names
                    or mode not in (0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK)):
                raise ValueError("Invalid Chromium archive member")
            names.add(name.casefold())
            if mode == stat.S_IFLNK:
                if entry.file_size > 512 or entry.is_dir():
                    raise ValueError("Invalid Chromium framework link")
                target = bundle.read(entry).decode("utf-8")
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                if not resolved.startswith("Chromium.app/") or "\\" in target:
                    raise ValueError("Chromium framework link escapes the bundle")
                links.add(name.casefold())
        if any(any("/".join(name.split("/")[:index]) in links
                   for index in range(1, len(name.split("/")))) for name in names):
            raise ValueError("Chromium archive member traverses a framework link")


def sign(path: Path, identity: str, *, runtime: bool = True, entitlements: Path | None = None) -> None:
    args = ["/usr/bin/codesign", "--force", "--timestamp", "--sign", identity]
    if runtime:
        args.extend(["--options", "runtime"])
    if entitlements is not None:
        args.extend(["--entitlements", entitlements])
    subprocess.run([*args, path], check=True)
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", path], check=True)


def prepare(candidate: Path, controller: Path, work: Path, identity: str) -> None:
    payload = candidate / "payload"
    manifest = json.loads((candidate / "manifest.json").read_bytes())
    if (manifest.get("platform") != "macos" or manifest.get("architecture") != "aarch64"
            or manifest != host_manifest(payload, manifest["sourceRevision"], manifest["epoch"])):
        raise ValueError("Unsigned Apple Silicon host inventory changed")
    archive = payload / "browser" / "Chromium.zip"
    browser_archive(archive)
    work.mkdir(mode=0o700)
    subprocess.run(["/usr/bin/ditto", "-x", "-k", archive, work], check=True)

    # Chromium's renderer and GPU helpers and the bundled Node interpreter use JIT.
    jit = work / "jit.plist"
    jit.write_bytes(plistlib.dumps({"com.apple.security.cs.allow-jit": True}))
    app = work / "Chromium.app"
    framework = app / "Contents/Frameworks/Chromium Framework.framework"
    if not framework.is_dir() or framework.is_symlink():
        raise ValueError("Missing Chromium framework")
    helpers = sorted(framework.rglob("*.app"), key=lambda path: len(path.parts), reverse=True)
    if not helpers:
        raise ValueError("Missing Chromium helpers")

    # The nested ML inventory already carries its own release signature.
    with ThreadPoolExecutor(max_workers=4) as pool:
        code = (payload / name for name in manifest["files"] if not name.startswith("ml/"))
        list(pool.map(lambda path: sign(path, identity, entitlements=jit if path == payload / "node" else None),
                      (path for path in code if native_code(path))))
    sign(controller, identity)
    for leaf in framework.rglob("*"):
        if not leaf.is_symlink() and leaf.is_file() and not any(parent in helpers for parent in leaf.parents):
            if native_code(leaf) and leaf.name != "Chromium Framework":
                sign(leaf, identity)
    for helper in helpers:
        entitlements = jit if "Renderer" in helper.name or "GPU" in helper.name else None
        sign(helper, identity, entitlements=entitlements)
    sign(framework, identity, runtime=False)
    sign(app, identity)
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "--deep", app], check=True)


def finish(candidate: Path, work: Path) -> None:
    app = work / "Chromium.app"
    subprocess.run(["/usr/bin/xcrun", "stapler", "validate", app], check=True)
    archive = work / "Chromium-notarized.zip"
    subprocess.run(["/usr/bin/ditto", "-c", "-k", "--keepParent", app, archive], check=True)
    browser_archive(archive)
    check = work / "repacked"
    check.mkdir(mode=0o700)
    subprocess.run(["/usr/bin/ditto", "-x", "-k", archive, check], check=True)
    subprocess.run(["/usr/bin/xcrun", "stapler", "validate", check / "Chromium.app"], check=True)
    os.replace(archive, candidate / "payload/browser/Chromium.zip")
    path = candidate / "manifest.json"
    old = json.loads(path.read_bytes())
    manifest = host_manifest(candidate / "payload", old["sourceRevision"], old["epoch"])
    path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    pre = modes.add_parser("prepare")
    end = modes.add_parser("finish")
    for mode in (pre, end):
        mode.add_argument("--candidate", type=Path, required=True)
        mode.add_argument("--work", type=Path, required=True)
    pre.add_argument("--controller", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.candidate, args.controller, args.work, os.environ["APPLE_SIGNING_IDENTITY"])
    else:
        finish(args.candidate, args.work)
