"""Sign the native code embedded in the verified private Python runtime before sealing it."""

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from build_runtime import sha256

MACH_HEADERS = {bytes.fromhex(magic) for magic in (
    "feedface", "cefaedfe", "feedfacf", "cffaedfe",
    "cafebabe", "bebafeca", "cafebabf", "bfbafeca",
)}


def native_code(path: Path) -> bool:
    with path.open("rb") as stream:
        if stream.read(4) not in MACH_HEADERS:
            return False
    # Universal Mach-O shares its magic with Java bytecode. Exclude objects and static archives.
    kind = subprocess.run(["/usr/bin/file", "-b", path], check=True, capture_output=True, text=True).stdout
    return "Mach-O" in kind and any(label in kind for label in ("executable", "shared library", "bundle"))


def sign_runtime(root: Path, identity: str) -> None:
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    payload = root / "payload"
    paths = [name for name in manifest["files"] if native_code(payload / name)]
    if manifest["python"] not in paths:
        raise ValueError("missing Mach-O runtime interpreter")

    def sign(name):
        path = payload / name
        subprocess.run(["/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp",
                        "--sign", identity, path], check=True)
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", path], check=True)
        return name, {"bytes": path.stat().st_size, "sha256": sha256(path)}

    with ThreadPoolExecutor(max_workers=4) as pool:
        manifest["files"].update(pool.map(sign, paths))
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    # The accelerated manifest seals the same payload, so it takes the same signed inventory
    # (the CoreML collector's identity is the hash of its signed library).
    accelerated_path = root / "manifest-accelerated.json"
    if accelerated_path.exists():
        accelerated = json.loads(accelerated_path.read_bytes())
        if accelerated["files"].keys() != manifest["files"].keys():
            raise ValueError("accelerated manifest inventory differs")
        accelerated["files"] = manifest["files"]
        accelerated_path.write_text(json.dumps(accelerated, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    sign_runtime(Path(sys.argv[1]).resolve(), os.environ["APPLE_SIGNING_IDENTITY"])
