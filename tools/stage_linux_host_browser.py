"""Stage Debian's pinned Chromium headless browser for the Ubuntu x64 host."""

import argparse
from pathlib import Path
import platform
import shutil
import subprocess
from tempfile import TemporaryDirectory

from build_runtime import sha256
from stage_host_browser import stage_browser


PACKAGES = {
    "chromium-common_156.0.8078.79-1~deb12u1_amd64.deb": "22f8b358b96ee1afca2cefa496b303f29381cea846a3791b23128dee154e3b6b",
    "chromium-headless-shell_156.0.8078.79-1~deb12u1_amd64.deb": "9ce30e8db4ab49b7a4770df094fe8afdf9105263e5c477fc78f41761674599f8",
    "libdav1d6_1.0.0-2+deb12u1_amd64.deb": "197f08108242177aeae4c04aac11825c39b7d18598191ab769f910687ccb387f",
    "libflac12_1.4.2+ds-2_amd64.deb": "4d8431c274eef13ec9ee2c0bf988c34b4342367dec053b7f69a432525be5b1fe",
    "libjpeg62-turbo_1%3a2.1.5-2_amd64.deb": "95ec30140789a342add8f8371ed018924de51b539056522b66f207b25cba9cad",
}
LAUNCHER = """#!/bin/sh
set -eu
here=${0%/*}
export LD_LIBRARY_PATH="$here/private-libs"
exec "$here/chromium-headless-shell" "$@"
"""


def stage(packages: Path, output: Path) -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Expected an x86_64 Linux build environment")
    archives = [packages / filename for filename in PACKAGES]
    for archive in archives:
        if archive.is_symlink() or not archive.is_file() or sha256(archive) != PACKAGES[archive.name]:
            raise ValueError(f"Unexpected Debian package: {archive.name}")

    with TemporaryDirectory() as directory:
        root = Path(directory)
        for archive in archives:
            subprocess.run(["dpkg-deb", "--extract", archive, root], check=True)
        browser = root / "usr/lib/chromium"
        libraries = browser / "private-libs"
        libraries.mkdir()
        # Ubuntu 24.04 does not supply these exact Debian ABI variants.
        for name in ["libFLAC.so.12", "libdav1d.so.6", "libjpeg.so.62"]:
            shutil.copy2(root / "usr/lib/x86_64-linux-gnu" / name, libraries / name)
        notices = browser / "licenses"
        notices.mkdir()
        for archive in archives:
            package = archive.name.split("_", 1)[0]
            shutil.copy2(root / "usr/share/doc" / package / "copyright", notices / package)
        launcher = browser / "chrome-headless-shell"
        launcher.write_text(LAUNCHER, encoding="utf-8")
        launcher.chmod(0o755)
        stage_browser(browser, output, launcher.name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    stage(args.packages, args.output)
