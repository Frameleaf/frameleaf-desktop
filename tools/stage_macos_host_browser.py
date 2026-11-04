"""Stage an intact signed Chromium app inside the link-free native host."""

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

from stage_host_browser import stage_browser


def stage(app: Path, destination: Path) -> None:
    if (
        sys.platform != "darwin"
        or not app.is_absolute()
        or app.resolve(strict=True) != app
        or app.name != "Chromium.app"
        or not destination.is_absolute()
        or destination.resolve() != destination
        or destination.is_relative_to(app)
    ):
        raise ValueError("Expected an intact Chromium.app and a new external staging directory")
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "--deep", app], check=True)
    launcher = Path(__file__).resolve().parents[1] / "runtime/studio-macos-chromium"

    with TemporaryDirectory() as work:
        source = Path(work).resolve()
        shutil.copy2(launcher, source / "chrome-headless-shell")
        subprocess.run(
            ["/usr/bin/ditto", "-c", "-k", "--keepParent", app, source / "Chromium.zip"],
            check=True,
        )
        stage_browser(source, destination, "chrome-headless-shell")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    stage(args.app, args.output)
