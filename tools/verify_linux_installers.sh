#!/usr/bin/env bash
set -euo pipefail
[[ "$(uname -s)" == Linux ]]
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
shopt -s nullglob
debs=(src-tauri/target/release/bundle/deb/*.deb)
images=(src-tauri/target/release/bundle/appimage/*.AppImage)
if [[ ${#debs[@]} != 1 || ${#images[@]} != 1 ]]; then
  echo 'Missing or ambiguous Linux installers' >&2
  exit 1
fi
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
dpkg-deb --extract "${debs[0]}" "$scratch/deb"
(cd "$scratch" && "$repo_root/${images[0]}" --appimage-extract > /dev/null)
for prefix in "$scratch/deb" "$scratch/squashfs-root"; do
  node --input-type=module -e '
    import { packageConfiguration } from "./tools/package_desktop.mjs";
    await packageConfiguration(process.argv[1]);
  ' "$prefix/usr/share/Frameleaf/native-runtime"
  python3 - "$prefix/usr/share/Frameleaf/native-runtime" <<'PYTHON'
import stat
import sys
from pathlib import Path
root = Path(sys.argv[1])
for path in [root, *root.rglob('*')]:
    mode = path.stat().st_mode
    required = 0o555 if stat.S_ISDIR(mode) else 0o444
    if mode & required != required or mode & 0o022:
        raise SystemExit('Installed runtime permissions are not readable and protected')
PYTHON
done
