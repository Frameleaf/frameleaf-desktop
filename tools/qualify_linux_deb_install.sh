#!/usr/bin/env bash
# Install the built Desktop .deb in clean distribution containers and fail on unmet dependencies.
#
#   qualify_linux_deb_install.sh PACKAGE.deb [IMAGE...]
#
# Every IMAGE (default: ubuntu:24.04 ubuntu:22.04 debian:12) must resolve and install the package's
# dependencies with apt. The tray is loaded at run time (libayatana-appindicator3.so.1 first), so the
# package must depend on libayatana-appindicator3-1, which all three distributions ship; the older
# libappindicator3-1 is not in Debian 12.
set -euo pipefail
[[ $# -ge 1 ]] || { echo 'usage: qualify_linux_deb_install.sh PACKAGE.deb [IMAGE...]' >&2; exit 2; }
package=$(realpath -- "$1")
shift
[[ -f "$package" && "$package" == *.deb ]] || { echo "Not a .deb package: $package" >&2; exit 2; }
images=("$@")
[[ ${#images[@]} -gt 0 ]] || images=(ubuntu:24.04 ubuntu:22.04 debian:12)

depends=$(dpkg-deb --field "$package" Depends)
echo "Depends: $depends"
tray=0
IFS=',' read -ra entries <<< "$depends"
for entry in "${entries[@]}"; do
  # A dependency is a list of alternatives; only the first word of each is the package name.
  IFS='|' read -ra alternatives <<< "$entry"
  names=()
  for alternative in "${alternatives[@]}"; do
    read -r name _ <<< "$alternative"
    names+=("${name%%:*}")
  done
  for name in "${names[@]}"; do
    [[ "$name" != libayatana-appindicator3-1 ]] || tray=1
  done
  if [[ " ${names[*]} " == *' libappindicator3-1 '* && " ${names[*]} " != *' libayatana-appindicator3-1 '* ]]; then
    echo 'The package requires libappindicator3-1, which Debian 12 does not ship. Build with libayatana-appindicator3-dev.' >&2
    exit 1
  fi
done
[[ $tray == 1 ]] || { echo 'The package does not depend on libayatana-appindicator3-1, so the tray library may be missing after install.' >&2; exit 1; }

name=$(dpkg-deb --field "$package" Package)
for image in "${images[@]}"; do
  echo "::group::Install $name in a clean $image container"
  docker run --rm --network bridge -e DEBIAN_FRONTEND=noninteractive -e PACKAGE_NAME="$name" \
    -v "$package:/install/package.deb:ro" "$image" bash -euo pipefail -c '
      apt-get update -qq
      # apt exits non-zero when a dependency cannot be satisfied in this distribution.
      apt-get install -y --no-install-recommends /install/package.deb
      [[ "$(dpkg-query --show --showformat="\${db:Status-Abbrev}" "$PACKAGE_NAME")" == "ii " ]]
      ls /usr/lib/*/libayatana-appindicator3.so.1 > /dev/null
      # Installing proves the dependencies resolve; whether this distribution can also load the
      # binaries depends on the C library of the build machine, reported here without failing.
      status=0
      while IFS= read -r file; do
        [[ -f "$file" && -x "$file" ]] || continue
        if missing=$(ldd "$file" 2>&1 | grep "not found"); then
          status=1
          echo "::warning::$file cannot be loaded here: $(echo "$missing" | head -n 3 | tr "\n" " ")"
        fi
      done < <(dpkg-query --listfiles "$PACKAGE_NAME" | grep -E "^/usr/bin/")
      [[ $status == 0 ]] && echo "Installed binaries load in this distribution."
      exit 0
    '
  echo '::endgroup::'
done
echo "Installed $name with apt in: ${images[*]}"
