#!/usr/bin/env bash
# Runs inside the container tools/manager_e2e/run.sh starts. See README.md beside this file.
set -euo pipefail
WORK=/work
DESKTOP=$WORK/desktop
export CARGO_TARGET_DIR=/cache/target CARGO_INCREMENTAL=0
BASE=/opt/frameleaf
released() {
  local manifests=()
  for path in "$BASE"/Runtimes/*/installation.json; do
    manifests+=("$(jq -r .manifestSha256 "$path")")
  done
  # The package apt installed is the one whose signature the unchanged release trust accepts.
  cat "$WORK/released" 2>/dev/null || { [[ ${#manifests[@]} == 1 ]] && printf '%s\n' "${manifests[0]}" | tee "$WORK/released"; }
}

build() {
  mkdir -p "$WORK"
  released > /dev/null
  rsync -a --delete --exclude node_modules --exclude dist --exclude target --exclude .git "${FRAMELEAF_MANAGER_E2E_SOURCE:-/src}/" "$DESKTOP/"
  # A signing key made for this run, added to the release trust of this build only. The copy
  # of the repository in the container is the only thing changed; /src is mounted read-only.
  if [[ ! -f $WORK/key.pem ]]; then
    node -e '
      const { generateKeyPairSync } = require("node:crypto");
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      const fs = require("node:fs");
      fs.writeFileSync(process.argv[1] + "/key.pem", privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
      fs.writeFileSync(process.argv[1] + "/key.hex", publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("hex"));
    ' "$WORK"
  fi
  jq --arg key "$(cat "$WORK/key.hex")" '.keys += [{id: "manager-e2e-run", publicKeyHex: $key}]' \
    "${FRAMELEAF_MANAGER_E2E_SOURCE:-/src}/runtime/release-trust.json" > "$DESKTOP/runtime/release-trust.json"
  cd "$DESKTOP"
  [[ -d node_modules ]] || npm ci
  npm run build
  cargo build --locked --manifest-path src-tauri/Cargo.toml --bin frameleaf-native-host
  cargo test --locked --manifest-path src-tauri/Cargo.toml --lib --no-run --message-format=json \
    | jq -r 'select(.reason == "compiler-artifact" and .profile.test and .target.name == "frameleaf_desktop") | .executable' \
    | tail -1 > "$WORK/tests.path"
  install -m 755 "$(cat "$WORK/tests.path")" "$WORK/desktop-tests"
  # The controller a package is assembled with stays fixed: its hash is part of what Manager stores.
  # Without its debug information: an installed controller may be at most 256 MB.
  [[ -f $WORK/frameleaf-native-host ]] || strip --strip-debug -o "$WORK/frameleaf-native-host" "$CARGO_TARGET_DIR/debug/frameleaf-native-host"
  ls -la "$WORK/desktop-tests" "$WORK/frameleaf-native-host"
}

# assemble NAME REVISION EPOCH: install a companion whose Manager is built from a server commit.
assemble() {
  local name=$1 revision=$2 epoch=$3 server=$WORK/server
  if [[ ! -d $server/.git ]]; then git init -q "$server"; fi
  git -C "$server" fetch -q --depth 1 "${FRAMELEAF_MANAGER_E2E_SERVER:-https://github.com/Frameleaf/frameleaf-app}" "$revision"
  node "$DESKTOP/tools/manager_e2e/assemble.mjs" --base "$(released)" --server "$server" --revision "$revision" \
    --controller "$WORK/frameleaf-native-host" --key "$WORK/key.pem" --epoch "$epoch" --desktop "$DESKTOP" --work "$WORK" \
    | tee "$WORK/package-$name.json"
}

manifest() {
  if [[ $1 == released ]]; then released; else jq -r .manifestSha256 "$WORK/package-$1.json"; fi
}

# run PACKAGE TESTS [FIRST_PACKAGE]: in a new account with a new library and keyring, the
# space-separated TESTS one after another in one login session; the first failure decides the result.
# An earlier one may end without stopping what it started, as a crash of the app would.
# With FIRST_PACKAGE the account's profile is prepared for that package, as for a library that
# was started with it before PACKAGE was installed.
run() {
  local package=$1 names=$2 first=${3:-$1} number account uid first_manifest controller
  # Nothing of an earlier account keeps a port: every earlier account's processes are ended.
  for uid in $(cat "$WORK/accounts" 2>/dev/null); do pkill -KILL -U "$uid" 2>/dev/null || true; done
  # A database ended that way leaves its socket lock behind, which the next account cannot replace.
  rm -f /tmp/.s.PGSQL.*
  number=$(( $(wc -l < "$WORK/accounts" 2>/dev/null || echo 0) + 1 ))
  account="library$number" uid=$((3000 + number))
  useradd --create-home --uid "$uid" "$account"
  echo "$uid" >> "$WORK/accounts"
  first_manifest=$(manifest "$first")
  controller=$(jq -r .controllerSha256 "$BASE/Runtimes/$first_manifest/installation.json")
  # What Desktop runs through pkexec when a person approves setting up their library profile.
  env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    "$BASE/Controllers/$first_manifest/$controller/frameleaf-native-host" --provision-profile "$first_manifest" "$controller" "$uid"
  install -d -m 700 -o "$account" -g "$account" "/run/user-$uid"
  echo "== $names as $account on $package ($(manifest "$package"))"
  # shellcheck disable=SC2086
  runuser -u "$account" -- env -i HOME="/home/$account" PATH=/usr/bin:/bin XDG_RUNTIME_DIR="/run/user-$uid" \
    FRAMELEAF_MANAGER_E2E=disposable \
    FRAMELEAF_MANAGER_E2E_MANIFEST="$(manifest "$package")" \
    FRAMELEAF_MANAGER_E2E_RELEASED="$(manifest "$first")" \
    FRAMELEAF_MANAGER_E2E_SHORT="${FRAMELEAF_MANAGER_E2E_SHORT:-480}" \
    dbus-run-session -- bash -uo pipefail -c '
      head -c 32 /dev/urandom | base64 | gnome-keyring-daemon --unlock --components=secrets > /dev/null
      tests=$0 result=0
      [[ $# -gt 0 ]] || exit 2
      for name in "$@"; do
        # Every test runs; the first one that fails decides the result.
        "$tests" --ignored --exact --nocapture --test-threads=1 "host_setup::manager_e2e::$name"
        status=$?
        [[ $result -ne 0 ]] || result=$status
      done
      exit "$result"
    ' "$WORK/desktop-tests" $names
}

"$@"
