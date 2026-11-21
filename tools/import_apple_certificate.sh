#!/usr/bin/env bash
set -euo pipefail
: "${APPLE_CERTIFICATE:?Missing Apple certificate}" "${APPLE_CERTIFICATE_PASSWORD:?Missing certificate password}"
[[ "$APPLE_SIGNING_IDENTITY" == 'Developer ID Application: '* ]]
keychain="$RUNNER_TEMP/desktop-release.keychain-db"
password=$(openssl rand -hex 32)
echo "::add-mask::$password"
printf '%s' "$APPLE_CERTIFICATE" | base64 --decode > "$RUNNER_TEMP/developer-id.p12"
security create-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 7200 "$keychain"
security unlock-keychain -p "$password" "$keychain"
security import "$RUNNER_TEMP/developer-id.p12" -k "$keychain" -P "$APPLE_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain"
security find-identity -v -p codesigning "$keychain" |
  awk -F'"' -v identity="$APPLE_SIGNING_IDENTITY" '$2 == identity { matches++ } END { exit matches != 1 }'
# The job's keychain goes first in the user's search list; the list as it was is kept beside it
# and restored by the job's cleanup, so a runner that is a person's own Mac keeps its keychains.
# The restoration file is written only after the list was read, and in one move, so a failed read
# never leaves an empty list for the cleanup to apply.
search_list="$RUNNER_TEMP/keychain-search-list"
if [[ ! -f "$search_list" ]]; then
  current=$(security list-keychains -d user)
  printf '%s\n' "$current" | sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//' -e '/^$/d' > "$search_list.partial"
  mv "$search_list.partial" "$search_list"
fi
kept=()
while IFS= read -r item; do [[ -n "$item" && "$item" != "$keychain" ]] && kept+=("$item"); done < "$search_list"
security list-keychains -d user -s "$keychain" ${kept[@]+"${kept[@]}"}
# Signing looks the identity up by name across that list: it must name exactly one certificate
# there, the one just imported, or codesign could pick or refuse another the user keeps.
security find-identity -v -p codesigning |
  awk -F'"' -v identity="$APPLE_SIGNING_IDENTITY" '$2 == identity { matches++ } END { exit matches != 1 }' ||
  { echo "::error::$APPLE_SIGNING_IDENTITY matches a certificate outside the job keychain too; signing would be ambiguous."; exit 1; }
rm "$RUNNER_TEMP/developer-id.p12"
