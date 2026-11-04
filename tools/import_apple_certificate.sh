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
security list-keychains -d user -s "$keychain"
rm "$RUNNER_TEMP/developer-id.p12"
