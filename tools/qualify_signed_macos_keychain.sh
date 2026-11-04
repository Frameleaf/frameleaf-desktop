#!/usr/bin/env bash
set -euo pipefail
: "${RUNNER_TEMP:?}" "${APPLE_SIGNING_IDENTITY:?}"
[[ "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || { echo 'A disposable hosted runner is required'; exit 1; }
app=src-tauri/target/release/bundle/macos/Frameleaf.app
test_dir=$(mktemp -d "$RUNNER_TEMP/keychain-qa.XXXXXX")
probe="$test_dir/KeychainQualification.app"
contents="$probe/Contents"
mkdir -p "$contents/MacOS"
cp "$app/Contents/embedded.provisionprofile" "$contents/embedded.provisionprofile"
codesign -d --entitlements - --xml "$app" > "$test_dir/gui-entitlements.plist"
plutil -create xml1 "$contents/Info.plist"
plutil -insert CFBundleIdentifier -string app.frameleaf.desktop "$contents/Info.plist"
plutil -insert CFBundlePackageType -string APPL "$contents/Info.plist"
plutil -insert CFBundleExecutable -string keychain-qualification "$contents/Info.plist"
plutil -insert CFBundleVersion -string 1 "$contents/Info.plist"
xcrun clang -fobjc-arc -framework Foundation -framework Security -framework LocalAuthentication \
  tools/qualify_macos_keychain.m src-tauri/src/macos_keychain.m -o "$contents/MacOS/keychain-qualification"
codesign --force --timestamp --options runtime --keychain "$RUNNER_TEMP/desktop-release.keychain-db" \
  --sign "$APPLE_SIGNING_IDENTITY" --entitlements "$test_dir/gui-entitlements.plist" "$probe"
codesign --verify --deep --strict "$probe"
"$contents/MacOS/keychain-qualification"
