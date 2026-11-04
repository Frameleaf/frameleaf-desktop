"""Authorize the GUI's private Keychain group, then sign its distribution disk image."""

import os
import platform
import plistlib
import subprocess
import ssl
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def app_entitlements(profile, team, identifier):
    claims = {
        "com.apple.application-identifier": f"{team}.{identifier}",
        "com.apple.developer.team-identifier": team,
    }
    if (
        identifier != "app.frameleaf.desktop"
        or profile.get("TeamIdentifier") != [team]
        or profile.get("Platform") != ["OSX"]
        or profile.get("ProvisionsAllDevices") is not True
        or profile.get("ExpirationDate", datetime.min).replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)
        or any(profile.get("Entitlements", {}).get(name) != value for name, value in claims.items())
    ):
        raise ValueError("Developer ID profile does not authorize this desktop application")
    return claims


def main(bundle, profile_path, keychain):
    app = bundle / "macos/Frameleaf.app"
    contents = app / "Contents"
    info = plistlib.loads((contents / "Info.plist").read_bytes())
    team = os.environ["APPLE_TEAM_ID"]
    identity = os.environ["APPLE_SIGNING_IDENTITY"]
    profile = plistlib.loads(subprocess.check_output(["security", "cms", "-D", "-i", profile_path]))
    claims = app_entitlements(profile, team, info["CFBundleIdentifier"])
    certificate = subprocess.check_output(["security", "find-certificate", "-c", identity, "-p", keychain], text=True)
    if ssl.PEM_cert_to_DER_cert(certificate) not in profile.get("DeveloperCertificates", []):
        raise ValueError("Developer ID profile does not authorize the imported signing certificate")
    requirement = f'anchor apple generic and certificate leaf[subject.OU] = "{team}" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
    sign = ["codesign", "--force", "--timestamp", "--keychain", keychain, "--sign", identity]
    verify = ["codesign", "--verify", "--strict", "--all-architectures", "-R=" + requirement]
    with tempfile.TemporaryDirectory(dir=bundle) as scratch:
        temp = Path(scratch)
        entitlements = temp / "app.plist"
        entitlements.write_bytes(plistlib.dumps(claims))
        # Tauri signs the nested executables. Only the main GUI may claim its Keychain identity.
        (contents / "embedded.provisionprofile").write_bytes(profile_path.read_bytes())
        subprocess.run([*sign, "--options", "runtime", "--entitlements", entitlements, app], check=True)
        subprocess.run([*verify, "--deep", app], check=True)
        for binary in (contents / "MacOS").iterdir():
            signed = subprocess.check_output(["codesign", "-d", "--entitlements", "-", "--xml", binary], stderr=subprocess.DEVNULL)
            actual = plistlib.loads(signed) if signed else {}
            expected = claims if binary.name == info["CFBundleExecutable"] else {}
            if actual != expected:
                raise ValueError(f"Unexpected signed entitlements on {binary.name}")
        root = temp / "disk"
        root.mkdir()
        subprocess.run(["ditto", app, root / app.name], check=True)
        (root / "Applications").symlink_to("/Applications")
        arch = {"arm64": "aarch64", "x86_64": "x64"}[platform.machine()]
        image = bundle / "dmg" / f"Frameleaf_{info['CFBundleShortVersionString']}_{arch}.dmg"
        image.parent.mkdir(exist_ok=True)
        # The temporary image is on the output volume so a failed build cannot replace a candidate.
        pending = temp / image.name
        subprocess.run(["hdiutil", "create", "-volname", "Frameleaf", "-format", "UDZO", "-srcfolder", root, pending], check=True)
        subprocess.run([*sign, pending], check=True)
        subprocess.run([*verify, pending], check=True)
        pending.replace(image)


if __name__ == "__main__":
    main(*(Path(arg).resolve(strict=True) for arg in sys.argv[1:]))
