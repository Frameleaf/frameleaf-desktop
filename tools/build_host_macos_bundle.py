"""Stage a closed controller bundle; never sign, install or execute it."""
from __future__ import annotations

import argparse
import json
import os
import platform
import plistlib
import re
import shutil
import stat
import subprocess
from pathlib import Path
from xml.parsers.expat import ExpatError

from build_runtime import BuildError, inventory, regular, run, sha256

ROOT = Path(__file__).resolve().parent.parent
NAME = 'Frameleaf Native Host.app'
EXECUTABLE = 'Contents/MacOS/frameleaf-native-host'


def info_bytes(version: str) -> bytes:
    if not isinstance(version, str) or len(version) > 32 or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise BuildError('host_controller_bundle_version_invalid')
    return (ROOT / 'runtime/macos-host-Info.plist.in').read_bytes().replace(b'@VERSION@', version.encode('ascii'))


def inspect_controller(controller: Path, work: Path, env: dict[str, str]) -> str:
    if not controller.is_absolute() or controller.resolve() != controller:
        raise BuildError('host_install_paths_invalid')
    info = regular(controller)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 256 * 1024**2:
        raise BuildError('host_install_controller_invalid')
    arch = {'arm64': 'arm64', 'x86_64': 'x86_64'}[platform.machine()]
    archs = run(['/usr/bin/lipo', '-archs', controller], cwd=work, env=env).split()
    if arch not in archs or not set(archs) <= {'arm64', 'x86_64'}:
        raise BuildError('host_install_controller_target_mismatch')
    dependencies = run(['/usr/bin/otool', '-L', controller], cwd=work, env=env).splitlines()[1:]
    if not dependencies or any(not line.strip().startswith(('/System/Library/', '/usr/lib/')) for line in dependencies):
        raise BuildError('host_install_controller_external_dependency')
    return arch


def validate_bundle(bundle: Path, controller_hash: str, version: str, *, signature_required: bool = False) -> dict:
    """Check a closed bundle; a seal validates integrity, not publisher/notarization acceptance."""
    expected_info = info_bytes(version)
    if (not re.fullmatch(r'[a-f0-9]{64}', controller_hash) or not bundle.is_absolute()
        or bundle.resolve() != bundle or bundle.name != NAME):
        raise BuildError('host_controller_bundle_invalid')
    expected = {'Contents': True, 'Contents/MacOS': True, 'Contents/Info.plist': False, EXECUTABLE: False}
    if signature_required:
        expected.update({'Contents/_CodeSignature': True, 'Contents/_CodeSignature/CodeResources': False})
    if not stat.S_ISDIR(regular(bundle).st_mode) or bundle.stat().st_mode & 0o7777 != 0o755:
        raise BuildError('host_controller_bundle_invalid')
    found = set()
    for count, path in enumerate(bundle.rglob('*'), 1):
        name = path.relative_to(bundle).as_posix()
        if count > len(expected) or name not in expected:
            raise BuildError('host_controller_bundle_invalid')
        info = regular(path)
        directory = expected[name]
        if (stat.S_ISDIR(info.st_mode) != directory or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))
            or info.st_mode & 0o7777 != (0o755 if directory or name == EXECUTABLE else 0o644)):
            raise BuildError('host_controller_bundle_invalid')
        found.add(name)
    if found != set(expected):
        raise BuildError('host_controller_bundle_invalid')
    with (bundle / 'Contents/Info.plist').open('rb') as stream:
        if stream.read(len(expected_info) + 1) != expected_info:
            raise BuildError('host_controller_bundle_invalid')
    if sha256(bundle / EXECUTABLE) != controller_hash:
        raise BuildError('host_install_controller_changed')
    if signature_required:
        resources = bundle / 'Contents/_CodeSignature/CodeResources'
        with resources.open('rb') as stream:
            raw = stream.read(256 * 1024 + 1)
        if not raw or len(raw) > 256 * 1024:
            raise BuildError('host_controller_bundle_signature_invalid')
        try:
            seal = plistlib.loads(raw)
        except (ValueError, plistlib.InvalidFileException, OverflowError, ExpatError, RecursionError) as error:
            raise BuildError('host_controller_bundle_signature_invalid') from error
        if (not isinstance(seal, dict) or not set(seal) <= {'files', 'files2', 'rules', 'rules2'}
            or any(not isinstance(value, dict) for value in seal.values())):
            raise BuildError('host_controller_bundle_signature_invalid')
        for kind, entries in seal.items():
            if len(entries) > 64:
                raise BuildError('host_controller_bundle_signature_invalid')
            for path in entries:
                if (not isinstance(path, str) or len(path.encode('utf-8')) > 4096
                    or (kind in ['files', 'files2'] and path not in ['Info.plist', 'MacOS/frameleaf-native-host'])):
                    raise BuildError('host_controller_bundle_signature_invalid')
        try:
            checked = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '--all-architectures', str(bundle)],
                env={'PATH': os.defpath, 'LC_ALL': 'C'}, capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise BuildError('host_controller_bundle_signature_invalid') from error
        if checked.returncode:
            raise BuildError('host_controller_bundle_signature_invalid')
    return inventory(bundle)


def stage_bundle(controller: Path, output: Path, controller_hash: str, version: str) -> Path:
    metadata = info_bytes(version)
    if (not re.fullmatch(r'[a-f0-9]{64}', controller_hash)
        or not all(path.is_absolute() and path.resolve() == path for path in [controller, output])
        or output.exists() or output.is_symlink()):
        raise BuildError('host_install_paths_invalid')
    info = regular(controller)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 256 * 1024**2:
        raise BuildError('host_install_controller_invalid')
    if sha256(controller) != controller_hash:
        raise BuildError('host_install_controller_changed')
    signed_source = controller.parents[2] if controller.parts[-4:] == (NAME, 'Contents', 'MacOS', 'frameleaf-native-host') else None
    if signed_source is not None and (signed_source / 'Contents/_CodeSignature').exists():
        if output.is_relative_to(signed_source):
            raise BuildError('host_install_paths_invalid')
        expected = validate_bundle(signed_source, controller_hash, version, signature_required=True)
        output.mkdir(mode=0o700)
        bundle = output / NAME
        shutil.copytree(signed_source, bundle, symlinks=True)
        if validate_bundle(bundle, controller_hash, version, signature_required=True) != expected:
            raise BuildError('host_controller_bundle_changed')
        return bundle
    output.mkdir(mode=0o700)
    bundle = output / NAME
    for directory in [bundle, bundle / 'Contents', bundle / 'Contents/MacOS']:
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
    shutil.copyfile(controller, bundle / EXECUTABLE)
    (bundle / EXECUTABLE).chmod(0o755)
    (bundle / 'Contents/Info.plist').write_bytes(metadata)
    (bundle / 'Contents/Info.plist').chmod(0o644)
    validate_bundle(bundle, controller_hash, version)
    return bundle


def build(controller: Path, output: Path) -> None:
    if platform.system() != 'Darwin':
        raise BuildError('host_install_platform_unsupported')
    if not output.is_absolute() or output.resolve() != output or output.exists() or output.is_symlink():
        raise BuildError('host_install_paths_invalid')
    env = os.environ.copy()
    env.update({'OMP_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1', 'RAYON_NUM_THREADS': '1'})
    arch = inspect_controller(controller, output.parent, env)
    controller_hash = sha256(controller)
    version = json.loads((ROOT / 'src-tauri/tauri.conf.json').read_text())['version']
    bundle = stage_bundle(controller, output, controller_hash, version)
    signature_required = (bundle / 'Contents/_CodeSignature').exists()
    files = validate_bundle(bundle, controller_hash, version, signature_required=signature_required)
    (output / 'qualification.json').write_text(json.dumps({
        'schemaVersion': 1, 'qualification': 'sealed-helper-bundle' if signature_required else 'unsigned-helper-bundle',
        'controllerSignatureVerified': signature_required,
        'bundle': NAME, 'bundleIdentifier': 'app.frameleaf.desktop.host',
        'controllerSha256': controller_hash, 'architecture': arch, 'files': files,
        'osCodeSigningQualified': False, 'provisioningProfileQualified': False,
        'sharedCredentialAccessQualified': False, 'installedLayoutQualified': False,
        'runtimeQualified': False, 'redistributable': False,
    }, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['controller', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    arguments = parser.parse_args()
    try:
        build(arguments.controller, arguments.output)
    except (BuildError, OSError, ValueError, KeyError) as error:
        parser.exit(1, str(error) + '\n')
