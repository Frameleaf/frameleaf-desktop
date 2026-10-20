"""Author an unsigned app-like controller bundle; never sign, install or execute it."""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
from pathlib import Path

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


def validate_bundle(bundle: Path, controller_hash: str, version: str) -> dict:
    """Check the unsigned authoring form, never installed ownership or signing admission."""
    expected_info = info_bytes(version)
    if (not re.fullmatch(r'[a-f0-9]{64}', controller_hash) or not bundle.is_absolute()
        or bundle.resolve() != bundle or bundle.name != NAME):
        raise BuildError('host_controller_bundle_invalid')
    expected = {'Contents': True, 'Contents/MacOS': True, 'Contents/Info.plist': False, EXECUTABLE: False}
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
    files = validate_bundle(bundle, controller_hash, version)
    (output / 'qualification.json').write_text(json.dumps({
        'schemaVersion': 1, 'qualification': 'unsigned-helper-bundle',
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
