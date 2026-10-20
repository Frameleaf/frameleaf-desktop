"""Author an unsigned macOS native-host component PKG; never install or start it."""
from __future__ import annotations

import argparse
import json
import os
import platform
import plistlib
import re
import shlex
import shutil
import stat
import xml.etree.ElementTree as ET
from pathlib import Path

from build_host_server import stage_server
from build_host_macos_bundle import EXECUTABLE, NAME, inspect_controller, stage_bundle
from build_runtime import BuildError, regular, run, sha256

ROOT = Path(__file__).resolve().parent.parent
BASE = Path('Library/Application Support/Frameleaf')


def validate_identities(manifest: str, controller: str) -> None:
    if any(not re.fullmatch(r'[a-f0-9]{64}', value) for value in [manifest, controller]):
        raise BuildError('host_install_identity_invalid')


def installer_scripts(manifest: str, controller: str) -> dict[str, str]:
    validate_identities(manifest, controller)
    installed = '/' + (BASE / 'Controllers' / manifest / controller / NAME / EXECUTABLE).as_posix()
    header = '#!/bin/sh\nset -eu\n[ "${3:-}" = / ] || exit 64\n'
    env = '/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C '
    return {
        'preinstall': header + 'script_dir=$(/usr/bin/dirname "$0")\nexec ' + env + '"$script_dir/Frameleaf Native Host.app/Contents/MacOS/frameleaf-native-host" --prepare-install ' + manifest + ' ' + controller + '\n',
        'postinstall': header + 'exec ' + env + shlex.quote(installed) + ' --finalize-install ' + manifest + ' ' + controller + '\n',
    }


def stage_package(candidate: Path, controller: Path, output: Path, manifest_hash: str, controller_hash: str) -> None:
    validate_identities(manifest_hash, controller_hash)
    if (not all(p.is_absolute() and p.resolve() == p for p in [candidate, controller, output])
        or output.exists() or output.is_symlink() or output.is_relative_to(candidate)):
        raise BuildError('host_install_paths_invalid')
    if sha256(controller) != controller_hash:
        raise BuildError('host_install_controller_changed')
    output.mkdir(mode=0o700)
    root = output / 'root'
    base = root / BASE
    runtime = base / 'Runtimes' / manifest_hash
    runtime.mkdir(parents=True)
    stage_server(candidate / 'payload', runtime / 'payload')
    for name in ['manifest.json', 'manifest.sig']:
        if not stat.S_ISREG(regular(candidate / name).st_mode):
            raise BuildError('host_install_manifest_invalid')
        shutil.copy2(candidate / name, runtime / name)
    version = json.loads((ROOT / 'src-tauri/tauri.conf.json').read_text())['version']
    destination = base / 'Controllers' / manifest_hash / controller_hash
    destination.parent.mkdir(parents=True)
    stage_bundle(controller, destination, controller_hash, version)
    (base / 'Profiles').mkdir()
    for path in root.rglob('*'):
        info = regular(path)
        path.chmod(0o755 if stat.S_ISDIR(info.st_mode) or info.st_mode & 0o111 else 0o644)
    scripts = output / 'scripts'
    stage_bundle(controller, scripts, controller_hash, version)
    for name, text in installer_scripts(manifest_hash, controller_hash).items():
        (scripts / name).write_text(text)
        (scripts / name).chmod(0o755)

    # Preserve versioned controllers; Installer must never relocate or skip this bundle.
    (output / 'components.plist').write_bytes(plistlib.dumps([{
        'RootRelativeBundlePath': (destination.relative_to(root) / NAME).as_posix(),
        'BundleIsRelocatable': False,
        'BundleIsVersionChecked': False,
        'BundleHasStrictIdentifier': True,
        'BundleOverwriteAction': 'upgrade',
    }], sort_keys=True))


def build(candidate: Path, controller: Path, output: Path) -> None:
    if platform.system() != 'Darwin':
        raise BuildError('host_install_platform_unsupported')
    if not all(p.is_absolute() and p.resolve() == p for p in [candidate, controller, output]) or output.exists() or output.is_symlink():
        raise BuildError('host_install_paths_invalid')
    # Inspect the local build artifact; never execute a supplied controller during authoring.
    work = candidate.parent
    env = os.environ.copy()
    env.update({'OMP_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1', 'RAYON_NUM_THREADS': '1'})
    arch = inspect_controller(controller, work, env)
    node = candidate / 'payload/node'
    verifier = (ROOT / 'tools/sign_host_runtime.mjs').as_uri()
    command = [node, '--input-type=module', '--eval', f'import({json.dumps(verifier)}).then(async m=>console.log(JSON.stringify(await m.verifySignedHostCandidate(process.argv[1]))))']
    checked = json.loads(run([*command, candidate], cwd=work, env=env))
    manifest = json.loads((candidate / 'manifest.json').read_text())
    if manifest['platform'] != 'macos' or manifest['architecture'] != {'arm64': 'aarch64', 'x86_64': 'x86_64'}[arch]:
        raise BuildError('host_install_runtime_target_mismatch')
    helper_hash = sha256(controller)
    stage_package(candidate, controller, output, checked['manifestSha256'], helper_hash)
    root = output / 'root'
    staged = root / BASE / 'Runtimes' / checked['manifestSha256']
    if json.loads(run([*command, staged], cwd=output, env=env)) != checked:
        raise BuildError('host_install_staged_runtime_changed')
    identifier = 'app.frameleaf.desktop.host.' + checked['manifestSha256'][:16] + '.' + helper_hash[:16]
    component = output / 'FrameleafHostComponent.pkg'
    run(['/usr/bin/pkgbuild', '--root', root, '--scripts', output / 'scripts', '--component-plist', output / 'components.plist', '--identifier', identifier, '--version', '0.1.0', '--install-location', '/', '--ownership', 'recommended', component], cwd=output, env=env)
    distribution = ET.Element('installer-gui-script', {'minSpecVersion': '2'})
    ET.SubElement(distribution, 'title').text = 'Frameleaf native host — internal candidate'
    ET.SubElement(distribution, 'domains', {'enable_anywhere': 'false', 'enable_currentUserHome': 'false', 'enable_localSystem': 'true'})
    ET.SubElement(distribution, 'options', {'customize': 'never', 'require-scripts': 'true', 'rootVolumeOnly': 'true'})
    outline = ET.SubElement(distribution, 'choices-outline')
    ET.SubElement(outline, 'line', {'choice': 'host'})
    choice = ET.SubElement(distribution, 'choice', {'id': 'host', 'visible': 'false', 'start_selected': 'true'})
    ET.SubElement(choice, 'pkg-ref', {'id': identifier})
    ET.SubElement(distribution, 'pkg-ref', {'id': identifier, 'version': '0.1.0'}).text = '#' + component.name
    document = output / 'Distribution.xml'
    ET.ElementTree(distribution).write(document, encoding='utf-8', xml_declaration=True)
    package = output / 'FrameleafNativeHost-internal.pkg'
    run(['/usr/bin/productbuild', '--distribution', document, '--package-path', output, package], cwd=output, env=env)
    (output / 'qualification.json').write_text(json.dumps({'schemaVersion': 1, 'qualification': 'built-not-installed', 'host': checked, 'controllerSha256': helper_hash, 'componentSha256': sha256(component), 'packageSha256': sha256(package), 'package': package.name, 'files': len(manifest['files']), 'platform': 'macos', 'architecture': arch, 'osCodeSigningQualified': False, 'installedProfileProvisioningQualified': False, 'runtimeQualified': False, 'redistributable': False}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['candidate', 'controller', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        build(args.candidate, args.controller, args.output)
    except (BuildError, OSError, ValueError, KeyError) as error:
        parser.exit(1, str(error) + '\n')
