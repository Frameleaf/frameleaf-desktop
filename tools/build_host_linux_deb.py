"""Author private Linux host/bootstrap Debian candidates; never install or start them."""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import stat
from pathlib import Path

from build_host_macos_pkg import validate_identities
from build_host_server import stage_server
from build_runtime import BuildError, build_environment, regular, run, sha256
from relocate_linux import search_directories

ROOT = Path(__file__).resolve().parent.parent
BASE = Path('opt/frameleaf')


def package_names(manifest: str, controller: str) -> tuple[str, str]:
    validate_identities(manifest, controller)
    return 'frameleaf-host-bootstrap-' + controller, 'frameleaf-host-runtime-' + manifest


def installer_scripts(manifest: str, controller: str) -> dict[str, dict[str, str]]:
    package_names(manifest, controller)
    bootstrap = '/opt/frameleaf/Bootstrap/' + controller
    runtime = '/opt/frameleaf/Runtimes/' + manifest
    header = '''#!/bin/sh
set -eu
[ "$(/usr/bin/id -u)" = 0 ] && [ "$(/usr/bin/id -ru)" = 0 ] || exit 77
cd /
protected() {
    [ ! -L "$1" ] || exit 65
    [ "$(/usr/bin/stat -c %u -- "$1")" = 0 ] || exit 65
    mode=$(/usr/bin/stat -c %a -- "$1")
    case "$mode" in ''|*[!0-7]*) exit 65 ;; esac
    [ "$((0$mode & 0022))" -eq 0 ] || exit 65
}
directory() { [ -d "$1" ] || exit 65; protected "$1"; }
file() { [ -f "$1" ] || exit 65; protected "$1"; [ "$(/usr/bin/stat -c %h -- "$1")" = 1 ] || exit 65; }
'''
    directories = ['/', '/opt', '/opt/frameleaf', '/opt/frameleaf/Bootstrap', bootstrap]
    checks = 'for path in ' + ' '.join(shlex.quote(p) for p in directories) + '; do directory "$path"; done\n'
    helper = bootstrap + '/frameleaf-native-host'
    verify = checks + 'file ' + helper + '\n[ -x ' + helper + ' ] || exit 65\nvalue=$(/usr/bin/sha256sum -- ' + helper + ')\n[ "${value%% *}" = ' + controller + ' ] || exit 65\n'
    invoke = 'exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C ' + helper
    ids = ' ' + manifest + ' ' + controller + '\n'
    initialize = 'for path in ' + ' '.join(directories) + '; do\n    if [ ! -e "$path" ] && [ ! -L "$path" ]; then /bin/mkdir -m 755 -- "$path"; fi\n    directory "$path"\ndone\n'
    bootstrap_hooks = {
        'preinst': header + 'case "${1:-}" in install|upgrade) ;; *) exit 64 ;; esac\n' + initialize + 'if [ -e ' + helper + ' ] || [ -L ' + helper + ' ]; then\n' + verify + 'fi\n',
        'postinst': header + 'case "${1:-}" in configure|abort-upgrade|abort-remove|abort-deconfigure) ;; *) exit 64 ;; esac\n' + verify,
        'prerm': header + 'case "${1:-}" in remove|upgrade|deconfigure) exit 0 ;; *) exit 64 ;; esac\n',
        'postrm': header + 'case "${1:-}" in remove|purge|upgrade|failed-upgrade|abort-install|abort-upgrade|disappear) exit 0 ;; *) exit 64 ;; esac\n',
    }
    receipt = runtime + '/installation.json'
    fence = runtime + '/.package-maintenance'
    retained = 'if [ -e ' + receipt + ' ] || [ -L ' + receipt + ' ]; then\n'
    retained += 'for path in / /opt /opt/frameleaf /opt/frameleaf/Runtimes ' + runtime + '; do directory "$path"; done\n'
    retained += 'file ' + receipt + '\nfile ' + fence + '\n[ "$(/usr/bin/stat -c %s -- ' + fence + ')" = 0 ] || exit 65\n/bin/rm -- ' + receipt + '\nfi\n'
    runtime_hooks = {
        'preinst': header + 'case "${1:-}" in install|upgrade) ;; *) exit 64 ;; esac\n' + verify + invoke + ' --prepare-linux-package' + ids,
        'postinst': header + 'case "${1:-}" in configure|abort-upgrade|abort-remove|abort-deconfigure) ;; *) exit 64 ;; esac\n' + verify + invoke + ' --finalize-install' + ids,
        # A failed old prerm must never become permission to unpack over live code.
        'prerm': header + 'case "${1:-}" in remove|upgrade|deconfigure) ;; *) exit 64 ;; esac\n' + verify + invoke + ' --prepare-linux-package' + ids,
        'postrm': header + 'case "${1:-}" in remove|purge|upgrade) ;; failed-upgrade|abort-install|abort-upgrade) exit 0 ;; *) exit 64 ;; esac\n' + retained,
    }
    return {'bootstrap': bootstrap_hooks, 'runtime': runtime_hooks}


def stage_packages(candidate: Path, controller: Path, output: Path, manifest_hash: str, controller_hash: str, architecture: str) -> tuple[Path, Path]:
    names = package_names(manifest_hash, controller_hash)
    if architecture not in {'amd64', 'arm64'}:
        raise BuildError('host_install_runtime_target_mismatch')
    if (not all(p.is_absolute() and p.resolve() == p for p in [candidate, controller, output])
        or output.exists() or output.is_symlink() or output.is_relative_to(candidate)):
        raise BuildError('host_install_paths_invalid')
    if not stat.S_ISREG(regular(controller).st_mode) or sha256(controller) != controller_hash:
        raise BuildError('host_install_controller_changed')
    output.mkdir(mode=0o700)
    bootstrap, runtime = output / 'bootstrap', output / 'runtime'
    resource = runtime / BASE / 'Runtimes' / manifest_hash
    resource.mkdir(parents=True)
    stage_server(candidate / 'payload', resource / 'payload')
    for name in ['manifest.json', 'manifest.sig']:
        if not stat.S_ISREG(regular(candidate / name).st_mode):
            raise BuildError('host_install_manifest_invalid')
        shutil.copy2(candidate / name, resource / name)
    for path in [bootstrap / BASE / 'Bootstrap' / controller_hash / 'frameleaf-native-host', runtime / BASE / 'Controllers' / manifest_hash / controller_hash / 'frameleaf-native-host']:
        path.parent.mkdir(parents=True)
        shutil.copy2(controller, path)
        path.chmod(0o755)
        if sha256(path) != controller_hash:
            raise BuildError('host_install_controller_changed')
    for role, tree, name in zip(['bootstrap', 'runtime'], [bootstrap, runtime], names):
        metadata = tree / 'DEBIAN'
        metadata.mkdir()
        control = f'Package: {name}\nVersion: 1\nArchitecture: {architecture}\nMaintainer: Frameleaf <support@frameleaf.app>\nSection: graphics\nPriority: optional\nDescription: Frameleaf private native host {role} candidate\n'
        if role == 'runtime':
            control += 'Pre-Depends: ' + names[0] + ' (= 1)\n'
        (metadata / 'control').write_text(control)
        for hook, text in installer_scripts(manifest_hash, controller_hash)[role].items():
            (metadata / hook).write_text(text)
            (metadata / hook).chmod(0o755)
        for path in tree.rglob('*'):
            info = regular(path)
            path.chmod(0o755 if stat.S_ISDIR(info.st_mode) or info.st_mode & 0o111 else 0o644)
        tree.chmod(0o755)
    return bootstrap, runtime


def dependencies(tree: Path, package: str, work: Path) -> str:
    work.mkdir(mode=0o700)
    (work / 'debian').mkdir()
    (work / 'debian/control').write_text('Source: frameleaf-native-host\n\nPackage: ' + package + '\nArchitecture: any\nDescription: private build dependency analysis\n')
    env = build_environment(work, {})
    elf, directories, shlibs = [], set(), set()
    for path in sorted(tree.rglob('*')):
        info = regular(path)
        if not stat.S_ISREG(info.st_mode):
            continue
        with path.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                continue
        directories.add(path.parent)
        dynamic = run(['readelf', '-d', path], cwd=work, env=env)
        analyzed = path
        needed = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', dynamic)
        origin = [name for name in needed if name.startswith(('$ORIGIN/', '${ORIGIN}/'))]
        if origin:
            targets = {}
            for name, expanded in zip(origin, search_directories(path, origin)):
                target = expanded.resolve(strict=True)
                if not target.is_relative_to(tree.resolve()) or not stat.S_ISREG(regular(target).st_mode):
                    raise BuildError('host_install_origin_dependency_invalid')
                targets[name] = target
            search = re.findall(r'\((?:RPATH|RUNPATH)\).*?\[([^\]]*)\]', dynamic)
            if len(search) > 1:
                raise BuildError('host_elf_search_path_ambiguous')
            patchelf = shutil.which('patchelf')
            if not patchelf:
                raise BuildError('host_install_elf_tools_missing')
            # dpkg-shlibdeps does not expand ORIGIN in NEEDED; patch only a disposable analysis copy.
            digest = sha256(path)
            directory = work / 'origin-analysis'
            directory.mkdir(exist_ok=True, mode=0o700)
            analyzed = directory / str(len(elf))
            shutil.copyfile(path, analyzed)
            analyzed.chmod(0o600)
            for name, target in targets.items():
                run([patchelf, '--replace-needed', name, target.name, analyzed], cwd=work, env=env)
            if search:
                expanded = search_directories(path, search[0].split(':'))
                run([patchelf, '--set-rpath', ':'.join(map(str, expanded)), analyzed], cwd=work, env=env)
            if sha256(path) != digest:
                raise BuildError('host_install_staged_runtime_changed')
        elf.append(analyzed)
        for soname in re.findall(r'\(SONAME\).*?\[([^\]]+)\]', dynamic):
            match = re.fullmatch(r'([A-Za-z0-9_.+-]+)\.so\.([A-Za-z0-9_.+-]+)', soname)
            if not match:
                match = re.fullmatch(r'([A-Za-z0-9_.+-]+)-([0-9][A-Za-z0-9_.+-]*)\.so', soname)
            if not match:
                # Node/Bare add-ons expose SONAMEs but have no Debian shared-library version.
                if re.fullmatch(r'[A-Za-z0-9_.+-]+(?:\.so|\.node|(?:@[0-9]+)?\.bare)', soname):
                    continue
                raise BuildError('host_install_private_soname_unsupported')
            shlibs.add(match[1] + ' ' + match[2] + ' ' + package)
    if not elf:
        raise BuildError('host_install_elf_missing')
    local = work / 'debian/shlibs.local'
    local.write_text(''.join(line + '\n' for line in sorted(shlibs)))
    # Missing external dependency metadata is fatal; only bundled SONAMEs map to this package.
    result = run(['dpkg-shlibdeps', '-O', '-x' + package, '-L' + str(local), *['-l' + str(p) for p in sorted(directories)], *['-e' + str(p) for p in elf]], cwd=work, env=env)
    lines = result.splitlines()
    if len(lines) != 1 or not lines[0].startswith('shlibs:Depends=') or '\r' in result:
        raise BuildError('host_install_dependencies_invalid')
    return lines[0].split('=', 1)[1]


def archive(tree: Path, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise BuildError('host_install_paths_invalid')
    run(['dpkg-deb', '--root-owner-group', '--threads-max=1', '-Zgzip', '-z6', '--build', tree, output], cwd=tree.parent, env=build_environment(tree.parent, {}))


def build(candidate: Path, controller: Path, output: Path) -> None:
    if platform.system() != 'Linux':
        raise BuildError('host_install_platform_unsupported')
    targets = {'x86_64': ('amd64', 'x86_64', 62), 'aarch64': ('arm64', 'aarch64', 183)}
    if platform.machine() not in targets:
        raise BuildError('host_install_runtime_target_mismatch')
    arch, host_arch, machine = targets[platform.machine()]
    if not all(p.is_absolute() and p.resolve() == p for p in [candidate, controller, output]) or output.exists() or output.is_symlink():
        raise BuildError('host_install_paths_invalid')
    info = regular(controller)
    if not stat.S_ISREG(info.st_mode) or not 20 <= info.st_size <= 256 * 1024**2:
        raise BuildError('host_install_controller_invalid')
    with controller.open('rb') as stream:
        header = stream.read(20)
    if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != machine:
        raise BuildError('host_install_controller_target_mismatch')
    node = shutil.which('node')
    if not node:
        raise BuildError('host_install_build_node_missing')
    env = build_environment(candidate.parent, {})
    verifier = (ROOT / 'tools/sign_host_runtime.mjs').as_uri()
    command = [node, '--input-type=module', '--eval', f'import({json.dumps(verifier)}).then(async m=>console.log(JSON.stringify(await m.verifySignedHostCandidate(process.argv[1]))))']
    checked = json.loads(run([*command, candidate], cwd=candidate.parent, env=env))
    manifest = json.loads((candidate / 'manifest.json').read_text())
    if manifest['platform'] != 'linux' or manifest['architecture'] != host_arch:
        raise BuildError('host_install_runtime_target_mismatch')
    helper_hash = sha256(controller)
    trees = stage_packages(candidate, controller, output, checked['manifestSha256'], helper_hash, arch)
    staged = trees[1] / BASE / 'Runtimes' / checked['manifestSha256']
    if json.loads(run([*command, staged], cwd=output, env=env)) != checked:
        raise BuildError('host_install_staged_runtime_changed')
    packages = []
    for tree, name in zip(trees, package_names(checked['manifestSha256'], helper_hash)):
        required = dependencies(tree, name, output / (tree.name + '-dependencies'))
        if required:
            with (tree / 'DEBIAN/control').open('a') as control:
                control.write('Depends: ' + required + '\n')
        package = output / (name + '_1_' + arch + '.deb')
        archive(tree, package)
        packages.append({'file': package.name, 'sha256': sha256(package), 'depends': required})
    (output / 'qualification.json').write_text(json.dumps({'schemaVersion': 1, 'qualification': 'built-not-installed', 'platform': 'linux', 'architecture': arch, 'host': checked, 'controllerSha256': helper_hash, 'packages': packages, 'osCodeSigningQualified': False, 'installedProfileProvisioningQualified': False, 'runtimeQualified': False, 'redistributable': False}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['candidate', 'controller', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        build(args.candidate, args.controller, args.output)
    except (BuildError, OSError, ValueError, KeyError) as error:
        parser.exit(1, str(error) + '\n')
