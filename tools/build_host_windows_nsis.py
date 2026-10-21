"""Author private Windows/x86_64 host installers with NSIS 3.11; never execute the controller.

Run the same installer with /REMOVE to remove protected code while retaining user data.
NSIS 3.11 restricted staging: https://github.com/nsis-dev/nsis/blob/v311/Source/build.cpp
(add_plugins_dir_initializer), Source/exehead/{exec.c,util.c}; Docs/src/history.but.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
from pathlib import Path

from build_host_macos_pkg import validate_identities
from build_runtime import BuildError, build_environment, regular, run, sha256

ROOT = Path(__file__).resolve().parent.parent


def windows_name(name: str) -> str:
    parts = name.split('/')
    if not name or len(name) > 220 or len(parts) > 32:
        raise BuildError('host_install_path_invalid')
    for part in parts:
        if (not part or part in {'.', '..'} or part.endswith(('.', ' '))
            or any(ord(c) < 32 or ord(c) == 127 or c in '\\:*?"<>|' for c in part)
            or re.fullmatch(r'(?i:con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(?:\..*)?', part)):
            raise BuildError('host_install_path_invalid')
    return name


def quote(value: str) -> str:
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise BuildError('host_install_path_invalid')
    return '"' + value.replace('$', '$$').replace('"', '$\\"') + '"'


def inspect_controller(controller: Path, approved: str) -> None:
    validate_identities('a' * 64, approved)
    info = regular(controller)
    if not stat.S_ISREG(info.st_mode) or not 256 <= info.st_size <= 256 * 1024**2 or sha256(controller) != approved:
        raise BuildError('host_install_controller_changed')
    raw = controller.read_bytes()
    offset = int.from_bytes(raw[60:64], 'little')
    if (raw[:2] != b'MZ' or offset < 64 or offset + 26 > len(raw)
        or raw[offset:offset + 6] != b'PE\0\0\x64\x86'
        or raw[offset + 24:offset + 26] != b'\x0b\x02'):
        raise BuildError('host_install_controller_target_mismatch')
    # Inspect the compiled policy bytes; no candidate-controlled executable is launched.
    policy = (ROOT / 'runtime/release-trust.json').read_bytes()
    if policy not in raw or any(mode not in raw for mode in [b'--install-windows-package', b'--remove-windows-package']):
        raise BuildError('host_install_controller_trust_mismatch')


def installer_script(manifest: str, controller: str, names: list[str]) -> str:
    validate_identities(manifest, controller)
    folded = set()
    for name in names:
        windows_name(name)
        if name.lower() in folded:
            raise BuildError('host_install_inventory_invalid')
        folded.add(name.lower())
    text = r'''Unicode true
RequestExecutionLevel admin
CRCCheck force
SetCompressor zlib
Name "Frameleaf native host - internal candidate"
OutFile "FrameleafNativeHost-internal.exe"
!include "FileFunc.nsh"
Page instfiles
Var DirectoryHandle
Var ControllerHandle
Var Mode
Function .onInit
  ${GetParameters} $0
  StrCpy $Mode "install"
  StrCmp $0 "" accepted
  StrCmp $0 "/S" accepted
  StrCmp $0 "/REMOVE" remove
  StrCmp $0 "/REMOVE /S" remove
  StrCmp $0 "/S /REMOVE" remove
  SetErrorLevel 64
  Quit
remove:
  StrCpy $Mode "remove"
accepted:
FunctionEnd
Section
  InitPluginsDir
  ; NSIS 3.11 creates an admin-owned restricted directory and retries precreation races.
  ; Hold the directory against rename/deletion through helper exit.
  System::Call 'kernel32::CreateFileW(w "$PLUGINSDIR", i 0x80000000, i 1, p 0, i 3, i 0x02200000, p 0) p.r1'
  StrCmp $1 -1 failed
  StrCpy $DirectoryHandle $1
  SetOutPath "$PLUGINSDIR"
  ClearErrors
  File /oname=frameleaf-native-host.exe "controller.bin"
  IfErrors failed
  System::Call 'kernel32::CreateFileW(w "$PLUGINSDIR\frameleaf-native-host.exe", i 0x80000000, i 1, p 0, i 3, i 0x00200000, p 0) p.r1'
  StrCmp $1 -1 failed
  StrCpy $ControllerHandle $1
  StrCmp $Mode "remove" remove_code
'''
    for index, name in enumerate(names):
        parent, _, basename = name.rpartition('/')
        destination = '\\candidate' + ('\\' + parent.replace('/', '\\') if parent else '')
        # Only the fixed NSIS variable is interpreted; every payload-controlled byte is escaped.
        text += '  SetOutPath "$PLUGINSDIR' + quote(destination)[1:] + '\n'
        text += '  File ' + quote('/oname=' + basename) + ' "files\\' + str(index) + '"\n  IfErrors failed\n'
    ids = manifest + ' ' + controller
    text += '''  SetOutPath "$PLUGINSDIR"
  ClearErrors
  ExecWait '\"$PLUGINSDIR\\frameleaf-native-host.exe\" --install-windows-package \"$PLUGINSDIR\\candidate\" ''' + ids + '''' $0
  IfErrors failed
  StrCmp $0 0 done failed
remove_code:
  ClearErrors
  ExecWait '\"$PLUGINSDIR\\frameleaf-native-host.exe\" --remove-windows-package ''' + ids + '''' $0
  IfErrors failed
  StrCmp $0 0 done failed
failed:
  System::Call 'kernel32::CloseHandle(p $ControllerHandle)'
  System::Call 'kernel32::CloseHandle(p $DirectoryHandle)'
  SetErrorLevel 1
  Abort "Native package operation failed; retained data and maintenance fences must be preserved."
done:
  System::Call 'kernel32::CloseHandle(p $ControllerHandle)'
  System::Call 'kernel32::CloseHandle(p $DirectoryHandle)'
  SetErrorLevel 0
SectionEnd
'''
    return text


def stage(candidate: Path, controller: Path, output: Path, manifest: str, approved: str) -> list[str]:
    validate_identities(manifest, approved)
    if (not all(path.is_absolute() and path.resolve() == path for path in [candidate, controller, output])
        or output.exists() or output.is_symlink() or output.is_relative_to(candidate)):
        raise BuildError('host_install_paths_invalid')
    inspect_controller(controller, approved)
    metadata = json.loads((candidate / 'manifest.json').read_text())
    names = ['manifest.json', 'manifest.sig', *['payload/' + name for name in sorted(metadata['files'])]]
    script = installer_script(manifest, approved, names)
    if sha256(candidate / 'manifest.json') != manifest:
        raise BuildError('host_install_runtime_changed')
    output.mkdir(mode=0o700)
    (output / 'files').mkdir()
    for index, name in enumerate(names):
        source = candidate / name
        if not stat.S_ISREG(regular(source).st_mode):
            raise BuildError('host_install_inventory_invalid')
        shutil.copyfile(source, output / 'files' / str(index))
        if sha256(source) != sha256(output / 'files' / str(index)):
            raise BuildError('host_install_staged_runtime_changed')
    shutil.copyfile(controller, output / 'controller.bin')
    inspect_controller(output / 'controller.bin', approved)
    (output / 'installer.nsi').write_text(script, encoding='utf-8')
    return names


def build(candidate: Path, controller: Path, output: Path, approved: str) -> None:
    # Trusted authoring tools are resolved independently from the supplied payload/controller.
    node, makensis = shutil.which('node'), shutil.which('makensis')
    if not node or not makensis:
        raise BuildError('host_install_build_tools_missing')
    env = build_environment(candidate.parent, os.environ)
    if run([makensis, '-VERSION'], cwd=candidate.parent, env=env).strip() != 'v3.11':
        raise BuildError('host_install_nsis_version_unapproved')
    inspect_controller(controller, approved)
    verifier = (ROOT / 'tools/sign_host_runtime.mjs').as_uri()
    command = [node, '--input-type=module', '--eval', f'import({json.dumps(verifier)}).then(async m=>console.log(JSON.stringify(await m.verifySignedHostCandidate(process.argv[1]))))']
    checked = json.loads(run([*command, candidate], cwd=candidate.parent, env=env))
    metadata = json.loads((candidate / 'manifest.json').read_text())
    if metadata['platform'] != 'windows' or metadata['architecture'] != 'x86_64':
        raise BuildError('host_install_runtime_target_mismatch')
    names = stage(candidate, controller, output, checked['manifestSha256'], approved)
    # Verify the exact numbered bytes embedded in NSIS using the same compiled release authority.
    staged = output / 'checked-candidate'
    for index, name in enumerate(names):
        target = staged / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(output / 'files' / str(index), target)
    if json.loads(run([*command, staged], cwd=output, env=env)) != checked:
        raise BuildError('host_install_staged_runtime_changed')
    run([makensis, '-NOCONFIG', '-V2', 'installer.nsi'], cwd=output, env=env)
    package = output / 'FrameleafNativeHost-internal.exe'
    if not stat.S_ISREG(regular(package).st_mode):
        raise BuildError('host_install_package_missing')
    (output / 'qualification.json').write_text(json.dumps({
        'schemaVersion': 1, 'qualification': 'built-not-installed', 'platform': 'windows',
        'architecture': 'x86_64', 'host': checked, 'controllerSha256': approved,
        'package': package.name, 'packageSha256': sha256(package), 'nsisVersion': '3.11',
        'osCodeSigningQualified': False, 'installedProfileProvisioningQualified': False,
        'runtimeQualified': False, 'redistributable': False,
    }, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['candidate', 'controller', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--controller-sha256', required=True)
    args = parser.parse_args()
    try:
        build(args.candidate, args.controller, args.output, args.controller_sha256)
    except (BuildError, OSError, ValueError, KeyError) as error:
        parser.exit(1, str(error) + '\n')
