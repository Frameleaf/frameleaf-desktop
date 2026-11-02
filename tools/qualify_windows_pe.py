"""Qualify the RAW packager's real PE inspector against owned Windows fixtures."""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from build_runtime import BuildError, build_environment, regular, sha256
from relocate_windows import closure, inspect_pe, pe_imports


def damaged_imports(data: bytes) -> tuple[bytes, bytes]:
    # Only mutate the known two-import compiler fixture; this is not a product PE parser.
    if not pe_imports(data[:69656]):
        raise BuildError('host_pe_probe_fixture_invalid')
    number = lambda offset, size=4: int.from_bytes(data[offset:offset + size], 'little')
    header = number(60)
    optional = header + 24
    sections = optional + number(header + 20, 2)
    count = number(header + 6, 2)
    if not 1 <= count <= 96 or sections + count * 40 > len(data):
        raise BuildError('host_pe_probe_fixture_invalid')
    address = number(optional + 120)
    matches = []
    for section in range(sections, sections + count * 40, 40):
        start, length, raw = number(section + 12), number(section + 16), number(section + 20)
        if start <= address and address + 60 <= start + length and raw + length <= len(data):
            matches.append(raw + address - start)
    if len(matches) != 1:
        raise BuildError('host_pe_probe_fixture_invalid')
    table = matches[0]
    if not number(table + 12) or not number(table + 32) or any(data[table + 40:table + 60]):
        raise BuildError('host_pe_probe_fixture_invalid')
    malformed, partial = bytearray(data), bytearray(data)
    malformed[optional + 120:optional + 124] = (0xffff0000).to_bytes(4, 'little')
    partial[table + 32:table + 36] = (0xffff0000).to_bytes(4, 'little')
    return bytes(malformed), bytes(partial)


def qualify(dependencies: Path, work: Path) -> dict:
    if platform.system() != 'Windows':
        raise BuildError('host_pe_probe_windows_required')
    if not work.is_absolute() or work.exists() or work.is_symlink() or dependencies.name != 'ucrt64':
        raise BuildError('host_pe_probe_paths_invalid')
    gcc, objdump = dependencies / 'bin/gcc.exe', dependencies / 'bin/objdump.exe'
    for tool in [gcc, objdump]:
        regular(tool)
    tools = {tool.name: sha256(tool) for tool in [gcc, objdump]}
    work.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix='pe-probe-', dir=work) as temporary:
        root = Path(temporary)
        env = build_environment(root, os.environ)
        env['PATH'] = str(dependencies / 'bin') + os.pathsep + env['PATH']
        env['FRAMELEAF_BUILD_ERROR_LOG'] = str(root / 'inspection-error.log')
        source = root / 'authoring'
        source.mkdir()
        (source / 'vendor.c').write_text('#include <windows.h>\n__declspec(dllexport) int answer(void) { return GetCurrentProcessId() ? 42 : 0; }\n', encoding='utf-8')
        (source / 'probe.c').write_text('#include <windows.h>\n__declspec(dllimport) int answer(void);\nvoid entry(void) { ExitProcess(answer() == 42 ? 0 : 1); }\n', encoding='utf-8')
        try:
            target = subprocess.run([gcc, '-dumpmachine'], cwd=source, env=env, text=True,
                                    capture_output=True, check=True, timeout=60).stdout.strip()
            if target != 'x86_64-w64-mingw32':
                raise BuildError('host_pe_probe_compiler_target_invalid')
            for arguments in [
                [gcc, '-shared', '-nostdlib', '-O2', 'vendor.c', '-o', 'fl-pe-probe.dll',
                 '-Wl,--out-implib,libfl-pe-probe.a', '-Wl,--entry,0', '-lkernel32'],
                [gcc, '-nostdlib', '-O2', 'probe.c', '-o', 'probe.exe', '-Wl,--entry,entry',
                 '-L.', '-lfl-pe-probe', '-lkernel32'],
            ]:
                subprocess.run(arguments, cwd=source, env=env, text=True,
                               capture_output=True, check=True, timeout=60)
            executable = source / 'probe.exe'
            originals = executable.read_bytes()
            inspect = lambda path: inspect_pe(objdump, path, cwd=root, env=env)
            report = closure({'bin/probe.exe': executable}, [source], root / 'staged', inspect)
            expected = {'bin/probe.exe': {'fl-pe-probe.dll', 'kernel32.dll'},
                        'bin/fl-pe-probe.dll': {'kernel32.dll'}}
            if (set(report['objects']) != set(expected) or
                    any(set(report['objects'][name]['imports']) != imports for name, imports in expected.items()) or
                    report['systemLibraries'] != ['kernel32.dll'] or report['posixRuntimeRequired']):
                raise BuildError('host_pe_probe_incomplete_closure')
            refusals = []
            for index, data in enumerate(damaged_imports(originals)):
                damaged = source / f'damaged-{index}.exe'
                damaged.write_bytes(data)
                try:
                    closure({'bin/probe.exe': damaged}, [source], root / f'refused-{index}', inspect)
                except BuildError as error:
                    if str(error) not in {'host_pe_inspection_failed', 'host_pe_dependency_invalid', 'host_pe_imports_missing'}:
                        raise
                    refusals.append(str(error))
                else:
                    raise BuildError('host_pe_probe_damaged_imports_accepted')
            source.rename(root / 'unavailable-authoring')
            runtime_env = build_environment(root, os.environ)
            runtime_env['PATH'] = str(root / 'staged/bin') + os.pathsep + runtime_env['PATH']
            subprocess.run([root / 'staged/bin/probe.exe'], cwd=root, env=runtime_env,
                           capture_output=True, check=True, timeout=15)
            if tools != {tool.name: sha256(tool) for tool in [gcc, objdump]}:
                raise BuildError('host_pe_probe_tool_changed')
        except BuildError:
            log = root / 'inspection-error.log'
            if log.is_file():
                sys.stderr.write(log.read_text(encoding='utf-8')[-32768:])
            raise
        except (OSError, subprocess.SubprocessError) as error:
            detail = getattr(error, 'stderr', '') or ''
            if isinstance(detail, bytes):
                detail = detail.decode('utf-8', errors='replace')
            sys.stderr.write(detail[-32768:])
            raise BuildError('host_pe_probe_command_failed') from error
    # Report success only after fixture binaries and authoring inputs have been removed.
    return {'schemaVersion': 1, 'qualification': 'passed', 'scope': 'windows-pe-inspector',
            'tools': tools, 'compilerTarget': target, 'closure': report, 'damagedImportRefusals': refusals,
            'checks': {'knownImports': 'passed', 'malformedImports': 'passed',
                       'partialImports': 'passed', 'relocatedExecution': 'passed', 'fixtureCleanup': 'passed'},
            'fullRawConformance': False, 'installedPlatformQualified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dependencies', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    options = parser.parse_args()
    try:
        print(json.dumps(qualify(options.dependencies.resolve(), options.work.absolute()), indent=2))
    except (BuildError, OSError) as error:
        code = str(error) if isinstance(error, BuildError) else 'host_pe_probe_environment_failed'
        print(json.dumps({'qualification': 'failed', 'scope': 'windows-pe-inspector', 'code': code}))
        if isinstance(error, OSError):
            sys.stderr.write(f'{type(error).__name__}: {error}\n'[-32768:])
        raise SystemExit(1) from error
