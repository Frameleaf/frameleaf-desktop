"""Requalify an exact retained Windows database component without recompiling it."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

from build_host_database_windows import qualify
from windows_private_directory import create_private_directory
from build_runtime import BuildError, build_environment, relative, sha256


def extract_candidate(archive, output, expected_digest, revision, lock):
    if not re.fullmatch(r'[a-f0-9]{64}', expected_digest) or sha256(archive) != expected_digest:
        raise BuildError('host_database_replay_digest_mismatch')
    with zipfile.ZipFile(archive) as bundle:
        metadata = bundle.getinfo('qualification.json')
        if metadata.file_size > 65536:
            raise BuildError('host_database_replay_receipt_invalid')
        receipt = json.loads(bundle.read(metadata))
        if (receipt.get('pins') != lock or receipt.get('sourceRevision') != revision
                or receipt.get('platform') != 'windows-x86_64'
                or receipt.get('redistributable') is not False):
            raise BuildError('host_database_replay_receipt_invalid')
        entries = [item for item in bundle.infolist() if item.filename.startswith('postgres/')]
        if not entries or len(entries) > 20000 or sum(item.file_size for item in entries) > 1024**3:
            raise BuildError('host_database_replay_inventory_invalid')
        names = set()
        for item in entries:
            name = relative(item.orig_filename.rstrip('/')).casefold()
            if name in names or stat.S_ISLNK(item.external_attr >> 16) or item.external_attr & 0x400:
                raise BuildError('host_database_replay_path_invalid')
            names.add(name)
        create_private_directory(output)
        for item in entries:
            bundle.extract(item, output)
    return receipt


def replay(archive, output, expected_digest, revision):
    if os.name != 'nt':
        raise BuildError('host_database_replay_requires_windows')
    lock = json.loads((Path(__file__).parent.parent / 'runtime/host-database.json').read_text())
    receipt = extract_candidate(archive, output, expected_digest, revision, lock)
    prefix = output / 'postgres'
    env = build_environment(output, os.environ)
    env['PATH'] = str(prefix / 'bin') + os.pathsep + env['PATH']
    env['FRAMELEAF_BUILD_ERROR_LOG'] = str(output / 'command-error.log')
    report = {'qualification': 'failed', 'archiveSha256': expected_digest,
              'sourceRevision': receipt['sourceRevision'], 'redistributable': False,
              'installedAcceptance': False, 'dlls': [], 'entrypoints': []}
    try:
        dlls = sorted((prefix / 'bin').glob('*.dll'))
        if not 0 < len(dlls) <= 128:
            raise BuildError('host_database_replay_inventory_invalid')
        probe = 'import ctypes,sys; ctypes.WinDLL(sys.argv[1], winmode=0x1100)'
        for binary in dlls:
            result = subprocess.run([sys.executable, '-c', probe, str(binary)], cwd=output, env=env,
                                    capture_output=True, text=True, errors='replace', timeout=15)
            report['dlls'].append({'name': binary.name, 'exitCode': result.returncode,
                                   'stderr': result.stderr[:2048]})
        for name in ['initdb', 'postgres', 'psql']:
            result = subprocess.run([str(prefix / 'bin' / (name + '.exe')), '--version'],
                                    cwd=output, env=env, capture_output=True, text=True,
                                    errors='replace', timeout=15)
            report['entrypoints'].append({'name': name, 'exitCode': result.returncode,
                                         'stdout': result.stdout[:2048], 'stderr': result.stderr[:2048]})
        if any(item['exitCode'] for item in report['entrypoints']):
            raise BuildError('host_database_replay_entrypoint_failed')
        report['fixture'] = qualify(prefix, output, lock, env)
        report['qualification'] = 'passed'
    finally:
        (output / 'loader-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args()
    replay(args.archive, args.output, args.sha256, args.source_revision)
