"""Compare reused Windows native inputs with selected Git source; not payload or runtime admission."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tomllib

from build_host_database import database_contract
from build_host_ffmpeg import ffmpeg_contract
from build_host_media import codec_pin
from build_host_raw import raw_contract
from build_runtime import BuildError, git_blob, regular

def verify(source: Path, revision: str, receipts: dict) -> dict:
    """Check original receipts from already authenticated artifacts; never rewrite their identities.

    The caller must separately verify producer identity, payload inventories and current runtime consumers.
    """
    if (not source.is_absolute() or source.resolve() != source
            or not re.fullmatch(r'[a-f0-9]{40}', revision)
            or not isinstance(receipts, dict) or set(receipts) != {'database', 'raw', 'media', 'hdr'}):
        raise BuildError('host_reused_sources_invalid')
    for report in receipts.values():
        if (not isinstance(report, dict) or report.get('qualification') != 'passed'
                or not isinstance(report.get('sourceRevision'), str)
                or not re.fullmatch(r'[a-f0-9]{40}', report['sourceRevision'])):
            raise BuildError('host_reused_receipt_invalid')
    git = shutil.which('git')
    if not git:
        raise BuildError('host_reused_git_missing')
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1',
               GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0')
    consumed = {}
    def blob(name):
        data = git_blob(git, source, revision, name, env)
        consumed[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        return data
    try:
        database = receipts['database']
        expected = json.loads((Path(__file__).parents[1] / 'runtime/host-database.json').read_text())
        if database['pins'] != expected:
            raise BuildError('host_reused_database_pin_changed')
        database_contract(blob('docker/postgres/Dockerfile').decode(), database['pins'])
        raw = receipts['raw']
        pin = json.loads(blob('server/base-image/sources/darktable.json'))
        libraw = json.loads(blob('server/base-image/sources/libraw.json'))
        patches = {name: blob('server/test/native/' + name)
                   for name in ['patch-darktable-lens.py', 'patch-darktable-mask-geometry.py']}
        raw_contract(pin, patches, libraw)
        if pin != raw['source'] or libraw != raw['librawSource']:
            raise BuildError('host_reused_raw_source_changed')
        media = receipts['media']
        lock = tomllib.loads(blob('mise.lock').decode())
        descriptor = json.loads(blob('server/base-image/packages/ffmpeg.json'))
        if (ffmpeg_contract(lock, descriptor, 'windows-x64') != media['archive']
                or descriptor['version'] != media['version']):
            raise BuildError('host_reused_media_pin_changed')
        hdr = receipts['hdr']
        snapshot = hdr['sourceFiles']
        if (not isinstance(snapshot, dict)
                or not {'server/native/CMakeLists.txt', 'server/native/image-hdr.cc',
                        'server/test/native/image-hdr.test.mjs'}.issubset(snapshot)
                or any(not isinstance(meta, dict) or set(meta) != {'sha256', 'bytes'}
                       or not isinstance(meta['sha256'], str)
                       or not re.fullmatch(r'[a-f0-9]{64}', meta['sha256'])
                       or type(meta['bytes']) is not int or meta['bytes'] < 0
                       for meta in snapshot.values())):
            raise BuildError('host_reused_hdr_snapshot_invalid')
        if hdr['nodeVersion'] != '26.11.1':
            raise BuildError('host_reused_hdr_host_node_changed')
        for name in ['libheif', 'libultrahdr']:
            base = 'server/base-image/sources/' + name
            pin = codec_pin(name, json.loads(blob(base + '.json')), blob(base + '-hdr.patch'))
            if pin != hdr['codecs'][name]:
                raise BuildError('host_reused_hdr_codec_changed')
        paths = subprocess.check_output([
            git, 'ls-tree', '-r', '-z', '--name-only', revision, '--', 'server/native', 'server/test/native',
        ], cwd=source, env=env, text=True, encoding='utf-8', timeout=30).split('\0')
        selected = {name for name in paths if name.startswith(('server/native/', 'server/test/native/fixtures/'))
                    or name == 'server/test/native/image-hdr.test.mjs'}
        if selected != set(hdr['sourceFiles']):
            raise BuildError('host_reused_hdr_snapshot_paths_changed')
        changed = []
        for name in sorted(selected):
            blob(name)
            if consumed[name] != hdr['sourceFiles'][name]:
                if name != 'server/test/native/image-hdr.test.mjs':
                    raise BuildError('host_reused_hdr_snapshot_changed:' + name)
                changed.append(name)
        build_node = blob('.nvmrc').decode().strip().removeprefix('v')
        if not re.fullmatch(r'\d+\.\d+\.\d+', build_node):
            raise BuildError('host_reused_build_control_invalid')
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise BuildError('host_reused_contract_invalid') from error
    return {
        'schemaVersion': 1, 'sourceRevision': revision, 'sourceContractsMatch': True,
        'originalSourceRevisions': {role: receipt['sourceRevision'] for role, receipt in receipts.items()},
        'receiptCanonicalSha256': {role: hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                         for role, receipt in receipts.items()},
        'consumedInputs': consumed,
        'hdr': {'changedFixturePaths': changed, 'originalBuildNode': hdr['nodeVersion'],
                'currentBuildControlNode': build_node, 'requiresCurrentHostQualification': True},
        'databaseCertified': database['pins']['certified'],
        'runtimeQualified': False, 'redistributable': False,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--revision', required=True)
    for role in ['database', 'raw', 'media', 'hdr']:
        parser.add_argument('--' + role, required=True, type=Path)
    args = parser.parse_args()
    try:
        receipts = {}
        for role in ['database', 'raw', 'media', 'hdr']:
            path = getattr(args, role)
            info = regular(path)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024**2:
                raise BuildError('host_reused_receipt_invalid')
            receipts[role] = json.loads(path.read_bytes())
        print(json.dumps(verify(args.source, args.revision, receipts), indent=2))
    except (BuildError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) if isinstance(error, BuildError) else 'host_reused_sources_failed')
