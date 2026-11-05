"""Stage the fixed Windows host component set; execution, ML signature and release admission remain separate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import zipfile

from bind_host_raw import build as bind_raw, read_receipt
from build_host_bundle import backup_component
from build_host_ffmpeg import unpack
from build_host_windows_support import NODE_EXE_SHA
from build_runtime import BuildError, git_blob, inventory, regular, sha256
from obtain_host_component import obtain as obtain_component, validate_approval
from verify_reused_host_sources import verify as verify_reused

SOURCE_REVISION = 'c64039743af7bb0d68b602ff842683906019de52'
MANAGER_REVISION = '6cb1613e67a988fdfad7042c4e07be9d1bf609fc'
# Canonical Git archives independently verified for this immutable application snapshot.
SOURCE_ARCHIVES = {
    'web': 'a2cace3f8eddb83ec5f5c4a90f00916e8fdeed92a0d5a510fabf31cb2f86c99a',
    'plugin': '41aad26098c4db5807e37518a0e4868bc657cc02c778e59c08383a0381b5c6a2',
    'studio': '4d6cb68c2eac8f59cf335111c260b44a43f1c93b49dd9ae39f49491ee02451b0',
    'server': '1a542a8ceedb577eef058d9dca39f5558b1927d8d8ead6c9c36d9a6b1ce89a42',
    'manager': '07549ce9a7145d1e5b5793b88fc5a926e40432db2db71542c887539447a77bd4',
}
BUILD_NODE_SHA = 'dccc52de28d8df2ee22d2062424f8c563070d95d8ad70c54c4bf01d590dec14f'
WORKFLOWS = {role: '.github/workflows/' + name + '.yml' for role, name in {
    'assets': 'windows-host-assets', 'server': 'windows-host-server',
    'manager': 'windows-host-manager', 'database': 'windows-host-database',
    'raw': 'windows-host-raw', 'media': 'windows-host-media', 'hdr': 'windows-host-hdr',
    'backup': 'native-backup', 'ml': 'factory-runtime',
}.items()}
ARCHIVES = {
    'assets': 'host-assets.tar.gz', 'server': 'windows-server-candidate.tar.gz',
    'manager': 'manager-component.tar.gz', 'raw': 'windows-raw-component.tar.gz',
    'backup': 'backup-component.tar.gz', 'ml': 'runtime.tar',
}


def validate_policy(approvals: dict) -> None:
    """Bind each required role to its producer before any download or output creation."""
    try:
        if not isinstance(approvals, dict) or set(approvals) != set(WORKFLOWS):
            raise ValueError()
        ids = set()
        for role, approved in approvals.items():
            validate_approval(approved)
            if approved['workflow'] != WORKFLOWS[role] or approved['artifactId'] in ids:
                raise ValueError()
            ids.add(approved['artifactId'])
    except (BuildError, ValueError, TypeError, KeyError) as error:
        raise BuildError('host_windows_component_policy_invalid') from error


def checked_receipt(root: Path, payload: str, target: str | None) -> dict:
    """Verify the complete selected payload without rewriting the producer's receipt."""
    receipt = read_receipt(root / 'qualification.json')
    if (not isinstance(receipt, dict) or type(receipt.get('schemaVersion')) is not int
            or receipt.get('schemaVersion') != 1 or receipt.get('qualification') != 'passed'
            or receipt.get('redistributable') is not False
            or (payload != 'backup' and (not isinstance(receipt.get('sourceRevision'), str)
                or not re.fullmatch('[a-f0-9]{40}', receipt['sourceRevision'])))
            or (target is not None and receipt.get('platform') != target)):
        raise BuildError('host_windows_component_receipt_invalid')
    expected = receipt.get('files')
    if payload == 'server':
        if not isinstance(expected, dict) or set(expected) != {'server'}:
            raise BuildError('host_windows_component_metadata_required')
        expected = expected['server']
    actual = inventory(root / payload)
    if payload == 'backup':
        if backup_component(root / payload) != receipt:
            raise BuildError('host_windows_component_backup_receipt_mismatch')
        actual.pop('component.json', None)
    if not isinstance(expected, dict) or not expected or expected != actual:
        raise BuildError('host_windows_component_inventory_mismatch:' + payload)
    return receipt


def check_source(role: str, receipt: dict, blobs: dict[str, bytes]) -> None:
    """Keep original builder identities and the pinned current application inputs explicit."""
    lock = 'manager/package-lock.json' if role == 'manager' else 'pnpm-lock.yaml'
    if (receipt.get('qualification') != 'passed'
            or receipt.get('sourceRevision') != (MANAGER_REVISION if role == 'manager' else SOURCE_REVISION)
            or receipt.get('sourceArchiveSha256') != SOURCE_ARCHIVES[role]
            or receipt.get('nodeSha256') != (BUILD_NODE_SHA if role in {'web', 'studio'} else NODE_EXE_SHA)
            or receipt.get('redistributable') is not False
            or (role != 'studio' and receipt.get('lockfileSha256') != hashlib.sha256(blobs[lock]).hexdigest())
            or (role in {'web', 'plugin', 'server'} and receipt.get('pnpmVersion') != '12.11.2')
            or (role in {'server', 'manager'} and receipt.get('nodeVersion') != '26.11.1')
            or (role in {'web', 'studio'} and (
                receipt.get('studioLockfileSha256') != hashlib.sha256(blobs['studio/engine-package-lock.json']).hexdigest()
                or receipt.get('npmVersion') != json.loads(blobs['studio/engine-build.json'])['npm']))
            or (role in {'web', 'plugin', 'studio', 'manager'} and receipt.get('runtimeQualified') is not False)
            or (role == 'studio' and receipt.get('browserIncluded') is not False)):
        raise BuildError('host_windows_component_source_mismatch:' + role)


def obtain(source: Path, approvals: dict, output: Path) -> None:
    """Use exclusively owned inputs throughout; the output contains candidates, never executable authority."""
    validate_policy(approvals)
    if (any(not p.is_absolute() or p.resolve() != p for p in [source, output])
            or output.exists() or output.is_symlink() or output.is_relative_to(source)
            or source.is_relative_to(output)
            or not stat.S_ISDIR(regular(source).st_mode)
            or not stat.S_ISDIR(regular(output.parent).st_mode)):
        raise BuildError('host_windows_component_paths_invalid')
    if platform.system() != 'Windows' or platform.machine() not in {'AMD64', 'x86_64'}:
        raise BuildError('host_windows_component_target_unsupported')
    git = shutil.which('git')
    if not git:
        raise BuildError('host_windows_component_git_missing')
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1',
               GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0')
    blobs = {name: git_blob(git, source, SOURCE_REVISION, name, env) for name in [
        'package.json', 'pnpm-lock.yaml', 'manager/package-lock.json',
        'studio/engine-package-lock.json', 'studio/engine-build.json']}
    if json.loads(blobs['package.json']).get('packageManager') != 'pnpm@12.11.2':
        raise BuildError('host_windows_component_source_control_invalid')

    output.mkdir(mode=0o700)
    try:
        inputs = output / 'inputs'
        inputs.mkdir(mode=0o700)
        roots, producers = {}, {}
        for role, approved in approvals.items():
            acquired = inputs / role
            obtain_component(approved, acquired)
            producers[role] = {'approval': approved, 'producerSha256': sha256(acquired / 'producer.json')}
            component = acquired / 'component'
            roots[role] = component
            if role in ARCHIVES:
                archive = component / ARCHIVES[role]
                if set(p.name for p in component.iterdir()) != {ARCHIVES[role]}:
                    raise BuildError('host_windows_component_archive_layout_invalid:' + role)
                expanded = acquired / 'expanded'
                expanded.mkdir(mode=0o700)
                unpack(archive, expanded)
                archive.unlink()
                roots[role] = expanded / {'server': 'server-candidate', 'raw': 'raw-candidate'}.get(role, '')
        assets = roots['assets']
        receipts = {}
        for role, payload, target in [
            ('web', 'www', None), ('plugin', 'plugin', 'windows-x64'),
            ('studio', 'studio-worker', 'Windows-AMD64'),
            ('server', 'server', 'Windows-AMD64'), ('manager', 'manager', None),
            ('database', 'postgres', 'windows-x86_64'), ('raw', 'raw', 'Windows-AMD64'),
            ('media', 'media', 'windows-x64'), ('hdr', 'media', 'windows-AMD64'),
            ('backup', 'backup', None),
        ]:
            root = assets / role if role in {'web', 'plugin', 'studio'} else roots[role]
            receipts[role] = checked_receipt(root, payload, target)
            if role in SOURCE_ARCHIVES:
                current = read_receipt(root / 'server-qualification.json') if role == 'server' else receipts[role]
                check_source(role, current, blobs)
                if role == 'server' and receipts[role]['sourceRevision'] != SOURCE_REVISION:
                    raise BuildError('host_windows_component_source_mismatch:' + role)
        reused = verify_reused(source, SOURCE_REVISION, {role: receipts[role] for role in ['database', 'raw', 'media', 'hdr']})
        # This existing binder checks the original/adapted module pins and component-bound metadata proof.
        bind_raw(source, roots['server'], roots['raw'], output / 'bound-server-raw')
        ml = roots['ml']
        manifest = read_receipt(ml / 'manifest.json')
        signature = regular(ml / 'manifest.sig')
        if (not isinstance(manifest, dict) or manifest.get('platform') != 'windows'
                or manifest.get('architecture') != 'x86_64'
                or manifest.get('files') != inventory(ml / 'payload')
                or not stat.S_ISREG(signature.st_mode) or not 0 < signature.st_size <= 16 * 1024):
            raise BuildError('host_windows_component_ml_candidate_invalid')
        report = {
            'schemaVersion': 1, 'qualification': 'passed', 'sourceRevision': SOURCE_REVISION,
            'components': {role: {'root': roots[role].relative_to(output).as_posix(), **producers[role]}
                           for role in WORKFLOWS},
            'receiptSha256': {role: sha256((assets / role if role in {'web', 'plugin', 'studio'} else roots[role]) / 'qualification.json')
                              for role in receipts},
            'reusedSources': reused, 'mlSignatureVerified': False,
            'requiresCurrentWindowsConsumers': True, 'runtimeQualified': False, 'redistributable': False,
            'scope': 'Authenticated producer archives, static payload/source checks and metadata/RAW binding only; ML signature verification and current Windows consumers are mandatory before assembly',
        }
        partial = output / 'qualification.json.part'
        partial.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
        partial.replace(output / 'qualification.json')
    except (Exception, KeyboardInterrupt):
        shutil.rmtree(output)
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'approvals', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        info = regular(args.approvals)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 16 * 1024:
            raise BuildError('host_windows_component_policy_invalid')
        obtain(args.source, json.loads(args.approvals.read_text(encoding='utf-8-sig')), args.output)
    except (BuildError, OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, str(error) if isinstance(error, BuildError) else 'host_windows_components_failed')
