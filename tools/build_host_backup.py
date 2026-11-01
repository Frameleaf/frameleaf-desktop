"""Stage a digest-pinned private restic component and qualify encrypted synthetic recovery."""
import argparse
import bz2
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import stat
import subprocess
import zipfile

from build_host_database import download
from build_runtime import BuildError, build_environment, inventory, run, sha256

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = json.loads((ROOT / 'runtime/host-backup.json').read_text())
MAX_BINARY_BYTES = 128 * 1024 * 1024


def artifact(system, machine):
    system = {'Darwin': 'darwin', 'Linux': 'linux', 'Windows': 'windows'}.get(system)
    machine = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'amd64', 'AMD64': 'amd64'}.get(machine)
    value = CONTRACT['artifacts'].get(f'{system}_{machine}')
    if value is None:
        raise BuildError('host_backup_target_unsupported')
    return value


def unpack(archive, destination, expected):
    if sha256(archive) != expected:
        raise BuildError('host_backup_archive_digest_mismatch')
    if archive.suffix == '.zip':
        with zipfile.ZipFile(archive) as contents:
            entries = contents.infolist()
            if len(entries) != 1:
                raise BuildError('host_backup_archive_invalid')
            entry = entries[0]
            if (entry.filename != archive.stem + '.exe'
                    or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)
                    or not 0 < entry.file_size <= MAX_BINARY_BYTES):
                raise BuildError('host_backup_archive_invalid')
            with contents.open(entry) as source, destination.open('xb') as output:
                copy_binary(source, output)
    elif archive.suffix == '.bz2':
        with bz2.open(archive, 'rb') as source, destination.open('xb') as output:
            copy_binary(source, output)
    else:
        raise BuildError('host_backup_archive_invalid')
    destination.chmod(0o755)


def copy_binary(source, output):
    size = 0
    while chunk := source.read(65536):
        size += len(chunk)
        if size > MAX_BINARY_BYTES:
            raise BuildError('host_backup_binary_limit')
        output.write(chunk)
    if size == 0:
        raise BuildError('host_backup_binary_empty')


def qualify(binary, work, env):
    checkpoint = work / 'checkpoint'
    checkpoint.mkdir(mode=0o700)
    expected = {'database.dump': b'synthetic database checkpoint; no user data',
                'recovery.json': b'{"databaseFormat":"frameleaf-canonical"}'}
    for name, content in expected.items():
        (checkpoint / name).write_bytes(content)
    key = work / 'recovery-key'
    key.write_text(secrets.token_urlsafe(32))
    key.chmod(0o600)
    wrong_key = work / 'wrong-key'
    wrong_key.write_text(secrets.token_urlsafe(32))
    wrong_key.chmod(0o600)
    args = [binary, '--repo', work / 'repository', '--password-file', key,
            '--cache-dir', work / 'cache', '--json']
    try:
        version = run([binary, 'version'], cwd=work, env=env)
        if not version.startswith('restic ' + CONTRACT['version'] + ' '):
            raise BuildError('host_backup_version_mismatch')
        run([*args, 'init'], cwd=work, env=env)
        run([*args, 'cat', 'config'], cwd=work, env=env)
        bad_args = [wrong_key if value == key else value for value in args]
        wrong = subprocess.run([*bad_args, 'cat', 'config'], cwd=work, env=env,
                               capture_output=True, timeout=60)
        if wrong.returncode == 0:
            raise BuildError('host_backup_wrong_key_accepted')
        run([*args, 'cat', 'config'], cwd=work, env=env)
        operation = '11111111-1111-4111-8111-111111111111'
        run([*args, 'backup', '--tag', 'frameleaf-manager-database', '--tag', operation,
             '--tag', 'frameleaf-canonical', '.'], cwd=checkpoint, env=env)
        snapshots = json.loads(run([*args, 'snapshots', '--tag',
                                    'frameleaf-manager-database,frameleaf-canonical'], cwd=work, env=env))
        if len(snapshots) != 1 or snapshots[0]['paths'] != [str(checkpoint)]:
            raise BuildError('host_backup_snapshot_invalid')
        run([*args, 'check', '--read-data'], cwd=work, env=env)
        restored = work / 'restored'
        run([*args, 'restore', snapshots[0]['id'], '--target', restored, '--verify'], cwd=work, env=env)
        if set(p.name for p in restored.iterdir()) != set(expected):
            raise BuildError('host_backup_restore_invalid')
        for name, content in expected.items():
            if (restored / name).read_bytes() != content:
                raise BuildError('host_backup_restore_invalid')
        return {'version': version, 'encryptedRepository': True, 'wrongKeyRejected': True,
                'readDataCheck': True, 'verifiedRestore': True, 'syntheticFiles': sorted(expected)}
    finally:
        key.unlink(missing_ok=True)
        wrong_key.unlink(missing_ok=True)


def build(output):
    if not output.is_absolute() or output.resolve() != output or output.exists() or output.is_symlink():
        raise BuildError('host_backup_output_invalid')
    pin = artifact(platform.system(), platform.machine())
    output.mkdir(mode=0o700)
    work, component = output / 'work', output / 'backup'
    work.mkdir(mode=0o700)
    component.mkdir(mode=0o700)
    env = build_environment(work, os.environ)
    env['GOMAXPROCS'] = '1'
    archive = work / pin['url'].rsplit('/', 1)[1]
    binary = component / ('restic.exe' if os.name == 'nt' else 'restic')
    receipt = {'schemaVersion': 1, 'name': 'restic', 'version': CONTRACT['version'],
               'source': CONTRACT['source'], 'artifact': pin, 'qualification': 'failed',
               'runtimeQualified': False, 'redistributable': False}
    try:
        download(pin['url'], archive, pin['sha256'])
        unpack(archive, binary, pin['sha256'])
        shutil.copyfile(ROOT / 'runtime/host-backup-LICENSE.txt', component / 'LICENSE')
        receipt['checks'] = qualify(binary, work, env)
        receipt['files'] = inventory(component)
        receipt['qualification'] = 'passed'
        (component / 'component.json').write_text(json.dumps(receipt, indent=2) + '\n')
    finally:
        (output / 'qualification.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        build(args.output)
    except (BuildError, OSError, ValueError, EOFError, zipfile.BadZipFile) as error:
        parser.exit(1, str(error) if isinstance(error, BuildError) else 'host_backup_component_failed')
