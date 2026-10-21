"""Assemble verified Windows components into an unsigned internal host; never install it."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit

from build_host_bundle import assemble
from build_host_database import download
from build_host_ffmpeg import unpack
from build_host_server import stage_server
from build_runtime import BuildError, build_environment, git_blob, inventory, sha256

SOURCE = '9bbe7c64e720fceee2fcba0f72055c945f56b19a'
REPOSITORY = 'repos/Frameleaf/frameleaf-desktop/'


def download_geodata(destination: Path, digest: str, capture: str) -> str:
    url = urlsplit(capture)
    partial = destination.with_name(destination.name + '.part')
    if (url.scheme != 'https' or url.netloc not in {'web.archive.org', 'raw.githubusercontent.com'}
        or url.query or url.fragment or not re.fullmatch(r'[a-f0-9]{64}', digest)
        or not re.fullmatch(r'[A-Za-z0-9_.-]+', destination.name)
        or destination.exists() or destination.is_symlink() or partial.exists() or partial.is_symlink()):
        raise BuildError('host_assembly_geodata_inputs_invalid')
    for source in ['https://static.frameleaf.cloud/geodata/2026-10-11/' + destination.name, capture]:
        try:
            download(source, partial, digest)
        except (URLError, TimeoutError, BuildError):
            partial.unlink(missing_ok=True)
            continue
        partial.rename(destination)
        return source
    raise BuildError('host_assembly_geodata_sources_unavailable:' + destination.name)


def qualified_files(root: Path, directory: str, revision: str = SOURCE) -> dict:
    record = json.loads((root / 'qualification.json').read_text())
    if record.get('qualification') != 'passed' or record.get('sourceRevision') != revision:
        raise BuildError('host_assembly_component_unqualified')
    if inventory(root / directory) != record.get('files'):
        raise BuildError('host_assembly_component_changed')
    return record


def api(path: str) -> dict:
    return json.loads(subprocess.check_output(['gh', 'api', REPOSITORY + path]))


def obtain(work: Path, name: str, artifact: int, digest: str, run: int, head: str,
           conclusion: str = 'success', *, maximum_bytes: int = 2 * 1024**3) -> Path:
    metadata = api(f'actions/artifacts/{artifact}')
    producer = api(f'actions/runs/{run}')
    if (metadata['workflow_run']['id'] != run or metadata['workflow_run']['head_sha'] != head
        or metadata['expired'] or not 0 < metadata['size_in_bytes'] < 2 * 1024**3
        or producer['head_sha'] != head or producer['status'] != 'completed'
        or producer['conclusion'] != conclusion):
        raise BuildError('host_assembly_producer_mismatch')
    archive = work / (name + '.zip')
    with archive.open('xb') as stream:
        subprocess.run(['gh', 'api', REPOSITORY + f'actions/artifacts/{artifact}/zip'],
                       stdout=stream, check=True)
    if sha256(archive) != digest:
        raise BuildError('host_assembly_archive_changed')
    destination = work / name
    destination.mkdir()
    unpack(archive, destination, maximum_bytes=maximum_bytes)
    archive.unlink()
    (work / (name + '-producer.json')).write_text(json.dumps(
        {'artifact': metadata, 'run': producer, 'archiveSha256': digest}, indent=2) + '\n')
    return destination


def build(source: Path, output: Path, assets_id: str, assets_sha: str,
          assets_head: str, signature: str) -> None:
    if (platform.system() != 'Windows' or platform.machine() != 'AMD64'
        or not all(p.is_absolute() for p in [source, output])
        or output.exists() or output.is_symlink()
        or not re.fullmatch(r'[1-9][0-9]{0,19}', assets_id)
        or not re.fullmatch(r'[a-f0-9]{64}', assets_sha)
        or not re.fullmatch(r'[a-f0-9]{40}', assets_head)
        or not re.fullmatch(r'[a-f0-9]{128}', signature)):
        raise BuildError('host_assembly_inputs_invalid')
    git = shutil.which('git')
    if not git:
        raise BuildError('host_assembly_git_missing')
    output.mkdir(mode=0o700)
    work = output / 'work'
    work.mkdir(mode=0o700)
    env = build_environment(work, os.environ)
    def blob(name: str) -> bytes:
        return git_blob(git, source, SOURCE, name, env)
    host = work / 'host'
    host.mkdir()
    # This original database archive failed its first loader probe; only its exact later replay admits it.
    replay = api('actions/runs/39074634710')
    if (replay['head_sha'] != '86341743be569c60d56da21fcf37f3b51afd0dfa'
        or replay['status'] != 'completed' or replay['conclusion'] != 'success'):
        raise BuildError('host_assembly_database_replay_unqualified')
    database = obtain(work, 'database', 12116805879,
        '5601dd2fe0e125cc4f4f9516423330ae00f12563e5d173d5a680e0297df786f2',
        39070988001, 'a99fcce5bbb8cc9a962aa473d8888ad78ea845e0', 'failure')
    db = json.loads((database / 'qualification.json').read_text())
    pins = json.loads((Path(__file__).resolve().parent.parent / 'runtime/host-database.json').read_text())
    if db['pins'] != pins or db['sourceDockerfileSha256'] != hashlib.sha256(blob('docker/postgres/Dockerfile')).hexdigest():
        raise BuildError('host_assembly_database_source_changed')
    stage_server(database / 'postgres', host / 'pg')
    hdr = obtain(work, 'hdr', 12113889531,
        'c5bcf6ad34f04e20bffbe558b5be814ab25a89f576f21ab4f4faa47690acc4aa',
        39067107761, '8bb8723c2df6210834235206199d45113925a6e6')
    report = qualified_files(hdr, 'media', '9bc18ba0474dc7df13ae80d6870e331f6c7641e6')
    if len(report['sourceFiles']) != 85 or any(
        hashlib.sha256(blob(name)).hexdigest() != item['sha256']
        for name, item in report['sourceFiles'].items()):
        raise BuildError('host_assembly_hdr_source_changed')
    stage_server(hdr / 'media', host / 'media')
    server = obtain(work, 'server', 12319854302,
        '90471ce82b214d41843d4805a20017fb3ec7bc05de6be34b72cd14fac174fbf9',
        39541951524, '6490a66e8931670f88bcb1be2009fb978cce6411')
    original = qualified_files(server / 'fl-windows-server', 'server')
    metadata_root = server / 'fl-windows-metadata'
    metadata = json.loads((metadata_root / 'qualification.json').read_text())
    adapted = inventory(metadata_root / 'server')
    if (metadata['qualification'] != 'passed' or metadata['sourceRevision'] != SOURCE
        or adapted != metadata['files']['server'] or set(adapted) != set(original['files'])
        or [n for n in adapted if adapted[n] != original['files'][n]] != ['node_modules/exiftool-vendored/dist/ExiftoolPath.js']):
        raise BuildError('host_assembly_metadata_changed')
    stage_server(metadata_root / 'server', host / 'server')
    manager = server / 'fl-windows-manager'
    qualified_files(manager, 'manager')
    backup = server / 'fl-windows-backup/backup'
    raw = obtain(work, 'raw', 12308277388,
        '52e67a2c23dac0bb4eeca8242ce6dc33d1c47aff69a6dcd792f127a02be77156',
        39514367004, '4f88cb18e4afe64b14f733e4e0b7eb828c88af95')
    qualified_files(raw / 'fl-windows-raw', 'raw')
    stage_server(raw / 'fl-windows-raw/raw', host / 'raw')
    asset_metadata = api(f'actions/artifacts/{assets_id}')
    assets = obtain(work, 'assets', int(assets_id), assets_sha,
                    asset_metadata['workflow_run']['id'], assets_head)
    (host / 'build/plugins').mkdir(parents=True)
    for component, directory, destination in [
        ('web', 'www', 'build/www'), ('plugin', 'plugin', 'build/plugins/immich-plugin-core'),
        ('studio', 'studio-worker', None), ('media-tools', 'media', 'media-tools')]:
        root = assets / ('fl-windows-' + component)
        qualified_files(root, directory)
        if destination:
            stage_server(root / directory, host / destination)
        else:
            for name in ['studio', 'fonts']:
                stage_server(root / directory / name, host / name)
    browser_pin = host / 'studio/engine/node_modules/playwright-core/browsers.json'
    if sha256(browser_pin) != '2cfd419f71ac6475d81e1301fa86c34cf2a2a6bae2a0da4b5a2b18310216b6bf':
        raise BuildError('host_assembly_browser_pin_changed')
    archive = work / 'browser.zip'
    download('https://cdn.playwright.dev/builds/cft/156.0.8078.4/win64/chrome-headless-shell-win64.zip',
             archive, '5af4c82cf4b351ec4bad4c71dcf938af14fccea8a0eb0d5c2a7b49ccc922698c')
    unpack(archive, work / 'browser')
    stage_server(work / 'browser/chrome-headless-shell-win64', host / 'browser')
    archive = work / 'node.zip'
    download('https://nodejs.org/dist/v26.11.1/node-v26.11.1-win-x64.zip', archive,
             '97f36a8a9684ff0d3e35758b4610fef5b628a5880e96f2ccc11240e5daf9934e')
    unpack(archive, work / 'node')
    node = work / 'node/node-v26.11.1-win-x64'
    if sha256(node / 'node.exe') != 'a619e2e09eb0d50ef4c733d678b4d22689d2afef138cd67fd3fa107b535f8819':
        raise BuildError('host_assembly_node_changed')
    shutil.copy2(node / 'node.exe', host / 'node.exe')
    (host / 'libraries').mkdir()
    licenses = host / 'licenses'
    licenses.mkdir()
    (licenses / 'Frameleaf-LICENSE').write_bytes(blob('LICENSE'))
    shutil.copy2(node / 'LICENSE', licenses / 'Node-LICENSE')
    stage_server(host / 'pg/licenses', licenses / 'database')
    geodata = host / 'build/geodata'
    geodata.mkdir()
    lock = blob('server/base-image/geodata/geodata.lock')
    (geodata / 'geodata.lock').write_bytes(lock)
    dockerfile = blob('server/Dockerfile').decode()
    if (re.findall(r'^ARG GEODATA_SNAPSHOT=(\S+)$', dockerfile, re.M) != ['2026-10-11']
        or re.findall(r'^ARG GEODATA_DATE=(\S+)$', dockerfile, re.M) != ['2026-10-10T00:00:00+00:00']):
        raise BuildError('host_assembly_geodata_pin_changed')
    geodata_sources = {}
    for line in lock.decode().splitlines():
        if not line or line.startswith('#'):
            continue
        digest, name, capture = line.split()
        if not re.fullmatch(r'[a-f0-9]{64}', digest) or not re.fullmatch(r'[A-Za-z0-9_.-]+', name):
            raise BuildError('host_assembly_geodata_lock_invalid')
        geodata_sources[name] = download_geodata(geodata / name, digest, capture)
    (work / 'geodata-producer.json').write_text(json.dumps(geodata_sources, indent=2) + '\n')
    with zipfile.ZipFile(geodata / 'cities500.zip') as cities:
        if cities.namelist() != ['cities500.txt'] or cities.getinfo('cities500.txt').file_size > 128 * 1024**2:
            raise BuildError('host_assembly_geodata_archive_invalid')
        (geodata / 'cities500.txt').write_bytes(cities.read('cities500.txt'))
    (geodata / 'cities500.zip').unlink()
    (geodata / 'geodata-date.txt').write_bytes(b'2026-10-10T00:00:00+00:00')
    ml = obtain(work, 'ml', 12303032800,
        '496d637d57087b9057ea4c3dfcb81fa86ea893307cfe35e249964b9cb277809d',
        39504442584, '91203102137fcff723ff91525eb8ebf624f64f1a')
    if sha256(ml / 'manifest.json') != '95c6f4176699ef44ea7a7cc59052523b4e4a112b5a703606d733e20d6b27c5e4':
        raise BuildError('host_assembly_ml_manifest_changed')
    (ml / 'manifest.sig').write_bytes(bytes.fromhex(signature))
    assemble(host, ml, manager / 'manager', backup, output / 'bundle', SOURCE, 16)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'output', 'assets-id', 'assets-sha', 'assets-head', 'runtime-signature']:
        parser.add_argument('--' + name, required=True)
    options = parser.parse_args()
    build(Path(options.source), Path(options.output), options.assets_id, options.assets_sha,
          options.assets_head, options.runtime_signature)
