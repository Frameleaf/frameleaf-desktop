"""Stage the server's pinned reverse-geocoding snapshot for native hosts; no runtime qualification."""

from __future__ import annotations

import argparse
from datetime import date, datetime
from http.client import HTTPException
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit
import zipfile

from build_host_database import download
from build_host_ffmpeg import unpack
from build_runtime import BuildError, git_blob, inventory

INPUTS = {
    'cities500.zip', 'admin1CodesASCII.txt', 'admin2Codes.txt', 'countryInfo.txt',
    'ne_10m_admin_0_countries.geojson', 'landmarks.ndjson.gz',
}


def build(source: Path, revision: str, output: Path) -> None:
    """Verify selected Git metadata before fetching into a new, caller-owned component directory."""
    if (not re.fullmatch(r'[a-f0-9]{40}', revision)
            or not source.is_absolute() or not output.is_absolute()
            or source.resolve() != source or output.resolve() != output
            or output.is_relative_to(source) or output.exists() or output.is_symlink()):
        raise BuildError('host_geodata_paths_invalid')
    git = shutil.which('git')
    if not git:
        raise BuildError('host_geodata_git_missing')
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0')
    docker = git_blob(git, source, revision, 'server/Dockerfile', env)
    lock = git_blob(git, source, revision, 'server/base-image/geodata/geodata.lock', env)
    try:
        snapshots = re.findall(r'^ARG GEODATA_SNAPSHOT=(\S+)\r?$', docker.decode(), re.M)
        dates = re.findall(r'^ARG GEODATA_DATE=(\S+)\r?$', docker.decode(), re.M)
        if (len(snapshots) != 1 or len(dates) != 1
                or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', snapshots[0])
                or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T00:00:00\+00:00', dates[0])
                or datetime.fromisoformat(dates[0]).date() > date.fromisoformat(snapshots[0])):
            raise ValueError()
        entries = {}
        for line in lock.decode().splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            digest, name, capture = line.split()
            url = urlsplit(capture)
            if (not re.fullmatch(r'[a-f0-9]{64}', digest) or name not in INPUTS or name in entries
                    or url.scheme != 'https' or url.netloc not in {'web.archive.org', 'raw.githubusercontent.com'}
                    or url.query or url.fragment):
                raise ValueError()
            entries[name] = (digest, capture)
        if set(entries) != INPUTS:
            raise ValueError()
    except (ValueError, UnicodeError) as error:
        raise BuildError('host_geodata_source_contract_invalid') from error

    output.mkdir(mode=0o700)
    data, work = output / 'geodata', output / 'work'
    report = {
        'schemaVersion': 1, 'sourceRevision': revision, 'snapshot': snapshots[0],
        'date': dates[0], 'sourceLockSha256': hashlib.sha256(lock).hexdigest(),
        'sourceDockerfileSha256': hashlib.sha256(docker).hexdigest(),
        'qualification': 'failed', 'runtimeQualified': False, 'redistributable': False,
        'sources': {},
    }
    try:
        data.mkdir(mode=0o700)
        work.mkdir(mode=0o700)
        for name, (digest, capture) in entries.items():
            partial = data / (name + '.part')
            for url in [f'https://static.frameleaf.cloud/geodata/{snapshots[0]}/{name}', capture]:
                try:
                    download(url, partial, digest)
                except (OSError, HTTPException, BuildError):
                    partial.unlink(missing_ok=True)
                    continue
                partial.rename(data / name)
                report['sources'][name] = url
                break
            else:
                raise BuildError('host_geodata_sources_unavailable:' + name)
        archive = data / 'cities500.zip'
        with zipfile.ZipFile(archive) as cities:
            if (cities.namelist() != ['cities500.txt']
                    or cities.getinfo('cities500.txt').file_size > 128 * 1024**2):
                raise BuildError('host_geodata_cities_archive_invalid')
        unpack(archive, work)
        (work / 'cities500.txt').rename(data / 'cities500.txt')
        archive.unlink()
        (data / 'geodata.lock').write_bytes(lock)
        (data / 'geodata-date.txt').write_bytes(dates[0].encode())
        report['files'] = inventory(data)
        report['qualification'] = 'passed'
    finally:
        try:
            if work.exists():
                shutil.rmtree(work)
            if report['qualification'] != 'passed' and data.exists():
                shutil.rmtree(data)
        except OSError:
            report['qualification'] = 'failed'
            raise
        finally:
            (output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'revision', 'output']:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        build(Path(args.source), args.revision, Path(args.output))
    except (BuildError, OSError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, str(error) if isinstance(error, BuildError) else 'host_geodata_build_failed')
