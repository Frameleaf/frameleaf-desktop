"""Admit one immutable unsigned Windows assembly for data-only host signing."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess

from build_host_ffmpeg import unpack
from build_runtime import BuildError, regular
from obtain_host_component import obtain as obtain_component, validate_approval

SOURCE_REVISION = '9118a01fdfb8a8cd20be24290660679b3a7c4de3'


def obtain(approved: dict, output: Path) -> None:
    """Preserve the producer's bytes in an exclusively controlled authoring workspace."""
    validate_approval(approved)
    if approved['workflow'] != '.github/workflows/windows-host-assembly.yml':
        raise BuildError('host_candidate_producer_invalid')
    if (not output.is_absolute() or output.exists() or output.is_symlink()
            or not stat.S_ISDIR(regular(output.parent).st_mode)):
        raise BuildError('host_candidate_output_invalid')
    output.mkdir(mode=0o700)
    try:
        acquired = output / 'input'
        obtain_component(approved, acquired)
        component = acquired / 'component'
        if {p.name for p in component.iterdir()} != {'windows-complete-host.tar.gz'}:
            raise BuildError('host_candidate_archive_invalid')
        candidate = output / 'candidate'
        candidate.mkdir(mode=0o700)
        # The complete host is 3.8 GB; ordinary components retain the default 2 GiB bound.
        unpack(component / 'windows-complete-host.tar.gz', candidate, max_bytes=8 * 1024**3)
        if ({p.name for p in candidate.iterdir()} != {'payload', 'manifest.json', 'qualification.json'}
                or not stat.S_ISDIR(regular(candidate / 'payload').st_mode)):
            raise BuildError('host_candidate_files_invalid')
        records = []
        for name in ['manifest.json', 'qualification.json']:
            path = candidate / name
            if not stat.S_ISREG(regular(path).st_mode) or not 0 < path.stat().st_size <= 16 * 1024**2:
                raise BuildError('host_candidate_control_invalid')
            records.append(path.read_bytes())
        raw, qualification = records
        manifest, receipt = json.loads(raw), json.loads(qualification)
        if (not isinstance(manifest, dict) or not isinstance(receipt, dict)
                or manifest.get('platform') != 'windows' or manifest.get('architecture') != 'x86_64'
                or manifest.get('sourceRevision') != SOURCE_REVISION
                or not isinstance(manifest.get('files'), dict) or not manifest['files']
                or type(receipt.get('schemaVersion')) is not int or receipt['schemaVersion'] != 1
                or receipt.get('qualification') != 'passed'
                or receipt.get('sourceRevision') != manifest['sourceRevision']
                or type(receipt.get('files')) is not int or receipt['files'] != len(manifest['files'])
                or type(receipt.get('manifestBytes')) is not int or receipt['manifestBytes'] != len(raw)
                or receipt.get('manifestSha256') != hashlib.sha256(raw).hexdigest()
                or any(receipt.get(flag) is not False for flag in
                       ['signaturePresent', 'runtimeQualified', 'redistributable'])):
            raise BuildError('host_candidate_receipt_invalid')
        shutil.copyfile(acquired / 'producer.json', output / 'producer.json')
        shutil.rmtree(acquired)
    except Exception as error:
        try:
            shutil.rmtree(output)
        except OSError as cleanup:
            error.add_note('Candidate cleanup failed: ' + str(cleanup))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--approval', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        if not stat.S_ISREG(regular(args.approval).st_mode) or args.approval.stat().st_size > 16 * 1024:
            raise BuildError('host_component_approval_invalid')
        obtain(json.loads(args.approval.read_text()), args.output)
    except (BuildError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) if isinstance(error, BuildError) else 'host_candidate_acquisition_failed')
