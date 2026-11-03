"""Stage a matched signed Windows host/evidence pair; compiled authority qualification follows."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import zipfile

from build_host_ffmpeg import unpack
from build_runtime import BuildError, inventory, regular
from obtain_host_component import obtain as obtain_component, validate_approval, validate_producer
from obtain_windows_host_candidate import SOURCE_REVISION
from windows_private_directory import create_private_directory


def bounded(path: Path, limit: int) -> bytes:
    info = regular(path)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        raise BuildError('host_signed_control_invalid')
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) != info.st_size or len(raw) > limit:
        raise BuildError('host_signed_control_invalid')
    return raw


def validate_pair(approvals: dict) -> None:
    """Require distinct artifacts from the same reviewed successful signing attempt."""
    if not isinstance(approvals, dict) or set(approvals) != {'candidate', 'evidence'}:
        raise BuildError('host_signed_pair_invalid')
    for approved in approvals.values():
        validate_approval(approved)
        if approved['workflow'] != '.github/workflows/windows-host-signing.yml':
            raise BuildError('host_signed_pair_invalid')
    candidate, evidence = approvals['candidate'], approvals['evidence']
    if (candidate['artifactId'] == evidence['artifactId'] or any(
            candidate[k] != evidence[k] for k in ['runId', 'runAttempt', 'headSha'])):
        raise BuildError('host_signed_pair_invalid')


def producer(path: Path, approved: dict) -> dict:
    record = json.loads(bounded(path, 2 * 1024**2))
    if not isinstance(record, dict) or record.get('approved') != approved:
        raise BuildError('host_signed_producer_invalid')
    validate_producer(approved, record.get('artifact'), record.get('run'))
    if record['run'].get('head_branch') != 'main' or record['run'].get('event') != 'workflow_dispatch':
        raise BuildError('host_signed_producer_invalid')
    return record


def obtain(approvals: dict, output: Path) -> None:
    """Read immutable archives into an exclusively controlled authoring workspace, never execute them."""
    validate_pair(approvals)
    if (not output.is_absolute() or output.exists() or output.is_symlink()
            or not stat.S_ISDIR(regular(output.parent).st_mode)):
        raise BuildError('host_signed_output_invalid')
    create_private_directory(output)
    try:
        for role in ['candidate', 'evidence']:
            acquired = output / (role + '-input')
            obtain_component(approvals[role], acquired)
            producer(acquired / 'producer.json', approvals[role])
            shutil.copyfile(acquired / 'producer.json', output / (role + '-producer.json'))
        component = output / 'candidate-input/component'
        if {p.name for p in component.iterdir()} != {'windows-complete-host-signed.tar.gz'}:
            raise BuildError('host_signed_archive_invalid')
        candidate = output / 'candidate'
        create_private_directory(candidate)
        unpack(component / 'windows-complete-host-signed.tar.gz', candidate, max_bytes=8 * 1024**3)
        if ({p.name for p in candidate.iterdir()} != {'payload', 'manifest.json', 'manifest.sig', 'qualification.json'}
                or not stat.S_ISDIR(regular(candidate / 'payload').st_mode)):
            raise BuildError('host_signed_files_invalid')
        evidence = output / 'evidence-input/component'
        if ({p.name for p in evidence.iterdir()} != {'candidate', 'signature.json', 'signature-verification.json', 'producer.json'}
                or set(inventory(evidence)) != {'candidate/manifest.json', 'candidate/manifest.sig',
                    'candidate/qualification.json', 'signature.json', 'signature-verification.json', 'producer.json'}):
            raise BuildError('host_signed_evidence_invalid')
        controls = {}
        for name, limit in [('manifest.json', 16 * 1024**2), ('manifest.sig', 64), ('qualification.json', 16 * 1024**2)]:
            controls[name] = bounded(candidate / name, limit)
            if controls[name] != bounded(evidence / 'candidate' / name, limit):
                raise BuildError('host_signed_control_mismatch')
        raw, signature = controls['manifest.json'], controls['manifest.sig']
        manifest, unsigned = json.loads(raw), json.loads(controls['qualification.json'])
        proof = json.loads(bounded(evidence / 'signature-verification.json', 16 * 1024))
        signed = json.loads(bounded(evidence / 'signature.json', 16 * 1024))
        original = json.loads(bounded(evidence / 'producer.json', 2 * 1024**2))
        if not isinstance(original, dict) or not isinstance(original.get('approved'), dict):
            raise BuildError('host_signed_original_producer_invalid')
        producer(evidence / 'producer.json', original['approved'])
        if original['approved']['workflow'] != '.github/workflows/windows-host-assembly.yml':
            raise BuildError('host_signed_original_producer_invalid')
        if not isinstance(proof, dict):
            raise BuildError('host_signed_evidence_mismatch')
        validate_approval(proof.get('approvedProducer'))
        if (not all(isinstance(r, dict) for r in [manifest, unsigned, proof, signed])
                or len(signature) != 64 or manifest.get('platform') != 'windows'
                or manifest.get('architecture') != 'x86_64' or manifest.get('sourceRevision') != SOURCE_REVISION
                or not isinstance(manifest.get('files'), dict) or not manifest['files']
                or type(manifest.get('epoch')) is not int or not 0 < manifest['epoch'] < 2**64
                or manifest.get('certified') is not False
                or type(unsigned.get('schemaVersion')) is not int or unsigned['schemaVersion'] != 1
                or unsigned.get('qualification') != 'passed' or unsigned.get('sourceRevision') != SOURCE_REVISION
                or type(unsigned.get('files')) is not int or unsigned['files'] != len(manifest['files'])
                or type(unsigned.get('manifestBytes')) is not int or unsigned['manifestBytes'] != len(raw)
                or unsigned.get('manifestSha256') != hashlib.sha256(raw).hexdigest()
                or any(unsigned.get(k) is not False for k in ['signaturePresent', 'runtimeQualified', 'redistributable'])
                or type(proof.get('schemaVersion')) is not int or proof['schemaVersion'] != 1
                or proof.get('signaturePresent') is not True or proof.get('certified') is not False
                or proof.get('sourceRevision') != SOURCE_REVISION or type(proof.get('epoch')) is not int
                or proof['epoch'] != manifest['epoch'] or proof.get('approvedProducer') != original['approved']
                or proof.get('manifestSha256') != hashlib.sha256(raw).hexdigest()
                or proof.get('signatureSha256') != hashlib.sha256(signature).hexdigest()
                or not isinstance(proof.get('keyId'), str) or not 0 < len(proof['keyId']) <= 64
                or any(proof.get(k) is not False for k in ['runtimeQualified', 'redistributable',
                    'installedPlatformQualified', 'fullMediaConformance'])
                or set(signed) != {'keyId', 'manifestSha256', 'signatureSha256', 'sourceRevision', 'epoch', 'certified'}
                or any(value != proof.get(k) or type(value) is not type(proof.get(k)) for k, value in signed.items())):
            raise BuildError('host_signed_evidence_mismatch')
        shutil.move(str(evidence), output / 'signature-evidence')
        for role in ['candidate', 'evidence']:
            shutil.rmtree(output / (role + '-input'))
        staged = {'schemaVersion': 1, 'state': 'signed-resources-staged',
                  'sourceRevision': SOURCE_REVISION, 'manifestSha256': proof['manifestSha256'],
                  'signatureSha256': proof['signatureSha256'], 'epoch': proof['epoch'], 'certified': False,
                  'approvals': approvals, 'runtimeQualified': False, 'redistributable': False,
                  'installedPlatformQualified': False, 'fullMediaConformance': False}
        (output / 'qualification.json').write_text(json.dumps(staged, indent=2) + '\n')
    except Exception as error:
        try:
            shutil.rmtree(output)
        except OSError as cleanup:
            error.add_note('Signed candidate cleanup failed: ' + str(cleanup))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--approvals', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        obtain(json.loads(bounded(args.approvals, 16 * 1024)), args.output)
    except (BuildError, OSError, ValueError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, str(error) if isinstance(error, BuildError) else 'host_signed_candidate_acquisition_failed')
