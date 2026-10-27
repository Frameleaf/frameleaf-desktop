"""Admit the current factory-signed Windows candidate from its private draft; never install."""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

from assemble_windows_host_candidate import api
from build_host_ffmpeg import unpack
from build_runtime import BuildError, build_environment, regular, run, sha256
from windows_probe_process import create_probe_directory

ROOT = Path(__file__).resolve().parent.parent
SOURCE = '1c258e8e7ab610a21e82d1457a38dcfd35c5cfd3'
ML_MANIFEST = '44c945e9053dcba02c04d32b1e3c4e5580f9410a3c07f28618ec1ed4f0468e6c'
NODE_SHA256 = 'a619e2e09eb0d50ef4c733d678b4d22689d2afef138cd67fd3fa107b535f8819'
RELEASE_ID = 419477762
ASSET_NAME = 'FrameleafNativeHost-candidate-1c258e8e-epoch18-windows-x64.zip'


def admit(candidate: Path, node: Path, env: dict) -> dict:
    for name, maximum in [('manifest.json', 16 * 1024**2), ('qualification.json', 16384),
                          ('manifest.sig', 64)]:
        path = candidate / name
        if (not path.is_file() or not 0 < regular(path).st_size <= maximum
            or (name == 'manifest.sig' and regular(path).st_size != 64)):
            raise BuildError('host_qualification_receipt_invalid')
    report = json.loads((candidate / 'qualification.json').read_text())
    manifest = json.loads((candidate / 'manifest.json').read_text())
    if (report.get('qualification') != 'passed' or report.get('sourceRevision') != SOURCE
        or report.get('manifestSha256') != sha256(candidate / 'manifest.json')
        or report.get('signaturePresent') is not True
        or any(report.get(key) is not False for key in ['runtimeQualified', 'redistributable'])
        or report.get('ml', {}).get('manifestSha256') != ML_MANIFEST
        or sha256(candidate / 'payload/ml/manifest.json') != ML_MANIFEST
        or manifest.get('sourceRevision') != SOURCE or manifest.get('platform') != 'windows'
        or manifest.get('architecture') != 'x86_64' or manifest.get('epoch') != 18):
        raise BuildError('host_qualification_receipt_invalid')
    verifier = (ROOT / 'tools/sign_host_runtime.mjs').as_uri()
    code = f'import({json.dumps(verifier)}).then(async m=>console.log(JSON.stringify(await m.verifySignedHostCandidate(process.argv[1]))))'
    checked = json.loads(run([node, '--input-type=module', '--eval', code, candidate], cwd=candidate.parent, env=env))
    if (checked.get('keyId') != 'desktop-release-2026-10'
        or checked.get('manifestSha256') != report['manifestSha256']
        or checked.get('sourceRevision') != SOURCE or checked.get('epoch') != 18
        or checked.get('certified') is not False):
        raise BuildError('host_qualification_authority_invalid')
    return checked


def prepare(output: Path, asset: str, digest: str) -> dict:
    if (platform.system() != 'Windows' or platform.machine() != 'AMD64'
        or not output.is_absolute() or output.exists() or output.is_symlink()
        or not re.fullmatch(r'[1-9][0-9]{0,19}', asset)
        or not re.fullmatch(r'[a-f0-9]{64}', digest)):
        raise BuildError('host_qualification_inputs_invalid')
    node = shutil.which('node')
    if not node or sha256(Path(node)) != NODE_SHA256:
        raise BuildError('host_qualification_node_unapproved')
    repository, release = api(''), api(f'releases/{RELEASE_ID}')
    if repository.get('private') is not True or release.get('id') != RELEASE_ID or release.get('draft') is not True:
        raise BuildError('host_qualification_producer_invalid')
    matches = [item for item in release['assets'] if item.get('id') == int(asset)]
    if len(matches) != 1:
        raise BuildError('host_qualification_producer_invalid')
    metadata = matches[0]
    if (metadata.get('name') != ASSET_NAME or metadata.get('state') != 'uploaded'
        or type(metadata.get('size')) is not int or not 0 < metadata['size'] <= 2 * 1024**3
        or metadata.get('digest') != 'sha256:' + digest):
        raise BuildError('host_qualification_producer_invalid')
    # PostgreSQL's restricted child must retain the user's access to staged DLLs.
    create_probe_directory(output)
    env = build_environment(output, os.environ)
    archive = output / 'input.zip'
    with archive.open('xb') as stream:
        subprocess.run(['gh', 'api', f'repos/Frameleaf/frameleaf-desktop/releases/assets/{asset}',
                        '-H', 'Accept: application/octet-stream'], stdout=stream, check=True, timeout=1800)
    if archive.stat().st_size != metadata['size'] or sha256(archive) != digest or not zipfile.is_zipfile(archive):
        raise BuildError('host_qualification_archive_invalid')
    retained = output / 'input'
    unpack(archive, retained, maximum_bytes=8 * 1024**3)
    if {path.name for path in retained.iterdir()} != {'bundle'}:
        raise BuildError('host_qualification_archive_invalid')
    candidate = retained / 'bundle'
    checked = admit(candidate, Path(node), env)
    archive.unlink()
    result = {'state': 'normal-signature-and-complete-inventory-verified', 'candidate': str(candidate),
              'releaseAssetId': int(asset), 'releaseAssetSha256': digest,
              'verified': checked, 'compiledLifecycleQualified': False,
              'installedAcceptance': False, 'installerExecuted': False}
    (output / 'input-producer.json').write_text(json.dumps(result, indent=2) + '\n')
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['output', 'asset', 'digest']:
        parser.add_argument('--' + name, required=True)
    options = parser.parse_args()
    print(json.dumps(prepare(Path(options.output), options.asset, options.digest)))
