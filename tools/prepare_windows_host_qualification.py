"""Verify an exact retained full Windows host using its public detached signature; never install."""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
from pathlib import Path

from assemble_windows_host_candidate import SOURCE, api, obtain
from build_runtime import BuildError, build_environment, regular, run, sha256
from windows_probe_process import create_probe_directory

ROOT = Path(__file__).resolve().parent.parent
ML_MANIFEST = '95c6f4176699ef44ea7a7cc59052523b4e4a112b5a703606d733e20d6b27c5e4'


def admit(candidate: Path, signature: str, node: Path, env: dict) -> dict:
    if not re.fullmatch(r'[a-f0-9]{128}', signature):
        raise BuildError('host_qualification_signature_invalid')
    for name, maximum in [('manifest.json', 16 * 1024**2), ('qualification.json', 16384)]:
        path = candidate / name
        if not path.is_file() or not 0 < regular(path).st_size <= maximum:
            raise BuildError('host_qualification_receipt_invalid')
    report = json.loads((candidate / 'qualification.json').read_text())
    manifest = json.loads((candidate / 'manifest.json').read_text())
    if (report.get('qualification') != 'passed' or report.get('sourceRevision') != SOURCE
        or report.get('manifestSha256') != sha256(candidate / 'manifest.json')
        or any(report.get(key) is not False for key in ['signaturePresent', 'runtimeQualified', 'redistributable'])
        or report.get('ml', {}).get('manifestSha256') != ML_MANIFEST
        or manifest.get('sourceRevision') != SOURCE or manifest.get('platform') != 'windows'
        or manifest.get('architecture') != 'x86_64' or manifest.get('epoch') != 16):
        raise BuildError('host_qualification_receipt_invalid')
    with (candidate / 'manifest.sig').open('xb') as stream:
        stream.write(bytes.fromhex(signature))
    verifier = (ROOT / 'tools/sign_host_runtime.mjs').as_uri()
    code = f'import({json.dumps(verifier)}).then(async m=>console.log(JSON.stringify(await m.verifySignedHostCandidate(process.argv[1]))))'
    checked = json.loads(run([node, '--input-type=module', '--eval', code, candidate], cwd=candidate.parent, env=env))
    if (checked.get('keyId') != 'desktop-release-2026-10'
        or checked.get('manifestSha256') != report['manifestSha256']
        or checked.get('sourceRevision') != SOURCE or checked.get('epoch') != 16
        or checked.get('certified') is not False):
        raise BuildError('host_qualification_authority_invalid')
    return checked


def prepare(output: Path, artifact: str, digest: str, head: str, signature: str) -> dict:
    if (platform.system() != 'Windows' or platform.machine() != 'AMD64'
        or not output.is_absolute() or output.exists() or output.is_symlink()
        or not re.fullmatch(r'[1-9][0-9]{0,19}', artifact)
        or not re.fullmatch(r'[a-f0-9]{64}', digest)
        or not re.fullmatch(r'[a-f0-9]{40}', head)
        or not re.fullmatch(r'[a-f0-9]{128}', signature)):
        raise BuildError('host_qualification_inputs_invalid')
    node_path = shutil.which('node')
    if not node_path or sha256(Path(node_path)) != 'a619e2e09eb0d50ef4c733d678b4d22689d2afef138cd67fd3fa107b535f8819':
        raise BuildError('host_qualification_node_unapproved')
    # PostgreSQL's restricted child must retain the user's access to staged DLLs.
    create_probe_directory(output)
    env = build_environment(output, os.environ)
    metadata = api(f'actions/artifacts/{artifact}')
    if metadata['name'] != 'frameleaf-windows-unsigned-full-host-candidate':
        raise BuildError('host_qualification_producer_invalid')
    retained = obtain(output, 'input', int(artifact), digest, metadata['workflow_run']['id'], head,
                      maximum_bytes=12 * 1024**3)
    candidate = retained / 'bundle'
    checked = admit(candidate, signature, Path(node_path), env)
    result = {'state': 'normal-signature-and-complete-inventory-verified', 'candidate': str(candidate),
              'artifactId': int(artifact), 'artifactSha256': digest, 'producerHead': head,
              'verified': checked, 'compiledLifecycleQualified': False,
              'installedAcceptance': False, 'installerExecuted': False}
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['output', 'artifact', 'digest', 'head', 'signature']:
        parser.add_argument('--' + name, required=True)
    options = parser.parse_args()
    print(json.dumps(prepare(Path(options.output), options.artifact, options.digest,
                             options.head, options.signature)))
