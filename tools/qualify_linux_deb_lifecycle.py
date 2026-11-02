"""Qualify real dpkg failure/retry hooks only in a disposable hosted Linux namespace."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

from build_host_linux_deb import archive, package_names, stage_packages
from qualify_linux_package_admission import require_hosted_linux

BASE = Path('/opt/frameleaf')


def require_failure(output, code):
    receipts = [json.loads(line) for line in output.splitlines() if line.startswith('{')]
    failures = [value for value in receipts if isinstance(value, dict) and value.get('state') == 'failed']
    assert failures and all(value.get('protocolVersion') == 1 and value.get('code') == code
                            for value in failures), (code, receipts)


def qualify(binary):
    import fcntl

    binary = Path(binary).resolve(strict=True)
    # Exclusive creation is the only authority to remove this fixture.
    BASE.mkdir(mode=0o755)
    try:
        with tempfile.TemporaryDirectory(prefix='frameleaf-dpkg-') as temporary:
            work = Path(temporary).resolve()
            candidate = work / 'candidate'
            payload = candidate / 'payload'
            payload.mkdir(parents=True)
            (payload / 'never-executed').write_bytes(b'unsigned fixture is never a runtime')
            raw = b'{}'
            (candidate / 'manifest.json').write_bytes(raw)
            (candidate / 'manifest.sig').write_bytes(bytes(64))
            manifest = hashlib.sha256(raw).hexdigest()
            controller = hashlib.sha256(binary.read_bytes()).hexdigest()
            architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
            names = package_names(manifest, controller)
            trees = stage_packages(candidate, binary, work / 'packages', manifest, controller, architecture)
            packages = [work / (name + '.deb') for name in names]
            for tree, package in zip(trees, packages):
                archive(tree, package)
            database = work / 'dpkg'
            database.mkdir()
            (database / 'status').touch()
            environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'HOME': str(work)}
            cases = []

            def invoke(label, arguments, success):
                result = subprocess.run(['dpkg', '--admindir=' + str(database), '--log=' + str(work / 'dpkg.log'), *map(str, arguments)],
                                        env=environment, capture_output=True, text=True, timeout=120)
                assert (result.returncode == 0) == success, (label, result.returncode, result.stdout, result.stderr)
                cases.append({'case': label, 'exitCode': result.returncode})
                return result

            def refused():
                runtime = BASE / 'Runtimes' / manifest
                assert (runtime / '.package-maintenance').read_bytes() == b''
                assert not (runtime / 'installation.json').exists()
                assert list((BASE / 'Profiles').iterdir()) == []
                result = subprocess.run(['dpkg-query', '--admindir=' + str(database), '--show',
                                         '--showformat=${db:Status-Status}', names[1]],
                                        env=environment, capture_output=True, text=True, timeout=30)
                assert result.returncode == 0 and result.stdout == 'half-configured', (result.returncode, result.stdout)
                return runtime

            invoke('bootstrap-installed', ['--install', packages[0]], True)
            result = invoke('unsigned-payload-configuration-refused', ['--install', packages[1]], False)
            require_failure(result.stdout, 'host_signature_invalid')
            runtime = refused()
            result = invoke('configuration-retry-still-refused', ['--configure', names[1]], False)
            require_failure(result.stdout, 'host_signature_invalid')
            refused()
            sentinel = runtime / 'payload' / 'never-executed'
            with (runtime / '.runtime-lease').open('rb') as lease:
                fcntl.flock(lease, fcntl.LOCK_SH | fcntl.LOCK_NB)
                result = invoke('live-reader-blocks-removal', ['--remove', names[1]], False)
                require_failure(result.stdout, 'host_package_busy')
                assert sentinel.read_bytes() == b'unsigned fixture is never a runtime'
            invoke('removal-after-reader-release', ['--remove', names[1]], True)
            assert not sentinel.exists()
            assert (runtime / '.package-maintenance').read_bytes() == b''
            assert not (runtime / 'installation.json').exists()
            assert (BASE / 'Profiles').is_dir()
            invoke('bootstrap-removal', ['--remove', names[0]], True)
            print(json.dumps({'qualification': 'passed', 'cases': cases, 'isolatedDpkgDatabase': True,
                              'unsignedPayloadActivated': False, 'installedAcceptance': False,
                              'runtimeQualified': False, 'serverStarted': False}))
    finally:
        shutil.rmtree(BASE)


def main(arguments=None):
    require_hosted_linux(platform.system(), getattr(os, 'getuid', lambda: -1)(),
                         getattr(os, 'geteuid', lambda: -1)())
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 1:
        raise RuntimeError('expected_built_controller_path')
    previous = os.umask(0o022)
    try:
        qualify(arguments[0])
    finally:
        os.umask(previous)


if __name__ == '__main__':
    main()
