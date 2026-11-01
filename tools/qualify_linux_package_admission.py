"""Exercise root admission only in a disposable GitHub-hosted Linux namespace."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys

BASE = Path('/opt/frameleaf')


def require_hosted_linux(system, uid, euid):
    if (system != 'Linux' or uid != 0 or euid != 0
            or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise RuntimeError('qualification_requires_disposable_hosted_linux_root')


def qualify(binary):
    import fcntl

    binary = Path(binary).resolve(strict=True)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest = hashlib.sha256(b'frameleaf-admission-ci-unsigned-fixture').hexdigest()
    runtime = BASE / 'Runtimes' / manifest
    controller = BASE / 'Controllers' / manifest / digest / 'frameleaf-native-host'
    bootstrap = BASE / 'Bootstrap' / digest / 'frameleaf-native-host'
    fence = runtime / '.package-maintenance'
    receipt = runtime / 'installation.json'
    results = []

    def invoke(label, success=False, code=None, phase='--prepare-linux-package'):
        result = subprocess.run([str(binary), phase, manifest, digest], capture_output=True, text=True, timeout=30)
        value = json.loads(result.stdout)
        if success:
            assert result.returncode == 0 and value['state'] == 'package-prepared', (label, value)
            assert value['serverStarted'] is False and value['runtimeQualified'] is False
        else:
            assert result.returncode != 0 and value['state'] == 'failed', (label, value)
            assert isinstance(value.get('code'), str), (label, value)
            if code is not None:
                assert value['code'] == code, (label, value)
        results.append({'case': label, 'state': value['state'], 'code': value.get('code')})

    # Exclusive creation is the cleanup authority; never adopt an existing installation.
    BASE.mkdir(mode=0o755)
    try:
        invoke('missing-bootstrap')
        assert not (BASE / 'Runtimes').exists()
        bootstrap.parent.mkdir(parents=True, mode=0o755)
        shutil.copyfile(binary, bootstrap)
        bootstrap.chmod(0o755)
        invoke('fresh-package', success=True)
        assert fence.read_bytes() == b''
        for path in [runtime, runtime.parent, BASE / 'Profiles', fence, runtime / '.runtime-lease']:
            info = path.lstat()
            assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) & 0o022 == 0
        protected = json.dumps({'schemaVersion': 1, 'manifestSha256': manifest, 'controllerSha256': digest}).encode()
        receipt.write_bytes(protected)
        sentinel = runtime / 'retained-data'
        sentinel.write_bytes(b'never replace user data during admission')
        invoke('missing-versioned-controller', success=True)
        controller.parent.mkdir(mode=0o755)
        controller.write_bytes(b'corrupt controller must never execute')
        invoke('damaged-versioned-controller', success=True)
        with (runtime / '.runtime-lease').open('rb') as lease:
            fcntl.flock(lease, fcntl.LOCK_SH | fcntl.LOCK_NB)
            invoke('live-code-reader', code='host_package_busy')
        invoke('retry-after-reader', success=True)
        receipt.write_bytes(protected.replace(manifest.encode(), b'a' * 64))
        invoke('mismatched-receipt', code='host_install_record_invalid')
        receipt.write_bytes(b'not json')
        invoke('malformed-receipt', code='host_install_record_invalid')
        assert receipt.read_bytes() == b'not json'
        receipt.write_bytes(protected)
        controller.chmod(0o777)
        invoke('writable-controller')
        controller.unlink()
        controller.symlink_to(sentinel)
        invoke('linked-controller')
        controller.unlink()
        controller.mkdir()
        invoke('directory-controller')
        controller.rmdir()
        controller.write_bytes(b'corrupt controller must never execute')
        fence.write_bytes(b'invalid fence')
        invoke('nonempty-fence')
        assert fence.read_bytes() == b'invalid fence'
        fence.write_bytes(b'')
        bootstrap.write_bytes(b'tampered bootstrap')
        invoke('tampered-bootstrap', code='host_install_controller_changed')
        shutil.copyfile(binary, bootstrap)
        invoke('recovered-bootstrap', success=True)
        shutil.copyfile(binary, controller)
        controller.chmod(0o755)
        invoke('missing-signed-payload-finalization', phase='--finalize-install')
        assert fence.read_bytes() == b'' and receipt.read_bytes() == protected
        assert sentinel.read_bytes() == b'never replace user data during admission'
        assert list((BASE / 'Profiles').iterdir()) == []
        print(json.dumps({'qualification': 'passed', 'cases': results, 'serverStarted': False,
                          'installedAcceptance': False, 'runtimeQualified': False}))
    finally:
        shutil.rmtree(BASE)


def main(arguments=None):
    require_hosted_linux(platform.system(), getattr(os, 'getuid', lambda: -1)(),
                         getattr(os, 'geteuid', lambda: -1)())
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 1:
        raise RuntimeError('expected_built_controller_path')
    qualify(arguments[0])


if __name__ == '__main__':
    main()
