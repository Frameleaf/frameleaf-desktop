"""Run fixed disposable Windows fixtures from the current Cargo compiler receipts."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess

from build_runtime import regular, sha256

FIXTURES = {
    'credentials': ('credentials::qualification::disposable_runner_epoch_persistence', 1, True),
    'package': ('host_install::windows::package::tests::disposable_runner_', 3, False),
    'cloud': ('copy_source::windows_cloud_tests::disposable_cloud_provider_qualification', 1, True),
}


def require_runner(system, architecture, environment):
    if (system != 'Windows' or architecture != 'AMD64' or environment.get('GITHUB_ACTIONS') != 'true'
        or environment.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise ValueError('disposable_windows_runner_required')


def select_artifacts(receipt, root):
    if not receipt.is_file() or not 0 < regular(receipt).st_size <= 32 * 1024**2:
        raise ValueError('windows_test_receipt_invalid')
    records = []
    for line in receipt.read_text(encoding='utf-8-sig').splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (isinstance(value, dict) and value.get('reason') == 'compiler-artifact'
            and value.get('manifest_path') and Path(value['manifest_path']).resolve() == (root / 'src-tauri/Cargo.toml').resolve()
            and value.get('executable')):
            records.append(value)
    libraries = [r for r in records if r.get('target', {}).get('name') == 'frameleaf_desktop'
                 and r.get('profile', {}).get('test') is True
                 and Path(r['target'].get('src_path', '')).resolve() == (root / 'src-tauri/src/lib.rs').resolve()]
    controllers = [r for r in records if r.get('target', {}).get('name') == 'frameleaf-native-host'
                   and r.get('target', {}).get('kind') == ['bin'] and r.get('profile', {}).get('test') is False]
    if len(libraries) != 1 or len(controllers) != 1:
        raise ValueError('windows_test_artifact_ambiguous')
    library, controller = (Path(row['executable']) for row in [libraries[0], controllers[0]])
    for binary in [library, controller]:
        if not binary.is_absolute() or not binary.is_file():
            raise ValueError('windows_test_executable_invalid')
        regular(binary)
    if (library.resolve().parent != (root / 'src-tauri/target/debug/deps').resolve()
        or not re.fullmatch(r'frameleaf_desktop-[a-f0-9]{16}\.exe', library.name)
        or controller.resolve() != (root / 'src-tauri/target/debug/frameleaf-native-host.exe').resolve()):
        raise ValueError('windows_test_executable_invalid')
    return library.resolve(), controller.resolve()


def qualify(receipt, kind, output):
    require_runner(platform.system(), platform.machine(), os.environ)
    if kind == 'credentials' and os.environ.get('FRAMELEAF_TEST_DISPOSABLE_KEYSTORE') != '1':
        raise ValueError('disposable_keystore_permission_required')
    root = Path.cwd().resolve()
    library, controller = select_artifacts(receipt, root)
    selected, count, exact = FIXTURES[kind]
    tests = subprocess.check_output([str(library), '--list'], text=True, encoding='utf-8', cwd=root / 'src-tauri', timeout=30).splitlines()
    names = [line.removesuffix(': test') for line in tests if line.endswith(': test')]
    matches = [name for name in names if name == selected] if exact else [name for name in names if name.startswith(selected)]
    if len(matches) != count:
        raise ValueError('windows_required_fixture_missing')
    env = dict(os.environ, FRAMELEAF_TEST_CONTROLLER=str(controller))
    command = [str(library), selected, '--ignored', '--nocapture'] + (['--exact'] if exact else [])
    result = subprocess.run(command, env=env, capture_output=True, text=True, encoding='utf-8', cwd=root / 'src-tauri', timeout=240)
    transcript = result.stdout + result.stderr
    print(transcript, flush=True)
    result.check_returncode()
    if not re.search(rf'(?m)^test result: ok\. {count} passed; 0 failed; 0 ignored;', transcript):
        raise ValueError('windows_required_fixture_did_not_run')
    report = {'state': 'compiled-Windows-' + kind + '-fixtures-passed', 'executedFixtures': matches,
              'librarySha256': sha256(library), 'controllerSha256': sha256(controller),
              'sourceHead': os.environ['GITHUB_SHA'], 'installedAcceptance': False}
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2); stream.write('\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipts', type=Path, required=True)
    parser.add_argument('--kind', choices=FIXTURES, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    qualify(args.receipts, args.kind, args.output)
