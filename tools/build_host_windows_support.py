"""Stage pinned Windows Node and private Chromium; no execution, signing or runtime qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import zipfile

from build_host_database import download
from build_host_ffmpeg import unpack
from build_runtime import BuildError, git_blob, inventory, regular, sha256
from stage_host_browser import stage_browser

NODE_URL = 'https://nodejs.org/dist/v26.11.1/node-v26.11.1-win-x64.zip'
NODE_ARCHIVE_SHA = '97f36a8a9684ff0d3e35758b4610fef5b628a5880e96f2ccc11240e5daf9934e'
NODE_EXE_SHA = 'a619e2e09eb0d50ef4c733d678b4d22689d2afef138cd67fd3fa107b535f8819'
BROWSER_URL = 'https://storage.googleapis.com/chromium-browser-snapshots/Win_x64/1735040/chrome-win.zip'
BROWSER_ARCHIVE_SHA = 'c6f856b110dba84f88c060f30ad9e84f11d4ca8f426eeab024e67b661a6624db'
BROWSER_MANIFEST_SHA = '2cfd419f71ac6475d81e1301fa86c34cf2a2a6bae2a0da4b5a2b18310216b6bf'
BROWSER_SOURCE = 'https://github.com/chromium/chromium/tree/437d8b7085ee32ec76c1145fd502169f2ad8be50'
BROWSER_LICENSE_URL = 'https://raw.githubusercontent.com/chromium/chromium/437d8b7085ee32ec76c1145fd502169f2ad8be50/LICENSE'
BROWSER_LICENSE_SHA = '368cca1106be99d39ecd32a38d8305585d802a475effb66380b91ffc9bcf709b'
PLAYWRIGHT = {
    'version': '1.64.0',
    'resolved': 'https://registry.npmjs.org/playwright-core/-/playwright-core-1.64.0.tgz',
    'integrity': 'sha512-T9r+MZkTECl2+oUcZ26YgZzTrYidTsIhYYkJix+6iDOymOb1FB2RLLSOxRGnZGv5DStt+aduIVbt+E8WygXYpg==',
}


def build(source: Path, revision: str, studio: Path, output: Path) -> None:
    """Verify immutable source and staged manifest, then stage into a new exclusively owned output."""
    if (not re.fullmatch(r'[a-f0-9]{40}', revision)
            or any(not p.is_absolute() or p.resolve() != p for p in [source, studio, output])
            or output.exists() or output.is_symlink()
            or output.is_relative_to(source) or output.is_relative_to(studio)):
        raise BuildError('host_windows_support_paths_invalid')
    git = shutil.which('git')
    if not git:
        raise BuildError('host_windows_support_git_missing')
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0')
    lock = git_blob(git, source, revision, 'studio/engine-package-lock.json', env)
    try:
        package = json.loads(lock)['packages']['node_modules/playwright-core']
        if any(package.get(k) != v for k, v in PLAYWRIGHT.items()):
            raise ValueError()
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise BuildError('host_windows_support_source_pin_changed') from error
    manifest = studio / 'engine/node_modules/playwright-core/browsers.json'
    for parent in manifest.parents:
        regular(parent)
        if parent == studio:
            break
    if (not stat.S_ISREG(regular(manifest).st_mode) or sha256(manifest) != BROWSER_MANIFEST_SHA):
        raise BuildError('host_windows_support_browser_manifest_changed')

    output.mkdir(mode=0o700)
    work, payload = output / 'work', output / 'support'
    report = {
        'schemaVersion': 1, 'sourceRevision': revision,
        'sourceLockSha256': hashlib.sha256(lock).hexdigest(),
        'browserManifestSha256': BROWSER_MANIFEST_SHA,
        'nodeVersion': '26.11.1', 'browserVersion': '159.0.8143.0',
        'nodeArchive': {'url': NODE_URL, 'sha256': NODE_ARCHIVE_SHA},
        'browserArchive': {'url': BROWSER_URL, 'sha256': BROWSER_ARCHIVE_SHA},
        'browserSource': BROWSER_SOURCE,
        'qualification': 'failed', 'runtimeQualified': False, 'redistributable': False,
    }
    try:
        work.mkdir(mode=0o700)
        payload.mkdir(mode=0o700)
        for name, url, digest in [('node', NODE_URL, NODE_ARCHIVE_SHA),
                                  ('browser', BROWSER_URL, BROWSER_ARCHIVE_SHA)]:
            archive, expanded = work / (name + '.zip'), work / name
            download(url, archive, digest, max_bytes=(384 if name == 'browser' else 128) * 1024**2)
            expanded.mkdir(mode=0o700)
            unpack(archive, expanded)
        node = work / 'node/node-v26.11.1-win-x64'
        browser = work / 'browser/chrome-win'
        if sha256(node / 'node.exe') != NODE_EXE_SHA or not (node / 'LICENSE').stat().st_size:
            raise BuildError('host_windows_support_payload_changed')
        (payload / 'node').mkdir(mode=0o700)
        for name in ['node.exe', 'LICENSE']:
            shutil.copy2(node / name, payload / 'node' / name)
        # Cross-staging Windows bytes on POSIX needs executable metadata, without executing them.
        (browser / 'chrome.exe').chmod(0o755)
        for name in ['interactive_ui_tests.exe', 'setup.exe']:
            (browser / name).unlink(missing_ok=True)
        stage_browser(browser, payload / 'browser', 'chrome.exe')
        download(BROWSER_LICENSE_URL, payload / 'browser/LICENSE', BROWSER_LICENSE_SHA)
        (payload / 'browser/SOURCE.txt').write_text(BROWSER_SOURCE + '\n', encoding='utf-8')
        report['files'] = inventory(payload)
        report['qualification'] = 'passed'
    finally:
        try:
            try:
                if work.exists():
                    shutil.rmtree(work)
            except OSError:
                report['qualification'] = 'failed'
                raise
            finally:
                if report['qualification'] != 'passed':
                    report.pop('files', None)
                    if payload.exists():
                        shutil.rmtree(payload)
        finally:
            partial = output / 'qualification.json.part'
            try:
                partial.write_text(json.dumps(report, indent=2) + '\n')
                partial.replace(output / 'qualification.json')
            except OSError:
                report['qualification'] = 'failed'
                report.pop('files', None)
                try:
                    if payload.exists():
                        shutil.rmtree(payload)
                finally:
                    partial.unlink(missing_ok=True)
                raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'revision', 'studio', 'output']:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        build(Path(args.source), args.revision, Path(args.studio), Path(args.output))
    except (BuildError, OSError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, str(error) if isinstance(error, BuildError) else 'host_windows_support_failed')
