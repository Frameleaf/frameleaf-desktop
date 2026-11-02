import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import build_host_windows_support as support
from build_runtime import BuildError, inventory


class WindowsSupportTests(unittest.TestCase):
    def fixture(self, root, damage=None):
        source, studio = root / 'source', root / 'studio'
        source.mkdir()
        manifest = studio / 'engine/node_modules/playwright-core/browsers.json'
        manifest.parent.mkdir(parents=True)
        manifest.write_bytes(b'{"browser":"source-pinned synthetic manifest"}')
        lock = {'packages': {'node_modules/playwright-core': dict(support.PLAYWRIGHT)}}
        if damage == 'lock':
            lock['packages']['node_modules/playwright-core']['version'] = '0.0.0'
        def archive(files):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, 'w') as z:
                for name, data in files.items():
                    z.writestr(name, data)
            return stream.getvalue()
        node_files = {'node-v26.11.1-win-x64/node.exe': b'private node fixture',
                      'node-v26.11.1-win-x64/LICENSE': b'node licence fixture'}
        browser_files = {'chrome-headless-shell-win64/chrome-headless-shell.exe': b'browser fixture',
                         'chrome-headless-shell-win64/LICENSE.headless_shell': b'complete browser notices',
                         'chrome-headless-shell-win64/locales/en-US.pak': b'locale fixture'}
        if damage == 'node-missing':
            del node_files['node-v26.11.1-win-x64/node.exe']
        if damage == 'node-digest':
            node_files['node-v26.11.1-win-x64/node.exe'] = b'wrong executable'
        if damage == 'browser-notice':
            del browser_files['chrome-headless-shell-win64/LICENSE.headless_shell']
        if damage == 'traversal':
            browser_files['../escape'] = b'forbidden'
        node, browser = archive(node_files), archive(browser_files)
        pins = dict(NODE_ARCHIVE_SHA=hashlib.sha256(node).hexdigest(),
                    NODE_EXE_SHA=hashlib.sha256(b'private node fixture').hexdigest(),
                    BROWSER_ARCHIVE_SHA=hashlib.sha256(browser).hexdigest(),
                    BROWSER_LICENSE_SHA=hashlib.sha256(b'complete browser notices').hexdigest(),
                    BROWSER_MANIFEST_SHA=hashlib.sha256(manifest.read_bytes()).hexdigest())
        if damage == 'manifest':
            manifest.write_bytes(b'changed installed browser manifest')
        if damage == 'digest':
            browser += b'changed download'
        downloads = {support.NODE_URL: node, support.BROWSER_URL: browser}
        calls = []
        def blob(git, path, revision, name, env):
            self.assertEqual((path, revision, name), (source, 'a' * 40, 'studio/engine-package-lock.json'))
            self.assertNotIn('GIT_DIR', env)
            return json.dumps(lock).encode()
        def request(url, timeout):
            calls.append(url)
            self.assertEqual(timeout, 60)
            return io.BytesIO(downloads[url])
        return source, studio, pins, blob, request, calls

    def test_stages_verified_archives_notices_and_complete_inventory_without_executing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            source, studio, pins, blob, request, calls = self.fixture(root)
            with patch.multiple(support, **pins), patch.object(support, 'git_blob', side_effect=blob), \
                    patch('urllib.request.urlopen', side_effect=request):
                support.build(source, 'a' * 40, studio, root / 'output')
            output = root / 'output'
            report = json.loads((output / 'qualification.json').read_text())
            self.assertEqual(report['qualification'], 'passed')
            self.assertEqual(report['files'], inventory(output / 'support'))
            self.assertEqual(len(report['files']), 5)
            self.assertEqual((output / 'support/browser/LICENSE.headless_shell').read_bytes(), b'complete browser notices')
            self.assertEqual(calls, [support.NODE_URL, support.BROWSER_URL])
            self.assertFalse(report['runtimeQualified'])
            self.assertFalse(report['redistributable'])
            self.assertFalse((output / 'work').exists())

    def test_changed_source_or_staged_manifest_is_refused_before_download_or_output(self):
        for damage in ['lock', 'manifest']:
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as td:
                root = Path(td).resolve()
                source, studio, pins, blob, request, calls = self.fixture(root, damage)
                with patch.multiple(support, **pins), patch.object(support, 'git_blob', side_effect=blob), \
                        patch('urllib.request.urlopen', side_effect=request), self.assertRaises(BuildError):
                    support.build(source, 'a' * 40, studio, root / 'output')
                self.assertEqual(calls, [])
                self.assertFalse((root / 'output').exists())

    def test_changed_download_missing_runtime_or_notices_and_traversal_fail_closed(self):
        for damage in ['digest', 'node-digest', 'node-missing', 'browser-notice', 'traversal']:
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as td:
                root = Path(td).resolve()
                source, studio, pins, blob, request, calls = self.fixture(root, damage)
                with patch.multiple(support, **pins), patch.object(support, 'git_blob', side_effect=blob), \
                        patch('urllib.request.urlopen', side_effect=request), self.assertRaises((BuildError, OSError)):
                    support.build(source, 'a' * 40, studio, root / 'output')
                output = root / 'output'
                self.assertEqual(json.loads((output / 'qualification.json').read_text())['qualification'], 'failed')
                self.assertFalse((output / 'support').exists())
                self.assertFalse((output / 'work').exists())
                self.assertFalse((root / 'escape').exists())

    def test_existing_output_and_source_nested_output_are_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            source, studio, pins, blob, request, calls = self.fixture(root)
            keep = root / 'output'
            keep.mkdir()
            (keep / 'existing').write_bytes(b'preserve')
            with patch('urllib.request.urlopen', side_effect=request):
                for output in [keep, source / 'new', studio / 'new']:
                    with self.subTest(output=output), self.assertRaises(BuildError):
                        support.build(source, 'a' * 40, studio, output)
            self.assertEqual((keep / 'existing').read_bytes(), b'preserve')
            self.assertEqual(calls, [])

    def test_cleanup_error_cannot_publish_a_successful_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            source, studio, pins, blob, request, calls = self.fixture(root)
            with patch.multiple(support, **pins), patch.object(support, 'git_blob', side_effect=blob), \
                    patch('urllib.request.urlopen', side_effect=request), \
                    patch.object(support.shutil, 'rmtree', side_effect=OSError('cleanup denied')), \
                    self.assertRaises(OSError):
                support.build(source, 'a' * 40, studio, root / 'output')
            report = json.loads((root / 'output/qualification.json').read_text())
            self.assertEqual(report['qualification'], 'failed')

    def test_work_cleanup_failure_still_removes_payload_and_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            source, studio, pins, blob, request, calls = self.fixture(root)
            remove = support.shutil.rmtree
            def cleanup(path):
                if path.name == 'work':
                    raise OSError('work cleanup denied')
                remove(path)
            with patch.multiple(support, **pins), patch.object(support, 'git_blob', side_effect=blob), \
                    patch('urllib.request.urlopen', side_effect=request), \
                    patch.object(support.shutil, 'rmtree', side_effect=cleanup), self.assertRaises(OSError):
                support.build(source, 'a' * 40, studio, root / 'output')
            report = json.loads((root / 'output/qualification.json').read_text())
            self.assertEqual(report['qualification'], 'failed')
            self.assertNotIn('files', report)
            self.assertFalse((root / 'output/support').exists())
