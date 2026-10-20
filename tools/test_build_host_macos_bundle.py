import hashlib
import os
import plistlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_host_macos_bundle import stage_bundle, validate_bundle, inspect_controller
from build_runtime import BuildError


@unittest.skipUnless(os.name == 'posix', 'macOS bundle file permissions require POSIX')
class MacControllerBundleTests(unittest.TestCase):
    def fixture(self, root):
        controller = root / 'controller'
        controller.write_bytes(b'synthetic controller')
        controller.chmod(0o700)
        return controller, hashlib.sha256(controller.read_bytes()).hexdigest()

    def test_bundle_has_stable_identity_exact_resources_and_an_independent_controller(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source, digest = self.fixture(root)
            bundle = stage_bundle(source, root / 'out', digest, '0.1.0')
            executable = bundle / 'Contents/MacOS/frameleaf-native-host'
            self.assertEqual(executable.read_bytes(), source.read_bytes())
            self.assertNotEqual(executable.stat().st_ino, source.stat().st_ino)
            self.assertEqual(source.stat().st_mode & 0o777, 0o700)
            info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
            self.assertEqual(info['CFBundleIdentifier'], 'app.frameleaf.desktop.host')
            self.assertTrue(info['LSBackgroundOnly'])
            self.assertEqual(set(validate_bundle(bundle, digest, '0.1.0')), {'Contents/Info.plist', 'Contents/MacOS/frameleaf-native-host'})
            with self.assertRaises(BuildError):
                stage_bundle(source, root / 'out', digest, '0.1.0')

    def test_invalid_input_never_creates_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source, digest = self.fixture(root)
            link = root / 'link'
            link.symlink_to(source)
            for path, expected, version in [(source, 'bad', '0.1.0'), (source, 'a'*64, '0.1.0'), (link, digest, '0.1.0'), (source, digest, '../escape'), (source, digest, '1.0.0-beta')]:
                with self.subTest(path=path, version=version), self.assertRaises(BuildError):
                    stage_bundle(path, root / 'out', expected, version)
                self.assertFalse((root / 'out').exists())
            directory = root / 'directory'
            directory.mkdir()
            alias = root / 'directory-link'
            alias.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(BuildError):
                stage_bundle(source, alias / 'out', digest, '0.1.0')
            self.assertFalse((directory / 'out').exists())

    def test_changed_metadata_extra_directories_permissions_and_links_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source, digest = self.fixture(root)
            bundle = stage_bundle(source, root / 'out', digest, '0.1.0')
            info = bundle / 'Contents/Info.plist'
            original = info.read_bytes()
            info.write_bytes(plistlib.dumps({'CFBundleIdentifier': 'foreign'}))
            with self.assertRaises(BuildError): validate_bundle(bundle, digest, '0.1.0')
            info.write_bytes(original)
            extra = bundle / 'Contents/PlugIns'
            extra.mkdir()
            with self.assertRaises(BuildError): validate_bundle(bundle, digest, '0.1.0')
            extra.rmdir()
            executable = bundle / 'Contents/MacOS/frameleaf-native-host'
            executable.chmod(0o644)
            with self.assertRaises(BuildError): validate_bundle(bundle, digest, '0.1.0')
            executable.chmod(0o755)
            executable.write_bytes(b'changed')
            with self.assertRaises(BuildError): validate_bundle(bundle, digest, '0.1.0')
            executable.write_bytes(source.read_bytes())
            alias = root / 'alias'
            os.link(executable, alias)
            with self.assertRaises(BuildError): validate_bundle(bundle, digest, '0.1.0')
            alias.unlink()
            executable.unlink()
            executable.symlink_to(source)
            with self.assertRaises(BuildError): validate_bundle(bundle, digest, '0.1.0')
            executable.unlink()
            shutil.copyfile(source, executable)
            executable.chmod(0o755)
            validate_bundle(bundle, digest, '0.1.0')

    def test_inspection_uses_os_tools_and_refuses_foreign_architecture_and_dependencies(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source, _ = self.fixture(root)
            for archs, deps, accepted in [('arm64', '/usr/lib/libSystem.B.dylib', True), ('i386', '/usr/lib/libSystem.B.dylib', False), ('arm64', '/usr/local/lib/foreign.dylib', False)]:
                with self.subTest(archs=archs, deps=deps), patch('build_host_macos_bundle.platform.machine', return_value='arm64'), patch('build_host_macos_bundle.run', side_effect=[archs, f'{source}:\n\t{deps} (compatibility version 1.0.0)']) as run:
                    if accepted:
                        self.assertEqual(inspect_controller(source, root, {}), 'arm64')
                        self.assertEqual(run.call_args_list[0].args[0], ['/usr/bin/lipo', '-archs', source])
                        self.assertEqual(run.call_args_list[1].args[0], ['/usr/bin/otool', '-L', source])
                    else:
                        with self.assertRaises(BuildError): inspect_controller(source, root, {})
