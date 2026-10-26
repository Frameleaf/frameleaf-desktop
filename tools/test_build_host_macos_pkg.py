import hashlib
import os
import platform
import plistlib
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from build_host_macos_pkg import build, installer_scripts, stage_package, validate_identities
from build_runtime import BuildError
from build_host_macos_bundle import stage_bundle


class MacHostInstallerTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == 'Darwin', 'real macOS signing')
    def test_verification_uses_authoring_node_without_executing_candidate_node(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            code = root / 'fixture.c'
            code.write_text('int main(void) { return 0; }\n')
            flat = root / 'controller'
            subprocess.run(['xcrun', 'clang', '-arch', platform.machine(), str(code), '-o', str(flat)], check=True, capture_output=True)
            bundle = stage_bundle(flat, root / 'bundle', hashlib.sha256(flat.read_bytes()).hexdigest(), '0.1.0')
            subprocess.run(['codesign', '--force', '--sign', '-', str(bundle)], check=True, capture_output=True)
            controller = bundle / 'Contents/MacOS/frameleaf-native-host'
            candidate = root / 'candidate'
            (candidate / 'payload').mkdir(parents=True)
            (candidate / 'payload/node').write_bytes(b'untrusted candidate executable')
            architecture = {'arm64': 'aarch64', 'x86_64': 'x86_64'}[platform.machine()]
            (candidate / 'manifest.json').write_text('{"platform":"macos","architecture":"' + architecture + '","files":{}}')
            (candidate / 'manifest.sig').write_bytes(b'fixture')
            calls = []
            def tool(arguments, **_):
                calls.append(arguments)
                self.assertNotEqual(Path(arguments[0]), candidate / 'payload/node', 'candidate cannot verify its own signature')
                if arguments[0] in ['/usr/bin/pkgbuild', '/usr/bin/productbuild']:
                    Path(arguments[-1]).write_bytes(b'fixture archive')
                    return ''
                return '{"manifestSha256":"' + 'a' * 64 + '"}'
            with patch('build_host_macos_pkg.run', side_effect=tool):
                build(candidate, controller, root / 'out')
            self.assertEqual(len([args for args in calls if '--input-type=module' in args]), 2)
            with patch('build_host_macos_pkg.shutil.which', return_value=str(candidate / 'payload/node')), patch('build_host_macos_pkg.run', side_effect=tool) as run:
                with self.assertRaises(BuildError):
                    build(candidate, controller, root / 'candidate-node-on-path')
                run.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX file permissions')
    def test_new_package_refuses_an_unsealed_controller_before_running_tools(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            candidate = root / 'candidate'
            (candidate / 'payload').mkdir(parents=True)
            (candidate / 'payload/node').write_bytes(b'synthetic node')
            (candidate / 'manifest.json').write_text('{"platform":"macos","architecture":"aarch64","files":{}}')
            (candidate / 'manifest.sig').write_bytes(b'fixture')
            controller = root / 'controller'
            controller.write_bytes(b'synthetic controller')
            def tool(arguments, **_):
                if arguments[0] in ['/usr/bin/pkgbuild', '/usr/bin/productbuild']:
                    Path(arguments[-1]).write_bytes(b'fixture archive')
                    return ''
                return '{"manifestSha256":"' + 'a' * 64 + '"}'
            with patch('build_host_macos_pkg.platform.system', return_value='Darwin'), patch('build_host_macos_pkg.inspect_controller', return_value='arm64'), patch('build_host_macos_pkg.run', side_effect=tool) as run:
                with self.assertRaises(BuildError):
                    build(candidate, controller, root / 'out')
                run.assert_not_called()

    def test_version_identifiers_cannot_escape_fixed_destinations(self):
        validate_identities('a' * 64, 'b' * 64)
        for value in ['', '../escape', '/tmp', 'A' * 64]:
            with self.assertRaises(BuildError):
                validate_identities(value, 'b' * 64)

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX installer shell')
    def test_scripts_refuse_other_volumes_and_only_pass_fixed_version_ids(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / 'called'
            helper = root / 'Frameleaf Native Host.app/Contents/MacOS/frameleaf-native-host'
            helper.parent.mkdir(parents=True)
            helper.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > ' + shlex.quote(str(marker)) + '\n')
            helper.chmod(0o755)
            for name, text in installer_scripts('a' * 64, 'b' * 64).items():
                script = root / name
                script.write_text(text)
                script.chmod(0o755)
                result = subprocess.run(['/bin/sh', str(script), 'package', 'unused', '/another-volume'], capture_output=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())
            result = subprocess.run(['/bin/sh', str(root / 'preinstall'), 'package', 'unused', '/'], capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(marker.read_text().splitlines(), ['--prepare-install', 'a' * 64, 'b' * 64])

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX file permissions')
    def test_staging_keeps_source_unchanged_and_only_places_versioned_resources(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            candidate = root / 'candidate'
            (candidate / 'payload').mkdir(parents=True)
            (candidate / 'payload' / 'node').write_bytes(b'synthetic node')
            (candidate / 'payload' / 'node').chmod(0o700)
            for name in ['manifest.json', 'manifest.sig']:
                (candidate / name).write_bytes(b'fixture')
            helper = root / 'controller'
            helper.write_bytes(b'synthetic controller')
            helper.chmod(0o700)
            out = root / 'out'
            digest = hashlib.sha256(helper.read_bytes()).hexdigest()
            stage_package(candidate, helper, out, 'a' * 64, digest)
            base = out / 'root' / 'Library' / 'Application Support' / 'Frameleaf'
            runtime = base / 'Runtimes' / ('a' * 64)
            self.assertEqual((runtime / 'payload' / 'node').read_bytes(), b'synthetic node')
            self.assertEqual((runtime / 'payload' / 'node').stat().st_mode & 0o777, 0o755)
            self.assertEqual((candidate / 'payload' / 'node').stat().st_mode & 0o777, 0o700)
            self.assertEqual((base / 'Controllers' / ('a' * 64) / digest / 'Frameleaf Native Host.app/Contents/MacOS/frameleaf-native-host').read_bytes(), helper.read_bytes())
            self.assertEqual(list((base / 'Profiles').iterdir()), [])
            self.assertEqual((out / 'scripts/Frameleaf Native Host.app/Contents/MacOS/frameleaf-native-host').read_bytes(), helper.read_bytes())
            with self.assertRaises(BuildError):
                stage_package(candidate, helper, out, 'a' * 64, digest)

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX file permissions')
    def test_installer_uses_same_app_like_controller_in_payload_and_bootstrap(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            candidate = root / 'candidate'
            (candidate / 'payload').mkdir(parents=True)
            (candidate / 'payload/node').write_bytes(b'node')
            for name in ['manifest.json', 'manifest.sig']:
                (candidate / name).write_bytes(b'fixture')
            helper = root / 'controller'
            helper.write_bytes(b'controller')
            digest = hashlib.sha256(helper.read_bytes()).hexdigest()
            out = root / 'out'
            stage_package(candidate, helper, out, 'a' * 64, digest)
            suffix = Path('Frameleaf Native Host.app/Contents/MacOS/frameleaf-native-host')
            version = out / 'root/Library/Application Support/Frameleaf/Controllers' / ('a' * 64) / digest
            self.assertEqual((version / suffix).read_bytes(), helper.read_bytes())
            self.assertEqual((out / 'scripts' / suffix).read_bytes(), helper.read_bytes())
            self.assertEqual((version / suffix.parent.parent / 'Info.plist').read_bytes(), (out / 'scripts' / suffix.parent.parent / 'Info.plist').read_bytes())
            self.assertFalse((version / 'frameleaf-native-host').exists())
            self.assertIn('/Frameleaf Native Host.app/Contents/MacOS/frameleaf-native-host', (out / 'scripts/postinstall').read_text())

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX file permissions')
    def test_package_pins_the_only_bundle_without_relocation_or_version_skipping(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            candidate = root / 'candidate'
            (candidate / 'payload').mkdir(parents=True)
            (candidate / 'payload/node').write_bytes(b'synthetic node')
            for name in ['manifest.json', 'manifest.sig']:
                (candidate / name).write_bytes(b'synthetic metadata')
            controller = root / 'controller'
            controller.write_bytes(b'synthetic controller')
            digest = hashlib.sha256(controller.read_bytes()).hexdigest()
            out = root / 'out'
            stage_package(candidate, controller, out, 'a' * 64, digest)
            policy = out / 'components.plist'
            self.assertTrue(policy.is_file(), 'component bundle policy is missing')
            self.assertEqual(plistlib.loads(policy.read_bytes()), [{
                'RootRelativeBundlePath': f'Library/Application Support/Frameleaf/Controllers/{"a" * 64}/{digest}/Frameleaf Native Host.app',
                'BundleIsRelocatable': False,
                'BundleIsVersionChecked': False,
                'BundleHasStrictIdentifier': True,
                'BundleOverwriteAction': 'upgrade',
            }])
