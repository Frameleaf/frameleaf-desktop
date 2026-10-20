import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import build_host_windows_nsis as builder
from build_runtime import BuildError


class WindowsHostInstallerTests(unittest.TestCase):
    def controller(self, root):
        path = root / 'controller.exe'
        raw = bytearray(256)
        raw[:2] = b'MZ'
        raw[60:64] = (128).to_bytes(4, 'little')
        raw[128:134] = b'PE\0\0\x64\x86'
        raw[152:154] = b'\x0b\x02'
        raw += (builder.ROOT / 'runtime/release-trust.json').read_bytes()
        raw += b'--install-windows-package --remove-windows-package'
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def fixture(self, root):
        candidate = root / 'candidate'
        (candidate / 'payload/licenses').mkdir(parents=True)
        artifact = b'synthetic payload, never executable'
        (candidate / 'payload/licenses/third-party.txt').write_bytes(artifact)
        metadata = {'platform': 'windows', 'architecture': 'x86_64', 'files': {
            'licenses/third-party.txt': {'bytes': len(artifact), 'sha256': hashlib.sha256(artifact).hexdigest()}
        }}
        (candidate / 'manifest.json').write_text(json.dumps(metadata))
        (candidate / 'manifest.sig').write_bytes(b'not a real signature')
        return candidate, hashlib.sha256((candidate / 'manifest.json').read_bytes()).hexdigest()

    def test_hash_identity_cannot_inject_installer_language(self):
        for value in ['A' * 64, '../escape', 'a' * 64 + '\nExec bad', '$0', '']:
            with self.assertRaises(BuildError):
                builder.installer_script(value, 'b' * 64, [])

    def test_windows_paths_reject_ambiguous_or_injectable_names(self):
        for name in ['../x', '/x', 'a//b', 'x\\b', 'x:y', 'a\nb', 'a\x7fb', 'NUL.txt', 'COM1', 'lpt².txt',
                     'x.', 'x ', 'a/*', 'a/?', 'a/"b', 'a/<>', '/'.join(['x'] * 33)]:
            with self.subTest(name=name), self.assertRaises(BuildError):
                builder.windows_name(name)
        with self.assertRaises(BuildError):
            builder.installer_script('a' * 64, 'b' * 64, ['A.txt', 'a.TXT'])

    def test_payload_dollars_remain_literal_and_sources_use_numbered_files(self):
        script = builder.installer_script('a' * 64, 'b' * 64, ['payload/$PLUGINSDIR/${evil}/hello$.txt'])
        self.assertIn('SetOutPath "$PLUGINSDIR\\candidate\\payload\\$$PLUGINSDIR\\$${evil}"', script)
        self.assertIn('File "/oname=hello$$.txt" "files/0"', script)
        self.assertNotIn('!include "${evil}', script)

    @unittest.skipUnless(shutil.which('makensis'), 'requires the pinned NSIS compiler')
    def test_actual_compiler_accepts_spaces_and_literal_dollars_in_payload_names(self):
        compiler = shutil.which('makensis')
        self.assertEqual(subprocess.check_output([compiler, '-VERSION'], text=True).strip(), 'v3.11')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'files').mkdir()
            names = ['manifest.json', 'payload/licenses/a spaced $.txt']
            for index in range(len(names)):
                (root / 'files' / str(index)).write_bytes(b'synthetic compiler fixture only')
            (root / 'controller.bin').write_bytes(b'synthetic controller fixture only')
            (root / 'installer.nsi').write_text(builder.installer_script('a' * 64, 'b' * 64, names))
            result = subprocess.run([compiler, '-NOCONFIG', '-V2', 'installer.nsi'], cwd=root,
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((root / 'FrameleafNativeHost-internal.exe').read_bytes()[:2], b'MZ')

    def test_extraction_and_execution_fail_closed_and_hold_bootstrap_handles(self):
        script = builder.installer_script('a' * 64, 'b' * 64, ['manifest.json'])
        self.assertIn('RequestExecutionLevel admin', script)
        self.assertIn('CRCCheck force', script)
        self.assertLess(script.index('InitPluginsDir'), script.index('File /oname=frameleaf-native-host.exe'))
        self.assertLess(script.index('StrCpy $ControllerHandle'), script.index('ExecWait'))
        self.assertGreater(script.index('CloseHandle'), script.rindex('ExecWait'))
        self.assertIn('i 1, p 0, i 3, i 0x02200000', script)
        self.assertIn('i 1, p 0, i 3, i 0x00200000', script)
        self.assertEqual(script.count('StrCmp $0 0 done failed'), 2)
        self.assertIn('SetErrorLevel 1\n  Abort', script)
        for forbidden in ['RMDir', 'Delete ', 'WriteReg', '$INSTDIR', '$PROGRAMFILES', 'PowerShell', 'ExecShell', '/REBOOTOK']:
            self.assertNotIn(forbidden, script)
        self.assertIn('--remove-windows-package ' + 'a' * 64 + ' ' + 'b' * 64, script)
        self.assertIn('StrCmp $0 "/REMOVE" remove', script)
        self.assertIn('SetErrorLevel 64\n  Quit', script)

    def test_controller_requires_exact_approved_hash_pe_target_and_compiled_trust(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path, approved = self.controller(root)
            builder.inspect_controller(path, approved)
            with self.assertRaisesRegex(BuildError, 'controller_changed'):
                builder.inspect_controller(path, 'f' * 64)
            raw = bytearray(path.read_bytes())
            raw[132:134] = b'\x4c\x01'
            path.write_bytes(raw)
            with self.assertRaisesRegex(BuildError, 'target_mismatch'):
                builder.inspect_controller(path, hashlib.sha256(raw).hexdigest())
            raw[132:134] = b'\x64\x86'
            raw = raw.replace(b'desktop-release-2026-10', b'unapproved-release-key')
            path.write_bytes(raw)
            with self.assertRaisesRegex(BuildError, 'trust_mismatch'):
                builder.inspect_controller(path, hashlib.sha256(raw).hexdigest())

    def test_staging_preserves_license_bytes_and_does_not_execute_controller(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            controller, approved = self.controller(root)
            candidate, manifest = self.fixture(root)
            with patch.object(builder, 'run') as command:
                names = builder.stage(candidate, controller, root / 'out', manifest, approved)
                command.assert_not_called()
            self.assertEqual((root / 'out/files' / str(names.index('payload/licenses/third-party.txt'))).read_bytes(),
                             (candidate / 'payload/licenses/third-party.txt').read_bytes())
            self.assertEqual((root / 'out/controller.bin').read_bytes(), controller.read_bytes())
            self.assertFalse((root / 'out/qualification.json').exists())
            self.assertEqual(set(names), {'manifest.json', 'manifest.sig', 'payload/licenses/third-party.txt'})

    def test_rejects_staging_paths_links_existing_output_and_changed_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            controller, approved = self.controller(root)
            candidate, manifest = self.fixture(root)
            for out in [candidate / 'out', root]:
                with self.assertRaisesRegex(BuildError, 'paths_invalid'):
                    builder.stage(candidate, controller, out, manifest, approved)
            with self.assertRaisesRegex(BuildError, 'runtime_changed'):
                builder.stage(candidate, controller, root / 'out', 'f' * 64, approved)
            self.assertFalse((root / 'out').exists())
            target = candidate / 'payload/licenses/third-party.txt'
            target.unlink()
            target.symlink_to(controller)
            with self.assertRaises(BuildError):
                builder.stage(candidate, controller, root / 'linked-out', manifest, approved)

    def test_unsigned_source_is_rejected_before_staging_or_compiler(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            controller, approved = self.controller(root)
            candidate, _ = self.fixture(root)
            def command(args, **kwargs):
                if args == ['/trusted/makensis', '-VERSION']:
                    return 'v3.11'
                self.assertEqual(args[0], '/trusted/node')
                self.assertNotIn(str(controller), [str(arg) for arg in args])
                raise BuildError('host_signature_invalid')
            with patch.object(builder.shutil, 'which', side_effect=lambda name: '/trusted/' + name), patch.object(builder, 'run', side_effect=command) as execute:
                with self.assertRaisesRegex(BuildError, 'host_signature_invalid'):
                    builder.build(candidate, controller, root / 'out', approved)
                self.assertEqual(execute.call_count, 2)
                self.assertFalse((root / 'out').exists())

    def test_unapproved_nsis_version_never_reaches_payload_or_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            controller, approved = self.controller(root)
            candidate, _ = self.fixture(root)
            for version in ['v3.10', 'v3.11-custom', 'v3.12', '']:
                with patch.object(builder.shutil, 'which', return_value='/trusted/tool'), patch.object(builder, 'run', return_value=version) as command:
                    with self.assertRaisesRegex(BuildError, 'nsis_version_unapproved'):
                        builder.build(candidate, controller, root / 'out', approved)
                    self.assertEqual(command.call_count, 1)
                    self.assertFalse((root / 'out').exists())

    def test_complete_authoring_rechecks_staged_signature_and_records_unqualified_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            controller, approved = self.controller(root)
            candidate, manifest = self.fixture(root)
            out = root / 'out'
            checked = {'manifestSha256': manifest, 'keyId': 'synthetic-test-only'}
            calls = []
            def command(args, **kwargs):
                calls.append(args)
                if args[1:] == ['-VERSION']:
                    return 'v3.11'
                if args[0] == '/trusted/node':
                    return json.dumps(checked)
                self.assertEqual(args, ['/trusted/makensis', '-NOCONFIG', '-V2', 'installer.nsi'])
                (out / 'FrameleafNativeHost-internal.exe').write_bytes(b'synthetic compiler output')
                return ''
            with patch.object(builder.shutil, 'which', side_effect=lambda name: '/trusted/' + name), patch.object(builder, 'run', side_effect=command), patch.object(builder, 'build_environment', wraps=builder.build_environment) as environment:
                builder.build(candidate, controller, out, approved)
                self.assertIs(environment.call_args.args[1], builder.os.environ)
            self.assertEqual(len(calls), 4)
            self.assertEqual(calls[1][-1], candidate)
            self.assertEqual(calls[2][-1], out / 'checked-candidate')
            self.assertTrue(all(args[0] != str(controller) for args in calls))
            result = json.loads((out / 'qualification.json').read_text())
            self.assertEqual(result['controllerSha256'], approved)
            self.assertEqual(result['host'], checked)
            for key in ['osCodeSigningQualified', 'installedProfileProvisioningQualified', 'runtimeQualified', 'redistributable']:
                self.assertIs(result[key], False)

    def test_changed_staged_signature_refuses_compiler_and_qualification_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            controller, approved = self.controller(root)
            candidate, manifest = self.fixture(root)
            out = root / 'out'
            with patch.object(builder.shutil, 'which', return_value='/trusted/tool'), patch.object(builder, 'run', side_effect=['v3.11', json.dumps({'manifestSha256': manifest}), json.dumps({'manifestSha256': 'f' * 64})]) as command:
                with self.assertRaisesRegex(BuildError, 'staged_runtime_changed'):
                    builder.build(candidate, controller, out, approved)
                self.assertEqual(command.call_count, 3)
                self.assertFalse((out / 'qualification.json').exists())
                self.assertFalse((out / 'FrameleafNativeHost-internal.exe').exists())

    def test_wrong_target_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            controller, approved = self.controller(root)
            candidate, _ = self.fixture(root)
            metadata = json.loads((candidate / 'manifest.json').read_text())
            metadata['platform'] = 'linux'
            (candidate / 'manifest.json').write_text(json.dumps(metadata))
            with patch.object(builder.shutil, 'which', return_value='/trusted/tool'), patch.object(builder, 'run', side_effect=['v3.11', '{}']):
                with self.assertRaisesRegex(BuildError, 'target_mismatch'):
                    builder.build(candidate, controller, root / 'out', approved)
                self.assertFalse((root / 'out').exists())


if __name__ == '__main__':
    unittest.main()
