import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_runtime import BuildError
from qualify_windows_controller import qualify, nsis_gui_sha256
from test_relocate_windows import pe


class ControllerQualificationTests(unittest.TestCase):
    def test_system_only_controller_reaches_its_bounded_entrypoint_without_ambient_paths(self):
        self.exercise('KERNEL32.dll\n api-ms-win-core-synch-l1-2-0.dll')

    def exercise(self, imports='kernel32.dll', probe=None, failure=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            system = root / 'Windows/System32'
            system.mkdir(parents=True)
            (system / 'kernel32.dll').write_bytes(b'OS fixture')
            binary = root / 'frameleaf-native-host.exe'
            image = bytearray(pe())
            image[86:88] = (0x22).to_bytes(2, 'little')
            binary.write_bytes(image)
            inspector = root / 'dumpbin.exe'
            inspector.write_bytes(b'authoring tool fixture')
            # A nearby private CRT must never excuse a forbidden runtime dependency.
            (root / 'vcruntime140.dll').write_bytes(b'private fixture')
            output = 'File Type: EXECUTABLE IMAGE\n  Image has the following dependencies:\n'
            output += '\n'.join('    ' + name for name in imports.splitlines()) + '\n  Summary\n'
            receipt = json.dumps({'protocolVersion': 1, 'state': 'failed', 'code': 'host_control_arguments_invalid'}).encode()
            responses = [subprocess.CompletedProcess([], 0, output.encode(), b''), probe or subprocess.CompletedProcess([], 1, receipt, b'')]
            with patch('qualify_windows_controller.platform.system', return_value='Windows'), patch('qualify_windows_controller.system_directory', return_value=system), patch('qualify_windows_controller.subprocess.run', side_effect=responses) as run:
                if failure:
                    with self.assertRaisesRegex(BuildError, failure):
                        qualify(binary, inspector)
                    return
                result = qualify(binary, inspector)
                self.assertTrue(result['systemOnlyDependencies'])
                self.assertTrue(result['sanitizedEntrypointQualified'])
                self.assertFalse(result['installedPlatformQualified'])
                self.assertEqual(run.call_count, 2)
                command = run.call_args_list[1]
                self.assertEqual(command.args[0], [str(binary), '--controller-dependency-probe'])
                self.assertEqual(command.kwargs['env'], {'SystemRoot': str(system.parent), 'WINDIR': str(system.parent), 'PATH': str(system)})
                self.assertEqual(command.kwargs['cwd'], system)
                self.assertEqual(command.kwargs['timeout'], 30)

    def test_private_unknown_and_missing_os_dlls_refuse_even_when_adjacent(self):
        for name in ['vcruntime140.dll', 'msvcp140.dll', 'unknown.dll', 'user32.dll']:
            self.exercise(name, failure='controller_dependency_')
        self.exercise('', failure='controller_imports_missing')

    def test_malformed_import_lines_cannot_hide_behind_a_valid_os_dependency(self):
        self.exercise('kernel32.dll\nbad path.dll', failure='controller_inspection_failed')
        for name in ['private.bin', 'helper.exe', 'user32']:
            self.exercise('kernel32.dll\n' + name, failure='controller_inspection_failed')

    def test_probe_timeouts_and_process_errors_refuse_qualification(self):
        for error in [subprocess.TimeoutExpired('probe', 30), OSError('loader unavailable')]:
            self.exercise(probe=error, failure='controller_inspection_or_launch_failed')

    def test_dll_and_malformed_images_refuse_before_inspection_or_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, inspector = root / 'controller.exe', root / 'dumpbin.exe'
            inspector.write_bytes(b'tool fixture')
            for image in [pe(), pe(False), b'not PE', pe(machine=0xaa64)]:
                binary.write_bytes(image)
                with patch('qualify_windows_controller.platform.system', return_value='Windows'), patch('qualify_windows_controller.subprocess.run') as run:
                    with self.assertRaises(BuildError):
                        qualify(binary, inspector)
                    run.assert_not_called()

    def test_loader_failure_wrong_receipt_and_unexpected_output_never_qualify(self):
        for probe in [subprocess.CompletedProcess([], 0, b'{}', b''), subprocess.CompletedProcess([], 1, b'{}', b''), subprocess.CompletedProcess([], 1, b'not json', b''), subprocess.CompletedProcess([], 1, b'x' * 4097, b''), subprocess.CompletedProcess([], 1, b'{}', b'loader error')]:
            self.exercise(probe=probe, failure='controller_entrypoint_failed')


class NsisGuiIdentityTests(unittest.TestCase):
    def test_expected_digest_changes_only_the_single_upstream_bundle_marker(self):
        original = b"PE-prefix __TAURI_BUNDLE_TYPE_VAR_UNK suffix"
        bundled = b"PE-prefix __TAURI_BUNDLE_TYPE_VAR_NSS suffix"
        self.assertEqual(nsis_gui_sha256(original), hashlib.sha256(bundled).hexdigest())
        self.assertNotEqual(nsis_gui_sha256(original), hashlib.sha256(original).hexdigest())
        self.assertEqual(original, b"PE-prefix __TAURI_BUNDLE_TYPE_VAR_UNK suffix")

    def test_absent_or_ambiguous_original_markers_are_refused(self):
        for image in [b"missing", b"__TAURI_BUNDLE_TYPE_VAR_NSS", b"__TAURI_BUNDLE_TYPE_VAR_UNK" * 2]:
            with self.assertRaisesRegex(BuildError, "desktop_bundle_marker_invalid"):
                nsis_gui_sha256(image)

    def test_unrelated_executable_changes_cannot_share_the_expected_digest(self):
        original = b"PE-prefix __TAURI_BUNDLE_TYPE_VAR_UNK suffix"
        self.assertNotEqual(nsis_gui_sha256(original), nsis_gui_sha256(original + b"tamper"))
