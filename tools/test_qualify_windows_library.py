import json
import tempfile
import unittest
from pathlib import Path

import qualify_windows_library as qualify


class WindowsLibraryArtifactTests(unittest.TestCase):
    def fixture(self, root):
        manifest = root / 'src-tauri/Cargo.toml'
        library = root / 'src-tauri/target/debug/deps/frameleaf_desktop-0123456789abcdef.exe'
        controller = root / 'src-tauri/target/debug/frameleaf-native-host.exe'
        for path in [library, controller]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'synthetic compiler artifact; never executed')
        records = [
            {'reason': 'compiler-artifact', 'manifest_path': str(manifest),
             'target': {'name': 'frameleaf_desktop', 'src_path': str(root / 'src-tauri/src/lib.rs')},
             'profile': {'test': True}, 'executable': str(library)},
            {'reason': 'compiler-artifact', 'manifest_path': str(manifest),
             'target': {'name': 'frameleaf-native-host', 'kind': ['bin']},
             'profile': {'test': False}, 'executable': str(controller)},
        ]
        receipt = root / 'cargo-test.jsonl'
        return receipt, records, library, controller

    def save(self, receipt, records):
        receipt.write_text('test output is not compiler JSON\n' + '\n'.join(json.dumps(r) for r in records) + '\n', encoding='utf-8-sig')

    def test_selects_only_current_library_test_and_normal_controller(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            receipt, records, library, controller = self.fixture(root)
            unrelated = {**records[0], 'target': {'name': 'frameleaf_desktop', 'src_path': str(root / 'src-tauri/src/main.rs')}}
            self.save(receipt, [unrelated, *records])
            self.assertEqual(qualify.select_artifacts(receipt, root), (library, controller))

    def test_missing_duplicate_foreign_or_external_artifacts_are_refused(self):
        for change in ['missing', 'duplicate', 'foreign-manifest', 'external-library', 'test-controller']:
            with tempfile.TemporaryDirectory() as temporary, self.subTest(change=change):
                root = Path(temporary).resolve()
                receipt, records, _, _ = self.fixture(root)
                if change == 'missing': records.pop()
                if change == 'duplicate': records.append(dict(records[0]))
                if change == 'foreign-manifest': records[0]['manifest_path'] = str(root / 'other/Cargo.toml')
                if change == 'external-library': records[0]['executable'] = str(root / 'outside.exe')
                if change == 'test-controller': records[1]['profile']['test'] = True
                self.save(receipt, records)
                with self.assertRaises(ValueError): qualify.select_artifacts(receipt, root)

    def test_qualification_requires_a_real_disposable_windows_environment(self):
        with self.assertRaises(ValueError):
            qualify.require_runner('Linux', 'x86_64', {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted'})
        with self.assertRaises(ValueError):
            qualify.require_runner('Windows', 'AMD64', {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted'})
        qualify.require_runner('Windows', 'AMD64', {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted'})
