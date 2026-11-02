import json
import os
import tempfile
import subprocess
import sys
import tarfile
import textwrap
import unittest
import zipfile
from pathlib import Path

from build_host_manager import stage_manager
from build_runtime import BuildError
from build_runtime import inventory


class HostManagerTests(unittest.TestCase):
    def workflow_archive(self):
        workflow = Path(__file__).resolve().parents[1] / '.github/workflows/windows-host-manager.yml'
        self.assertTrue(workflow.is_file(), 'Windows Manager component workflow is missing')
        return textwrap.dedent(workflow.read_text().split(
            '      - name: Archive the qualified Manager component\n', 1
        )[1].split('        run: |\n', 1)[1].split('      - name:', 1)[0])

    def qualified_fixture(self, root):
        source = self.fixture(root)
        output = root / 'fl-windows-manager'
        output.mkdir()
        component = stage_manager(source, output / 'manager', 'a' * 40)
        receipt = component | {
            'sourceArchiveSha256': 'b' * 64,
            'nodeSha256': 'c' * 64,
            'npmVersion': '11.0.0',
            'qualification': 'passed',
            'files': inventory(output / 'manager'),
        }
        (output / 'qualification.json').write_text(json.dumps(receipt))
        return output, receipt

    def test_workflow_archive_transports_only_the_qualified_manager_and_receipt(self):
        """Archive the real staged layout; build state must not enter the downloaded component."""
        script = self.workflow_archive()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output, receipt = self.qualified_fixture(root)
            (output / 'work').mkdir()
            (output / 'work/private-state').write_text('not distributable')
            subprocess.run([sys.executable, '-c', script], check=True,
                           cwd=Path(__file__).resolve().parents[1], capture_output=True,
                           env=os.environ | {'RUNNER_TEMP': str(root), 'MANAGER_REVISION': 'a' * 40})
            archive = output / 'manager-component.tar.gz'
            with zipfile.ZipFile(root / 'artifact.zip', 'w') as upload:
                upload.write(archive, archive.name)
            with zipfile.ZipFile(root / 'artifact.zip') as download:
                download.extractall(root / 'download')
            with tarfile.open(root / 'download' / archive.name) as restored:
                self.assertTrue(all(member.name == 'qualification.json' or
                                    member.name == 'manager' or member.name.startswith('manager/')
                                    for member in restored.getmembers()))
                restored.extractall(root / 'restored', filter='data')
            self.assertEqual(inventory(root / 'restored/manager'), receipt['files'])
            self.assertEqual(json.loads((root / 'restored/qualification.json').read_text()), receipt)
            self.assertEqual((root / 'restored/manager/LICENSE').read_text(), 'fixture license')

    def test_workflow_archive_refuses_unqualified_mismatched_or_changed_payload(self):
        """Removing a source, result, toolchain or inventory guard must allow a failing case through."""
        script = self.workflow_archive()
        for damage in ['failed', 'source', 'node-version', 'runtime-claim', 'redistributable-claim',
                       'lockfile', 'node', 'archive', 'changed', 'extra', 'missing']:
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                output, receipt = self.qualified_fixture(root)
                if damage == 'failed': receipt['qualification'] = 'failed'
                elif damage in ['source', 'node-version', 'runtime-claim', 'redistributable-claim']:
                    key, value = {
                        'source': ('sourceRevision', 'd' * 40),
                        'node-version': ('nodeVersion', '0.0.0'),
                        'runtime-claim': ('runtimeQualified', True),
                        'redistributable-claim': ('redistributable', True),
                    }[damage]
                    component_file = output / 'manager/component.json'
                    component = json.loads(component_file.read_text())
                    component[key] = receipt[key] = value
                    component_file.write_text(json.dumps(component))
                    receipt['files'] = inventory(output / 'manager')
                elif damage == 'lockfile': receipt['lockfileSha256'] = 'd' * 64
                elif damage == 'node': receipt['nodeSha256'] = 'not a digest'
                elif damage == 'archive': receipt['sourceArchiveSha256'] = 'not a digest'
                elif damage == 'changed': (output / 'manager/app/build/main.js').write_text('changed')
                elif damage == 'extra': (output / 'manager/unqualified').write_text('extra')
                elif damage == 'missing': (output / 'manager/LICENSE').unlink()
                (output / 'qualification.json').write_text(json.dumps(receipt))
                result = subprocess.run([sys.executable, '-c', script],
                                        cwd=Path(__file__).resolve().parents[1], capture_output=True,
                                        env=os.environ | {'RUNNER_TEMP': str(root), 'MANAGER_REVISION': 'a' * 40})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((output / 'manager-component.tar.gz').exists())

    def fixture(self, root):
        source = root / "source"
        (source / "build").mkdir(parents=True)
        (source / "build/main.js").write_text("export const fixture = true;")
        (source / "ui/dist").mkdir(parents=True)
        (source / "ui/dist/index.html").write_text("<main>Manager</main>")
        (source / "src").mkdir()
        (source / "src/private.ts").write_text("not runtime code")
        (source / "test").mkdir()
        (source / "test/private.ts").write_text("not runtime code")
        (source / "LICENSE").write_text("fixture license")
        (source / "release-worker.cjs").write_text("module.exports = {};")
        (source / "media-copy.cjs").write_text("module.exports = {};")
        (root / ".github").mkdir()
        for name in ["frameleaf-release.cjs", "verify-release-bundle.cjs"]:
            (root / ".github" / name).write_text("module.exports = {};")
        (root / "cosign.pub").write_text("fixture public key")
        (source / "package.json").write_text(
            json.dumps(
                {
                    "name": "@frameleaf/manager",
                    "type": "module",
                    "dependencies": {"example": "1.0.0"},
                    "devDependencies": {"compiler": "1.0.0"},
                }
            )
        )
        (source / "package-lock.json").write_text("{}")
        dependency = source / "node_modules/example"
        dependency.mkdir(parents=True)
        (dependency / "package.json").write_text('{"name":"example","version":"1.0.0"}')
        (dependency / "index.js").write_text("export const value = true;")
        return source

    def test_stages_only_production_manager_with_bound_source_and_licenses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = self.fixture(root)
            output = root / "runtime"
            receipt = stage_manager(source, output, "a" * 40)
            self.assertEqual(receipt["sourceRevision"], "a" * 40)
            self.assertEqual(receipt["nodeVersion"], "26.11.1")
            self.assertFalse(receipt["runtimeQualified"])
            self.assertEqual(
                json.loads((output / "component.json").read_text()), receipt
            )
            for name in [
                "app/build/main.js",
                "app/ui/dist/index.html",
                "node_modules/example/index.js",
                "LICENSE",
                ".github/frameleaf-release.cjs",
                ".github/verify-release-bundle.cjs",
                "app/release-worker.cjs",
                "app/media-copy.cjs",
                "cosign.pub",
            ]:
                self.assertTrue((output / name).is_file(), name)
            for name in ["src", "test", "package-lock.json"]:
                self.assertFalse((output / name).exists(), name)
            with self.assertRaises(BuildError):
                stage_manager(source, output, "a" * 40)
            with self.assertRaises(BuildError):
                stage_manager(source, source / "nested", "a" * 40)

    def test_missing_ui_dependency_or_backend_cannot_be_packaged(self):
        for missing in [
            "build/main.js",
            "ui/dist/index.html",
            "node_modules/example/package.json",
            "LICENSE",
            "release-worker.cjs",
            "media-copy.cjs",
        ]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                source = self.fixture(root)
                (source / missing).unlink()
                with self.assertRaises((BuildError, FileNotFoundError)):
                    stage_manager(source, root / "runtime", "a" * 40)

    @unittest.skipIf(
        os.name == "nt",
        "Unix link fixture; Windows reparse qualification remains separate",
    )
    def test_cannot_copy_symlinks_or_private_source_as_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = self.fixture(root)
            outside = root / "outside"
            outside.write_text("private input")
            (source / "build/escape").symlink_to(outside)
            with self.assertRaises(BuildError):
                stage_manager(source, root / "runtime", "a" * 40)

    def test_invalid_revision_or_package_identity_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = self.fixture(root)
            with self.assertRaises(BuildError):
                stage_manager(source, root / "runtime", "bad")
            (source / "package.json").write_text(
                '{"name":"other","type":"module","dependencies":{}}'
            )
            with self.assertRaises(BuildError):
                stage_manager(source, root / "runtime", "a" * 40)
