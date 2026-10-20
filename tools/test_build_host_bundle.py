import json
import hashlib
import os
import platform
import shutil
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from build_host_bundle import REQUIRED_HOST_FILES, assemble, host_entries, host_manifest, backup_component
from build_host_backup import ROOT, CONTRACT, artifact
from build_runtime import inventory
from build_runtime import BuildError


class ExifToolEntryTests(unittest.TestCase):
    def test_metadata_entry_selects_the_platforms_vendored_runtime(self):
        for system, os_name, expected in [
            ("Windows", "nt", "server/node_modules/exiftool-vendored.exe/bin/exiftool.exe"),
            ("Darwin", "posix", "server/node_modules/exiftool-vendored.pl/bin/exiftool"),
            ("Linux", "posix", "server/node_modules/exiftool-vendored.pl/bin/exiftool"),
        ]:
            with (
                self.subTest(system=system),
                patch("build_host_bundle.platform.system", return_value=system),
                patch("build_host_bundle.os.name", os_name),
            ):
                self.assertEqual(host_entries()["exiftool"], expected)


class HostBundleTests(unittest.TestCase):
    def test_backup_component_is_bound_to_approved_binary_and_license(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = 'restic.exe' if os.name == 'nt' else 'restic'
            (root / binary).write_bytes(b'engine')
            shutil.copyfile(ROOT / 'runtime/host-backup-LICENSE.txt', root / 'LICENSE')
            pin = {**artifact(platform.system(), platform.machine()), 'binarySha256': hashlib.sha256(b'engine').hexdigest()}
            record = {'schemaVersion': 1, 'name': 'restic', 'version': CONTRACT['version'], 'source': CONTRACT['source'],
                      'artifact': pin, 'qualification': 'passed', 'runtimeQualified': False, 'redistributable': False,
                      'checks': {'encryptedRepository': True, 'wrongKeyRejected': True, 'readDataCheck': True, 'verifiedRestore': True},
                      'files': inventory(root)}
            (root / 'component.json').write_text(json.dumps(record))
            with patch('build_host_bundle.backup_artifact', return_value=pin):
                self.assertEqual(backup_component(root), record)
                for field, value in [('schemaVersion', True), ('version', '0.0.0'), ('qualification', 'failed'), ('runtimeQualified', True), ('redistributable', True), ('artifact', {})]:
                    changed = {**record, field: value}
                    (root / 'component.json').write_text(json.dumps(changed))
                    with self.subTest(field=field), self.assertRaises(BuildError):
                        backup_component(root)
                (root / 'component.json').write_text(json.dumps(record))
                (root / 'unexpected').write_bytes(b'not a backup component')
                with self.assertRaises(BuildError):
                    backup_component(root)
                (root / 'unexpected').unlink()
                (root / 'LICENSE').write_bytes(b'changed license')
                with self.assertRaises(BuildError):
                    backup_component(root)
                shutil.copyfile(ROOT / 'runtime/host-backup-LICENSE.txt', root / 'LICENSE')
                (root / binary).write_bytes(b'changed')
                record['files'][binary] = {'bytes': 7, 'sha256': hashlib.sha256(b'changed').hexdigest()}
                (root / 'component.json').write_text(json.dumps(record))
                with self.assertRaisesRegex(BuildError, 'host_backup_component_invalid'):
                    backup_component(root)

    def test_backup_engine_is_a_required_host_role(self):
        self.assertIn('backupEngine', host_entries())
        self.assertIn('backup/LICENSE', REQUIRED_HOST_FILES)
        self.assertIn('backup/component.json', REQUIRED_HOST_FILES)

    def test_database_extension_entry_matches_each_native_install_layout(self):
        for system, os_name, vector, node in [
            ("Windows", "nt", "pg/lib/vector.dll", "node.exe"),
            ("Darwin", "posix", "pg/lib/postgresql/vector.dylib", "node"),
            ("Linux", "posix", "pg/lib/postgresql/vector.so", "node"),
        ]:
            with (
                self.subTest(system=system),
                patch("build_host_bundle.platform.system", return_value=system),
                patch("build_host_bundle.os.name", os_name),
            ):
                entries = host_entries()
                self.assertEqual(entries["vector"], vector)
                self.assertEqual(entries["node"], node)

    def test_complete_roles_and_unlisted_fixture_agent_are_not_confused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = set(host_entries().values()) | set(REQUIRED_HOST_FILES)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture")
            manifest = host_manifest(root, "a" * 40, 2)
            self.assertEqual(manifest["protocolVersion"], 2)
            self.assertEqual(len(manifest["entryPoints"]), 27)
            self.assertEqual(set(manifest["files"]), names)
            self.assertFalse(manifest["certified"])
            for name in [
                "studio/runtime/admission-font.ttf",
                host_entries()["mlManifest"],
                host_entries()["manager"],
                host_entries()["managerWebIndex"],
                host_entries()["vector"],
                host_entries()["backupEngine"],
                "backup/LICENSE",
                "backup/component.json",
            ]:
                path = root / name
                path.unlink()
                with self.assertRaisesRegex(
                    BuildError, "host_bundle_component_missing"
                ):
                    host_manifest(root, "a" * 40, 2)
                path.write_bytes(b"fixture")
            (root / "host-agent.mjs").write_text("fixture gate enabled")
            with self.assertRaisesRegex(
                BuildError, "host_bundle_fixture_agent_forbidden"
            ):
                host_manifest(root, "a" * 40, 2)

    def test_refuses_invalid_source_or_epoch_before_inventory(self):
        for revision, epoch in [("bad", 2), ("a" * 40, 0), ("a" * 40, 1)]:
            with (
                self.subTest(revision=revision, epoch=epoch),
                self.assertRaises(BuildError),
            ):
                host_manifest(Path("/not-a-payload"), revision, epoch)

    def test_host_epoch_uses_its_own_compiled_release_floor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload"
            names = set(host_entries().values()) | set(REQUIRED_HOST_FILES)
            for name in names:
                path = payload / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture")
            policy_root = root / "policy"
            (policy_root / "runtime").mkdir(parents=True)
            policy_path = policy_root / "runtime/release-trust.json"
            policy = {"schemaVersion": 1, "minimumRuntimeEpoch": 99, "minimumHostEpoch": 2}
            policy_path.write_text(json.dumps(policy))
            shutil.copyfile(ROOT / "runtime/host-database.json", policy_root / "runtime/host-database.json")
            with patch("build_host_bundle.ROOT", policy_root):
                self.assertEqual(host_manifest(payload, "a" * 40, 2)["epoch"], 2)
                policy["minimumHostEpoch"] = 3
                policy_path.write_text(json.dumps(policy))
                with self.assertRaises(BuildError):
                    host_manifest(payload, "a" * 40, 2)
                for floor in [None, 0, True, "2"]:
                    policy["minimumHostEpoch"] = floor
                    policy_path.write_text(json.dumps(policy))
                    with self.assertRaises(BuildError):
                        host_manifest(payload, "a" * 40, 2)
                policy["minimumHostEpoch"] = 1
                policy_path.write_text(json.dumps(policy))
                with self.assertRaises(BuildError):
                    host_manifest(payload, "a" * 40, True)

    def test_malformed_manager_provenance_is_refused_before_creating_output(self):
        valid = {
            "schemaVersion": 1,
            "sourceRevision": "a" * 40,
            "nodeVersion": "26.11.1",
            "lockfileSha256": "b" * 64,
            "runtimeQualified": False,
            "redistributable": False,
        }
        for value in [
            [],
            {},
            {**valid, "sourceRevision": 4},
            {**valid, "runtimeQualified": True},
            {**valid, "redistributable": True},
        ]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                host, ml, manager, backup = [root / name for name in ["host", "ml", "manager", "backup"]]
                for path in [host, ml, manager, backup]:
                    path.mkdir()
                (manager / "component.json").write_text(json.dumps(value))
                with self.assertRaises(BuildError):
                    assemble(host, ml, manager, backup, root / "output", "a" * 40, 2)
                self.assertFalse((root / "output").exists())
