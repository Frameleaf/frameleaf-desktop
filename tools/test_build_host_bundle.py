import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from build_host_bundle import REQUIRED_HOST_FILES, assemble, host_entries, host_manifest
from build_runtime import BuildError


class HostBundleTests(unittest.TestCase):
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
            self.assertEqual(len(manifest["entryPoints"]), 26)
            self.assertEqual(set(manifest["files"]), names)
            self.assertFalse(manifest["certified"])
            for name in [
                "studio/runtime/admission-font.ttf",
                host_entries()["mlManifest"],
                host_entries()["manager"],
                host_entries()["managerWebIndex"],
                host_entries()["vector"],
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
                host, ml, manager = [root / name for name in ["host", "ml", "manager"]]
                for path in [host, ml, manager]:
                    path.mkdir()
                (manager / "component.json").write_text(json.dumps(value))
                with self.assertRaises(BuildError):
                    assemble(host, ml, manager, root / "output", "a" * 40, 2)
                self.assertFalse((root / "output").exists())
