import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import build_coreml_observer as builder

GOOD = f"""cmd LC_ID_DYLIB
name {builder.IDENTITY} (offset 24)
cmd LC_LOAD_DYLIB
name /System/Library/Frameworks/Metal.framework/Versions/A/Metal (offset 24)
cmd LC_LOAD_DYLIB
name /usr/lib/libSystem.B.dylib (offset 24)
"""


class CoreMLObserverBuilderTests(unittest.TestCase):
    def test_component_contains_the_exact_private_loader_and_its_hash(self):
        def compiler(args, **kwargs):
            if "-dynamiclib" in args:
                Path(args[args.index("-o") + 1]).write_bytes(b"compiled fixture")
            output = (
                "Apple clang fixture"
                if "--version" in args
                else "27.0"
                if "--show-sdk-version" in args
                else "arm64"
                if "lipo" in args
                else GOOD
                if "otool" in args
                else ""
            )
            return SimpleNamespace(stdout=output)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "component"
            with (
                patch.object(builder.platform, "system", return_value="Darwin"),
                patch.object(builder.platform, "machine", return_value="arm64"),
                patch.object(builder.subprocess, "run", side_effect=compiler),
            ):
                builder.build(output)
            loader = output / "metal_observer.py"
            self.assertTrue(loader.is_file(), "private runtime loader was omitted")
            self.assertEqual(
                loader.read_bytes(),
                (
                    Path(__file__).resolve().parent.parent / "runtime/metal_observer.py"
                ).read_bytes(),
            )
            import json

            provenance = json.loads((output / "provenance.json").read_text())
            self.assertEqual(provenance["loaderSha256"], builder.sha256(loader))
            adapter = output / "metal_inference.py"
            self.assertTrue(adapter.is_file(), "owned inference adapter was omitted")
            self.assertEqual(
                adapter.read_bytes(),
                (
                    Path(__file__).resolve().parent.parent
                    / "runtime/metal_inference.py"
                ).read_bytes(),
            )
            self.assertEqual(provenance["adapterSha256"], builder.sha256(adapter))
            self.assertTrue((output / "__init__.py").is_file())
            entry = output / "entry.py"
            self.assertTrue(entry.is_file(), "fixed private entrypoint was omitted")
            self.assertEqual(
                entry.read_bytes(),
                (
                    Path(__file__).resolve().parent.parent / "runtime/metal_entry.py"
                ).read_bytes(),
            )
            self.assertEqual(provenance["entrySha256"], builder.sha256(entry))

    def test_failed_compilation_never_publishes_a_partial_component(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "component"
            with (
                patch.object(builder.platform, "system", return_value="Darwin"),
                patch.object(builder.platform, "machine", return_value="arm64"),
                patch.object(
                    builder.subprocess,
                    "run",
                    side_effect=subprocess.CalledProcessError(1, ["clang"]),
                ),
                self.assertRaisesRegex(builder.BuildError, "build_command_failed"),
            ):
                builder.build(output)
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_only_apple_dependencies_and_exact_relocatable_identity_are_allowed(self):
        self.assertEqual(len(builder.verified_linkage(GOOD)), 2)
        for text in [
            GOOD.replace(builder.IDENTITY, "/tmp/private-build/observer.dylib"),
            GOOD.replace("/usr/lib/libSystem.B.dylib", "/tmp/unapproved.dylib"),
            GOOD + "cmd LC_RPATH\npath /tmp/inherited (offset 12)\n",
            GOOD + "cmd LC_DYLD_ENVIRONMENT\n",
            f"cmd LC_ID_DYLIB\nname {builder.IDENTITY} (offset 24)\n",
        ]:
            with self.assertRaises(builder.BuildError):
                builder.verified_linkage(text)

    def test_unsupported_build_hosts_cannot_create_an_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "component"
            for system, machine in [
                ("Windows", "arm64"),
                ("Linux", "arm64"),
                ("Darwin", "x86_64"),
            ]:
                with (
                    patch.object(builder.platform, "system", return_value=system),
                    patch.object(builder.platform, "machine", return_value=machine),
                ):
                    with self.assertRaisesRegex(
                        builder.BuildError, "target_unsupported"
                    ):
                        builder.build(output)
                    self.assertFalse(output.exists())

    def test_existing_outputs_are_preserved_before_running_a_compiler(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "component"
            output.mkdir()
            (output / "keep").write_bytes(b"owned")
            with (
                patch.object(builder.platform, "system", return_value="Darwin"),
                patch.object(builder.platform, "machine", return_value="arm64"),
                patch.object(builder.subprocess, "run") as command,
            ):
                with self.assertRaisesRegex(builder.BuildError, "output_must_be_new"):
                    builder.build(output)
                command.assert_not_called()
            self.assertEqual((output / "keep").read_bytes(), b"owned")


if __name__ == "__main__":
    unittest.main()
