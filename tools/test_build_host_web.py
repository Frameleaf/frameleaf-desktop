import tempfile
import unittest
from pathlib import Path

from build_host_web import stage_web
from build_runtime import BuildError


class WebPackageTests(unittest.TestCase):
    def test_studio_entries_must_travel_with_the_photo_ui(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "build"
            source.mkdir()
            (source / "index.html").write_text("<html>photos</html>")
            with self.assertRaises(BuildError):
                stage_web(source, root / "incomplete")
            (source / "studio-engine").mkdir()
            for name in ["editor.html", "commands.html"]:
                (source / "studio-engine" / name).write_text("<html>studio</html>")
            files = stage_web(source, root / "complete")
            self.assertIn("index.html", files)
            self.assertIn("studio-engine/editor.html", files)
            self.assertIn("studio-engine/commands.html", files)
            self.assertEqual(
                (root / "complete/index.html").read_text(), "<html>photos</html>"
            )

class PinnedStudioNodeTests(unittest.TestCase):
    def check_node_gate(self, module, pinned, actual, accepted):
        import json
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'source'; source.mkdir()
            node = root / 'node'; node.write_text('fixture executable; mocked')
            def blob(_git, _source, _revision, name, _env):
                return json.dumps({'node': pinned, 'npm': '12.2.0'} if name == 'studio/engine-build.json' else {'packageManager': 'pnpm@12.11.2'}).encode()
            def run(arguments, **_options):
                if [str(x) for x in arguments] == [str(node), '--version']:
                    return actual
                if 'archive' in arguments:
                    raise BuildError('source_pin_accepted')
                raise AssertionError(arguments)
            with (
                patch.object(module.shutil, 'which', return_value='/fixture/tool'),
                patch.object(module, 'git_blob', side_effect=blob, create=True),
                patch.object(module, 'run', side_effect=run),
                self.assertRaisesRegex(BuildError, 'source_pin_accepted' if accepted else 'unapproved'),
            ):
                module.build(source, 'a' * 40, node, root / 'output')

    def test_each_builder_accepts_the_exact_selected_source_node_pin(self):
        import build_host_web, build_host_studio
        for module in [build_host_web, build_host_studio]:
            for version in ['22.23.4', '26.11.1']:
                with self.subTest(builder=module.__name__, node=version):
                    self.check_node_gate(module, version, 'v' + version, True)

    def test_each_builder_rejects_mismatched_or_malformed_source_node_pins(self):
        import build_host_web, build_host_studio
        for module in [build_host_web, build_host_studio]:
            for version in ['22.23.4', '26.11', '', None, 26, ['26.11.1']]:
                with self.subTest(builder=module.__name__, pin=version):
                    self.check_node_gate(module, version, 'v26.11.1', False)
