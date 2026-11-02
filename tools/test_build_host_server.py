import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import build_host_server
from build_host_server import build, stage_server
from build_runtime import BuildError, build_environment, inventory as runtime_inventory, run as checked_run


class HostServerTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "requires Git")
    def test_source_archive_preserves_canonical_bytes_with_windows_git_settings(self):
        git = shutil.which("git")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture_env = build_environment(root, os.environ)
            source = root / "source"
            source.mkdir()
            canonical = b'{"canonical":true}\n'
            fixtures = {
                "package.json": b'{"packageManager":"pnpm@12.11.2"}\n',
                "pnpm-lock.yaml": b"fixture\n", "pnpm-workspace.yaml": b"fixture\n",
                ".pnpmfile.cjs": b"fixture\n", "LICENSE": b"fixture\n",
                "packages/sdk/fixture": b"fixture", "packages/plugin-sdk/fixture": b"fixture",
                "packages/sql-tools/fixture": b"fixture", "packages/patches/fixture": b"fixture",
                "packages/locked-crypto/dist/index.js": b"export const fixture = true;\n",
                "server/src/schema/catalog/fixture.json": canonical,
                "studio/runtime/fixture": b"fixture", "studio/tools/fixture": b"fixture",
                "docker/scripts/verify-server-package.mjs": b"fixture",
            }
            for name, data in fixtures.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            for arguments in [
                ["init", "-q"], ["add", "."],
                ["-c", "user.name=Frameleaf fixture", "-c", "user.email=fixture@invalid",
                 "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + str(root / "no-hooks"),
                 "commit", "-q", "-m", "fixture"],
                ["config", "core.autocrlf", "true"], ["config", "core.eol", "crlf"],
            ]:
                subprocess.run([git, *arguments], cwd=source, env=fixture_env, check=True, capture_output=True)
            revision = subprocess.check_output([git, "rev-parse", "HEAD"], cwd=source, env=fixture_env, text=True).strip()
            node = root / "node"
            node.write_bytes(b"fixture")
            output = root / "output"

            def command(arguments, *, cwd, env):
                if arguments[0] == node:
                    return "v26.11.1"
                if "archive" in arguments:
                    return checked_run(arguments, cwd=cwd, env=env)
                self.assertEqual(
                    (output / "work/source/server/src/schema/catalog/fixture.json").read_bytes(), canonical
                )
                self.assertEqual(
                    (output / "work/source/packages/locked-crypto/dist/index.js").read_bytes(),
                    fixtures["packages/locked-crypto/dist/index.js"],
                )
                raise BuildError("canonical_archive_checked_before_build")

            with (
                patch("build_host_server.shutil.which", side_effect=lambda name: git if name == "git" else str(root / "pnpm")),
                patch("build_host_server.run", side_effect=command),
                self.assertRaisesRegex(BuildError, "canonical_archive_checked_before_build"),
            ):
                build(source, revision, node, output)

    def test_windows_build_uses_git_bash_only_for_source_scripts(self):
        for system, has_bash in [("Windows", True), ("Windows", False), ("Linux", False), ("Darwin", False)]:
            with self.subTest(system=system, has_bash=has_bash), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                source = root / "source"
                source.mkdir()
                (source / "pnpm-lock.yaml").write_text("fixture")
                node = root / "node"
                node.write_bytes(b"fixture")
                git = root / "Git with spaces/cmd/git.exe"
                bash = git.parent.parent / "bin/bash.exe"
                if has_bash:
                    bash.parent.mkdir(parents=True)
                    bash.touch()
                commands = []

                def command(arguments, *, cwd, env):
                    if arguments[0] == node:
                        return "v26.11.1"
                    if "archive" in arguments:
                        with tarfile.open(arguments[arguments.index("--output") + 1], "w") as contents:
                            contents.add(source, arcname=".")
                    elif "--version" in arguments:
                        return "12.11.2"
                    else:
                        commands.append(arguments)
                        self.assertEqual(env["NODE_OPTIONS"], "--max-old-space-size=3072")
                        if "build" in arguments:
                            options = [arg for arg in arguments if str(arg).startswith("--config.script-shell=")]
                            self.assertEqual(options, ["--config.script-shell=" + str(bash)] if system == "Windows" else [])
                            raise BuildError("source_build_checked")
                        self.assertFalse(any(str(arg).startswith("--config.script-shell=") for arg in arguments))
                    return ""

                expected = "host_server_script_shell_missing" if system == "Windows" and not has_bash else "source_build_checked"
                with (
                    patch("build_host_server.platform.system", return_value=system),
                    patch("build_host_server.shutil.which", side_effect=lambda name: str(git if name == "git" else root / "pnpm")),
                    patch("build_host_server.git_blob", return_value='{"packageManager":"pnpm@12.11.2"}'),
                    patch("build_host_server.verify_source_archive"),
                    patch("build_host_server.run", side_effect=command),
                    self.assertRaisesRegex(BuildError, expected),
                ):
                    build(source, "a" * 40, node, root / "output")
                if expected == "host_server_script_shell_missing":
                    self.assertEqual(commands, [])

    def test_source_archive_fixture_ignores_inherited_git_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            decoy = Path(temporary).resolve()
            sentinel = decoy / "sentinel"
            sentinel.write_bytes(b"unrelated repository")
            with patch.dict(os.environ, {"GIT_DIR": str(decoy / ".git"), "GIT_WORK_TREE": str(decoy)}):
                self.test_source_archive_preserves_canonical_bytes_with_windows_git_settings()
            self.assertFalse((decoy / ".git").exists())
            self.assertEqual(sentinel.read_bytes(), b"unrelated repository")

    def test_runtime_metadata_keeps_versions_without_build_machine_paths(self):
        for origin, version in [("file:///developer/private-build", "0.0.0"), ("file:///C:/Users/builder/private-build", "1.2.3-beta.1"), ("file:///developer/private-build", "1.2.3-alpha-beta.1+build.001")]:
            with self.subTest(origin=origin, version=version), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                dependencies = {}
                for name in ["@frameleaf/plugin-sdk", "@frameleaf/sql-tools", "@frameleaf/locked-crypto"]:
                    package = root / "node_modules" / name / "package.json"
                    package.parent.mkdir(parents=True)
                    package.write_text(json.dumps({"name": name, "version": version}))
                    dependencies[name] = name + "@" + origin + "/" + name
                original = {"name": "frameleaf", "type": "module", "exports": {".": "./dist/main.js"}, "dependencies": dependencies}
                (root / "package.json").write_text(json.dumps(original))
                for name in ["pnpm-lock.yaml", "pnpm-workspace.yaml", "dist/tsconfig.build.tsbuildinfo"]:
                    path = root / name
                    path.parent.mkdir(exist_ok=True)
                    path.write_text("private build-only state")
                (root / "dist/main.js").write_text("export const value = 42;")
                retained = root / "node_modules/@frameleaf/plugin-sdk/pnpm-lock.yaml"
                retained.write_text("dependency source provenance")
                build_host_server.clean_runtime_metadata(root)
                actual = json.loads((root / "package.json").read_text())
                self.assertEqual(actual, {**original, "dependencies": {name: version for name in dependencies}})
                for name in ["pnpm-lock.yaml", "pnpm-workspace.yaml", "dist/tsconfig.build.tsbuildinfo"]:
                    self.assertFalse((root / name).exists())
                self.assertEqual((root / "dist/main.js").read_text(), "export const value = 42;")
                self.assertEqual(retained.read_text(), "dependency source provenance")

    @patch("build_host_server.inventory")
    def test_build_receipt_describes_cleaned_runtime(self, inventory):
        def cleaned_inventory(path):
            for name in ["pnpm-lock.yaml", "pnpm-workspace.yaml", "dist/tsconfig.build.tsbuildinfo"]:
                self.assertFalse((path / name).exists(), "metadata cleanup must precede the first inventory")
            return runtime_inventory(path)
        inventory.side_effect = cleaned_inventory
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            node = root / "node"
            node.write_text("fixture node")
            deployed = root / "deployment-fixture"
            deployed.mkdir()
            dependencies = {}
            for name in ["@frameleaf/plugin-sdk", "@frameleaf/sql-tools", "@frameleaf/locked-crypto"]:
                package = deployed / "node_modules" / name / "package.json"
                package.parent.mkdir(parents=True)
                package.write_text(json.dumps({"name": name, "version": "1.2.3"}))
                dependencies[name] = "file:///private/build/" + name
            (deployed / "package.json").write_text(json.dumps({"dependencies": dependencies}))
            for name in ["pnpm-lock.yaml", "pnpm-workspace.yaml", "dist/tsconfig.build.tsbuildinfo", "dist/main.js", "resources/studio/subtitle-sidecar.mjs"]:
                path = deployed / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture")
            case_sensitive = not (deployed / "PNPM-LOCK.YAML").exists()
            if case_sensitive:
                (deployed / "PNPM-LOCK.YAML").write_text("retained case-distinct fixture")
            verifier = source / "docker/scripts/verify-server-package.mjs"
            verifier.parent.mkdir(parents=True)
            verifier.write_text("fixture verifier")
            (source / "pnpm-lock.yaml").write_text("fixture source lock")
            output = root / "output"

            def command(arguments, **kwargs):
                if arguments[0] == node:
                    return "v26.11.1"
                if "archive" in arguments:
                    archive = arguments[arguments.index("--output") + 1]
                    with tarfile.open(archive, "w") as contents:
                        contents.add(source, arcname=".")
                elif "--version" in arguments:
                    return "10.0.0"
                elif "deploy" in arguments:
                    shutil.copytree(deployed, arguments[-1])
                return ""

            bash = root / "Git/bin/bash.exe"
            bash.parent.mkdir(parents=True)
            bash.touch()
            with patch("build_host_server.shutil.which", side_effect=lambda name: str(root / "Git/cmd/git.exe") if name == "git" else "/trusted/" + name), patch("build_host_server.git_blob", return_value=json.dumps({"packageManager": "pnpm@10.0.0"})), patch("build_host_server.verify_source_archive"), patch("build_host_server.run", side_effect=command):
                build(source, "a" * 40, node, output)
            receipt = json.loads((output / "qualification.json").read_text())
            runtime = output / "server"
            self.assertEqual(receipt["qualification"], "passed")
            self.assertEqual(receipt["files"], build_host_server.inventory(runtime))
            if case_sensitive:
                self.assertEqual((runtime / "PNPM-LOCK.YAML").read_text(), "retained case-distinct fixture")
                self.assertIn("PNPM-LOCK.YAML", receipt["files"])
            metadata = json.loads((runtime / "package.json").read_text())
            self.assertEqual(metadata["dependencies"], {name: "1.2.3" for name in dependencies})
            for name in ["pnpm-lock.yaml", "pnpm-workspace.yaml", "dist/tsconfig.build.tsbuildinfo"]:
                self.assertFalse((runtime / name).exists())
                self.assertNotIn(name, receipt["files"])
            self.assertEqual((runtime / "dist/main.js").read_text(), "fixture")

    def test_runtime_metadata_refuses_wrong_or_unversioned_workspace_packages(self):
        for invalid in [None, {"name": "other", "version": "1.2.3"}, *[{"name": "@frameleaf/plugin-sdk", "version": value} for value in ["file:///private-build", "1.2.3-alpha..1", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01", "1.2.3+build..meta", "١.2.3"]]]:
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = {"dependencies": {"@frameleaf/plugin-sdk": "workspace:*", "@frameleaf/sql-tools": "workspace:*"}}
                (root / "package.json").write_text(json.dumps(original))
                for name in original["dependencies"]:
                    manifest = root / "node_modules" / name / "package.json"
                    manifest.parent.mkdir(parents=True)
                    manifest.write_text(json.dumps({"name": name, "version": "1.2.3"}))
                package = root / "node_modules/@frameleaf/plugin-sdk/package.json"
                package.write_text(json.dumps(invalid))
                with self.assertRaises(BuildError):
                    build_host_server.clean_runtime_metadata(root)
                self.assertEqual(json.loads((root / "package.json").read_text()), original)

    def test_compiler_has_bounded_heap_without_inheriting_node_injection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            node = root / "node"
            node.write_text("fixture")

            def inspect_environment(git, source, revision, name, env):
                self.assertEqual(env.get("NODE_OPTIONS"), "--max-old-space-size=3072")
                raise BuildError("fixture_environment_checked")

            with (
                patch("build_host_server.shutil.which", return_value="/fixture/tool"),
                patch("build_host_server.git_blob", side_effect=inspect_environment),
                patch.dict(os.environ, {"NODE_OPTIONS": "--require=/untrusted.js"}),
                self.assertRaisesRegex(BuildError, "fixture_environment_checked"),
            ):
                build(root, "a" * 40, node, root / "output")

    def test_staged_runtime_has_regular_dependencies_without_package_manager_links(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "dist").mkdir(parents=True)
            (source / "dist/main.js").write_text("export const value = 42;")
            package = source / "node_modules/example"
            package.mkdir(parents=True)
            (package / "index.js").write_text("module.exports = 42;")
            for name in [".bin", ".pnpm"]:
                folder = source / "node_modules" / name
                folder.mkdir()
                (folder / "unused").write_text("package-manager-only executable")
            (source / "node_modules/.modules.yaml").write_text(
                "storeDir: /developer/store"
            )
            destination = root / "runtime"
            files = stage_server(source, destination)
            self.assertEqual(
                (destination / "node_modules/example/index.js").read_text(),
                "module.exports = 42;",
            )
            self.assertIn("dist/main.js", files)
            self.assertFalse((destination / "node_modules/.bin").exists())
            self.assertFalse((destination / "node_modules/.pnpm").exists())
            self.assertFalse((destination / "node_modules/.modules.yaml").exists())
            with self.assertRaises(BuildError):
                stage_server(source, destination)
            with self.assertRaises(BuildError):
                stage_server(source, source / "nested-output")
            self.assertFalse((source / "nested-output").exists())

    @unittest.skipIf(
        os.name == "nt",
        "Unix link fixture; Windows reparse acceptance remains separate",
    )
    def test_runtime_links_cannot_read_external_files_or_follow_directory_cycles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "private"
            outside.write_text("must not be copied")
            for name, target in [("file", outside), ("directory", root)]:
                source = root / name
                source.mkdir()
                (source / "escape").symlink_to(
                    target, target_is_directory=target.is_dir()
                )
                destination = root / (name + "-output")
                with self.assertRaises(BuildError):
                    stage_server(source, destination)
                self.assertFalse(destination.exists())
