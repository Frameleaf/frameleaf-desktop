import hashlib
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from build_host_macos_pkg import installer_scripts, stage_package, validate_identities
from build_runtime import BuildError


class MacHostInstallerTests(unittest.TestCase):
    def test_version_identifiers_cannot_escape_fixed_destinations(self):
        validate_identities('a' * 64, 'b' * 64)
        for value in ['', '../escape', '/tmp', 'A' * 64]:
            with self.assertRaises(BuildError):
                validate_identities(value, 'b' * 64)

    def test_scripts_refuse_other_volumes_and_only_pass_fixed_version_ids(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / 'called'
            helper = root / 'frameleaf-native-host'
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
            self.assertEqual((base / 'Controllers' / digest / 'frameleaf-native-host').read_bytes(), helper.read_bytes())
            self.assertEqual(list((base / 'Profiles').iterdir()), [])
            self.assertEqual((out / 'scripts' / 'frameleaf-native-host').read_bytes(), helper.read_bytes())
            with self.assertRaises(BuildError):
                stage_package(candidate, helper, out, 'a' * 64, digest)
