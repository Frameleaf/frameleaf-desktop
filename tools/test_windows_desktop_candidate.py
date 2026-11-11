import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from build_runtime import BuildError
import test_obtain_host_component as components
import windows_desktop_candidate as desktop
from windows_desktop_candidate import extract_desktop


class WindowsDesktopCandidateTests(unittest.TestCase):
    def package(self, root, *, source="a" * 40, qualified=True, tamper=False, extra=None,
                version="0.1.5", runtime_run="42717141687", signed=False):
        exe = f"Frameleaf_{version}_x64-setup.exe"
        msi = f"Frameleaf_{version}_x64_en-US.msi"
        hashes = {exe: hashlib.sha256(b"MZ-synthetic-exe").hexdigest(), msi: hashlib.sha256(b"synthetic-msi").hexdigest()}
        receipt = {"sourceRevision": source, "runtimeRunId": runtime_run, "target": "windows-x86_64",
                   "installedQualified": qualified, "osSigned": signed, "files": hashes}
        files = {exe: b"modified" if tamper else b"MZ-synthetic-exe", msi: b"synthetic-msi",
                 "candidate.json": json.dumps(receipt).encode(),
                 "SHA256SUMS": "".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items())).encode()}
        archive = root / "candidate.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for name, data in files.items():
                info = tarfile.TarInfo("installers/" + name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            if extra:
                info = tarfile.TarInfo(extra)
                info.size = 1
                tar.addfile(info, io.BytesIO(b"x"))
        return archive, hashes[exe]

    def test_exact_installed_candidate_is_staged_before_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, digest = self.package(root)
            receipt = extract_desktop(archive, root / "setup.exe", "a" * 40, digest)
            self.assertEqual((root / "setup.exe").read_bytes(), b"MZ-synthetic-exe")
            self.assertEqual(receipt["sourceRevision"], "a" * 40)

    def test_acquisition_records_the_separate_tool_and_desktop_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "windows-compiled-host").mkdir()
            tar, digest = self.package(root, source="b" * 40)
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as package:
                package.writestr("installer-candidates.tar.gz", tar.read_bytes())
            data = stream.getvalue()
            _, pin, artifact, run = components.ComponentAcquisitionTests().fixture()
            pin["workflow"] = run["path"] = ".github/workflows/installer-candidates.yml"
            pin["archiveSha256"] = hashlib.sha256(data).hexdigest()
            artifact.update(name="frameleaf-installer-candidates-windows-x86_64", size_in_bytes=len(data), digest="sha256:" + pin["archiveSha256"])
            env = {"RUNNER_TEMP": temp, "GITHUB_SHA": "c" * 40, "DESKTOP_SHA256": digest,
                   "DESKTOP_APPROVAL": json.dumps({**pin, "sourceRevision": "b" * 40})}
            with patch.dict(os.environ, env), patch.object(desktop, "api", side_effect=[artifact, run]), \
                    patch.object(desktop, "download", side_effect=lambda approved, path, size: path.write_bytes(data)), \
                    patch.object(desktop.subprocess, "run") as git:
                desktop.obtain()
                git.assert_called_once_with(["git", "merge-base", "--is-ancestor", "b" * 40, "c" * 40], check=True)
            receipt = json.loads((root / "windows-compiled-host/desktop-producer.json").read_text())
            self.assertEqual(receipt["approval"]["headSha"], "a" * 40)
            self.assertEqual(receipt["candidate"]["sourceRevision"], "b" * 40)
            self.assertEqual((root / "windows-compiled-host/desktop/setup.exe").read_bytes(), b"MZ-synthetic-exe")
            self.assertFalse((root / "windows-compiled-host/desktop/artifact.zip").exists())

    def test_signed_main_candidate_matches_source_version_and_reviewed_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "windows-compiled-host").mkdir()
            tar, digest = self.package(root, version="0.1.6", runtime_run="42870045811",
                                       signed=True, qualified=False)
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as package:
                package.writestr("installer-candidates.tar.gz", tar.read_bytes())
            data = stream.getvalue()
            _, pin, artifact, run = components.ComponentAcquisitionTests().fixture()
            pin["workflow"] = run["path"] = ".github/workflows/installer-candidates.yml"
            pin["archiveSha256"] = hashlib.sha256(data).hexdigest()
            run.update(head_branch="main", event="workflow_dispatch")
            artifact.update(name="frameleaf-installer-candidates-windows-x86_64",
                            size_in_bytes=len(data), digest="sha256:" + pin["archiveSha256"])
            env = {"RUNNER_TEMP": temp, "GITHUB_SHA": "c" * 40, "DESKTOP_SHA256": digest,
                   "DESKTOP_APPROVAL": json.dumps({**pin, "sourceRevision": "a" * 40,
                                                   "runtimeRunId": "42870045811"})}
            with patch.dict(os.environ, env), patch.object(desktop, "api", side_effect=[artifact, run]), \
                    patch.object(desktop, "download", side_effect=lambda approved, path, size: path.write_bytes(data)), \
                    patch.object(desktop.subprocess, "run"), \
                    patch.object(desktop.subprocess, "check_output", return_value=b'{"version":"0.1.6"}'):
                desktop.obtain()
            result = json.loads((root / "windows-compiled-host/desktop-producer.json").read_text())
            self.assertEqual(result["approval"]["runtimeRunId"], "42870045811")
            self.assertEqual(result["candidate"]["osSigned"], True)
            for expected in [{"runtime_run": "1"}, {"version": "0.1.7"}, {"signed": False}]:
                options = {"version": "0.1.6", "runtime_run": "42870045811", "signed": True, **expected}
                with self.subTest(expected=expected), self.assertRaises(BuildError):
                    extract_desktop(tar, root / "wrong.exe", "a" * 40, digest, **options)

    def test_unmerged_desktop_source_is_refused_before_any_download(self):
        _, pin, _, _ = components.ComponentAcquisitionTests().fixture()
        pin["workflow"] = ".github/workflows/installer-candidates.yml"
        env = {"GITHUB_SHA": "c" * 40, "DESKTOP_APPROVAL": json.dumps({**pin, "sourceRevision": "b" * 40})}
        with patch.dict(os.environ, env), patch.object(desktop.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "git")), \
                patch.object(desktop, "api") as api:
            with self.assertRaises(subprocess.CalledProcessError):
                desktop.obtain()
            api.assert_not_called()

    def test_wrong_source_unqualified_modified_or_escaping_archives_are_refused(self):
        cases = [{"source": "b" * 40}, {"qualified": False}, {"tamper": True},
                 {"extra": "../outside.exe"}, {"extra": "installers/candidate.json"}]
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive, digest = self.package(root, **case)
                with self.assertRaises(BuildError):
                    extract_desktop(archive, root / "setup.exe", "a" * 40, digest)
                self.assertFalse((root / "outside.exe").exists())


if __name__ == "__main__":
    unittest.main()
