import stat
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import zipfile

from sign_macos_host_runtime import browser_archive


class MacHostBrowserArchiveTests(unittest.TestCase):
    def test_internal_framework_alias_is_preserved(self):
        with TemporaryDirectory() as work:
            archive = Path(work) / "Chromium.zip"
            alias = zipfile.ZipInfo("Chromium.app/Framework/Versions/Current")
            alias.create_system = 3
            alias.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(alias, "1.2")
                bundle.writestr("Chromium.app/Framework/Versions/1.2/Chromium", "fixture")
            browser_archive(archive)

    def test_links_cannot_escape_or_be_used_as_archive_parents(self):
        for target, child in [("../../../escape", False), ("/etc", False), ("1.2", True)]:
            with self.subTest(target=target, child=child), TemporaryDirectory() as work:
                archive = Path(work) / "Chromium.zip"
                alias = zipfile.ZipInfo("Chromium.app/Framework/Versions/Current")
                alias.create_system = 3
                alias.external_attr = (stat.S_IFLNK | 0o777) << 16
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.writestr(alias, target)
                    if child:
                        bundle.writestr(alias.filename + "/Chrome", "fixture")
                with self.assertRaises(ValueError):
                    browser_archive(archive)
