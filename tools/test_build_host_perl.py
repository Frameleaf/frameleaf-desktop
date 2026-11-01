import tempfile
import unittest
from pathlib import Path

from build_host_perl import perl_contract, validate_probe
from build_runtime import BuildError


class PrivatePerlTests(unittest.TestCase):
    def test_source_contract_requires_the_versioned_official_archive_and_digest(self):
        pin = {
            "schemaVersion": 1,
            "version": "5.44.0",
            "url": "https://www.cpan.org/src/5.0/perl-5.44.0.tar.xz",
            "sha256": "a" * 64,
        }
        self.assertEqual(perl_contract(pin), pin)
        for change in [
            {"url": "http://www.cpan.org/src/5.0/perl-5.44.0.tar.xz"},
            {"version": "5.42.0"},
            {"sha256": "bad"},
            {"url": pin["url"] + "?token=x"},
        ]:
            with self.assertRaises(BuildError):
                perl_contract({**pin, **change})

    def test_runtime_probe_refuses_external_module_and_search_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private"
            root.mkdir()
            required = [
                "IO/Handle.pm",
                "Cwd.pm",
                "JSON/PP.pm",
                "Compress/Raw/Zlib.pm",
                "Time/HiRes.pm",
            ]
            modules = {}
            for name in required:
                path = root / "lib" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture")
                modules[name] = str(path)
            record = {
                "version": "5.44.0",
                "inc": [str(root / "lib")],
                "modules": modules,
                "libraries": [],
            }
            validate_probe(root, "5.44.0", record)
            outside = Path(temporary) / "outside.pm"
            outside.write_text("external")
            for change in [
                {"inc": [str(outside.parent)]},
                {"modules": {**modules, "Cwd.pm": str(outside)}},
                {"version": "5.34.1"},
                {"modules": {}},
            ]:
                with self.assertRaises(BuildError):
                    validate_probe(root, "5.44.0", {**record, **change})
