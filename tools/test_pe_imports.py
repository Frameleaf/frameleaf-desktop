import os
import sys
import tempfile
import unittest
from pathlib import Path

from pe_imports import PortableExecutable, unsatisfied


class PortableExecutableTests(unittest.TestCase):
    def test_a_file_that_is_not_a_windows_library_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "library.dll"
            path.write_bytes(b"\x7fELF" + bytes(128))
            with self.assertRaises(ValueError):
                PortableExecutable(path)

    @unittest.skipUnless(os.name == "nt", "reads real Windows libraries")
    def test_imports_are_judged_against_the_exports_of_what_is_found(self):
        system = Path(os.environ["SystemRoot"]) / "System32"
        kernel = PortableExecutable(system / "kernel32.dll")
        self.assertIn("LoadLibraryW", kernel.exports())
        # The interpreter's own library: everything it imports is in its folder or the system's.
        home = Path(sys.base_prefix)
        library = next(home.glob("python3*.dll"))
        imports = PortableExecutable(library).imports()
        self.assertTrue(any(name.lower() == "kernel32.dll" for name in imports))
        self.assertEqual(unsatisfied(library, [home, system]), {})
        # With nowhere to look, each imported library is reported absent by name.
        with tempfile.TemporaryDirectory() as empty:
            missing = unsatisfied(library, [Path(empty)])
        self.assertTrue(missing and all(value is None for value in missing.values()))
        # A library that is found but lacks an imported function is reported with the function.
        with tempfile.TemporaryDirectory() as temporary:
            stand_in = Path(temporary) / next(name for name in imports if name.lower() == "kernel32.dll")
            stand_in.write_bytes((system / "version.dll").read_bytes())
            lacking = unsatisfied(library, [Path(temporary), system])
        self.assertTrue(lacking[stand_in.name])


if __name__ == "__main__":
    unittest.main()
