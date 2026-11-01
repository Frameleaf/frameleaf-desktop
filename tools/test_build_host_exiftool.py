import json
import platform
import tempfile
import unittest
from pathlib import Path

from build_host_exiftool import adapt_exiftool, build
from build_runtime import BuildError


class PrivateExifToolTests(unittest.TestCase):
    source = """const PERL = "/usr/bin/perl";
const result = await (0, Which_1.which)(PERL);
const ignoreShebang = o.ignoreShebang ?? _ignoreShebang();
throw new Error("Perl must be installed. Please add perl to your $PATH and try again.");"""

    def test_private_interpreter_has_no_system_lookup_fallback(self):
        result = adapt_exiftool(self.source, "39.0.1")
        self.assertIn('"../../../../perl/bin/perl"', result)
        self.assertIn("_fs.existsSync(PERL) ? PERL : undefined", result)
        self.assertIn("const ignoreShebang = !(0, IsWin32_1.isWin32)();", result)
        self.assertNotIn("Which_1.which)(PERL)", result)
        self.assertNotIn("/usr/bin/perl", result)

    def test_unknown_or_already_adapted_vendor_source_is_rejected(self):
        for source, version in [
            (self.source, "40.0.0"),
            (self.source.replace("/usr/bin/perl", "/bin/perl"), "39.0.1"),
            (self.source + '\nconst PERL = "/usr/bin/perl";', "39.0.1"),
        ]:
            with self.assertRaises(BuildError):
                adapt_exiftool(source, version)
        with self.assertRaises(BuildError):
            adapt_exiftool(adapt_exiftool(self.source, "39.0.1"), "39.0.1")

    @unittest.skipUnless(platform.system() in {"Darwin", "Linux"}, "Unix binder")
    def test_both_input_platforms_must_match_before_staging(self):
        host = platform.system() + "-" + platform.machine()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for mismatch in ["server", "perl"]:
                for name in ["server", "perl"]:
                    package = root / name
                    package.mkdir(exist_ok=True)
                    (package / "qualification.json").write_text(
                        json.dumps(
                            {
                                "qualification": "passed",
                                "files": {"fixture": {}},
                                "platform": "different-platform"
                                if name == mismatch
                                else host,
                            }
                        )
                    )
                output = root / "candidate"
                with self.assertRaisesRegex(
                    BuildError, "host_exiftool_input_platform_mismatch"
                ):
                    build(root / "server", root / "perl", output)
                self.assertFalse(output.exists())
