import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_host_database import BuildError, database_contract, download


class HostDatabaseTests(unittest.TestCase):
    def test_archives_are_refused_before_extraction_when_bytes_do_not_match_the_pin(
        self,
    ):
        payload = b"synthetic source archive"
        with tempfile.TemporaryDirectory() as temporary:
            for expected in [hashlib.sha256(payload).hexdigest(), "0" * 64]:
                target = Path(temporary) / expected
                with patch(
                    "build_host_database.urllib.request.urlopen",
                    return_value=io.BytesIO(payload),
                ):
                    if expected == "0" * 64:
                        with self.assertRaisesRegex(BuildError, "digest_mismatch"):
                            download("https://example.test/source", target, expected)
                    else:
                        download("https://example.test/source", target, expected)
                        self.assertEqual(target.read_bytes(), payload)

    def test_native_database_requires_the_exact_server_source_contract(self):
        lock = json.loads(
            (Path(__file__).parent.parent / "runtime/host-database.json").read_text()
        )
        dockerfile = (
            f"ARG POSTGRES_IMAGE={lock['postgresImage']}\n"
            f"ARG PGVECTOR_VERSION={lock['pgvectorVersion']}\n"
            f"ARG PGVECTOR_SHA256={lock['pgvectorSourceSha256']}\n"
        )
        self.assertEqual(database_contract(dockerfile, lock), lock)
        for changed in [
            dockerfile.replace("19beta4", "16"),
            dockerfile.replace("0.8.7", "0.8.6"),
            dockerfile.replace(lock["pgvectorSourceSha256"], "0" * 64),
        ]:
            with self.assertRaises(BuildError):
                database_contract(changed, lock)
        for field, value in [
            ("schemaVersion", True),
            ("certified", True),
            ("postgresVersion", "16"),
            ("postgresSourceSha256", "missing"),
        ]:
            with self.subTest(field=field), self.assertRaises(BuildError):
                database_contract(dockerfile, {**lock, field: value})
