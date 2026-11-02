"""Verify generated source archives against their selected Git objects."""
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile

from build_runtime import BuildError


def verify_source_archive(git: str, source: Path, revision: str, paths: list[str], archive: Path, env: dict[str, str]) -> None:
    """Reject altered included bytes before extraction or compilation of a caller-owned archive."""
    try:
        result = subprocess.run([git, "ls-tree", "-r", "-z", revision, "--", *paths],
                                cwd=source, env=env, capture_output=True, timeout=60, check=True)
        if result.stdout and not result.stdout.endswith(b"\0"):
            raise ValueError("incomplete Git tree")
        objects = {}
        for record in result.stdout.split(b"\0")[:-1]:
            header, name = record.split(b"\t", 1)
            mode, kind, oid = header.split(b" ")
            objects[name] = (mode, kind, oid.decode("ascii"))
        with tarfile.open(archive) as contents:
            for member in contents:
                if member.isdir():
                    continue
                mode, kind, oid = objects[member.name.encode("utf-8", "surrogateescape")]
                if kind != b"blob" or len(oid) not in {40, 64}:
                    raise ValueError("unexpected Git object")
                if member.isfile() and mode in {b"100644", b"100755"}:
                    stream, size = contents.extractfile(member), member.size
                elif member.issym() and mode == b"120000":
                    target = member.linkname.encode("utf-8", "surrogateescape")
                    stream, size = io.BytesIO(target), len(target)
                else:
                    raise ValueError("unexpected archive entry")
                # Git object IDs include the blob header; this is compatibility, not new cryptography.
                digest = hashlib.new("sha1" if len(oid) == 40 else "sha256", usedforsecurity=False)
                digest.update(b"blob " + str(size).encode("ascii") + b"\0")
                with stream:
                    while block := stream.read(1024 * 1024):
                        digest.update(block)
                if digest.hexdigest() != oid:
                    raise ValueError("archive bytes differ from Git")
    except (OSError, subprocess.SubprocessError, tarfile.TarError, ValueError, KeyError) as error:
        # The archive belongs to the fresh build directory; do not retain an unverified input.
        archive.unlink(missing_ok=True)
        raise BuildError("host_source_archive_not_canonical") from error
