"""Reject Git archive attributes that change canonical source line endings."""
from pathlib import Path
import subprocess

from build_runtime import BuildError

def require_lf_archive(git: str, source: Path, revision: str, paths: list[str], env: dict[str, str]) -> None:
    try:
        files = subprocess.run([git, "ls-tree", "-r", "--name-only", "-z", revision, "--", *paths],
                               cwd=source, env=env, capture_output=True, timeout=60, check=True)
        attributes = subprocess.run([git, "check-attr", "--source=" + revision, "-z", "--stdin", "eol"],
                                    input=files.stdout, cwd=source, env=env, capture_output=True, timeout=60, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        raise BuildError("host_source_archive_attributes_unavailable") from error
    fields = attributes.stdout.split(b"\0")
    if fields.pop() != b"" or len(fields) % 3 or len(fields) != 3 * files.stdout.count(b"\0"):
        raise BuildError("host_source_archive_attributes_invalid")
    # Git archive honors repository-local attributes even when core.eol is LF.
    for index in range(0, len(fields), 3):
        if fields[index + 1] != b"eol" or fields[index + 2] not in {b"unspecified", b"unset", b"lf"}:
            raise BuildError("host_source_archive_eol_not_lf")

