"""Reject Git archive attributes that change canonical source line endings."""
from pathlib import Path
import subprocess

from build_runtime import BuildError


def require_lf_archive(git: str, source: Path, revision: str, paths: list[str], env: dict[str, str]) -> None:
    """Check included regular files for an already-approved revision and path selection."""
    try:
        files = subprocess.run([git, "ls-tree", "-r", "-z", revision, "--", *paths],
                               cwd=source, env=env, capture_output=True, timeout=60, check=True)
        if files.stdout and not files.stdout.endswith(b"\0"):
            raise BuildError("host_source_archive_attributes_invalid")
        entries, parents = {}, {}
        for record in files.stdout.split(b"\0")[:-1]:
            header, separator, path = record.partition(b"\t")
            if not separator:
                raise BuildError("host_source_archive_attributes_invalid")
            entries[path] = header.split(b" ", 1)[0]
            parts = path.split(b"/")
            parents[path] = [b"/".join(parts[:end]) for end in range(1, len(parts) + 1)]
        names = sorted({name for lineage in parents.values() for name in lineage})
        attributes = subprocess.run([git, "check-attr", "--source=" + revision, "-z", "--stdin", "eol", "export-ignore"],
                                    input=b"".join(name + b"\0" for name in names), cwd=source, env=env,
                                    capture_output=True, timeout=60, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        raise BuildError("host_source_archive_attributes_unavailable") from error
    fields = attributes.stdout.split(b"\0")
    if fields.pop() != b"" or len(fields) != 6 * len(names):
        raise BuildError("host_source_archive_attributes_invalid")
    effective = {name: {} for name in names}
    for index in range(0, len(fields), 3):
        path, attribute, value = fields[index:index + 3]
        if path not in effective or attribute not in {b"eol", b"export-ignore"} or attribute in effective[path]:
            raise BuildError("host_source_archive_attributes_invalid")
        effective[path][attribute] = value
    for path, mode in entries.items():
        if mode not in {b"100644", b"100755"}:
            continue
        if any(effective[parent][b"export-ignore"] == b"set" for parent in parents[path]):
            continue
        # Git archive honors repository-local attributes even when core.eol is LF.
        if effective[path][b"eol"] not in {b"unspecified", b"unset", b"lf"}:
            raise BuildError("host_source_archive_eol_not_lf")
