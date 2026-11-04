"""Private native PostgreSQL feasibility build; never attaches existing user data."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

from build_runtime import BuildError, build_environment, git_blob, run, sha256


def database_contract(dockerfile: str, lock: dict) -> dict:
    if (
        not isinstance(lock, dict)
        or type(lock.get("schemaVersion")) is not int
        or lock.get("schemaVersion") != 1
        or lock.get("certified") is not False
    ):
        raise BuildError("host_database_contract_invalid")
    for key in ["postgresSourceSha256", "pgvectorSourceSha256"]:
        if not isinstance(lock.get(key), str) or not re.fullmatch(
            r"[0-9a-f]{64}", lock[key]
        ):
            raise BuildError("host_database_contract_invalid")
    version = lock.get("postgresVersion", "")
    if not isinstance(version, str) or not re.fullmatch(
        r"\d+(?:\.\d+|beta\d+|rc\d+)", version
    ):
        raise BuildError("host_database_contract_invalid")
    image = lock.get("postgresImage", "")
    if not isinstance(image, str) or not re.fullmatch(
        rf"docker.io/library/postgres:{re.escape(version)}-bookworm@sha256:[0-9a-f]{{64}}",
        image,
    ):
        raise BuildError("host_database_contract_invalid")
    expected = {
        "POSTGRES_IMAGE": image,
        "PGVECTOR_VERSION": lock.get("pgvectorVersion"),
        "PGVECTOR_SHA256": lock["pgvectorSourceSha256"],
    }
    if not isinstance(expected["PGVECTOR_VERSION"], str) or not re.fullmatch(
        r"\d+\.\d+\.\d+", expected["PGVECTOR_VERSION"]
    ):
        raise BuildError("host_database_contract_invalid")
    for key, value in expected.items():
        found = re.findall(rf"^ARG {key}=(\S+)$", dockerfile, re.MULTILINE)
        if found != [value]:
            raise BuildError("host_database_server_pin_mismatch")
    return lock


def download(url: str, destination: Path, expected: str, *, max_bytes: int = 128 * 1024**2) -> None:
    with (
        urllib.request.urlopen(url, timeout=60) as response,
        destination.open("xb") as output,
    ):
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise BuildError("host_database_download_too_large")
            output.write(chunk)
    if sha256(destination) != expected:
        raise BuildError("host_database_archive_digest_mismatch")


def build(source: Path, revision: str, dependencies: Path, output: Path) -> None:
    system = platform.system()
    if system not in {"Darwin", "Linux"}:
        raise BuildError("host_database_feasibility_target_unsupported")
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or not all(
        path.is_absolute() for path in [source, dependencies, output]
    ):
        raise BuildError("host_database_source_invalid")
    git, make = shutil.which("git"), shutil.which("make")
    if not git or not make:
        raise BuildError("host_database_build_tools_missing")
    lock = json.loads(
        (Path(__file__).parent.parent / "runtime/host-database.json").read_text()
    )
    output.mkdir(mode=0o700)
    work, prefix = output / "work", output / "prefix"
    work.mkdir(mode=0o700)
    env = build_environment(work, {})
    env["LDFLAGS"] = "-Wl,-headerpad_max_install_names" if system == "Darwin" else ""
    include_paths = [dependencies / "include"]
    library_paths = [dependencies / "lib"]
    if system == "Darwin":
        include_paths.insert(0, dependencies / "opt/openssl@3/include")
        library_paths.insert(0, dependencies / "opt/openssl@3/lib")
    env["PATH"] = os.pathsep.join(
        [
            str(prefix / "bin"),
            str(dependencies / "opt/bison/bin"),
            str(dependencies / "opt/flex/bin"),
            str(dependencies / "bin"),
            os.defpath,
        ]
    )
    env["PKG_CONFIG_PATH"] = os.pathsep.join(
        str(path / "lib/pkgconfig")
        for path in [
            dependencies / "opt/icu4c",
            dependencies / "opt/openssl@3",
            dependencies,
        ]
    )
    env["FRAMELEAF_BUILD_ERROR_LOG"] = str(output / "command-error.log")
    dockerfile = git_blob(
        git, source, revision, "docker/postgres/Dockerfile", env
    ).decode()
    database_contract(dockerfile, lock)
    report = {
        "schemaVersion": 1,
        "scope": "native-database-fixture",
        "sourceRevision": revision,
        "sourceDockerfileSha256": __import__("hashlib")
        .sha256(dockerfile.encode())
        .hexdigest(),
        "platform": f"{'macos' if system == 'Darwin' else 'linux'}-{platform.machine()}",
        "pins": lock,
        "redistributable": False,
        "developmentDependencyPrefix": str(dependencies),
        "linkerFlags": env["LDFLAGS"],
        "qualification": "failed",
    }
    with (output / "build.log").open("w") as log:

        def command(args: list, cwd: Path = work) -> str:
            result = run([str(arg) for arg in args], cwd=cwd, env=env)
            log.write(result + "\n")
            log.flush()
            return result

        try:
            archives = [
                (
                    "postgres",
                    f"https://ftp.postgresql.org/pub/source/v{lock['postgresVersion']}/postgresql-{lock['postgresVersion']}.tar.bz2",
                    lock["postgresSourceSha256"],
                ),
                (
                    "vector",
                    f"https://codeload.github.com/pgvector/pgvector/tar.gz/refs/tags/v{lock['pgvectorVersion']}",
                    lock["pgvectorSourceSha256"],
                ),
            ]
            for name, url, checksum in archives:
                archive = work / f"{name}.tar"
                download(url, archive, checksum)
                target = work / name
                target.mkdir()
                with tarfile.open(archive) as contents:
                    contents.extractall(target, filter="data")
            postgres = work / "postgres" / f"postgresql-{lock['postgresVersion']}"
            command(
                [
                    postgres / "configure",
                    f"--prefix={prefix}",
                    "--without-readline",
                    "--with-icu",
                    "--with-openssl",
                    "--with-uuid=e2fs",
                    "--with-includes=" + ":".join(map(str, include_paths)),
                    "--with-libraries=" + ":".join(map(str, library_paths)),
                    "--with-lz4",
                    "--with-zstd",
                    "--with-libxml",
                ],
                postgres,
            )
            command([make, "-j1", "world-bin"], postgres)
            command([make, "install-world-bin"], postgres)
            vector = work / "vector" / f"pgvector-{lock['pgvectorVersion']}"
            command(
                [make, "-j1", f"PG_CONFIG={prefix / 'bin/pg_config'}", "OPTFLAGS="],
                vector,
            )
            command([make, f"PG_CONFIG={prefix / 'bin/pg_config'}", "install"], vector)
            report["postgresSha256"] = sha256(prefix / "bin/postgres")
            report["pgDumpSha256"] = sha256(prefix / "bin/pg_dump")
            report["pgvectorSha256"] = sha256(
                prefix
                / "lib/postgresql"
                / ("vector.dylib" if system == "Darwin" else "vector.so")
            )
            data = output / "fixture-data"
            command(
                [
                    prefix / "bin/initdb",
                    "-D",
                    data,
                    "--username=frameleaf",
                    "--encoding=UTF8",
                    "--locale=C",
                    "--data-checksums",
                    "--auth-local=trust",
                    "--auth-host=reject",
                ]
            )
            report["fixtureAuthentication"] = "trust-private-unix-socket-only-no-tcp"
            with (
                tempfile.TemporaryDirectory(prefix="fl-pg19-", dir="/tmp") as temporary,
                (output / "postgres.log").open("w") as server_log,
            ):
                socket = str(Path(temporary).resolve())
                args = ["-h", socket, "-p", "54329", "-U", "frameleaf"]
                child = None

                def stop() -> None:
                    nonlocal child
                    if child is None:
                        return
                    child.terminate()
                    try:
                        child.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=10)
                    child = None

                def start() -> None:
                    nonlocal child
                    if (data / "PG_VERSION").read_text().strip() != re.match(
                        r"\d+", lock["postgresVersion"]
                    )[0]:
                        raise BuildError("host_database_major_mismatch")
                    child = subprocess.Popen(
                        [
                            prefix / "bin/postgres",
                            "-D",
                            data,
                            "-h",
                            "",
                            "-k",
                            socket,
                            "-p",
                            "54329",
                            "-c",
                            "unix_socket_permissions=0700",
                        ],
                        env=env,
                        stdout=server_log,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                    )
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline and child.poll() is None:
                        ready = subprocess.run(
                            [prefix / "bin/pg_isready", *args, "-d", "postgres"],
                            env=env,
                            capture_output=True,
                            check=False,
                            timeout=3,
                        )
                        if ready.returncode == 0:
                            return
                        time.sleep(0.2)
                    raise BuildError("host_database_readiness_failed")

                def sql(database: str, query: str) -> str:
                    return command(
                        [
                            prefix / "bin/psql",
                            *args,
                            "-d",
                            database,
                            "-X",
                            "-qAt",
                            "--set=ON_ERROR_STOP=1",
                            "-c",
                            query,
                        ]
                    )

                def facts(database: str) -> dict:
                    result = json.loads(
                        sql(
                            database,
                            "SELECT json_build_object('serverVersion',current_setting('server_version'),'vectorVersion',(SELECT extversion FROM pg_extension WHERE extname='vector'),'extensions',(SELECT json_agg(extname ORDER BY extname) FROM pg_extension WHERE extname <> 'plpgsql'),'checksums',current_setting('data_checksums'),'neighbor',(SELECT id FROM native_fixture ORDER BY embedding <-> '[1,0,0]' LIMIT 1))",
                        )
                    )
                    if result != {
                        "serverVersion": lock["postgresVersion"],
                        "vectorVersion": lock["pgvectorVersion"],
                        "extensions": [
                            "cube",
                            "earthdistance",
                            "pg_trgm",
                            "unaccent",
                            "uuid-ossp",
                            "vector",
                        ],
                        "checksums": "on",
                        "neighbor": 1,
                    }:
                        raise BuildError("host_database_fixture_mismatch")
                    return result

                try:
                    start()
                    sql(
                        "postgres",
                        "CREATE EXTENSION cube; CREATE EXTENSION earthdistance; CREATE EXTENSION pg_trgm; CREATE EXTENSION unaccent; CREATE EXTENSION \"uuid-ossp\"; CREATE EXTENSION vector; CREATE TABLE native_fixture (id int PRIMARY KEY, embedding vector(3)); INSERT INTO native_fixture VALUES (1,'[1,0,0]'),(2,'[0,1,0]'); CREATE INDEX native_fixture_hnsw ON native_fixture USING hnsw (embedding vector_l2_ops); SELECT earth_distance(ll_to_earth(0,0),ll_to_earth(1,1)); SELECT uuid_generate_v4(), similarity('frameleaf','frameleaf'), unaccent('café');",
                    )
                    report["fresh"] = facts("postgres")
                    backup = output / "fixture.dump"
                    command(
                        [
                            prefix / "bin/pg_dump",
                            *args,
                            "-d",
                            "postgres",
                            "--format=custom",
                            "--no-owner",
                            "--no-acl",
                            "--file",
                            backup,
                        ]
                    )
                    command([prefix / "bin/createdb", *args, "restored_fixture"])
                    command(
                        [
                            prefix / "bin/pg_restore",
                            *args,
                            "-d",
                            "restored_fixture",
                            "--exit-on-error",
                            "--single-transaction",
                            "--no-owner",
                            "--no-acl",
                            backup,
                        ]
                    )
                    report["restored"] = facts("restored_fixture")
                    stop()
                    start()
                    report["restarted"] = facts("restored_fixture")
                    stop()
                    command([prefix / "bin/pg_checksums", "--check", "-D", data])
                    report["physicalChecksumsVerified"] = True
                    report["backupSha256"] = sha256(backup)
                    report["qualification"] = "passed"
                finally:
                    stop()
        finally:
            (output / "qualification.json").write_text(
                json.dumps(report, indent=2) + "\n"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ["source", "revision", "dependency-prefix", "output"]:
        parser.add_argument(f"--{argument}", required=True)
    args = parser.parse_args()
    build(
        Path(args.source),
        args.revision,
        Path(args.dependency_prefix),
        Path(args.output),
    )
