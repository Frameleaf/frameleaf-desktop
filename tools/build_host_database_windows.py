"""Build and qualify the pinned private Windows PostgreSQL component in fresh state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import tarfile
from pathlib import Path

from build_host_database import database_contract, download
from build_runtime import BuildError, build_environment, git_blob, inventory, regular, run, sha256

ROOT = Path(__file__).resolve().parent.parent
SYSTEM_DLLS = {
    "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll", "comdlg32.dll",
    "crypt32.dll", "dbghelp.dll", "dnsapi.dll", "gdi32.dll", "iphlpapi.dll",
    "kernel32.dll", "kernelbase.dll", "msvcrt.dll", "ncrypt.dll", "netapi32.dll",
    "normaliz.dll", "ntdll.dll", "ole32.dll", "oleaut32.dll", "psapi.dll",
    "rpcrt4.dll", "secur32.dll", "setupapi.dll", "shell32.dll", "shlwapi.dll",
    "user32.dll", "userenv.dll", "ucrtbase.dll", "version.dll", "winmm.dll",
    "ws2_32.dll", "wtsapi32.dll",
}


def data_only_pe(binary: Path) -> bool:
    with binary.open("rb") as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            return False
        offset = int.from_bytes(dos[60:64], "little")
        if offset < 64:
            return False
        stream.seek(offset)
        header = stream.read(24)
        if len(header) != 24 or header[:6] != b"PE\0\0\x64\x86":
            return False
        size = int.from_bytes(header[20:22], "little")
        if not 128 <= size <= 4096 or not int.from_bytes(header[22:24], "little") & 0x2000:
            return False
        optional = stream.read(size)
    # ICU ships a data-only DLL: successful dumpbin output legitimately has no imports.
    return (
        len(optional) == size and optional[:2] == b"\x0b\x02"
        and optional[4:8] == b"\0" * 4 and optional[16:20] == b"\0" * 4
        and int.from_bytes(optional[108:112], "little") >= 2
        and optional[120:128] == b"\0" * 8
    )


def stage_dependencies(prefix: Path, dependencies: Path, dumpbin: str, env: dict) -> None:
    for source in sorted((dependencies / "bin").glob("*.dll")):
        regular(source)
        target = prefix / "bin" / source.name
        if target.exists() and sha256(target) != sha256(source):
            raise BuildError("host_database_dll_collision")
        shutil.copy2(source, target)
    for source in sorted((dependencies / "share").glob("*/*")):
        if source.name not in {"copyright", "ossp-uuid.spdx.json"}:
            continue
        regular(source)
        target = prefix / "licenses" / source.parent.name / source.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    binaries = [p for p in prefix.rglob("*") if p.suffix.lower() in {".exe", ".dll"}]
    if not binaries or len(binaries) > 512:
        raise BuildError("host_database_binary_inventory_invalid")
    private = {}
    for binary in binaries:
        regular(binary)
        key = binary.name.lower()
        if key in private and sha256(private[key]) != sha256(binary):
            raise BuildError("host_database_dll_collision")
        private[key] = binary
    for binary in binaries:
        imports = re.findall(r"^\s+([\w.+-]+\.dll)\s*$", run(
            [dumpbin, "/nologo", "/dependents", binary], cwd=prefix, env=env
        ), re.MULTILINE | re.IGNORECASE)
        if not imports and not data_only_pe(binary):
            raise BuildError("host_database_pe_imports_missing")
        for name in imports:
            key = name.lower()
            if key not in private and key not in SYSTEM_DLLS and not key.startswith(("api-ms-win-", "ext-ms-win-")):
                raise BuildError("host_database_dll_missing:" + key)


def qualify(prefix: Path, output: Path, lock: dict, env: dict) -> dict:
    data = output / "fixture-data"
    password = secrets.token_hex(32)
    password_file = output / "fixture-password"
    password_file.write_text(password, encoding="ascii")
    client_env = {**env, "PGPASSWORD": password}
    binary = lambda name: prefix / "bin" / (name + ".exe")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    args = ["-h", "127.0.0.1", "-p", str(port), "-U", "frameleaf"]
    active = False

    def command(arguments: list) -> str:
        return run(arguments, cwd=output, env=client_env)

    def start() -> None:
        nonlocal active
        if (data / "PG_VERSION").read_text().strip() != re.match(r"\d+", lock["postgresVersion"])[0]:
            raise BuildError("host_database_major_mismatch")
        # Mark owned state before launch so a readiness failure is also drained.
        active = True
        command([binary("pg_ctl"), "-D", data, "-l", output / "postgres.log", "-o",
                 f"-h 127.0.0.1 -p {port}", "-w", "-t", "30", "start"])

    def stop() -> None:
        nonlocal active
        if active:
            command([binary("pg_ctl"), "-D", data, "-m", "fast", "-w", "-t", "30", "stop"])
            active = False

    def sql(database: str, query: str) -> str:
        return command([binary("psql"), *args, "-d", database, "-X", "-qAt", "--set=ON_ERROR_STOP=1", "-c", query])

    def facts(database: str) -> dict:
        result = json.loads(sql(database, "SELECT json_build_object('serverVersion',current_setting('server_version'),'vectorVersion',(SELECT extversion FROM pg_extension WHERE extname='vector'),'extensions',(SELECT json_agg(extname ORDER BY extname) FROM pg_extension WHERE extname <> 'plpgsql'),'checksums',current_setting('data_checksums'),'neighbor',(SELECT id FROM native_fixture ORDER BY embedding <-> '[1,0,0]' LIMIT 1))"))
        if result != {
            "serverVersion": lock["postgresVersion"], "vectorVersion": lock["pgvectorVersion"],
            "extensions": ["cube", "earthdistance", "pg_trgm", "unaccent", "uuid-ossp", "vector"],
            "checksums": "on", "neighbor": 1,
        }:
            raise BuildError("host_database_fixture_mismatch")
        return result

    try:
        try:
            command([binary("initdb"), "-D", data, "--username=frameleaf", "--encoding=UTF8", "--locale=C", "--data-checksums", "--auth-local=scram-sha-256", "--auth-host=scram-sha-256", "--pwfile=" + str(password_file)])
        finally:
            password_file.unlink(missing_ok=True)
        start()
        sql("postgres", "CREATE EXTENSION cube; CREATE EXTENSION earthdistance; CREATE EXTENSION pg_trgm; CREATE EXTENSION unaccent; CREATE EXTENSION \"uuid-ossp\"; CREATE EXTENSION vector; CREATE TABLE native_fixture (id int PRIMARY KEY, embedding vector(3)); INSERT INTO native_fixture VALUES (1,'[1,0,0]'),(2,'[0,1,0]'); CREATE INDEX native_fixture_hnsw ON native_fixture USING hnsw (embedding vector_l2_ops); SELECT earth_distance(ll_to_earth(0,0),ll_to_earth(1,1)); SELECT uuid_generate_v4(), similarity('frameleaf','frameleaf'), unaccent('café');")
        result = {"fresh": facts("postgres")}
        backup = output / "fixture.dump"
        command([binary("pg_dump"), *args, "-d", "postgres", "--format=custom", "--no-owner", "--no-acl", "--file", backup])
        command([binary("createdb"), *args, "restored_fixture"])
        command([binary("pg_restore"), *args, "-d", "restored_fixture", "--exit-on-error", "--single-transaction", "--no-owner", "--no-acl", backup])
        result["restored"] = facts("restored_fixture")
        stop()
        start()
        result["restarted"] = facts("restored_fixture")
        stop()
        command([binary("pg_checksums"), "--check", "-D", data])
        result.update(physicalChecksumsVerified=True, backupSha256=sha256(backup), fixtureAuthentication="scram-private-loopback-only")
        return result
    finally:
        stop()


def build(source: Path, revision: str, dependencies: Path, output: Path) -> None:
    if not re.fullmatch(r"[a-f0-9]{40}", revision) or not all(p.is_absolute() for p in [source, dependencies, output]):
        raise BuildError("host_database_source_invalid")
    if platform.system() != "Windows" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise BuildError("host_database_windows_target_unsupported")
    tools = {name: shutil.which(name) for name in ["git", "cl", "nmake", "meson", "ninja", "dumpbin", "perl", "rc", "mt"]}
    for name, alternate in [("flex", "win_flex"), ("bison", "win_bison")]:
        tools[name] = shutil.which(name) or shutil.which(alternate)
    tools["pkg-config"] = shutil.which("pkgconf", path=str(dependencies / "tools/pkgconf"))
    if not all(tools.values()):
        raise BuildError("host_database_build_tools_missing")
    output.mkdir(mode=0o700)
    # PostgreSQL suppresses Unix-specific subdirectories when the prefix contains postgres.
    work, prefix = output / "work", output / "postgres"
    work.mkdir(mode=0o700)
    env = build_environment(work, os.environ)
    # Only compiler inputs cross the development environment boundary.
    for key in ["INCLUDE", "LIB", "LIBPATH"]:
        if key in os.environ:
            env[key] = os.environ[key]
    env["PATH"] = os.pathsep.join(dict.fromkeys([str(Path(p).parent) for p in tools.values()] + [str(dependencies / "bin"), env["PATH"]]))
    env["CC"] = "cl"
    env["CXX"] = "cl"
    env["PKG_CONFIG"] = tools["pkg-config"]
    env["FRAMELEAF_BUILD_ERROR_LOG"] = str(output / "command-error.log")
    lock = json.loads((ROOT / "runtime/host-database.json").read_text())
    dockerfile = git_blob(tools["git"], source, revision, "docker/postgres/Dockerfile", env).decode()
    database_contract(dockerfile, lock)
    report = {"schemaVersion": 1, "scope": "native-database-fixture", "sourceRevision": revision, "sourceDockerfileSha256": hashlib.sha256(dockerfile.encode()).hexdigest(), "platform": "windows-x86_64", "pins": lock, "redistributable": False, "certified": False, "qualification": "failed"}
    with (output / "build.log").open("w", encoding="utf-8") as log:
        def command(arguments: list, cwd: Path) -> None:
            result = subprocess.run(arguments, cwd=cwd, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=1200)
            log.flush()
            if result.returncode:
                raise BuildError("host_database_build_command_failed:" + Path(arguments[0]).name)
        try:
            for name, url, checksum in [
                ("postgres", f"https://ftp.postgresql.org/pub/source/v{lock['postgresVersion']}/postgresql-{lock['postgresVersion']}.tar.bz2", lock["postgresSourceSha256"]),
                ("vector", f"https://codeload.github.com/pgvector/pgvector/tar.gz/refs/tags/v{lock['pgvectorVersion']}", lock["pgvectorSourceSha256"]),
            ]:
                archive = work / (name + ".tar")
                download(url, archive, checksum)
                target = work / name
                target.mkdir()
                with tarfile.open(archive) as contents:
                    contents.extractall(target, filter="data")
            postgres = work / "postgres" / ("postgresql-" + lock["postgresVersion"])
            configured = work / "configured"
            command([tools["meson"], "setup", configured, postgres, "--prefix=" + str(prefix), "--buildtype=release", "-DFLEX=" + tools["flex"], "-DBISON=" + tools["bison"], "-DPERL=" + tools["perl"], "-Dicu=enabled", "-Duuid=ossp", "-Dplperl=disabled", "-Dplpython=disabled", "-Dpltcl=disabled", "-Dssl=openssl", "-Dlibxml=enabled", "-Dlz4=enabled", "-Dzstd=enabled", "-Dzlib=enabled", "-Dreadline=disabled", "-Ddocs=disabled", "-Dextra_include_dirs=" + str(dependencies / "include"), "-Dextra_lib_dirs=" + str(dependencies / "lib"), "-Dpkg_config_path=" + str(dependencies / "lib/pkgconfig")], work)
            command([tools["meson"], "compile", "-C", configured, "-j", "1"], work)
            command([tools["meson"], "install", "-C", configured], work)
            if not all((prefix / name).is_file() for name in [
                "lib/postgres.lib", "include/server/pg_config.h", "share/extension/cube.control"
            ]):
                raise BuildError("host_database_windows_layout_invalid")
            vector = work / "vector" / ("pgvector-" + lock["pgvectorVersion"])
            env["PGROOT"] = str(prefix)
            command([tools["nmake"], "/NOLOGO", "/F", "Makefile.win"], vector)
            command([tools["nmake"], "/NOLOGO", "/F", "Makefile.win", "install"], vector)
            stage_dependencies(prefix, dependencies, tools["dumpbin"], env)
            (prefix / "licenses").mkdir(exist_ok=True)
            shutil.copy2(postgres / "COPYRIGHT", prefix / "licenses/PostgreSQL-COPYRIGHT")
            shutil.copy2(vector / "LICENSE", prefix / "licenses/pgvector-LICENSE")
            runtime_env = build_environment(work, os.environ)
            runtime_env["PATH"] = str(prefix / "bin") + os.pathsep + runtime_env["PATH"]
            runtime_env["FRAMELEAF_BUILD_ERROR_LOG"] = env["FRAMELEAF_BUILD_ERROR_LOG"]
            report.update(qualify(prefix, output, lock, runtime_env))
            report["files"] = inventory(prefix)
            report["qualification"] = "passed"
        finally:
            (output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ["source", "revision", "dependency-prefix", "output"]:
        parser.add_argument("--" + argument, required=True)
    args = parser.parse_args()
    build(Path(args.source), args.revision, Path(args.dependency_prefix), Path(args.output))
