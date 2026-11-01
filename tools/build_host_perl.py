"""Build a relocatable private Unix Perl VM for the native ExifTool package."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import tarfile
from pathlib import Path

from build_host_database import download
from build_host_server import stage_server
from build_runtime import BuildError, build_environment, inventory, regular, run
from relocate_macos import apple_library, load_commands


def perl_contract(pin: dict) -> dict:
    version = pin.get("version", "")
    if (
        type(pin.get("schemaVersion")) is not int
        or pin["schemaVersion"] != 1
        or not re.fullmatch(r"5\.\d+\.\d+", version)
        or pin.get("url") != f"https://www.cpan.org/src/5.0/perl-{version}.tar.xz"
        or not re.fullmatch(r"[a-f0-9]{64}", pin.get("sha256", ""))
    ):
        raise BuildError("host_perl_contract_invalid")
    return pin


def validate_probe(root: Path, version: str, record: dict) -> None:
    required = {
        "IO/Handle.pm",
        "Cwd.pm",
        "JSON/PP.pm",
        "Compress/Raw/Zlib.pm",
        "Time/HiRes.pm",
    }
    if (
        record.get("version") != version
        or not required.issubset(record.get("modules", {}))
        or not record.get("inc")
    ):
        raise BuildError("host_perl_probe_invalid")
    root = root.resolve()
    for value in [*record["inc"], *record["modules"].values(), *record["libraries"]]:
        if (
            not isinstance(value, str)
            or not Path(value).is_absolute()
            or not Path(value).resolve().is_relative_to(root)
        ):
            raise BuildError("host_perl_external_module_path")
    for value in [*record["modules"].values(), *record["libraries"]]:
        regular(Path(value))


def build(output: Path) -> None:
    if platform.system() not in {"Darwin", "Linux"}:
        raise BuildError("host_perl_target_unsupported")
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise BuildError("host_perl_output_invalid")
    pin = perl_contract(
        json.loads(
            (Path(__file__).parent.parent / "runtime/host-perl.json").read_text()
        )
    )
    output.mkdir(mode=0o700)
    work = output / "work"
    work.mkdir(mode=0o700)
    env = build_environment(work, os.environ)
    env["FRAMELEAF_BUILD_ERROR_LOG"] = str(output / "command-error.log")
    report = {
        "schemaVersion": 1,
        "source": pin,
        "platform": platform.system() + "-" + platform.machine(),
        "qualification": "failed",
        "redistributable": False,
        "installedPlatformQualified": False,
    }
    with (output / "build.log").open("w") as log:

        def command(arguments: list, cwd: Path = work) -> str:
            value = run(arguments, cwd=cwd, env=env)
            log.write(value + "\n")
            log.flush()
            return value

        try:
            archive = work / "perl.tar.xz"
            download(pin["url"], archive, pin["sha256"])
            extracted = work / "source"
            extracted.mkdir(mode=0o700)
            with tarfile.open(archive) as contents:
                contents.extractall(extracted, filter="data")
            source = extracted / ("perl-" + pin["version"])
            prefix = work / "installed"
            arguments = [
                "/bin/sh",
                "Configure",
                "-des",
                "-Dprefix=" + str(prefix),
                "-Duserelocatableinc",
                "-Uuseshrplib",
                "-Dinstallusrbinperl=undef",
                "-Dman1dir=none",
                "-Dman3dir=none",
                "-Dlocincpth=",
                "-Dloclibpth=",
            ]
            report["configureArguments"] = arguments[2:]
            command(arguments, cwd=source)
            command(["make", "-j4"], cwd=source)
            command(["make", "install"], cwd=source)
            staged = work / "staged"
            (staged / "bin").mkdir(parents=True, mode=0o700)
            regular(prefix / "bin/perl")
            shutil.copyfile(prefix / "bin/perl", staged / "bin/perl")
            (staged / "bin/perl").chmod(0o700)
            shutil.copytree(prefix / "lib", staged / "lib", symlinks=True)
            (staged / "licenses").mkdir(mode=0o700)
            for name in ["Artistic", "Copying"]:
                shutil.copyfile(source / name, staged / "licenses" / name)
            candidate = work / "candidate"
            stage_server(staged, candidate)
            program = r"""use Config; use IO::Handle; use Cwd; use JSON::PP; use Compress::Raw::Zlib; use Time::HiRes; use Fcntl;
print JSON::PP->new->canonical->encode({version=>sprintf("%vd",$^V),inc=>\@INC,modules=>\%INC,libraries=>\@DynaLoader::dl_shared_objects});"""
            facts = json.loads(command([candidate / "bin/perl", "-e", program]))
            validate_probe(candidate, pin["version"], facts)
            runtime = output / "perl"
            candidate.rename(runtime)
            prefix.rename(work / "original-install-unavailable")
            facts = json.loads(command([runtime / "bin/perl", "-e", program]))
            validate_probe(runtime, pin["version"], facts)
            report["relocatedProbe"] = facts
            if platform.system() == "Darwin":
                count = 0
                for path in runtime.rglob("*"):
                    if not path.is_file():
                        continue
                    with path.open("rb") as stream:
                        magic = stream.read(4)
                    if magic not in {
                        b"\xcf\xfa\xed\xfe",
                        b"\xce\xfa\xed\xfe",
                        b"\xca\xfe\xba\xbe",
                    }:
                        continue
                    if command(["/usr/bin/lipo", "-archs", path]).split() != [
                        platform.machine()
                    ]:
                        raise BuildError("host_perl_architecture_mismatch")
                    _, dependencies, paths = load_commands(
                        command(["/usr/bin/otool", "-l", path])
                    )
                    if paths or not all(apple_library(value) for value in dependencies):
                        raise BuildError("host_perl_external_native_dependency")
                    command(["/usr/bin/codesign", "--verify", "--strict", path])
                    count += 1
                report["macosLoadCommandObjects"] = count
            report["files"] = inventory(runtime)
            report["qualification"] = "passed"
        finally:
            (output / "qualification.json").write_text(
                json.dumps(report, indent=2) + "\n"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    try:
        build(options.output)
    except (BuildError, OSError, ValueError, tarfile.TarError) as error:
        parser.exit(
            1, str(error) if isinstance(error, BuildError) else "host_perl_build_failed"
        )
