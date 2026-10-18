"""Build the source-pinned native RAW engine and copy its private native closure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

from build_host_database import download
from build_host_server import stage_server
from build_runtime import (
    BuildError,
    build_environment,
    git_blob,
    inventory,
    regular,
    sha256,
)
from relocate_linux import closure as elf_closure
from relocate_macos import closure, load_commands
from relocate_windows import closure as pe_closure


def raw_contract(pin: dict, patches: dict[str, bytes], libraw: dict) -> dict:
    expected = {
        "darktable": ("darktable-org/darktable", "."),
        "rawspeed": ("darktable-org/rawspeed", "src/external/rawspeed"),
        "whereami": ("gpakosz/whereami", "src/external/whereami"),
        "opencl": ("KhronosGroup/OpenCL-Headers", "src/external/OpenCL"),
        "lensfun": ("lensfun/lensfun", "lensfun"),
    }
    if (
        pin.get("name") != "darktable"
        or pin.get("repository") != "darktable-org/darktable"
        or pin.get("version") != "5.6.2"
        or pin.get("lensfunVersion") != "0.3.4"
        or not re.fullmatch(r"[a-f0-9]{40}", pin.get("revision", ""))
        or pin.get("patches")
        != {name: hashlib.sha256(value).hexdigest() for name, value in patches.items()}
        or set(patches)
        != {"patch-darktable-lens.py", "patch-darktable-mask-geometry.py"}
        or not isinstance(pin.get("inputs"), list)
        or len(pin["inputs"]) != len(expected)
        or libraw.get("name") != "libraw"
        or libraw.get("repository") != "LibRaw/LibRaw"
        or not re.fullmatch(r"[a-f0-9]{40}", libraw.get("revision", ""))
    ):
        raise BuildError("host_raw_source_contract_invalid")
    found = set()
    for item in pin["inputs"]:
        name = item.get("name")
        if name not in expected or name in found:
            raise BuildError("host_raw_source_contract_invalid")
        repository, path = expected[name]
        revision = item.get("revision", "")
        if (
            item.get("repository") != repository
            or item.get("path") != path
            or not re.fullmatch(r"[a-f0-9]{40}", revision)
            or not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", ""))
            or item.get("url")
            != f"https://codeload.github.com/{repository}/tar.gz/{revision}"
            or (name == "darktable" and revision != pin["revision"])
        ):
            raise BuildError("host_raw_source_contract_invalid")
        found.add(name)
    return pin



def use_windows_libraw_wide_input(source: Path) -> dict:
    regular(source)
    original = source.read_text()
    include = "#include <windows.h>\n"
    opening = "        ret = RawProcessor.open_file(argv[arg]);\n"
    if original.count(include) != 1 or original.count(opening) != 1:
        raise BuildError("host_raw_libraw_entrypoint_changed")
    before = sha256(source)
    # Keep the original UTF-16 input; the CRT narrow argv has already lost Unicode characters.
    adapted = original.replace(include, include + "#include <shellapi.h>\n#include <memory>\n")
    adapted = adapted.replace(opening, """#ifndef LIBRAW_WIN32_UNICODEPATHS
#error Windows RAW input requires wide-path support
#endif
        int wide_argc = 0;
        std::unique_ptr<wchar_t *, decltype(&LocalFree)> wide_argv(
            CommandLineToArgvW(GetCommandLineW(), &wide_argc), &LocalFree);
        if (!wide_argv || wide_argc != argc)
          return 1;
        ret = RawProcessor.open_file(wide_argv.get()[arg]);
""")
    source.write_text(adapted)
    return {"originalSha256": before, "adaptedSha256": sha256(source)}


def use_pinned_windows_lensfun_database(macro: Path, prefix: Path) -> dict:
    database = prefix / "share/lensfun/version_1"
    if not (database / "timestamp.txt").is_file() or not any(database.glob("*.xml")):
        raise BuildError("host_raw_lensfun_database_missing")
    regular(macro)
    original = macro.read_text()
    match = re.search(
        r"  # Add lensfun libraries\n.*?  endif\(LensFun_FOUND\)\n",
        original,
        re.DOTALL,
    )
    if (
        not match
        or original.count("  # Add lensfun libraries\n") != 1
        or hashlib.sha256(match.group().encode()).hexdigest()
        != "06d7d8439b9ffc230aceba696f509cf5a0f526750c132d3aacda084c538629df"
    ):
        raise BuildError("host_raw_lensfun_packaging_changed")
    before = sha256(macro)
    # Lensfun already installed its pinned database here; do not import mutable MSYS data.
    macro.write_text(
        original[:match.start()]
        + "  # Source-pinned Lensfun database already installed in this private prefix.\n"
        + original[match.end():]
    )
    return {
        "originalSha256": before,
        "adaptedSha256": sha256(macro),
        "databaseRelativePath": "share/lensfun/version_1",
        "databaseFiles": inventory(database),
    }


def stage_raw(
    prefix: Path, work: Path, output: Path, command, dependencies: Path
) -> dict:
    linux = platform.system() == "Linux"
    windows = platform.system() == "Windows"
    extension = ".exe" if windows else ""
    entries = {}
    for path in prefix.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        # MinGW debug sidecars keep PE headers without loadable section contents.
        if windows and path.suffix.casefold() == ".dbg":
            continue
        with path.open("rb") as stream:
            header = stream.read(4)
            if (header[:2] == b"MZ" if windows else header == (b"\x7fELF" if linux else b"\xcf\xfa\xed\xfe")):
                entries[path.relative_to(prefix).as_posix()] = path
    regular(prefix / ("bin/darktable-cli" + extension))
    for name, marker in [
        ("liblens.so", b"frameleaf-lens-calibration:"),
        (
            "librotatepixels.so",
            b"frameleaf-native-mask-geometry:rotatepixels:1",
        ),
    ]:
        path = prefix / "lib/darktable/plugins" / (name.removesuffix(".so") + ".dll" if windows else name)
        regular(path)
        if marker not in path.read_bytes():
            raise BuildError("host_raw_patch_marker_missing")
    adjustments = {}
    if not linux and not windows:
        for name, path in entries.items():
            _, references, paths = load_commands(
                command(["/usr/bin/otool", "-l", path])
            )
            if not any(value.startswith("@rpath/") for value in references):
                continue
            before = sha256(path)
            for search in [prefix / "lib", prefix / "lib/darktable"]:
                if str(search) not in paths:
                    command(
                        ["/usr/bin/install_name_tool", "-add_rpath", str(search), path]
                    )
            adjustments[name] = {
                "originalSha256": before,
                "normalizedSha256": sha256(path),
            }
    staged = output / "raw"
    if windows:
        native = pe_closure(entries, [prefix / "bin", prefix / "lib", dependencies / "bin"], staged,
                            lambda path: command([dependencies / "bin/objdump.exe", "-p", path]))
        stage_server(dependencies / "share/licenses", staged / "licenses-toolchain")
    elif linux:
        directories = [
            prefix / "lib",
            prefix / "lib/darktable",
            dependencies / "lib",
            dependencies / "lib" / (platform.machine() + "-linux-gnu"),
        ]
        native = elf_closure(
            entries, [path for path in directories if path.is_dir()], staged
        )
    else:
        native = closure(entries, staged)
    for name in ["share/darktable", "share/lensfun"]:
        stage_server(prefix / name, staged / name)
    notices = staged / "licenses"
    notices.mkdir()
    if windows:
        regex_notice = work / "lensfun/include/regex/regex.h"
        regular(regex_notice)
        shutil.copyfile(regex_notice, notices / "lensfun-tre-regex.h")
    for name, path in {
        "darktable-LICENSE": work / "darktable/LICENSE",
        "rawspeed-LICENSE": work / "darktable/src/external/rawspeed/LICENSE",
        "whereami-LICENSE.MIT": work / "darktable/src/external/whereami/LICENSE.MIT",
        "opencl-LICENSE": work / "darktable/src/external/OpenCL/LICENSE",
        "lensfun-lgpl-3.0.txt": work / "lensfun/docs/lgpl-3.0.txt",
        "lensfun-cc-by-sa-3.0.txt": work / "lensfun/docs/cc-by-sa-3.0.txt",
        "libraw-LICENSE.LGPL": work / "libraw/LICENSE.LGPL",
        "libraw-LICENSE.CDDL": work / "libraw/LICENSE.CDDL",
    }.items():
        regular(path)
        shutil.copyfile(path, notices / name)
    prefix.rename(work / "original-install-unavailable")
    banner = command([staged / ("bin/darktable-cli" + extension), "--version"],
                     **({"runtime_root": staged} if windows else {}))
    if not re.match(r"darktable(?:-cli)?\s+5\.6\.2(?:\s|$)", banner):
        raise BuildError("host_raw_version_mismatch")
    return {
        "nativeClosure": native,
        "rpathAdjustments": adjustments,
        "reportedVersion": banner,
        "files": inventory(staged),
    }


def build(source: Path, revision: str, dependencies: Path, output: Path) -> None:
    windows = platform.system() == "Windows"
    if platform.system() not in {"Darwin", "Linux", "Windows"} or (windows and platform.machine().lower() not in {"amd64", "x86_64"}):
        raise BuildError("host_raw_target_unsupported")
    if (
        not re.fullmatch(r"[a-f0-9]{40}", revision)
        or not all(path.is_absolute() for path in [source, dependencies, output])
        or output.exists()
        or output.is_symlink()
    ):
        raise BuildError("host_raw_output_invalid")
    tools = {
        name: shutil.which(name)
        for name in [
            "git",
            "cmake",
            "ninja",
            "make",
            "autoreconf",
            "python3",
            "pkg-config",
            "intltool-merge",
            "xsltproc",
        ]
    }
    if windows:
        msys = dependencies.parent / "usr/bin"
        tools = {name: str((msys if name in {"git", "make"} else dependencies / "bin") / (name + ".exe"))
                 for name in ["git", "make", "cmake", "ninja", "pkg-config", "xsltproc"]}
        tools.update({name: str(msys / name) for name in ["autoreconf", "intltool-merge"]})
        tools["python3"] = sys.executable
        tools["bash"] = str(msys / "bash.exe")
        if dependencies.name != "ucrt64" or any(not Path(tool).is_file() for tool in tools.values()):
            raise BuildError("host_raw_ucrt64_tools_missing")
    if not all(tools.values()):
        raise BuildError("host_raw_build_tools_missing")
    output.mkdir(mode=0o700)
    work = output / "work"
    work.mkdir(mode=0o700)
    prefix = work / "prefix"
    env = build_environment(work, os.environ)
    env.update(
        {
            "PATH": os.pathsep.join(
                [
                    str(dependencies / "bin"),
                    str(dependencies / "opt/libtool/libexec/gnubin"),
                    os.defpath,
                ]
            ),
            "PKG_CONFIG_PATH": os.pathsep.join(
                [str(prefix / "lib/pkgconfig"), str(dependencies / "lib/pkgconfig")]
            ),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "FRAMELEAF_BUILD_ERROR_LOG": str(output / "command-error.log"),
        }
    )
    if windows:
        if not env.get("SystemRoot") or not Path(env["SystemRoot"]).is_absolute():
            raise BuildError("host_raw_windows_system_root_missing")
        env.update({
            "PATH": os.pathsep.join([str(dependencies / "bin"), str(msys), str(Path(env["SystemRoot"]) / "System32")]),
            "CC": "gcc", "CXX": "g++", "MSYSTEM": "UCRT64",
            "CONFIG_SHELL": "/usr/bin/bash", "MSYS2_ARG_CONV_EXCL": "*",
        })
    if platform.system() == "Darwin":
        env["CPPFLAGS"] = "-I" + str(dependencies / "opt/jpeg-turbo/include")
        env["LDFLAGS"] = "-L" + str(dependencies / "opt/jpeg-turbo/lib")
    git = tools["git"]
    patches = {
        name: git_blob(git, source, revision, "server/test/native/" + name, env)
        for name in ["patch-darktable-lens.py", "patch-darktable-mask-geometry.py"]
    }
    pin = json.loads(
        git_blob(git, source, revision, "server/base-image/sources/darktable.json", env)
    )
    libraw = json.loads(
        git_blob(git, source, revision, "server/base-image/sources/libraw.json", env)
    )
    raw_contract(pin, patches, libraw)
    report = {
        "schemaVersion": 1,
        "sourceRevision": revision,
        "platform": "Windows-AMD64" if windows else platform.system() + "-" + platform.machine(),
        "source": pin,
        "librawSource": libraw,
        "developmentDependencyPrefix": str(dependencies),
        "qualification": "failed",
        "redistributable": False,
        "dynamicLoadingQualified": False,
        "fullRawConformance": False,
        "installedPlatformQualified": False,
    }
    with (output / "build.log").open("w") as log:

        def command(arguments: list, cwd: Path = work, runtime_root: Path | None = None) -> str:
            child_env = env
            if windows and runtime_root is not None:
                child_env = {key: env[key] for key in ["SystemRoot", "HOME", "USERPROFILE", "TMP", "TEMP"]}
                child_env["PATH"] = os.pathsep.join([str(runtime_root / "bin"), str(Path(env["SystemRoot"]) / "System32")])
                child_env["OMP_NUM_THREADS"] = "1"
            elif windows:
                arguments = [tools["bash"], "--noprofile", "--norc", "-c", 'exec "$@"', "frameleaf-build",
                             *[str(arg).replace("\\", "/") for arg in arguments]]
            result = subprocess.run(
                arguments,
                check=False,
                cwd=cwd,
                env=child_env,
                text=True,
                capture_output=True,
                timeout=1200,
            )
            log.write(result.stdout + "\n" + result.stderr + "\n")
            log.flush()
            if result.returncode:
                raise BuildError("host_raw_command_failed:" + Path(arguments[0]).name)
            return result.stdout.strip()

        try:
            if windows:
                if command([dependencies / "bin/gcc.exe", "-dumpmachine"]) != "x86_64-w64-mingw32":
                    raise BuildError("host_raw_compiler_target_invalid")
            for item in pin["inputs"]:
                archive = work / (item["name"] + ".tar.gz")
                download(item["url"], archive, item["sha256"])
                unpacked = work / (item["name"] + "-unpacked")
                unpacked.mkdir()
                with tarfile.open(archive) as contents:
                    contents.extractall(unpacked, filter="data")
                roots = list(unpacked.iterdir())
                if len(roots) != 1 or not roots[0].is_dir():
                    raise BuildError("host_raw_archive_root_invalid")
                target = (
                    work / "lensfun"
                    if item["name"] == "lensfun"
                    else work / "darktable" / item["path"]
                )
                if target.exists():
                    if not target.is_dir() or any(target.iterdir()):
                        raise BuildError("host_raw_archive_target_populated")
                    target.rmdir()
                target.parent.mkdir(parents=True, exist_ok=True)
                roots[0].rename(target)
            for name, value in patches.items():
                patch = work / name
                patch.write_bytes(value)
                command([tools["python3"], patch, work / "darktable"])
            raw = work / "libraw"
            raw.mkdir()
            command([git, "init", raw])
            command(
                [
                    git,
                    "-C",
                    raw,
                    "fetch",
                    "--depth=1",
                    "https://github.com/LibRaw/LibRaw.git",
                    libraw["revision"],
                ]
            )
            command([git, "-C", raw, "checkout", "--detach", "FETCH_HEAD"])
            if command([git, "-C", raw, "rev-parse", "HEAD"]) != libraw["revision"]:
                raise BuildError("host_raw_libraw_revision_mismatch")
            if windows:
                report["windowsLibRawWideInput"] = use_windows_libraw_wide_input(
                    raw / "samples/dcraw_emu.cpp"
                )
            command([tools["autoreconf"], "--install",
                     *(["--force", "-I", "m4", "-I", (dependencies / "share/aclocal").as_posix()] if windows else [])], raw)
            command(
                [
                    raw / "configure",
                    "--prefix=" + str(prefix),
                    "--enable-examples",
                    "--disable-static",
                    *(["--host=x86_64-w64-mingw32", "LIBS=-lshell32"] if windows else []),
                ],
                raw,
            )
            if "-DUSE_JPEG" not in (raw / "Makefile").read_text():
                raise BuildError("host_raw_jpeg_decoder_missing")
            command([tools["make"], "-j1"], raw)
            command([tools["make"], "install"], raw)
            cmake = tools["cmake"]
            command(
                [
                    cmake,
                    "-S",
                    work / "lensfun",
                    "-B",
                    work / "lensfun-build",
                    "-G",
                    "Ninja",
                    "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DCMAKE_INSTALL_PREFIX=" + str(prefix),
                    "-DCMAKE_INSTALL_LIBDIR=lib",
                    "-DINSTALL_HELPER_SCRIPTS=OFF",
                    "-DINSTALL_PYTHON_MODULE=OFF",
                    # This pinned Lensfun revision discovers Python even with helper installation disabled.
                    "-DPYTHON:FILEPATH=OFF",
                    "-DBUILD_DOC=OFF",
                    "-DBUILD_TESTS=OFF",
                    *(["-DHAVE_REGEX_H=OFF", "-DCMAKE_INSTALL_DATAROOTDIR:PATH=share",
                       "-DLENSFUN_WINDOWS_DATADIR:PATH=../share/lensfun"] if windows else []),
                ]
            )
            command([cmake, "--build", work / "lensfun-build", "--parallel", "1"])
            command([cmake, "--install", work / "lensfun-build"])
            if windows:
                report["windowsLensfunPackaging"] = use_pinned_windows_lensfun_database(
                    work / "darktable/cmake/windows-macros.cmake", prefix
                )
            flags = [
                "BINARY_PACKAGE_BUILD=ON",
                "RAWSPEED_ENABLE_WERROR=OFF",
                "USE_LIBRAW=ON",
                "DONT_USE_INTERNAL_LIBRAW=ON",
                "USE_OPENMP=ON",
            ]
            flags += [
                name + "=OFF"
                for name in [
                    "USE_OPENCL",
                    "USE_AI",
                    "USE_CAMERA_SUPPORT",
                    "USE_COLORD",
                    "USE_MAP",
                    "USE_LUA",
                    "USE_KWALLET",
                    "USE_LIBSECRET",
                    "USE_GRAPHICSMAGICK",
                    "USE_IMAGEMAGICK",
                    "USE_PORTMIDI",
                    "USE_OPENJPEG",
                    "USE_JXL",
                    "USE_WEBP",
                    "USE_AVIF",
                    "USE_HEIF",
                    "USE_XCF",
                    "USE_OPENEXR",
                    "USE_GMIC",
                    "USE_ICU",
                    "USE_SDL2",
                    "USE_MAC_INTEGRATION",
                    "BUILD_PRINT",
                    "BUILD_CMSTEST",
                    "BUILD_RS_IDENTIFY",
                    "BUILD_TESTING",
                ]
            ]
            if platform.system() == "Darwin":
                omp = dependencies / "opt/libomp"
                for language in ["C", "CXX"]:
                    flags += [
                        f"OpenMP_{language}_FLAGS=-Xpreprocessor -fopenmp -I{omp / 'include'}",
                        f"OpenMP_{language}_LIB_NAMES=omp",
                    ]
                flags += ["OpenMP_omp_LIBRARY=" + str(omp / "lib/libomp.dylib")]
            command(
                [
                    cmake,
                    "-S",
                    work / "darktable",
                    "-B",
                    work / "darktable-build",
                    "-G",
                    "Ninja",
                    "-DPROJECT_VERSION=" + pin["version"],
                    "-DCMAKE_C_FLAGS=-I" + str(prefix / "include"),
                    "-DCMAKE_CXX_FLAGS=-I" + str(prefix / "include"),
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DCMAKE_INSTALL_PREFIX=" + str(prefix),
                    "-DCMAKE_INSTALL_LIBDIR=lib",
                    f"-DCMAKE_PREFIX_PATH={prefix};{dependencies}",
                    f"-DCMAKE_INSTALL_RPATH={prefix / 'lib/darktable'};{prefix / 'lib'};{dependencies / 'lib'}",
                    *["-D" + flag for flag in flags],
                ]
            )
            cache = (work / "darktable-build/CMakeCache.txt").read_text()
            if not re.search(
                r"^libraw_LIBRARY:FILEPATH=" + re.escape((prefix / "lib").as_posix()) + "/",
                cache,
                re.MULTILINE,
            ):
                raise BuildError("host_raw_libraw_linkage_not_pinned")
            command([cmake, "--build", work / "darktable-build", "--parallel", "1"])
            command([cmake, "--install", work / "darktable-build"])
            report.update(stage_raw(prefix, work, output, command, dependencies))
            report["qualification"] = "passed"
        finally:
            (output / "qualification.json").write_text(
                json.dumps(report, indent=2) + "\n"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source", "revision", "dependency-prefix", "output"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        build(
            Path(args.source),
            args.revision,
            Path(args.dependency_prefix),
            Path(args.output),
        )
    except (BuildError, OSError, ValueError, tarfile.TarError) as error:
        parser.exit(
            1, str(error) if isinstance(error, BuildError) else "host_raw_build_failed"
        )
