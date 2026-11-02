"""Stage source-pinned portable FFmpeg binaries and exercise CPU codecs; authoring only."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import shutil
import stat
import struct
import tarfile
import tomllib
import zipfile
from pathlib import Path

from build_host_database import download
from build_host_plugin import tool_pin
from build_host_server import stage_server
from build_runtime import BuildError, build_environment, git_blob, regular, relative, run, sha256
from relocate_macos import apple_library, load_commands


def ffmpeg_contract(lock: dict, descriptor: dict, target: str) -> dict:
    entries = [
        entry
        for entry in lock.get("tools", {}).get("github:jellyfin/jellyfin-ffmpeg", [])
        if "platforms." + target in entry
    ]
    version = descriptor.get("version", "")
    if (
        descriptor.get("name") != "ffmpeg"
        or not re.fullmatch(r"\d+\.\d+\.\d+-\d+", version)
        or len(entries) != 1
        or entries[0].get("version") != version
    ):
        raise BuildError("host_ffmpeg_source_pin_mismatch")
    pin = tool_pin(lock, "jellyfin/jellyfin-ffmpeg", target)
    if "/releases/download/v" + version + "/" not in pin["url"]:
        raise BuildError("host_ffmpeg_source_pin_mismatch")
    return pin


def unpack(archive: Path, destination: Path) -> None:
    """Validate the entire bounded, link-free archive before writing into an empty directory."""
    if (not stat.S_ISREG(regular(archive).st_mode)
            or not stat.S_ISDIR(regular(destination).st_mode)
            or any(destination.iterdir())):
        raise BuildError("host_ffmpeg_archive_paths_invalid")

    def validate(entries):
        names = {}
        total = 0
        for count, (name, directory, size) in enumerate(entries, 1):
            name = relative(name[:-1] if name.endswith("/") else name).casefold()
            total += size
            if count > 100_000 or size < 0 or total > 2 * 1024**3:
                raise BuildError("host_ffmpeg_archive_limit")
            if name in names:
                raise BuildError("host_ffmpeg_archive_entry_invalid")
            names[name] = directory
        for name in names:
            parents = name.split("/")[:-1]
            if any(names.get("/".join(parents[:index])) is False
                   for index in range(1, len(parents) + 1)):
                raise BuildError("host_ffmpeg_archive_entry_invalid")

    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as contents:
            entries = contents.infolist()
            for entry in entries:
                mode = stat.S_IFMT(entry.external_attr >> 16)
                if (mode not in (0, stat.S_IFREG, stat.S_IFDIR)
                        or mode == stat.S_IFDIR and not entry.is_dir()
                        or mode == stat.S_IFREG and entry.is_dir()):
                    raise BuildError("host_ffmpeg_archive_entry_invalid")
            validate((entry.filename, entry.is_dir(), entry.file_size) for entry in entries)
            contents.extractall(destination)
    else:
        with tarfile.open(archive) as contents:
            def entries():
                for entry in contents:
                    if not (entry.isfile() or entry.isdir()):
                        raise BuildError("host_ffmpeg_archive_entry_invalid")
                    yield entry.name, entry.isdir(), entry.size
            validate(entries())
            contents.extractall(destination, filter="data")


def qualify(ffmpeg: Path, ffprobe: Path, work: Path, env: dict) -> dict:
    def encode(arguments: list) -> None:
        run(
            [ffmpeg, "-hide_banner", "-v", "error", "-nostdin", "-y", *arguments],
            cwd=work,
            env=env,
        )

    def probe(path: Path) -> dict:
        return json.loads(
            run(
                [
                    ffprobe,
                    "-v",
                    "error",
                    "-show_streams",
                    "-show_format",
                    "-of",
                    "json",
                    path,
                ],
                cwd=work,
                env=env,
            )
        )

    sample = work / "synthetic.mp4"
    encode(
        [
            "-f",
            "lavfi",
            "-i",
            "smptebars=size=96x64:rate=12",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=1000:sample_rate=48000",
            "-t",
            "0.5",
            "-c:v",
            "libx264",
            "-threads",
            "2",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
            sample,
        ]
    )
    outputs = [("h264", "aac", sample)]
    for video, audio, encoder, filename, extra in [
        ("vp9", "opus", "libvpx-vp9", "synthetic.webm", []),
        (
            "hevc",
            "aac",
            "libx265",
            "synthetic-hevc.mp4",
            ["-preset", "ultrafast", "-x265-params", "pools=1:frame-threads=1"],
        ),
        (
            "av1",
            "opus",
            "libsvtav1",
            "synthetic-av1.mkv",
            ["-preset", "12", "-svtav1-params", "lp=2"],
        ),
    ]:
        destination = work / filename
        encode(
            [
                "-i",
                sample,
                "-c:v",
                encoder,
                "-threads",
                "2",
                *extra,
                "-c:a",
                "libopus" if audio == "opus" else "aac",
                destination,
            ]
        )
        outputs.append((video, audio, destination))
    fixtures = []
    for video, audio, path in outputs:
        facts = probe(path)
        streams = facts["streams"]
        videos = [stream for stream in streams if stream["codec_type"] == "video"]
        audios = [stream for stream in streams if stream["codec_type"] == "audio"]
        if (
            len(videos) != 1
            or len(audios) != 1
            or videos[0]["codec_name"] != video
            or audios[0]["codec_name"] != audio
            or (videos[0]["width"], videos[0]["height"]) != (96, 64)
            or not 0.4 <= float(facts["format"]["duration"]) <= 1
        ):
            raise BuildError("host_ffmpeg_codec_fixture_failed")
        thumbnail = work / (video + "-thumbnail.png")
        encode(["-i", path, "-frames:v", "1", "-vf", "scale=16:12", thumbnail])
        dimensions = probe(thumbnail)["streams"][0]
        if dimensions["codec_name"] != "png" or (
            dimensions["width"],
            dimensions["height"],
        ) != (16, 12):
            raise BuildError("host_ffmpeg_thumbnail_fixture_failed")
        pcm = work / (video + "-decoded-audio.pcm")
        encode(["-i", path, "-vn", "-ac", "1", "-ar", "48000", "-f", "s16le", pcm])
        if not 38_400 <= pcm.stat().st_size <= 96_000 or pcm.stat().st_size % 2:
            raise BuildError("host_ffmpeg_audio_decode_failed")
        samples = [value[0] for value in struct.iter_unpack("<h", pcm.read_bytes())]
        rms = math.sqrt(sum(value * value for value in samples) / len(samples))
        if rms < 100:
            raise BuildError("host_ffmpeg_audio_decode_failed")
        fixtures.append(
            {
                "video": video,
                "audio": audio,
                "sha256": sha256(path),
                "thumbnailSha256": sha256(thumbnail),
                "audioPcmSha256": sha256(pcm),
                "decodedAudioSamples": len(samples),
                "decodedAudioRms": round(rms, 2),
                "width": 96,
                "height": 64,
            }
        )
    return {
        "qualification": "passed",
        "fixtures": fixtures,
        "scope": "synthetic CPU encode/decode/probe/thumbnail only",
        "fullMediaConformance": False,
    }


def build(source: Path, revision: str, output: Path) -> None:
    if not re.fullmatch("[0-9a-f]{40}", revision) or not all(
        path.is_absolute() for path in [source, output]
    ):
        raise BuildError("host_ffmpeg_source_invalid")
    if output.exists() or output.is_symlink():
        raise BuildError("host_ffmpeg_output_invalid")
    git = shutil.which("git")
    systems = {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}
    machines = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "AMD64": "x64"}
    if (
        not git
        or platform.system() not in systems
        or platform.machine() not in machines
    ):
        raise BuildError("host_ffmpeg_build_target_unsupported")
    target = systems[platform.system()] + "-" + machines[platform.machine()]
    output.mkdir(mode=0o700)
    work = output / "work"
    work.mkdir(mode=0o700)
    env = build_environment(work, os.environ)
    env["FRAMELEAF_BUILD_ERROR_LOG"] = str(output / "command-error.log")
    locked = git_blob(git, source, revision, "mise.lock", env)
    described = git_blob(
        git, source, revision, "server/base-image/packages/ffmpeg.json", env
    )
    descriptor = json.loads(described)
    pin = ffmpeg_contract(tomllib.loads(locked.decode()), descriptor, target)
    report = {
        "schemaVersion": 1,
        "sourceRevision": revision,
        "platform": target,
        "sourceLockfileSha256": hashlib.sha256(locked).hexdigest(),
        "serverDescriptorSha256": hashlib.sha256(described).hexdigest(),
        "version": descriptor["version"],
        "archive": pin,
        "qualification": "failed",
        "redistributable": False,
        "installedPlatformQualified": False,
    }
    try:
        archive = work / "ffmpeg.archive"
        download(pin["url"], archive, pin["checksum"][7:])
        extracted = work / "extracted"
        extracted.mkdir(mode=0o700)
        unpack(archive, extracted)
        payload = output / "media"
        stage_server(extracted, payload)
        binaries = {}
        for name in ["ffmpeg", "ffprobe"]:
            matches = list(payload.rglob(name + (".exe" if os.name == "nt" else "")))
            if len(matches) != 1 or not matches[0].is_file():
                raise BuildError("host_ffmpeg_binary_missing_or_ambiguous")
            binaries[name] = matches[0]
            matches[0].chmod(0o700)
        report["entryPoints"] = {
            name: path.relative_to(payload).as_posix()
            for name, path in binaries.items()
        }
        report["binaryVersions"] = {}
        for name, path in binaries.items():
            version = run([path, "-version"], cwd=work, env=env).splitlines()[0]
            if not re.match(
                r"^"
                + name
                + r" version "
                + re.escape(descriptor["version"].rsplit("-", 1)[0])
                + r"(?:[- ]|$)",
                version,
            ):
                raise BuildError("host_ffmpeg_version_mismatch")
            report["binaryVersions"][name] = version
        if platform.system() == "Darwin":
            for path in binaries.values():
                if run(
                    ["/usr/bin/lipo", "-archs", path], cwd=work, env=env
                ).split() != [platform.machine()]:
                    raise BuildError("host_ffmpeg_architecture_mismatch")
                _, dependencies, paths = load_commands(
                    run(["/usr/bin/otool", "-l", path], cwd=work, env=env)
                )
                if paths or not all(
                    apple_library(reference) for reference in dependencies
                ):
                    raise BuildError("host_ffmpeg_external_dependency")
                run(
                    ["/usr/bin/codesign", "--verify", "--strict", path],
                    cwd=work,
                    env=env,
                )
            report["macosLoadCommandAudit"] = "passed"
        report["codecQualification"] = qualify(
            binaries["ffmpeg"], binaries["ffprobe"], work, env
        )
        (payload / "FFMPEG-LICENSE.txt").write_text(
            run([binaries["ffmpeg"], "-L"], cwd=work, env=env) + "\n"
        )
        from build_runtime import inventory

        report["files"] = inventory(payload)
        report["qualification"] = "passed"
    finally:
        (output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source", "revision", "output"]:
        parser.add_argument("--" + name, required=True)
    options = parser.parse_args()
    try:
        build(Path(options.source), options.revision, Path(options.output))
    except (
        BuildError,
        OSError,
        ValueError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        parser.exit(
            1,
            str(error) if isinstance(error, BuildError) else "host_ffmpeg_build_failed",
        )
