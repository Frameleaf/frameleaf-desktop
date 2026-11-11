"""Offline candidate preparation and synthetic Qwen vision qualification.

This tool never enrolls a provider or produces a release trust record.
"""
import argparse
import base64
import hashlib
import http.client
import importlib.metadata
import json
import os
import platform
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path

SOURCE = "851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a"
LLAMA = "7fe450e19305b828c199d602c23a8337aaa1f03b"
EXPORT = "e87f176479d0855a907a41277aca2f8ee7a09523"
EXPORTED_FILES = {
    "model": (2740937888, "00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4"),
    "projector": (672423616, "cd88edcf8d031894960bb0c9c5b9b7e1fea6ebee02b9f7ce925a00d12891f864"),
}
SOURCE_FILES = (
    "LICENSE", "chat_template.jinja", "config.json", "merges.txt",
    "model.safetensors-00001-of-00002.safetensors",
    "model.safetensors-00002-of-00002.safetensors",
    "model.safetensors.index.json", "preprocessor_config.json", "tokenizer.json",
    "tokenizer_config.json", "video_preprocessor_config.json", "vocab.json",
)
SCHEMA = {
    "type": "object",
    "properties": {"description": {"type": "string", "maxLength": 240}},
    "required": ["description"],
    "additionalProperties": False,
}
DESCRIPTION_TASK = "image-description-tagging"
LIMIT = 64 * 1024


def artifact(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected a regular artifact")
    with path.open("rb") as file:
        return {"bytes": path.stat().st_size, "sha256": hashlib.file_digest(file, "sha256").hexdigest()}


def checked_artifact(path, expected):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != expected[0]:
        raise ValueError("Artifact size does not match its receipt")
    value = artifact(path)
    if value["sha256"] != expected[1]:
        raise ValueError("Artifact digest does not match its receipt")
    return value


def synthetic_png(color, circle):
    size = 128
    raw = bytearray()
    for y in range(size):
        raw.append(0)
        for x in range(size):
            inside = (x - 64) ** 2 + (y - 64) ** 2 <= 35**2 if circle else 30 <= x < 98 and 30 <= y < 98
            raw.extend(color if inside else (255, 255, 255))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def request_body(image, *, stream=False):
    prompt = (
        "Identify the color and geometric shape in this image. Return one factual sentence."
        if not stream else
        "Describe the color and shape and then explain in detail what visual evidence led to your answer."
    )
    return {
        "messages": [{
            "role": "user",
            "content": [
                {"type": "image_url", "image_url": {"url": "data:image/png;base64," + base64.b64encode(image).decode("ascii")}},
                {"type": "text", "text": prompt},
            ],
        }],
        "chat_template_kwargs": {"enable_thinking": False},
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "description", "strict": True, "schema": SCHEMA},
        },
        "temperature": 0,
        "seed": 31,
        "max_tokens": 96 if not stream else 256,
        "stream": stream,
    }


def unique_fields(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON field")
    return result


def worker_output(raw):
    """Project a bounded model description onto Library's existing worker result."""
    if len(raw) > LIMIT:
        raise ValueError("Oversized inference response")
    envelope = json.loads(raw, object_pairs_hook=unique_fields)
    choices = envelope.get("choices") if isinstance(envelope, dict) else None
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise ValueError("Missing inference choice")
    choice = choices[0]
    message = choice.get("message")
    if choice.get("finish_reason") != "stop" or not isinstance(message, dict) or any(
        message.get(field) for field in ("reasoning", "reasoning_content", "tool_calls", "function_call")
    ):
        raise ValueError("Incomplete or non-description inference")
    content = message.get("content")
    if not isinstance(content, str) or len(content.encode("utf-8")) > 2048:
        raise ValueError("Invalid inference content")
    value = json.loads(content, object_pairs_hook=unique_fields)
    if not isinstance(value, dict) or set(value) != {"description"}:
        raise ValueError("Unexpected description fields")
    description = value["description"]
    if (
        not isinstance(description, str) or not description.strip() or len(description) > 240
        or re.search(r"[\x00-\x1f\x7f]|<\s*/?\s*think\b", description, re.IGNORECASE)
    ):
        raise ValueError("Invalid description text")
    return {DESCRIPTION_TASK: {
        "description": description.strip(), "people": [], "environment": "",
        "objects": [], "visible_text": [], "context": "", "tags": [],
    }}


def git_bytes(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], timeout=20)


def verify_source(repo):
    if git_bytes(repo, "rev-parse", "HEAD").decode().strip() != SOURCE:
        raise ValueError("The Qwen checkout must match the pinned revision")
    records = {}
    for name in SOURCE_FILES:
        blob = git_bytes(repo, "show", f"{SOURCE}:{name}")
        if blob.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
            fields = dict(line.split(" ", 1) for line in blob.decode().splitlines()[1:])
            records[name] = checked_artifact(repo / name, (int(fields["size"]), fields["oid"].removeprefix("sha256:")))
        else:
            records[name] = checked_artifact(repo / name, (len(blob), hashlib.sha256(blob).hexdigest()))
    return records


def convert(source, llama, quantizer, output):
    if output.exists() or shutil.disk_usage(output.parent).free < 24 * 1024**3:
        raise ValueError("Conversion needs a new output directory and at least 24 GiB free")
    if git_bytes(llama, "rev-parse", "HEAD").decode().strip() != LLAMA or git_bytes(
        llama, "status", "--porcelain", "--untracked-files=normal"
    ):
        raise ValueError("The converter checkout must be clean and match the pinned revision")
    source_files = verify_source(source)
    quantizer_receipt = artifact(quantizer)
    output.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="conversion-", dir=output) as directory:
        scratch = Path(directory)
        # The converter sees exactly the verified inputs, with no adjacent files.
        inputs = scratch / "source"
        inputs.mkdir()
        for name in SOURCE_FILES:
            os.link(source / name, inputs / name)
        environment = {
            "PATH": os.defpath, "HOME": str(scratch), "TMPDIR": str(scratch), "LC_ALL": "C",
            "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_HOME": str(scratch / "hf"),
        }
        convert_script = [sys.executable, str(llama / "convert_hf_to_gguf.py"), str(inputs)]
        fp16 = scratch / "source-bf16.gguf"
        subprocess.run(
            [*convert_script, "--outtype", "bf16", "--outfile", str(fp16)],
            check=True, timeout=900, env=environment, cwd=llama,
        )
        quantized = subprocess.check_output(
            [str(quantizer), str(fp16), str(output / "model.gguf"), "Q4_K_M", "2"],
            timeout=900, env=environment, cwd=llama, stderr=subprocess.STDOUT,
        )
        if LLAMA[:9].encode() not in quantized:
            raise ValueError("Quantizer did not report the pinned source revision")
        subprocess.run(
            [*convert_script, "--mmproj", "--outtype", "f16", "--outfile", str(output / "mmproj.gguf")],
            check=True, timeout=900, env=environment, cwd=llama,
        )
    shutil.copyfile(source / "LICENSE", output / "LICENSE")
    receipt = {
        "schemaVersion": 1, "sourceRevision": SOURCE, "converterRevision": LLAMA,
        "sourceFiles": source_files, "quantizer": quantizer_receipt,
        "host": {"os": platform.system(), "architecture": platform.machine()},
        "python": platform.python_version(),
        "pythonPackages": dict(sorted((item.metadata["Name"], item.version) for item in importlib.metadata.distributions())),
        "artifacts": {name: artifact(output / name) for name in ("model.gguf", "mmproj.gguf", "LICENSE")},
        "releaseQualified": False,
    }
    with (output / "candidate.json").open("x") as file:
        json.dump(receipt, file, indent=2)


def converted_artifacts(receipt):
    with receipt.open("rb") as file:
        raw = file.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("Oversized conversion receipt")
    value = json.loads(raw, object_pairs_hook=unique_fields)
    if (
        not isinstance(value, dict) or value.get("schemaVersion") != 1 or
        value.get("sourceRevision") != SOURCE or value.get("converterRevision") != LLAMA or
        value.get("releaseQualified") is not False
    ):
        raise ValueError("Unexpected conversion receipt")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {"model.gguf", "mmproj.gguf", "LICENSE"}:
        raise ValueError("Conversion artifact inventory is incomplete")
    expected = {}
    for name, file in (("model", "model.gguf"), ("projector", "mmproj.gguf")):
        record = artifacts[file]
        if (
            not isinstance(record, dict) or type(record.get("bytes")) is not int
            or not 0 < record["bytes"] <= 8 * 1024**3
            or not isinstance(record.get("sha256"), str)
            or re.fullmatch("[a-f0-9]{64}", record["sha256"]) is None
        ):
            raise ValueError("Invalid conversion artifact receipt")
        expected[name] = record["bytes"], record["sha256"]
    return expected


def free_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def request_local(port, path, token, *, body=None, timeout=20):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(
            "GET" if body is None else "POST", path,
            None if body is None else json.dumps(body),
            {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        return connection, connection.getresponse()
    except BaseException:
        connection.close()
        raise


def stop(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        except ProcessLookupError:
            process.wait(timeout=5)


def qualify(binary, model, projector, backend, output, receipt=None):
    if os.name != "posix" or (backend == "metal" and sys.platform != "darwin"):
        raise ValueError("Expected a POSIX host with the requested backend")
    if output.exists():
        raise ValueError("Expected a new qualification report")
    paths = {"model": model, "projector": projector}
    inventory = converted_artifacts(receipt) if receipt else EXPORTED_FILES
    checked = {name: checked_artifact(paths[name], expected) for name, expected in inventory.items()}
    binary_receipt = artifact(binary)
    fixtures = [
        ("red", "square", synthetic_png((224, 24, 32), False)),
        ("blue", "circle", synthetic_png((20, 70, 234), True)),
    ]
    records = []
    with tempfile.TemporaryDirectory(prefix="frameleaf-qwen-") as directory:
        scratch = Path(directory)
        environment = {"HOME": directory, "PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        key_file = scratch / "key"
        token = os.urandom(32).hex()
        key_file.write_text(token + "\n")
        key_file.chmod(0o600)
        port = free_port()
        log_file = scratch / "runtime.log"
        with log_file.open("wb") as log:
            process = subprocess.Popen([
                str(binary), "--host", "127.0.0.1", "--port", str(port), "--offline",
                "--api-key-file", str(key_file), "--no-webui", "--no-ui-mcp-proxy", "--no-warmup",
                "-m", str(model), "--mmproj", str(projector), "--ctx-size", "4096",
                "--threads", "4", "--parallel", "1", "--batch-size", "128", "--ubatch-size", "128",
                "--n-gpu-layers", "0" if backend == "cpu" else "99",
                *(["--no-mmproj-offload"] if backend == "cpu" else []),
                "--reasoning", "off", "--reasoning-budget", "0",
            ], env=environment, cwd=scratch,
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    connection, response = request_local(port, "/health", token, timeout=1)
                    connection.close()
                    if response.status == 200:
                        break
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.1)
            else:
                raise ValueError("Qwen did not become ready within 45 seconds")
            connection, response = request_local(port, "/props", token)
            try:
                data = response.read(LIMIT + 1)
                if response.status != 200 or len(data) > LIMIT:
                    raise ValueError("The runtime identity could not be read")
                build = json.loads(data).get("build_info", "")
                if not isinstance(build, str) or re.fullmatch(r"b[0-9]+-" + LLAMA[:9] + r"[a-f0-9]*", build) is None:
                    raise ValueError("Expected the pinned llama.cpp build")
            finally:
                connection.close()
            for color, shape, image in fixtures:
                connection, response = request_local(port, "/v1/chat/completions", token, body=request_body(image), timeout=30)
                try:
                    if response.status != 200:
                        raise ValueError(f"Qwen returned HTTP {response.status}")
                    result = worker_output(response.read(LIMIT + 1))
                finally:
                    connection.close()
                text = result[DESCRIPTION_TASK]["description"]
                if not all(re.search(rf"\b{word}\b", text, re.IGNORECASE) for word in (color, shape)):
                    raise ValueError(f"Golden photo description mismatch: {text}")
                records.append({"fixtureSha256": hashlib.sha256(image).hexdigest(), "description": text})
            # Wait for the server's streaming headers, then stop the owned group with that
            # request outstanding. No streamed fragments are committed to a caller.
            connection, stream = request_local(port, "/v1/chat/completions", token, body=request_body(fixtures[0][2], stream=True))
            try:
                if stream.status != 200 or stream.headers.get_content_type() != "text/event-stream":
                    raise ValueError("Expected a streaming response for the cancellation fixture")
                stop(process)
                try:
                    tail = stream.read(LIMIT + 1)
                except (OSError, http.client.HTTPException):
                    tail = b""
                if b"data: [DONE]" in tail:
                    raise ValueError("The cancellation request completed before termination")
            finally:
                connection.close()
        finally:
            stop(process)
        log = log_file.read_text(errors="replace")
        backend_evidence = [
            line[:200] for line in log.splitlines()
            if re.search(r"offload|metal|model buffer size", line, re.IGNORECASE)
        ][:24]
        verified_backend = "metal" if (
            backend == "metal"
            and re.search(r"offloaded [1-9][0-9]*/[0-9]+ layers to GPU", log)
            and re.search(r"metal", log, re.IGNORECASE)
        ) else None
    with output.open("x") as file:
        json.dump({
            "schemaVersion": 1, "scope": "synthetic-local-component", "releaseQualified": False,
            "modelProvenance": {"conversionReceipt": artifact(receipt)} if receipt else {"exportRevision": EXPORT},
            "runtimeRevision": LLAMA, "build": build, "binary": binary_receipt,
            "requestedBackend": backend, "verifiedBackend": verified_backend, "backendEvidence": backend_evidence,
            "artifacts": checked, "goldens": records, "cancelled": True,
            "processExited": process.returncode is not None,
        }, file, indent=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("convert")
    for name in ("source", "llama", "quantizer", "output"):
        prepare.add_argument(f"--{name}", type=Path, required=True)
    run = commands.add_parser("qualify")
    for name in ("binary", "model", "projector", "output"):
        run.add_argument(f"--{name}", type=Path, required=True)
    run.add_argument("--backend", choices=["cpu", "metal"], required=True)
    run.add_argument("--receipt", type=Path, help="Local conversion receipt; otherwise use the pinned third-party export")
    args = parser.parse_args()
    if args.command == "convert":
        convert(*(getattr(args, name).absolute() for name in ("source", "llama", "quantizer", "output")))
    else:
        qualify(args.binary.absolute(), args.model.absolute(), args.projector.absolute(), args.backend, args.output.absolute(), args.receipt)


if __name__ == "__main__":
    main()
