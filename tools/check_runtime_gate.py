"""A runtime pack's interpreter started exactly as the app starts it, each probe must finish.

Run with the pack's own interpreter: `<payload>/python/python.exe -I -B check_runtime_gate.py`.

The app starts every runtime through its gate program (`GATE` in src-tauri/src/native_runtime.rs,
read from there): it waits for the start line on its standard input, then watches that pipe, which
the app holds open for as long as the runtime runs. On Windows the watch used to keep a read of the
pipe pending, and importing onnxruntime then waited behind it forever (FD-71). Each probe runs in
that gate with the pipe held open and in the app's environment, and must exit within 120 seconds; a
plain start is reported beside it for comparison. A stuck probe prints where it is stuck.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

PROBES = {
    "onnxruntime": "import onnxruntime",
    # The C runtime's lock on descriptor 0, which a pending read held (lseek takes it).
    "standard input": "import os, time\ntime.sleep(1)\ntry: os.lseek(0, 0, 1)\nexcept OSError: pass\nos.fstat(0)",
    # A child inherits the standard input; Python asks what it is as it starts. `-B`, as the app
    # starts it: the pack's files are signed, and a compiled module rewritten breaks them.
    "child process": "import subprocess, sys; subprocess.run([sys.executable, '-I', '-B', '-c', 'pass'], check=True)",
}
SECONDS = 120


def gate_program() -> str:
    source = (Path(__file__).resolve().parent.parent / "src-tauri" / "src" / "native_runtime.rs").read_text(encoding="utf-8")
    return re.search(r'const GATE: &str = r#"(.*?)"#;', source, re.S).group(1)


def app_environment(scratch: str, folders: list[Path] = ()) -> dict[str, str]:
    """What `VerifiedRuntime::launch` gives a runtime (src-tauri/src/native_runtime.rs): nothing
    inherited; on Windows the OS directory (and the pack's library folders, if given)."""
    environment = {
        "FRAMELEAF_ML_AUTH_TOKEN": "0" * 64,
        "TMP": scratch,
        "TEMP": scratch,
        "TMPDIR": scratch,
        "XDG_CACHE_HOME": str(Path(scratch) / "cache"),
        "HF_HOME": str(Path(scratch) / "huggingface"),
        "TORCH_HOME": str(Path(scratch) / "torch"),
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "MACHINE_LEARNING_MODEL_INTRA_OP_THREADS": "4",
        "MACHINE_LEARNING_MODEL_INTER_OP_THREADS": "1",
        "MACHINE_LEARNING_REQUEST_THREADS": "1",
    }
    if os.name == "nt":
        system = Path(os.environ["SystemRoot"]) / "System32"
        environment["SystemRoot"] = os.environ["SystemRoot"]
        environment["PATH"] = os.pathsep.join(str(folder) for folder in [system, *folders])
    else:
        environment["PATH"] = "/usr/bin:/bin"
    return environment


def run_probes(probes: dict[str, str], folders: list[Path] = ()) -> dict:
    """Each probe in the gate (the pipe held open) and plainly, in the app's environment."""
    gate = gate_program()
    results = {}
    for name, statement in probes.items():
        for gated in (True, False):
            setup = f"import faulthandler; faulthandler.dump_traceback_later({SECONDS - 20}, exit=True)"
            program = [sys.executable, "-I", "-B", "-c", gate] if gated else [sys.executable, "-I", "-B", "-m"]
            with tempfile.TemporaryDirectory() as scratch:
                started = time.perf_counter()
                process = subprocess.Popen(
                    program + ["timeit", "-n", "1", "-r", "1", "-s", setup, statement],
                    cwd=scratch,
                    env=app_environment(scratch, list(folders)),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                collected: list[bytes] = []
                reader = threading.Thread(target=lambda: collected.append(process.stderr.read()), daemon=True)
                reader.start()
                process.stdin.write(b"frameleaf-native-start\n")
                process.stdin.flush()
                try:
                    code = process.wait(timeout=SECONDS)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    code = None
                reader.join(10)
                process.stdin.close()
                errors = b"".join(collected).decode("utf-8", "replace")
                results[f"{name} ({'gate' if gated else 'plain'})"] = {
                    "seconds": round(time.perf_counter() - started, 1),
                    "exit": code,
                    "errors": (f"no exit after {SECONDS} seconds: " if code is None else "") + errors[-3000:],
                }
    return results


def problems(results: dict) -> list[str]:
    """Started as the app starts a runtime, every probe must finish; the plain start only compares."""
    return [
        f"started as the app starts the runtime, '{name}' did not finish (exit {result['exit']}): {result['errors'][-1500:].strip()}"
        for name, result in results.items()
        if name.endswith("(gate)") and result["exit"] != 0
    ]


def main() -> None:
    results = run_probes(PROBES)
    print(json.dumps(results, indent=2))
    found = problems(results)
    if found:
        raise SystemExit("\n".join(found))
    print("runtime gate ok")


if __name__ == "__main__":
    main()
