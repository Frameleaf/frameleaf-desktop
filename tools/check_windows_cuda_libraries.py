"""Which NVIDIA libraries a Windows CUDA pack needs, against what it carries and what Windows finds.

Run with the pack's own interpreter:
`<pack>/payload/python/python.exe -I -B check_windows_cuda_libraries.py --pack <pack> --output <dir>`.

onnxruntime does not fail when a CUDA or cuDNN library cannot be loaded on Windows: it leaves the
CUDA provider out and the session runs on the processor. So what is missing has to be found
before that, and by name. Three checks, none of which needs an NVIDIA card:

1. The table. Starting from the CUDA provider library and the libraries onnxruntime preloads, every
   library they import (import table, delay-load table) or name in their own data (what they open
   later with `LoadLibrary`) is followed. Each NVIDIA library referenced must be in the pack,
   unless it is one of the few named in `ABSENT_BY_DESIGN` with the reason.
2. The loader. A fresh interpreter is started the way the app starts the runtime (no inherited
   environment, the search path the app gives it, another working directory). It runs the runtime's
   own `native_ort.configure`, asks cuDNN to load each of its parts, and opens by bare name every
   pack library that is only ever opened that way. Each must load, and from the pack.
3. The paths. Windows opens a library only below 260 characters. No native library of the pack may
   be deeper than what is left after the app's own install folder for a 20 character user name,
   and nothing the runtime imports may be.

`--session` (a computer with an NVIDIA card) also creates a CUDA session in that interpreter,
requires it to be on `CUDAExecutionProvider`, runs it and records the libraries then loaded.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe_imports import PortableExecutable  # noqa: E402

PROVIDER = "CUDAExecutionProvider"
PROVIDER_LIBRARY = "onnxruntime_providers_cuda.dll"
NVIDIA = re.compile(r"^(cudart|cudnn|cublas|cufft|curand|cusolver|cusparse|nvrtc|nvjitlink|nvblas|nvcuda|zlibwapi)", re.I)
NAMED = re.compile(rb"(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]{3,64}\.dll", re.I)
# Referenced by name, not in the pack, and not needed in it. Anything else that is absent fails.
ABSENT_BY_DESIGN = {
    "nvcuda.dll": "the NVIDIA driver's own library: only a computer with the driver has it",
    "zlibwapi.dll": "named in cuDNN's message about a failed load; no library in the pack imports it",
    "cudart64_13.dll": "the CUDA 13 name onnxruntime also tries; this build uses CUDA 12",
    "nvrtc64_130_0.dll": "the CUDA 13 name onnxruntime also tries; this build uses CUDA 12",
    "nvrtc64_131_0.dll": "the CUDA 13 name onnxruntime also tries; this build uses CUDA 12",
    "nvrtc-builtins.dll": "the name the run-time compiler's builtins library gives itself",
}
# `<profile>\AppData\Local\app.frameleaf.desktop\gpu\releases\<64 hex>\payload\`
# for a profile at `C:\Users\<20 characters>` (the longest local account name).
# `gpu` is `ACCELERATED_STORE` on Windows in src-tauri/src/provider_selection.rs.
INSTALL_PREFIX = len("C:\\Users\\") + 20 + len("\\AppData\\Local\\app.frameleaf.desktop\\gpu\\releases\\") + 64 + len("\\payload\\")
PATH_BUDGET = 259 - INSTALL_PREFIX


def references(library: Path) -> dict[str, list[str]]:
    """What a library needs: imported, delay-loaded, and named in its data (opened by name later)."""
    image = PortableExecutable(library)
    imported = sorted(image.imports(), key=str.lower)
    delayed = sorted(image.delayed(), key=str.lower)
    known = {name.lower() for name in imported + delayed} | {library.name.lower()}
    named = sorted({match.decode("ascii").lower() for match in NAMED.findall(image.data)} - known)
    return {"imported": imported, "delayed": delayed, "named": [name for name in named if NVIDIA.match(name)]}


def library_folders(site: Path) -> list[Path]:
    """The folders the app adds to the runtime's search path (`device_library_folders` in
    `src-tauri/src/native_runtime.rs`): `site-packages/nvidia/<component>/bin` with a library."""
    return sorted({library.parent for library in site.glob("nvidia/*/bin/*") if library.suffix.lower() == ".dll"})


def table(
    site: Path, start: list[str], optional: frozenset[str] = frozenset()
) -> tuple[list[dict[str, str]], list[str]]:
    """Rows of (library, how it refers, what to, where that is in the pack) and what is wrong.

    `optional` names starting libraries the pack may lack; nothing else may be absent."""
    pack = {}
    for folder in [site / "onnxruntime" / "capi", *library_folders(site)]:
        for library in sorted(folder.iterdir()) if folder.is_dir() else []:
            if library.suffix.lower() == ".dll":
                pack.setdefault(library.name.lower(), library)
    rows, problems, seen = [], [], set()
    queue = [name.lower() for name in start]
    for name in queue:
        if name not in pack and name not in optional:
            problems.append(f"{name} is not in the pack")
    while queue:
        name = queue.pop(0)
        if name in seen or name not in pack:
            continue
        seen.add(name)
        for kind, targets in references(pack[name]).items():
            for target in targets:
                lowered = target.lower()
                if not NVIDIA.match(lowered):
                    continue
                if lowered in pack:
                    where = pack[lowered].parent.relative_to(site).as_posix()
                    queue.append(lowered)
                elif lowered in ABSENT_BY_DESIGN and kind == "named":
                    where = f"absent by design: {ABSENT_BY_DESIGN[lowered]}"
                else:
                    where = "MISSING"
                    problems.append(f"{pack[name].name} needs {target} ({kind}), which is not in the pack")
                rows.append({"library": pack[name].name, "reference": kind, "needs": target, "pack": where})
    return rows, problems


def over_budget(names: list[str]) -> list[str]:
    return sorted(name for name in names if len(name) > PATH_BUDGET)


def child(site: Path, stage: str) -> dict:
    """Inside the interpreter started the way the app starts it.

    One stage per process, so one does not load what the next is looking for: `cudnn` has cuDNN
    load its own parts, `names` opens each library by name and imports the runtime, `session`
    is `names` and then a CUDA session."""
    import contextlib
    import ctypes
    import io
    import time
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetModuleHandleW.restype = wintypes.HMODULE
    kernel.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel.GetModuleFileNameW.argtypes = [wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]

    def loaded(name: str) -> str | None:
        handle = kernel.GetModuleHandleW(name)
        if not handle:
            return None
        buffer = ctypes.create_unicode_buffer(32768)
        kernel.GetModuleFileNameW(handle, buffer, len(buffer))
        return buffer.value

    result: dict = {"problems": [], "path": os.environ.get("PATH", "")}
    problems = result["problems"]
    from frameleaf_ml import native_ort

    printed = io.StringIO()
    started = time.perf_counter()
    with contextlib.redirect_stdout(printed):
        native_ort.configure(PROVIDER)
    result["preloadSeconds"] = round(time.perf_counter() - started, 2)
    result["preloadOutput"] = printed.getvalue().strip().splitlines()
    problems += [line for line in result["preloadOutput"] if "Failed to load" in line or "not installed" in line]
    import onnxruntime as ort

    rows, _ = table(site, start_libraries(ort))
    carried = sorted({row["needs"].lower() for row in rows if not row["pack"].startswith(("absent", "MISSING"))})
    result["afterPreload"] = {name: loaded(name) for name in carried}

    if stage == "cudnn":
        result["cudnn"] = cudnn_parts(problems)
        result["afterCudnn"] = {name: loaded(name) for name in carried}
        return result

    # What native code gets from LoadLibrary("<name>"): the standard search, as NVIDIA's libraries use.
    result["byName"] = {}
    for name in carried:
        try:
            ctypes.WinDLL(name, winmode=0)
            result["byName"][name] = loaded(name)
        except OSError as error:
            result["byName"][name] = None
            problems.append(f"{name} is in the pack but Windows does not find it by name: {error}")
    root = str(site.resolve()).lower()
    for name, where in result["byName"].items():
        if where is not None and not str(Path(where).resolve()).lower().startswith(root):
            problems.append(f"{name} was loaded from outside the pack: {where}")

    # The runtime's own modules: none may sit deeper than Windows opens without long-path support.
    payload = site.parents[2]
    try:
        import frameleaf_ml.main  # noqa: F401
    except Exception as error:  # the import is the check
        problems.append(f"the runtime's serving module does not import: {type(error).__name__}: {error}")
    deep = []
    for module in list(sys.modules.values()):
        origin = getattr(module, "__file__", None)
        if origin and Path(origin).resolve().is_relative_to(payload.resolve()):
            name = Path(origin).resolve().relative_to(payload.resolve()).as_posix()
            if len(name) > PATH_BUDGET:
                deep.append(name)
    result["importedOverBudget"] = sorted(deep)
    problems += [
        f"imported from a path too deep for Windows without long-path support ({len(name)} > {PATH_BUDGET}): {name}"
        for name in sorted(deep)
    ]

    if stage == "session":
        import numpy as np
        import onnx
        import psutil
        from onnx import TensorProto, helper, numpy_helper

        weights = np.arange(8, dtype=np.float32).reshape(2, 4)
        model = helper.make_model(
            helper.make_graph(
                [helper.make_node("MatMul", ["input", "weights"], ["output"])],
                "check",
                [helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 2])],
                [helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 4])],
                [numpy_helper.from_array(weights, name="weights")],
            ),
            opset_imports=[helper.make_opsetid("", 17)],
            ir_version=9,
        )
        feed = np.array([[1.0, 2.0]], dtype=np.float32)
        created = ort.InferenceSession(model.SerializeToString(), providers=[PROVIDER, "CPUExecutionProvider"])
        result["sessionProviders"] = created.get_providers()
        if created.get_providers()[:1] != [PROVIDER]:
            problems.append(f"the session is not on {PROVIDER}: {created.get_providers()} (onnxruntime fell back)")
        elif not np.allclose(created.run(None, {"input": feed})[0], feed @ weights):
            problems.append("the CUDA session returned a wrong result")
        interesting = re.compile(r"(cudart|cudnn|cublas|cufft|curand|nvrtc|nvjitlink|nvcuda|nvapi|onnxruntime)", re.I)
        result["loadedLibraries"] = sorted(
            {entry.path for entry in psutil.Process().memory_maps() if interesting.search(Path(entry.path).name)}
        )
    return result


def cudnn_parts(problems: list[str]) -> dict:
    """cuDNN opens its parts by name the first time each is used. These calls need no card; when
    a part is not found cuDNN ends the process, which the caller reports."""
    import ctypes

    parts: dict = {}
    try:
        cudnn = ctypes.WinDLL("cudnn64_9.dll", winmode=0)
        cudnn.cudnnGetVersion.restype = ctypes.c_size_t
        parts["version"] = cudnn.cudnnGetVersion()
        for part in ("Ops", "Cnn", "Adv", "Graph"):
            status = getattr(cudnn, f"cudnn{part}VersionCheck")()
            parts[part] = status
            if status != 0:
                problems.append(f"cuDNN could not use its {part} library (status {status})")
    except (OSError, AttributeError) as error:
        problems.append(f"cuDNN could not be opened by name: {error}")
    return parts


def start_libraries(ort) -> list[str]:
    """The provider library and what onnxruntime's own list preloads on Windows."""
    return [PROVIDER_LIBRARY] + [parts[-1] for parts in ort._get_nvidia_dll_paths(True, True, True)]


def app_environment(scratch: str, folders: list[Path], home: bool = True) -> dict[str, str]:
    """The environment `VerifiedRuntime::launch` gives the runtime on Windows
    (src-tauri/src/native_runtime.rs): nothing inherited. `folders` and `home` are what FD-63
    added to it."""
    system = Path(os.environ["SystemRoot"]) / "System32"
    environment = {
        "SystemRoot": os.environ["SystemRoot"],
        "PATH": os.pathsep.join(str(folder) for folder in [system, *folders]),
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
    if home:
        environment["USERPROFILE"] = scratch
    return environment


def run_child(pack: Path, folders: list[Path], stage: str, home: bool = True) -> dict:
    """Start the pack's interpreter in the app's environment for one stage of `child`."""
    with tempfile.TemporaryDirectory() as scratch:
        environment = app_environment(scratch, folders, home)
        arguments = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child", stage, "--pack", str(pack)]
        done = subprocess.run(
            arguments,
            cwd=scratch,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=900,
        )
    lines = [line for line in done.stdout.splitlines() if line.startswith("RESULT ")]
    if done.returncode != 0 or not lines:
        return {"problems": [f"the runtime process ended ({done.returncode:#x}) at stage {stage}: {done.stderr[-2000:].strip()}"]}
    return json.loads(lines[-1][len("RESULT ") :])


GATE_PROBES = {
    "hardware facts": "from frameleaf_ml.native_hardware import snapshot; snapshot()",
    "platform": "import platform; platform.uname(); platform.processor()",
    "child process": "import subprocess; subprocess.run(['cmd', '/c', 'ver'], capture_output=True)",
    "event loop": "import asyncio; asyncio.run(asyncio.sleep(0))",
    "memory": "import psutil; psutil.virtual_memory()",
}


def run_gate(folders: list[Path]) -> dict:
    """Each probe in the pack's interpreter started exactly as the app starts a runtime: the
    app's own gate program (read from its source) on a pipe that stays open, the app's
    environment, nothing on the console. A probe that has not finished after 40 seconds reports
    where it is stuck."""
    source = (Path(__file__).resolve().parent.parent / "src-tauri" / "src" / "native_runtime.rs").read_text(encoding="utf-8")
    gate = re.search(r'const GATE: &str = r#"(.*?)"#;', source, re.S).group(1)
    results = {}
    for name, statement in GATE_PROBES.items():
        for gated in (True, False):
            setup = "import faulthandler; faulthandler.dump_traceback_later(40, exit=True)"
            program = [sys.executable, "-I", "-B", "-c", gate] if gated else [sys.executable, "-I", "-B", "-m"]
            with tempfile.TemporaryDirectory() as scratch:
                import time

                started = time.perf_counter()
                process = subprocess.Popen(
                    program + ["timeit", "-n", "1", "-r", "1", "-s", setup, statement],
                    cwd=scratch,
                    env=app_environment(scratch, folders),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                process.stdin.write(b"frameleaf-native-start\n")
                process.stdin.flush()
                # The pipe stays open, as the app holds it for as long as the runtime runs.
                try:
                    code = process.wait(timeout=75)
                    errors = process.stderr.read()
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    code, errors = None, b"no exit after 75 seconds: " + process.stderr.read()
                process.stdin.close()
                results[f"{name} ({'gate' if gated else 'plain'})"] = {
                    "seconds": round(time.perf_counter() - started, 1),
                    "exit": code,
                    "errors": errors.decode("utf-8", "replace")[-3000:],
                }
    return results


def run_stages(pack: Path, folders: list[Path], last: str, home: bool = True) -> dict:
    """The cuDNN stage, then `names` or `session`, each in its own process; problems of both."""
    first, second = run_child(pack, folders, "cudnn", home), run_child(pack, folders, last, home)
    return {**first, **second, "problems": first["problems"] + second["problems"]}


def markdown(report: dict) -> str:
    lines = ["| Library | How | Needs | In the pack |", "| --- | --- | --- | --- |"]
    lines += [f"| `{row['library']}` | {row['reference']} | `{row['needs']}` | {row['pack']} |" for row in report["table"]]
    if "loader" in report:
        lines += ["", "| Library | Found by name, OS directory only (before) | Found by name, with the pack's folders (now) |", "| --- | --- | --- |"]
        before, now = report["loaderBefore"].get("byName", {}), report["loader"].get("byName", {})
        lines += [f"| `{name}` | {'yes' if before.get(name) else 'NO'} | {'yes' if now.get(name) else 'NO'} |" for name in sorted(now)]
    lines += ["", f"Longest path in the pack: {report['longestPath']} characters (budget {PATH_BUDGET})."]
    lines += ["", "Problems: " + ("none" if not report["problems"] else "")] + [f"- {problem}" for problem in report["problems"]]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pack", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--session", action="store_true")
    parser.add_argument("--child", choices=("cudnn", "names", "session"))
    args = parser.parse_args()
    pack = args.pack.resolve()
    site = pack / "payload" / "python" / "Lib" / "site-packages"
    if args.child:
        sys.stdout.reconfigure(encoding="utf-8")
        print("RESULT " + json.dumps(child(site, args.child)))
        return
    if os.name != "nt" or not args.output:
        parser.error("run on Windows with --output")
    import onnxruntime as ort

    # A cuDNN engine library the wheel does not have is optional to onnxruntime itself.
    optional = {parts[-1].lower() for parts in ort._get_nvidia_dll_paths(True, False, True)} - {"cudnn64_9.dll"}
    rows, problems = table(site, start_libraries(ort), frozenset(optional))
    manifest = json.loads((pack / "manifest-accelerated.json").read_text(encoding="utf-8"))
    if manifest["provider"] != PROVIDER:
        parser.error("not a CUDA pack")
    names = sorted(manifest["files"])
    native = [name for name in over_budget(names) if name.lower().endswith((".dll", ".pyd", ".exe"))]
    problems += [f"native library too deep for Windows to open once installed ({len(name)} > {PATH_BUDGET}): {name}" for name in native]
    folders = library_folders(site)
    report = {
        "onnxruntime": ort.__version__,
        "table": rows,
        "searchFolders": [folder.relative_to(pack / "payload").as_posix() for folder in folders],
        "longestPath": max(len(name) for name in names),
        "pathBudget": PATH_BUDGET,
        "overBudget": over_budget(names),
        "payloadBytes": sum(item["bytes"] for item in manifest["files"].values()),
        # What the app did before FD-63 (OS directory only, no home): evidence, nothing is required of it.
        "loaderBefore": run_stages(pack, [], "names", home=False),
        "loader": run_stages(pack, folders, "session" if args.session else "names"),
        "gate": run_gate(folders),
    }
    report["problems"] = problems + report["loader"]["problems"]
    # Started as the app starts it, each probe must finish; the plain start is only the comparison.
    report["problems"] += [
        f"started as the app starts the runtime, '{name}' did not finish (exit {result['exit']}): {result['errors'][-600:].strip()}"
        for name, result in report["gate"].items()
        if name.endswith("(gate)") and result["exit"] != 0
    ]
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "cuda-libraries.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (args.output / "cuda-libraries.md").write_text(markdown(report), encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print(markdown(report))
    print("before FD-63 (OS directory only, no home directory):", json.dumps(report["loaderBefore"]["problems"], indent=2))
    print("gate probes:", json.dumps(report["gate"], indent=2))
    print("preload seconds:", report["loader"].get("preloadSeconds"), "cuDNN:", report["loader"].get("cudnn"))
    print("payload bytes:", report["payloadBytes"], "files over the path budget:", len(report["overBudget"]))
    if report["problems"]:
        raise SystemExit("the CUDA pack's libraries do not all resolve")
    print("cuda libraries ok")


if __name__ == "__main__":
    main()
