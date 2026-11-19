"""Qualify catalogue models with a built processor pack, as the app does after installing it.

    python tools/qualify_runtime_models.py <pack> <work folder> <model name>...

For each named model, every processor profile the catalogue has for the pack's source is run:
the model is staged with the pack's own staging command (a download from the model hub), then
the pack's qualification command runs the profile's fixture and compares the output with the
catalogue's expected output. FD-6: this is what shows a pack whose onnxruntime differs from the
one the runtime source locks (Intel macOS) still produces the catalogue's results.
"""

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main(arguments):
    pack, work, names = Path(arguments[0]).resolve(), Path(arguments[1]).resolve(), arguments[2:]
    manifest = json.loads((pack / "manifest.json").read_text())
    python = pack / "payload" / manifest["python"]
    namespace = manifest.get("moduleNamespace", "immich_ml")
    catalogue = json.loads((ROOT / "runtime/model-catalogue.json").read_text())
    cache = work / "cache"
    cache.mkdir(parents=True)
    environment = {
        "PATH": os.defpath,
        "HOME": str(work),
        "TMPDIR": str(work),
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "MACHINE_LEARNING_CACHE_FOLDER": str(cache),
        **({"SystemRoot": os.environ["SystemRoot"]} if "SystemRoot" in os.environ else {}),
    }
    failed = False
    for name in names:
        profiles = [
            profile
            for profile in catalogue["profiles"]
            if profile["modelName"] == name
            and profile["runtimeSourceRevision"] == manifest["sourceRevision"]
            and profile["spec"]["provider"] == manifest["provider"]
        ]
        if not profiles:
            print(f"{name}: the catalogue has no {manifest['provider']} profile for this pack's source")
            failed = True
        for index, profile in enumerate(profiles):
            spec = profile["spec"]
            for model in spec["models"]:
                options = spec["entries"][model["task"]][model["type"]].get("options", {})
                subprocess.run(
                    [python, "-I", "-B", "-m", f"{namespace}.staging", "--task", model["task"], "--type", model["type"],
                     "--model", model["name"], "--options", json.dumps(options)],
                    env=environment, cwd=work, check=True, timeout=1800,
                )  # fmt: skip
            folder = work / f"{name}-{index}"
            folder.mkdir()
            (folder / "spec.json").write_text(json.dumps(spec))
            (folder / spec["fixtureFile"]).write_bytes(base64.b64decode(profile["fixtureBase64"]))
            report = folder / "report.json"
            result = subprocess.run(
                [python, "-I", "-B", "-m", f"{namespace}.native_qualification", "--spec", folder / "spec.json",
                 "--cache-dir", cache, "--output", report],
                env=environment, cwd=work, timeout=spec["deadlineSeconds"] + 60,
            )  # fmt: skip
            value = json.loads(report.read_text()) if report.is_file() else {}
            runtime = value.get("runtime", {})
            print(
                f"{name} ({profile['workload']}, {spec['fixtureKind']}): {value.get('state')} "
                f"{value.get('reason') or ''} onnxruntime {runtime.get('ort')} {runtime.get('architecture')} "
                f"cold {value.get('coldMilliseconds', 0):.0f} ms warm {value.get('warmMilliseconds', 0):.0f} ms"
            )
            if result.returncode or value.get("state") != "ready-cpu":
                failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
