import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from check_catalogue_parity import (  # noqa: E402
    catalogue_differences,
    main,
    runtime_differences,
    source_differences,
)


def profile(name="buffalo_l", source="a" * 40, provider="CPUExecutionProvider", x1=181):
    return {
        "workload": "face",
        "modelName": name,
        "runtimeSourceRevision": source,
        "spec": {"provider": provider, "expectedOutput": {"x1": x1, "score": 0.5}},
    }


def catalogue(*profiles, epoch=13):
    return {"schemaVersion": 1, "epoch": epoch, "profiles": list(profiles)}


RUNTIME = {
    "profiles": {
        "cpu-ort": {
            "python": "3.12.13",
            "uv": "0.11.2",
            "extra": "cpu",
            "provider": "CPUExecutionProvider",
            "targets": ["macos-aarch64", "linux-x86_64"],
        }
    }
}


class CatalogueParity(unittest.TestCase):
    def test_identical_catalogues_and_whole_number_spelling_pass(self):
        server = catalogue(profile(), profile(provider="CUDAExecutionProvider"))
        self.assertEqual(catalogue_differences(copy.deepcopy(server), server), [])
        desktop = catalogue(profile(x1=181.0), profile(provider="CUDAExecutionProvider"))
        self.assertEqual(catalogue_differences(desktop, server), [])

    def test_epoch_missing_extra_changed_and_reordered_profiles_fail(self):
        server = catalogue(profile(), profile(provider="CUDAExecutionProvider"))
        self.assertEqual(
            catalogue_differences(catalogue(*server["profiles"], epoch=9), server),
            ["epoch: desktop 9, server 13"],
        )
        self.assertEqual(
            catalogue_differences(catalogue(profile()), server),
            ["server only: face buffalo_l @aaaaaaaa CUDAExecutionProvider (1)"],
        )
        self.assertEqual(
            catalogue_differences(server, catalogue(profile())),
            ["desktop only: face buffalo_l @aaaaaaaa CUDAExecutionProvider (1)"],
        )
        changed = catalogue(profile(x1=182), profile(provider="CUDAExecutionProvider"))
        self.assertEqual(
            catalogue_differences(changed, server),
            ["differs: face buffalo_l @aaaaaaaa CPUExecutionProvider"],
        )
        self.assertEqual(
            catalogue_differences(catalogue(*reversed(server["profiles"])), server),
            ["profile order differs"],
        )

    def test_desktop_runtime_profiles_must_be_server_approved(self):
        server = copy.deepcopy(RUNTIME)
        server["profiles"]["cuda-ort"] = {"provider": "CUDAExecutionProvider"}
        self.assertEqual(runtime_differences(RUNTIME, server), [])
        desktop = copy.deepcopy(RUNTIME)
        desktop["profiles"]["cpu-ort"]["python"] = "3.13.0"
        desktop["profiles"]["cpu-ort"]["targets"].append("windows-aarch64")
        desktop["profiles"]["gpu-ort"] = {}
        self.assertEqual(
            runtime_differences(desktop, server),
            [
                "runtime profile cpu-ort: python desktop '3.13.0', server '3.12.13'",
                "runtime profile cpu-ort: targets not approved: ['windows-aarch64']",
                "runtime profile gpu-ort: not approved by the server",
            ],
        )

    def test_command_exit_status_follows_the_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            server = Path(directory) / "server.json"
            desktop = Path(directory) / "desktop.json"
            server.write_text(json.dumps(catalogue(profile())))
            desktop.write_text(json.dumps(catalogue(profile())))
            self.assertEqual(main([str(server), "--desktop", str(desktop)]), 0)
            desktop.write_text(json.dumps(catalogue(profile(), epoch=12)))
            self.assertEqual(main([str(server), "--desktop", str(desktop)]), 1)

    def test_runtime_without_a_catalogue_profile_for_its_provider_and_source_fails(self):
        runtime = copy.deepcopy(RUNTIME)
        runtime["profiles"]["cpu-ort"]["sourceRevision"] = "a" * 40
        runtime["profiles"]["coreml-ort"] = {
            "provider": "CoreMLExecutionProvider",
            "sourceRevision": "a" * 40,
        }
        server = catalogue(profile(), profile(provider="CoreMLExecutionProvider"))
        self.assertEqual(source_differences(runtime, server), [])
        self.assertEqual(
            source_differences(runtime, catalogue(profile())),
            [
                "runtime profile coreml-ort: no catalogue profile for "
                "CoreMLExecutionProvider @aaaaaaaa"
            ],
        )
        runtime["profiles"]["cpu-ort"]["sourceRevision"] = "b" * 40
        self.assertEqual(
            source_differences(runtime, server),
            ["runtime profile cpu-ort: no catalogue profile for CPUExecutionProvider @bbbbbbbb"],
        )


if __name__ == "__main__":
    unittest.main()
