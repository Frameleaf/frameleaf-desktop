# Qwen photo description qualification

The component harness runs an offline llama.cpp process on loopback. It supplies two generated
images, checks that the output names their different colors and shapes, and cancels a third
streaming request. It accepts bounded description JSON and maps it to Library's existing
`image-description-tagging` response. The resulting receipt records the binary and both GGUF
digests, golden descriptions, backend, and process cleanup. Its release qualification flag is false.

## Prepare model artifacts

Provide a locally materialized [Qwen source checkout](https://huggingface.co/Qwen/Qwen3.5-4B/tree/851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a),
a clean [llama.cpp checkout](https://github.com/ggml-org/llama.cpp/tree/7fe450e19305b828c199d602c23a8337aaa1f03b)
and the quantizer built from that revision. The converter uses the local Python environment.
Use the same filesystem for the Qwen checkout and the new output directory so the tool can hard-link
verified inputs. Allow 24 GiB of free space on that filesystem.

```sh
python3 tools/qwen_description.py convert \
  --source /path/to/Qwen3.5-4B --llama /path/to/llama.cpp \
  --quantizer /path/to/llama-quantize --output /path/to/new-candidate
```

FD-31 (owner, 2026-11-24) adds the larger model: pass `--model-name Qwen2.5-VL-7B-Instruct` to
both commands with a [Qwen2.5-VL-7B-Instruct checkout](https://huggingface.co/Qwen/Qwen2.5-VL-7B-Instruct/tree/cc594898137f460bfe9f0759e9844b3ce807cfb5).
That checkpoint has no LICENSE file; its model card states Apache-2.0, so `convert` also takes
`--license` with that license's text (Library's `licenses/texts/apache-2.0.txt`). It has no pinned
third-party export, so `qualify` needs its conversion receipt. Each of its descriptions may take
90 seconds on four processor threads (30 for Qwen3.5-4B).

Build the quantizer and `llama-server` so they report the 9-character commit `7fe450e19` and build
11146, as Library and Desktop require. A shallow clone abbreviates to 7 characters, and its build
number is 1, which also makes the web UI asset download fail:

```sh
git -C /path/to/llama.cpp config core.abbrev 9
cmake -S /path/to/llama.cpp -B /path/to/llama.cpp/build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DLLAMA_CURL=OFF -DLLAMA_USE_PREBUILT_UI=OFF -DLLAMA_BUILD_NUMBER=11146 \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
  -DBUILD_SHARED_LIBS=OFF -DGGML_NATIVE=OFF -DGGML_METAL=OFF -DGGML_OPENMP=OFF -DLLAMA_OPENSSL=OFF
cmake --build /path/to/llama.cpp/build --target llama-server llama-quantize
```

The last line makes the `llama-server` a candidate pack copies self-contained and portable, as the
factory builds it (`.github/workflows/factory-runtime.yml`, which also selects the static C runtime on
Windows). The free-space check counts the space macOS frees on demand, as Finder does.

The tool verifies the checkpoint files against Git and LFS, then converts to BF16, quantizes to
Q4_K_M, exports the F16 vision projector, and copies the Apache license. The receipt records the
exact inputs, converter revision, quantizer binary and resulting artifacts.

```sh
python3 tools/qwen_description.py qualify --backend metal \
  --binary /path/to/llama-server \
  --model /path/to/new-candidate/model.gguf --projector /path/to/new-candidate/mmproj.gguf \
  --receipt /path/to/new-candidate/candidate.json --output /path/to/new-report.json
```

The diagnostic also accepts the exact [published GGUF and projector pair](https://huggingface.co/unsloth/Qwen3.5-4B-GGUF/tree/e87f176479d0855a907a41277aca2f8ee7a09523)
when the conversion receipt is omitted. That export identifies its base model and license. The
converter's input revision and build are unverified for those published bytes.

The goldens exercise the same adapter that accepts the candidate native request
`image-description-tagging.visual` for `Qwen3.5-4B` with empty options. It accepts inline
JPEG or PNG bytes and returns the Library result schema. Desktop's bound prediction client
has a transport test for these exact entries and the result shape.

Installed execution still needs a Qwen binding in Library's signed native sidecar with an
owned llama.cpp process, qualification for both GGUF files and the execution backend, and an
approved model catalogue and claim route on both sides. The current inventory and runtime
admission are unchanged. Installed resource, cancellation, and output-quality checks are
required on the platforms where the provider will be offered.

## Catalogue profiles (epoch 20)

Library's catalogue epoch 20 has both description profiles for runtime source `35ba35dd`:
- Qwen3.5-4B, from Hugging Face `frameleaf/Qwen3.5-4B` (the pinned unsloth export, revision `90ad97bb`), with an 8 GiB floor.
- Qwen2.5-VL-7B-Instruct, from `frameleaf/Qwen2.5-VL-7B-Instruct` (the pinned ggml-org export, revision `b58477fc`), with an 11.75 GiB floor.

Library's `machine-learning/scripts/add_desktop_description_profiles.py` makes these profiles.
The factory's CPU job builds the pinned `llama-server` (static, portable, no Metal) and passes it to the
builder below, so every processor pack from that source can describe photos.

## Build the candidate runtime pack

Use the CPU runtime profile and a self-contained native `llama-server`
(`llama-server.exe` on Windows) built from the pinned source. Put it beside its `LICENSE` in a
local directory. Supply the digest of that exact executable to the builder.

```sh
python3 tools/build_runtime.py --source /path/to/library --revision LIBRARY_COMMIT \
  --epoch NEXT_EPOCH --output /path/to/new-runtime --profile cpu-ort \
  --qwen-runtime /path/to/llama-build --qwen-sha256 BINARY_SHA256
```

The builder checks the digest before running the version probe. Its manifest
inventories the executable and license. The macOS signing step updates the
manifest with the post-signing binary digest before runtime sealing. Desktop
matches qualification evidence to that final signed digest. The candidate uses
a private Unix socket on macOS and Linux. On Windows it checks the owner PID of
the established loopback socket before sending the bearer credential or image.
The candidate process inherits the supervisor’s Windows Job Object and its token
file inherits the private working directory ACL.

The qualification spec uses `engine: "qwen-gguf"`, the CPU provider, one image
fixture and its exact expected result, and the two staged file digests at
`visual/model.gguf` and `visual/mmproj.gguf`. The report records two cold
executions because each prediction owns a separate process. This pack does
not add model inventory, approve a Library source revision for the factory, or
enable installed worker claims.
