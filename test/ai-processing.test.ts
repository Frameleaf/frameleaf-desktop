import assert from 'node:assert/strict';
import { test } from 'node:test';
import { processingPlaces, queueProgress, queueState, workloadProvider, type AiQueue } from '../src/ai-processing.ts';

const run: AiQueue = {
  name: 'smartSearch', state: 'running', isPaused: false,
  active: 1, waiting: 5, processed: 4, total: 10,
};

test('reports finished jobs for the current Library run, and keeps unavailable counts unknown', () => {
  assert.deepEqual(queueProgress(run), { finished: '4 of 10 finished', counts: '1 running · 5 waiting', percent: 40 });
  assert.equal(queueProgress({ ...run, unavailable: true }), null);
  assert.equal(queueProgress({ ...run, total: 2 }), null);
  assert.equal(queueProgress({ ...run, total: 0, processed: 0, waiting: 0, active: 0 })?.percent, null);
});

test('keeps reported wait reasons and configured places separate from execution', () => {
  assert.equal(queueState({ ...run, unavailable: true }), 'Status unknown');
  assert.equal(queueState({ ...run, heldForNight: true, isPaused: true }), 'Waiting for quiet hours');
  assert.equal(queueState({ ...run, isPaused: true }), 'Paused on the Library');
  assert.equal(queueState({ ...run, state: 'unavailable' }), 'No worker available');
  assert.equal(queueState({ ...run, state: 'blocked' }), 'Waiting for a dependency');
  assert.equal(queueState({ ...run, state: 'future-value' }), 'Wait reason unknown');
  assert.equal(processingPlaces(['local', 'desktops', 'cloud']), 'Library server → Your computers → Frameleaf Cloud');
  assert.equal(processingPlaces(['future-value']), 'Unknown');
  assert.equal(processingPlaces([]), 'Off');
});

// FD-52: the provider shown is the one the backend chose, never a guess.
test('each workload shows the provider the backend chose and why the processor stands in', () => {
  const providers = [
    { workload: 'clip', provider: 'CoreMLExecutionProvider', fallback: null },
    { workload: 'face', provider: 'CPUExecutionProvider', fallback: 'runtime_qualification_timeout' },
    { workload: 'ocr', provider: 'CPUExecutionProvider', fallback: null },
  ];
  assert.equal(workloadProvider(providers, 'clip'), 'Runs on CoreML');
  assert.equal(workloadProvider(providers, 'ocr'), 'Runs on CPU');
  assert.equal(workloadProvider(providers, 'face'), 'Runs on CPU (GPU acceleration is not used: it did not pass its check on this computer)');
  assert.equal(workloadProvider([{ workload: 'face', provider: 'CPUExecutionProvider', fallback: 'provider_device_ineligible' }], 'face'),
    'Runs on CPU (GPU acceleration is not used: this computer has no supported GPU)');
  // FD-63: a driver known to be too old is named, so the person knows what to do.
  assert.equal(workloadProvider([{ workload: 'face', provider: 'CPUExecutionProvider', fallback: 'provider_driver_outdated' }], 'face'),
    'Runs on CPU (GPU acceleration is not used: the NVIDIA driver is too old; update it to use the GPU)');
  // FD-56: a GPU provider that measured slower than the processor does not keep the workload.
  assert.equal(workloadProvider([{ workload: 'clip', provider: 'CPUExecutionProvider', fallback: 'provider_slower' }], 'clip'),
    'Runs on CPU (GPU acceleration is not used: the processor is faster for this on this computer)');
  assert.equal(workloadProvider([{ workload: 'clip', provider: 'CPUExecutionProvider', fallback: 'provider_speed_unknown' }], 'clip'),
    'Runs on CPU (GPU acceleration is not used: its speed could not be measured this time)');
  assert.equal(workloadProvider([{ workload: 'face', provider: 'CPUExecutionProvider', fallback: 'workload_desktop_runtime_incompatible' }], 'face'),
    'Runs on CPU (GPU acceleration is not used: the Library did not accept it)');
  assert.equal(workloadProvider([{ workload: 'face', provider: 'CPUExecutionProvider', fallback: 'runtime_signature_invalid' }], 'face'),
    'Runs on CPU (GPU acceleration is not used: it could not be prepared on this computer)');
  assert.equal(workloadProvider([{ workload: 'clip', provider: 'CUDAExecutionProvider', fallback: null }], 'clip'), 'Runs on NVIDIA CUDA');
  // Nothing chosen yet, an older backend, or a provider this build has no name for: say nothing.
  for (const none of [undefined, null, [], [{ workload: 'clip', provider: 'InventedProvider', fallback: null }]])
    assert.equal(workloadProvider(none, 'clip'), '');
  assert.equal(workloadProvider(providers, 'enrichment'), '');
});

// FD-60: the downloadable GPU pack is offered with its size, never fetched without the person
// choosing Download, and a failure always says the processor keeps the work.
test('the GPU pack is offered with its size, shows progress and failure, and says when it is in use', async () => {
  const { acceleratedPackView } = await import('../src/ai-processing.ts');
  const size = (bytes: number) => `${(bytes / 1e9).toFixed(1)} GB`;
  const reason = (code: string) => `[${code}]`;
  const base = { provider: 'CUDAExecutionProvider', bytes: 2.9e9, receivedBytes: 0, code: null, declined: false, metered: false };
  const view = (pack: Record<string, unknown>, providers: { workload: string; provider: string; fallback: string | null }[] | null = null) =>
    acceleratedPackView({ ...base, ...pack } as never, providers, size, reason);

  assert.equal(acceleratedPackView(null, null, size, reason), null);
  assert.equal(view({ state: 'none', provider: null }), null);
  assert.equal(view({ state: 'available', provider: 'FutureExecutionProvider' }), null);

  const offer = view({ state: 'available' })!;
  assert.equal(offer.title, 'Faster processing available for your NVIDIA graphics card');
  assert.match(offer.detail, /^Download 2\.9 GB to use it/);
  assert.match(offer.detail, /uses the processor\.$/);
  assert.deepEqual(offer.actions, ['download', 'decline']);
  assert.match(view({ state: 'available', metered: true })!.detail, /may be metered\.$/);
  // Not now: the offer stays, quietly, and only Download fetches anything.
  const declined = view({ state: 'available', declined: true })!;
  assert.deepEqual(declined.actions, ['download']);
  assert.match(declined.detail, /^Not downloaded \(2\.9 GB\)/);

  const downloading = view({ state: 'downloading', receivedBytes: 1.45e9 })!;
  assert.equal(downloading.progress, 50);
  assert.deepEqual(downloading.actions, ['cancel']);
  assert.match(downloading.detail, /^1\.4 GB of 2\.9 GB|^1\.5 GB of 2\.9 GB/);
  assert.equal(view({ state: 'downloading', receivedBytes: 9e9 })!.progress, 100);
  assert.deepEqual(view({ state: 'unpacking' })!.actions, []);

  const failed = view({ state: 'failed', code: 'accelerated_pack_download_interrupted' })!;
  assert.equal(failed.title, 'Faster processing for your NVIDIA graphics card could not be set up');
  assert.equal(failed.detail, '[accelerated_pack_download_interrupted] AI processing continues on the processor.');
  assert.deepEqual(failed.actions, ['download']);

  // FD-63: a driver too old for the pack offers no download and says to update the driver.
  const outdated = view({ state: 'outdated', code: 'provider_driver_outdated' })!;
  assert.equal(outdated.title, 'Update the driver for your NVIDIA graphics card');
  assert.equal(outdated.detail, '[provider_driver_outdated] AI processing continues on the processor.');
  assert.deepEqual(outdated.actions, []);

  // Downloaded: "Using NVIDIA graphics" only once a workload actually runs on it.
  assert.equal(view({ state: 'ready' })!.title, 'Support for your NVIDIA graphics card is downloaded');
  const using = view({ state: 'ready' }, [
    { workload: 'clip', provider: 'CUDAExecutionProvider', fallback: null },
    { workload: 'face', provider: 'CPUExecutionProvider', fallback: 'provider_slower' },
  ])!;
  assert.equal(using.title, 'Using NVIDIA graphics');
  assert.deepEqual(using.actions, []);
  const unused = view({ state: 'ready' }, [{ workload: 'clip', provider: 'CPUExecutionProvider', fallback: 'runtime_qualification_timeout' }])!;
  assert.equal(unused.title, 'NVIDIA graphics not in use');
  assert.equal(unused.detail, 'AI processing uses the processor: it did not pass its check on this computer.');
  assert.deepEqual(unused.actions, ['retry-provider']);
  assert.equal(view({ state: 'ready', provider: 'OpenVINOExecutionProvider' }, [{ workload: 'ocr', provider: 'OpenVINOExecutionProvider', fallback: null }])!.title, 'Using Intel graphics');
});

test('every code the GPU pack download can report has its own words', async () => {
  const { errorCopy } = await import('../src/errors.ts');
  for (const code of ['accelerated_pack_download_interrupted', 'accelerated_pack_download_invalid', 'accelerated_pack_archive_invalid', 'accelerated_pack_storage_failed',
    'accelerated_pack_disk_space', 'accelerated_pack_epoch_mismatch', 'accelerated_pack_missing', 'accelerated_pack_busy', 'accelerated_pack_unavailable',
    'accelerated_pack_signature_invalid', 'accelerated_pack_manifest_invalid'])
    assert.match(errorCopy(code) ?? '', /graphics card/, code);
  // FD-63: an outdated driver is named with what to do about it.
  assert.match(errorCopy('provider_driver_outdated') ?? '', /Update the NVIDIA driver/);
});
