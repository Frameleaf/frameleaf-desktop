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
