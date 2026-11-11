import assert from 'node:assert/strict';
import { test } from 'node:test';
import { processingPlaces, queueProgress, queueState, type AiQueue } from '../src/ai-processing.ts';

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
