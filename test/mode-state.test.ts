import { test } from 'node:test';
import assert from 'node:assert/strict';
import { workerStatus, safeMode } from '../src/mode-state.ts';

test('persisted modes reject unknown values without treating them as hosting', () => {
  assert.equal(safeMode('local-server'), 'local-server');
  assert.equal(safeMode('client-worker'), 'client-worker');
  assert.equal(safeMode(''), null);
  assert.equal(safeMode('host'), null);
});
test('enrollment never implies qualified inference', () => {
  assert.equal(workerStatus({ state:'preparing', workerSupported:false }), 'Your server needs a desktop-worker update');
  assert.equal(workerStatus({ state:'awaiting-approval', workerSupported:false }), 'Waiting for administrator approval');
  assert.equal(workerStatus({ state:'preparing', workerSupported:true }), 'Preparing this computer');
  assert.equal(workerStatus({ state:'incompatible', workerSupported:true }), 'This computer is not compatible with the selected models');
});
