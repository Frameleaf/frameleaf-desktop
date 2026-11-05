import assert from 'node:assert/strict';
import { test } from 'node:test';
import { diagnosePhoto } from './diagnose_installed_photo.mjs';

test('photo diagnostic reports bounded categories without errors, job data or credentials', async () => {
  const secret = 'synthetic-private-password-and-path';
  const calls = [];
  const result = await diagnosePhoto(async (path) => {
    calls.push(path);
    return { json: async () => path.includes('/jobs?') ? Array.from({ length: 30 }, () => ({
      failedReason: 'Sharp child closed (3221225794) ENOENT ' + secret, data: { password: secret },
    })) : { isPaused: false, statistics: { active: 1, completed: -1, failed: secret, waiting: 2 } } };
  });
  assert.equal(calls.length, 4);
  assert.equal(result.length, 2);
  for (const item of result) {
    assert.equal(item.readable, true);
    assert.equal(item.isPaused, false);
    assert.deepEqual(item.statistics, { active: 1, completed: null, failed: null, delayed: null, waiting: 2, paused: null });
    assert.equal(item.failures.length, 20);
    assert.deepEqual(item.failures[0], { categories: ['input_missing', 'sharp_child_closed'], sharpExitCode: 3221225794 });
  }
  assert.ok(!JSON.stringify(result).includes(secret));
});

test('photo diagnostic preserves the original failure when endpoints are unavailable', async () => {
  const result = await diagnosePhoto(async () => { throw Error('private error'); });
  assert.deepEqual(result, [
    { name: 'metadataExtraction', readable: false }, { name: 'thumbnailGeneration', readable: false },
  ]);
});

test('photo diagnostic classifies the pinned media idle timeout', async () => {
  const result = await diagnosePhoto(async (path) => ({ json: async () => path.includes('/jobs?')
    ? [{ failedReason: 'Media process stopped making progress' }]
    : { statistics: {} } }));
  assert.deepEqual(result[0].failures, [{ categories: ['process_timeout'], sharpExitCode: null }]);
});
