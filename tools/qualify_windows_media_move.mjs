/**
 * Installed Windows qualification driver. The caller supplies an installed, signed
 * candidate controller built with qualify-windows-media-move, and an owned Manager
 * session for the exact disposable profile returned by the controller. The session
 * signs requests with an approved, recently authenticated disposable Desktop grant.
 *
 * openManager receives the create receipt. Its return value implements
 * request(scope, absolutePath, body) and close(). The request method rejects HTTP
 * failures with the returned error code. confirmReview displays or verifies
 * the specific destination and review hash and returns the displayed hash.
 *
 * Each scenario allocates a fresh fixture. Cleanup belongs to the installed
 * harness so a refusal retains both copies, the database backup, and the journals.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const namespace = '/manager-api/desktop/';
const pixels = Buffer.from([80, 54, 10, 49, 32, 49, 10, 50, 53, 53, 10, 64, 128, 192]);

export async function qualifyWindowsMediaMove({
  controller, host, libraryId, openManager, confirmReview, decision,
}) {
  assert.equal(process.platform, 'win32');
  assert.ok(isAbsolute(controller) && isAbsolute(host.candidate));
  assert.ok(decision === 'target' || decision === 'original');
  assert.equal(typeof openManager, 'function');
  assert.equal(typeof confirmReview, 'function');

  const fixtureId = randomUUID();
  const invoke = (action, input = {}) => {
    const result = spawnSync(controller, ['--qualify-media-move'], {
      input: JSON.stringify({ protocolVersion: 1, fixtureId, action, ...input }) + '\n',
      encoding: 'utf8',
      env: process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {},
      maxBuffer: 16 * 1024,
      timeout: 300_000,
      windowsHide: true,
    });
    if (result.error || result.status !== 0 || result.signal)
      throw Error(`qualification controller refused ${action}`);
    return JSON.parse(result.stdout);
  };
  const profile = invoke('create');
  assert.equal(profile.state, 'fixture-created');
  const manager = await openManager(profile);
  const request = (scope, path, body) => manager.request(scope, namespace + path, body);
  const wait = async (read, condition) => {
    const deadline = Date.now() + 5 * 60_000;
    while (Date.now() < deadline) {
      const operation = await read();
      if (condition(operation)) return operation;
      assert.notEqual(operation.state, 'failed');
      await delay(20_000);
    }
    throw Error('qualification operation timed out');
  };
  const control = async (action) => {
    const { id } = await request(action, 'control', { action, key: randomUUID() });
    await wait(() => request('status', 'operation', { id }), ({ state }) => state === 'complete');
    return id;
  };

  try {
    await control('start');
    const backupOperationId = await control('backup');
    const reviewedBackup = await request('move-library', 'media-move-safety', { id: backupOperationId });
    await control('stop');
    assert.equal(invoke('seed', { host }).state, 'fixture-seeded');
    const stagedReview = invoke('review', { host, libraryId, reviewedBackup });
    assert.equal(stagedReview.state, 'fixture-reviewed');
    assert.equal(stagedReview.targetPath, profile.targetPath);
    const confirmedReviewSha256 = await confirmReview({
      phase: 'stage', targetPath: profile.targetPath, decision,
      reviewSha256: stagedReview.reviewSha256,
    });
    assert.equal(confirmedReviewSha256, stagedReview.reviewSha256);
    const stage = invoke('stage', { host, confirmedReviewSha256 });
    assert.equal(stage.state, 'selected-fenced');
    assert.equal(stage.binding.secureInstallationId, profile.secureInstallationId);
    assert.equal(invoke('interrupt-next-cutover', { host, confirmedReviewSha256 }).state, 'fixture-interruption-armed');

    const review = await request('move-library', 'review-media-move', {
      binding: stage.binding, backupOperationId, decision,
    });
    assert.equal(review.decision, decision);
    assert.equal(await confirmReview({
      phase: 'cutover', targetPath: profile.targetPath, decision,
      reviewSha256: review.reviewSha256,
    }), review.reviewSha256);
    const { id } = await request('move-library', 'confirm-media-move', {
      reviewId: review.reviewId, reviewSha256: review.reviewSha256, key: randomUUID(),
    });
    const operation = () => request('move-library', 'media-move-operation', { id });
    await wait(operation, ({ state }) => state === 'failed');
    assert.deepEqual(invoke('check-interrupted-cutover', { host, confirmedReviewSha256 }), {
      protocolVersion: 1, state: 'fixture-cutover-interrupted', operationId: id, decision,
    });
    // The real controller returned after persisting cutover intent and before
    // releasing the fence. A separate start must still be refused by Manager.
    await assert.rejects(
      request('start', 'control', { action: 'start', key: randomUUID() }),
      /operation_in_progress/,
    );
    assert.equal((await request('move-library', 'resume-media-move', { id })).id, id);
    await wait(operation, ({ state }) => state === 'complete');
    await control('restart');

    const name = 'qualification-photo.ppm';
    assert.deepEqual(await readFile(join(profile.statePath, 'media', name)), pixels);
    assert.deepEqual(await readFile(join(profile.targetPath, `frameleaf-media-${stage.binding.moveId}`, name)), pixels);
    return { fixtureId, operationId: id, decision };
  } finally {
    await manager.close();
  }
}
