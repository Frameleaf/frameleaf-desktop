import assert from 'node:assert/strict';
import test from 'node:test';
import { sourceCopyApprovals } from '../src/source-copy-state.ts';

type CopyState = Parameters<typeof sourceCopyApprovals>[0];
const state = (patch: Partial<CopyState> = {}): CopyState => ({
  state: 'paused', provider: null, stagedBytes: null, code: null,
  sourceReadRemaining: 100, exportRemaining: null, uploadRemaining: 100, ...patch,
});

test('restart exposes exhausted folder read and upload allowances without an error code', () => {
  assert.deepEqual(sourceCopyApprovals(state({ sourceReadRemaining: 0 })), { read: true, export: false, upload: false, canResumeWithoutUpload: false, canResume: false });
  assert.deepEqual(sourceCopyApprovals(state({ uploadRemaining: 0 })), { read: false, export: false, upload: true, canResumeWithoutUpload: false, canResume: false });
});
test('restart exposes exhausted Photos export allowance before another original can be exported', () => {
  assert.deepEqual(sourceCopyApprovals(state({ provider: 'apple-photos', exportRemaining: 0, uploadRemaining: null })), { read: false, export: true, upload: false, canResumeWithoutUpload: false, canResume: false });
});
test('missing approvals and reported insufficiency require explicit additional permission', () => {
  assert.equal(sourceCopyApprovals(state({ sourceReadRemaining: null })).read, true);
  assert.equal(sourceCopyApprovals(state({ code: 'source_read_budget_exhausted' })).read, true);
  assert.equal(sourceCopyApprovals(state({ code: 'source_upload_budget_exhausted' })).upload, true);
  assert.equal(sourceCopyApprovals(state({ provider: 'apple-photos', exportRemaining: 100, code: 'photos_export_budget_exhausted' })).export, true);
});
test('a verified staged original needs no new source-read or Photos export approval', () => {
  assert.deepEqual(sourceCopyApprovals(state({ stagedBytes: 50, sourceReadRemaining: 0 })), { read: false, export: false, upload: false, canResumeWithoutUpload: false, canResume: true });
  assert.deepEqual(sourceCopyApprovals(state({ provider: 'apple-photos', stagedBytes: 50, exportRemaining: 0 })), { read: false, export: false, upload: false, canResumeWithoutUpload: false, canResume: true });
});
test('Photos requests upload approval only after the exact staged size is known', () => {
  assert.deepEqual(sourceCopyApprovals(state({ provider: 'apple-photos', exportRemaining: 100, uploadRemaining: null })), { read: false, export: false, upload: false, canResumeWithoutUpload: false, canResume: true });
  assert.equal(sourceCopyApprovals(state({ provider: 'apple-photos', stagedBytes: 50, uploadRemaining: null })).upload, true);
});
test('running and terminal jobs offer neither budget mutation nor Resume', () => {
  for (const status of ['copying', 'complete', 'cancelled']) {
    assert.deepEqual(sourceCopyApprovals(state({ state: status, sourceReadRemaining: 0, exportRemaining: 0, uploadRemaining: 0 })), { read: false, export: false, upload: false, canResumeWithoutUpload: false, canResume: false });
  }
});

test('Photos terminal or running jobs do not offer export approval from a retained error code', () => {
  for (const status of ['copying', 'complete', 'cancelled']) {
    assert.deepEqual(sourceCopyApprovals(state({ state: status, provider: 'apple-photos', code: 'photos_export_budget_exhausted', exportRemaining: 0 })), { read: false, export: false, upload: false, canResumeWithoutUpload: false, canResume: false });
  }
});

test('a staged copy can settle a saved server upload without granting more payload data', () => {
  assert.equal(sourceCopyApprovals(state({ stagedBytes: 50, uploadRemaining: 0 })).canResume, true);
  assert.deepEqual(sourceCopyApprovals(state({ stagedBytes: 50, uploadRemaining: 0, code: 'source_upload_budget_exhausted' })), { read: false, export: false, upload: true, canResumeWithoutUpload: true, canResume: true });
  assert.deepEqual(sourceCopyApprovals(state({ provider: 'apple-photos', stagedBytes: 50, exportRemaining: 0, uploadRemaining: 0 })), { read: false, export: false, upload: true, canResumeWithoutUpload: true, canResume: true });
});
test('zero-upload resume requires an existing staged original and an approved upload counter', () => {
  assert.equal(sourceCopyApprovals(state({ uploadRemaining: 0 })).canResumeWithoutUpload, false);
  assert.equal(sourceCopyApprovals(state({ stagedBytes: 50, uploadRemaining: null })).canResumeWithoutUpload, false);
  assert.equal(sourceCopyApprovals(state({ state: 'copying', stagedBytes: 50, uploadRemaining: 0 })).canResumeWithoutUpload, false);
});
