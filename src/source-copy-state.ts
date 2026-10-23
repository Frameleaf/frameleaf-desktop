type CopyBudgetState = {
  state: string;
  provider: string | null;
  stagedBytes: number | null;
  code: string | null;
  sourceReadRemaining: number | null;
  exportRemaining: number | null;
  uploadRemaining: number | null;
};

const needsAllowance = (remaining: number | null) => remaining === null || !Number.isFinite(remaining) || remaining <= 0;

export function sourceCopyApprovals(job: CopyBudgetState) {
  const actionable = ['ready', 'paused', 'needs-attention'].includes(job.state);
  const read = actionable && !job.provider && job.stagedBytes === null &&
    (needsAllowance(job.sourceReadRemaining) || ['source_read_budget_required', 'source_read_budget_exhausted'].includes(job.code ?? ''));
  const exportApproval = actionable && !!job.provider && job.stagedBytes === null &&
    (needsAllowance(job.exportRemaining) || ['photos_export_budget_required', 'photos_export_budget_exhausted'].includes(job.code ?? ''));
  // Photos upload approval follows export, once the actual staged size is known.
  const upload = actionable && (!job.provider || job.stagedBytes !== null) &&
    (needsAllowance(job.uploadRemaining) || ['source_upload_budget_required', 'source_upload_budget_exhausted'].includes(job.code ?? ''));
  // A zero-byte allowance can still settle an upload already received by the server.
  const canResumeWithoutUpload = actionable && job.stagedBytes !== null && job.uploadRemaining === 0;
  return { read, export: exportApproval, upload, canResumeWithoutUpload, canResume: actionable && !read && !exportApproval && (!upload || canResumeWithoutUpload) };
}
