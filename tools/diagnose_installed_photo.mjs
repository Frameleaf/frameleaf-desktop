const reasons = [
  ['input_missing', /Input file is missing|ENOENT|no such file or directory/i],
  ['permission_denied', /EACCES|EPERM|permission denied|access is denied/i],
  ['invalid_path', /EINVAL|ENAMETOOLONG|invalid (?:file|path|argument)/i],
  ['unsupported_image', /unsupported image|unsupported file format|corrupt|pngload|libpng/i],
  ['missing_module', /MODULE_NOT_FOUND|Cannot find (?:module|package)|Could not load the .sharp. module/i],
  ['sharp_child_closed', /Sharp child closed/],
  ['process_timeout', /timed out|timeout|deadline|idle child/i],
  ['source_changed', /source changed|lost its claim|lease expired/i],
  ['resource_limit', /resource limit|too large|capacity/i],
];

/** Emit fixed categories only: job payloads, raw errors, paths and credentials stay private. */
export async function diagnosePhoto(request) {
  const result = [];
  for (const name of ['metadataExtraction', 'thumbnailGeneration']) {
    const item = { name, readable: false };
    try {
      const queue = await (await request('/api/queues/' + name, {}, [200])).json();
      item.statistics = Object.fromEntries(['active', 'completed', 'failed', 'delayed', 'waiting', 'paused'].map(key => [
        key, Number.isSafeInteger(queue.statistics?.[key]) && queue.statistics[key] >= 0 ? queue.statistics[key] : null,
      ]));
      item.isPaused = typeof queue.isPaused === 'boolean' ? queue.isPaused : null;
      const jobs = await (await request('/api/queues/' + name + '/jobs?status=failed', {}, [200])).json();
      item.failures = jobs.slice(0, 20).map(job => {
        const message = typeof job.failedReason === 'string' ? job.failedReason.slice(0, 8192) : '';
        const categories = reasons.filter(([, pattern]) => pattern.test(message)).map(([name]) => name);
        const exit = message.match(/Sharp child closed \((-?\d{1,10})\)/)?.[1];
        return { categories: categories.length ? categories : ['unreported'], sharpExitCode: exit ? Number(exit) : null };
      });
      item.readable = true;
    } catch { /* Diagnostic failure must preserve the original qualification failure. */ }
    result.push(item);
  }
  return result;
}
