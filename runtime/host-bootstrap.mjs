// Keep embedded agent source off the Windows command line; leave later frames for the agent.
try {
  const frame = await new Promise((resolve, reject) => {
    let pending = Buffer.alloc(0);
    const cleanup = () => {
      process.stdin.pause();
      process.stdin.off('data', receive);
      process.stdin.off('end', fail);
      process.stdin.off('error', fail);
    };
    const fail = () => { cleanup(); reject(new Error('invalid')); };
    const receive = chunk => {
      const end = chunk.indexOf(10);
      if (pending.length + (end < 0 ? chunk.length : end) > 262144) return fail();
      pending = Buffer.concat([pending, end < 0 ? chunk : chunk.subarray(0, end)]);
      if (end < 0) return;
      cleanup();
      if (end + 1 < chunk.length) process.stdin.unshift(chunk.subarray(end + 1));
      resolve(pending.toString('latin1'));
    };
    process.stdin.on('data', receive);
    process.stdin.once('end', fail);
    process.stdin.once('error', fail);
  });
  if (!frame || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(frame) ||
      Buffer.from(frame, 'base64').toString('base64') !== frame) throw new Error('invalid');
  await import('data:text/javascript;base64,' + frame);
} catch {
  process.stdin.destroy();
  process.stderr.write('host_agent_source_invalid\n');
  process.exitCode = 1;
}
