// Appended to the embedded host agent; prepare and verify one retained target without serving photos.
await (async () => {
  const input = createInterface({input:process.stdin,crlfDelay:Infinity});
  const lines = input[Symbol.asyncIterator]();
  let stopped = false, stop;
  const stopping = new Promise(resolve => {stop = () => {stopped = true; resolve();};});
  process.stdin.on('end',stop);
  process.on('SIGTERM',stop);
  process.on('SIGINT',stop);
  const check = () => {if(stopped) fail('host_restore_cancelled');};
  try {
    const first = await lines.next();
    if(first.done || first.value.length > 65536) fail('host_start_gate_closed');
    const request = JSON.parse(first.value);
    const fields=request&&Object.keys(request).sort().join(','), verifyOnly=fields==='configuration,prepared,update';
    if((fields!=='configuration,update'&&!verifyOnly)||request.configuration?.mode!=='restore-prepare') fail('host_start_gate_closed');
    if(verifyOnly&&(request.prepared?.state!=='update-prepared'||!isDeepStrictEqual(request.prepared.update,request.update))) fail('host_start_gate_closed');
    validateConfig(request.configuration);
    void (async () => {
      for await (const line of {[Symbol.asyncIterator]:()=>lines}) {
        stop();
        if(line !== 'stop') fail('host_control_command_invalid');
        break;
      }
      stop();
    })().catch(stop);
    check();
    const receipt = verifyOnly ? request.prepared : await restoreHostUpdateDatabase(request.configuration,request.update,stopping);
    check();
    const checked = await (verifyOnly ? validateSelectedHostUpdateTarget : validateHostUpdateTarget)(request.configuration,receipt,stopping);
    check();
    if(checked.offlineChecksums !== true || checked.schemaValidated !== true || !isDeepStrictEqual(checked.receipt,receipt)) fail('host_update_preparation_failed');
    process.stdout.write(JSON.stringify({state:'update-verified',prepared:checked.receipt,offlineChecksums:true,schemaValidated:true})+'\n');
  } finally {
    input.close();
    process.stdin.pause();
  }
})().catch(() => {
  process.stderr.write('host_update_preparation_failed\n');
  process.exitCode = 1;
});
