const childProcess = require('node:child_process');
const { syncBuiltinESMExports } = require('node:module');
const { basename } = require('node:path');

// Observe only fixed failure receipts; never inspect stdin or raw child stderr.
function observe(output, emit) {
  let pending = '';
  let disabled = false;
  output.on('data', chunk => {
    if (disabled) return;
    pending += chunk.toString('utf8');
    if (Buffer.byteLength(pending) > 16 * 1024) {
      pending = '';
      disabled = true;
      return;
    }
    let newline;
    while ((newline = pending.indexOf('\n')) !== -1) {
      const line = pending.slice(0, newline);
      pending = pending.slice(newline + 1);
      try {
        const value = JSON.parse(line);
        if (value?.protocolVersion === 1 && value.state === 'failed'
          && Object.keys(value).sort().join(',') === 'code,protocolVersion,state'
          && typeof value.code === 'string' && value.code.length <= 80
          && /^(host_|runtime_|native_)[a-z_]+$/.test(value.code)) emit(value.code);
      } catch {}
    }
  });
}

const spawn = childProcess.spawn;
childProcess.spawn = function (...args) {
  const child = Reflect.apply(spawn, this, args);
  if (typeof args[0] === 'string' && basename(args[0]).toLowerCase() === 'frameleaf-native-host.exe'
    && Array.isArray(args[1]) && args[1][0] === '--owner-pipe' && child.stdout) {
    observe(child.stdout, code => process.stderr.write('Installed controller refusal: ' + code + '\n'));
  }
  return child;
};
syncBuiltinESMExports();
module.exports = { observe };
