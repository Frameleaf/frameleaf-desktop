// FD-77: Computer backup end to end, against the local Cloud and S3 stand-ins (never a live system).
// Starts tools/computer_backup_stand_in.mjs, then runs the Rust test that links, backs up, browses and
// restores through it. `node tools/test_computer_backup_e2e.mjs`; it is not part of `npm test` because
// it builds the desktop crate.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { standIn } from './computer_backup_stand_in.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const running = await standIn();
// Asynchronous, so the stand-in in this process keeps answering while the test runs.
const result = await new Promise((resolve) => {
  const child = spawn('cargo', ['test', '--manifest-path', 'src-tauri/Cargo.toml', '--lib', 'computer_backup::tests::end_to_end', '--', '--ignored', '--nocapture'], {
    cwd: root, stdio: 'inherit', env: { ...process.env, FRAMELEAF_CLOUD_URL: running.cloud },
  });
  child.once('close', resolve);
});
const routes = [...new Set(running.state.log)].sort();
console.log(`stand-in saw ${running.state.log.length} Cloud requests on ${routes.length} routes; ${running.objects.size} stored objects`);
await running.close();
process.exit(result ?? 1);
