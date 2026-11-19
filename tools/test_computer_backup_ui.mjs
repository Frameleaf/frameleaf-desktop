import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { enabled, withBrowser } from './ui_test_support.mjs';

// FD-77: the Computer backup page in every state the owner approved (frameleaf-prototype PR 78,
// notes/desktop-backup/screens), on macOS and Windows, light and dark, against synthetic IPC. With
// FRAMELEAF_TEST_OUTPUT set, each state is saved there under the prototype capture's name.
// Run it with `npm run test:ui`.
if (!enabled) process.exit(0);
const output = process.env.FRAMELEAF_TEST_OUTPUT;
if (output) mkdirSync(output, { recursive: true });

const GB = 1024 ** 3;
const at = (daysAgo, hour, minute = 0) => {
  const date = new Date();
  date.setDate(date.getDate() - daysAgo);
  date.setHours(hour, minute, 0, 0);
  return date.getTime();
};
function sample(os, change = {}) {
  const home = os === 'windows' ? 'C:\\Users\\Taylor\\' : '/Users/taylor/';
  const folder = (id, name, size, files, on, photos = false) => ({ id, name, path: `${home}${name}`, size, files, on, photos });
  return {
    os, computer: os === 'windows' ? 'Taylor’s Surface' : 'Taylor’s MacBook Pro', connected: true, connecting: null, plan: true, enabled: true,
    folders: [
      folder('documents', 'Documents', 38.2 * GB, 21_840, true), folder('desktop', 'Desktop', 6.1 * GB, 1_204, true), folder('downloads', 'Downloads', 17.9 * GB, 3_512, true),
      { ...folder('pictures', os === 'windows' ? 'Pictures' : 'Photos Library', 212 * GB, 48_310, false, true), path: os === 'windows' ? `${home}Pictures` : `${home}Pictures/Photos Library.photoslibrary` },
    ],
    schedule: { every: 'day', at: 120, stopBy: 420, limitMbps: null, waitOnBattery: true, keep: 'recommended' },
    running: null,
    runs: [
      { at: at(0, 2, 14), kind: 'backup', ok: true, files: 26_556, bytes: 1.1 * GB, tookMs: 9 * 60_000, problem: null, from: null, original: null },
      { at: at(1, 2, 12), kind: 'backup', ok: true, files: 26_410, bytes: 220 * 1024 ** 2, tookMs: 3 * 60_000, problem: null, from: null, original: null },
      { at: at(2, 9, 40), kind: 'restore', ok: true, files: 2, bytes: 1000, tookMs: 1000, problem: null, from: new Date(at(4, 2, 10)).toISOString(), original: true },
      { at: at(3, 2, 30), kind: 'backup', ok: false, files: 0, bytes: 0, tookMs: 60_000, problem: 'computer_backup_cloud_unreachable', from: null, original: null },
    ],
    lastSuccess: at(0, 2, 14), problem: null, offline: false, skipped: 0, usage: [51.6 * GB, 413 * GB, 1024 ** 4], fullDiskAccess: true,
    keySavedAt: new Date(at(3, 10)).toISOString(), lockedCopy: false, purge: null, ...change,
  };
}
const DOCUMENTS = [
  { name: 'Household', folder: true, size: 0, changed: 0, files: 3 }, { name: 'Receipts', folder: true, size: 0, changed: 0, files: 12 },
  { name: 'School', folder: true, size: 0, changed: 0, files: 40 }, { name: 'House insurance.pdf', folder: false, size: 2.4 * 1024 ** 2, changed: at(40, 10, 5), files: null },
  { name: 'Passwords export.kdbx', folder: false, size: 310 * 1024, changed: at(1, 21, 30), files: null }, { name: 'Tax 2025.xlsx', folder: false, size: 84 * 1024, changed: at(3, 15, 42), files: null },
];
const off = { enabled: false, connected: false, lastSuccess: null, runs: [], usage: null, keySavedAt: null };
const STATES = [
  ['01-off', off], ['02-off-no-plan', { ...off, connected: true, plan: false }],
  ['03-setup-1-connect', off, 'setup1'], ['04-setup-1-waiting', { ...off, connecting: 'KMQD-7T2P' }, 'setup1'],
  ['05-setup-2-folders', { ...off, connected: true }, 'setup2'], ['06-setup-2-folders-full-disk-access', { ...off, connected: true, fullDiskAccess: false }, 'setup2', 'mac'],
  ['07-setup-2-folders-windows', { ...off, connected: true }, 'setup2', 'windows'],
  ['08-setup-3-key', { ...off, connected: true }, 'setup3'], ['09-setup-4-schedule', { ...off, connected: true }, 'setup4'],
  ['10-overview', {}], ['11-overview-running', { running: { startedAt: Date.now() - 4 * 60_000, files: 9000, bytes: 1.2 * GB, totalFiles: 26_556, totalBytes: 2.9 * GB, storedBytes: 0.4 * GB } }],
  ['12-overview-warning', { problem: 'computer_backup_cloud_unreachable' }], ['13-overview-offline', { offline: true, problem: 'computer_backup_cloud_unreachable' }],
  ['14-folders', {}, 'Folders'], ['15-schedule', {}, 'Schedule'], ['16-restore', {}, 'Restore'], ['17-restore-where', {}, 'Restore+'],
  ['18-recovery-key', {}, 'Recovery key'], ['19-settings', {}, 'Settings'], ['20-settings-delete', {}, 'Settings+'],
  ['21-settings-deleted-held', { purge: new Date(Date.now() + 30 * 86_400_000).toISOString() }, 'Settings'],
];

await withBrowser(async ({ browser, origin }) => {
  let shots = 0;
  for (const [name, change, how = '', only] of STATES) {
    for (const os of only ? [only] : ['mac', 'windows']) {
      for (const scheme of ['light', 'dark']) {
        const context = await browser.newContext({
          viewport: { width: 1100, height: 760 }, deviceScaleFactor: 2, colorScheme: scheme,
          userAgent: os === 'windows' ? 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        });
        const page = await context.newPage();
        const errors = [];
        const calls = [];
        let view = sample(os, change);
        page.on('pageerror', error => errors.push(error.message));
        await page.exposeFunction('backupInvoke', (command, args) => {
          calls.push(command);
          if (command === 'plugin:event|listen') return 1;
          if (['discover_camera_folders', 'photo_import_history'].includes(command)) return [];
          if (command === 'local_host_status') return { backgroundActive: false };
          if (command === 'restore_connection') return { navigationScope: 'scope-a', server: 'https://home-server.local', name: 'Taylor', mode: 'client', state: 'ready', features: { worker: false, workerSession: false, enrollment: true, nativeHost: false, sources: false } };
          if (command === 'server_summary') return { me: { isAdmin: true } };
          if (command === 'computer_backup_status') return view;
          if (command === 'computer_backup_connect') { view = { ...view, connecting: 'KMQD-7T2P' }; return 'KMQD-7T2P'; }
          if (command === 'computer_backup_connect_poll') return 'pending';
          if (command === 'computer_backup_setup_key') return 'FLRK-FGF9-M85J-PDHY-1RJF-9KZF-WRT8-7HYR-KYX2-0C4E-PQ8M-ZT3B-77AA';
          if (command === 'computer_backup_backups') return [0, 1, 2, 3, 7, 14, 30].map((days, index) => ({ key: `s/${String(30 - index).padStart(12, '0')}-a`, time: new Date(at(days, 2, 14)).toISOString(), files: 26_000, bytes: 62 * GB }));
          if (command === 'computer_backup_browse') return args.path.length ? DOCUMENTS : ['Desktop', 'Documents', 'Downloads'].map(n => ({ name: n, folder: true, size: 0, changed: 0, files: 1 }));
          return null;
        });
        await page.addInitScript(() => {
          globalThis.isTauri = true;
          globalThis.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} };
          globalThis.__TAURI_INTERNALS__ = { invoke: (...args) => globalThis.backupInvoke(...args), transformCallback: () => 1 };
        });
        await page.goto(origin);
        const sidebar = page.getByRole('navigation', { name: 'Sidebar' });
        await sidebar.getByRole('button', { name: 'Computer backup' }).click();
        await page.getByRole('heading', { name: 'Computer backup', exact: true }).waitFor();
        assert.ok(await sidebar.getByRole('button', { name: 'Recovery points' }).isVisible(), 'Server › Backups shows as Recovery points');
        const button = (label) => page.getByRole('button', { name: label, exact: true });
        if (how.startsWith('setup')) {
          await button('Set Up Computer Backup…').click();
          const step = Number(how.slice(5));
          if (step >= 3) { await button('Continue').click(); await page.getByText('FLRK-FGF9').waitFor(); }
          if (step >= 4) { await page.getByRole('checkbox').check(); await button('Continue').click(); await page.getByText('When to back up').waitFor(); }
        } else if (how) {
          await page.getByRole('tab', { name: how.replace('+', '') }).click();
          if (how === 'Restore' || how === 'Restore+') {
            await page.getByRole('button', { name: 'Open Documents' }).click();
            await page.getByText('Tax 2025.xlsx').waitFor();
            await page.getByRole('checkbox', { name: 'Select Receipts' }).check();
            await page.getByRole('checkbox', { name: 'Select Tax 2025.xlsx' }).check();
            assert.equal(await page.getByText('2 selected').count(), 1);
          }
          if (how === 'Restore+') await button('Restore…').click();
          if (how === 'Settings+') await button('Delete Backups…').click();
        }
        await page.waitForTimeout(350);
        // What each state must say, whatever it looks like.
        const expect = {
          '01-off': 'Set Up Computer Backup…', '02-off-no-plan': 'Not on this account', '03-setup-1-connect': 'Continue in Browser…',
          '04-setup-1-waiting': 'Check the code matches: KMQD-7T2P', '05-setup-2-folders': 'Left out', '06-setup-2-folders-full-disk-access': 'Full Disk Access',
          '07-setup-2-folders-windows': 'Windows snapshot', '08-setup-3-key': 'Download Recovery Kit…', '09-setup-4-schedule': 'Wait while on battery',
          '10-overview': 'Last backup Today', '11-overview-running': 'Backing up · 41%', '12-overview-warning': 'The last backup didn’t finish',
          '13-overview-offline': 'This computer is offline', '14-folders': 'Folders to back up', '15-schedule': 'Keep earlier versions for',
          '16-restore': 'As it was on', '17-restore-where': 'Where should they go?', '18-recovery-key': 'Show the recovery key',
          '19-settings': 'Delete this computer’s backups', '20-settings-delete': 'Keep My Backups calls it off', '21-settings-deleted-held': 'stay restorable for 30 more days',
        }[name];
        assert.ok(await page.getByText(expect, { exact: false }).first().isVisible(), `${name} (${os}, ${scheme}) shows “${expect}”`);
        if (name === '05-setup-2-folders') assert.equal(await page.getByRole('switch', { name: 'Back up Photos Library' }).count() + await page.getByRole('switch', { name: 'Back up Pictures' }).count(), 0, 'the photo library starts left out');
        assert.deepEqual(errors, [], `${name}: no page errors`);
        if (output) await page.screenshot({ path: join(output, `${name}-${os === 'windows' && !name.includes('windows') ? 'windows-' : ''}${scheme}.png`) });
        shots += 1;
        await context.close();
      }
    }
  }
  console.log(`Computer backup UI: ${shots} states checked`);
});
