// State of the external media copy. It lives outside MediaCopy.svelte so the copy keeps running, and
// keeps its outcome, while the Backups page is closed. Only cancelCopy cancels it.
import { get, writable } from 'svelte/store';
import type { Platform } from './ui-state.ts';
import { explainError } from './errors.ts';

export type SavedCopy = { path: string; originals: number; bytes: number };
export type CopyState = { copying: boolean; cancelling: boolean; saved: SavedCopy | null; message: string };
type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>;

const idle: CopyState = { copying: false, cancelling: false, saved: null, message: '' };
export const mediaCopy = writable<CopyState>(idle);

const safeDrive: Record<Platform, string> = { mac: 'an APFS drive', windows: 'an NTFS drive', linux: 'an ext4 drive' };
export function explainCopy(error: unknown, platform: Platform): string {
  const errors: Record<string, string> = {
    media_copy_package_unavailable: 'This package is no longer available as a complete, verified export. Refresh the list or verify it again in Photos.',
    media_copy_session_changed: 'Your server sign-in changed. Sign in again before saving a copy.',
    media_copy_destination_invalid: 'Choose a writable folder on a local drive. Check that the drive is still connected.',
    media_copy_destination_unsupported: `Choose a drive that can safely save a copy without replacing another file, such as ${safeDrive[platform]}.`,
    sign_in_required: 'Sign in to your library before saving a media copy.',
    media_copy_busy: 'Wait for the current media copy or update to finish.',
    media_copy_server_unavailable: 'Could not check whether your library supports media copies. Check your connection and refresh the list.',
    media_copy_download_failed: 'The download stopped. Check your library connection and try again.',
    media_copy_destination_exists: 'This folder already has a copy with the same package ID. Choose another folder to keep both.',
    media_copy_space_insufficient: 'The selected drive does not have enough free space for this archive.',
    media_copy_archive_invalid: 'The downloaded package did not match its verified manifest. Try verifying the package again in Photos.',
    media_copy_write_failed: 'The copy could not be saved. Check the drive and its file-size limits.',
    server_http_404: 'This server does not provide the preservation packages needed for Desktop copies.',
  };
  const code = String(error);
  return Object.hasOwn(errors, code) ? errors[code]! : explainError(error, 'The media copy could not be completed. Check your server and drive, then try again.');
}

export async function saveCopy(invoke: Invoke, packageId: string, platform: Platform): Promise<void> {
  if (get(mediaCopy).copying) return;
  mediaCopy.set({ ...idle, copying: true });
  try { mediaCopy.set({ ...idle, saved: await invoke('save_preservation_copy', { packageId }) as SavedCopy | null }); }
  catch (error) { mediaCopy.set({ ...idle, message: error === 'media_copy_cancelled' ? 'Media copy cancelled.' : explainCopy(error, platform) }); }
}

export async function cancelCopy(invoke: Invoke, platform: Platform): Promise<void> {
  mediaCopy.update(state => ({ ...state, cancelling: true }));
  try { await invoke('cancel_preservation_copy'); }
  catch (error) { mediaCopy.update(state => ({ ...state, cancelling: false, message: explainCopy(error, platform) })); }
}
