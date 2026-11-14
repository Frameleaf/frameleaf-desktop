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
// The library session the running copy belongs to; cancelling names it so a switched library cannot be cancelled by mistake.
let copyEpoch: number | null = null;

const safeDrive: Record<Platform, string> = { mac: 'an APFS drive', windows: 'an NTFS drive', linux: 'an ext4 drive' };
export function explainCopy(error: unknown, platform: Platform): string {
  // Wording only this page uses; every other code takes the shared copy in errors.ts.
  const errors: Record<string, string> = {
    // Names the file system to choose on this platform.
    media_copy_destination_unsupported: `Choose a drive that can safely save a copy without replacing another file, such as ${safeDrive[platform]}.`,
    // Here these two codes are about saving a media copy, not about signing in or a missing server feature in general.
    sign_in_required: 'Sign in to your library before saving a media copy.',
    server_http_404: 'This server does not provide the preservation packages needed for Desktop copies.',
  };
  const code = String(error);
  return Object.hasOwn(errors, code) ? errors[code]! : explainError(error, 'The media copy could not be completed. Check your server and drive, then try again.');
}

export async function saveCopy(invoke: Invoke, packageId: string, epoch: number, platform: Platform): Promise<void> {
  if (get(mediaCopy).copying) return;
  copyEpoch = epoch;
  mediaCopy.set({ ...idle, copying: true });
  try { mediaCopy.set({ ...idle, saved: await invoke('save_preservation_copy', { packageId, epoch }) as SavedCopy | null }); }
  catch (error) { mediaCopy.set({ ...idle, message: explainCopy(error, platform) }); }
  finally { copyEpoch = null; }
}

export async function cancelCopy(invoke: Invoke, platform: Platform): Promise<void> {
  if (copyEpoch === null) return;
  mediaCopy.update(state => ({ ...state, cancelling: true }));
  try { await invoke('cancel_preservation_copy', { epoch: copyEpoch }); }
  catch (error) { mediaCopy.update(state => ({ ...state, cancelling: false, message: explainCopy(error, platform) })); }
}
