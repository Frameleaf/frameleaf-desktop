<script lang="ts">
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { onDestroy } from 'svelte';
  import { formatBytes, formatWhen } from './ui-state';

  type Package = { id: string; name: string; createdAt: string; manifest: { exported: number } };
  type SavedCopy = { path: string; originals: number; bytes: number };
  const native = isTauri();
  let packages = $state<Package[] | null>(null);
  let packageEpoch = $state<number | null>(null);
  let copyEpoch = $state<number | null>(null);
  let loading = $state(false);
  let copying = $state(false);
  let cancelling = $state(false);
  let saved = $state<SavedCopy | null>(null);
  let message = $state('');
  onDestroy(() => {
    if (native && copyEpoch !== null) void invoke('cancel_preservation_copy', { epoch: copyEpoch }).catch(() => {});
  });

  const errors: Record<string, string> = {
    media_copy_package_unavailable: 'This package is no longer available as a complete, verified export. Refresh the list or verify it again in Photos.',
    media_copy_session_changed: 'Your library changed. Reload the verified packages before saving a copy.',
    media_copy_destination_invalid: 'Choose a writable folder on a local drive. Check that the drive is still connected.',
    media_copy_destination_unsupported: 'Choose a drive that can safely save a copy without replacing another file, such as an APFS drive.',
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
  function explain(error: unknown) {
    const code = String(error);
    return Object.hasOwn(errors, code) ? errors[code]! : 'The media copy could not be completed. Check your server and drive, then try again.';
  }
  async function load() {
    loading = true;
    message = '';
    try {
      const result = await invoke<{ epoch: number; packages: Package[] }>('preservation_copy_packages');
      packages = result.packages;
      packageEpoch = result.epoch;
    }
    catch (error) { message = explain(error); }
    finally { loading = false; }
  }
  async function save(id: string) {
    if (packageEpoch === null) return;
    copyEpoch = packageEpoch;
    copying = true;
    message = '';
    saved = null;
    try { saved = await invoke<SavedCopy | null>('save_preservation_copy', { packageId: id, epoch: copyEpoch }); }
    catch (error) { message = error === 'media_copy_cancelled' ? 'Media copy cancelled.' : explain(error); }
    finally { copyEpoch = null; copying = false; cancelling = false; }
  }
  async function cancel() {
    if (copyEpoch === null) return;
    cancelling = true;
    try { await invoke('cancel_preservation_copy', { epoch: copyEpoch }); }
    catch (error) { message = explain(error); cancelling = false; }
  }
  async function openPhotos() {
    message = '';
    try { await invoke('open_photos'); }
    catch (error) { message = explain(error); }
  }
</script>

<section aria-labelledby="media-copy-heading" aria-busy={loading || copying}>
  <div class="group-head">
    <h2 class="group-title" id="media-copy-heading">External media copy</h2>
    <button class="btn quiet" disabled={!native || copying || loading} onclick={openPhotos}>Open Photos</button>
    <button class="btn quiet" disabled={!native || copying || loading} onclick={load}>{packages ? 'Refresh packages' : 'Load verified packages'}</button>
  </div>
  <div class="group">
    <div class="row top"><span class="l"><b>Save originals and their package metadata</b><small>In Photos, preview, create and verify a preservation package. Then load the verified package here and choose a folder on your external drive. Keep a separate database backup for library recovery.</small></span></div>
    {#if packages?.length}
      {#each packages as item (item.id)}
        <div class="row top">
          <span class="l"><b>{item.name}</b><small>{formatWhen(item.createdAt, Date.now())} · {item.manifest.exported.toLocaleString()} originals</small></span>
          <button class="btn" disabled={copying || loading} onclick={() => save(item.id)}>Save verified copy…</button>
        </div>
      {/each}
    {:else if packages}
      <div class="row"><span class="l"><small>No complete, verified packages are available for this account. Use Photos to manage packages that contain Locked items.</small></span></div>
    {/if}
    {#if copying}
      <div class="row" role="status"><span class="l"><small>{cancelling ? 'Cancelling the copy…' : 'Waiting for a destination or downloading and verifying the archive. Keep the drive connected.'}</small></span><button class="btn quiet" disabled={cancelling} onclick={cancel}>Cancel copy</button></div>
    {/if}
    {#if message}<div class="row"><span class="l"><small role="status">{message}</small></span></div>{/if}
    {#if saved}
      <div class="row top"><span class="l"><b>Verified copy saved</b><small role="status">{saved.originals.toLocaleString()} originals · {formatBytes(saved.bytes)} · {saved.path}</small><small>Before relying on this backup for recovery, open originals and play videos from a separate recovery location.</small></span></div>
    {/if}
  </div>
</section>
