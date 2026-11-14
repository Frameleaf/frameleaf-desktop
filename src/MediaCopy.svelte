<script lang="ts">
  import ErrorText from './ErrorText.svelte';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { formatBytes, formatWhen, platformFromUserAgent } from './ui-state';
  import { cancelCopy, explainCopy, mediaCopy, saveCopy } from './media-copy';

  type Package = { id: string; name: string; createdAt: string; manifest: { exported: number } };
  const native = isTauri();
  const platform = platformFromUserAgent(navigator.userAgent);
  let packages = $state<Package[] | null>(null);
  let packageEpoch = $state<number | null>(null);
  let loading = $state(false);
  let message = $state('');
  // Leaving this page does not cancel a copy: its state is kept in media-copy.ts and shown again here.
  const copying = $derived($mediaCopy.copying);
  const explain = (error: unknown) => explainCopy(error, platform);
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
  function save(id: string) {
    // The copy is fenced to the library session the package list came from.
    if (packageEpoch === null) return;
    message = '';
    void saveCopy(invoke, id, packageEpoch, platform);
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
      <div class="row" role="status"><span class="l"><small>{$mediaCopy.cancelling ? 'Cancelling the copy…' : 'Waiting for a destination or downloading and verifying the archive. Keep the drive connected. The copy continues if you leave this page.'}</small></span><button class="btn quiet" disabled={$mediaCopy.cancelling} onclick={() => cancelCopy(invoke, platform)}>Cancel copy</button></div>
    {/if}
    {#if message || $mediaCopy.message}<div class="row"><span class="l"><small role="status"><ErrorText text={message || $mediaCopy.message} /></small></span></div>{/if}
    {#if $mediaCopy.saved}
      {@const saved = $mediaCopy.saved}
      <div class="row top"><span class="l"><b>Verified copy saved</b><small role="status">{saved.originals.toLocaleString()} originals · {formatBytes(saved.bytes)} · {saved.path}</small><small>Before relying on this backup for recovery, open originals and play videos from a separate recovery location.</small></span></div>
    {/if}
  </div>
</section>
