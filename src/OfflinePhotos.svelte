<script lang="ts">
  import ErrorText from './ErrorText.svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import { formatBytes } from './ui-state';
  import { explainError } from './errors';

  type Media = { id: string; name: string; mime: string };
  type Album = { id: string; name: string; bytes: number; expiresAt: number; items: Media[] };
  type Progress = { done: number; total: number; error: string | null };
  type Status = { busy: boolean; albums: Album[]; progress: Progress | null };

  let albums = $state<Album[]>([]);
  let progress = $state<Progress | null>(null);
  let albumId = $state('');
  let selected = $state<Media | null>(null);
  let mediaUrl = $state('');
  let loading = $state(false);
  let busy = $state(false);
  let message = $state('');
  let generation = 0;
  const album = $derived(albums.find(({ id }) => id === albumId));
  // The other offline album codes take the shared copy in errors.ts; this window names what signing in is for.
  const errorMessages: Record<string, string> = {
    sign_in_required: 'Sign in to Frameleaf to open offline albums.',
    // Each approved library has its own offline storage, which this window can clear.
    offline_album_storage_unavailable: 'Frameleaf could not open this Library’s offline storage. You can clear it here and keep the albums again from Photos.',
  };
  const explain = (error: unknown) => errorMessages[String(error)] ?? explainError(error, 'Frameleaf could not verify or open this offline album.');

  function closeMedia() {
    generation += 1;
    if (mediaUrl) void invoke('offline_album_close_media', { grant: mediaUrl.split('/').at(-1) }).catch(() => {});
    mediaUrl = '';
    selected = null;
  }

  async function refresh(resetMedia = false) {
    if (resetMedia) closeMedia();
    if (loading || busy) return;
    loading = true;
    try {
      const value = await invoke<Status>('offline_album_status');
      if (value.busy) { if (value.progress) progress = value.progress; return; }
      progress = value.progress;
      albums = value.albums;
      if (albumId && !albums.some(({ id }) => id === albumId)) {
        albumId = '';
        closeMedia();
      }
      message = progress?.error ? explain(progress.error) : '';
    } catch (error) {
      albums = [];
      closeMedia();
      message = explain(error);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    const reconnect = () => { void refresh(true); };
    const focus = () => { void refresh(); };
    let ticks = 0;
    const timer = setInterval(() => {
      ticks += 1;
      const live = albums.filter(({ expiresAt }) => expiresAt * 1000 > Date.now());
      if (live.length !== albums.length) albums = live;
      if (albumId && !live.some(({ id }) => id === albumId)) {
        albumId = '';
        closeMedia();
      }
      if ((progress && !progress.error) || ticks % 30 === 0) void refresh();
    }, 1000);
    window.addEventListener('online', reconnect);
    window.addEventListener('focus', focus);
    void refresh();
    return () => {
      clearInterval(timer);
      window.removeEventListener('online', reconnect);
      window.removeEventListener('focus', focus);
      closeMedia();
    };
  });

  async function open(item: Media) {
    if (!album || busy) return;
    closeMedia();
    const expected = generation;
    const id = album.id;
    selected = item;
    busy = true;
    message = '';
    try {
      const url = await invoke<string>('offline_album_original', { album: id, item: item.id });
      if (expected === generation) mediaUrl = url;
    } catch (error) {
      closeMedia();
      message = explain(error);
    } finally {
      busy = false;
    }
  }

  function cannotPreview() {
    message = 'This original could not be previewed. Save it to open it in another app.';
  }

  async function saveOriginal() {
    if (!album || !selected || busy) return;
    busy = true;
    message = '';
    try { await invoke('offline_album_save_original', { album: album.id, item: selected.id }); }
    catch (error) { message = explain(error); }
    finally { busy = false; }
  }

  async function remove(id: string | null) {
    if (busy) return;
    closeMedia();
    busy = true;
    try {
      await invoke('offline_album_remove', { album: id });
      albumId = '';
    } catch (error) {
      message = explain(error);
      return;
    } finally {
      busy = false;
    }
    await refresh();
  }

  async function cancel() {
    try { await invoke('offline_album_cancel'); }
    catch (error) { message = explain(error); }
  }

  async function browse() {
    closeMedia();
    try { await invoke('offline_album_browse_library'); }
    catch (error) { message = explain(error); }
  }
</script>

<main class="offline">
  <header class="top">
    <div>
      <h1>Offline albums</h1>
      <p>Open originals for up to 24 hours after Frameleaf last verified access with your Library.</p>
    </div>
    <button class="btn" onclick={browse}>Back to Photos</button>
  </header>

  {#if !album && !albums.length && (!progress || progress.error) && !loading}
    <button class="btn quiet" disabled={busy} onclick={() => remove(null)}>Clear Offline Storage</button>
  {/if}
  {#if progress && !progress.error}
    <section class="download" aria-label="Offline album download">
      <div><strong>Keeping album offline</strong><p role="status">{progress.done} of {progress.total} originals saved</p></div>
      <progress aria-label="Originals saved" value={progress.done} max={Math.max(1, progress.total)}></progress>
      <button class="btn" onclick={cancel}>Cancel Download</button>
    </section>
  {/if}
  {#if message}<p role="status" class="notice"><ErrorText text={message} /></p>{/if}
  {#if album}
    <div class="album-heading">
      <button class="btn quiet" onclick={() => { albumId = ''; closeMedia(); }}>All Offline Albums</button>
      <div>
        <h2>{album.name || 'Untitled album'}</h2>
        <p>{album.items.length.toLocaleString()} originals · {formatBytes(album.bytes)}</p>
        <p>Offline access expires {new Date(album.expiresAt * 1000).toLocaleString()} unless reverified.</p>
      </div>
      <button class="btn" disabled={busy} onclick={() => remove(album!.id)}>Remove from This Computer</button>
    </div>
    {#if selected}
      <section class="viewer" aria-label="Original preview">
        <div class="viewer-heading">
          <strong>{selected.name || 'Original'}</strong>
          <button class="btn" disabled={busy} onclick={saveOriginal}>Save Original</button>
          <button class="btn quiet" onclick={closeMedia}>Close Preview</button>
        </div>
        {#if !mediaUrl}
          <p role="status">Checking access and opening the original…</p>
        {:else if selected.mime.startsWith('image/')}
          <img src={mediaUrl} alt={selected.name || 'Album original'} onerror={cannotPreview} />
        {:else if selected.mime.startsWith('video/')}
          <video src={mediaUrl} controls aria-label={selected.name || 'Album original'} onerror={cannotPreview}>
            <track kind="captions" />
          </video>
        {:else}
          <p>Save this original to open it with an app that supports its format.</p>
        {/if}
      </section>
    {/if}
    <ul class="items">
      {#each album.items as item (item.id)}
        <li><button class="btn" disabled={busy} onclick={() => open(item)}>{item.name || 'Original'}</button></li>
      {/each}
    </ul>
  {:else if albums.length}
    <ul class="albums">
      {#each albums as item (item.id)}
        <li><button class="btn album" onclick={() => { albumId = item.id; }}>
          <strong>{item.name || 'Untitled album'}</strong><span>{item.items.length.toLocaleString()} originals · {formatBytes(item.bytes)}</span>
        </button></li>
      {/each}
    </ul>
  {:else if !progress && !message}
    <p>{loading ? 'Checking album access…' : 'No offline albums are available. Open an album in Photos and choose Keep Offline.'}</p>
  {/if}
</main>

<style>
  .offline { max-width: 1000px; height: 100vh; margin: 0 auto; padding: 42px 36px; overflow: auto; }
  h1, h2, p { margin: 0; }
  h1 { margin-bottom: 8px; }
  p { color: var(--muted); }
  .top, .album-heading, .viewer-heading, .download { display: flex; align-items: center; flex-wrap: wrap; gap: 14px; }
  .top { justify-content: space-between; padding-bottom: 28px; }
  .album-heading { padding-bottom: 18px; }
  .album-heading > div, .viewer-heading strong { flex: 1; min-width: 0; overflow-wrap: anywhere; }
  .download, .viewer { border: 1px solid var(--border); border-radius: 12px; padding: 14px; margin: 12px 0 22px; }
  .notice { margin: 12px 0; }
  .albums, .items { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }
  .albums { grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
  .items { grid-template-columns: repeat(auto-fill, minmax(185px, 1fr)); }
  .items button, .album { width: 100%; overflow-wrap: anywhere; white-space: normal; }
  .album { display: grid; justify-items: start; gap: 6px; min-height: 66px; padding: 12px; }
  .viewer img, .viewer video { display: block; margin: 12px auto 0; max-width: 100%; max-height: 60vh; }
  progress { flex: 1; }
</style>
