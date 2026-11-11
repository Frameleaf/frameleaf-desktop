<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { albumErrors, type AlbumDestination } from './import-destination';

  let {
    albumMode = $bindable(false),
    destination = $bindable<AlbumDestination | null>(null),
    disabled = false,
    onchange,
  }: { albumMode?: boolean; destination?: AlbumDestination | null; disabled?: boolean; onchange?: () => void } = $props();

  let query = $state('');
  let albums = $state<AlbumDestination[]>([]);
  let loading = $state(false);
  let loaded = $state(false);
  let error = $state('');

  async function search() {
    if (disabled || loading) return;
    loading = true;
    loaded = false;
    error = '';
    try {
      albums = await invoke<AlbumDestination[]>('list_photo_import_albums', { search: query });
      loaded = true;
    } catch (reason) {
      error = albumErrors[String(reason)] ?? 'Albums could not be loaded. Check the library connection and try again.';
    } finally { loading = false; }
  }

  function selectMode(event: Event) {
    albumMode = (event.currentTarget as HTMLSelectElement).value === 'album';
    onchange?.();
    if (!albumMode) {
      destination = null;
      return;
    }
    if (!loaded) void search();
  }
</script>

<div class="destination">
  <label>
    Destination
    <select value={albumMode ? 'album' : 'library'} onchange={selectMode} {disabled}>
      <option value="library">Library</option>
      <option value="album">Album</option>
    </select>
  </label>
  {#if albumMode}
    <div class="search">
      <input type="search" maxlength="100" placeholder="Find an album" aria-label="Album name" bind:value={query} onkeydown={event => { if (event.key === 'Enter') { event.preventDefault(); void search(); } }} disabled={disabled || loading} />
      <button class="btn small" type="button" onclick={search} disabled={disabled || loading}>Search Albums</button>
    </div>
    {#if loading}<small role="status">Loading albums…</small>
    {:else if error}<small role="status" class="danger-text">{error}</small>
    {:else if loaded && !albums.length}<small role="status">No writable albums found. Try another name.</small>{/if}
    {#if albums.length || destination}
      <label>
        Album
        <select
          value={destination?.id ?? ''}
          onchange={event => { destination = albums.find(album => album.id === event.currentTarget.value) ?? null; onchange?.(); }}
          disabled={disabled || loading}
        >
          <option value="">Choose an album</option>
          {#if destination && !albums.some(album => album.id === destination?.id)}
            <option value={destination.id}>{destination.name}{destination.shared ? ' (shared)' : ''}</option>
          {/if}
          {#each albums as album (album.id)}<option value={album.id}>{album.name}{album.shared ? ' (shared)' : ''}</option>{/each}
        </select>
      </label>
    {/if}
    {#if destination?.shared}<small>People with access to this shared album will be able to see the photos you add.</small>{/if}
  {/if}
</div>

<style>
  .destination { display: grid; gap: 6px; margin: 10px 0; }
  .destination label, .search { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .destination select { max-width: 100%; }
</style>
