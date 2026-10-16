<script lang="ts">
  import { invoke, isTauri } from '@tauri-apps/api/core';
  type Hint = { label: string; path: string };
  type Inventory = { path: string; photos: number; logicalBytes: number; skipped: number; truncated: boolean };
  let hints = $state<Hint[]>([]);
  let folder = $state<Inventory | null>(null);
  let busy = $state(false);
  let message = $state('');
  const native = isTauri();
  const errors: Record<string, string> = {
    source_choose_photo_subfolder: 'Choose a photo folder inside your home folder, rather than your entire home folder.',
    source_package_requires_provider: 'Apple Photos libraries need the Photos connection. Choose an ordinary folder here.',
    source_folder_unavailable: 'This folder is unavailable. Check that its drive is connected and you have access.',
    source_account_unavailable: 'This OneDrive folder moved or is unavailable. Choose its new location.',
  };
  async function discover() {
    busy = true; message = '';
    try {
      hints = await invoke<Hint[]>('discover_onedrive');
      if (!hints.length) message = 'No OneDrive folder was found in the known sync locations. You can choose a synced folder yourself.';
    } catch { message = 'Could not check OneDrive locations. Choose a synced folder yourself.'; }
    finally { busy = false; }
  }
  async function choose(oneDrive: number | null = null) {
    busy = true; message = '';
    try {
      const selected = await invoke<Inventory | null>('choose_photo_folder', { oneDrive });
      if (selected) folder = selected;
    } catch (error) { message = errors[String(error)] ?? 'Could not preview this folder. Choose an accessible photo folder and try again.'; }
    finally { busy = false; }
  }
</script>

<section class="sources" aria-labelledby="photo-sources-heading" aria-busy={busy}>
  <h2 id="photo-sources-heading">Photo sources</h2>
  <p>Choose where to bring photos from. Local folders are separate from this computer’s AI processing permission.</p>
  <div class="actions">
    <button class="secondary" disabled={busy || !native} onclick={() => choose()}>Choose a photo folder</button>
    <button class="text-button" disabled={busy || !native} onclick={discover}>Find OneDrive folders</button>
  </div>
  {#if hints.length}
    <ul aria-label="Known OneDrive folders">
      {#each hints as hint, index (hint.path)}
        <li><strong>{hint.label}</strong><small>{hint.path}</small><button class="text-button" disabled={busy} onclick={() => choose(index)}>Choose folders</button></li>
      {/each}
    </ul>
  {/if}
  {#if busy}<p role="status">Waiting for folder selection or checking file metadata…</p>{/if}
  {#if message}<p role="status">{message}</p>{/if}
  {#if folder}
    <div class="folder-preview" aria-label="Selected folder preview">
      <strong>{folder.path}</strong>
      <p>{folder.photos.toLocaleString()} photo or video filenames found{folder.truncated ? ' in a partial preview' : ''}.</p>
      <p class="footnote">{folder.skipped ? `${folder.skipped} unavailable, linked or excluded entries skipped. ` : ''}Counts use filenames and metadata. Files have not been opened, downloaded or imported. Cloud-only availability and account completeness are unknown.</p>
      <button class="text-button" disabled={busy} onclick={() => { folder = null; }}>Clear preview</button>
    </div>
  {/if}
  <p class="footnote">This build previews folders only. Copy imports and external-library connections are still being implemented. Selecting a OneDrive folder does not sign in to or inventory your entire cloud account.</p>
</section>

<style>
  .sources { margin-top: 36px; padding-top: 28px; border-top: 1px solid var(--border); }
  p { color: var(--muted); line-height: 1.6; }
  .actions { flex-wrap: wrap; margin-top: 16px; }
  ul { padding: 0; list-style: none; }
  li, .folder-preview { margin-top: 14px; padding: 16px; border: 1px solid var(--border); border-radius: 8px; background: var(--panel); overflow-wrap: anywhere; }
  small { display: block; color: var(--muted); margin: 6px 0; }
</style>
