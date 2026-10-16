<script lang="ts">
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  type Hint = { label: string; path: string };
  type Inventory = { selectionId: string; path: string; photos: number; logicalBytes: number; skipped: number; truncated: boolean };
  let hints = $state<Hint[]>([]);
  let folder = $state<Inventory | null>(null);
  type Consent = { id: string; name: string; path: string; registered: boolean; allowDownload: boolean };
  let consent = $state<Consent | null>(null);
  let blockedConsent = $state(false);
  let allowReads = $state(false);
  let alive = true;
  let busy = $state(false);
  let message = $state('');
  const native = isTauri();
  const errors: Record<string, string> = {
    source_selection_changed: 'The folder selection expired. Choose the folder again.',
    source_remove_previous_approval: 'Remove the existing folder permission before choosing another folder.',
    source_photo_session_changed: 'This folder permission belongs to an earlier sign-in. Remove it and approve the folder again.',
    source_approval_invalid: 'The saved folder permission no longer matches this connection. Remove it before continuing.',
    credential_store_locked_or_unavailable: 'Unlock your computer’s credential store, then try again.',
    credential_store_unavailable: 'Your computer’s secure credential store is unavailable.',
    credential_record_invalid: 'The saved folder permission could not be read. Remove it before continuing.',
    server_http_404: 'Your server needs the desktop photo-source update before this folder can be registered.',
    source_server_update_required: 'Your server needs the desktop photo-source update.',
    source_registration_unavailable: 'The server could not be reached. The local permission is saved; retry registration when connected.',
    source_registration_response_invalid: 'The server did not confirm this exact folder permission. Copying remains stopped.',
    server_identity_changed: 'The server identity changed. Sign out before reconnecting.',

    source_choose_photo_subfolder: 'Choose a photo folder inside your home folder, rather than your entire home folder.',
    source_package_requires_provider: 'Apple Photos libraries need the Photos connection. Choose an ordinary folder here.',
    source_folder_unavailable: 'This folder is unavailable. Check that its drive is connected and you have access.',
    source_account_unavailable: 'This OneDrive folder moved or is unavailable. Choose its new location.',
  };
  function explain(error: unknown) { return errors[String(error)] ?? 'This operation could not finish. Check the server connection and try again.'; }
  async function loadConsent() {
    try {
      const current = await invoke<Consent | null>('photo_source_status');
      if (alive) { consent = current; blockedConsent = false; }
    } catch (error) {
      if (alive) {
        blockedConsent = ['source_photo_session_changed', 'source_approval_invalid', 'credential_record_invalid'].includes(String(error));
        message = explain(error);
      }
    }
  }
  onMount(() => {
    if (native) void loadConsent();
    return () => { alive = false; };
  });
  async function approve(retry = false) {
    if (!retry && (!folder || !allowReads)) return;
    busy = true; message = '';
    try {
      consent = await invoke<Consent>('approve_photo_folder', { selectionId: retry ? null : folder!.selectionId, allowDownload: allowReads });
      folder = null; allowReads = false;
    } catch (error) { await loadConsent(); message = explain(error); }
    finally { busy = false; }
  }
  async function revoke() {
    busy = true; message = '';
    try {
      const confirmed = await invoke<boolean>('revoke_photo_source');
      consent = null; blockedConsent = false; folder = null; allowReads = false;
      message = confirmed ? 'Folder permission removed. Existing server copies are kept.' : 'Local folder permission removed. The server could not confirm revocation; check it when connected.';
    } catch (error) { message = explain(error); }
    finally { busy = false; }
  }
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
      if (selected) { folder = selected; allowReads = false; }
    } catch (error) { message = errors[String(error)] ?? 'Could not preview this folder. Choose an accessible photo folder and try again.'; }
    finally { busy = false; }
  }
</script>

<section class="sources" aria-labelledby="photo-sources-heading" aria-busy={busy}>
  <h2 id="photo-sources-heading">Photo sources</h2>
  <p>Choose where to bring photos from. Local folders are separate from this computer’s AI processing permission.</p>
  <div class="actions">
    <button class="secondary" disabled={busy || !native || !!consent || blockedConsent} onclick={() => choose()}>Choose a photo folder</button>
    <button class="text-button" disabled={busy || !native || !!consent || blockedConsent} onclick={discover}>Find OneDrive folders</button>
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
  {#if consent}
    <div class="folder-preview" aria-label="Approved photo folder">
      <strong>{consent.name}</strong><p>{consent.path}</p>
      <p>{consent.registered ? 'Folder permission saved and registered with your server. Copying has not started.' : 'Folder permission saved locally. Server registration still needs to finish.'}</p>
      {#if !consent.registered}<button class="secondary" disabled={busy} onclick={() => approve(true)}>Retry server registration</button>{/if}
      <button class="text-button" disabled={busy} onclick={revoke}>Remove folder permission</button>
    </div>
  {:else if blockedConsent}
    <button class="text-button" disabled={busy} onclick={revoke}>Remove previous folder permission</button>
  {/if}
  {#if folder && !consent && !blockedConsent}
    <div class="folder-preview" aria-label="Selected folder preview">
      <strong>{folder.path}</strong>
      <p>{folder.photos.toLocaleString()} photo or video filenames found{folder.truncated ? ' in a partial preview' : ''}.</p>
      <p class="footnote">{folder.skipped ? `${folder.skipped} unavailable, linked or excluded entries skipped. ` : ''}Counts use filenames and metadata. Files have not been opened, downloaded or imported. Cloud-only availability and account completeness are unknown.</p>
      <label class="source-consent"><input type="checkbox" bind:checked={allowReads} disabled={busy}> Allow this folder to be read for copying. Cloud-only originals may require downloading; approval does not start a copy.</label>
      <button class="secondary" disabled={busy || !allowReads} onclick={() => approve()}>Approve this folder</button>
      <button class="text-button" disabled={busy} onclick={() => { folder = null; allowReads = false; }}>Clear preview</button>
    </div>
  {/if}
  <p class="footnote">This build previews folders and manages folder permission. Copy imports and external-library connections are still being implemented. Selecting a OneDrive folder does not sign in to or inventory your entire cloud account.</p>
</section>

<style>
  .sources { margin-top: 36px; padding-top: 28px; border-top: 1px solid var(--border); }
  p { color: var(--muted); line-height: 1.6; }
  .actions { flex-wrap: wrap; margin-top: 16px; }
  ul { padding: 0; list-style: none; }
  li, .folder-preview { margin-top: 14px; padding: 16px; border: 1px solid var(--border); border-radius: 8px; background: var(--panel); overflow-wrap: anywhere; }
  .source-consent { display: flex; align-items: start; gap: 10px; margin: 16px 0; color: var(--muted); line-height: 1.6; }
  .source-consent input { margin-top: 5px; flex-shrink: 0; }
  small { display: block; color: var(--muted); margin: 6px 0; }
</style>
