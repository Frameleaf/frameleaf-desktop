<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import Sheet from './Sheet.svelte';
  import { connectionError } from './errors';
  import type { Connection } from './server-types';

  type Library = { id: string; server: string; name: string; active: boolean };
  let { onclose, onactivate }: {
    onclose: () => void; onactivate: (connection: Connection) => void;
  } = $props();

  let libraries = $state<Library[]>([]);
  let busy = $state(false);
  let failure = $state('');
  let notice = $state('');
  let adding = $state(false);
  let removing = $state<Library | null>(null);
  let server = $state('');
  let email = $state('');
  let password = $state('');
  let deviceName = $state('My computer');

  async function run(action: () => Promise<void>) {
    busy = true; failure = ''; notice = '';
    try { await action(); }
    catch (error) { failure = connectionError(error); }
    finally { busy = false; }
  }

  async function refresh() {
    libraries = await invoke<Library[]>('approved_libraries');
  }

  onMount(() => { void run(refresh); });

  async function activate(id: string) {
    await run(async () => {
      onactivate(await invoke<Connection>('activate_approved_library', { id }));
    });
  }

  async function submit() {
    if (removing) {
      const { id } = removing;
      await run(async () => {
        const revoked = await invoke<boolean>('remove_approved_library', { id });
        removing = null;
        await refresh();
        notice = revoked
          ? 'Library removed from this computer.'
          : 'Library removed from this computer. Revoke its session from the server when it is available.';
      });
    } else if (adding && server && email && password && deviceName.trim()) {
      const secret = password;
      password = '';
      await run(async () => {
        onactivate(await invoke<Connection>('add_approved_library', { server, email, password: secret, deviceName }));
      });
    }
  }
</script>

<Sheet
  title={removing ? 'Remove approved library?' : adding ? 'Approve another library' : 'Approved libraries'}
  {busy} onclose={onclose} onsubmit={submit}
>
  {#if removing}
    <p>Remove {removing.name} at {removing.server} from this computer? Its saved sign-in and import permissions will be removed.</p>
  {:else if adding}
    <p>Sign in to approve this library on this computer. Switching closes Photos and stops imports and AI work for the previous library.</p>
    <div class="form">
      <label>Server address <input type="text" inputmode="url" placeholder="https://photos.example.com" required bind:value={server} /></label>
      <label>Email <input type="email" autocomplete="username" required bind:value={email} /></label>
      <label>Password <input type="password" autocomplete="current-password" required bind:value={password} /></label>
      <label>Computer name <input type="text" maxlength="128" required bind:value={deviceName} /></label>
    </div>
  {:else}
    <p>Switching closes Photos and parks imports and AI work for the previous library.</p>
    {#if libraries.length > 0}
      <ul class="libraries" aria-label="Approved libraries">
        {#each libraries as library (library.id)}
          <li>
            <div><strong>{library.name}</strong><small>{library.server}</small></div>
            {#if library.active}
              <span>Active</span>
            {:else}
              <button class="btn small primary" type="button" disabled={busy} onclick={() => activate(library.id)}>Switch</button>
              <button class="btn small quiet" type="button" disabled={busy} onclick={() => { removing = library; failure = ''; }}>Remove</button>
            {/if}
          </li>
        {/each}
      </ul>
    {:else if !busy && !failure}
      <p>No libraries are saved on this computer.</p>
    {/if}
  {/if}
  {#if failure}
    <div class="inline-msg error" role="alert"><p>{failure}</p></div>
  {/if}
  {#if notice}<p role="status">{notice}</p>{/if}
  {#snippet actions()}
    {#if removing || adding}
      <button class="btn" type="button" disabled={busy} onclick={() => { adding = false; removing = null; password = ''; void run(refresh); }}>Back</button>
      {#if removing}
        <button class="btn danger" type="submit" disabled={busy}>{busy ? 'Removing…' : 'Remove library'}</button>
      {:else}
        <button class="btn primary" type="submit" disabled={busy || !server || !email || !password || !deviceName.trim()}>
          {busy ? 'Approving…' : 'Approve and switch'}
        </button>
      {/if}
    {:else}
      <button class="btn" type="button" disabled={busy} onclick={onclose}>Done</button>
      <button class="btn primary" type="button" disabled={busy} onclick={() => { adding = true; failure = ''; }}>Add library</button>
    {/if}
  {/snippet}
</Sheet>

<style>
  .libraries { list-style: none; margin: 12px 0; padding: 0; }
  .libraries li { display: flex; align-items: center; gap: 8px; padding: 10px 0; border-bottom: 1px solid var(--border); }
  .libraries li > div { flex: 1; min-width: 0; overflow-wrap: anywhere; }
  .libraries small { display: block; color: var(--muted); }
  .form { display: grid; gap: 12px; margin: 16px 0; }
  .form label { display: grid; gap: 5px; }
  .form input { min-width: 0; width: 100%; }
</style>
