<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import Icon from './Icon.svelte';

  type Hint = { label: string; path: string };
  let { busy, onchoose }: { busy: boolean; onchoose: (path: string) => void } = $props();
  let hints = $state<Hint[]>([]);

  onMount(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function refresh() {
      const found = await invoke<Hint[]>('discover_camera_folders').catch(() => []);
      if (stopped) return;
      hints = found;
      timer = setTimeout(refresh, 5000);
    }
    void refresh();
    return () => { stopped = true; clearTimeout(timer); };
  });
</script>

{#if hints.length}
  <div>
    <div class="group-head"><h2 class="group-title">Cameras and memory cards</h2></div>
    <div class="group">
      {#each hints as hint (hint.path)}
        <div class="row">
          <span class="ic" aria-hidden="true"><Icon name="folder" /></span>
          <span class="l"><b>{hint.label}</b><small>Camera photos and videos</small></span>
          <button class="btn" aria-label={`Preview photos from ${hint.label}`} disabled={busy} onclick={() => onchoose(hint.path)}>Preview…</button>
        </div>
      {/each}
    </div>
  </div>
{/if}
