<script lang="ts">
  // A modal sheet over the content: dimmed backdrop, title, body, actions. Used for confirmations and
  // password prompts. Escape and the backdrop close it unless `busy`.
  import type { Snippet } from 'svelte';
  import mark from './mark.svg';
  let { title, open = true, kind = 'plain', busy = false, wide = false, onclose, onsubmit, children, actions, labelledby = undefined }: {
    title: string; open?: boolean; kind?: 'plain' | 'warning' | 'danger'; busy?: boolean; wide?: boolean;
    onclose?: () => void; onsubmit?: () => void; children?: Snippet; actions?: Snippet; labelledby?: string | undefined;
  } = $props();
  const id = `sheet-${Math.random().toString(36).slice(2, 8)}`;
  let panel = $state<HTMLElement | null>(null);
  $effect(() => {
    if (!open || !panel) return;
    const focusable = panel.querySelector<HTMLElement>('input:not([type="checkbox"]), select, textarea, button.primary, button.danger, button');
    focusable?.focus();
  });
  function keydown(event: KeyboardEvent) {
    if (event.key === 'Escape' && !busy) { event.preventDefault(); onclose?.(); }
  }
  function submit(event: SubmitEvent) { event.preventDefault(); if (!busy) onsubmit?.(); }
</script>

{#if open}
  <div class="sheet-backdrop" role="presentation" onkeydown={keydown} onpointerdown={event => { if (event.target === event.currentTarget && !busy) onclose?.(); }}>
    <div class="sheet" class:wide role="dialog" aria-modal="true" aria-labelledby={labelledby ?? id} aria-busy={busy} bind:this={panel}>
    <form class="sheet-form" onsubmit={submit}>
      {#if kind !== 'plain'}
        <span class="warn" aria-hidden="true">
          <img src={mark} alt="" />
          <svg viewBox="0 0 24 24"><path d="M12 2L1.5 21h21z" fill={kind === 'danger' ? '#f16966' : '#f5b400'} stroke="#fff" stroke-width="1.5" stroke-linejoin="round"/><path d="M12 9v5M12 17.5v.5" stroke="#1d1d1f" stroke-width="2" stroke-linecap="round"/></svg>
        </span>
      {/if}
      <div class="sheet-body">
        <h2 id={id}>{title}</h2>
        {@render children?.()}
        {#if actions}<div class="acts">{@render actions()}</div>{/if}
      </div>
    </form>
    </div>
  </div>
{/if}
