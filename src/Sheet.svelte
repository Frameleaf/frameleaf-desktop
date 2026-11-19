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
  let panel = $state<HTMLDialogElement | null>(null);
  const tabbable = 'a[href], button, input:not([type="hidden"]), select, textarea, [tabindex]';
  function controls(dialog: HTMLDialogElement) {
    return [...dialog.querySelectorAll<HTMLElement>(tabbable)]
      .filter(item => item.tabIndex >= 0 && !item.matches(':disabled') && item.getClientRects().length > 0);
  }
  $effect(() => {
    const dialog = panel;
    if (!open || !dialog) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    dialog.showModal();
    const focusable = controls(dialog);
    const input = focusable.find(item => item.matches('input:not([type="checkbox"]), select, textarea'));
    (input ?? focusable[0] ?? dialog).focus();
    return () => {
      dialog.close();
      if (opener?.isConnected) opener.focus();
    };
  });
  function keydown(event: KeyboardEvent) {
    if (event.key !== 'Tab' || !panel) return;
    const items = controls(panel);
    const first = items[0], last = items.at(-1);
    const focused = document.activeElement;
    if (!first || !last || !items.includes(focused as HTMLElement) ||
        focused === (event.shiftKey ? first : last)) {
      event.preventDefault();
      (event.shiftKey ? last ?? panel : first ?? panel).focus();
    }
  }
  function dismiss(event: Event) {
    event.preventDefault();
    if (!busy) onclose?.();
  }
  function backdrop(event: PointerEvent) {
    if (!panel || event.target !== panel || busy) return;
    const box = panel.getBoundingClientRect();
    if (event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom) onclose?.();
  }
  function submit(event: SubmitEvent) { event.preventDefault(); if (!busy) onsubmit?.(); }
</script>

{#if open}
  <dialog class="sheet" class:wide aria-labelledby={labelledby ?? id} aria-busy={busy} bind:this={panel} oncancel={dismiss} onkeydown={keydown} onpointerdown={backdrop}>
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
  </dialog>
{/if}
