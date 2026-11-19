<script lang="ts">
  // The one way a failure is shown: its message, then the reference of a failure this app has no words for
  // as small secondary text. `text` is a line from explainError (or any plain message); a caller that
  // already holds the reference apart passes it as `reference`.
  import { splitReference } from './errors';
  let { text, reference = null }: { text: string; reference?: string | null } = $props();
  const parts = $derived(reference ? { message: text, reference } : splitReference(text));
</script>

{parts.message}{#if parts.reference}{' '}<span class="reference">Reference: {parts.reference}</span>{/if}
