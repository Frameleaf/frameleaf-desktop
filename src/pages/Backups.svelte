<script lang="ts">
  import ManagerPanel from '../ManagerPanel.svelte';
  let { onstate = undefined }: { onstate?: ((paired: boolean) => void) | undefined } = $props();
</script>

<ManagerPanel focus="backups" {onstate} />
