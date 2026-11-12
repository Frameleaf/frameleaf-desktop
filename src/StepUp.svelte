<script lang="ts">
  // A page's request the server refused until Two-Step Verification: say so, take one proof, then retry.
  import { invoke } from '@tauri-apps/api/core';
  import Sheet from './Sheet.svelte';
  import TwoStepCode from './TwoStepCode.svelte';
  import { beginStep, chooseMethod, proofReady, stepFailed, type StepOffer } from './sign-in-steps';

  let { offer, retry, onclose }: { offer: StepOffer; retry: () => void; onclose: () => void } = $props();
  // svelte-ignore state_referenced_locally
  let step = $state(beginStep(offer));
  let open = $state(false);
  let busy = $state(false);
  let proof = $state('');

  async function verify() {
    if (busy || !step.method || !proofReady(step.method, proof)) return;
    busy = true;
    const secret = proof; proof = '';
    try {
      await invoke('server_step_up', { transaction: step.transaction, method: step.method, proof: secret });
      // Closing removes this prompt, and its props with it: take the retry first or it never runs.
      const again = retry;
      onclose();
      again();
    } catch (error) { step = stepFailed(step, error); }
    finally { busy = false; }
  }
</script>

<div class="inline-msg" role="alert">
  <p>This needs Two-Step Verification.{step.method ? '' : ' Set it up for your login on the server’s web page, or sign out and sign in again with a Passkey.'}</p>
  {#if step.method}<button class="btn small" type="button" onclick={() => { open = true; }}>Verify</button>{/if}
  <button class="btn small quiet" type="button" onclick={onclose}>Dismiss</button>
</div>
{#if open}
  <Sheet title="Two-Step Verification" {busy} onclose={() => { open = false; proof = ''; }} onsubmit={verify}>
    <TwoStepCode {step} bind:proof {busy} onchoose={method => { step = chooseMethod(step, method); }} />
    {#snippet actions()}
      <button class="btn" type="button" disabled={busy} onclick={() => { open = false; proof = ''; }}>Cancel</button>
      <button class="btn primary" type="submit" disabled={busy || !proofReady(step.method, proof)}>{busy ? 'Checking…' : 'Continue'}</button>
    {/snippet}
  </Sheet>
{/if}
