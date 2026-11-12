<script lang="ts">
  // The one field of a Two-Step Verification step: the proof being entered and the other proofs offered.
  import { methodChoice, otherMethods, proofLabel, stepPrompt, type Step, type StepMethod } from './sign-in-steps';

  let { step, proof = $bindable(''), busy = false, onchoose }: {
    step: Step; proof?: string; busy?: boolean; onchoose: (method: StepMethod) => void;
  } = $props();
  const recovery = $derived(step.method === 'recovery_code');
</script>

<p class="sub">{stepPrompt(step)}</p>
{#if step.failure}<div class="inline-msg error" role="alert"><p>{step.failure}</p></div>{/if}
{#if step.method}
  <div class="form-row"><label for="two-step-proof">{proofLabel(step.method)}</label><input id="two-step-proof" type="text" bind:value={proof} required disabled={busy} autocomplete={recovery ? 'off' : 'one-time-code'} inputmode={recovery ? 'text' : 'numeric'} maxlength={recovery ? 32 : 6} spellcheck="false" /></div>
  {#each otherMethods(step) as method (method)}
    <button class="btn quiet" type="button" disabled={busy} onclick={() => { proof = ''; onchoose(method); }}>{methodChoice(method)}</button>
  {/each}
{/if}
