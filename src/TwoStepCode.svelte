<script lang="ts">
  // The one field of a Two-Step Verification step: the proof being entered and the other proofs offered.
  import { tick } from 'svelte';
  import { methodChoice, otherMethods, proofLabel, stepPrompt, type Step, type StepMethod } from './sign-in-steps';

  let { step, proof = $bindable(''), busy = false, onchoose }: {
    step: Step; proof?: string; busy?: boolean; onchoose: (method: StepMethod) => void;
  } = $props();
  const recovery = $derived(step.method === 'recovery_code');
  // Opening the step, choosing another proof and a refused proof each remove or disable whatever had
  // keyboard focus: put it on the field, where the next thing is typed.
  let field = $state<HTMLInputElement>();
  $effect(() => {
    void step.method; void step.failure;
    if (!busy) void tick().then(() => field?.focus());
  });
</script>

<p class="sub">{stepPrompt(step)}</p>
{#if step.failure}<div class="inline-msg error" role="alert"><p id="two-step-error">{step.failure}</p></div>{/if}
{#if step.method}
  <div class="form-row"><label for="two-step-proof">{proofLabel(step.method)}</label><input id="two-step-proof" type="text" bind:this={field} bind:value={proof} aria-invalid={step.failure ? 'true' : undefined} aria-describedby={step.failure ? 'two-step-error' : undefined} required disabled={busy} autocomplete={recovery ? 'off' : 'one-time-code'} inputmode={recovery ? 'text' : 'numeric'} maxlength={recovery ? 32 : 6} spellcheck="false" /></div>
  {#each otherMethods(step) as method (method)}
    <button class="btn quiet" type="button" disabled={busy} onclick={() => { proof = ''; onchoose(method); }}>{methodChoice(method)}</button>
  {/each}
{/if}
