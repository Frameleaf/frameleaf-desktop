<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { processingPlaces, queueNames, queueProgress, queueState, type LibraryAiProcessing } from '../ai-processing';
  import { workloadName } from '../ui-state';
  import StepUp from '../StepUp.svelte';
  import { noStepUp, stepUpAfterFailure, stepUpDismissed, type StepUpState } from '../sign-in-steps';
  let { native, server, accountId, admin, connected }: {
    native: boolean; server: string; accountId: string | undefined; admin: boolean; connected: boolean;
  } = $props();

  let library = $state<LibraryAiProcessing | null>(null);
  let checking = $state(false);
  // The server can refuse the queues until Two-Step Verification: say so with Verify, then read them again.
  let stepUp = $state<StepUpState>(noStepUp);
  // The same prompt outside the effect below, which must not rerun each time the prompt changes.
  let prompt = noStepUp;
  function setStepUp(next: StepUpState) { prompt = next; stepUp = next; }
  $effect(() => {
    if (!native || !server || !accountId || !admin || !connected) return;
    let alive = true;
    let reading = false;
    library = null;
    checking = true;
    setStepUp(noStepUp);
    async function refresh() {
      // While the prompt is open nothing is asked again: the server's answer would start a new verification.
      if (reading || document.hidden || prompt.request) return;
      reading = true;
      let result: LibraryAiProcessing | null = null;
      let failed: unknown;
      try { result = await invoke<LibraryAiProcessing>('server_ai_processing'); }
      catch (error) { failed = error; }
      reading = false;
      if (alive) {
        library = result;
        checking = false;
        setStepUp(result ? noStepUp : stepUpAfterFailure(prompt, failed, () => { setStepUp(noStepUp); void refresh(); }));
      }
    }
    void refresh();
    const timer = setInterval(refresh, 20_000);
    document.addEventListener('visibilitychange', refresh);
    return () => {
      alive = false;
      clearInterval(timer);
      document.removeEventListener('visibilitychange', refresh);
    };
  });
</script>

<section aria-labelledby="ai-library-title">
  <div class="group-head"><h2 id="ai-library-title" class="group-title">Library AI queues</h2></div>
  {#if stepUp.request}{#key stepUp.request}<StepUp offer={stepUp.request.offer} retry={stepUp.request.retry} onclose={() => { setStepUp(stepUpDismissed); }} />{/key}{/if}
  <div class="group">
    {#if !connected}
      <div class="row"><span class="l"><b>Queue status unknown</b><small>Connect to the Library to see live progress.</small></span></div>
    {:else if !admin}
      <div class="row"><span class="l"><b>Queue status unknown</b><small>Library administrators can see server-wide queue progress.</small></span></div>
    {:else if checking}
      <div class="row"><span class="l" role="status">Checking Library queues…</span></div>
    {:else if !library?.queues}
      <div class="row"><span class="l">Queue status unknown</span></div>
    {:else if library.queues.length === 0}
      <div class="row"><span class="l">No active AI queues reported.</span></div>
    {:else}
      {#each library.queues as queue (queue.name)}
        {@const progress = queueProgress(queue)}
        <div class="row" class:top={progress?.percent != null}>
          <span class="l">
            <b>{queueNames[queue.name] ?? 'AI queue'}</b>
            <small>{queueState(queue)}{progress ? ` · ${progress.counts}` : ''}</small>
            {#if progress?.percent != null}
              <span class="progress" role="progressbar" aria-valuenow={progress.percent} aria-valuemin="0" aria-valuemax="100" aria-label={queueNames[queue.name]} aria-valuetext={progress.finished}><span style="width:{progress.percent}%"></span></span>
            {/if}
          </span>
          <span class="muted">{progress?.finished ?? 'Progress unknown'}</span>
        </div>
      {/each}
      <div class="row"><span class="l"><b>Execution location</b><small>Unknown for Library queues.</small></span></div>
    {/if}
  </div>
  {#if connected && admin}
    <div class="group-head order"><h2 class="group-title">Library processing order</h2></div>
    <div class="group">
      <div class="row"><span class="l"><b>Configured order</b><small>{library?.processingOrder ? processingPlaces(library.processingOrder.order) : 'Unknown'}</small></span></div>
      {#each library?.processingOrder?.workloads ?? [] as workload (workload.workload)}
        <div class="row"><span class="l"><b>{workloadName(workload.workload)}</b><small>{processingPlaces(workload.sources)}</small></span></div>
      {/each}
    </div>
  {/if}
</section>

<style>
  .order { margin-top: 16px; }
</style>
