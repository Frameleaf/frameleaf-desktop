<script lang="ts">
  // One server's sign-in (mobile onboarding screens 6 and 8): every method the server offers, on one screen.
  import { onMount, tick } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import Icon from './Icon.svelte';
  import { connectionError, savedSignInNeedsRecovery } from './errors';
  import { signInMethods } from './ui-state';
  import TwoStepCode from './TwoStepCode.svelte';
  import { beginStep, chooseMethod, proofReady, stepFailed, type Step } from './sign-in-steps';
  import type { Connection, CloudAccount, SignInOptions, SignInOutcome } from './server-types';

  let { options, native, computer, cloudAccount, autostart = false, deviceName = $bindable('My computer'), onconnected, onlocked, oncloudsignin, onback }: {
    options: SignInOptions; native: boolean; computer: string; cloudAccount: CloudAccount | null; autostart?: boolean; deviceName?: string;
    onconnected: (connection: Connection) => void; onlocked: () => void;
    oncloudsignin: () => void; onback: () => void;
  } = $props();
  let email = $state('');
  let password = $state('');
  let busy = $state(false);
  let failure = $state('');
  const methods = $derived(signInMethods(options));
  const route = $derived(options.local ? `On this network · ${new URL(options.server).host}` : `Over the internet · ${new URL(options.server).host}`);

  async function withFrameleaf() {
    if (!native || busy) return;
    busy = true; failure = '';
    try {
      // No Frameleaf account yet: sign in to it first, then this screen comes back and finishes.
      if (!cloudAccount) { oncloudsignin(); return; }
      onconnected(await invoke<Connection>('connect_cloud_server', { instanceId: options.id, deviceName, server: options.server }));
    } catch (error) { if (savedSignInNeedsRecovery(error)) onlocked(); failure = connectionError(error); }
    finally { busy = false; }
  }
  onMount(() => { if (autostart && cloudAccount) void withFrameleaf(); });
  async function withProvider() {
    if (!native || busy) return;
    busy = true; failure = '';
    try { onconnected(await invoke<Connection>('server_oauth_sign_in', { server: options.server, deviceName })); }
    catch (error) { if (savedSignInNeedsRecovery(error)) onlocked(); if (String(error) !== 'server_oauth_cancelled') failure = connectionError(error); }
    finally { busy = false; }
  }
  async function withPassword(event: SubmitEvent) {
    event.preventDefault();
    if (!native || busy) return;
    busy = true; failure = '';
    const secret = password; password = '';
    try { settle(await invoke<SignInOutcome>('connect_server', { server: options.server, email, password: secret, deviceName })); }
    catch (error) {
      if (savedSignInNeedsRecovery(error)) onlocked(); failure = connectionError(error);
      // The Password was cleared and its field disabled while signing in: put focus back where it is retyped.
      void tick().then(() => passwordField?.focus());
    }
    finally { busy = false; }
  }
  // The Password was right and the server wants one more proof: the step replaces the form until it is done.
  let step = $state<Step | null>(null);
  let proof = $state('');
  let passwordField = $state<HTMLInputElement>();
  let stepTitle = $state<HTMLHeadingElement>();
  function settle(outcome: SignInOutcome) {
    if (outcome.status === 'done') { step = null; onconnected(outcome.connection); }
    else {
      proof = ''; step = beginStep(outcome);
      // The step's field takes focus by itself; a step with nothing to type gets it on its heading.
      if (!step.method) void tick().then(() => stepTitle?.focus());
    }
  }
  async function withProof(event: SubmitEvent) {
    event.preventDefault();
    const current = step;
    if (!native || busy || !current?.method || !proofReady(current.method, proof)) return;
    busy = true; failure = '';
    const secret = proof; proof = '';
    try { settle(await invoke<SignInOutcome>('connect_server_step', { server: options.server, transaction: current.transaction, method: current.method, proof: secret, deviceName })); }
    catch (error) { if (savedSignInNeedsRecovery(error)) onlocked(); step = stepFailed(current, error); }
    finally { busy = false; }
  }
  function startAgain() { step = null; proof = ''; failure = ''; }
</script>

<div class="srv-head">
  <span class="ic" aria-hidden="true"><Icon name="server" /></span>
  <span class="l"><b>{options.name}</b><small><i class="route" class:local={options.local} aria-hidden="true"></i>{route}</small></span>
  <button class="btn quiet small" type="button" disabled={busy} onclick={onback}>Use a Different Server</button>
</div>
{#if failure}<div class="inline-msg error notice" role="alert"><p>{failure}</p><button class="btn small quiet" type="button" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
{#if options.loginMessage}<p class="sub">{options.loginMessage}</p>{/if}

{#if options.needsSetup}
  <div class="inline-msg notice" role="status"><p>“{options.name}” has no administrator yet. Open it in a browser to finish its setup, then sign in here.</p></div>
{:else if step}
  <form class="form" id="server-step" aria-label="Two-Step Verification" onsubmit={withProof}>
    <h3 tabindex="-1" bind:this={stepTitle}>Two-Step Verification</h3>
    <TwoStepCode {step} bind:proof {busy} onchoose={method => { if (step) step = chooseMethod(step, method); }} />
    {#if !step.method}
      <!-- Nothing offered can be entered here (a Passkey needs WebAuthn): the sign-ins that open a browser still work. -->
      {#if methods.frameleaf || methods.oauth}
        <p class="sub">Sign in another way instead.</p>
        {#if methods.frameleaf}<button class="btn primary" type="button" disabled={busy || !native} onclick={withFrameleaf}><Icon name="cloud" />{busy ? 'Signing in…' : 'Sign In with Frameleaf'}</button>{/if}
        {#if methods.oauth}<button class="btn" type="button" disabled={busy || !native} onclick={withProvider}>{busy ? 'Signing in…' : methods.oauth}</button>{/if}
      {:else}
        <p class="sub">Ask the person who runs this server to link it to Frameleaf, or turn on Two-Step Verification for your account on the server’s web page.</p>
      {/if}
    {/if}
  </form>
  <div class="wfoot">
    <p>Your Verification Code is used only to sign in and is never saved.</p>
    <button class="btn" type="button" disabled={busy} onclick={startAgain}>Start Again</button>
    {#if step.method}<button class="btn primary" type="submit" form="server-step" disabled={busy || !native || !proofReady(step.method, proof)}>{busy ? 'Signing in…' : 'Continue'}</button>{/if}
  </div>
{:else}
  <div class="form">
    {#if methods.frameleaf}
      <p class="sub">This server is linked to Frameleaf, so your Frameleaf account works here.</p>
      <button class="btn primary" type="button" disabled={busy || !native} onclick={withFrameleaf}><Icon name="cloud" />{busy ? 'Signing in…' : 'Sign In with Frameleaf'}</button>
    {/if}
    {#if methods.oauth}
      {#if methods.frameleaf}<div class="or" role="separator">or use this server’s sign-in</div>{/if}
      <!-- The administrator's own label; primary only when it is the server's sole method. -->
      <button class="btn" class:primary={!methods.frameleaf && !methods.password} type="button" disabled={busy || !native} onclick={withProvider}>{busy ? 'Signing in…' : methods.oauth}</button>
      {#if !methods.frameleaf && !methods.password}<p class="sub">A sign-in window opens for {methods.oauth}. It stores nothing after you finish.</p>{/if}
    {/if}
    {#if methods.password}
      {#if methods.frameleaf || methods.oauth}<div class="or" role="separator">{methods.oauth ? 'or with email and Password' : 'or use this server’s sign-in'}</div>{:else}<h3>This server’s sign-in</h3>{/if}
      <form id="server-login" aria-label="This server’s sign-in" onsubmit={withPassword}>
        <div class="form-row"><label for="sl-em">Account</label><span class="two"><input id="sl-em" type="email" placeholder="Email" bind:value={email} required disabled={busy} autocomplete="username" /><input id="sl-pw" type="password" placeholder="Password" aria-label="Password" bind:this={passwordField} bind:value={password} required disabled={busy} autocomplete="current-password" /></span></div>
      </form>
    {/if}
    {#if !options.linked}
      <div class="inline-msg" role="note"><p>This server isn’t linked to Frameleaf, so Sign in with Frameleaf doesn’t work here yet. If you run it, you can link it after you sign in.</p></div>
    {/if}
    {#if !methods.oauth && !methods.password && !methods.frameleaf}
      <div class="inline-msg error" role="alert"><p>This server doesn’t offer a way to sign in from this app. Ask the person who runs it to turn on Password sign-in or link it to Frameleaf.</p></div>
    {/if}
    {#if methods.password || methods.frameleaf || methods.oauth}
      <div class="form-row"><label for="sl-nm">This {computer}’s name</label><input id="sl-nm" type="text" bind:value={deviceName} required maxlength="128" disabled={busy} autocomplete="off" /></div>
    {/if}
  </div>
  <div class="wfoot">
    <p>No account on this server? The person who runs it adds you on the server’s web page; you can’t make one here.{methods.password ? ' Your Password is used only to sign in and is never saved.' : ''}</p>
    {#if methods.password}<button class="btn" class:primary={!methods.frameleaf} type="submit" form="server-login" disabled={busy || !native || !email || !password}>{busy ? 'Signing in…' : 'Sign In'}</button>{/if}
  </div>
{/if}
