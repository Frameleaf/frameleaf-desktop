<script lang="ts">
  // Frameleaf account sign-in and sign-up with an emailed code (mobile onboarding screens 3, 4 and 5).
  import { invoke } from '@tauri-apps/api/core';
  import Sheet from './Sheet.svelte';
  import { connectionError } from './errors';
  import { countryOptions, defaultCountry } from './ui-state';
  import type { CloudAccount } from './server-types';

  type Consent = { version: string; text: string; content: string };
  type Consents = { tos: Consent; privacy: Consent };
  let { start, native, onsignedin, onbrowser, onownlogin, onback }: {
    start: 'sign-in' | 'create'; native: boolean;
    onsignedin: (account: CloudAccount) => void; onbrowser: () => void; onownlogin: () => void; onback: () => void;
  } = $props();
  // svelte-ignore state_referenced_locally
  let mode = $state<'sign-in' | 'create' | 'code'>(start);
  let codeFor = $state<'sign-in' | 'create'>('sign-in');
  let email = $state('');
  let name = $state('');
  let country = $state(defaultCountry(navigator.language));
  let agreed = $state(false);
  let code = $state('');
  let consents = $state<Consents | null>(null);
  let reading = $state<{ title: string; content: string } | null>(null);
  let disclosure = $state('');
  let busy = $state(false);
  let failure = $state('');
  let failureCode = $state('');
  const countries = countryOptions(navigator.language);

  async function loadConsents() {
    if (!native || consents) return;
    try { consents = await invoke<Consents>('cloud_email_consents'); }
    catch (error) { fail(error); }
  }
  $effect(() => { if (mode === 'create') void loadConsents(); });
  function fail(error: unknown) { failureCode = String(error); failure = connectionError(error); }

  async function send(kind: 'sign-in' | 'create') {
    if (!native || busy) return;
    busy = true; failure = ''; failureCode = '';
    try {
      const registration = kind === 'create' && consents
        ? { country, name, termsVersion: consents.tos.version, privacyVersion: consents.privacy.version } : null;
      const started = await invoke<{ disclosure: string | null }>('cloud_email_start', { email, registration });
      disclosure = started.disclosure ?? ''; codeFor = kind; code = ''; mode = 'code';
    } catch (error) {
      fail(error);
      // The terms changed while this screen was open: show the new ones to accept again.
      if (String(error) === 'cloud_email_consent_changed') { consents = null; agreed = false; void loadConsents(); }
    } finally { busy = false; }
  }
  async function verify(event: SubmitEvent) {
    event.preventDefault();
    if (!native || busy || code.length !== 6) return;
    busy = true; failure = ''; failureCode = '';
    try { onsignedin(await invoke<CloudAccount>('cloud_email_complete', { code })); }
    catch (error) {
      fail(error);
      if (String(error) === 'cloud_email_consent_changed') { mode = 'create'; consents = null; agreed = false; }
    } finally { busy = false; }
  }
  function submitEmail(event: SubmitEvent) { event.preventDefault(); void send(mode === 'create' ? 'create' : 'sign-in'); }
</script>

<h2>{mode === 'create' ? 'Create a Frameleaf account' : mode === 'code' ? 'Check your email' : 'Frameleaf account'}</h2>
<p class="sub">{mode === 'create' ? 'Accounts are made at Frameleaf, never on someone’s server.' : mode === 'code' ? 'Enter the code to finish.' : 'Use the same sign-in you use on the web.'}</p>
{#if failure}
  <div class="inline-msg error notice" role="alert">
    <p>{failure}</p>
    {#if failureCode === 'cloud_email_no_account'}<button class="btn small" type="button" onclick={() => { mode = 'create'; failure = ''; }}>Create Account</button>{/if}
    {#if failureCode === 'cloud_email_expired_code'}<button class="btn small" type="button" disabled={busy} onclick={() => send(codeFor)}>Send a New Code</button>{/if}
    <button class="btn small quiet" type="button" onclick={() => { failure = ''; }}>Dismiss</button>
  </div>
{/if}

{#if mode === 'code'}
  <form class="form" id="email-code" aria-label="Email code" onsubmit={verify}>
    <p class="sub">We sent a six-digit code to <b>{email}</b>. It works for a few minutes.</p>
    {#if disclosure}<p class="sub">{disclosure}</p>{/if}
    <div class="form-row"><label for="fa-code">Code</label><input id="fa-code" class="code" inputmode="numeric" pattern="[0-9]{'{6}'}" autocomplete="one-time-code" value={code} oninput={event => { const field = event.currentTarget; code = field.value.replace(/\D/g, '').slice(0, 6); field.value = code; }} required disabled={busy} /></div>
  </form>
  <div class="wfoot">
    <p>Didn’t get it? Check your spam folder, or send a new code.</p>
    <button class="btn quiet" type="button" disabled={busy} onclick={() => send(codeFor)}>Send a New Code</button>
    <button class="btn quiet" type="button" disabled={busy} onclick={() => { mode = codeFor; failure = ''; }}>Change Email</button>
    <button class="btn primary" type="submit" form="email-code" disabled={busy || !native || code.length !== 6}>{busy ? 'Verifying…' : 'Verify'}</button>
  </div>
{:else}
  <form class="form" id="frameleaf-account" aria-label={mode === 'create' ? 'Create a Frameleaf account' : 'Frameleaf account'} onsubmit={submitEmail}>
    {#if mode === 'create'}
      <p class="sub">One free account signs you in to your servers from home or away. Your photos stay on your own server.</p>
    {/if}
    <div class="form-row"><label for="fa-em">Email</label><input id="fa-em" type="email" placeholder="you@example.com" bind:value={email} required maxlength="254" disabled={busy} autocomplete="username" /></div>
    {#if mode === 'create'}
      <div class="form-row"><label for="fa-nm">Name <small>(optional)</small></label><input id="fa-nm" type="text" bind:value={name} maxlength="100" disabled={busy} autocomplete="name" /></div>
      <div class="form-row"><label for="fa-co">Country or region</label>
        <select id="fa-co" bind:value={country} disabled={busy}>
          {#each countries as option (option.code)}<option value={option.code}>{option.name}</option>{/each}
        </select>
      </div>
      <div class="form-row check">
        <label><input type="checkbox" aria-label="I agree to the Terms of Service and Privacy Notice" bind:checked={agreed} disabled={busy || !consents} /> I agree to the
          <button class="link" type="button" disabled={!consents} onclick={() => { if (consents) reading = { title: 'Terms of Service', content: consents.tos.content }; }}>Terms of Service</button> and
          <button class="link" type="button" disabled={!consents} onclick={() => { if (consents) reading = { title: 'Privacy Notice', content: consents.privacy.content }; }}>Privacy Notice</button>.</label>
      </div>
      <div class="inline-msg" role="note"><p>Joining someone else’s server? Its owner adds you on the server’s web page. If that server uses Frameleaf accounts, this account works there too.</p></div>
    {/if}
  </form>
  <div class="wfoot">
    {#if mode === 'create'}
      <p>Already have an account? <button class="link" type="button" onclick={() => { mode = 'sign-in'; failure = ''; }}>Sign in</button></p>
    {:else}
      <p>New to Frameleaf? <button class="link" type="button" onclick={() => { mode = 'create'; failure = ''; }}>Create an account</button>. <button class="link" type="button" onclick={onownlogin}>Use my server’s own login instead</button>.</p>
      <button class="btn quiet" type="button" disabled={busy || !native} onclick={onbrowser}>Use a Passkey in My Browser</button>
    {/if}
    <button class="btn quiet" type="button" disabled={busy} onclick={onback}>Back</button>
    <button class="btn primary" type="submit" form="frameleaf-account" disabled={busy || !native || !email || (mode === 'create' && (!agreed || !consents))}>{busy ? 'Sending…' : mode === 'create' ? 'Create Account' : 'Continue'}</button>
  </div>
{/if}

{#if reading}
  <Sheet title={reading.title} onclose={() => { reading = null; }}>
    <div class="legal" tabindex="-1">{reading.content}</div>
    {#snippet actions()}<button class="btn" type="button" onclick={() => { reading = null; }}>Close</button>{/snippet}
  </Sheet>
{/if}
