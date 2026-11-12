<script lang="ts">
  // Frameleaf account sign-in and sign-up in the app (mobile onboarding screens 3, 4 and 5): an emailed
  // Verification Code, then the account's second step when it has one. A Passkey is finished in the browser.
  import { tick } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import Sheet from './Sheet.svelte';
  import { connectionError } from './errors';
  import { countryOptions, defaultCountry } from './ui-state';
  import { cleanProof, proofReady, screenAfter, secondStepCopy, type Completed, type SecondStep } from './cloud-sign-in';
  import type { CloudAccount } from './server-types';

  type Consent = { version: string; text: string; content: string };
  type Consents = { tos: Consent; privacy: Consent };
  let { start, native, onsignedin, onbrowser, onownlogin, onback }: {
    start: 'sign-in' | 'create'; native: boolean;
    onsignedin: (account: CloudAccount) => void; onbrowser: () => void; onownlogin: () => void; onback: () => void;
  } = $props();
  // svelte-ignore state_referenced_locally
  let mode = $state<'sign-in' | 'create' | 'code' | 'second' | 'browser'>(start);
  let codeFor = $state<'sign-in' | 'create'>('sign-in');
  let email = $state('');
  let name = $state('');
  let country = $state(defaultCountry(navigator.language));
  let agreed = $state(false);
  // What is typed for the current step. It is handed to the app once and never kept or stored here.
  let proof = $state('');
  let sentTo = $state('');
  let methods = $state<SecondStep[]>([]);
  let method = $state<SecondStep>('totp');
  let consents = $state<Consents | null>(null);
  let reading = $state<{ title: string; content: string } | null>(null);
  let disclosure = $state('');
  let busy = $state(false);
  let failure = $state('');
  let failureCode = $state('');
  const countries = countryOptions(navigator.language);
  const second = $derived(secondStepCopy(method));
  const using = $derived(mode === 'second' ? method : 'email_code');
  const heading = $derived(
    mode === 'create' ? { title: 'Create a Frameleaf account', sub: 'Accounts are made at Frameleaf, never on someone’s server.' }
    : mode === 'code' ? { title: 'Check your email', sub: 'Enter the Verification Code to finish.' }
    : mode === 'second' ? second
    : mode === 'browser' ? { title: 'Finish in your browser', sub: 'This account signs in with a Passkey, or needs a step this app can’t show.' }
    : { title: 'Frameleaf account', sub: 'Use the same sign-in you use on the web.' });

  // Only the latest load may set the terms: a slower, older answer must not replace what the person read and accepted.
  let consentRequest = 0;
  async function loadConsents() {
    if (!native || consents) return;
    const asked = ++consentRequest;
    try {
      const loaded = await invoke<Consents>('cloud_email_consents');
      if (asked === consentRequest) consents = loaded;
    } catch (error) { if (asked === consentRequest) fail(error); }
  }
  $effect(() => { if (mode === 'create') void loadConsents(); });
  function fail(error: unknown) { failureCode = String(error); failure = connectionError(error); }
  // Each step replaces the form, and a field is disabled while its answer is checked, so keyboard focus is
  // dropped: after a step or its error changes, put it on the step's field, or on the heading when the
  // step has nothing to type. The first screen is left alone.
  let title = $state<HTMLHeadingElement>();
  let shown = false;
  $effect(() => {
    void mode; void method; void failure;
    if (busy) return;
    if (!shown) { shown = true; return; }
    void tick().then(() => (document.querySelector<HTMLElement>('#fa-code, #fa-second, #fa-em') ?? title)?.focus());
  });
  function show(next: typeof mode) { mode = next; proof = ''; failure = ''; failureCode = ''; }

  async function send(kind: 'sign-in' | 'create') {
    if (!native || busy) return;
    // A sign-up needs the current terms accepted; without them it must never go out as a sign-in.
    if (kind === 'create' && (!consents || !agreed)) { mode = 'create'; void loadConsents(); return; }
    busy = true; failure = ''; failureCode = '';
    try {
      const registration = kind === 'create' && consents
        ? { country, name, termsVersion: consents.tos.version, privacyVersion: consents.privacy.version } : null;
      const started = await invoke<{ disclosure: string | null; sentTo: string | null }>('cloud_email_start', { email, registration });
      disclosure = started.disclosure ?? ''; sentTo = started.sentTo ?? ''; codeFor = kind; proof = ''; mode = 'code';
    } catch (error) {
      fail(error);
      // The terms changed while this screen was open: show the new ones to accept again.
      // Clearing the consents makes the create-mode effect load the current ones.
      if (String(error) === 'cloud_email_consent_changed') { mode = 'create'; consents = null; agreed = false; }
    } finally { busy = false; }
  }
  /** Gives the current step's proof: signed in, the account's second step, or the browser for a Passkey. */
  async function verify(event: SubmitEvent) {
    event.preventDefault();
    if (!native || busy || !proofReady(using, proof)) return;
    busy = true; failure = ''; failureCode = '';
    const given = proof;
    if (using === 'password') proof = '';
    try {
      const answer = await invoke<Completed>('cloud_email_complete', { method: using, proof: given });
      if (answer.status === 'done') { onsignedin(answer.account); return; }
      const next = screenAfter(answer);
      if (next.mode === 'second') { methods = next.methods; method = next.methods[0]!; }
      show(next.mode);
    } catch (error) {
      fail(error);
      if (String(error) === 'cloud_email_consent_changed') { mode = 'create'; consents = null; agreed = false; }
    } finally { busy = false; }
  }
  function submitEmail(event: SubmitEvent) { event.preventDefault(); void send(mode === 'create' ? 'create' : 'sign-in'); }
</script>

<h2 tabindex="-1" bind:this={title}>{heading.title}</h2>
<p class="sub">{heading.sub}</p>
{#if failure}
  <div class="inline-msg error notice" role="alert">
    <p id="fa-failure">{failure}</p>
    {#if failureCode === 'cloud_email_no_account'}<button class="btn small" type="button" onclick={() => show('create')}>Create Account</button>{/if}
    {#if failureCode === 'cloud_email_expired_code'}<button class="btn small" type="button" disabled={busy} onclick={() => send(codeFor)}>Send a New Verification Code</button>{/if}
    <button class="btn small quiet" type="button" onclick={() => { failure = ''; }}>Dismiss</button>
  </div>
{/if}

{#if mode === 'code'}
  <form class="form" id="email-code" aria-label="Verification Code" onsubmit={verify}>
    <p class="sub">We sent a six-digit Verification Code to <b>{sentTo || email}</b>. It works for a few minutes.</p>
    {#if disclosure}<p class="sub">{disclosure}</p>{/if}
    <div class="form-row"><label for="fa-code">Verification Code</label><input id="fa-code" class="code" aria-describedby={failure ? 'fa-failure' : undefined} inputmode="numeric" pattern="[0-9]{'{6}'}" autocomplete="one-time-code" value={proof} oninput={event => { const field = event.currentTarget; proof = cleanProof('email_code', field.value); field.value = proof; }} required disabled={busy} /></div>
  </form>
  <div class="wfoot">
    <p>Didn’t get it? Check your spam folder, or send a new Verification Code.</p>
    <button class="btn quiet" type="button" disabled={busy} onclick={() => send(codeFor)}>Send a New Verification Code</button>
    <button class="btn quiet" type="button" disabled={busy} onclick={() => show(codeFor)}>Change Email</button>
    <button class="btn primary" type="submit" form="email-code" disabled={busy || !native || !proofReady('email_code', proof)}>{busy ? 'Verifying…' : 'Verify'}</button>
  </div>
{:else if mode === 'second'}
  <form class="form" id="second-step" aria-label={second.title} onsubmit={verify}>
    {#key method}
      <div class="form-row"><label for="fa-second">{second.label}</label>
        {#if method === 'password'}
          <input id="fa-second" type="password" aria-describedby={failure ? 'fa-failure' : undefined} autocomplete="current-password" maxlength="256" bind:value={proof} required disabled={busy} />
        {:else}
          <input id="fa-second" class="code" aria-describedby={failure ? 'fa-failure' : undefined} inputmode={method === 'totp' ? 'numeric' : 'text'} autocomplete={method === 'totp' ? 'one-time-code' : 'off'} autocapitalize="characters" spellcheck="false" value={proof} oninput={event => { const field = event.currentTarget; proof = cleanProof(method, field.value); field.value = proof; }} required disabled={busy} />
        {/if}
      </div>
    {/key}
  </form>
  <div class="wfoot">
    <p>Can’t use this? Choose another way, or finish with a Passkey in your browser.</p>
    {#each methods.filter(other => other !== method) as other (other)}
      <button class="btn quiet" type="button" disabled={busy} onclick={() => { method = other; show('second'); }}>{secondStepCopy(other).choose}</button>
    {/each}
    <button class="btn quiet" type="button" disabled={busy || !native} onclick={onbrowser}>Use a Passkey in My Browser</button>
    <button class="btn quiet" type="button" disabled={busy} onclick={() => show('sign-in')}>Start Over</button>
    <button class="btn primary" type="submit" form="second-step" disabled={busy || !native || !proofReady(method, proof)}>{busy ? 'Verifying…' : 'Verify'}</button>
  </div>
{:else if mode === 'browser'}
  <div class="inline-msg notice" role="status"><p>Your Verification Code was right. Continue in your browser to finish signing in to <b>{email}</b>; Frameleaf comes back here when you’re done.</p></div>
  <div class="wfoot">
    <p>No Passkey to hand? Your browser’s sign-in page also offers account recovery.</p>
    <button class="btn quiet" type="button" disabled={busy} onclick={() => show('sign-in')}>Start Over</button>
    <button class="btn primary" type="button" disabled={busy || !native} onclick={onbrowser}>Continue in My Browser</button>
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
