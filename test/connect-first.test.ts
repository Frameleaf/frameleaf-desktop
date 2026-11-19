// FD-55: Sign in with Frameleaf (OAuth in the browser, through Frameleaf Cloud) is the default action on
// every sign-in entry point. A server's own Password stays reachable as the secondary path, because a
// home server with no Frameleaf account behind it must still be reachable. These read the markup.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { signInMethods } from '../src/ui-state.ts';

const read = (path: string) => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8');
const markup = (source: string) => source.slice(source.indexOf('</script>') + 9);
/** Every `<button>` in the markup: [its opening tag, its text]. */
const buttons = (html: string) => [...html.matchAll(/<button\b([\s\S]*?)<\/button>/g)].map(match => {
  const whole = match[1]!.replace(/<Icon [^>]*\/>/g, '');
  const end = whole.lastIndexOf('>');
  return [whole.slice(0, end), whole.slice(end + 1).trim()] as const;
});
const primary = (html: string) => buttons(html).filter(([tag]) => /class="btn primary"/.test(tag));
const secondaryLabel = 'Sign In with a Server Password Instead';

test('Welcome starts with Sign in with Frameleaf in the browser, and offers a server Password second', () => {
  const welcome = read('pages/Welcome.svelte');
  const start = markup(welcome).split('<div class="start">')[1]!.split('</div>')[0]!;
  // The one primary action starts the OAuth sign-in directly: no in-app form comes first.
  assert.deepEqual(primary(start).map(([, text]) => text), ["{cloudLocked ? 'Restore Saved Frameleaf Sign-In' : 'Sign In with Frameleaf'}"]);
  assert.match(primary(start)[0]![0], /onclick=\{\(\) => cloudLocked \? restoreCloud\(true\) : cloudSignIn\(\)\}/);
  assert.match(welcome, /async function cloudSignIn\([\s\S]{0,400}invoke<CloudAccount>\('cloud_sign_in'\)/);
  // Creating an account and a server's own sign-in follow, neither of them primary.
  const others = buttons(start).filter(([tag]) => !/class="btn primary"/.test(tag)).map(([, text]) => text);
  assert.deepEqual(others, ['Create a Frameleaf Account', secondaryLabel]);
  assert.match(start, new RegExp(`<button class="btn quiet" type="button" onclick=\\{ownSignIn\\}>${secondaryLabel}</button>`));
  // The secondary path asks for the server's address, which may be any local address over plain http.
  assert.match(welcome, /function ownSignIn\(\) \{ step = 'address';/);
  assert.match(welcome, /invoke<SignInOptions>\('server_sign_in_options', \{ server: address\.trim\(\) \}\)/);
  assert.doesNotMatch(markup(welcome), /pattern="https/);
});

test('a server’s sign-in screen leads with Sign in with Frameleaf and keeps its Password one click away', () => {
  const screen = read('ServerSignIn.svelte');
  const html = markup(screen);
  // Signing in to the Frameleaf account happens in the browser and this screen then carries on by itself.
  assert.match(screen, /if \(!cloudAccount && !\(await oncloudsignin\(\)\)\) return;/);
  assert.match(read('pages/Welcome.svelte'), /oncloudsignin=\{async \(\) => !!\(await cloudSignIn\(false, true\)\)\}/);
  // Typed or found, the server's address goes with the request, so a local http address works here too.
  assert.match(screen, /invoke<SignInOutcome>\('connect_cloud_server', \{ instanceId: options\.id, deviceName, server: options\.server \}\)/);
  assert.match(screen, /invoke<SignInOutcome>\('connect_server', \{ server: options\.server, email, password: secret, deviceName \}\)/);
  // The Password form shows at once only where Frameleaf sign-in is not offered; otherwise a button opens it.
  assert.match(screen, /const passwordShown = \$derived\(methods\.password && \(!methods\.frameleaf \|\| ownPassword\)\);/);
  assert.match(html, new RegExp(`\\{#if methods\\.password && !passwordShown\\}\\s*<button class="btn quiet" type="button" aria-expanded="false" disabled=\\{busy\\} onclick=\\{showPassword\\}>${secondaryLabel}</button>`));
  assert.match(html, /\{#if passwordShown\}[\s\S]{0,400}<form id="server-login"/);
  assert.match(html, /\{#if passwordShown\}<button class="btn" class:primary=\{!methods\.frameleaf\} type="submit" form="server-login"/);
  // Sign In with Frameleaf is primary wherever it is offered, and nothing else on the form is.
  const form = html.split('{:else}\n  <div class="form">')[1]!;
  assert.deepEqual(primary(form).map(([, text]) => text), ["{busy ? 'Signing in…' : 'Sign In with Frameleaf'}"]);
  // A linked server offers Frameleaf sign-in; an unlinked home server offers its Password straight away.
  const linked = signInMethods({ frameleafSignIn: true, linked: true, passwordLogin: true, oauth: false, oauthButtonText: '' });
  const home = signInMethods({ frameleafSignIn: true, linked: false, passwordLogin: true, oauth: false, oauthButtonText: '' });
  assert.deepEqual([linked.frameleaf, linked.password], [true, true]);
  assert.deepEqual([home.frameleaf, home.password], [false, true]);
});

test('the Frameleaf account screen signs in through the browser first and by emailed Verification Code second', () => {
  const html = markup(read('FrameleafAccount.svelte'));
  const first = html.split('{:else}').at(-1)!;
  assert.match(first, /\{#if mode !== 'create'\}<button class="btn primary" type="button" disabled=\{busy \|\| !native\} onclick=\{onbrowser\}>Sign In with Frameleaf<\/button>\{\/if\}/);
  assert.match(first, /<button class="btn" class:primary=\{mode === 'create'\} type="submit" form="frameleaf-account"[^>]*>\{busy \? 'Sending…' : mode === 'create' \? 'Create Account' : 'Email Me a Verification Code'\}<\/button>/);
  assert.match(first, /<button class="link" type="button" onclick=\{onownlogin\}>Sign in with a server Password instead<\/button>/);
  assert.match(read('pages/Welcome.svelte'), /onownlogin=\{ownSignIn\}/);
});
