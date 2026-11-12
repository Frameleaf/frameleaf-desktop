// Accessibility basics of the screens the November QA fixes added: the sign-in steps, the Two-Step
// Verification prompt, the kept-sign-in (reconnecting) screen and the worker status card. These read the
// markup; the behaviour itself (where focus lands, what is announced) was checked in a browser for FD-49.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path: string) => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8');
const markup = (source: string) => source.slice(source.indexOf('</script>') + 9);

test('every field and button on the sign-in steps has an accessible name', () => {
  for (const file of ['ServerSignIn.svelte', 'TwoStepCode.svelte', 'FrameleafAccount.svelte', 'StepUp.svelte']) {
    const html = markup(read(file));
    const fields = [...html.matchAll(/<(?:input|select)\b[^>]*>/g)].map(match => match[0]);
    assert.ok(file === 'StepUp.svelte' || fields.length > 0, `${file}: no fields found`);
    for (const field of fields) {
      const id = /\bid="([^"]+)"/.exec(field)?.[1];
      // Named by aria-label, by a label pointing at it, or by the label it sits inside.
      const named = /\baria-label=/.test(field) || (id !== undefined && html.includes(`for="${id}"`)) || new RegExp(`<label>\\s*${field.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`).test(html);
      assert.ok(named, `${file}: ${field.slice(0, 80)} has no label`);
    }
    // A button's name is its text: none is empty or holds only an icon.
    for (const button of html.matchAll(/<button\b[^>]*>([\s\S]*?)<\/button>/g)) {
      const text = button[1]!.replace(/<Icon [^>]*\/>/g, '').trim();
      assert.ok(text.length > 0 || /aria-label=/.test(button[0]), `${file}: ${button[0].slice(0, 80)} has no name`);
    }
  }
});

test('a refused proof is announced, tied to its field, and the field takes focus again', () => {
  const step = read('TwoStepCode.svelte');
  assert.match(step, /\{#if step\.failure\}<div class="inline-msg error" role="alert"><p id="two-step-error">/);
  assert.match(step, /<input id="two-step-proof"[^>]*aria-invalid=\{step\.failure \? 'true' : undefined\}[^>]*aria-describedby=\{step\.failure \? 'two-step-error' : undefined\}/);
  // Opening the step, another proof and a refusal each put focus on the field once it can be typed in.
  assert.match(step, /\$effect\(\(\) => \{\s*void step\.method; void step\.failure;\s*if \(!busy\) void tick\(\)\.then\(\(\) => field\?\.focus\(\)\);/);

  const server = read('ServerSignIn.svelte');
  assert.match(server, /\{#if failure\}<div class="inline-msg error notice" role="alert">/);
  // A wrong Password clears the field: focus returns to it. A step with nothing to type focuses its heading.
  assert.match(server, /failure = connectionError\(error\);[\s\S]{0,200}passwordField\?\.focus\(\)/);
  assert.match(server, /if \(!step\.method\) void tick\(\)\.then\(\(\) => stepTitle\?\.focus\(\)\);/);
  assert.match(server, /<h3 tabindex="-1" bind:this=\{stepTitle\}>Two-Step Verification<\/h3>/);

  const account = read('FrameleafAccount.svelte');
  assert.match(account, /<div class="inline-msg error notice" role="alert">\s*<p id="fa-failure">/);
  assert.match(account, /void mode; void method; void failure;[\s\S]{0,200}'#fa-code, #fa-second, #fa-em'\) \?\? title\)\?\.focus\(\)/);
  for (const field of ['fa-code', 'fa-second']) assert.match(account, new RegExp(`<input id="${field}"[^>]*aria-describedby=\\{failure \\? 'fa-failure' : undefined\\}`));
});

test('the Two-Step Verification prompt is announced and its sheet returns focus', () => {
  const prompt = read('StepUp.svelte');
  assert.match(prompt, /<div class="inline-msg" role="alert">\s*<p>This needs Two-Step Verification\./);
  // The sheet is the shared modal: it moves focus to its first field and gives it back to the opener.
  assert.match(prompt, /<Sheet title="Two-Step Verification"/);
  const sheet = read('Sheet.svelte');
  assert.match(sheet, /\(input \?\? focusable\[0\] \?\? dialog\)\.focus\(\);/);
  assert.match(sheet, /if \(opener\?\.isConnected\) opener\.focus\(\);/);
});

test('the reconnecting screen takes focus on its title and keeps it on Try now', () => {
  const app = read('App.svelte');
  assert.match(app, /\$effect\(\(\) => \{ if \(keptSignIn && !connection\) void tick\(\)\.then\(\(\) => keptTitle\?\.focus\(\)\); \}\);/);
  assert.match(app, /<h2 tabindex="-1" bind:this=\{keptTitle\}>\{kept\.panel\.title\}<\/h2>\s*<p class="sub" role="status">\{kept\.panel\.detail\}<\/p>/);
  assert.match(app, /if \(keptSignIn === before && button\.isConnected\) button\.focus\(\);/);
  assert.match(app, /<button class="btn primary" disabled=\{busy\} onclick=\{retryKept\}>\{kept\.panel\.retry\}<\/button>/);
});

test('the worker status card is a named group, says its state in words and announces when it needs the person', () => {
  const overview = read('pages/Overview.svelte');
  assert.match(overview, /<div class="group" role="group" aria-label="Computer processing status">/);
  // The coloured dot is decoration; every pill carries its label as text.
  assert.match(overview, /<span class="pill \{worker\.pill\.tone\}"><i aria-hidden="true"><\/i>\{worker\.pill\.label\}<\/span>/);
  for (const pill of overview.matchAll(/<span class="pill [^>]*>([\s\S]*?)<\/span>/g)) assert.match(pill[1]!, /^<i aria-hidden="true"><\/i>\s*\S/, pill[0]);
  assert.match(overview, /<span class="visually-hidden" role="status">\{worker\.attention === 'needs-you' \? `\$\{worker\.headline\}\. \$\{worker\.detail\}` : ''\}<\/span>/);
  assert.match(read('style.css'), /\.visually-hidden \{[^}]*clip-path: inset\(50%\)/);
});
