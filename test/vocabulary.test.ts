// The sign-in vocabulary is fixed: Passkey, Password, Verification Code, Recovery Code, Two-Step
// Verification, and "sign in" / "sign-in". This reads everything in src/ outside comments (markup, string
// literals and code alike) and fails on any other word for those things.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ui = fileURLToPath(new URL('../src', import.meta.url));

const forbidden: readonly (readonly [string, RegExp])[] = [
  ['2FA', /\b2fa\b/gi],
  ['two-factor', /\btwo[- _]?factor\b/gi],
  ['OTP', /\botp\b/gi],
  ['one-time code', /\bone[- ]time[- ](?:pass)?(?:code|word)\b/gi],
  ['email code', /\be-?mail(?:ed)?[ _-]code\b/gi],
  ['login', /\blog(?:ged|ging)?[- ]?ins?\b/gi],
  ['passcode', /\b(?:passcode|security code|backup code)s?\b/gi],
];
// The fixed terms are written with exactly these capitals wherever they are spelled out.
const fixedTerms = ['Verification Code', 'Recovery Code', 'Two-Step Verification'];

// Identifiers and wire values that contain a forbidden word and are never shown: the whole token
// (letters, digits, `_` and `-`) must be one of these.
const identifiers = new Set([
  'email_code', // sign-in method name on the wire
  'one-time-code', // the HTML autocomplete value for a Verification Code field
  'server_refused_two_factor_setup_required', // backend error code
  'server-login', 'email-code', // ids of the server sign-in form and the Verification Code form
]);

/** Source with comments blanked out, keeping line numbers. */
function withoutComments(source: string): string {
  const blank = (text: string) => text.replace(/[^\n]/g, ' ');
  return source
    .replace(/<!--[\s\S]*?-->/g, blank)
    .replace(/\/\*[\s\S]*?\*\//g, blank)
    .replace(/(^|[\s;{}(),])\/\/[^\n]*/g, (text, lead: string) => lead + blank(text.slice(lead.length)));
}

/** Every forbidden word in `source`, as `line: word in "token"`. */
export function vocabularyProblems(source: string): string[] {
  const code = withoutComments(source);
  const problems: string[] = [];
  const report = (index: number, what: string) => {
    let start = index, end = index;
    while (start > 0 && /[\w-]/.test(code[start - 1]!)) start--;
    while (end < code.length && /[\w-]/.test(code[end]!)) end++;
    const token = code.slice(start, end);
    if (identifiers.has(token)) return;
    problems.push(`${code.slice(0, index).split('\n').length}: ${what} in "${code.slice(Math.max(0, index - 20), index + 30).replace(/\s+/g, ' ').trim()}"`);
  };
  for (const [name, pattern] of forbidden) for (const match of code.matchAll(pattern)) report(match.index, `"${name}"`);
  for (const term of fixedTerms) {
    for (const match of code.matchAll(new RegExp(term.replace(/[ -]/g, '[ -]'), 'gi'))) if (match[0] !== term) report(match.index, `"${match[0]}" should be "${term}"`);
  }
  return problems;
}

function sources(directory: string): string[] {
  return readdirSync(directory).flatMap(entry => {
    const path = join(directory, entry);
    return statSync(path).isDirectory() ? sources(path) : /\.(?:svelte|ts|html)$/.test(path) ? [path] : [];
  });
}

test('the app uses only the fixed sign-in vocabulary', () => {
  const files = sources(ui);
  assert.ok(files.length > 30, `only ${files.length} source files found`);
  const problems = files.flatMap(path => vocabularyProblems(readFileSync(path, 'utf8')).map(problem => `${relative(ui, path)}:${problem}`));
  assert.deepEqual(problems, [], 'use Passkey, Password, Verification Code, Recovery Code, Two-Step Verification and "sign-in"');
  // Every allowed identifier is still in use; remove the ones that are not.
  const all = files.map(path => readFileSync(path, 'utf8')).join('\n');
  for (const name of identifiers) assert.ok(all.includes(name), `${name} is no longer used; remove it from identifiers`);
});

test('the vocabulary check finds forbidden words in markup and strings, and leaves identifiers and comments alone', () => {
  const found = (source: string) => vocabularyProblems(source).map(problem => problem.replace(/ in ".*$/, ''));
  assert.deepEqual(found(`<p>Use this server’s login.</p>
    <button aria-label="Log in">Enter your 2FA code</button>
    const a = 'Turn on two-factor authentication'; const b = "Your OTP"; const c = \`We sent a one-time code\`;
    <small>Check your email code, or a backup code.</small>
    <label>verification code</label> <b>Two-step verification</b> <i>Recovery code</i>`), [
    '2: "2FA"', '3: "two-factor"', '3: "OTP"', '3: "one-time code"', '4: "email code"', '1: "login"', '2: "login"', '4: "passcode"',
    '5: "verification code" should be "Verification Code"', '5: "Recovery code" should be "Recovery Code"', '5: "Two-step verification" should be "Two-Step Verification"',
  ]);
  assert.deepEqual(found(`
    // Old servers call this 2FA; a comment may say login.
    <!-- the OTP field -->
    /* email code */
    type Method = 'totp' | 'email_code' | 'recovery_code';
    <input autocomplete="one-time-code" /> <form id="server-login"></form>
    const messages = { server_refused_two_factor_setup_required: 'Set up Two-Step Verification.', manager_login_details_invalid: 'Enter your Manager password.' };
    let { passwordLogin, onownlogin, loginMessage } = options; const url = 'https://example.test/sign-in';
    <p>Enter the Verification Code, a Recovery Code or your Password, or sign in with a Passkey.</p>`), []);
  // An allowed identifier does not excuse the same words in a sentence.
  assert.deepEqual(found(`'Enter your email_code or the email code'`), ['1: "email code"']);
});
