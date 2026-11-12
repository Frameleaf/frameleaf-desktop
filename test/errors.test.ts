import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connectionError, describeError, errorCode, errorCopy, explainError, splitReference, workerReason } from '../src/errors.ts';
import { backendCodes, codesInSource, type BackendCodes } from './backend-error-codes.ts';

const rust = fileURLToPath(new URL('../src-tauri/src', import.meta.url));
const ui = fileURLToPath(new URL('../src', import.meta.url));
const generic = 'This operation could not finish. Check your connection and try again.';

// Code-shaped strings the backend produces that are names, not errors or statuses. A new entry
// here needs the same care as new copy: the UI shows a generic message for anything listed.
const notErrorCodes = new Set([
  'immich_ml', 'frameleaf_ml', // Python module namespaces of the AI runtime
  'native_runtime', 'native_qualification', // names of the runtime's two launch modes
  'x86_64', // CPU architecture reported at enrollment
  'email_code', 'recovery_code', // sign-in method names
]);

// The components that still hold the only copy for some codes. Every other file's copy is in
// src/errors.ts, so a code shown on any screen gets its words. Do not add a file here: add the copy
// to src/errors.ts instead.
const ownCopy = ['LocalHost.svelte']; // being changed under FD-44; its table moves once that lands

// Copy those components keep for the codes only they show: `=== 'code' ? 'text'` and
// `if (… === 'code' || ….startsWith('prefix_')) return 'text'`.
function componentCopy(): { codes: Set<string>; prefixes: string[] } {
  const codes = new Set<string>();
  const prefixes: string[] = [];
  const shape = '[a-z][a-z0-9]*(?:_[a-z0-9]+)+';
  for (const file of ownCopy) {
    for (const line of readFileSync(join(ui, file), 'utf8').split('\n')) {
      for (const match of line.matchAll(new RegExp(`['"](${shape})['"]\\s*\\?\\s*['"\`]`, 'g'))) codes.add(match[1]!);
      const answer = line.search(/return ['"`]/);
      if (answer < 0) continue;
      const condition = line.slice(0, answer);
      for (const match of condition.matchAll(new RegExp(`=== ['"](${shape})['"]`, 'g'))) codes.add(match[1]!);
      for (const match of condition.matchAll(new RegExp(`startsWith\\(['"](${shape}_)['"]\\)`, 'g'))) prefixes.push(match[1]!);
    }
  }
  return { codes, prefixes };
}

/** Backend codes and run-time code families the UI has no words for. */
function withoutCopy(backend: BackendCodes): string[] {
  const local = componentCopy();
  const missing: string[] = [];
  for (const [code, where] of backend.codes) {
    if (notErrorCodes.has(code) || errorCopy(code) !== null) continue;
    if (local.codes.has(code) || local.prefixes.some(prefix => code.startsWith(prefix))) continue;
    missing.push(`${code} (${where})`);
  }
  // A family is covered only by a rule for its prefix: any suffix must get copy.
  for (const [prefix, where] of backend.families) if (errorCopy(`${prefix}zz9`) === null) missing.push(`${prefix}… (${where})`);
  return missing.sort();
}

test('every error code the backend can return has copy', () => {
  const backend = backendCodes(rust);
  // Guard the scanner itself: if it stopped finding codes this test would pass for the wrong reason.
  assert.ok(backend.codes.size > 500, `only ${backend.codes.size} backend codes found`);
  for (const known of ['server_identity_changed', 'worker_no_eligible_workloads', 'model_download_interrupted', 'memory_low', 'host_manifest_invalid', 'manager_pair_again', 'desktop_pool_route_changed', 'native_restore_review_expired', 'media_copy_cancelled'])
    assert.ok(backend.codes.has(known), `scanner missed ${known}`);
  for (const prefix of ['server_http_', 'cloud_sign_in_', 'worker_resume_', 'workload_', 'source_upload_http_'])
    assert.ok(backend.families.has(prefix), `scanner missed the ${prefix} family`);
  assert.deepEqual(withoutCopy(backend), [], 'add copy to src/errors.ts');
  for (const name of notErrorCodes) assert.ok(backend.codes.has(name), `${name} is no longer produced; remove it from notErrorCodes`);
});

test('a new backend code without copy is reported, and a new one with copy is not', () => {
  const added = codesInSource(`
    fn start() -> Result<(), String> {
        let port = listener.local_addr().map_err(|_| "worker_brand_new_failure")?;
        if port == 0 { return Err("server_identity_changed".into()); }
        Err(format!("quota_http_{}", status))
    }`, 'new.rs');
  assert.deepEqual(withoutCopy(added), ['quota_http_… (new.rs:5)', 'worker_brand_new_failure (new.rs:3)']);
});

test('the scanner reads codes where the backend produces them and nowhere else', () => {
  const found = (source: string) => [...codesInSource(source, 'x.rs').codes.keys()].sort();
  assert.deepEqual(found(`
    const BUSY: &str = "album_is_busy";
    fn a() -> Result<u8, String> {
        let file = open().map_err(|_| "file_open_failed")?;
        let name = path.to_str().ok_or("path_not_text")?;
        let item = list.first().ok_or_else(|| "list_was_empty".to_string())?;
        if bad { return Err("request_was_bad".into()); }
        progress.set("paused", Some("on_battery_power".into()));
        match status { 404 => "thing_not_found", _ => { "thing_failed" } }
    }
    fn b(code: &str) -> String {
        match code {
            "kept_as_is" | "also_kept_as_is" => code,
            "wire_code_in" => "mapped_code_out",
            _ => "fallback_code_out",
        }.into()
    }
    fn c(error: &str) -> bool { matches!(error, "listed_code_one" | "listed_code_two") }
  `), ['album_is_busy', 'also_kept_as_is', 'fallback_code_out', 'file_open_failed', 'kept_as_is', 'list_was_empty', 'listed_code_one', 'listed_code_two', 'mapped_code_out', 'on_battery_power', 'path_not_text', 'request_was_bad', 'thing_failed', 'thing_not_found']);
  // Field names, form parameters, cookies, attributes, comparisons, comments and tests are not codes.
  assert.deepEqual(found(`
    // return Err("commented_out_code".into());
    /* Err("block_commented_code") */
    #[serde(rename = "renamed_field", skip_serializing_if = "is_false_value")]
    fn d() {
        let body = json!({ "installation_id": id, "nested_key": { "inner_key": 1 } });
        let form = [("grant_type", "refresh_token"), ("client_id", CLIENT)];
        url.query_pairs_mut().append_pair("redirect_uri", target);
        let cookie = Cookie::build(("access_token_cookie", token));
        let text = "a sentence with Err(\\"quoted_inner_code\\") inside";
        let raw = r#"{"raw_json_key":"raw_json_value"}"#;
        if code == "compared_code" || code != "other_compared_code" { retry(); }
        if cfg!(target_os = "some_os_name") {}
        let quote = '"'; let value = operation["indexed_key"].as_str();
        match incoming { "wire_only_code" => 1, Some("optional_wire_code") => 2, _ => 3 };
    }
    #[cfg(test)]
    mod tests {
        #[test]
        fn e() { assert_eq!(run(), Err("test_only_code".into())); }
    }
    #[test]
    fn f() { let _ = Err::<(), String>("lone_test_code".into()); }
  `), []);
  const families = [...codesInSource('fn g() { Err(format!("thing_http_{}", s)); let h = format!("{:x}", d); let p = format!("not_a_family_{}_tail", n); }', 'x.rs').families.keys()];
  assert.deepEqual(families, ['thing_http_']);
});

test('an unknown code shows the generic message with the code as its reference', () => {
  assert.deepEqual(describeError('brand_new_backend_code'), { message: generic, reference: 'brand_new_backend_code' });
  assert.equal(connectionError('brand_new_backend_code'), `${generic} (Reference: brand_new_backend_code)`);
  assert.equal(connectionError(new Error('brand_new_backend_code')), `${generic} (Reference: brand_new_backend_code)`);
  assert.equal(explainError('brand_new_backend_code', 'This import could not finish.'), 'This import could not finish. (Reference: brand_new_backend_code)');
  // Anything that is not a code (free text, objects, nothing) is never echoed.
  for (const other of ['Command open_photos not allowed by ACL', '', null, undefined, {}, 42, 'x'.repeat(200)]) {
    assert.equal(errorCode(other), '');
    assert.deepEqual(describeError(other), { message: generic, reference: null });
  }
  assert.deepEqual(describeError('server_identity_changed'), { message: 'Your server’s identity changed. Sign out and sign in again to confirm it.', reference: null });
});

test('a code one screen used to own gets its copy on every screen', () => {
  // Each of these had its words only in one component's table, so any other screen showed the generic message.
  const moved: Record<string, RegExp> = {
    media_copy_space_insufficient: /enough free space for this archive/, // media-copy.ts
    manager_clock_skew: /clock/, // manager-state.ts
    offline_album_storage_limit: /2 GB offline cache/, // OfflinePhotos.svelte
    source_capacity_insufficient: /not enough free space for this original/, // PhotoSources.svelte
    source_drop_existing: /current import/, // PhotoDrop.svelte
    source_album_missing: /album could not be found/, // import-destination.ts
  };
  for (const [code, words] of Object.entries(moved)) {
    assert.match(errorCopy(code)!, words, code);
    // The helpers every screen uses (the app banner, Overview, sign-in) now find it too.
    assert.deepEqual(describeError(code), { message: errorCopy(code), reference: null }, code);
    assert.equal(connectionError(code), errorCopy(code), code);
    assert.equal(explainError(Error(code), 'Some other screen could not finish.'), errorCopy(code), code);
  }
  // The files that were moved keep no copy the coverage test has to read.
  assert.deepEqual(ownCopy, ['LocalHost.svelte']);
});

test('the reference of an unknown failure is shown one way: small secondary text after the message', () => {
  // The line explainError writes splits back into exactly what describeError gave.
  for (const [error, fallback] of [['brand_new_backend_code', undefined], ['x9', 'This import could not finish.'], ['server_identity_changed', undefined], ['free text', 'Could not save (again).']] as const)
    assert.deepEqual(splitReference(explainError(error, fallback)), describeError(error, fallback));
  // Only that exact ending is a reference; a message that merely mentions one stays whole.
  for (const text of ['', 'Saved.', 'See (Reference: abc_def) above.', 'Wrong (Reference: Not A Code)', 'x (Reference: a_b) '])
    assert.deepEqual(splitReference(text), { message: text, reference: null });

  const files: string[] = [];
  const walk = (directory: string) => {
    for (const entry of readdirSync(directory)) {
      const path = join(directory, entry);
      if (statSync(path).isDirectory()) walk(path); else if (path.endsWith('.svelte')) files.push(path);
    }
  };
  walk(ui);
  const renderer = readFileSync(join(ui, 'ErrorText.svelte'), 'utf8');
  assert.match(renderer, /\{parts\.message\}\{#if parts\.reference\}\{' '\}<span class="reference">Reference: \{parts\.reference\}<\/span>\{\/if\}/);
  assert.match(readFileSync(join(ui, 'style.css'), 'utf8'), /\.reference \{ color: var\(--muted\); font-size: 11px;/);
  const shows = /\b(?:explainError|connectionError|describeError|managerError|explainCopy|stepPrompt)\b/;
  let screens = 0;
  for (const path of files) {
    const name = path.slice(ui.length + 1);
    // LocalHost.svelte is being changed under FD-44 and still writes the reference inline.
    if (name === 'ErrorText.svelte' || name === 'LocalHost.svelte') continue;
    const source = readFileSync(path, 'utf8');
    assert.doesNotMatch(source, /Reference:/, `${name} writes a reference itself; render the message with ErrorText`);
    if (!shows.test(source)) continue;
    screens += 1;
    assert.match(source, /<ErrorText text=\{/, `${name} shows a failure without ErrorText`);
  }
  assert.ok(screens >= 14, `only ${screens} screens found that show a failure`);
});

test('no copy shows a raw error code', () => {
  const backend = backendCodes(rust);
  const samples = [...backend.codes.keys(), ...[...backend.families.keys()].flatMap(prefix => [`${prefix}zz9`, `${prefix}401`, `${prefix}404`, `${prefix}429`, `${prefix}500`, `${prefix}503`])];
  for (const code of samples) {
    const copy = errorCopy(code);
    if (copy === null) continue;
    assert.doesNotMatch(copy, /[a-z0-9]_[a-z0-9]/, `${code}: ${copy}`);
    assert.match(copy, /^[A-Z].*[.]$/s, `${code}: ${copy}`);
  }
});

test('codes built at run time get copy for any suffix, and exact copy wins', () => {
  assert.match(errorCopy('server_http_503')!, /did not answer in time/);
  assert.match(errorCopy('server_http_500')!, /ran into a problem/);
  assert.match(errorCopy('server_http_418')!, /did not accept this request/);
  assert.equal(errorCopy('server_http_403'), 'Your server did not permit this sign-in.');
  assert.equal(errorCopy('cloud_sign_in_access_denied'), 'Frameleaf Cloud sign-in was cancelled.');
  assert.equal(errorCopy('cloud_sign_in_server_error'), 'Frameleaf Cloud did not complete the sign-in. Try again.');
  assert.equal(errorCopy('worker_resume_offline'), 'Your server did not answer. Check that it is online, then try Resume again.');
  assert.equal(errorCopy('workload_desktop_pool_route_changed'), errorCopy('desktop_pool_route_changed'));
  assert.equal(errorCopy('resource_memory_low'), errorCopy('memory_low'));
  assert.equal(errorCopy('server_http_'), null);
  assert.equal(errorCopy('constructor'), null);
  assert.equal(errorCopy('__proto__'), null);
});

test('advice names something the person can actually do', () => {
  // Signing out keeps this installation's identity, so it cannot repair a refused worker credential.
  assert.doesNotMatch(errorCopy('server_http_401')!, /sign out/i);
  assert.match(errorCopy('server_http_401')!, /sign in again/i);
  assert.equal(workerReason('server_http_401'), 'removed');
  // The server never re-enrolls a computer it removed, so removing it is not a fix.
  assert.doesNotMatch(errorCopy('worker_resume_enrollment_failed')!, /remove this computer/i);
});
