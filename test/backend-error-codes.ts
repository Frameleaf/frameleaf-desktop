// Reads the error codes the Rust backend can hand to the UI straight from src-tauri/src, so
// test/errors.test.ts fails when a new code has no copy. A string literal counts only when it is
// shaped like a code (lower_snake_case, two or more words) AND sits where the backend produces an
// error or status code; names of JSON fields, form parameters, cookies and the like never do.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

export type BackendCodes = {
  /** Exact codes, each with the first place it is produced. */
  codes: Map<string, string>;
  /** Prefixes of codes built at run time, e.g. `server_http_` from format!("server_http_{}", status). */
  families: Map<string, string>;
};

const codeShape = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;
const familyShape = /^([a-z][a-z0-9]*(?:_[a-z0-9]+)*_)\{[^{}]*\}$/;

// Rules read the code leading up to a literal (`leads…`) or trailing it (`trails…`).
// Leading text that makes it a produced code.
const leadsProduced = [
  /\bErr\(\s*$/,
  /\bmap_err\(\s*(?:move\s+)?\|[^|]*\|\s*$/,
  /\bok_or\(\s*$/,
  /\bok_or_else\(\s*\|\|\s*$/,
  /\|[^|]*\|\s*(?:String::from\(\s*)?$/, // a closure that returns the code
  /=>\s*(?:\{\s*)?$/, // the value of a match arm
  /\bSome\(\s*$/,
  /\bconst\s+[A-Z][A-Z0-9_]*\s*:\s*&(?:'static\s+)?str\s*=\s*$/,
  /\breturn\s+$/,
  /\bjson!\(\s*$/,
  /\bformat!\(\s*$/,
  /\bString::from\(\s*$/,
  /\b(?:unwrap_or|then_some)\(\s*$/,
];
// Trailing text that makes it a produced code: turned into an owned String, or the tail expression
// of a block.
const trailsProduced = [/^\.(?:into|to_string|to_owned)\(\)/, /^\s*\}/];
// A literal that is matched against rather than produced: `"x" =>`, `"x" | "y"`, `Some("x") =>`,
// `(409, "x") =>`, `== "x"`. These are codes from another service unless one of the rules below
// says the match forwards them.
const trailsConsumed = /^\s*\)*\s*(?:=>|\||if\b|==|!=)/;
const leadsConsumed = /(?:==|!=|""\s*\|)\s*(?:Some\(\s*)?$/;
// Alternatives that the arm forwards unchanged (`"a" | "b" => code`), and allow-lists inside
// matches!(…) whose members are passed through to the UI.
const trailsForwarded = /^(?:\s*\|\s*"")*\s*=>\s*(?:code|error|reason|message)\b/;
const leadsAllowList = /\bmatches!\(\s*[a-z_.()]+\s*,\s*(?:""\s*\|\s*)*$/;

type Literal = { value: string; before: string; after: string; line: number };

// Splits Rust source into code with comments removed and every string literal emptied to "", so
// neither a comment nor the inside of another string can be read as code.
function scan(source: string): { code: string; literals: Literal[] } {
  let code = '';
  const found: { value: string; start: number; end: number }[] = [];
  const push = (value: string) => {
    const start = code.length;
    code += '""' + value.replace(/[^\n]/g, '');
    found.push({ value, start, end: code.length });
  };
  const length = source.length;
  let i = 0;
  while (i < length) {
    const c = source[i]!;
    if (c === '/' && source[i + 1] === '/') { while (i < length && source[i] !== '\n') i++; continue; }
    if (c === '/' && source[i + 1] === '*') {
      let depth = 1; i += 2;
      while (i < length && depth) {
        if (source[i] === '/' && source[i + 1] === '*') { depth++; i += 2; }
        else if (source[i] === '*' && source[i + 1] === '/') { depth--; i += 2; }
        else { if (source[i] === '\n') code += '\n'; i++; }
      }
      continue;
    }
    const raw = /^b?r(#*)"/.exec(source.slice(i, i + 20));
    if (raw && !/[A-Za-z0-9_]/.test(source[i - 1] ?? '')) {
      const close = '"' + raw[1];
      const start = i + raw[0].length;
      const end = source.indexOf(close, start);
      const stop = end < 0 ? length : end;
      push(source.slice(start, stop));
      i = stop + close.length;
      continue;
    }
    if (c === '"') {
      let j = i + 1; let value = '';
      while (j < length && source[j] !== '"') {
        if (source[j] === '\\') { value += source.slice(j, j + 2); j += 2; } else value += source[j++];
      }
      push(value);
      i = j + 1;
      continue;
    }
    if (c === "'") {
      // A char literal ('"', '\n', '\u{1f}') rather than a lifetime.
      const char = /^'(?:\\.[^']*|[^'\\])'/.exec(source.slice(i, i + 14));
      if (char) { code += "' '"; i += char[0].length; continue; }
    }
    code += c; i++;
  }
  let line = 1; let at = 0;
  return {
    code,
    literals: found.map(({ value, start, end }) => {
      for (; at < start; at++) if (code[at] === '\n') line++;
      return { value, line, before: code.slice(Math.max(0, start - 2000), start), after: code.slice(end, end + 400) };
    }),
  };
}

// Line ranges of test-only items: #[cfg(test)] modules and #[test] functions.
function testRanges(code: string): [number, number][] {
  const ranges: [number, number][] = [];
  const attribute = /#\[(?:cfg\(\s*(?:test|all\(\s*test\b[^\]]*)\)|test|tokio::test[^\]]*)\]/g;
  let match: RegExpExecArray | null;
  while ((match = attribute.exec(code))) {
    let i = match.index + match[0].length;
    let depth = 0; let opened = false;
    for (; i < code.length; i++) {
      const c = code[i];
      if (c === '{') { depth++; opened = true; }
      else if (c === '}') { depth--; if (opened && depth === 0) break; }
      else if (c === ';' && !opened) break;
    }
    ranges.push([code.slice(0, match.index).split('\n').length, code.slice(0, i).split('\n').length]);
    attribute.lastIndex = i;
  }
  return ranges;
}

export function codesInSource(source: string, file: string, into: BackendCodes = { codes: new Map(), families: new Map() }): BackendCodes {
  const { code, literals } = scan(source);
  const tests = testRanges(code);
  for (const literal of literals) {
    if (tests.some(([from, to]) => literal.line >= from && literal.line <= to)) continue;
    const where = `${file}:${literal.line}`;
    const family = familyShape.exec(literal.value);
    if (family) {
      if (/\bformat!\(\s*$/.test(literal.before) && !into.families.has(family[1]!)) into.families.set(family[1]!, where);
      continue;
    }
    if (!codeShape.test(literal.value)) continue;
    const consumed = trailsConsumed.test(literal.after) || leadsConsumed.test(literal.before);
    const produced = consumed
      ? trailsForwarded.test(literal.after) || leadsAllowList.test(literal.before)
      : leadsProduced.some(rule => rule.test(literal.before)) || trailsProduced.some(rule => rule.test(literal.after))
        || leadsAllowList.test(literal.before);
    if (produced && !into.codes.has(literal.value)) into.codes.set(literal.value, where);
  }
  return into;
}

function rustFiles(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory).sort()) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) files.push(...rustFiles(path));
    // *_tests.rs and *_qualification.rs are test-only modules, included behind #[cfg(test)] elsewhere.
    else if (path.endsWith('.rs') && !/_(?:tests|qualification)\.rs$/.test(path)) files.push(path);
  }
  return files;
}

export function backendCodes(root: string): BackendCodes {
  const result: BackendCodes = { codes: new Map(), families: new Map() };
  for (const file of rustFiles(root)) codesInSource(readFileSync(file, 'utf8'), file.slice(root.length).replace(/^[\\/]/, ''), result);
  return result;
}
