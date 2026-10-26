// ─────────────────────────────────────────────────────────────────────────
// Finding blocks in the Typst report source.
//
// A finding is a `#finding(...)` call, the shape the team's CPTC report
// already uses (level, number, title, impact, likelihood, cvss, vector,
// scope, rediscovered, description, business-impact, likelihood-description,
// tactics, mitigations, exploitation, remediation, resources). The source
// stays the only copy of a finding's content, so every export path keeps
// working unchanged.
//
// Identity and the team's status tag sit in a marker comment on the line
// directly above the call:
//
//   // @finding id=fb-k3x9q2 status=needs-work
//   #finding(
//     level: "high",
//     ...
//   )
//
// A comment renders nothing and is not an argument, so the marker works with
// any `finding` definition, the CPTC one included. It travels with the block
// through copy and paste, the workspace ZIP, backups and a severity move.
//
// Everything here is pure (string in, string out) so the Findings mode in
// TypstView can rewrite the CURRENT Y.Text through `applySource` (invariant
// 3b) and the rules can be tested without an editor.
// ─────────────────────────────────────────────────────────────────────────

import { parseStringLiteral, toStringLiteral } from './typst-placeholders';
// The argument table. A cycle (typst-finding-schema imports this module back), so
// nothing here may use it at module top level, only inside functions.
import {
  FINDING_SCHEMA,
  argForRole,
  declaresArg,
  emptyValue,
  proseArgs,
  searchArgs,
  type FieldKind,
  type FindingSignature,
} from './typst-finding-schema';

export type { FieldKind } from './typst-finding-schema';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

/**
 * The four severities the Findings mode shows and offers. `info` is still
 * parsed (and the helper still accepts it, for compatibility), but the UI
 * lists such a finding under Low with an "info" note and never offers info
 * as a choice; the source is left as written.
 */
export const UI_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type UiSeverity = (typeof UI_SEVERITIES)[number];

/** Where a block is listed: its severity, with info folded into Low; null when unknown. */
export function displaySeverity(f: { severity: Severity | null }): UiSeverity | null {
  if (f.severity === null) return null;
  return f.severity === 'info' ? 'low' : f.severity;
}

/**
 * A severity pick in the form: one of the four, or null for No severity.
 * No severity is written `level: none` (a missing `level:` also reads as no
 * severity, but CPTC's definition would then draw it as Medium, its
 * default). It needs a `#finding` that accepts `none`
 * (`findingAcceptsNoSeverity`); BTCT's helper does.
 */
export type SeverityPick = Severity | null;

/** The Typst value a pick is written as. */
export function levelLiteral(severity: SeverityPick): string {
  return severity === null ? 'none' : toStringLiteral(severity);
}

export const STATUSES = ['blank', 'needs-work', 'written', 'completed'] as const;
export type FindingStatus = (typeof STATUSES)[number];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export const STATUS_LABEL: Record<FindingStatus, string> = {
  blank: 'Blank',
  'needs-work': 'Needs work',
  written: 'Written',
  completed: 'Completed',
};

export const FINDING_FN = 'finding';

// ── scanner ──────────────────────────────────────────────────────────────
//
// Finding bodies hold bash, python and URLs, so bracket matching has to know
// Typst's modes: strings and comments in code, escapes and raw text in
// markup, and that a bare `(` or `"` in markup is just text.

type Mode = 'code' | 'markup';

/** Index just past a raw block or inline raw that starts at `i` (a backtick). */
function skipRaw(src: string, i: number): number {
  let n = 0;
  while (src[i + n] === '`') n++;
  if (n === 2) return i + 2; // `` is an empty inline raw
  const fence = '`'.repeat(n);
  if (n >= 3) {
    const close = src.indexOf(fence, i + n);
    return close === -1 ? src.length : close + n;
  }
  const close = src.indexOf('`', i + 1);
  return close === -1 ? src.length : close + 1;
}

function skipLineComment(src: string, i: number): number {
  const nl = src.indexOf('\n', i);
  return nl === -1 ? src.length : nl;
}

function skipBlockComment(src: string, i: number): number {
  const close = src.indexOf('*/', i + 2);
  return close === -1 ? src.length : close + 2;
}

function skipString(src: string, i: number): number {
  for (let j = i + 1; j < src.length; j++) {
    if (src[j] === '\\') { j++; continue; }
    if (src[j] === '"') return j + 1;
  }
  return src.length;
}

/** Is `//` at `i` (in markup) the start of a comment rather than a URL's `://`? */
function markupCommentAt(src: string, i: number): boolean {
  return src[i] === '/' && src[i + 1] === '/' && src[i - 1] !== ':';
}

/**
 * Index of the delimiter that closes the one at `openIdx` (`(`, `[` or `{`),
 * or -1 when the source is unbalanced (an edit in progress).
 */
export function matchClose(src: string, openIdx: number): number {
  const stack: { close: string; mode: Mode }[] = [];
  const push = (ch: string) => {
    if (ch === '(') stack.push({ close: ')', mode: 'code' });
    else if (ch === '{') stack.push({ close: '}', mode: 'code' });
    else stack.push({ close: ']', mode: 'markup' });
  };
  const first = src[openIdx];
  if (first !== '(' && first !== '[' && first !== '{') return -1;
  push(first);

  let i = openIdx + 1;
  while (i < src.length) {
    const top = stack[stack.length - 1]!;
    const ch = src[i]!;
    if (top.mode === 'code') {
      if (ch === '"') { i = skipString(src, i); continue; }
      if (ch === '/' && src[i + 1] === '/') { i = skipLineComment(src, i); continue; }
      if (ch === '/' && src[i + 1] === '*') { i = skipBlockComment(src, i); continue; }
      if (ch === '`') { i = skipRaw(src, i); continue; }
      if (ch === '(' || ch === '[' || ch === '{') { push(ch); i++; continue; }
      if (ch === ')' || ch === ']' || ch === '}') {
        if (ch !== top.close) return -1;
        stack.pop();
        if (stack.length === 0) return i;
        i++;
        continue;
      }
      i++;
      continue;
    }
    // markup
    if (ch === '\\') { i += 2; continue; }
    if (ch === '`') { i = skipRaw(src, i); continue; }
    if (markupCommentAt(src, i)) { i = skipLineComment(src, i); continue; }
    if (ch === '/' && src[i + 1] === '*') { i = skipBlockComment(src, i); continue; }
    if (ch === '[') { push(ch); i++; continue; }
    if (ch === ']') {
      stack.pop();
      if (stack.length === 0) return i;
      i++;
      continue;
    }
    if (ch === '#') {
      // An embedded expression: `#name(...)`, `#name.field[...]`, `#(...)`, `#{...}`.
      let j = i + 1;
      while (j < src.length && /[A-Za-z0-9_.-]/.test(src[j]!)) j++;
      const next = src[j];
      if (next === '(' || next === '{') { push(next); i = j + 1; continue; }
      i = j;
      continue;
    }
    i++;
  }
  return -1;
}

/** Ranges of the top-level source that are comments or raw text. */
function inertRanges(src: string): [number, number][] {
  const out: [number, number][] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === '\\') { i += 2; continue; }
    if (ch === '`') { const end = skipRaw(src, i); out.push([i, end]); i = end; continue; }
    if (markupCommentAt(src, i)) { const end = skipLineComment(src, i); out.push([i, end]); i = end; continue; }
    if (ch === '/' && src[i + 1] === '*') { const end = skipBlockComment(src, i); out.push([i, end]); i = end; continue; }
    i++;
  }
  return out;
}

function inRanges(ranges: [number, number][], at: number): boolean {
  for (const [a, b] of ranges) {
    if (at >= a && at < b) return true;
    if (a > at) break;
  }
  return false;
}

// ── arguments ────────────────────────────────────────────────────────────

export interface ArgSpan {
  name: string | null;
  /** Start of the argument text (after the comma, leading whitespace included). */
  start: number;
  /** End of the argument text (before the next comma or the closing paren). */
  end: number;
  /** The value's own span, trimmed. */
  valueStart: number;
  valueEnd: number;
}

/** Split `(...)` at `open` into top-level arguments, with absolute offsets. */
export function splitCallArgs(src: string, open: number, close: number): ArgSpan[] {
  const out: ArgSpan[] = [];
  let start = open + 1;
  let i = open + 1;
  const finish = (end: number) => {
    const text = src.slice(start, end);
    if (text.trim() === '') { start = end + 1; return; }
    const m = /^(\s*)([A-Za-z_][A-Za-z0-9_-]*)\s*:(?!:)\s*/.exec(text);
    let name: string | null = null;
    let vs = start + (/^\s*/.exec(text)?.[0].length ?? 0);
    if (m) { name = m[2]!; vs = start + m[0].length; }
    let ve = end;
    while (ve > vs && /\s/.test(src[ve - 1]!)) ve--;
    // A trailing line comment after the value belongs to the layout, not the value.
    out.push({ name, start, end, valueStart: vs, valueEnd: ve });
    start = end + 1;
  };
  while (i < close) {
    const ch = src[i]!;
    if (ch === '"') { i = skipString(src, i); continue; }
    if (ch === '/' && src[i + 1] === '/') { i = skipLineComment(src, i); continue; }
    if (ch === '/' && src[i + 1] === '*') { i = skipBlockComment(src, i); continue; }
    if (ch === '`') { i = skipRaw(src, i); continue; }
    if (ch === '(' || ch === '[' || ch === '{') {
      const end = matchClose(src, i);
      if (end === -1 || end > close) { i = close; break; }
      i = end + 1;
      continue;
    }
    if (ch === ',') { finish(i); i++; continue; }
    i++;
  }
  finish(close);
  return out;
}

// ── values ───────────────────────────────────────────────────────────────

/** Remove the common indentation of the non-blank lines, and blank edge lines. */
export function dedent(text: string): string {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  while (lines.length > 0 && lines[0]!.trim() === '') lines.shift();
  while (lines.length > 0 && lines[lines.length - 1]!.trim() === '') lines.pop();
  let min = Infinity;
  for (const l of lines) {
    if (l.trim() === '') continue;
    min = Math.min(min, /^[ \t]*/.exec(l)![0].length);
  }
  if (!Number.isFinite(min)) min = 0;
  return lines.map((l) => (l.trim() === '' ? '' : l.slice(min))).join('\n');
}

/** The markup inside a `[...]` value, dedented; null when the value is not one block. */
export function decodeContent(raw: string): string | null {
  const t = raw.trim();
  if (!t.startsWith('[')) return null;
  const close = matchClose(t, 0);
  if (close !== t.length - 1) return null;
  const inner = t.slice(1, -1);
  return inner.includes('\n') ? dedent(inner) : inner.trim();
}

/** `[...]` for `text`, multi-line blocks indented one step deeper than the argument. */
export function encodeContent(text: string, indent = '  '): string {
  const body = text.replace(/\r\n/g, '\n').replace(/\s+$/, '');
  // A trailing backslash would escape the closing bracket: keep a space after it.
  if (!body.includes('\n')) return `[${body.trim()}${body.trim().endsWith('\\') ? ' ' : ''}]`;
  const inner = body
    .split('\n')
    .map((l) => (l.trim() === '' ? '' : `${indent}  ${l}`))
    .join('\n');
  return `[\n${inner}\n${indent}]`;
}

/** Is every `[`/`]` in this markup balanced (so it can sit inside `[...]`)? */
export function contentIsBalanced(text: string): boolean {
  // The newline stands in for the one `encodeContent` writes before `]`, so a
  // trailing `\` (a line break) is not read as escaping the bracket.
  return matchClose(`[${text}\n]`, 0) === text.length + 2;
}

/** Elements of a `(a, b, c)` array value, or null when it is not one. */
function arrayItems(raw: string): string[] | null {
  const t = raw.trim();
  if (!t.startsWith('(')) return null;
  const close = matchClose(t, 0);
  if (close !== t.length - 1) return null;
  return splitCallArgs(t, 0, close)
    .filter((a) => a.name === null)
    .map((a) => t.slice(a.valueStart, a.valueEnd));
}

export function decodeStringArray(raw: string): string[] | null {
  const items = arrayItems(raw);
  if (!items) return null;
  const out: string[] = [];
  for (const it of items) {
    const s = parseStringLiteral(it);
    if (s === null) return null;
    out.push(s);
  }
  return out;
}

/** Array items as text: strings as their value, `[..]` as their markup. */
export function decodeContentArray(raw: string): string[] | null {
  const items = arrayItems(raw);
  if (!items) return null;
  const out: string[] = [];
  for (const it of items) {
    const s = parseStringLiteral(it) ?? decodeContent(it);
    if (s === null) return null;
    out.push(s.replace(/\s*\n\s*/g, ' '));
  }
  return out;
}

export type ScopeRow = [string, string, string];

export function decodeScope(raw: string): ScopeRow[] | null {
  const items = arrayItems(raw);
  if (!items) return null;
  const rows: ScopeRow[] = [];
  for (const it of items) {
    const cells = decodeStringArray(it);
    if (!cells) return null;
    rows.push([cells[0] ?? '', cells[1] ?? '', cells[2] ?? '']);
  }
  return rows;
}

/** A Typst array literal; one element keeps its trailing comma so it stays an array. */
function encodeArray(items: string[], indent: string, multiline: boolean): string {
  if (items.length === 0) return '()';
  if (!multiline) return `(${items.join(', ')}${items.length === 1 ? ',' : ''})`;
  return `(\n${items.map((i) => `${indent}  ${i},`).join('\n')}\n${indent})`;
}

export function encodeStringArray(items: string[], indent = '  '): string {
  const lits = items.map(toStringLiteral);
  return encodeArray(lits, indent, lits.join(', ').length > 60);
}

export function encodeContentArray(items: string[], indent = '  '): string {
  const lits = items.map((t) => `[${t.trim()}]`);
  return encodeArray(lits, indent, lits.join(', ').length > 60);
}

export function encodeScope(rows: ScopeRow[], indent = '  '): string {
  const lits = rows.map((r) => `(${r.map(toStringLiteral).join(', ')})`);
  return encodeArray(lits, indent, rows.length > 1);
}

// ── finding blocks ───────────────────────────────────────────────────────

export interface FindingBlock {
  /** Document order, 0-based. */
  index: number;
  /** Stable id from the marker; null until the block is first tagged or edited. */
  id: string | null;
  /** The tag the team set, or null when none (or an unknown word) is set. */
  tag: FindingStatus | null;
  /** The tag, else the computed status (`auto` true). */
  status: FindingStatus;
  auto: boolean;
  /** Parsed `level:`; null when absent or not a known severity. */
  severity: Severity | null;
  title: string;
  cvss: string | null;
  /** The text the rail's search matches (the schema's `search` arguments); title and cvss when absent. */
  searchText?: string;
  /** 1-based line of the call. */
  line: number;
  /**
   * Start of the block: the start of its `#pagebreak(...)` line when one sits
   * directly above it (`pagebreakStart`), else of the marker line (or of the
   * call's line when there is none).
   */
  start: number;
  /**
   * Start of a line holding only `#pagebreak(...)` that sits directly above the
   * marker (or the call when there is no marker), blank lines aside. The break
   * is part of the block it opens: it moves, copies and deletes with it. Null
   * when there is none. `markerStart`, `markerEnd` and `callStart` do not count it.
   */
  pagebreakStart: number | null;
  /** End of the block: past `)`, or past a `#end-of-block` that follows it. */
  end: number;
  markerStart: number | null;
  markerEnd: number | null;
  callStart: number;
  /** Index of the call's `)`. */
  callClose: number;
  /** Indentation of the call's own line. */
  indent: string;
  args: ArgSpan[];
}

const MARKER_RE = /^[ \t]*\/\/[ \t]*@finding\b(.*)$/;
const PLACEHOLDER_RE = /\{\{[^}]*\}\}/g;

function parseMarker(text: string): { id: string | null; status: string | null } {
  const m = MARKER_RE.exec(text);
  if (!m) return { id: null, status: null };
  const pairs = new Map<string, string>();
  for (const kv of m[1]!.trim().split(/\s+/)) {
    const eq = kv.indexOf('=');
    if (eq > 0) pairs.set(kv.slice(0, eq), kv.slice(eq + 1));
  }
  return { id: pairs.get('id') ?? null, status: pairs.get('status') ?? null };
}

function isStatus(s: string | null): s is FindingStatus {
  return s !== null && (STATUSES as readonly string[]).includes(s);
}

function asSeverity(s: string | null): Severity | null {
  if (!s) return null;
  const v = s.trim().toLowerCase();
  if (v === 'informational') return 'info';
  return (SEVERITIES as readonly string[]).includes(v) ? (v as Severity) : null;
}

/** True when the value holds nothing but whitespace, markup symbols and `{{PLACEHOLDERS}}`. */
export function isPlaceholderOnly(text: string | null): boolean {
  if (text === null) return true;
  return text.replace(PLACEHOLDER_RE, '').replace(/[\s*_+\-#\\[\](),."]/g, '') === '';
}

const PAGEBREAK_LINE_RE = /^[ \t]*#pagebreak\([^()\n]*\)[ \t]*$/;

/**
 * Start of the `#pagebreak(...)` line directly above the line starting at
 * `lineStart` (blank lines skipped, nothing else), or null.
 */
function pagebreakLineAbove(src: string, lineStart: number): number | null {
  let end = lineStart;
  while (end > 0) {
    const start = src.lastIndexOf('\n', end - 2) + 1;
    const line = src.slice(start, end - 1);
    if (/^[ \t]*$/.test(line)) { end = start; continue; }
    return PAGEBREAK_LINE_RE.test(line) ? start : null;
  }
  return null;
}

function lineOf(src: string, at: number): number {
  let n = 1;
  for (let i = 0; i < at; i++) if (src.charCodeAt(i) === 10) n++;
  return n;
}

function argRaw(src: string, args: ArgSpan[], name: string): string | null {
  const a = args.find((x) => x.name === name);
  return a ? src.slice(a.valueStart, a.valueEnd) : null;
}

/**
 * Every `#finding(...)` call in the document, in source order. Skips the
 * `#let finding(` definition, comments and raw text. A call whose parentheses
 * do not close yet (mid-edit) is left out until they do.
 */
export function findFindings(src: string): FindingBlock[] {
  const out: FindingBlock[] = [];
  const inert = inertRanges(src);
  const needle = `#${FINDING_FN}(`;
  let from = 0;
  while (true) {
    const at = src.indexOf(needle, from);
    if (at === -1) break;
    from = at + needle.length;
    // `#finding-counts(` and similar longer names are not this function.
    if (inRanges(inert, at)) continue;
    const open = at + needle.length - 1;
    const close = matchClose(src, open);
    if (close === -1) continue;
    from = close + 1;

    const lineStart = src.lastIndexOf('\n', at - 1) + 1;
    const lead = src.slice(lineStart, at);
    const atLineStart = /^[ \t]*$/.test(lead);
    let markerStart: number | null = null;
    let markerEnd: number | null = null;
    let id: string | null = null;
    let rawStatus: string | null = null;
    if (atLineStart && lineStart > 0) {
      const prevStart = src.lastIndexOf('\n', lineStart - 2) + 1;
      const prevLine = src.slice(prevStart, lineStart - 1);
      if (MARKER_RE.test(prevLine)) {
        markerStart = prevStart;
        markerEnd = lineStart - 1;
        ({ id, status: rawStatus } = parseMarker(prevLine));
      }
    }

    const blockLineStart = markerStart ?? lineStart;
    const pagebreakStart = atLineStart ? pagebreakLineAbove(src, blockLineStart) : null;

    let end = close + 1;
    const after = /^[ \t]*\n?[ \t\n]*#end-of-block\b/.exec(src.slice(end));
    if (after) end += after[0].length;

    const args = splitCallArgs(src, open, close);
    const titleArg = argForRole('title');
    const title = parseStringLiteral(argRaw(src, args, titleArg) ?? '') ?? argRaw(src, args, titleArg) ?? '';
    const levelRaw = argRaw(src, args, argForRole('level'));
    const severity = asSeverity(levelRaw === null ? null : parseStringLiteral(levelRaw));
    const cvssRaw = argRaw(src, args, argForRole('score'));
    const cvss = cvssRaw === null ? null : parseStringLiteral(cvssRaw) ?? cvssRaw;
    const searchText = searchArgs()
      .map((name) => {
        const raw = argRaw(src, args, name);
        return raw === null ? '' : (parseStringLiteral(raw) ?? raw).trim();
      })
      .join(' ');

    const tag = isStatus(rawStatus) ? rawStatus : null;
    let computed: FindingStatus = 'blank';
    for (const name of proseArgs()) {
      const raw = argRaw(src, args, name);
      if (raw === null) continue;
      const content = decodeContent(raw);
      // An expression (CPTC's `template-exploitation`) counts as written:
      // somebody put it there on purpose.
      if (content === null || !isPlaceholderOnly(content)) { computed = 'written'; break; }
    }

    out.push({
      index: out.length,
      id,
      tag,
      status: tag ?? computed,
      auto: tag === null,
      severity,
      title: title.trim(),
      cvss: cvss?.trim() ?? null,
      searchText,
      line: lineOf(src, at),
      start: pagebreakStart ?? markerStart ?? (atLineStart ? lineStart : at),
      pagebreakStart,
      end,
      markerStart,
      markerEnd,
      callStart: at,
      callClose: close,
      indent: atLineStart ? lead : '',
      args,
    });
  }
  return out;
}

/** Re-find a block in a (possibly newer) source: by id, else by document order. */
export function locateFinding(src: string, ref: { id: string | null; index: number }): FindingBlock | null {
  const all = findFindings(src);
  if (ref.id) return all.find((f) => f.id === ref.id) ?? null;
  return all[ref.index] ?? null;
}

// ── fields ───────────────────────────────────────────────────────────────

/** Is the block written with no severity: no `level:` at all, or `level: none`? */
export function isNoSeverity(src: string, f: FindingBlock): boolean {
  const raw = argRaw(src, f.args, argForRole('level'));
  return raw === null || raw.trim() === 'none';
}

export type FieldValue = string | string[] | ScopeRow[] | boolean;

export interface DecodedField {
  /** The value, or null when the argument is absent (the definition's default applies). */
  value: FieldValue | null;
  /** The raw source when the value is an expression the form cannot edit. */
  expression: string | null;
}

/**
 * Form text to markup: a `//` or `/*` the operator typed would open a Typst
 * comment (and could hide the closing `]`, losing the block), so it is written
 * `\/\/` or `\/*`. A URL's `://` and raw text in backticks are left as they are.
 */
export function escapeMarkupComments(text: string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '\\') { out += text.slice(i, i + 2); i += 2; continue; }
    if (ch === '`') { const end = skipRaw(text, i); out += text.slice(i, end); i = end; continue; }
    if (ch === '/' && (text[i + 1] === '*' || (text[i + 1] === '/' && text[i - 1] !== ':'))) {
      out += '\\/';
      i++;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

/** The reverse of `escapeMarkupComments`, for the form. */
export function unescapeMarkupComments(text: string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '`') { const end = skipRaw(text, i); out += text.slice(i, end); i = end; continue; }
    if (ch === '\\' && text[i + 1] === '/' && (text[i + 2] === '*' || text[i + 2] === '/' || text.slice(i + 2, i + 4) === '\\/')) {
      out += '/';
      i += 2;
      continue;
    }
    if (ch === '\\') { out += text.slice(i, i + 2); i += 2; continue; }
    out += ch;
    i++;
  }
  return out;
}

export function decodeField(raw: string | null, kind: FieldKind): DecodedField {
  if (raw === null) return { value: null, expression: null };
  let value: FieldValue | null = null;
  switch (kind) {
    case 'string': value = parseStringLiteral(raw); break;
    case 'content': {
      const markup = decodeContent(raw);
      value = markup !== null ? unescapeMarkupComments(markup) : parseStringLiteral(raw);
      break;
    }
    case 'strings': value = decodeStringArray(raw); break;
    case 'contents': value = decodeContentArray(raw)?.map(unescapeMarkupComments) ?? null; break;
    case 'scope': value = decodeScope(raw); break;
    case 'bool': value = raw.trim() === 'true' ? true : raw.trim() === 'false' ? false : null; break;
  }
  return value === null ? { value: null, expression: raw } : { value, expression: null };
}

export function encodeField(value: FieldValue, kind: FieldKind, indent = '  '): string {
  switch (kind) {
    case 'string': return toStringLiteral(String(value));
    case 'content': return encodeContent(escapeMarkupComments(String(value)), indent);
    case 'strings': return encodeStringArray(value as string[], indent);
    case 'contents': return encodeContentArray((value as string[]).map(escapeMarkupComments), indent);
    case 'scope': return encodeScope(value as ScopeRow[], indent);
    case 'bool': return value ? 'true' : 'false';
  }
}

/**
 * Every schema field of a block, decoded (`lib/typst-finding-schema.ts`), plus any
 * `extra` fields (the parameters a report's own definition adds).
 */
export function readFindingFields(
  src: string,
  f: FindingBlock,
  extra: readonly { name: string; kind: FieldKind }[] = [],
): Record<string, DecodedField> {
  const out: Record<string, DecodedField> = {};
  for (const field of [...FINDING_SCHEMA, ...extra]) out[field.name] = decodeField(argRaw(src, f.args, field.name), field.kind);
  return out;
}

/** The raw source of one argument's value, or null when the block does not pass it. */
export function findingArgRaw(src: string, f: FindingBlock, name: string): string | null {
  return argRaw(src, f.args, name);
}

/** Indentation an argument of this call uses (the first named one's), else the call's plus two. */
export function argIndent(src: string, f: FindingBlock): string {
  for (const a of f.args) {
    const ls = src.lastIndexOf('\n', a.valueStart - 1);
    if (ls >= f.callStart) {
      const m = /^[ \t]*/.exec(src.slice(ls + 1));
      return m ? m[0] : '  ';
    }
  }
  return `${f.indent}  `;
}

/**
 * Add, replace or remove one named argument of a finding call, leaving every
 * other argument, comment and the author's layout alone. `literal` is Typst
 * source for the value; `null` removes the argument.
 */
export function setFindingArg(src: string, f: FindingBlock, name: string, literal: string | null): string {
  const arg = f.args.find((a) => a.name === name);
  if (arg) {
    if (literal !== null) return src.slice(0, arg.valueStart) + literal + src.slice(arg.valueEnd);
    // Remove the argument with its comma. On its own line the whole line goes;
    // the last argument of a one-line call takes the comma before it instead.
    let a = arg.start;
    let b = arg.end;
    const nl = src.slice(a, arg.valueStart).lastIndexOf('\n');
    if (src[b] === ',') {
      b++;
      if (nl === -1) while (src[b] === ' ') b++;
    } else if (nl === -1 && src[a - 1] === ',') {
      a--;
    }
    if (nl !== -1) a += nl;
    return src.slice(0, a) + src.slice(b);
  }
  if (literal === null) return src;

  // Make sure the last argument ends with a comma before appending.
  const last = f.args[f.args.length - 1];
  let s = src;
  let close = f.callClose;
  if (last && src[last.end] !== ',') {
    s = s.slice(0, last.valueEnd) + ',' + s.slice(last.valueEnd);
    close++;
  }
  if (s.slice(f.callStart, close).includes('\n')) {
    const ind = argIndent(src, f);
    const closeLineStart = s.lastIndexOf('\n', close - 1) + 1;
    if (s.slice(closeLineStart, close).trim() === '') {
      return s.slice(0, closeLineStart) + `${ind}${name}: ${literal},\n` + s.slice(closeLineStart);
    }
    return s.slice(0, close) + `\n${ind}${name}: ${literal},\n${f.indent}` + s.slice(close);
  }
  const sep = last ? ' ' : '';
  return s.slice(0, close) + `${sep}${name}: ${literal}` + s.slice(close);
}

/** Set one form field, encoding the value for its kind. */
export function setFindingField(src: string, f: FindingBlock, name: string, kind: FieldKind, value: FieldValue | null): string {
  return setFindingArg(src, f, name, value === null ? null : encodeField(value, kind, argIndent(src, f)));
}

// ── marker ───────────────────────────────────────────────────────────────

/** A short id that is unique enough within one report. */
export function newFindingId(rand: () => number = Math.random): string {
  let s = '';
  for (let i = 0; i < 6; i++) s += Math.floor(rand() * 36).toString(36);
  return `fb-${s}`;
}

export function markerLine(id: string, status: FindingStatus, indent = ''): string {
  return `${indent}// @finding id=${id} status=${status}`;
}

/**
 * Give a block a marker (keeping an existing id and status) and return the
 * new source and the block's id. A block that already has both is unchanged.
 */
export function ensureFindingMarker(
  src: string,
  f: FindingBlock,
  rand?: () => number,
): { source: string; id: string } {
  if (f.markerStart !== null && f.markerEnd !== null) {
    if (f.id) return { source: src, id: f.id };
    const id = newFindingId(rand);
    const line = markerLine(id, f.tag ?? f.status, f.indent);
    return { source: src.slice(0, f.markerStart) + line + src.slice(f.markerEnd), id };
  }
  const id = newFindingId(rand);
  const lineStart = src.lastIndexOf('\n', f.callStart - 1) + 1;
  const line = markerLine(id, f.status, f.indent);
  if (f.indent === src.slice(lineStart, f.callStart)) {
    return { source: src.slice(0, lineStart) + line + '\n' + src.slice(lineStart), id };
  }
  // The call does not start its line: put it on one of its own.
  return { source: src.slice(0, f.callStart) + '\n' + line + '\n' + src.slice(f.callStart), id };
}

/** Tag a block with a status, adding the marker when it has none. */
export function setFindingStatus(src: string, f: FindingBlock, status: FindingStatus, rand?: () => number): { source: string; id: string } {
  if (f.markerStart !== null && f.markerEnd !== null && f.id) {
    const line = markerLine(f.id, status, /^[ \t]*/.exec(src.slice(f.markerStart))![0]);
    return { source: src.slice(0, f.markerStart) + line + src.slice(f.markerEnd), id: f.id };
  }
  const { source, id } = ensureFindingMarker(src, f, rand);
  const again = findFindings(source).find((x) => x.id === id);
  if (!again) return { source, id };
  return setFindingStatus(source, again, status, rand);
}

// ── sections ─────────────────────────────────────────────────────────────

export interface SeveritySection {
  severity: Severity;
  /** Heading level (number of `=`). */
  level: number;
  headingStart: number;
  /** End of the heading line (its newline not included). */
  headingEnd: number;
  /** Start of the next heading at this level or above, else the end of the source. */
  end: number;
}

interface Heading { level: number; start: number; end: number; text: string }

function headings(src: string, skip: [number, number][]): Heading[] {
  const out: Heading[] = [];
  const re = /^(=+)[ \t]+(.*)$/gm;
  for (let m = re.exec(src); m; m = re.exec(src)) {
    if (inRanges(skip, m.index)) continue;
    out.push({ level: m[1]!.length, start: m.index, end: m.index + m[0].length, text: m[2]! });
  }
  return out;
}

function headingSeverity(text: string): Severity | null {
  const label = /<sec-(critical|high|medium|low|info)>/i.exec(text);
  if (label) return label[1]!.toLowerCase() as Severity;
  if (!/finding/i.test(text)) return null;
  const word = /\b(critical|high|medium|low|info(?:rmational)?)\b/i.exec(text);
  return word ? asSeverity(word[1]!) : null;
}

function skipRangesFor(src: string): [number, number][] {
  const ranges = inertRanges(src);
  for (const f of findFindings(src)) ranges.push([f.callStart, f.callClose + 1]);
  // Code blocks can hold lines starting with `=`; so can a `#let` body.
  const letRe = /^#let\s+[A-Za-z_][\w-]*\s*\(/gm;
  for (let m = letRe.exec(src); m; m = letRe.exec(src)) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(src, open);
    if (close !== -1) {
      const body = /^\s*=\s*[{[(]/.exec(src.slice(close + 1));
      const bodyOpen = body ? close + body[0].length : -1;
      const bodyClose = bodyOpen !== -1 ? matchClose(src, bodyOpen) : -1;
      ranges.push([m.index, bodyClose !== -1 ? bodyClose + 1 : close + 1]);
    }
  }
  return ranges.sort((a, b) => a[0] - b[0]);
}

export function findSeveritySections(src: string): SeveritySection[] {
  const hs = headings(src, skipRangesFor(src));
  const out: SeveritySection[] = [];
  hs.forEach((h, i) => {
    const severity = headingSeverity(h.text);
    if (!severity) return;
    let end = src.length;
    for (let j = i + 1; j < hs.length; j++) {
      if (hs[j]!.level <= h.level) { end = hs[j]!.start; break; }
    }
    out.push({ severity, level: h.level, headingStart: h.start, headingEnd: h.end, end });
  });
  return out;
}

/** The heading a new severity section would get, matching its siblings' case. */
export function sectionHeading(severity: Severity, level: number, upper: boolean): string {
  const name = severity === 'info' ? 'Informational Findings' : `${SEVERITY_LABEL[severity]}-Risk Findings`;
  return `${'='.repeat(level)} ${upper ? name.toUpperCase() : name} <sec-${severity}>`;
}

/**
 * Insert a block (marker + call, as text) at the end of its severity's
 * section: after the section's last finding (and its `#end-of-block`), or
 * under the heading when the section has none yet. With no such section a
 * new heading is added in severity order.
 */
export function insertFinding(src: string, block: string, severity: SeverityPick): string {
  const sections = findSeveritySections(src);
  const findings = findFindings(src);
  const whole = block.replace(/^\n+|\n+$/g, '');
  if (severity === null) return insertUnrated(src, whole, sections);
  // A page break that opens the block stays with it, except under a heading
  // that has no rated block yet (it would strand the heading): see below.
  const lead = splitLeadingPagebreak(whole);
  const target = sections.find((s) => s.severity === severity);
  if (target) {
    // After the section's last rated finding: unrated ones parked at the end
    // of the last section stay after the rated ones.
    const inside = findings.filter((f) => f.start >= target.headingEnd && f.start < target.end && f.severity !== null);
    if (inside.length > 0) {
      const at = inside[inside.length - 1]!.end;
      return `${src.slice(0, at)}\n\n${whole}${src.slice(at)}`;
    }
    const at = target.headingEnd;
    const body = `${src.slice(0, at)}\n\n${lead.rest}${src.slice(at)}`;
    if (lead.pagebreak === null || pagebreakLineAbove(src, target.headingStart) !== null) return body;
    // The break goes above the heading, so the heading starts the page.
    return `${src.slice(0, target.headingStart)}${lead.pagebreak}\n\n${body.slice(target.headingStart)}`;
  }

  const order = SEVERITIES.indexOf(severity);
  const level = sections[0]?.level ?? 2;
  const upper = sections.length > 0 && sections.every((s) => {
    const line = src.slice(s.headingStart, s.headingEnd).replace(/<[^>]*>/g, '');
    return line === line.toUpperCase();
  });
  const heading = sectionHeading(severity, level, upper);
  // The new heading carries the block's break above it (unless one is already there).
  const chunkFor = (before: string): string => {
    const brk = lead.pagebreak !== null && pagebreakLineAbove(before + '\n', before.length + 1) === null ? `${lead.pagebreak}\n\n` : '';
    return `${brk}${heading}\n\n${lead.rest}\n\n`;
  };

  // After the nearest more severe section, else before the nearest less severe one.
  const before = sections.filter((s) => SEVERITIES.indexOf(s.severity) < order);
  const after = sections.filter((s) => SEVERITIES.indexOf(s.severity) > order);
  if (before.length > 0) {
    const s = before.reduce((a, b) => (SEVERITIES.indexOf(b.severity) > SEVERITIES.indexOf(a.severity) ? b : a));
    // Insert where the next section starts (or the end of the document).
    const at = s.end;
    const head = src.slice(0, at);
    const gap = head.endsWith('\n\n') ? '' : head.endsWith('\n') ? '\n' : '\n\n';
    return `${head}${gap}${chunkFor(head)}${src.slice(at)}`;
  }
  if (after.length > 0) {
    const s = after.reduce((a, b) => (SEVERITIES.indexOf(b.severity) < SEVERITIES.indexOf(a.severity) ? b : a));
    return `${src.slice(0, s.headingStart)}${chunkFor(src.slice(0, s.headingStart))}${src.slice(s.headingStart)}`;
  }
  const gap = src.length === 0 || src.endsWith('\n\n') ? '' : src.endsWith('\n') ? '\n' : '\n\n';
  return `${src}${gap}${chunkFor(src + gap).replace(/\n+$/, '\n')}`;
}

/** A block's opening `#pagebreak(...)` line (trimmed), and the block without it. */
function splitLeadingPagebreak(block: string): { pagebreak: string | null; rest: string } {
  const m = /^([ \t]*#pagebreak\([^()\n]*\)[ \t]*)\n+/.exec(block);
  return m ? { pagebreak: m[1]!.trim(), rest: block.slice(m[0].length) } : { pagebreak: null, rest: block };
}

/**
 * A block with no severity goes to the end of the findings area: after the
 * last severity section's content (before a `#pagebreak` that closes it) and
 * before whatever follows, so it is still among the findings. With no
 * sections it goes to the end of the document.
 */
function insertUnrated(src: string, text: string, sections: SeveritySection[]): string {
  if (sections.length === 0) {
    const lead = src.length === 0 || src.endsWith('\n\n') ? '' : src.endsWith('\n') ? '\n' : '\n\n';
    return `${src}${lead}${text}\n`;
  }
  const last = sections.reduce((a, b) => (b.headingStart > a.headingStart ? b : a));
  let at = last.end;
  const tail = /\n[ \t]*#pagebreak\([^)]*\)[ \t]*\n*$/.exec(src.slice(last.headingEnd, at));
  if (tail) at = last.headingEnd + tail.index + 1;
  const before = src.slice(0, at);
  const lead = before.endsWith('\n\n') ? '' : before.endsWith('\n') ? '\n' : '\n\n';
  const trail = at >= src.length ? '\n' : '\n\n';
  return `${before}${lead}${text}${trail}${src.slice(at).replace(/^\n+/, '')}`;
}

/** Remove a block (marker, call and its `#end-of-block`), tidying the blank lines it leaves. */
export function removeFinding(src: string, f: FindingBlock): string {
  let a = f.start;
  let b = f.end;
  // Take the line break after the block with it, and collapse the blank run.
  while (b < src.length && (src[b] === ' ' || src[b] === '\t')) b++;
  if (src[b] === '\n') b++;
  while (a > 0 && src[a - 1] === '\n' && src[a - 2] === '\n') a--;
  return src.slice(0, a) + src.slice(b);
}

/** The text of a block as it stands in the source (marker included). */
export function findingText(src: string, f: FindingBlock): string {
  return src.slice(f.start, f.end);
}

/**
 * First half of a severity change: give the block a marker (so it keeps its
 * identity), rewrite its `level`, then cut it out. Returns the source without
 * the block and the block's text, ready for `insertFinding` into the target
 * section. Two halves rather than one rewrite so each is its own minimal
 * delta: a collaborator typing between the old and new spots is never inside
 * a rewritten span. `text` is null when the block cannot be found.
 */
export function liftFinding(
  src: string,
  f: FindingBlock,
  severity: SeverityPick,
  rand?: () => number,
): { source: string; text: string | null; id: string } {
  const marked = ensureFindingMarker(src, f, rand);
  let live = findFindings(marked.source).find((x) => x.id === marked.id);
  if (!live) return { source: src, text: null, id: marked.id };
  const relevelled = setFindingArg(marked.source, live, argForRole('level'), levelLiteral(severity));
  live = findFindings(relevelled).find((x) => x.id === marked.id);
  if (!live) return { source: src, text: null, id: marked.id };
  return { source: removeFinding(relevelled, live), text: findingText(relevelled, live), id: marked.id };
}

/**
 * Does a severity change move the block? Only in a report organised by
 * severity sections: one with none keeps the block where it is and only its
 * `level` changes, so a severity pick never invents headings on its own.
 */
export function movesOnSeverityChange(src: string): boolean {
  return findSeveritySections(src).length > 0;
}

/** Both halves in one string, for tests and single-writer callers. */
export function moveFindingToSeverity(src: string, f: FindingBlock, severity: SeverityPick, rand?: () => number): string {
  if (!movesOnSeverityChange(src)) {
    return setFindingArg(src, f, argForRole('level'), levelLiteral(severity));
  }
  const lifted = liftFinding(src, f, severity, rand);
  return lifted.text === null ? src : insertFinding(lifted.source, lifted.text, severity);
}

// ── whole blocks ─────────────────────────────────────────────────────────

/**
 * Field values for a new block, keyed by the schema's `key`
 * (`lib/typst-finding-schema.ts`). Anything left out is written empty.
 */
export interface FindingFields {
  /** null writes `level: none` (No severity). */
  severity: SeverityPick;
  title?: string;
  cvss?: string;
  vector?: string;
  likelihood?: string;
  impact?: string;
  scope?: ScopeRow[];
  description?: string;
  businessImpact?: string;
  likelihoodDescription?: string;
  tactics?: string[];
  mitigations?: string[];
  exploitation?: string;
  remediation?: string;
  resources?: string[];
}

/**
 * A complete block (marker + call). Every schema argument marked `blank` is
 * written, empty when not given, so neither BTCT's helper nor the team's own
 * `finding` definition fills a new block with default or placeholder text.
 * With a `signature` (the report's own definition, `parseFindingSignature`)
 * an argument the definition does not declare is left out, so a block never
 * passes an argument its template would reject.
 */
export function serializeFinding(
  t: FindingFields,
  opts: { id: string; status: FindingStatus; endOfBlock?: boolean; signature?: FindingSignature | null; pagebreak?: boolean },
): string {
  const ind = '  ';
  const lines: string[] = [];
  // Weak, so a block already at the top of a page leaves no empty page.
  if (opts.pagebreak) lines.push('#pagebreak(weak: true)');
  lines.push(markerLine(opts.id, opts.status), `#${FINDING_FN}(`);
  const values = t as unknown as Record<string, FieldValue | SeverityPick | undefined>;
  for (const spec of FINDING_SCHEMA) {
    if (!spec.blank || !declaresArg(opts.signature ?? null, spec.name)) continue;
    const literal = spec.editor === 'severity'
      ? levelLiteral(t.severity)
      : encodeField((values[spec.key] as FieldValue | undefined) ?? emptyValue(spec.kind), spec.kind, ind);
    lines.push(`${ind}${spec.name}: ${literal},`);
  }
  lines.push(')');
  if (opts.endOfBlock) lines.push('', '#end-of-block');
  return lines.join('\n');
}

/** A new, empty block tagged Blank: what Add and a severity group's + insert. */
export function blankFinding(
  severity: SeverityPick,
  opts: { id: string; endOfBlock?: boolean; signature?: FindingSignature | null; pagebreak?: boolean },
): string {
  return serializeFinding({ severity }, { id: opts.id, status: 'blank', endOfBlock: opts.endOfBlock, signature: opts.signature, pagebreak: opts.pagebreak });
}

// ── helper definition ────────────────────────────────────────────────────

/** Does the report define a `finding` function of its own? */
export function hasFindingHelper(src: string): boolean {
  return /^[ \t]*#let[ \t]+finding[ \t]*\(/m.test(src);
}

/** The report's own `#let finding(...) = ...` definition: its text range, or null. */
export function findingDefinitionRange(src: string): { start: number; end: number } | null {
  const m = /^[ \t]*#let[ \t]+finding[ \t]*\(/m.exec(src);
  if (!m) return null;
  const open = m.index + m[0].length - 1;
  const close = matchClose(src, open);
  if (close === -1) return null;
  const body = /^\s*=\s*/.exec(src.slice(close + 1));
  if (!body) return { start: m.index, end: close + 1 };
  const bodyOpen = close + 1 + body[0].length;
  const bodyClose = matchClose(src, bodyOpen);
  if (bodyClose !== -1) return { start: m.index, end: bodyClose + 1 };
  // A one-expression body: to the end of its line.
  const nl = src.indexOf('\n', bodyOpen);
  return { start: m.index, end: nl === -1 ? src.length : nl };
}

/**
 * Can the report's `#finding` draw `level: none`? True when the report has
 * no definition of its own (BTCT's helper is added, and it can) or its
 * definition tests `level` against `none`. CPTC's indexes its colour table
 * with the level (`levels.at(level)`), which fails on `none`.
 */
export function findingAcceptsNoSeverity(src: string): boolean {
  const def = findingDefinitionRange(src);
  if (!def) return true;
  return /\blevel\s*(?:==|!=)\s*none\b/.test(src.slice(def.start, def.end));
}

/** The line in a definition that looks its colours up by level: `let lvl = levels.at(level)`. */
const LEVEL_LOOKUP_RE = /\blet[ \t]+([A-Za-z_][\w-]*)[ \t]*=[ \t]*([A-Za-z_][\w-]*)\.at\([ \t]*level[ \t]*((?:,[^()\n]*)?)\)/g;

/** The colours a finding with no severity gets: CPTC's `finding-grey`-ish bar, white text, no name. */
export const NO_SEVERITY_LEVEL = '(bar: luma(110), fg: white, name: "")';

/**
 * Teach the report's own `#finding` to draw `level: none`, on request: the
 * one line that looks the colours up by level gets a branch for `none`
 * (`NO_SEVERITY_LEVEL`). Null when the definition has no such line, or more
 * than one, and then the form only explains why No severity is unavailable.
 */
export function allowNoSeverity(src: string): string | null {
  if (findingAcceptsNoSeverity(src)) return src;
  const def = findingDefinitionRange(src);
  if (!def) return null;
  const text = src.slice(def.start, def.end);
  const hits = [...text.matchAll(LEVEL_LOOKUP_RE)];
  if (hits.length !== 1) return null;
  const h = hits[0]!;
  const at = def.start + h.index!;
  const line = `let ${h[1]} = if level == none { ${NO_SEVERITY_LEVEL} } else { ${h[2]}.at(level${h[3]}) }`;
  return src.slice(0, at) + line + src.slice(at + h[0].length);
}

/** Does it define CPTC's `#end-of-block` separator? */
export function hasEndOfBlock(src: string): boolean {
  return /^[ \t]*#let[ \t]+end-of-block\b/m.test(src);
}

/**
 * The finding block BTCT adds to a report that has none: CPTC's argument
 * list (so a block moves between the two reports unchanged) plus level
 * "info", drawn with the bundled fonts only.
 */
export const FINDING_HELPER = `// Finding block (added by the Report tab's Findings mode). Same arguments
// as the CPTC template's #finding, plus level: "info" and level: none.
#let finding-levels = (
  critical: (bar: rgb("#5b3f9e"), name: "Critical"),
  high: (bar: rgb("#b83a32"), name: "High"),
  medium: (bar: rgb("#c9711f"), name: "Medium"),
  low: (bar: rgb("#a88a12"), name: "Low"),
  info: (bar: rgb("#3c6e9f"), name: "Informational"),
)
#let finding(
  level: "medium",
  number: auto,
  title: "",
  impact: "",
  likelihood: "",
  cvss: "",
  vector: "",
  scope: (),
  rediscovered: false,
  description: [],
  business-impact: [],
  likelihood-description: [],
  tactics: (),
  mitigations: (),
  exploitation: [],
  remediation: [],
  resources: (),
) = {
  // level: none is a finding with no severity: a neutral bar and no label.
  let lvl = if level == none { (bar: luma(110), name: none) } else { finding-levels.at(level, default: finding-levels.medium) }
  let mono = "DejaVu Sans Mono"
  let cap(body, fill: luma(70), size: 7pt) = text(fill: fill, weight: "bold", size: size, tracking: 0.08em, upper(body))
  let lbl(body, colspan: 1) = table.cell(fill: luma(244), colspan: colspan, cap(body))
  let sec(body) = table.cell(fill: luma(64), colspan: 4, inset: (x: 8pt, y: 5pt), cap(body, fill: white, size: 7.5pt))
  let wide(body) = table.cell(colspan: 4, inset: (x: 10pt, y: 8pt), body)
  let lines(items) = if items.len() == 0 { text(fill: luma(140))[none] } else { items.map(i => [#i]).join(linebreak()) }
  let vec = if type(vector) == str { vector.replace("/", "/\\u{200b}") } else { vector }
  let pill(body, fill) = box(fill: fill, radius: 2pt, inset: (x: 5pt, y: 3pt), cap(body, fill: white, size: 6.5pt))
  set text(size: 9.5pt)
  set par(justify: false, leading: 0.6em)
  show raw.where(block: true): it => block(
    width: 100%, fill: luma(242), stroke: (left: 2.5pt + lvl.bar), inset: (x: 8pt, y: 6pt),
    text(font: mono, size: 7.5pt, it),
  )
  show heading.where(level: 3): it => block(above: 0pt, below: 0pt, text(size: 12.5pt, weight: "bold", fill: white, {
    if it.numbering != none { counter(heading).display(it.numbering); h(0.7em) }
    it.body
  }))
  let head = if number == auto {
    heading(level: 3, title)
  } else {
    text(size: 12.5pt, weight: "bold", fill: white)[#number #h(0.7em) #title]
  }
  block(breakable: true, above: 1.2em, below: 1.4em, table(
    columns: (1fr, 2.2fr, 1fr, 1fr),
    stroke: 0.5pt + luma(205),
    inset: (x: 7pt, y: 6pt),
    align: left + horizon,
    table.cell(colspan: 4, fill: lvl.bar, inset: (x: 10pt, y: 9pt), grid(
      columns: (1fr, auto), align: (left + horizon, right + horizon), column-gutter: 8pt,
      head,
      {
        if rediscovered { pill([Rediscovered], rgb("#8e2420")); h(4pt) }
        if lvl.name != none { pill(lvl.name, white.transparentize(100%)) }
      },
    )),
    lbl[CVSS score], lbl[CVSS vector], lbl[Likelihood], lbl[Impact],
    text(size: 12pt, weight: "bold", fill: lvl.bar)[#cvss], text(font: mono, size: 7pt, vec), [#likelihood], [#impact],
    sec[Affected scope],
    lbl(colspan: 2)[Host], lbl[Service], lbl[Port],
    ..scope.map(r => (
      table.cell(colspan: 2, text(font: mono, size: 8pt, r.at(0, default: ""))),
      [#r.at(1, default: "")],
      text(font: mono, size: 8pt, r.at(2, default: "")),
    )).flatten(),
    sec[Finding details],
    wide[
      #cap(size: 7.5pt)[Vulnerability description] \\
      #description

      #cap(size: 7.5pt)[Business impact] \\
      #business-impact

      #cap(size: 7.5pt)[Likelihood] \\
      #likelihood-description

      #grid(
        columns: (1fr, 1fr), column-gutter: 18pt, row-gutter: 5pt,
        cap(size: 7.5pt)[MITRE ATT&CK techniques], cap(size: 7.5pt)[Mitigations],
        lines(tactics), lines(mitigations),
      )
    ],
    sec[Exploitation details], wide(exploitation),
    sec[Remediation], wide(remediation),
    sec[Resources], wide(if resources.len() == 0 { text(fill: luma(140))[none] } else { list(..resources) }),
  ))
}`;

/** Offset just past the leading `#set`/`#import`/`#show` rules (0 when there are none). */
function endOfRules(src: string): number {
  const re = /^#(set|import|show)\b/gm;
  let last = 0;
  for (let m = re.exec(src); m; m = re.exec(src)) {
    // Only the leading run: stop at the first rule after other content.
    const between = src.slice(last, m.index).trim();
    if (last > 0 && between !== '' && !/^(\/\/[^\n]*\n?\s*)*$/.test(between)) break;
    let end = src.indexOf('\n', m.index);
    const paren = src.slice(m.index, end === -1 ? src.length : end).search(/[([{]/);
    if (paren !== -1) {
      const close = matchClose(src, m.index + paren);
      if (close !== -1) end = src.indexOf('\n', close);
    }
    last = end === -1 ? src.length : end;
  }
  return last;
}

/** Add `FINDING_HELPER` after the leading rules when the report has no `finding` of its own. */
export function ensureFindingHelper(src: string): { source: string; changed: boolean } {
  if (hasFindingHelper(src)) return { source: src, changed: false };
  const at = endOfRules(src);
  if (at === 0) return { source: `${FINDING_HELPER}\n\n${src}`, changed: true };
  return { source: `${src.slice(0, at)}\n\n${FINDING_HELPER}\n${src.slice(at)}`, changed: true };
}

/**
 * The command panel exploitation steps wrap their code in (`#cmd[```bash
 * ...```]`), shaped like the CPTC template's: a dark bar and a light panel.
 * Added only to a report that has no `cmd` of its own.
 */
export const CMD_HELPER = `// Command panel for exploitation steps (added by the Report tab's Findings
// mode). Same shape as the CPTC template's #cmd.
#let cmd(body) = grid(
  columns: (0.1in, 1fr),
  fill: (x, _) => if x == 0 { luma(89) } else { luma(236) },
  inset: (x: 9pt, y: 7pt),
  align: horizon,
  [], body,
)`;

export function hasCmdHelper(src: string): boolean {
  return /^[ \t]*#let[ \t]+cmd[ \t]*\(/m.test(src);
}

/** Add `CMD_HELPER` after the leading rules when the report has no `cmd` of its own. */
export function ensureCmdHelper(src: string): { source: string; changed: boolean } {
  if (hasCmdHelper(src)) return { source: src, changed: false };
  const at = endOfRules(src);
  if (at === 0) return { source: `${CMD_HELPER}\n\n${src}`, changed: true };
  return { source: `${src.slice(0, at)}\n\n${CMD_HELPER}\n${src.slice(at)}`, changed: true };
}

/**
 * The markup of a top-level `#let name = [...]` (CPTC's
 * `template-exploitation`), dedented; null when there is no such content.
 * Lets the form offer to copy a shared template into one finding.
 */
export function letContent(src: string, name: string): string | null {
  if (!/^[A-Za-z_][\w-]*$/.test(name)) return null;
  const re = new RegExp(`^[ \\t]*#let[ \\t]+${name.replace(/-/g, '\\-')}[ \\t]*=[ \\t]*\\[`, 'm');
  const m = re.exec(src);
  if (!m) return null;
  const open = m.index + m[0].length - 1;
  const close = matchClose(src, open);
  if (close === -1) return null;
  return decodeContent(src.slice(open, close + 1));
}

// ── summary ──────────────────────────────────────────────────────────────

export interface FindingFilter {
  statuses: ReadonlySet<FindingStatus>;
  severities: ReadonlySet<UiSeverity | 'none'>;
  query: string;
}

/** Does a block pass the sidebar's filters? Empty sets mean "any". */
export function matchesFilter(f: FindingBlock, filter: FindingFilter): boolean {
  if (filter.statuses.size > 0 && !filter.statuses.has(f.status)) return false;
  if (filter.severities.size > 0 && !filter.severities.has(displaySeverity(f) ?? 'none')) return false;
  const q = filter.query.trim().toLowerCase();
  if (q && !(f.searchText ?? `${f.title} ${f.cvss ?? ''}`).toLowerCase().includes(q)) return false;
  return true;
}

export function countBy<K extends string>(list: FindingBlock[], key: (f: FindingBlock) => K): Record<K, number> {
  const out = {} as Record<K, number>;
  for (const f of list) {
    const k = key(f);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}
