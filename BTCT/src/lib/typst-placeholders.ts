// ─────────────────────────────────────────────────────────────────────────
// Screenshot slots in a Typst document.
//
// Images are not dropped at an arbitrary cursor position: they go into a
// declared figure slot, so a report keeps its captions, numbering and layout
// discipline no matter who is filling it in. A slot is a call to the
// `image-placeholder` helper:
//
//     #image-placeholder("Authentication bypass on /admin")
//
// which renders a grey "insert screenshot here" box until an image is
// assigned, at which point the same call renders the real figure:
//
//     #image-placeholder("Authentication bypass on /admin", path: "/assets/x.png")
//
// Keeping the slot as one call (rather than swapping it for a raw `#figure`)
// means placing is reversible, the caption lives in exactly one place, and an
// unfilled slot is visually obvious in the rendered PDF.
//
// This module is deliberately pure string→string: no DOM, no Yjs. The editing
// surface applies the returned source through the collaborative Y.Text.
// ─────────────────────────────────────────────────────────────────────────

import { formatLength, formatRatio, parseLength, parseRatio } from './typst-geometry';

/** The helper function name that marks a screenshot slot. */
export const PLACEHOLDER_FN = 'image-placeholder';

/**
 * Canonical definition of the slot helper. Renders a placeholder block when
 * `path` is none and the real image otherwise, so one call covers both
 * states. `width` lets one figure be shrunk (with its height, so it keeps its
 * shape) without changing the rest.
 */
export const PLACEHOLDER_HELPER = `#let ${PLACEHOLDER_FN}(caption, path: none, height: 2.2in, width: 90%) = figure(
  block(
    width: width,
    height: height,
    fill: luma(245),
    stroke: 1pt + luma(180),
    radius: 4pt,
    clip: true,
    inset: 0pt,
    align(center + horizon,
      if path == none {
        text(fill: luma(120), style: "italic", size: 11pt)[
          \\[ {{TODO: Insert screenshot here}} \\]
        ]
      } else {
        image(path, width: 100%, height: 100%, fit: "cover")
      },
    ),
  ),
  caption: caption,
)`;

/**
 * Helper bodies this app has generated in the past.
 *
 * `ensureHelper` upgrades a definition only when it byte-matches (modulo
 * whitespace) one we wrote ourselves. A definition the author has since
 * customized (different colours, a different placeholder message) is left
 * alone even if it's an older shape, because silently reverting someone's
 * styling is worse than running on an old helper.
 */
const SUPERSEDED_HELPERS: readonly string[] = [
  // v4: no `width` argument, so a figure could not be shrunk on its own.
  `#let ${PLACEHOLDER_FN}(caption, path: none, height: 2.2in) = figure(
  block(
    width: 90%,
    height: height,
    fill: luma(245),
    stroke: 1pt + luma(180),
    radius: 4pt,
    clip: true,
    inset: 0pt,
    align(center + horizon,
      if path == none {
        text(fill: luma(120), style: "italic", size: 11pt)[
          \\[ {{TODO: Insert screenshot here}} \\]
        ]
      } else {
        image(path, width: 100%, height: 100%, fit: "cover")
      },
    ),
  ),
  caption: caption,
)`,
  // v3: `fit: "contain"`, which letterboxed the box whenever the image's
  // aspect ratio didn't match it exactly, leaving blank strips against the
  // rounded corners. `cover` + `clip` always fills.
  `#let ${PLACEHOLDER_FN}(caption, path: none, height: 2.2in) = figure(
  block(
    width: 90%,
    height: height,
    fill: luma(245),
    stroke: 1pt + luma(180),
    radius: 4pt,
    clip: true,
    align(center + horizon,
      if path == none {
        text(fill: luma(120), style: "italic", size: 11pt)[
          \\[ {{TODO: Insert screenshot here}} \\]
        ]
      } else {
        image(path, width: 100%, height: 100%, fit: "contain")
      },
    ),
  ),
  caption: caption,
)`,
  // v2: white fill behind the image and a 4pt inset, from before the crop
  // pipeline started baking the box's own padding into the image bytes.
  `#let ${PLACEHOLDER_FN}(caption, path: none, height: 2.2in) = figure(
  block(
    width: 90%,
    height: height,
    fill: if path == none { luma(245) } else { white },
    stroke: 1pt + luma(180),
    radius: 4pt,
    clip: true,
    inset: if path == none { 0pt } else { 4pt },
    align(center + horizon,
      if path == none {
        text(fill: luma(120), style: "italic", size: 11pt)[
          \\[ {{TODO: Insert screenshot here}} \\]
        ]
      } else {
        image(path, width: 100%, height: 100%, fit: "contain")
      },
    ),
  ),
  caption: caption,
)`,
  // v1: the image *replaced* the bordered block rather than sitting inside it.
  `#let ${PLACEHOLDER_FN}(caption, path: none, height: 2.2in) = figure(
  if path == none {
    block(
      width: 90%,
      height: height,
      fill: luma(245),
      stroke: 1pt + luma(180),
      radius: 4pt,
      align(center + horizon,
        text(fill: luma(120), style: "italic", size: 11pt)[
          \\[ {{TODO: Insert screenshot here}} \\]
        ],
      ),
    )
  } else {
    image(path, width: 90%)
  },
  caption: caption,
)`,
];

/** Collapse whitespace so a reformatted-but-identical helper still matches. */
function canonicalize(source: string): string {
  return source.replace(/\s+/g, ' ').trim();
}

export interface ScreenshotSlot {
  /** 0-based position among the slots in the document. */
  index: number;
  /** Offset of the leading `#`. */
  start: number;
  /** Offset just past the closing `)`. */
  end: number;
  /** Caption, when it's a plain string literal. Null for a computed caption. */
  caption: string | null;
  /** Currently-assigned asset path, or null when the slot is empty. */
  path: string | null;
  /**
   * The slot's `height:` in points, or null when it uses the helper's
   * default. Drives the crop viewport's aspect ratio.
   */
  heightPt: number | null;
  /**
   * The slot's `width:` as a fraction of the text width (`60%` is 0.6), or
   * null when it uses the helper's default.
   */
  widthFraction: number | null;
  /** 1-based line number of the call, for display in the picker. */
  line: number;
}

// ── low-level scanning ───────────────────────────────────────────────────

/**
 * Walk from an opening delimiter to its match, respecting nesting and Typst
 * string literals. Returns the index of the closing delimiter, or -1 if the
 * source is unbalanced (an in-progress edit, so callers must tolerate it).
 *
 * Typst content blocks (`[...]`) can contain unbalanced quotes as ordinary
 * text, so quote tracking is suspended inside them.
 */
function matchDelimiter(src: string, openIdx: number): number {
  const open = src[openIdx];
  if (open !== '(' && open !== '[' && open !== '{') return -1;

  let paren = 0;
  let bracket = 0;
  let brace = 0;
  let inString = false;

  for (let i = openIdx; i < src.length; i++) {
    const ch = src[i];

    if (inString) {
      if (ch === '\\') { i++; continue; }
      if (ch === '"') inString = false;
      continue;
    }

    // Inside a content block, `"` is literal text rather than a string start.
    if (ch === '"' && bracket === 0) { inString = true; continue; }

    if (ch === '(') paren++;
    else if (ch === ')') paren--;
    else if (ch === '[') bracket++;
    else if (ch === ']') bracket--;
    else if (ch === '{') brace++;
    else if (ch === '}') brace--;

    if (paren === 0 && bracket === 0 && brace === 0) return i;
    if (paren < 0 || bracket < 0 || brace < 0) return -1;
  }
  return -1;
}

/** Split an argument list on top-level commas. */
function splitArgs(argsText: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let inString = false;
  let start = 0;

  for (let i = 0; i < argsText.length; i++) {
    const ch = argsText[i];
    if (inString) {
      if (ch === '\\') { i++; continue; }
      if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"' && depth === 0) { inString = true; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (ch === ',' && depth === 0) {
      out.push(argsText.slice(start, i));
      start = i + 1;
    }
  }
  const tail = argsText.slice(start);
  if (tail.trim() !== '' || out.length > 0) out.push(tail);
  return out;
}

/** Name of a named argument (`foo: …`), or null when positional. */
function argName(arg: string): string | null {
  const m = /^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*:/.exec(arg);
  return m ? m[1]! : null;
}

/**
 * Parse a Typst string literal, honouring backslash escapes. Null if not one.
 *
 * A start-and-end quote check on its own is not enough: `"Host " + host + "
 * admin login"` also starts and ends with a quote, and reading it as one
 * literal hands back `Host " + host + " admin login`, which is neither the
 * source nor what Typst renders. So an UNESCAPED quote inside the body means
 * this is an expression, not a literal, and the caller treats the caption as
 * computed (the place dialog says so, and the DOCX export warns).
 */
export function parseStringLiteral(text: string): string | null {
  const t = text.trim();
  if (t.length < 2 || !t.startsWith('"') || !t.endsWith('"')) return null;
  const body = t.slice(1, -1);
  let out = '';
  for (let i = 0; i < body.length; i++) {
    if (body[i] === '\\' && i + 1 < body.length) {
      const next = body[++i]!;
      if (next === 'n') out += '\n';
      else if (next === 't') out += '\t';
      else if (next === 'r') out += '\r';
      else if (next === 'u' && body[i + 1] === '{') {
        const close = body.indexOf('}', i + 2);
        const hex = close === -1 ? '' : body.slice(i + 2, close);
        if (close !== -1 && /^[0-9a-fA-F]{1,6}$/.test(hex)) {
          out += String.fromCodePoint(parseInt(hex, 16));
          i = close;
        } else {
          out += next;
        }
      } else out += next;
    } else if (body[i] === '"') {
      return null; // a closing quote mid-body: this is an expression
    } else {
      out += body[i];
    }
  }
  return out;
}

/** Render a JS string as a Typst string literal. */
export function toStringLiteral(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

// ── slots ────────────────────────────────────────────────────────────────

/**
 * Find every screenshot slot in the document, in source order.
 *
 * Skips the helper's own `#let` definition (which mentions the name but is
 * not a call site) and any occurrence inside a comment.
 */
export function findScreenshotSlots(source: string): ScreenshotSlot[] {
  const slots: ScreenshotSlot[] = [];
  const needle = `#${PLACEHOLDER_FN}(`;
  const letNeedle = `#let ${PLACEHOLDER_FN}(`;

  let searchFrom = 0;
  while (true) {
    const at = source.indexOf(needle, searchFrom);
    if (at === -1) break;
    searchFrom = at + needle.length;

    // `#let image-placeholder(` also contains `#…(` but is a definition.
    if (source.startsWith(letNeedle, at)) continue;
    if (isInComment(source, at)) continue;

    const openParen = at + needle.length - 1;
    const closeParen = matchDelimiter(source, openParen);
    if (closeParen === -1) continue; // unbalanced mid-edit: ignore this one

    const argsText = source.slice(openParen + 1, closeParen);
    const args = splitArgs(argsText);

    let caption: string | null = null;
    let path: string | null = null;
    let heightPt: number | null = null;
    let widthFraction: number | null = null;
    let seenPositional = false;

    for (const arg of args) {
      const name = argName(arg);
      if (name === null) {
        if (!seenPositional) {
          seenPositional = true;
          caption = parseStringLiteral(arg);
        }
        continue;
      }
      const value = arg.slice(arg.indexOf(':') + 1);
      if (name === 'path') {
        path = value.trim() === 'none' ? null : parseStringLiteral(value);
      } else if (name === 'height') {
        heightPt = parseLength(value);
      } else if (name === 'width') {
        widthFraction = parseRatio(value);
      }
    }

    slots.push({
      index: slots.length,
      start: at,
      end: closeParen + 1,
      caption,
      path,
      heightPt,
      widthFraction,
      line: lineOf(source, at),
    });
  }

  return slots;
}

/** 1-based line number of an offset. */
function lineOf(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source[i] === '\n') line++;
  }
  return line;
}

/** True if the offset sits inside a line comment or a block comment. */
function isInComment(source: string, offset: number): boolean {
  const lineStart = source.lastIndexOf('\n', offset - 1) + 1;
  const before = source.slice(lineStart, offset);
  // A `//` inside a string literal (a URL, say) is not a comment.
  let inString = false;
  for (let i = 0; i < before.length; i++) {
    const ch = before[i];
    if (ch === '\\' && inString) { i++; continue; }
    if (ch === '"') inString = !inString;
    else if (!inString && ch === '/' && before[i + 1] === '/') return true;
  }

  const lastOpen = source.lastIndexOf('/*', offset);
  if (lastOpen === -1) return false;
  const lastClose = source.lastIndexOf('*/', offset);
  return lastClose < lastOpen;
}

/**
 * Assign an asset path to a slot (or clear it with `null`), returning the new
 * source.
 *
 * Rewrites only the slot's own argument list, so any other arguments the
 * author added (a custom `height`, say) survive untouched. Clearing removes
 * the `path` argument entirely rather than writing `path: none`, keeping the
 * source as clean as the author left it.
 */
export function setSlotPath(source: string, slot: ScreenshotSlot, path: string | null): string {
  return setSlotArg(source, slot, 'path', path === null ? null : toStringLiteral(path));
}

/**
 * Set the slot's rendered height, which is what the crop viewport's aspect
 * ratio is derived from. `null` restores the helper's default.
 */
export function setSlotHeight(source: string, slot: ScreenshotSlot, heightPt: number | null): string {
  return setSlotArg(source, slot, 'height', heightPt === null ? null : formatLength(heightPt, 'in'));
}

/**
 * Set the slot's width as a fraction of the text width (written as `60%`).
 * `null` restores the helper's default. The helper must take `width`
 * (`ensureHelperWidth`).
 */
export function setSlotWidth(source: string, slot: ScreenshotSlot, fraction: number | null): string {
  return setSlotArg(source, slot, 'width', fraction === null ? null : formatRatio(fraction));
}

/**
 * Add, replace, or remove one named argument on a slot call, leaving every
 * other argument (and the author's spacing) as it was.
 */
function setSlotArg(
  source: string,
  slot: ScreenshotSlot,
  name: string,
  literal: string | null,
): string {
  const call = source.slice(slot.start, slot.end);
  const openParen = call.indexOf('(');
  const closeParen = call.length - 1;
  if (openParen === -1) return source;

  const argsText = call.slice(openParen + 1, closeParen);
  const args = splitArgs(argsText);
  const existing = args.findIndex((a) => argName(a) === name);

  let nextArgs: string[];
  if (literal === null) {
    if (existing === -1) return source; // already absent
    nextArgs = args.filter((_, i) => i !== existing);
  } else if (existing !== -1) {
    // Preserve the author's spacing around the argument.
    const original = args[existing]!;
    const lead = /^\s*/.exec(original)?.[0] ?? '';
    nextArgs = args.map((a, i) => (i === existing ? `${lead}${name}: ${literal}` : a));
  } else {
    // A trailing comma in the original leaves an empty last argument; drop
    // it before appending or the call ends up with `,,`.
    const base = [...args];
    while (base.length > 0 && base[base.length - 1]!.trim() === '') base.pop();
    nextArgs = [...base, ` ${name}: ${literal}`];
  }

  // Drop a trailing empty argument left by a trailing comma in the original.
  while (nextArgs.length > 0 && nextArgs[nextArgs.length - 1]!.trim() === '') nextArgs.pop();

  const rebuilt = `${call.slice(0, openParen + 1)}${nextArgs.join(',')})`;
  return source.slice(0, slot.start) + rebuilt + source.slice(slot.end);
}

// ── helper definition ────────────────────────────────────────────────────

export interface HelperState {
  /** True when the document defines the helper at all. */
  defined: boolean;
  /** True when the definition accepts a `path` argument. */
  supportsPath: boolean;
  /** True when the definition accepts a `width` argument. */
  supportsWidth: boolean;
  /** True when the definition is one this app generated and has since revised. */
  superseded: boolean;
  /** True when the definition differs from every version we've generated. */
  customized: boolean;
  /** Span of the existing definition, when defined. */
  start?: number;
  end?: number;
}

/**
 * Locate the helper's `#let` definition and report whether it can take an
 * image path. A document written against the original two-argument helper
 * parses fine but would error on `path:`, so the caller has to upgrade it
 * before placing.
 */
export function inspectHelper(source: string): HelperState {
  const letNeedle = `#let ${PLACEHOLDER_FN}(`;
  const at = source.indexOf(letNeedle);
  if (at === -1) {
    return { defined: false, supportsPath: false, supportsWidth: false, superseded: false, customized: false };
  }

  const paramsOpen = at + letNeedle.length - 1;
  const paramsClose = matchDelimiter(source, paramsOpen);
  if (paramsClose === -1) {
    return {
      defined: true, supportsPath: false, supportsWidth: false, superseded: false, customized: true,
      start: at, end: source.length,
    };
  }

  const params = source.slice(paramsOpen + 1, paramsClose);
  const supportsPath = splitArgs(params).some((p) => argName(p) === 'path');
  const supportsWidth = splitArgs(params).some((p) => argName(p) === 'width');

  // The body runs from the `=` to the point where all delimiters close and
  // the line ends, which covers the multi-line `figure(...)` form.
  let i = paramsClose + 1;
  while (i < source.length && /\s/.test(source[i]!)) i++;
  if (source[i] !== '=') {
    return {
      defined: true, supportsPath, supportsWidth, superseded: false, customized: true,
      start: at, end: paramsClose + 1,
    };
  }
  i++;
  while (i < source.length && /[ \t]/.test(source[i]!)) i++;

  let depth = 0;
  let inString = false;
  let end = source.length;
  for (let j = i; j < source.length; j++) {
    const ch = source[j]!;
    if (inString) {
      if (ch === '\\') { j++; continue; }
      if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { inString = true; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (ch === '\n' && depth <= 0) { end = j; break; }
  }

  // Classify the body against the versions this app has generated, so an
  // upgrade never overwrites a definition the author has customized.
  const body = canonicalize(source.slice(at, end));
  const isCurrent = body === canonicalize(PLACEHOLDER_HELPER);
  const superseded = !isCurrent && SUPERSEDED_HELPERS.some((h) => body === canonicalize(h));
  const customized = !isCurrent && !superseded;

  return { defined: true, supportsPath, supportsWidth, superseded, customized, start: at, end };
}

/**
 * Guarantee the document has a path-aware helper, returning the (possibly
 * unchanged) source.
 *
 * - Missing → insert the canonical definition after the leading run of
 *   `#set` / `#import` / `#show` rules, which is where Typst preambles live.
 * - Present but path-unaware → replace it in place, preserving position.
 */
export function ensureHelper(source: string): { source: string; changed: boolean } {
  const state = inspectHelper(source);

  // Already current, or customized by the author and still functional:
  // either way, don't touch it.
  if (state.defined && state.supportsPath && !state.superseded) {
    return { source, changed: false };
  }

  if (state.defined && state.start !== undefined && state.end !== undefined) {
    return {
      source: source.slice(0, state.start) + PLACEHOLDER_HELPER + source.slice(state.end),
      changed: true,
    };
  }

  const insertAt = endOfPreamble(source);
  const before = source.slice(0, insertAt);
  const after = source.slice(insertAt);
  const sep = before.endsWith('\n\n') || before === '' ? '' : before.endsWith('\n') ? '\n' : '\n\n';
  return {
    source: `${before}${sep}${PLACEHOLDER_HELPER}\n${after.startsWith('\n') ? '' : '\n'}${after}`,
    changed: true,
  };
}

/**
 * Guarantee the document's helper takes a `width` argument, returning the
 * (possibly unchanged) source and whether a slot's `width:` will now take
 * effect.
 *
 * A helper this app wrote is replaced by the current one (`ensureHelper`). A
 * customized one is edited in place, keeping its styling: `width: <w>` is
 * added to its parameters, where `<w>` is the first width literal in its body
 * (`90%` in every helper seen so far), and each `width: <w>` in the body then
 * reads the parameter instead. A body with no width literal is left alone
 * and reported as not scalable.
 */
export function ensureHelperWidth(source: string): { source: string; changed: boolean; scalable: boolean } {
  const ensured = ensureHelper(source);
  const state = inspectHelper(ensured.source);
  if (state.supportsWidth) return { ...ensured, scalable: true };
  if (!state.defined || state.start === undefined || state.end === undefined) {
    return { ...ensured, scalable: false };
  }
  const def = ensured.source.slice(state.start, state.end);
  const paramsOpen = def.indexOf('(');
  const paramsClose = matchDelimiter(def, paramsOpen);
  if (paramsOpen === -1 || paramsClose === -1) return { ...ensured, scalable: false };
  const body = def.slice(paramsClose + 1);
  const literal = /\bwidth\s*:\s*(\d*\.?\d+\s*(?:%|pt|mm|cm|in))/.exec(body)?.[1];
  if (!literal) return { ...ensured, scalable: false };
  const escaped = literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const nextBody = body.replace(new RegExp(`\\bwidth(\\s*):(\\s*)${escaped}`, 'g'), 'width$1:$2width');
  const params = def.slice(paramsOpen + 1, paramsClose).replace(/,?\s*$/, '');
  const nextDef = `${def.slice(0, paramsOpen + 1)}${params}, width: ${literal})${nextBody}`;
  return {
    source: ensured.source.slice(0, state.start) + nextDef + ensured.source.slice(state.end),
    changed: true,
    scalable: true,
  };
}

/** Offset just past the document's leading `#set`/`#import`/`#show` lines. */
function endOfPreamble(source: string): number {
  const lines = source.split('\n');
  let offset = 0;
  let lastRuleEnd = 0;
  // A rule can span lines (`#set page(\n  paper: "a4",\n)`): keep counting
  // brackets until it closes so the helper lands after the whole statement.
  let depth = 0;
  let inRule = false;
  for (const line of lines) {
    const trimmed = line.trim();
    const isRule = /^#(set|import|show)\b/.test(trimmed);
    if (isRule && depth === 0) inRule = true;
    if (inRule) {
      for (const ch of line) {
        if (ch === '(' || ch === '[' || ch === '{') depth++;
        else if ((ch === ')' || ch === ']' || ch === '}') && depth > 0) depth--;
      }
      lastRuleEnd = offset + line.length;
      if (depth === 0) inRule = false;
    } else if (trimmed !== '' && lastRuleEnd > 0) break;
    offset += line.length + 1;
  }
  return lastRuleEnd;
}

/** A ready-to-insert empty slot, for adding a new figure location. */
export function newSlotSnippet(caption: string): string {
  return `#${PLACEHOLDER_FN}(${toStringLiteral(caption)})\n`;
}

/**
 * `source` with one new empty figure slot appended, helper included.
 *
 * Appending at the end is deliberate: it is a predictable spot the picker
 * then scrolls to, rather than wherever a stale caret happens to be. Pure,
 * so the caller can run it against the live Y.Text content at the moment of
 * the write (invariant #3b).
 */
export function appendSlot(source: string, caption: string): string {
  const ensured = ensureHelper(source);
  const base = ensured.source.endsWith('\n') ? ensured.source : `${ensured.source}\n`;
  return `${base}\n${newSlotSnippet(caption)}`;
}

/**
 * Repoint every reference to `oldPath` at `newPath`: used when an asset is
 * renamed, so the document doesn't end up pointing at a file that no longer
 * exists in the virtual filesystem.
 *
 * Rewrites the *quoted string literal* rather than walking slots, so it also
 * catches hand-written `#image("/assets/x.png")` calls outside a figure slot.
 * Matching a full quoted path makes a false positive essentially impossible:
 * a bare occurrence of the same text in prose isn't quoted-and-absolute.
 * Lives in asset-retarget.ts so the store can use it without this module.
 */
export { retargetAssetPath } from './asset-retarget';

