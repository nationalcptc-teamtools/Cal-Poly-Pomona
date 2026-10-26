// ─────────────────────────────────────────────────────────────────────────
// Mapping a click in the rendered preview back to a position in the source.
//
// typst.ts's SVG output carries a hidden text-selection layer: every rendered
// run of text appears verbatim inside a `<foreignObject><div class="tsel">`.
// That gives us the literal string the user clicked on, and we find it in the
// source by text search.
//
// Why not the "proper" route: the renderer exposes `session.getSourceLoc()`,
// which resolves an element path to a Typst span. But spans are only embedded
// when the compiler has debug info attached, and typst.ts only exposes that
// switch on its incremental-server API: a rendered document from the normal
// compile path contains a single `data-span` for the whole page, which is
// useless for this. Text search needs no compiler cooperation and degrades
// gracefully.
//
// The trade-off is that a rendered string doesn't always appear literally in
// the source: `= Heading` renders as `Heading`, `--` renders as an en dash,
// and markup can split a sentence across runs. The matching below handles the
// common transformations and falls back progressively rather than failing.
//
// Pure and DOM-free; the click handling that feeds it lives in TypstPreview.
// ─────────────────────────────────────────────────────────────────────────

export interface SourceRange {
  from: number;
  to: number;
}

/**
 * Canonicalize typographic variants so rendered text can be matched against
 * the source that produced it.
 *
 * Every rule here is strictly **one character in, one character out**. The
 * search runs on the normalized string but reports offsets into the original,
 * so any rule that changed the length would silently skew every result.
 * (That's why `--` → en dash isn't handled here: it's 2:1. The fallbacks
 * below cover it instead.)
 */
export function normalizeForMatch(text: string): string {
  let out = '';
  for (const ch of text) {
    switch (ch) {
      // Smart quotes: Typst applies these automatically.
      case '‘': case '’': case '‚': case '‛':
        out += "'"; break;
      case '“': case '”': case '„': case '‟':
        out += '"'; break;
      // Spaces of every width.
      case ' ': case ' ': case ' ': case ' ': case ' ':
      case ' ': case ' ': case ' ': case ' ': case ' ':
      case ' ': case ' ': case '　':
        out += ' '; break;
      // Dashes and the non-breaking hyphen.
      case '‐': case '‑': case '‒': case '–': case '\u2014':
      case '−':
        out += '-'; break;
      default:
        out += ch;
    }
  }
  return out;
}

/** All indices at which `needle` occurs in `haystack`. */
function allIndicesOf(haystack: string, needle: string): number[] {
  if (!needle) return [];
  const out: number[] = [];
  let at = haystack.indexOf(needle);
  while (at !== -1) {
    out.push(at);
    at = haystack.indexOf(needle, at + 1);
  }
  return out;
}

/** A line that opens a "design" statement: layout/config, not prose. */
const DESIGN_DIRECTIVE = /^#(set|show|let|import|include)\b/;

/**
 * Character ranges occupied by **design** statements: page setup, `#set`/`#show`
 * rules, imports, and helper `#let` definitions (e.g. the `image-placeholder`
 * helper). Text that lives *only* inside one of these controls how the document
 * looks, not what it says, so a click on rendered prose should never land
 * there when the same words also exist as editable body content.
 *
 * A region starts at a line that, at bracket depth 0, begins with a design
 * directive, and runs until the statement's brackets/braces have all closed:
 * the first line end at which depth has returned to 0. That one rule covers
 * every shape uniformly, because depth simply stays > 0 until the whole thing
 * is closed:
 *   - one-liners            `#set heading(numbering: "1.1")`
 *   - multi-line calls      `#set page(\n  header: [Confidential]\n)`
 *   - brace-bodied helpers  `#let ph(c, ..) = figure( ... )`
 *
 * Pure and offset-exact: because `normalizeForMatch` is 1:1 per character, the
 * offsets returned here index the normalized haystack and the original source
 * identically.
 */
export function designRegions(source: string): Array<[number, number]> {
  const regions: Array<[number, number]> = [];
  let depth = 0;
  let start = -1; // start offset of the region we're inside, or -1
  let lineStart = true;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i]!;

    // At the first non-space of a fresh line, and only when we're not already
    // inside a region and all brackets are balanced, decide whether this line
    // opens a design statement.
    if (lineStart && start === -1 && depth === 0 && ch !== ' ' && ch !== '\t') {
      if (DESIGN_DIRECTIVE.test(source.slice(i, i + 9))) start = i;
      lineStart = false;
    } else if (ch !== ' ' && ch !== '\t') {
      lineStart = false;
    }

    switch (ch) {
      // Brackets only matter inside a region: a stray `(` in prose used to
      // leave the depth at 1 forever and hide every later design line.
      case '(': case '[': case '{': if (start !== -1) depth++; break;
      case ')': case ']': case '}': if (start !== -1 && depth > 0) depth--; break;
      case '\n':
        if (start !== -1 && depth === 0) {
          regions.push([start, i]);
          start = -1;
        }
        lineStart = true;
        break;
    }
  }
  if (start !== -1) regions.push([start, source.length]);
  return regions;
}

/** Whether `offset` falls inside any design region. */
function inDesignRegion(offset: number, regions: ReadonlyArray<readonly [number, number]>): boolean {
  for (const [s, e] of regions) if (offset >= s && offset < e) return true;
  return false;
}

/**
 * Choose the match to jump to among every occurrence of `needle`.
 *
 * Body prose the user can edit is preferred over identical text buried in a
 * design region: clicking "Confidential" in the page body must not land in the
 * `#set page(header: [Confidential])` that also renders it. Filtering the
 * design occurrences out first *also* realigns the occurrence index: the
 * rendered runs we count against are (mostly) body content, so counting only
 * body matches makes the Nth click select the Nth body instance.
 *
 * Only when there is no body match at all do we fall back to the design
 * occurrences, so a click never dead-ends when the sole source is a directive.
 */
function chooseMatch(
  haystack: string,
  needle: string,
  occurrence: number,
  regions: ReadonlyArray<readonly [number, number]>,
): number | null {
  const all = allIndicesOf(haystack, needle);
  if (all.length === 0) return null;
  const body = all.filter((i) => !inDesignRegion(i, regions));
  return pickIndex(body.length > 0 ? body : all, occurrence);
}

/**
 * Pick the `occurrence`-th hit, clamping rather than failing.
 *
 * Render order and source order can diverge (a floating figure, a footnote),
 * so an out-of-range index means our count was off, not that there's no
 * match. Landing on the last plausible hit is far more useful than doing
 * nothing.
 */
function pickIndex(indices: number[], occurrence: number): number | null {
  if (indices.length === 0) return null;
  const i = Math.min(Math.max(occurrence, 0), indices.length - 1);
  return indices[i]!;
}

/** The longest word in `text`, used as a last-resort anchor. */
function longestWord(text: string): string | null {
  const words = text.split(/[^\p{L}\p{N}_-]+/u).filter((w) => w.length >= 4);
  if (words.length === 0) return null;
  return words.reduce((a, b) => (b.length > a.length ? b : a));
}

/**
 * Locate rendered `text` in `source`, returning the range to select.
 *
 * Tries progressively looser strategies, because rendered text is not always
 * a literal substring of what produced it:
 *
 *   1. the whole string,
 *   2. whitespace-collapsed (markup can introduce line breaks mid-sentence),
 *   3. the first clause, cut at a dash or punctuation Typst may have rewritten,
 *   4. the longest single word, which survives almost any transformation.
 *
 * Every strategy prefers an editable body match over one inside a design
 * region (see `chooseMatch`), so a click lands on the prose to edit rather
 * than on the styling that formats it.
 *
 * Returns null only when nothing recognizable is found, so the caller can
 * leave the cursor where it is rather than jumping somewhere wrong.
 */
export function findSourceRange(
  source: string,
  text: string,
  occurrence = 0,
): SourceRange | null {
  const haystack = normalizeForMatch(source);
  const needle = normalizeForMatch(text).trim();
  if (needle.length < 2) return null;

  const regions = designRegions(source);

  // 1. Exact.
  let at = chooseMatch(haystack, needle, occurrence, regions);
  if (at !== null) return { from: at, to: at + needle.length };

  // 2. Collapse runs of whitespace in the needle and retry against a source
  //    whose whitespace has been collapsed the same way. Both transforms are
  //    length-preserving per character, so offsets stay meaningful only if we
  //    search the *original* haystack, so instead, split on whitespace and
  //    anchor on the longest contiguous fragment.
  const fragments = needle.split(/\s+/).filter((f) => f.length >= 3);
  if (fragments.length > 1) {
    const anchor = fragments.reduce((a, b) => (b.length > a.length ? b : a));
    at = chooseMatch(haystack, anchor, occurrence, regions);
    if (at !== null) return { from: at, to: at + anchor.length };
  }

  // 3. First clause, before any character Typst commonly rewrites.
  const clause = needle.split(/[–\u2014\-,;:]/)[0]?.trim() ?? '';
  if (clause.length >= 4) {
    at = chooseMatch(haystack, clause, occurrence, regions);
    if (at !== null) return { from: at, to: at + clause.length };
  }

  // 4. Longest word.
  const word = longestWord(needle);
  if (word) {
    at = chooseMatch(haystack, word, occurrence, regions);
    if (at !== null) return { from: at, to: at + word.length };
  }

  return null;
}

/**
 * Which occurrence of `text` this is, among `allTexts` in render order.
 *
 * Repeated strings ("Severity", a recurring table header) would otherwise all
 * jump to the first one in the source. Counting identical earlier runs lets
 * the Nth rendered instance select the Nth source instance.
 */
export function occurrenceIndex(allTexts: readonly string[], index: number): number {
  const target = normalizeForMatch(allTexts[index] ?? '').trim();
  let n = 0;
  for (let i = 0; i < index; i++) {
    if (normalizeForMatch(allTexts[i] ?? '').trim() === target) n++;
  }
  return n;
}
