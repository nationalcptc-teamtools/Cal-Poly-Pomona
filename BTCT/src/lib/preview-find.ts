// ─────────────────────────────────────────────────────────────────────────
// Find in the rendered report (the preview's Ctrl/⌘+F bar).
//
// The browser's own find cannot be trusted with the preview: the pages live
// in a shadow root, and their text is typst.ts's transparent selection layer
// (one `<foreignObject>` per text run, see lib/typst-pages), most of which is
// not even in the DOM because pages mount only near the viewport. So the
// preview searches the text runs of every page itself, parsed from the page
// fragments, and highlights what it finds on the pages that are mounted.
//
// Pure and DOM-free: the input is each page's runs, in document order, as
// `extractTextRuns` returns them; the output says which characters of which
// runs a match covers, so the preview can measure them on a mounted page.
// ─────────────────────────────────────────────────────────────────────────

export interface FindOptions {
  /** Case-sensitive matching (default: insensitive). */
  caseSensitive: boolean;
}

/** One run's share of a match: characters `[start, end)` of run `run` on the page. */
export interface FindPiece {
  run: number;
  start: number;
  end: number;
}

/** One match. A phrase that crosses a style change or a line break covers several runs. */
export interface PreviewMatch {
  page: number;
  pieces: FindPiece[];
}

/** Hard ceiling, so a one-letter query over a long report stays cheap to draw. */
export const MAX_PREVIEW_MATCHES = 2000;

/**
 * A page's runs joined into one searchable string, and where each run starts
 * in it. Runs are joined with a space unless one side already has whitespace
 * at the seam: typst cuts runs at line breaks (the trailing space dropped) and
 * at style changes (the space kept on one side), so a phrase that wraps or
 * changes weight still reads as words separated by one space.
 */
export function joinRuns(runs: readonly string[]): { text: string; starts: number[] } {
  let text = '';
  const starts: number[] = [];
  for (let i = 0; i < runs.length; i++) {
    const run = runs[i]!;
    if (i > 0 && text.length > 0 && run.length > 0 && !/\s$/.test(text) && !/^\s/.test(run)) text += ' ';
    starts.push(text.length);
    text += run;
  }
  return { text, starts };
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * The matcher for a query, or null when it cannot match anything (empty or
 * whitespace only). The query is literal; any run of whitespace in it matches
 * any run of whitespace on the page, since the page's spacing (a line break,
 * a non-breaking space, a justified gap) is not something the reader sees.
 */
export function compileFindQuery(query: string, opts: FindOptions): RegExp | null {
  if (!query.trim()) return null;
  const body = query.split(/\s+/).map(escapeRegExp).join('\\s+');
  return new RegExp(body, opts.caseSensitive ? 'gu' : 'giu');
}

/** Split the joined-text range `[from, to)` back into per-run pieces. */
function piecesOf(from: number, to: number, runs: readonly string[], starts: readonly number[]): FindPiece[] {
  const pieces: FindPiece[] = [];
  for (let i = 0; i < runs.length; i++) {
    const s = starts[i]!;
    const e = s + runs[i]!.length;
    if (e <= from) continue;
    if (s >= to) break;
    const start = Math.max(from, s) - s;
    const end = Math.min(to, e) - s;
    if (end > start) pieces.push({ run: i, start, end });
  }
  return pieces;
}

/**
 * Every match of `query` in the document, page by page, in reading order.
 * A match never spans two pages. Capped at `limit`.
 */
export function findInPages(
  pages: readonly (readonly string[])[],
  query: string,
  opts: FindOptions,
  limit = MAX_PREVIEW_MATCHES,
): PreviewMatch[] {
  const re = compileFindQuery(query, opts);
  if (!re) return [];
  const out: PreviewMatch[] = [];
  for (let page = 0; page < pages.length && out.length < limit; page++) {
    const runs = pages[page]!;
    const { text, starts } = joinRuns(runs);
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const from = m.index;
      const to = from + m[0].length;
      if (to === from) { re.lastIndex++; continue; }
      const pieces = piecesOf(from, to, runs, starts);
      if (pieces.length > 0) out.push({ page, pieces });
      if (out.length >= limit) break;
    }
  }
  return out;
}

/** `current` moved by `dir`, wrapping at both ends; -1 when there are no matches. */
export function stepMatch(current: number, total: number, dir: 1 | -1): number {
  if (total <= 0) return -1;
  if (current < 0 || current >= total) return dir === 1 ? 0 : total - 1;
  return (current + dir + total) % total;
}

/**
 * Where a new search starts: the first match on or after `page` (the page in
 * view), wrapping to the first match of the document; -1 when there is none.
 */
export function firstMatchFrom(matches: readonly PreviewMatch[], page: number): number {
  if (matches.length === 0) return -1;
  const i = matches.findIndex((m) => m.page >= page);
  return i === -1 ? 0 : i;
}

/** The status text for the bar: "3 of 12", "No matches", or "" before anything is typed. */
export function matchLabel(current: number, total: number, query: string, capped: boolean): string {
  if (!query.trim()) return '';
  if (total === 0) return 'No matches';
  const of = capped ? `${total}+` : String(total);
  return `${Math.max(0, current) + 1} of ${of}`;
}

// ─────────────────────────────────────────────────────────────────────────
// Measuring a match on a mounted page.
// ─────────────────────────────────────────────────────────────────────────

/** A highlight rectangle in page units (the page's own SVG coordinates). */
export interface PageBox {
  x: number;
  y: number;
  w: number;
  h: number;
}

interface RectLike {
  left: number;
  top: number;
  right: number;
  bottom: number;
  width: number;
}

/**
 * Screen rectangles (from `getClientRects`) as page-unit boxes. `card` is the
 * page card's own rectangle and `pageWidth` its width in page units, so the
 * conversion is a ratio of two rectangles: it holds at any preview zoom and
 * any interface zoom (invariant 19) without knowing either. `clip` is the
 * run's box: typst.ts's selection text is transparent and can overrun it, and
 * a highlight should stay on the glyphs the reader sees. Rectangles of one
 * piece are merged into one box, since a piece never leaves its line.
 */
export function toPageBox(rects: readonly RectLike[], card: RectLike, pageWidth: number, clip: RectLike | null): PageBox | null {
  if (card.width <= 0 || pageWidth <= 0) return null;
  let left = Infinity, right = -Infinity;
  for (const r of rects) {
    if (r.right - r.left <= 0 && r.bottom - r.top <= 0) continue;
    left = Math.min(left, r.left);
    right = Math.max(right, r.right);
  }
  if (left === Infinity) return null;
  let top: number, bottom: number;
  if (clip) {
    // The run's box gives the line's height; the text range only says where along it.
    top = clip.top;
    bottom = clip.bottom;
    left = Math.max(left, clip.left);
    right = Math.min(right, clip.right);
    if (right <= left) return null;
  } else {
    top = Math.min(...rects.map((r) => r.top));
    bottom = Math.max(...rects.map((r) => r.bottom));
  }
  const scale = card.width / pageWidth;
  return {
    x: (left - card.left) / scale,
    y: (top - card.top) / scale,
    w: (right - left) / scale,
    h: (bottom - top) / scale,
  };
}

/**
 * A DOM Range over characters `[start, end)` of `root`'s text, counted the way
 * `textContent` counts them (nested spans flattened), or null when the text is
 * shorter than that.
 */
export function textRange(root: Node, start: number, end: number): Range | null {
  const doc = root.ownerDocument;
  if (!doc || end <= start) return null;
  const walker = doc.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let offset = 0;
  let startNode: Text | null = null, startOffset = 0;
  for (let node = walker.nextNode() as Text | null; node; node = walker.nextNode() as Text | null) {
    const len = node.data.length;
    if (!startNode && start < offset + len) { startNode = node; startOffset = start - offset; }
    if (startNode && end <= offset + len) {
      const range = doc.createRange();
      range.setStart(startNode, startOffset);
      range.setEnd(node, end - offset);
      return range;
    }
    offset += len;
  }
  return null;
}

/** One glyph of a rendered run: its pen position, and whether it draws nothing (a space). */
export interface GlyphPos {
  x: number;
  blank: boolean;
}

/**
 * Where characters `[start, end)` of a run's text sit along its glyphs, in
 * the glyphs' own units, or null when that cannot be told.
 *
 * typst.ts draws a run as one `<use x=…>` per glyph, and its selection text
 * is a different font stretched to the run's width, so a Range over the
 * selection text drifts off the glyphs along a line. The glyphs cannot be
 * mapped to characters one to one (a ligature is one glyph for "fi"), but
 * words can: the n-th run of non-blank glyphs is the n-th word of the text.
 * A word's edges are therefore exact, and a position inside a word is placed
 * in proportion to its characters. When the word counts disagree (a glyph
 * typst drew for whitespace, text the selection layer spells differently)
 * the answer is null and the caller falls back to the Range.
 *
 * `width` is where the run ends, in the same units, so the last glyph's
 * advance is known.
 */
export function glyphSpan(text: string, start: number, end: number, glyphs: readonly GlyphPos[], width: number): [number, number] | null {
  if (end <= start || glyphs.length === 0) return null;
  const words: Array<[number, number]> = [];
  for (const m of text.matchAll(/\S+/g)) words.push([m.index!, m.index! + m[0].length]);
  const spans: Array<[number, number]> = [];
  for (let i = 0; i < glyphs.length; i++) {
    if (glyphs[i]!.blank) continue;
    let j = i;
    while (j + 1 < glyphs.length && !glyphs[j + 1]!.blank) j++;
    spans.push([glyphs[i]!.x, j + 1 < glyphs.length ? glyphs[j + 1]!.x : width]);
    i = j;
  }
  if (words.length === 0 || words.length !== spans.length) return null;

  // The word a position falls in, moved off whitespace: a start onto the next
  // word, an end back onto the previous one.
  const at = (pos: number, isEnd: boolean): number | null => {
    for (let k = 0; k < words.length; k++) {
      const [s, e] = words[k]!;
      const inside = isEnd ? pos > s && pos <= e : pos >= s && pos < e;
      if (inside) {
        const [x0, x1] = spans[k]!;
        return x0 + ((pos - s) / (e - s)) * (x1 - x0);
      }
    }
    if (isEnd) {
      for (let k = words.length - 1; k >= 0; k--) if (words[k]![1] <= pos) return spans[k]![1];
    } else {
      for (let k = 0; k < words.length; k++) if (words[k]![0] >= pos) return spans[k]![0];
    }
    return null;
  };
  const x0 = at(start, false);
  const x1 = at(end, true);
  if (x0 === null || x1 === null || x1 <= x0) return null;
  return [x0, x1];
}
