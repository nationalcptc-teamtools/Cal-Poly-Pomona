// ─────────────────────────────────────────────────────────────────────────
// Findings mode: which rendered block in the preview is the selected
// finding, and what selecting one may do to the code editor.
//
// typst.ts's normal compile path carries no usable source-to-document map
// (see lib/typst-source-map: one `data-span` per page), so the block is found
// in the rendered text, over the text runs of every page (mounted or not, the
// same input the preview's find bar searches):
//
//  1. Every finding block draws the label "CVSS SCORE" once (CPTC's
//     `#finding` and BTCT's helper both upper-case their label cells), and a
//     writer's prose almost never spells it in capitals. When the rendered
//     document has exactly as many of those labels as the source has
//     `#finding(...)` calls, the n-th label belongs to the n-th finding:
//     duplicate titles, empty titles and a title that also sits in the
//     contents or the report card all resolve by position.
//  2. Otherwise (a template without that label, a finding the template does
//     not render) the title is matched, preferring a match that a "CVSS
//     SCORE" label follows closely (a block head rather than a contents line
//     or a table cell), and duplicates are told apart by their order.
//
// The block's head is the title match just before its label, else the label
// itself. Pure and DOM-free; TypstPreview does the measuring and scrolling.
// ─────────────────────────────────────────────────────────────────────────

import { compileFindQuery, joinRuns, type FindPiece } from './preview-find';

/** What the rail knows about the selected finding, from the source. */
export interface FindingTarget {
  /** Document order among the source's findings, 0-based. */
  ordinal: number;
  /** How many findings the source has. */
  count: number;
  /** The title as written (may be empty). */
  title: string;
  /** How many earlier findings have the same title (case and spacing ignored). */
  titleOrdinal: number;
  /** How many findings have this title, this one included. */
  titleCount: number;
  /** The next finding's title, so the highlight stops above its head. */
  nextTitle: string;
}

/** A located block: the page it starts on and the runs of its head there. */
export interface FindingHit {
  page: number;
  pieces: FindPiece[];
  /** The next block's head when it starts on the same page (bounds the highlight). */
  next: FindPiece[] | null;
  /** Which rule found it, for tests and debugging. */
  via: 'label' | 'title';
}

/** The label every finding block draws once. Case-sensitive on purpose. */
export const BLOCK_LABEL = 'CVSS SCORE';

/** How far (in joined characters) a block's label may sit after its title. */
const HEAD_SPAN = 600;

interface Located {
  page: number;
  /** Offset in the whole document's joined text (pages joined with one newline). */
  at: number;
  end: number;
  pieces: FindPiece[];
}

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

/** Every match of `query` with its place in the whole document. */
export function locateAll(pages: readonly (readonly string[])[], query: string, caseSensitive: boolean): Located[] {
  const re = compileFindQuery(query, { caseSensitive });
  if (!re) return [];
  const out: Located[] = [];
  let base = 0;
  for (let page = 0; page < pages.length; page++) {
    const runs = pages[page]!;
    const { text, starts } = joinRuns(runs);
    re.lastIndex = 0;
    for (let m = re.exec(text); m; m = re.exec(text)) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      const pieces = piecesOf(m.index, m.index + m[0].length, runs, starts);
      if (pieces.length > 0) out.push({ page, at: base + m.index, end: base + m.index + m[0].length, pieces });
    }
    base += text.length + 1;
  }
  return out;
}

/** Titles compare with case and spacing ignored, like the matcher. */
export function titleKey(title: string): string {
  return title.trim().replace(/\s+/g, ' ').toLowerCase();
}

/** The rail's target for finding `index` of `titles` (every finding's title, in document order). */
export function findingTarget(titles: readonly string[], index: number): FindingTarget {
  const key = titleKey(titles[index] ?? '');
  let titleOrdinal = 0;
  let titleCount = 0;
  titles.forEach((t, i) => {
    if (titleKey(t) !== key) return;
    if (i < index) titleOrdinal++;
    titleCount++;
  });
  return { ordinal: index, count: titles.length, title: titles[index] ?? '', titleOrdinal, titleCount, nextTitle: titles[index + 1] ?? '' };
}

/** The last title match that ends before `label` and within `HEAD_SPAN` of it. */
function headBefore(titles: readonly Located[], label: Located, after: number): Located | null {
  let best: Located | null = null;
  for (const t of titles) {
    if (t.end > label.at) break;
    if (t.at < after || label.at - t.end > HEAD_SPAN) continue;
    best = t;
  }
  return best;
}

/** A run the title bar of a block with no title draws: its number ("6.1.x", "1.4.1") or a pill. */
const BAR_RUN_RE = /^(?:[\d.]+x?|[\d.]*\d|REDISCOVERED|CRITICAL|HIGH|MEDIUM|LOW|INFO(?:RMATIONAL)?)$/i;

/**
 * A block with an empty title has no title to match, so its head is its
 * label; the title bar above it still draws a number and maybe a pill. Take
 * up to three such runs right before the label, on its page, into the head
 * so the outline starts at the bar.
 */
function withTitleBar(runs: readonly string[], label: Located): Located {
  const first = label.pieces[0]!.run;
  let from = first;
  for (let r = first - 1; r >= 0 && r >= first - 3; r--) {
    const text = runs[r]!.trim();
    if (!text) continue;
    if (!BAR_RUN_RE.test(text)) break;
    from = r;
  }
  if (from === first) return label;
  const extra: FindPiece[] = [];
  for (let r = from; r < first; r++) if (runs[r]!.length > 0) extra.push({ run: r, start: 0, end: runs[r]!.length });
  return { ...label, pieces: [...extra, ...label.pieces] };
}

/** Where the selected finding's block starts in the rendered pages, or null. */
export function locateFindingBlock(pages: readonly (readonly string[])[], target: FindingTarget): FindingHit | null {
  const labels = locateAll(pages, BLOCK_LABEL, true);
  const titles = target.title.trim() ? locateAll(pages, target.title, false) : [];

  // Each block's head: its title just above the label when the title is
  // found there, else the label. Heads never reach back past the previous
  // block's label.
  const headOf = (i: number, list: readonly Located[], titleList: readonly Located[]): Located => {
    const label = list[i]!;
    const prev = i > 0 ? list[i - 1]!.end : 0;
    return headBefore(titleList, label, prev) ?? withTitleBar(pages[label.page]!, label);
  };
  const nextOnPage = (head: Located, nextHead: Located | null): FindPiece[] | null =>
    nextHead && nextHead.page === head.page ? nextHead.pieces : null;

  if (target.count > 0 && labels.length === target.count && target.ordinal < labels.length) {
    const head = headOf(target.ordinal, labels, titles);
    // The next block's head may carry another title: a label bounds it well enough.
    const next = target.ordinal + 1 < labels.length ? labels[target.ordinal + 1]! : null;
    const nextTitles = next && target.nextTitle.trim() ? locateAll(pages, target.nextTitle, false) : [];
    const nextHead = next ? headBefore(nextTitles, next, head.end) ?? next : null;
    return { page: head.page, pieces: head.pieces, next: nextOnPage(head, nextHead), via: 'label' };
  }

  if (titles.length === 0) return null;
  // A block head is a title a label follows closely, with no other label between.
  const isHead = (t: Located): boolean => {
    const label = labels.find((l) => l.at >= t.end);
    return !!label && label.at - t.end <= HEAD_SPAN;
  };
  const heads = titles.filter(isHead);
  const list = heads.length > 0 ? heads : titles;
  let pick: number;
  if (list.length === target.titleCount) pick = target.titleOrdinal;
  // More matches than findings with the title: the extra ones are usually
  // earlier (contents, a summary table), so count from the end.
  else if (list.length > target.titleCount) pick = list.length - target.titleCount + target.titleOrdinal;
  else pick = Math.min(target.titleOrdinal, list.length - 1);
  const head = list[pick]!;
  // The highlight stops at the next block: its label, or its title just above it.
  const following = labels.find((l) => l.at >= head.end);
  const after = following ? labels.find((l) => l.at > following.at) ?? null : null;
  const nextTitles = after && target.nextTitle.trim() ? locateAll(pages, target.nextTitle, false) : [];
  const nextHead = after ? headBefore(nextTitles, after, following!.end) ?? after : null;
  return { page: head.page, pieces: head.pieces, next: nextOnPage(head, nextHead), via: 'title' };
}

// ─────────────────────────────────────────────────────────────────────────
// The highlight's rectangle on a mounted page.
// ─────────────────────────────────────────────────────────────────────────

export interface Rect {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

/** A rectangle in page units. */
export interface PageRect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/**
 * The block's area on its first page, in page units: from just above its
 * head down to just above the next block's head (when that is on the same
 * page) or to the last line of text on the page, ignoring the footer band;
 * across the page's text column. Every rectangle is in screen pixels;
 * `card` is the page card's and `pageWidth`/`pageHeight` its size in page
 * units, so the conversion is a ratio and holds at any zoom.
 */
export function blockRegion(
  head: readonly Rect[],
  next: readonly Rect[] | null,
  all: readonly Rect[],
  card: Rect,
  pageWidth: number,
  pageHeight: number,
): PageRect | null {
  const cardW = card.right - card.left;
  if (head.length === 0 || cardW <= 0 || pageWidth <= 0) return null;
  const scale = cardW / pageWidth;
  const toY = (y: number) => (y - card.top) / scale;
  const toX = (x: number) => (x - card.left) / scale;
  const pad = 8;
  const top = Math.max(0, Math.min(...head.map((r) => toY(r.top))) - pad);
  const footer = pageHeight * 0.92;
  let bottom: number;
  if (next && next.length > 0) {
    bottom = Math.min(...next.map((r) => toY(r.top))) - pad;
  } else {
    const below = all.map((r) => toY(r.bottom)).filter((y) => y > top && y < footer);
    bottom = (below.length > 0 ? Math.max(...below) : Math.max(...head.map((r) => toY(r.bottom)))) + pad;
  }
  bottom = Math.min(bottom, pageHeight);
  if (bottom <= top) bottom = Math.min(pageHeight, top + 2 * pad + 20);
  const lefts = all.map((r) => toX(r.left)).filter((x) => x >= 0);
  const left = Math.max(0, (lefts.length > 0 ? Math.min(...lefts) : 0) - pad);
  const right = Math.max(pageWidth - left, ...all.map((r) => toX(r.right) + pad).filter((x) => x <= pageWidth));
  return { x: left, y: top, w: Math.max(0, Math.min(pageWidth, right) - left), h: bottom - top };
}

// ─────────────────────────────────────────────────────────────────────────
// The preview lock's say over the code editor.
// ─────────────────────────────────────────────────────────────────────────

/**
 * What selecting a finding does, decided once at selection time: with the
 * preview locked (invariant 34) the operator is reading the rendered report,
 * so the code editor is left alone (no spotlight, no scroll, no focus, a
 * hidden Code pane stays hidden) and only the form opens and the preview
 * jumps. Unlocked, the code is spotlit as well. Edits in the form write to
 * the source either way.
 */
export function findingSelectEffects(locked: boolean): { spotlightCode: boolean; jumpPreview: boolean } {
  return { spotlightCode: !locked, jumpPreview: true };
}
