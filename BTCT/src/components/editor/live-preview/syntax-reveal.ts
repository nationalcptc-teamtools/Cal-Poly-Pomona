// ─────────────────────────────────────────────────────────────────────────
// Live preview: which markdown markers to reveal for a given selection.
//
// Pure functions over a ProseMirror document. `buildRevealMarkers` answers
// "given this doc and this selection, which markers appear where", and
// `buildRevealDecorations` turns that answer into widget and node
// decorations. Nothing here creates a transaction: the markers are drawn
// next to the text, never written into it, so the Yjs fragment, undo
// history, copy and export only ever see the real content.
//
// What is revealed, Obsidian style:
// - for every textblock the selection touches, its line prefix: `> ` per
//   enclosing quote and `# `..`###### ` for a heading;
// - a list item's marker (`- `, `- [ ] `, `- [x] `) only when the caret
//   sits in front of it or a selection runs across it, drawn where the
//   rendered bullet or checkbox was. Everywhere else the bullet stays a dot
//   and the checkbox stays a checkbox. A number (`1. `) is plain text in
//   both states, as in Obsidian;
// - for a code block holding the selection, its fences (```lang and ```);
// - for a selected rule, `---` in place of the line; for a selected image
//   block, or an inline image on the caret's line, its `![alt](src)`;
// - for every inline mark range that contains or touches the selection, its
//   delimiters: `**`, `*`, `~~`, `` ` ``, `==`, and `[` + `](url)` for links.
//
// Caret slots. Several markers can share one document position (the end of
// `**bold**` followed by a link, the start of a quoted heading), and in
// Obsidian each of them is real text the caret can stand on either side of.
// ProseMirror has one caret position there, so the plugin keeps a "slot":
// how many of the markers at the caret are to its left. The slot decides
// the widgets' sides (so the native caret is drawn in that slot), which
// marks typing picks up (`slotStoredMarks`), and what Backspace and Delete
// undo. With no slot the caret takes its natural one, which matches how
// ProseMirror would extend the marks when typing there.
// ─────────────────────────────────────────────────────────────────────────

import type { Mark, Node as ProseNode } from '@milkdown/prose/model';
import { Decoration, DecorationSet } from '@milkdown/prose/view';

export type RevealKind =
  | 'heading'
  | 'quote'
  | 'list'
  | 'task'
  | 'ordered'
  | 'fence-open'
  | 'fence-close'
  | 'mark-open'
  | 'mark-close'
  | 'hr'
  | 'image';

export interface RevealMarker {
  /** Document position the widget is anchored at. */
  pos: number;
  /** The markdown the widget shows, e.g. `## ` or `](https://x)`. */
  text: string;
  kind: RevealKind;
  /**
   * ProseMirror widget side. Negative draws the marker before a caret at the
   * same position, positive after it; the magnitude orders markers that
   * share a position (lower first).
   */
  side: number;
  /** Mark name for `mark-open` / `mark-close`. */
  mark?: string;
  /** Position of the list_item node a `list` / `task` / `ordered` marker belongs to. */
  listItemPos?: number;
  /**
   * List markers only: true while the item keeps its rendered bullet or
   * checkbox (the caret is not in front of the marker and no selection
   * crosses it). Hidden markers still count as caret slots.
   */
  hidden?: boolean;
  /** List markers only: the caret stands directly in front of this marker. */
  caret?: boolean;
  /** Position of the atom node (`hr`, `image`) the marker stands for. */
  nodePos?: number;
}

/** Internal extras, kept off the enumerable shape so tests can compare markers. */
interface MarkInfo {
  mark: Mark;
  from: number;
  to: number;
}
const markInfo = new WeakMap<RevealMarker, MarkInfo>();

/** The mark and range behind a `mark-open` / `mark-close` marker. */
export function markerMark(m: RevealMarker): MarkInfo | undefined {
  return markInfo.get(m);
}

export interface RevealSelection {
  from: number;
  to: number;
  /**
   * For a caret: how many of the slot markers at the caret sit to its left.
   * Null or absent means the natural slot.
   */
  slot?: number | null;
  /**
   * Source mode: reveal every line's markdown, not only what the selection
   * touches (list markers included). The caret's slot still applies.
   */
  all?: boolean;
}

/** Upper bound on revealed textblocks, so a select-all on a huge page stays cheap. */
export const MAX_REVEAL_BLOCKS = 200;
/** The same bound in Source mode, where every block shows its markdown. */
export const MAX_SOURCE_BLOCKS = 5000;

/** Markers the caret can stand on either side of. */
const SLOT_KINDS = new Set<RevealKind>(['heading', 'quote', 'list', 'task', 'ordered', 'mark-open', 'mark-close']);
export const LINE_PREFIX_KINDS = new Set<RevealKind>(['heading', 'quote', 'list', 'task', 'ordered']);

// Mark name → [opening, closing] delimiters. `link` is built from its attrs.
function markDelimiters(mark: Mark): [string, string] | null {
  switch (mark.type.name) {
    case 'strong': {
      const m = mark.attrs.marker === '_' ? '_' : '*';
      return [m + m, m + m];
    }
    case 'emphasis': {
      const m = mark.attrs.marker === '_' ? '_' : '*';
      return [m, m];
    }
    case 'strike_through':
      return ['~~', '~~'];
    case 'inlineCode':
      return ['`', '`'];
    case 'highlight':
      return ['==', '=='];
    case 'link': {
      const href = String(mark.attrs.href ?? '');
      const title = mark.attrs.title ? ` "${String(mark.attrs.title)}"` : '';
      return ['[', `](${href}${title})`];
    }
    default:
      return null;
  }
}

/** Same mark for range-merging purposes: same type and the same attributes. */
function sameMark(a: Mark, b: Mark): boolean {
  return a.eq(b);
}

interface MarkRange {
  mark: Mark;
  from: number;
  to: number;
  /** Index of the mark in the schema's mark order, used to break ties. */
  rank: number;
}

/** Contiguous runs of each mark inside one textblock (positions are absolute). */
export function markRangesIn(block: ProseNode, blockPos: number): MarkRange[] {
  const out: MarkRange[] = [];
  const open = new Map<Mark, MarkRange>();
  let offset = blockPos + 1;
  block.forEach((child) => {
    const start = offset;
    const end = offset + child.nodeSize;
    offset = end;
    // Close every open run whose mark this child does not carry.
    for (const [m, range] of [...open]) {
      if (!child.marks.some((cm) => sameMark(cm, m))) {
        out.push(range);
        open.delete(m);
      }
    }
    child.marks.forEach((m, i) => {
      if (!markDelimiters(m)) return;
      const existing = [...open.keys()].find((om) => sameMark(om, m));
      if (existing) {
        open.get(existing)!.to = end;
      } else {
        open.set(m, { mark: m, from: start, to: end, rank: i });
      }
    });
  });
  for (const range of open.values()) out.push(range);
  return out.sort((a, b) => a.from - b.from || b.to - a.to || a.rank - b.rank);
}

/** How many other ranges strictly enclose `r` (0 = outermost). */
function nestingDepth(r: MarkRange, all: MarkRange[]): number {
  let depth = 0;
  for (const o of all) {
    if (o === r) continue;
    const encloses = o.from <= r.from && o.to >= r.to;
    if (!encloses) continue;
    const identical = o.from === r.from && o.to === r.to;
    // Two marks over the exact same text: the earlier schema mark is outer.
    if (identical && o.rank > r.rank) continue;
    depth++;
  }
  return depth;
}

function headingPrefix(level: unknown): string {
  const n = Math.min(Math.max(Number(level) || 1, 1), 6);
  return '#'.repeat(n) + ' ';
}

/** The markdown an image node stands for, as the serializer would write it. */
export function imageMarkdown(node: ProseNode): string {
  const a = node.attrs;
  const title = (t: unknown) => (t ? ` "${String(t)}"` : '');
  switch (node.type.name) {
    case 'image-block': {
      const ratio = Number.parseFloat(String(a.ratio ?? 1));
      return `![${(Number.isFinite(ratio) ? ratio : 1).toFixed(2)}](${String(a.src ?? '')}${title(a.caption)})`;
    }
    case 'asset_image':
      return `![${String(a.alt ?? '')}](asset:${String(a.assetId ?? '')})`;
    default:
      return `![${String(a.alt ?? '')}](${String(a.src ?? '')}${title(a.title)})`;
  }
}

const BLOCK_IMAGES = new Set(['image-block', 'asset_image']);

interface Touched {
  node: ProseNode;
  pos: number;
}

/** Textblocks, rules and block images the selection touches, with their positions. */
function touchedBlocks(doc: ProseNode, from: number, to: number, max = MAX_REVEAL_BLOCKS): Touched[] {
  const out: Touched[] = [];
  if (from === to) {
    const $pos = doc.resolve(from);
    if ($pos.parent.isTextblock) out.push({ node: $pos.parent, pos: $pos.before() });
    return out;
  }
  doc.nodesBetween(from, to, (node, pos) => {
    if (out.length >= max) return false;
    if (node.isTextblock) {
      out.push({ node, pos });
      return false;
    }
    if (node.type.name === 'horizontal_rule' || node.type.name === 'hr' || BLOCK_IMAGES.has(node.type.name)) {
      // Only when the selection covers the whole node (a node selection or a
      // range across it), not when a range merely starts or ends inside it.
      if (pos >= from && pos + node.nodeSize <= to) out.push({ node, pos });
      return false;
    }
    return true;
  });
  return out;
}

/** Slot markers at `pos`, in on-screen order. */
export function slotMarkersAt(markers: RevealMarker[], pos: number): RevealMarker[] {
  return markers.filter((m) => m.pos === pos && SLOT_KINDS.has(m.kind)).sort((a, b) => a.side - b.side);
}

/** The slot a caret takes when nothing chose one: after every marker drawn before it. */
export function naturalSlot(at: RevealMarker[]): number {
  return at.filter((m) => m.side < 0).length;
}

/**
 * Which markers to reveal, and where, for `sel` in `doc`. Pure: same input,
 * same output, and the document is only read.
 */
export function buildRevealMarkers(doc: ProseNode, sel: RevealSelection): RevealMarker[] {
  const markers: RevealMarker[] = [];
  const closers: PendingCloser[] = [];
  const lo = Math.max(0, Math.min(sel.from, sel.to));
  const hi = Math.min(doc.content.size, Math.max(sel.from, sel.to));
  const empty = lo === hi;
  const listMarkers: Array<{ marker: RevealMarker; textStart: number }> = [];

  const all = !!sel.all;
  const blocks = all ? touchedBlocks(doc, 0, doc.content.size, MAX_SOURCE_BLOCKS) : touchedBlocks(doc, lo, hi);
  for (const { node, pos } of blocks) {
    const textStart = pos + 1;
    const name = node.type.name;

    if (!node.isTextblock) {
      if (name === 'horizontal_rule' || name === 'hr') {
        markers.push({ pos, text: '---', kind: 'hr', side: -1, nodePos: pos });
      } else {
        markers.push({ pos, text: imageMarkdown(node), kind: 'image', side: -1, nodePos: pos });
      }
      continue;
    }

    // Code block: fences go outside the block, on their own lines.
    if (name === 'code_block') {
      const lang = String(node.attrs.language ?? '');
      markers.push({ pos, text: '```' + lang, kind: 'fence-open', side: -1 });
      markers.push({ pos: pos + node.nodeSize, text: '```', kind: 'fence-close', side: 1 });
      continue;
    }

    // Line prefix from the enclosing structure, outermost first, one marker
    // per level so each is a caret slot of its own.
    const $start = doc.resolve(textStart);
    let order = 0;
    for (let d = 1; d < $start.depth; d++) {
      const anc = $start.node(d);
      if (anc.type.name === 'blockquote') {
        markers.push({ pos: textStart, text: '> ', kind: 'quote', side: -100 + order++ });
      } else if (anc.type.name === 'list_item') {
        // Only the item's first line carries the marker; a second paragraph
        // inside the same item is a continuation.
        if ($start.before(d) + 1 !== pos) continue;
        const list = $start.node(d - 1);
        const index = $start.index(d - 1);
        const checked = anc.attrs.checked;
        let text: string;
        let kind: RevealKind = 'list';
        if (checked === true || checked === false) {
          text = checked ? '- [x] ' : '- [ ] ';
          kind = 'task';
        } else if (list.type.name === 'ordered_list') {
          const start = Number(list.attrs.order ?? 1);
          text = `${(Number.isFinite(start) ? start : 1) + index}. `;
          kind = 'ordered';
        } else {
          text = '- ';
        }
        const marker: RevealMarker = { pos: textStart, text, kind, side: -100 + order++, listItemPos: $start.before(d) };
        markers.push(marker);
        listMarkers.push({ marker, textStart });
      }
    }
    if (name === 'heading') {
      markers.push({ pos: textStart, text: headingPrefix(node.attrs.level), kind: 'heading', side: -1 });
    }

    // Inline images on the line show their source in front of them.
    node.forEach((child, offset) => {
      if (child.type.name === 'image') {
        markers.push({ pos: textStart + offset, text: imageMarkdown(child), kind: 'image', side: -1, nodePos: textStart + offset });
      }
    });

    // Inline marks that contain or touch the selection.
    const ranges = markRangesIn(node, pos);
    for (const r of ranges) {
      if (!all && (r.from > hi || r.to < lo)) continue;
      const delims = markDelimiters(r.mark);
      if (!delims) continue;
      const depth = nestingDepth(r, ranges);
      // Openers sit after a caret at the range start (typing there is outside
      // the mark), outer first. Closers are ordered below.
      const open: RevealMarker = { pos: r.from, text: delims[0], kind: 'mark-open', side: 200 + depth, mark: r.mark.type.name };
      markInfo.set(open, { mark: r.mark, from: r.from, to: r.to });
      markers.push(open);
      const close: RevealMarker = { pos: r.to, text: delims[1], kind: 'mark-close', side: 0, mark: r.mark.type.name };
      markInfo.set(close, { mark: r.mark, from: r.from, to: r.to });
      closers.push({ marker: close, depth, inclusive: r.mark.type.spec.inclusive !== false });
    }
  }

  markers.push(...orderClosers(closers));
  markers.sort((a, b) => a.pos - b.pos || a.side - b.side);

  // The caret's slot: re-side the markers at the caret so the native caret
  // is drawn after exactly `slot` of them.
  let at: RevealMarker[] = [];
  let slot = 0;
  if (empty) {
    at = slotMarkersAt(markers, lo);
    const natural = naturalSlot(at);
    slot = sel.slot == null ? natural : Math.min(Math.max(0, Math.floor(sel.slot)), at.length);
    if (slot !== natural) {
      at.forEach((m, i) => {
        m.side = i < slot ? -1000 + i : 1000 + i;
      });
      markers.sort((a, b) => a.pos - b.pos || a.side - b.side);
    }
  }

  // A list marker shows (in place of the bullet) only when the caret is in
  // front of it or a selection runs across the start of the item.
  for (const { marker, textStart } of listMarkers) {
    let shown: boolean;
    if (all) {
      shown = true;
      if (empty && lo === textStart && at.indexOf(marker) === slot) marker.caret = true;
    } else if (empty) {
      const idx = lo === textStart ? at.indexOf(marker) : -1;
      shown = idx >= 0 && slot <= idx;
      if (idx >= 0 && slot === idx) marker.caret = true;
    } else {
      shown = lo < textStart && hi >= textStart;
    }
    marker.hidden = !shown;
  }
  return markers;
}

/**
 * The marks a character typed in `slot` at `pos` should carry: the marks of
 * the text on the left, then each marker passed on the way to the slot
 * (a closer ends its mark, an opener starts one).
 */
export function slotStoredMarks(doc: ProseNode, markers: RevealMarker[], pos: number, slot: number): readonly Mark[] {
  const $pos = doc.resolve(pos);
  let set: readonly Mark[] = $pos.nodeBefore ? $pos.nodeBefore.marks : [];
  const at = slotMarkersAt(markers, pos);
  for (let i = 0; i < Math.min(slot, at.length); i++) {
    const info = markInfo.get(at[i]!);
    if (!info) continue;
    set = at[i]!.kind === 'mark-close' ? info.mark.removeFromSet(set) : info.mark.addToSet(set);
  }
  return set;
}

interface PendingCloser {
  marker: RevealMarker;
  depth: number;
  inclusive: boolean;
}

/**
 * Closers at one position go inner first, so the delimiters stay balanced.
 * A closer sits after the caret when its mark is inclusive (typing there
 * extends the mark) and before it otherwise; once an inclusive closer has
 * gone after the caret, every outer one has to follow it there too, since
 * balance beats caret placement. All closers precede any opener (200+).
 */
function orderClosers(closers: PendingCloser[]): RevealMarker[] {
  const byPos = new Map<number, PendingCloser[]>();
  for (const c of closers) {
    const list = byPos.get(c.marker.pos) ?? [];
    list.push(c);
    byPos.set(c.marker.pos, list);
  }
  const out: RevealMarker[] = [];
  for (const list of byPos.values()) {
    list.sort((a, b) => b.depth - a.depth);
    let afterCaret = false;
    list.forEach((c, i) => {
      if (c.inclusive) afterCaret = true;
      c.marker.side = afterCaret ? 50 + i : -(50 - i);
      out.push(c.marker);
    });
  }
  return out;
}

const MARKER_CLASS: Partial<Record<RevealKind, string>> = {
  heading: 'lp-marker lp-marker-block',
  quote: 'lp-marker lp-marker-block',
  'fence-open': 'lp-marker lp-marker-fence',
  'fence-close': 'lp-marker lp-marker-fence',
  hr: 'lp-marker lp-marker-fence lp-marker-hr',
  'mark-open': 'lp-marker lp-marker-inline',
  'mark-close': 'lp-marker lp-marker-inline',
};

function markerDom(m: RevealMarker, blockImage: boolean): HTMLElement {
  const block = m.kind === 'fence-open' || m.kind === 'fence-close' || m.kind === 'hr' || blockImage;
  const el = document.createElement(block ? 'div' : 'span');
  el.className =
    m.kind === 'image'
      ? `lp-marker ${blockImage ? 'lp-marker-fence' : 'lp-marker-inline'} lp-marker-image`
      : MARKER_CLASS[m.kind] ?? 'lp-marker';
  el.setAttribute('contenteditable', 'false');
  el.setAttribute('aria-hidden', 'true');
  el.dataset.lpKind = m.kind;
  if (m.mark) el.dataset.lpMark = m.mark;
  el.textContent = m.text;
  return el;
}

/** CSS classes a list item gets for its marker's state. */
function listItemClasses(m: RevealMarker): string[] {
  const out: string[] = [];
  if (!m.hidden) {
    out.push('lp-li-raw');
    if (m.kind === 'task') out.push(m.text.includes('[x]') ? 'lp-li-raw-done' : 'lp-li-raw-todo');
    else out.push(m.kind === 'ordered' ? 'lp-li-raw-ordered' : 'lp-li-raw-bullet');
  }
  if (m.caret) out.push('lp-li-caret');
  return out;
}

/**
 * Decorations for `sel` in `doc`: one widget per shown marker, plus node
 * classes on list items whose marker is revealed (the CSS swaps the
 * rendered bullet or checkbox for the raw marker, in the same spot) and on
 * a revealed rule.
 */
export function buildRevealDecorations(doc: ProseNode, sel: RevealSelection): DecorationSet {
  const markers = buildRevealMarkers(doc, sel);
  if (markers.length === 0) return DecorationSet.empty;
  const decos: Decoration[] = [];
  const items = new Map<number, string[]>();
  for (const m of markers) {
    if (m.listItemPos != null) {
      const classes = listItemClasses(m);
      if (classes.length) items.set(m.listItemPos, [...(items.get(m.listItemPos) ?? []), ...classes]);
      continue;
    }
    const target = m.nodePos != null ? doc.nodeAt(m.nodePos) : null;
    const blockImage = m.kind === 'image' && !!target && !target.isInline;
    decos.push(
      Decoration.widget(m.pos, () => markerDom(m, blockImage), {
        side: m.side,
        ignoreSelection: true,
        marks: [],
        key: `lp:${m.kind}:${m.side}:${m.text}`,
        lpKind: m.kind,
      }),
    );
    if (m.kind === 'hr' && target) {
      decos.push(Decoration.node(m.pos, m.pos + target.nodeSize, { class: 'lp-hr-raw' }));
    }
  }
  for (const [itemPos, classes] of items) {
    const item = doc.nodeAt(itemPos);
    if (item) decos.push(Decoration.node(itemPos, itemPos + item.nodeSize, { class: classes.join(' ') }));
  }
  return DecorationSet.create(doc, decos);
}
