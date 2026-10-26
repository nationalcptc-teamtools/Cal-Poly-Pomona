// ─────────────────────────────────────────────────────────────────────────
// Live preview ProseMirror plugin (Obsidian-style editor).
//
// Installed on every page editor in both styles; it only acts while the
// "Editor style" pref is `live` (see editor-style.ts), so switching styles
// never rebuilds the editor (invariant #3).
//
// - Decorations: the markers from syntax-reveal.ts for the local selection.
//   They appear once this editor has had focus and then follow its
//   selection, focused or not, the way Obsidian keeps the cursor line's
//   source showing when you click into another pane. A remote
//   collaborator's cursor never reveals anything on your screen.
// - The decorations never write to the document (invariant #33). The
//   transactions they cause are meta-only (style switch, focus, end of an
//   IME composition, a caret slot change, stored marks for a slot), all
//   flagged `addToHistory: false`.
// - Caret slots (see syntax-reveal.ts): ArrowLeft / ArrowRight step the
//   caret across the revealed markers at its position before moving it,
//   Home from the start of a line steps in front of the line's markers, and
//   typing picks up the marks of the slot the caret is in.
// - Editing the revealed syntax: Backspace right after a revealed marker,
//   or Delete right before one, undoes that piece of markdown with a real
//   editing command: `## ` becomes `# `, `- [ ] ` becomes `- `, a list item
//   or a quoted line leaves its list or quote, `**` unbolds. `#` typed in
//   front of a heading's `## ` raises its level. Delete at the start of a
//   line deletes forward, as in a text editor.
// - Paste: `==text==` in pasted text becomes a highlight (highlight-syntax.ts).
// - `*` `_` `~` `=` typed over a selection in one line wrap it (italic, then
//   bold; strike; highlight), Obsidian's "Auto pair Markdown syntax".
// - Source mode (editor-style.ts `setSourceMode`): every line shows its
//   markdown, not only the selection's, with the same caret slots.
// - IME and mouse drags: while either runs the decorations are mapped, not
//   rebuilt, so no widget is inserted or moved next to the text being
//   composed or at a drag's anchor.
// - `view.dom` carries `lp-live` while the style is active, for the CSS.
// ─────────────────────────────────────────────────────────────────────────

import { $prose } from '@milkdown/utils';
import { Plugin, PluginKey, Selection, TextSelection, type EditorState, type Transaction } from '@milkdown/prose/state';
import { joinBackward, joinForward, lift } from '@milkdown/prose/commands';
import { liftTarget } from '@milkdown/prose/transform';
import { Mark, type MarkType } from '@milkdown/prose/model';
import { DecorationSet, type EditorView } from '@milkdown/prose/view';
import {
  buildRevealDecorations,
  buildRevealMarkers,
  markerMark,
  naturalSlot,
  slotMarkersAt,
  slotStoredMarks,
  type RevealMarker,
} from './syntax-reveal';
import { convertHighlightSyntax } from './highlight-syntax';
import './live-preview.css';
import { getEditorStyle, isSourceMode, subscribeEditorStyle, type EditorStyle } from './editor-style';

export interface LivePreviewState {
  style: EditorStyle;
  /** The editor holds focus right now. */
  focused: boolean;
  /** The editor has had focus at least once; markers show from then on. */
  engaged: boolean;
  /** Caret slot (see syntax-reveal.ts); null is the natural one. */
  slot: number | null;
  /** Source mode: every line shows its markdown. */
  source: boolean;
  decorations: DecorationSet;
}

interface LivePreviewMeta {
  style?: EditorStyle;
  focused?: boolean;
  refresh?: boolean;
  source?: boolean;
  /** Set the caret slot (null: natural). */
  slot?: number | null;
}

export const livePreviewKey = new PluginKey<LivePreviewState>('btct-live-preview');

function compute(
  state: Pick<EditorState, 'doc' | 'selection'>,
  style: EditorStyle,
  engaged: boolean,
  slot: number | null,
  source: boolean,
): DecorationSet {
  if (style !== 'live' || (!engaged && !source)) return DecorationSet.empty;
  const { from, to } = state.selection;
  return buildRevealDecorations(state.doc, { from, to, slot, all: source });
}

export interface LivePreviewOptions {
  /** Style the plugin starts with (default: the current pref). */
  initialStyle?: EditorStyle;
  /** Start as focused (tests; a real editor learns it from focus events). */
  initialFocused?: boolean;
  /** Start in Source mode (default: the current setting). */
  initialSource?: boolean;
}

/** Dispatch a meta-only transaction that changes no content and records no history. */
function dispatchMeta(view: EditorView, meta: LivePreviewMeta): void {
  if ((view as unknown as { isDestroyed?: boolean }).isDestroyed) return;
  view.dispatch(view.state.tr.setMeta(livePreviewKey, meta).setMeta('addToHistory', false));
}

/** Slot markers at an empty caret, with the slot the caret is in. */
function caretSlots(state: EditorState): { pos: number; at: RevealMarker[]; slot: number; natural: number } | null {
  const sel = state.selection;
  if (!(sel instanceof TextSelection) || !sel.empty) return null;
  const pos = sel.from;
  // The markers at the caret are the same in Source mode: only the ones at
  // this position matter, and those always touch it.
  const markers = buildRevealMarkers(state.doc, { from: pos, to: pos });
  const at = slotMarkersAt(markers, pos);
  const natural = naturalSlot(at);
  const chosen = livePreviewKey.getState(state)?.slot;
  const slot = chosen == null ? natural : Math.min(Math.max(0, chosen), at.length);
  return { pos, at, slot, natural };
}

/** A meta transaction moving the caret to `slot`, with the marks typing there should carry. */
function slotTransaction(state: EditorState, slot: number): Transaction {
  const info = caretSlots(state);
  const tr = state.tr.setMeta(livePreviewKey, { slot }).setMeta('addToHistory', false);
  if (!info) return tr;
  if (slot === info.natural) return tr.setStoredMarks(null);
  const markers = buildRevealMarkers(state.doc, { from: info.pos, to: info.pos });
  return tr.setStoredMarks(slotStoredMarks(state.doc, markers, info.pos, slot));
}

/**
 * Put the caret in front of a list item's marker (what a click on its
 * rendered bullet does): the raw `- ` / `- [ ] ` / `1. ` shows in place.
 * Returns false when the item has no text line to hold the caret.
 */
export function placeCaretBeforeListMarker(view: EditorView, itemPos: number): boolean {
  const state = view.state;
  const item = state.doc.nodeAt(itemPos);
  const first = item?.firstChild;
  if (!item || !first || !first.isTextblock) return false;
  const caret = itemPos + 2;
  const markers = buildRevealMarkers(state.doc, { from: caret, to: caret });
  const at = slotMarkersAt(markers, caret);
  const idx = at.findIndex((m) => m.listItemPos === itemPos);
  if (idx < 0) return false;
  const tr = state.tr.setSelection(TextSelection.create(state.doc, caret)).setMeta(livePreviewKey, { slot: idx });
  view.dispatch(tr.setStoredMarks(null));
  if (!view.hasFocus()) view.focus();
  return true;
}

type Cmd = (state: EditorState, dispatch?: (tr: Transaction) => void, view?: EditorView) => boolean;

/** Undo the markdown construct one revealed marker stands for. */
function undoMarker(view: EditorView, m: RevealMarker, direction: 'backward' | 'forward'): boolean {
  const state = view.state;
  const dispatch = (tr: Transaction) => view.dispatch(tr.scrollIntoView());
  const $pos = state.doc.resolve(state.selection.from);
  switch (m.kind) {
    case 'mark-open':
    case 'mark-close': {
      const info = markerMark(m);
      if (!info) return false;
      dispatch(state.tr.removeMark(info.from, info.to, info.mark));
      return true;
    }
    case 'heading': {
      const block = $pos.parent;
      if (block.type.name !== 'heading') return false;
      const level = Number(block.attrs.level) || 1;
      const at = $pos.before();
      if (level > 1) {
        dispatch(state.tr.setNodeMarkup(at, undefined, { ...block.attrs, level: level - 1 }));
      } else {
        const para = state.schema.nodes.paragraph;
        if (!para) return false;
        dispatch(state.tr.setBlockType(at + 1, at + 1, para));
      }
      return true;
    }
    case 'quote': {
      const range = $pos.blockRange();
      const target = range ? liftTarget(range) : null;
      if (!range || target == null) return false;
      dispatch(state.tr.lift(range, target));
      return true;
    }
    case 'task': {
      if (direction === 'backward' && m.listItemPos != null) {
        // `- [ ] ` loses its box first, the way deleting the space after
        // `]` leaves a plain `- ` item in Obsidian.
        const item = state.doc.nodeAt(m.listItemPos);
        if (!item) return false;
        dispatch(state.tr.setNodeMarkup(m.listItemPos, undefined, { ...item.attrs, checked: null }));
        return true;
      }
      return (joinBackward as Cmd)(state, dispatch, view) || (lift as Cmd)(state, dispatch);
    }
    case 'list':
    case 'ordered':
      // The first item of a list becomes a plain line; a later one becomes a
      // continuation line of the item above, which is what deleting its
      // marker does to the markdown (CodeMirror's deleteMarkupBackward too).
      return (joinBackward as Cmd)(state, dispatch, view) || (lift as Cmd)(state, dispatch);
    default:
      return false;
  }
}

/**
 * Backspace on an empty line that follows a nested list inside a list item
 * (or any non-text block in a container): delete the line and put the caret
 * at the end of the line above, as a text editor does. ProseMirror's own
 * joinBackward would wrap the empty line into the nested list as a new item.
 */
function deleteEmptyLine(view: EditorView): boolean {
  const state = view.state;
  const $pos = state.selection.$from;
  if ($pos.parent.content.size !== 0 || $pos.depth < 2) return false;
  const index = $pos.index(-1);
  if (index === 0) return false;
  const before = $pos.node(-1).child(index - 1);
  if (before.isTextblock) return false;
  const start = $pos.before();
  const tr = state.tr.delete(start, $pos.after());
  tr.setSelection(Selection.near(tr.doc.resolve(start), -1));
  view.dispatch(tr.scrollIntoView());
  return true;
}

/** Delete one character (or inline node) forward from an empty caret. */
function deleteForward(view: EditorView): boolean {
  const state = view.state;
  const $pos = state.selection.$from;
  const after = $pos.nodeAfter;
  if (!after) return (joinForward as Cmd)(state, (tr) => view.dispatch(tr.scrollIntoView()), view);
  let len = 1;
  if (after.isText) {
    const code = after.text!.charCodeAt($pos.textOffset);
    if (code >= 0xd800 && code <= 0xdbff && after.text!.length > $pos.textOffset + 1) len = 2;
  } else {
    len = after.nodeSize;
  }
  view.dispatch(state.tr.delete($pos.pos, $pos.pos + len).scrollIntoView());
  return true;
}

export interface WidgetBox {
  left: number;
  right: number;
}

/**
 * The slot a click at `x` puts the caret in, given the slot markers at the
 * caret (`at`) and the boxes of their widgets on screen, in order. List
 * markers have no widget (they are drawn in the bullet column) and are
 * never chosen by a click in the text: a click left of every widget lands
 * just after them. Null when the boxes do not match the markers.
 */
export function slotFromClick(at: RevealMarker[], boxes: WidgetBox[], x: number): number | null {
  const isList = (m: RevealMarker) => m.listItemPos != null;
  if (boxes.length !== at.filter((m) => !isList(m)).length || boxes.length === 0) return null;
  let slot = at.findIndex((m) => !isList(m));
  let b = 0;
  for (let i = 0; i < at.length; i++) {
    if (isList(at[i]!)) continue;
    const box = boxes[b++]!;
    if (x >= (box.left + box.right) / 2) slot = i + 1;
    else break;
  }
  return slot;
}

/** Slot for a click at (x, y) after the selection has landed, or null. */
function clickSlot(view: EditorView, x: number, y: number): number | null {
  const info = caretSlots(view.state);
  if (!info || info.at.length === 0) return null;
  const boxes: WidgetBox[] = [];
  for (const el of view.dom.querySelectorAll<HTMLElement>('.lp-marker')) {
    if (!['heading', 'quote', 'mark-open', 'mark-close'].includes(el.dataset.lpKind ?? '')) continue;
    let pos: number;
    try {
      pos = view.posAtDOM(el, 0);
    } catch {
      continue;
    }
    if (pos !== info.pos) continue;
    const r = el.getBoundingClientRect();
    if (y < r.top - 2 || y > r.bottom + 2) continue;
    boxes.push({ left: r.left, right: r.right });
  }
  const slot = slotFromClick(info.at, boxes, x);
  return slot == null || slot === info.natural ? null : slot;
}

/** Keys that wrap a selection in markdown, as Obsidian's "Auto pair Markdown syntax" does. */
const WRAP_KEYS = new Set(['*', '_', '~', '=']);

/** True when every text node in from..to carries `type`. */
function allHave(state: EditorState, from: number, to: number, type: MarkType): boolean {
  let all = true;
  let any = false;
  state.doc.nodesBetween(from, to, (node) => {
    if (!node.isText) return true;
    any = true;
    if (!type.isInSet(node.marks)) all = false;
    return all;
  });
  return any && all;
}

/**
 * `*` / `_` / `~` / `=` typed over a selection inside one line wraps it the
 * way Obsidian does, as marks: `*` makes it italic, a second `*` bold, a
 * third bold and italic; `~` strikes it, `=` highlights it. The selection
 * stays, so the next key can wrap again. Not in code.
 */
export function wrapSelection(view: EditorView, key: string): boolean {
  const state = view.state;
  const sel = state.selection;
  if (!(sel instanceof TextSelection) || sel.empty) return false;
  const { $from, $to, from, to } = sel;
  if (!$from.sameParent($to) || !$from.parent.isTextblock || $from.parent.type.spec.code) return false;
  const marks = state.schema.marks;
  const tr = state.tr;
  const allow = (t: MarkType | undefined): t is MarkType => !!t && $from.parent.type.allowsMarkType(t);
  if (key === '*' || key === '_') {
    const em = marks.emphasis;
    const strong = marks.strong;
    if (!allow(em) || !allow(strong)) return false;
    const hasEm = allHave(state, from, to, em);
    const hasStrong = allHave(state, from, to, strong);
    if (hasEm && hasStrong) return true;
    if (hasStrong) {
      tr.addMark(from, to, em.create({ marker: key }));
    } else if (hasEm) {
      tr.removeMark(from, to, em).addMark(from, to, strong.create({ marker: key }));
    } else {
      tr.addMark(from, to, em.create({ marker: key }));
    }
  } else {
    const type = key === '~' ? marks.strike_through : marks.highlight;
    if (!allow(type)) return false;
    if (allHave(state, from, to, type)) return true;
    tr.addMark(from, to, type.create());
  }
  view.dispatch(tr.scrollIntoView());
  return true;
}

/** Raw ProseMirror plugin (exported for tests on a bare EditorView). */
export function createLivePreviewProsePlugin(opts: LivePreviewOptions = {}): Plugin<LivePreviewState> {
  // Per-view flags: this plugin instance belongs to one editor. While an IME
  // composition or a mouse drag is running the decorations are mapped, not
  // rebuilt: inserting a widget at the anchor of a drag selection (or next to
  // the text being composed) makes the browser drop that selection.
  let composing = false;
  let dragging = false;
  // An arrow key the browser is about to carry out: the caret lands in the
  // first slot when it came from the left, the last when from the right.
  let arrival: { dir: 'left' | 'right'; at: number } | null = null;
  // A paste is landing: the next document change gets `==` converted.
  let pasting = 0;

  function handleKey(view: EditorView, event: KeyboardEvent): boolean {
    if (livePreviewKey.getState(view.state)?.style !== 'live') return false;
    if (event.isComposing || event.keyCode === 229 || composing) return false;
    if (event.ctrlKey || event.metaKey || event.altKey) return false;
    const key = event.key;
    if (WRAP_KEYS.has(key) && !view.state.selection.empty) {
      if (wrapSelection(view, key)) {
        event.preventDefault();
        return true;
      }
      return false;
    }
    if (event.shiftKey && key !== '#') return false;
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'Backspace', 'Delete', '#'].includes(key)) return false;
    const info = caretSlots(view.state);
    if (!info) return false;
    const { at, slot } = info;
    const $pos = view.state.selection.$from;
    const lineStart = $pos.parent.isTextblock && $pos.parentOffset === 0;
    const setSlot = (next: number) => {
      view.dispatch(slotTransaction(view.state, next));
      event.preventDefault();
      return true;
    };

    switch (key) {
      case 'ArrowRight':
        if (slot < at.length) return setSlot(slot + 1);
        arrival = { dir: 'left', at: Date.now() };
        return false;
      case 'ArrowLeft':
        if (slot > 0) return setSlot(slot - 1);
        arrival = { dir: 'right', at: Date.now() };
        return false;
      case 'Home':
        if (lineStart && slot > 0) return setSlot(0);
        return false;
      case 'Backspace': {
        if (slot > 0) {
          if (undoMarker(view, at[slot - 1]!, 'backward')) {
            event.preventDefault();
            return true;
          }
          return false;
        }
        if (lineStart && at.length > 0) {
          // In front of the line's markers: join with the line above.
          (joinBackward as Cmd)(view.state, (tr) => view.dispatch(tr.scrollIntoView()), view);
          event.preventDefault();
          return true;
        }
        if (lineStart && deleteEmptyLine(view)) {
          event.preventDefault();
          return true;
        }
        return false;
      }
      case 'Delete': {
        if (slot < at.length) {
          if (undoMarker(view, at[slot]!, 'forward')) {
            event.preventDefault();
            return true;
          }
          return false;
        }
        if (lineStart && $pos.parent.content.size > 0) {
          // The commonmark keymap treats Delete at the start of a heading or
          // list item like Backspace; in a text editor it deletes forward.
          event.preventDefault();
          return deleteForward(view);
        }
        return false;
      }
      case '#': {
        const next = at[slot];
        if (next?.kind !== 'heading') return false;
        const block = $pos.parent;
        const level = Number(block.attrs.level) || 1;
        event.preventDefault();
        if (level < 6) {
          const tr = view.state.tr.setNodeMarkup($pos.before(), undefined, { ...block.attrs, level: level + 1 });
          // Keep the caret in front of the hashes.
          view.dispatch(tr.setMeta(livePreviewKey, { slot }));
        }
        return true;
      }
    }
    return false;
  }

  return new Plugin<LivePreviewState>({
    key: livePreviewKey,
    state: {
      init: (_config, state) => {
        const style = opts.initialStyle ?? getEditorStyle();
        const focused = opts.initialFocused ?? false;
        const source = opts.initialSource ?? isSourceMode();
        return { style, focused, engaged: focused, slot: null, source, decorations: compute(state, style, focused, null, source) };
      },
      apply(tr: Transaction, prev: LivePreviewState, _old: EditorState, next: EditorState): LivePreviewState {
        const meta = tr.getMeta(livePreviewKey) as LivePreviewMeta | undefined;
        const style = meta?.style ?? prev.style;
        const focused = meta?.focused ?? prev.focused;
        const source = meta?.source ?? prev.source;
        const engaged = prev.engaged || focused;
        let slot = prev.slot;
        if (meta && 'slot' in meta) {
          slot = meta.slot ?? null;
        } else if (tr.docChanged || tr.selectionSet) {
          slot = null;
          const arrived = arrival;
          arrival = null;
          if (arrived && Date.now() - arrived.at < 500 && !tr.docChanged && next.selection.empty) {
            slot = arrived.dir === 'left' ? 0 : Number.MAX_SAFE_INTEGER;
          }
        }
        if (!meta && !tr.docChanged && !tr.selectionSet) return prev;
        const frozen = (composing || dragging) && !meta?.refresh && !meta?.style && meta?.source === undefined;
        if (frozen) {
          return { style, focused, engaged, slot, source, decorations: prev.decorations.map(tr.mapping, tr.doc) };
        }
        return { style, focused, engaged, slot, source, decorations: compute(next, style, engaged, slot, source) };
      },
    },
    appendTransaction(trs, _old, state) {
      const ps = livePreviewKey.getState(state);
      if (!ps || ps.style !== 'live') return null;
      // A paste just landed: `==text==` in what it inserted becomes a highlight.
      if (pasting && trs.some((t) => t.docChanged)) {
        pasting = 0;
        const type = state.schema.marks.highlight;
        if (!type) return null;
        let from = Infinity;
        let to = -Infinity;
        for (const t of trs) {
          for (const map of t.mapping.maps) {
            map.forEach((_a, _b, start, end) => {
              from = Math.min(from, start);
              to = Math.max(to, end);
            });
          }
        }
        if (from > to) return null;
        const tr = state.tr;
        const range = { from: Math.max(0, from), to: Math.min(state.doc.content.size, to) };
        return convertHighlightSyntax(tr, range.from, range.to, type) > 0 ? tr : null;
      }
      // The caret moved: make what typing picks up match the slot it is
      // drawn in (an arrow key that carried it into a new slot, or a caret
      // at the start of a line in front of `**bold**`, where ProseMirror on
      // its own would type bold).
      if (composing || !trs.some((t) => t.selectionSet || t.docChanged)) return null;
      const lastMeta = trs[trs.length - 1]!.getMeta(livePreviewKey) as LivePreviewMeta | undefined;
      if (lastMeta && 'slot' in lastMeta) return null;
      const info = caretSlots(state);
      if (!info || info.at.length === 0) return null;
      const markers = buildRevealMarkers(state.doc, { from: info.pos, to: info.pos });
      if (state.storedMarks) {
        // Someone chose the marks on purpose (the `**bold**` input rule
        // leaves the caret outside the bold it just made): keep them, and
        // draw the caret in the slot that types them.
        const stored = state.storedMarks;
        if (Mark.sameSet(slotStoredMarks(state.doc, markers, info.pos, info.slot), stored)) return null;
        for (let s = info.at.length; s >= 0; s--) {
          if (Mark.sameSet(slotStoredMarks(state.doc, markers, info.pos, s), stored)) {
            return state.tr.setMeta(livePreviewKey, { slot: s }).setMeta('addToHistory', false);
          }
        }
        return null;
      }
      const want = slotStoredMarks(state.doc, markers, info.pos, info.slot);
      const have = state.selection.$from.marks();
      if (Mark.sameSet(want, have)) return null;
      return state.tr
        .setStoredMarks(want)
        .setMeta(livePreviewKey, { slot: ps.slot })
        .setMeta('addToHistory', false);
    },
    props: {
      decorations(state) {
        return livePreviewKey.getState(state)?.decorations ?? null;
      },
      attributes(state): Record<string, string> {
        const ps = livePreviewKey.getState(state);
        if (ps?.style !== 'live') return {};
        return { class: ps.source ? 'lp-live lp-source' : 'lp-live' };
      },
      handleDOMEvents: {
        keydown(view, event) {
          return handleKey(view, event);
        },
        paste(view) {
          if (livePreviewKey.getState(view.state)?.style === 'live') {
            pasting = Date.now();
            // A paste that inserts nothing must not convert the next edit.
            setTimeout(() => {
              pasting = 0;
            }, 0);
          }
          return false;
        },
        compositionstart() {
          composing = true;
          return false;
        },
        compositionend(view) {
          composing = false;
          // Rebuild once the composed text has landed.
          setTimeout(() => dispatchMeta(view, { refresh: true }), 0);
          return false;
        },
        mousedown(view, event) {
          if (livePreviewKey.getState(view.state)?.style !== 'live') return false;
          if ((event as MouseEvent).button !== 0) return false;
          // Hold the markers still until the button comes up, then show
          // the ones for wherever the selection ended.
          dragging = true;
          const end = (up: Event) => {
            window.removeEventListener('mouseup', end, true);
            window.removeEventListener('pointerup', end, true);
            window.removeEventListener('blur', end);
            if (!dragging) return;
            dragging = false;
            const x = (up as MouseEvent).clientX;
            const y = (up as MouseEvent).clientY;
            setTimeout(() => {
              // A click among revealed markers lands on the side of each
              // marker the pointer was on, as it would in Obsidian's text.
              if ((view as unknown as { isDestroyed?: boolean }).isDestroyed) return;
              const slot = typeof x === 'number' ? clickSlot(view, x, y) : null;
              if (slot == null) dispatchMeta(view, { refresh: true });
              else view.dispatch(slotTransaction(view.state, slot));
            }, 0);
          };
          window.addEventListener('mouseup', end, true);
          window.addEventListener('pointerup', end, true);
          window.addEventListener('blur', end);
          return false;
        },
      },
    },
    view(view) {
      // focusin/focusout bubble, so focus inside a node view (a code block's
      // CodeMirror, a table input) counts as this editor having focus, and
      // leaving it from there is still seen.
      const onFocusIn = () => {
        if (!livePreviewKey.getState(view.state)?.focused) dispatchMeta(view, { focused: true });
      };
      const onFocusOut = (event: FocusEvent) => {
        const next = event.relatedTarget as Node | null;
        if (next && view.dom.contains(next)) return;
        if (livePreviewKey.getState(view.state)?.focused) dispatchMeta(view, { focused: false });
      };
      view.dom.addEventListener('focusin', onFocusIn);
      view.dom.addEventListener('focusout', onFocusOut);
      if (view.hasFocus() && !livePreviewKey.getState(view.state)?.focused) {
        queueMicrotask(() => dispatchMeta(view, { focused: true }));
      }
      const unsubscribe = subscribeEditorStyle((style) => dispatchMeta(view, { style, source: isSourceMode() }));
      // The pref may have changed between plugin init and view creation.
      if (opts.initialStyle === undefined && livePreviewKey.getState(view.state)?.style !== getEditorStyle()) {
        queueMicrotask(() => dispatchMeta(view, { style: getEditorStyle() }));
      }
      return {
        destroy() {
          unsubscribe();
          view.dom.removeEventListener('focusin', onFocusIn);
          view.dom.removeEventListener('focusout', onFocusOut);
        },
      };
    },
  });
}

/** Milkdown wrapper, `.use()`d by PageEditor. */
export const livePreviewPlugin = $prose(() => createLivePreviewProsePlugin());
