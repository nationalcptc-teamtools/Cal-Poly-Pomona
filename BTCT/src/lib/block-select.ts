// ─────────────────────────────────────────────────────────────────────────
// Notion-style block selection.
//
// Press Escape ONCE while editing to leave text mode and select the block the
// caret is in (paragraphs, headings, code blocks, lists, quotes, …). Then:
//
//   ↑ / ↓            move the single-block selection
//   Shift+↑ / ↓      extend the selection across multiple blocks
//   Ctrl/⌘+Shift+↑/↓ move the selected block(s) up / down
//   Ctrl/⌘+D         duplicate the selected block(s), selecting the copy
//   Backspace/Del    delete the selected block(s); caret lands where they were
//   Enter            drop the caret INTO the selected block and edit it
//   Esc              leave block mode and restore the caret to where it started
//   click            leave block-selection mode
//   Ctrl/⌘+A         select every block
//
// While still editing text, Ctrl/⌘+A ladders the Notion way: the first press
// selects the current block's text, the second selects the block itself
// (entering this mode), and the third selects every block. Ctrl/⌘+Shift+↑/↓
// also work in text mode, moving the top-level block the caret sits in.
//
// Selection lives in this plugin's own state (not ProseMirror's) and is drawn
// with node decorations, so it can span several top-level blocks at once. The
// caret position the user started from is remembered (state `saved`) so a plain
// Escape puts the cursor back exactly where it was, while Enter instead drops
// into the block you highlighted, and Delete leaves the caret at the deletion.
//
// A single Escape enters the mode (matching Notion's "Esc selects the current
// block" and the single-Esc behavior inside code blocks). An open Crepe popup
// (slash menu, link / latex / table tooltip) always wins the Escape: there
// the key should dismiss the popup, so we bail without entering.
//
// Keyboard handling runs in a *capture-phase* listener on `document`
// (`view()` below) rather than ProseMirror's `handleKeyDown`. Capture phase
// guarantees the Escape and the in-mode navigation keys are seen BEFORE any
// other ProseMirror plugin or Crepe feature (slash menu, tooltips, base keymap)
// can swallow them, which is what made the feature silently fail when those ran
// first.
//
// Listening on `document` (not the editor's own `.ProseMirror`) makes the
// feature *focus-independent*: a `.ProseMirror` listener only fires while the
// prose has DOM focus, but the editor is NOT auto-focused when a page opens,
// and focus is often on the title field or a button instead, so Esc did
// nothing until you first clicked into the text. The document listener lets the
// active, on-screen page editor enter block mode even when the caret isn't in
// the prose yet, while still refusing to hijack typing in another field/editor
// (see the `inThisEditor` gate). Keys originating inside a CodeMirror code
// block are ignored here; the code-block Esc is bridged separately via
// `selectBlockAt` (see editor-keybinds.ts).
// ─────────────────────────────────────────────────────────────────────────

import {
  Plugin,
  PluginKey,
  Selection,
  TextSelection,
  type EditorState,
  type Transaction,
} from '@milkdown/prose/state';
import type { Node as ProseNode, Slice } from '@milkdown/prose/model';
import { Decoration, DecorationSet, type EditorView } from '@milkdown/prose/view';
import { $prose } from '@milkdown/utils';
import { serializerCtx } from '@milkdown/core';
import { isLivePreview } from '@/components/editor/live-preview/editor-style';

interface BlockSelState {
  active: boolean;
  anchor: number; // top-level block index
  head: number;   // top-level block index
  /**
   * The text selection the caret sat at *before* block mode was entered, so
   * exiting with Escape can put the cursor back exactly where it was. `null`
   * when not in block mode. Doc positions stay valid while active because any
   * real doc change drops us out of the mode (see `state.apply`).
   */
  saved: { from: number; to: number } | null;
}

const KEY = new PluginKey<BlockSelState>('milkdown-block-select');
const INACTIVE: BlockSelState = { active: false, anchor: 0, head: 0, saved: null };

// The editor that should answer a *focus-independent* Escape (one fired while
// the caret isn't in any prose). Set when an editor mounts and whenever it's
// focused, so the most-recently-touched / only on-screen page editor wins.
// Without this, split-pane editors would all react to one stray Esc.
let primaryView: EditorView | null = null;

/** Test-only: reset cross-keydown state so it can't leak across cases. */
export function __resetBlockSelectForTests(): void {
  primaryView = null;
}

// Crepe renders its popups (slash menu, link / latex / table tooltips) with a
// `data-show="true"` attribute while they're open. When one is open an Escape
// should dismiss IT, not grab a block, so block selection bails and lets the
// key propagate to the popup's own handler. Nothing else in the app uses
// `data-show`, so this is an unambiguous "a Crepe popup is open" signal.
function crepePopupOpen(): boolean {
  if (typeof document === 'undefined') return false;
  return !!document.querySelector('[data-show="true"]');
}

interface BlockInfo { from: number; to: number }

function topBlocks(doc: ProseNode): BlockInfo[] {
  const blocks: BlockInfo[] = [];
  doc.forEach((node, offset) => {
    blocks.push({ from: offset, to: offset + node.nodeSize });
  });
  return blocks;
}

function blockIndexAt(blocks: BlockInfo[], pos: number): number {
  for (let i = 0; i < blocks.length; i++) {
    if (pos >= blocks[i]!.from && pos < blocks[i]!.to) return i;
  }
  return Math.max(0, blocks.length - 1);
}

/**
 * Pure arrow-key navigation math. Given the current selection (anchor/head
 * block indices), the arrow pressed, and whether Shift is held, return the
 * next selection. Exported for unit testing.
 *
 *   • plain ↑/↓  collapse to a single block one step up/down from the current
 *     selection edge.
 *   • Shift+↑/↓  keep the anchor and move the head, extending the range.
 */
export function stepBlockSelection(
  s: { anchor: number; head: number },
  key: 'ArrowUp' | 'ArrowDown',
  shift: boolean,
  blockCount: number,
): { anchor: number; head: number } {
  const lo = Math.min(s.anchor, s.head);
  const hi = Math.max(s.anchor, s.head);
  if (key === 'ArrowDown') {
    if (shift) return { anchor: s.anchor, head: Math.min(s.head + 1, blockCount - 1) };
    const n = Math.min(hi + 1, blockCount - 1);
    return { anchor: n, head: n };
  }
  if (shift) return { anchor: s.anchor, head: Math.max(s.head - 1, 0) };
  const n = Math.max(lo - 1, 0);
  return { anchor: n, head: n };
}

/**
 * Build the transaction that moves the top-level blocks `lo..hi` one step up
 * (`dir` = -1) or down (`dir` = 1), swapping places with the neighbouring
 * block. Returns the transaction plus `delta`, the signed distance every
 * position inside the moved span travels (so callers can re-derive a caret
 * or the new block indices). Null when the move would fall off either end.
 * Exported for unit testing.
 */
export function moveBlocksTr(
  state: EditorState,
  lo: number,
  hi: number,
  dir: -1 | 1,
): { tr: Transaction; delta: number } | null {
  const blocks = topBlocks(state.doc);
  if (lo < 0 || hi >= blocks.length || lo > hi) return null;
  if (dir === -1 && lo === 0) return null;
  if (dir === 1 && hi === blocks.length - 1) return null;
  const from = blocks[lo]!.from;
  const to = blocks[hi]!.to;
  const slice = state.doc.slice(from, to);
  const insertPos =
    dir === -1 ? blocks[lo - 1]!.from : blocks[hi + 1]!.to - (to - from);
  const tr = state.tr.delete(from, to);
  tr.insert(insertPos, slice.content);
  return { tr, delta: insertPos - from };
}

/**
 * Programmatically enter block-selection mode with the top-level block that
 * contains `pos` selected. Used to bridge an Escape from *inside* a code
 * block (whose CodeMirror swallows keys) into ProseMirror block selection.
 *
 * The caret is parked in an adjacent block (never inside the target) because
 * a code-block node-view pulls focus back into CodeMirror whenever the
 * selection lands inside it, which would stop arrow/Delete keys from ever
 * reaching this plugin.
 */
export function selectBlockAt(view: EditorView, pos: number): boolean {
  // Live preview style has no block selection (Esc in a code block stays put).
  if (isLivePreview()) return false;
  const blocks = topBlocks(view.state.doc);
  if (blocks.length === 0) return false;
  // Remember where the caret was so an Escape exit can restore it.
  const original = view.state.selection;
  const idx = blockIndexAt(blocks, pos);
  const block = blocks[idx]!;
  const docSize = view.state.doc.content.size;
  // Prefer a caret just after the block, else just before it.
  const caret = block.to < docSize ? block.to : block.from > 0 ? block.from - 1 : block.from;
  const sel = Selection.near(view.state.doc.resolve(Math.max(0, Math.min(caret, docSize))));
  view.dispatch(
    view.state.tr.setSelection(sel).setMeta(KEY, {
      active: true,
      anchor: idx,
      head: idx,
      saved: { from: original.from, to: original.to },
    }),
  );
  view.focus();
  return true;
}

/**
 * Serialize the top-level blocks `lo..hi` to markdown, wrapping them in a
 * throwaway doc node so a fenced code block keeps its ``` fences. Returns null
 * on any failure so callers fall back to ProseMirror's plain-text extraction.
 */
function blocksToMarkdown(
  view: EditorView,
  from: number,
  to: number,
  serialize: (node: ProseNode) => string,
): string | null {
  try {
    const slice = view.state.doc.slice(from, to);
    const docNode = view.state.schema.topNodeType.create(null, slice.content);
    const md = serialize(docNode);
    return typeof md === 'string' ? md.replace(/\s+$/, '') : null;
  } catch {
    return null;
  }
}

/**
 * Write the selected block(s) to the clipboard as BOTH rich HTML (so a paste
 * back into this or another rich editor re-creates the block, code box and
 * all) and markdown text (so a paste into a terminal, chat or plain editor
 * keeps the ``` fences instead of dropping the code out of its box).
 *
 * Needed because block-selection lives in this plugin's own state, not
 * ProseMirror's: the real selection is a collapsed caret, so the browser's
 * native copy would grab nothing. We build the slice from the selected block
 * range and populate the clipboard ourselves.
 */
function copySelectedBlocks(
  view: EditorView,
  s: BlockSelState,
  event: ClipboardEvent,
  cut: boolean,
  serialize?: (node: ProseNode) => string,
): boolean {
  const data = event.clipboardData;
  if (!data) return false;
  const blocks = topBlocks(view.state.doc);
  const lo = Math.min(s.anchor, s.head);
  const hi = Math.max(s.anchor, s.head);
  if (lo < 0 || hi >= blocks.length) return false;
  const from = blocks[lo]!.from;
  const to = blocks[hi]!.to;
  const slice = view.state.doc.slice(from, to);
  const { dom, text } = view.serializeForClipboard(slice);
  const markdown = serialize ? blocksToMarkdown(view, from, to, serialize) : null;

  event.preventDefault();
  data.clearData();
  data.setData('text/html', dom.innerHTML);
  data.setData('text/plain', markdown ?? text);

  if (cut) {
    const tr = view.state.tr.delete(from, to).setMeta(KEY, INACTIVE);
    if (tr.doc.childCount === 0) {
      const para = view.state.schema.nodes.paragraph?.createAndFill();
      if (para) tr.insert(0, para);
    }
    tr.setSelection(Selection.near(tr.doc.resolve(Math.min(from, tr.doc.content.size))));
    view.dispatch(tr.scrollIntoView());
    view.focus();
  }
  return true;
}

export interface BlockSelectOptions {
  /**
   * Milkdown markdown serializer (`ctx.get(serializerCtx)`). When present, a
   * copy that includes a code block emits fenced markdown as the plain-text
   * flavour so the code box survives a paste into an external app.
   */
  serialize?: (node: ProseNode) => string;
}

/**
 * Build the raw ProseMirror plugin. Exported (separately from the Milkdown
 * `$prose` wrapper) so it can be mounted on a bare EditorView in tests.
 */
export function createBlockSelectProsePlugin(opts: BlockSelectOptions = {}): Plugin<BlockSelState> {
  const { serialize } = opts;
  return new Plugin<BlockSelState>({
    key: KEY,
    state: {
      init: () => INACTIVE,
      apply(tr, prev) {
        // Meta is applied as a patch over the previous state so navigation
        // (which only sets anchor/head) preserves `saved`, while a full reset
        // to INACTIVE clears it.
        const meta = tr.getMeta(KEY) as Partial<BlockSelState> | undefined;
        if (meta) return { ...prev, ...meta };
        // Any real document change (typing, remote collab edit) drops us back
        // to normal editing.
        if (prev.active && tr.docChanged) return INACTIVE;
        return prev;
      },
    },
    props: {
      attributes(state): Record<string, string> {
        const s = KEY.getState(state);
        return s?.active ? { class: 'block-select-mode' } : {};
      },

      decorations(state) {
        const s = KEY.getState(state);
        if (!s?.active) return null;
        const blocks = topBlocks(state.doc);
        const lo = Math.min(s.anchor, s.head);
        const hi = Math.max(s.anchor, s.head);
        const decos: Decoration[] = [];
        for (let i = lo; i <= hi && i < blocks.length; i++) {
          decos.push(
            Decoration.node(blocks[i]!.from, blocks[i]!.to, { class: 'pm-block-selected' }),
          );
        }
        return DecorationSet.create(state.doc, decos);
      },

      handleDOMEvents: {
        // A mouse click returns to normal text editing.
        mousedown(view) {
          if (KEY.getState(view.state)?.active) {
            view.dispatch(view.state.tr.setMeta(KEY, INACTIVE));
          }
          return false;
        },
      },

      // Plain-text flavour of any copy that includes a code block: emit fenced
      // markdown so pasting into a terminal / chat keeps the code box, instead
      // of ProseMirror's default that drops the fences. Non-code copies fall
      // through to the default text extraction unchanged. (Block-selection
      // copies are handled directly in `view()` and never reach here.)
      clipboardTextSerializer: (slice: Slice) => {
        const fallback = () => slice.content.textBetween(0, slice.content.size, '\n\n');
        if (!serialize) return fallback();
        let hasCode = false;
        slice.content.descendants((n) => {
          if (n.type.name === 'code_block') hasCode = true;
        });
        if (!hasCode) return fallback();
        try {
          const first = slice.content.firstChild;
          if (!first) return fallback();
          const docNode = first.type.schema.topNodeType.create(null, slice.content);
          const md = serialize(docNode).replace(/\s+$/, '');
          return md || fallback();
        } catch {
          return fallback();
        }
      },
    },

    // Capture-phase keyboard handling: beats every bubble-phase handler.
    view(view) {
      // Claim "primary" on mount and on focus so a focus-independent Esc-Esc is
      // routed to the editor the user last touched / the only one on screen.
      const claimPrimary = () => { primaryView = view; };
      claimPrimary();
      view.dom.addEventListener('focusin', claimPrimary);

      // Copy / cut while a block (or a run of blocks) is selected. Capture
      // phase so we populate the clipboard before ProseMirror's own handler,
      // which would otherwise copy the collapsed caret (i.e. nothing).
      const onClip = (cut: boolean) => (event: ClipboardEvent) => {
        const s = KEY.getState(view.state);
        if (!s?.active) return;
        if (copySelectedBlocks(view, s, event, cut, serialize)) {
          event.stopImmediatePropagation();
        }
      };
      const onCopy = onClip(false);
      const onCut = onClip(true);
      view.dom.addEventListener('copy', onCopy, true);
      view.dom.addEventListener('cut', onCut, true);

      const onKeyDown = (event: KeyboardEvent) => {
        // Keystrokes inside a code block belong to CodeMirror (and the
        // code-block Esc path in editor-keybinds.ts).
        const target = event.target as HTMLElement | null;
        if (target?.closest?.('.cm-editor, .milkdown-code-block')) return;

        const s = KEY.getState(view.state) ?? INACTIVE;

        const modKey = event.metaKey || event.ctrlKey;
        const isSelectAll =
          modKey && !event.shiftKey && !event.altKey &&
          (event.key === 'a' || event.key === 'A');
        const isMoveCombo =
          modKey && event.shiftKey && !event.altKey &&
          (event.key === 'ArrowUp' || event.key === 'ArrowDown');

        // Fast-path bail for the common case (typing anywhere): when idle the
        // only keys that matter are Escape, the Ctrl/⌘+A ladder, and the
        // Ctrl/⌘+Shift+↑/↓ block moves.
        if (!s.active && event.key !== 'Escape' && !isSelectAll && !isMoveCombo) return;
        // Live preview (Obsidian) style: no block-selection mode. Esc and
        // Ctrl/Cmd+A stay with the browser and ProseMirror (text selection);
        // only the Ctrl/Cmd+Shift+Up/Down block move remains.
        if (!s.active && !isMoveCombo && isLivePreview()) return;

        // Does the event originate from inside THIS editor's prose? If so it's
        // the focused case and always ours. Otherwise this is a focus-
        // independent press: only the active, on-screen editor may claim it,
        // and never while the user is typing in another field/editor.
        const inThisEditor = !!target && view.dom.contains(target);
        if (!inThisEditor) {
          if (view !== primaryView) return;
          if (!view.dom.isConnected || view.dom.offsetParent === null) return;
          const active = document.activeElement as HTMLElement | null;
          const activeEditable =
            !!active &&
            (active.tagName === 'INPUT' ||
              active.tagName === 'TEXTAREA' ||
              active.tagName === 'SELECT' ||
              active.isContentEditable);
          if (activeEditable) return;
        }

        const blocks = topBlocks(view.state.doc);
        if (blocks.length === 0) return;

        // Consume the event so nothing else (PM, Crepe, browser) reacts.
        const consume = () => {
          event.preventDefault();
          event.stopPropagation();
        };

        // ── Not in block mode. ──
        if (!s.active) {
          // Ctrl/⌘+Shift+↑/↓ while editing: move the current top-level block
          // (Notion's "move selected block", available without selecting).
          if (isMoveCombo) {
            if (!inThisEditor) return;
            consume();
            const sel = view.state.selection;
            const idx = blockIndexAt(blocks, sel.from);
            const dir = event.key === 'ArrowDown' ? 1 : -1;
            const moved = moveBlocksTr(view.state, idx, idx, dir);
            if (!moved) return;
            // Keep the caret at the same spot inside the moved block.
            const size = moved.tr.doc.content.size;
            const a = Math.max(0, Math.min(sel.anchor + moved.delta, size));
            const h = Math.max(0, Math.min(sel.head + moved.delta, size));
            moved.tr.setSelection(
              TextSelection.between(moved.tr.doc.resolve(a), moved.tr.doc.resolve(h)),
            );
            view.dispatch(moved.tr.scrollIntoView());
            return;
          }

          // Ctrl/⌘+A ladder (Notion): first select the current block's text,
          // then the block itself; a third press (handled in-mode below)
          // selects every block. A selection already spanning several blocks
          // jumps straight to selecting those blocks.
          if (isSelectAll) {
            if (!inThisEditor) return;
            const sel = view.state.selection;
            const idxA = blockIndexAt(blocks, sel.from);
            const idxB = blockIndexAt(blocks, Math.max(sel.from, sel.to - 1));
            if (idxA === idxB && sel.$head.parent.isTextblock) {
              const start = sel.$head.start();
              const end = sel.$head.end();
              const covers = sel.from <= start && sel.to >= end;
              if (!covers && end > start) {
                consume();
                view.dispatch(
                  view.state.tr.setSelection(
                    TextSelection.create(view.state.doc, start, end),
                  ),
                );
                return;
              }
            }
            consume();
            view.dispatch(
              view.state.tr.setMeta(KEY, {
                active: true,
                anchor: idxA,
                head: idxB,
                saved: { from: sel.from, to: sel.to },
              }),
            );
            view.focus();
            return;
          }

          // A single Escape enters block selection (Notion: "Esc selects the
          // current block"), unless a Crepe popup owns the key: there it
          // should dismiss the popup instead.
          if (crepePopupOpen()) return;
          consume();
          const original = view.state.selection;
          const idx = blockIndexAt(blocks, original.from);
          view.dispatch(
            view.state.tr
              .setSelection(Selection.near(view.state.doc.resolve(original.from)))
              .setMeta(KEY, {
                active: true,
                anchor: idx,
                head: idx,
                saved: { from: original.from, to: original.to },
              }),
          );
          // Pull DOM focus into the editor so in-mode keys keep flowing and
          // exiting drops the caret back in the prose (matters when we entered
          // while focus was on a button / nothing).
          view.focus();
          return;
        }

        // ── In block mode. ──
        const lo = Math.min(s.anchor, s.head);
        const hi = Math.max(s.anchor, s.head);

        const select = (anchor: number, head: number) =>
          view.dispatch(view.state.tr.setMeta(KEY, { active: true, anchor, head }));

        const exit = (sel?: Selection) => {
          const tr = view.state.tr.setMeta(KEY, INACTIVE);
          if (sel) tr.setSelection(sel);
          view.dispatch(tr);
          view.focus();
        };

        switch (event.key) {
          case 'Escape': {
            consume();
            // Restore the caret to exactly where it was before block mode. Use
            // Selection.near for a collapsed caret and TextSelection.between for
            // a range so both snap to valid positions if the doc shape shifted.
            if (s.saved) {
              const size = view.state.doc.content.size;
              const from = Math.min(s.saved.from, size);
              const to = Math.min(s.saved.to, size);
              const doc = view.state.doc;
              const sel =
                from === to
                  ? Selection.near(doc.resolve(from))
                  : TextSelection.between(doc.resolve(from), doc.resolve(to));
              exit(sel);
            } else {
              exit();
            }
            return;
          }

          case 'ArrowDown':
          case 'ArrowUp': {
            consume();
            // Ctrl/⌘+Shift+↑/↓ moves the selected block(s); the selection
            // follows the blocks to their new position.
            if (isMoveCombo) {
              const dir = event.key === 'ArrowDown' ? 1 : -1;
              const moved = moveBlocksTr(view.state, lo, hi, dir);
              if (moved) {
                moved.tr.setMeta(KEY, {
                  active: true,
                  anchor: s.anchor + dir,
                  head: s.head + dir,
                });
                view.dispatch(moved.tr.scrollIntoView());
              }
              return;
            }
            const next = stepBlockSelection(s, event.key, event.shiftKey, blocks.length);
            select(next.anchor, next.head);
            return;
          }

          case 'Backspace':
          case 'Delete': {
            consume();
            const from = blocks[lo]!.from;
            const to = blocks[hi]!.to;
            const tr = view.state.tr.delete(from, to);
            tr.setMeta(KEY, INACTIVE);
            // The doc must keep at least one block.
            if (tr.doc.childCount === 0) {
              const para = view.state.schema.nodes.paragraph?.createAndFill();
              if (para) tr.insert(0, para);
            }
            const at = Math.min(from, tr.doc.content.size);
            tr.setSelection(Selection.near(tr.doc.resolve(at)));
            view.dispatch(tr.scrollIntoView());
            view.focus();
            return;
          }

          case 'Enter': {
            consume();
            const pos = Math.min(blocks[s.head]!.from + 1, view.state.doc.content.size);
            exit(Selection.near(view.state.doc.resolve(pos)));
            return;
          }

          case 'a':
          case 'A':
            if (event.metaKey || event.ctrlKey) {
              consume();
              select(0, blocks.length - 1);
              return;
            }
            consume();
            return;

          case 'd':
          case 'D':
            // Ctrl/⌘+D duplicates the selected block(s) below themselves and
            // moves the selection onto the copy (Notion's duplicate).
            if (modKey && !event.shiftKey && !event.altKey) {
              consume();
              const from = blocks[lo]!.from;
              const to = blocks[hi]!.to;
              const copy = view.state.doc.slice(from, to);
              const tr = view.state.tr.insert(to, copy.content);
              tr.setMeta(KEY, {
                active: true,
                anchor: hi + 1,
                head: hi + 1 + (hi - lo),
              });
              view.dispatch(tr.scrollIntoView());
              return;
            }
            // Plain typing is swallowed while selecting, like other letters.
            if (!event.metaKey && !event.ctrlKey && !event.altKey) consume();
            return;

          default:
            // Swallow plain typing / horizontal arrows so nothing is edited
            // while selecting, but let modifier combos (copy, devtools, …) and
            // Tab pass through untouched.
            if (
              (event.key.length === 1 || event.key === 'ArrowLeft' || event.key === 'ArrowRight') &&
              !event.metaKey && !event.ctrlKey && !event.altKey
            ) {
              consume();
            }
            return;
        }
      };

      document.addEventListener('keydown', onKeyDown, true);
      return {
        destroy() {
          document.removeEventListener('keydown', onKeyDown, true);
          view.dom.removeEventListener('focusin', claimPrimary);
          view.dom.removeEventListener('copy', onCopy, true);
          view.dom.removeEventListener('cut', onCut, true);
          if (primaryView === view) primaryView = null;
        },
      };
    },
  });
}

export const blockSelectPlugin = $prose((ctx) =>
  createBlockSelectProsePlugin({
    // Read the serializer lazily at copy time (it exists once the editor is
    // created); a bare-view test harness mounts the plugin without it.
    serialize: (node) => ctx.get(serializerCtx)(node),
  }),
);
