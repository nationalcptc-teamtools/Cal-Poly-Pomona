// ─────────────────────────────────────────────────────────────────────────
// Raw-Typst code editor.
//
// A CodeMirror 6 instance bound to a shared-doc Y.Text via y-codemirror.next,
// so the Typst source is collaboratively edited character-by-character (with
// remote carets) exactly like the rest of BTCT: no last-writer-wins clobber.
// Undo/redo is handled by the Yjs UndoManager that yCollab installs.
// ─────────────────────────────────────────────────────────────────────────

import { useEffect, useRef, memo } from 'react';
import * as Y from 'yjs';
import { EditorState, StateField, StateEffect, RangeSetBuilder, type Extension } from '@codemirror/state';
import {
  EditorView, lineNumbers, highlightActiveLine, highlightActiveLineGutter,
  drawSelection, keymap, Decoration, type DecorationSet,
} from '@codemirror/view';
import { defaultKeymap, indentWithTab } from '@codemirror/commands';
import { highlightSelectionMatches } from '@codemirror/search';
import { yCollab, yUndoManagerKeymap } from 'y-codemirror.next';
import { getSharedDoc } from '@/realtime/shared-doc';
import { useAuthStore } from '@/auth/auth-store';
import { typstLanguage, typstHighlightExtension } from '@/lib/typst-language';
import { codeChromeTheme } from '@/lib/code-chrome';
import { useAppStore } from '@/stores';
import { assetPath } from '@/lib/assets';
import { parseAssetLinkList } from '@/lib/asset-link';
import { ensureHelper } from '@/lib/typst-placeholders';
import { figureWidthPt } from '@/lib/typst-geometry';
import { captionFor, fitFigureHeight, slotCall } from '@/lib/typst-exploit-steps';

// Layout for the source editor. Colours (caret, selection, active line,
// gutters, search panel) come from codeChromeTheme and the token colours
// from typstHighlightExtension, the same palettes as a note's code blocks in
// both modes. The pane behind it is bg-editor.
const editorTheme = EditorView.theme({
  '&': { height: '100%', fontSize: '13px' },
  '.cm-scroller': {
    fontFamily: 'var(--font-code)',
    lineHeight: '1.6',
    overflow: 'auto',
  },
});

// ─────────────────────────────────────────────────────────────────────────
// Module-level handle on the live editor, so the assets panel can insert an
// `#image(…)` snippet at the caret without prop-drilling a ref through the
// split-pane tree. Mirrors the pattern in lib/active-editor.ts.
//
// Writes go through the CodeMirror view (not the Y.Text directly) so the
// insertion participates in the collab binding's undo history and lands
// exactly where the user's cursor is.
// ─────────────────────────────────────────────────────────────────────────
let activeView: EditorView | null = null;

/**
 * Paste of copied asset links (`btct-asset:<id>`, from Copy link on the
 * Assets tab or the report's assets rail): insert a filled figure slot per
 * image, sized to the image's shape, instead of the link text. The slot
 * helper is added to the report in the same transaction when it has none.
 * A paste of anything else, or of links to unknown assets, is left alone.
 */
export function assetLinkPaste(view: EditorView, text: string): boolean {
  const ids = parseAssetLinkList(text);
  if (!ids) return false;
  const images = useAppStore.getState().typstAssets.filter((a) => a.kind === 'image' && !a.deletedAt);
  const found = ids.map((id) => images.find((a) => a.id === id)).filter((a): a is NonNullable<typeof a> => !!a);
  if (found.length === 0) return false;
  const doc = view.state.doc.toString();
  const width = figureWidthPt(doc);
  const snippet = found
    .map((a) => slotCall(captionFor(a.filename), assetPath(a), fitFigureHeight(a, width)))
    .join('\n');
  const { from, to } = view.state.selection.main;
  const changes: { from: number; to: number; insert: string }[] = [{ from, to, insert: snippet }];
  const ensured = ensureHelper(doc);
  if (ensured.changed) {
    // The helper edit as one minimal change: what differs between the two.
    const next = ensured.source;
    let p = 0;
    while (p < doc.length && p < next.length && doc[p] === next[p]) p++;
    let q = 0;
    while (q < doc.length - p && q < next.length - p && doc[doc.length - 1 - q] === next[next.length - 1 - q]) q++;
    const helper = { from: p, to: doc.length - q, insert: next.slice(p, next.length - q) };
    if (helper.to <= from || helper.from >= to) changes.push(helper);
  }
  const set = view.state.changes(changes);
  view.dispatch({ changes: set, selection: { anchor: set.mapPos(to, 1) }, scrollIntoView: true });
  return true;
}

// ─────────────────────────────────────────────────────────────────────────
// Finding focus: a purely visual spotlight on one finding block. Lines
// inside the range keep their colour and gain an accent bar; every other
// line is dimmed. This is decoration only (invariant #33's spirit): it
// dispatches an effect, never a document change, so the Yjs binding, undo
// and every collaborator's view are untouched.
// ─────────────────────────────────────────────────────────────────────────
const setFocusEffect = StateEffect.define<{ from: number; to: number } | null>();
const dimMark = Decoration.line({ attributes: { class: 'cm-finding-dim' } });
const focusMark = Decoration.line({ attributes: { class: 'cm-finding-focus' } });

const focusField = StateField.define<DecorationSet>({
  create: () => Decoration.none,
  update(deco, tr) {
    let range: { from: number; to: number } | null | undefined;
    for (const e of tr.effects) if (e.is(setFocusEffect)) range = e.value;
    if (range === undefined) return tr.docChanged ? deco.map(tr.changes) : deco;
    if (range === null) return Decoration.none;
    const builder = new RangeSetBuilder<Decoration>();
    const { from, to } = range;
    for (let pos = 0; pos <= tr.state.doc.length; ) {
      const line = tr.state.doc.lineAt(pos);
      const inside = line.to >= from && line.from <= to;
      builder.add(line.from, line.from, inside ? focusMark : dimMark);
      pos = line.to + 1;
    }
    return builder.finish();
  },
  provide: (f) => EditorView.decorations.from(f),
});

const focusTheme = EditorView.baseTheme({
  '.cm-finding-dim': { opacity: '0.32' },
  '.cm-finding-focus': { boxShadow: 'inset 2px 0 0 0 var(--cm-focus-bar, currentColor)' },
});

const findingFocusExtension: Extension = [focusField, focusTheme];

/**
 * Spotlight the block at `[from, to)` (dim the rest and scroll it in), or
 * clear the spotlight with `null`. Returns false when no editor is mounted.
 */
export function setTypstFindingFocus(range: { from: number; to: number } | null): boolean {
  const view = activeView;
  if (!view) return false;
  const max = view.state.doc.length;
  if (range) {
    const anchor = Math.min(Math.max(range.from, 0), max);
    view.dispatch({
      effects: [setFocusEffect.of(range), EditorView.scrollIntoView(anchor, { y: 'start', yMargin: 40 })],
      selection: { anchor },
    });
  } else {
    view.dispatch({ effects: setFocusEffect.of(null) });
  }
  return true;
}

/**
 * Select `[from, to)` and scroll it into view: the landing action for
 * click-to-source from the rendered preview.
 *
 * Centers the target rather than scrolling it to the top edge, so the
 * surrounding context stays visible. Returns false when no editor is mounted.
 *
 * `focus` defaults to true (a preview click wants the caret in the editor to
 * type immediately). The search panel passes `false` so focus stays in its
 * input, letting `Enter`/`Shift+Enter` keep stepping through matches instead of
 * being swallowed by the editor.
 */
export function revealTypstRange(from: number, to: number, focus = true): boolean {
  const view = activeView;
  if (!view) return false;
  const max = view.state.doc.length;
  const anchor = Math.min(Math.max(from, 0), max);
  const head = Math.min(Math.max(to, 0), max);
  view.dispatch({
    selection: { anchor, head },
    effects: EditorView.scrollIntoView(anchor, { y: 'center' }),
  });
  if (focus) view.focus();
  return true;
}

/**
 * The current caret offset, so the search panel can start "find next" from
 * where the user actually is rather than the top of the document. Returns 0
 * when no editor is mounted.
 */
export function getTypstCaret(): number {
  return activeView?.state.selection.main.head ?? 0;
}

// Bridge for the in-editor Ctrl/⌘+F: CodeMirror's key handler runs inside the
// view, but the search *panel* is React state owned by TypstView. The view
// calls this to ask the tab to open (and focus) the panel. Registered while
// the tab is mounted; a no-op otherwise.
let onSearchRequest: (() => void) | null = null;
export function setTypstSearchRequest(fn: (() => void) | null): void {
  onSearchRequest = fn;
}

/**
 * Insert `text` at the caret, replacing any selection. Returns false when no
 * Typst editor is mounted (the code pane is hidden), so callers can fall
 * back to copying the snippet instead.
 */
export function insertAtTypstCursor(text: string): boolean {
  const view = activeView;
  if (!view) return false;
  const { from, to } = view.state.selection.main;
  view.dispatch({
    changes: { from, to, insert: text },
    selection: { anchor: from + text.length },
    scrollIntoView: true,
  });
  view.focus();
  return true;
}

// Memoized: `ytext` is stable for the document's lifetime, so the CodeMirror
// instance never re-renders due to parent state changes (e.g. the divider
// drag updating the width, or the source mirror updating on each keystroke).
export const TypstEditor = memo(function TypstEditor({ ytext }: { ytext: Y.Text }) {
  const hostRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    // Share the same awareness used for the shared doc so remote carets and
    // name tags appear; advertise this user's presence for the labels.
    const awareness = getSharedDoc().provider.awareness;
    const user = useAuthStore.getState().user;
    if (user) {
      // Same shape as applyAwarenessUser in yjs-providers.ts: dropping `id`
      // here removed the user from every teammate's presence roster.
      awareness.setLocalStateField('user', { id: user.id, name: user.username, color: user.color });
    }

    const undoManager = new Y.UndoManager(ytext);

    const view = new EditorView({
      parent: host,
      state: EditorState.create({
        doc: ytext.toString(),
        extensions: [
          lineNumbers(),
          highlightActiveLineGutter(),
          highlightActiveLine(),
          drawSelection(),
          EditorView.lineWrapping,
          EditorState.tabSize.of(2),
          typstLanguage(),
          typstHighlightExtension,
          codeChromeTheme,
          editorTheme,
          findingFocusExtension,
          // Still highlight other occurrences of the current selection.
          highlightSelectionMatches(),
          // Ctrl/⌘+F opens BTCT's own whole-document search panel (see
          // TypstSearchPanel) instead of CodeMirror's built-in, whose match
          // decorations only cover the rendered viewport. This binding sits
          // before defaultKeymap so it wins, and returns true to swallow the
          // browser's native find.
          keymap.of([
            { key: 'Mod-f', preventDefault: true, run: () => { onSearchRequest?.(); return true; } },
            ...yUndoManagerKeymap,
            ...defaultKeymap,
            indentWithTab,
          ]),
          EditorView.domEventHandlers({
            paste(event, v) {
              const text = event.clipboardData?.getData('text/plain') ?? '';
              if (!assetLinkPaste(v, text)) return false;
              event.preventDefault();
              return true;
            },
          }),
          // Binds the editor doc to the Y.Text (source of truth) + remote carets.
          yCollab(ytext, awareness, { undoManager }),
        ],
      }),
    });

    activeView = view;

    return () => {
      // Only clear if we're still the active view: guards against a
      // remount ordering where the new instance registers before this
      // cleanup runs, which would otherwise null out the live editor.
      if (activeView === view) activeView = null;
      view.destroy();
      undoManager.destroy();
    };
  }, [ytext]);

  return <div ref={hostRef} className="h-full w-full overflow-hidden bg-editor" />;
});
