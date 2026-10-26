// ─────────────────────────────────────────────────────────────────────────
// Clicks on a block's chrome leave the caret alone.
//
// Node views draw non-text chrome inside the editor as contenteditable=false
// islands: a code block's header bar (language picker, Copy), a table's
// handles. A mousedown on the bare part of such an island is still a
// mousedown inside the contenteditable root, so the browser looks for the
// nearest editable spot and puts a blinking caret there: clicking the empty
// right half of a code block's header dropped the caret into the empty line
// above the block, nowhere near the click.
//
// This plugin cancels the browser's default for those mousedowns, so focus
// and the selection stay where they were (no caret if the editor was not
// focused). Buttons, inputs, the code block's own CodeMirror, draggable
// handles, list markers (list-item-view.ts handles those) and atom nodes
// (images, rules, page chips, which ProseMirror selects as a whole) are left
// to their usual handling.
// ─────────────────────────────────────────────────────────────────────────

import { $prose } from '@milkdown/utils';
import { Plugin, PluginKey } from '@milkdown/prose/state';
import type { EditorView } from '@milkdown/prose/view';

/** Things inside an island that take their own clicks. */
const INTERACTIVE = [
  'button',
  'a[href]',
  'input',
  'textarea',
  'select',
  'label',
  '[role="button"]',
  '[role="option"]',
  '[role="menuitem"]',
  '[draggable="true"]',
  '[contenteditable="true"]',
  '.cm-editor',
  '.label-wrapper',
].join(',');

/**
 * True when `target` is bare chrome: inside a contenteditable=false island
 * of `root` and not inside anything that takes its own clicks.
 */
export function isEditorChrome(target: EventTarget | null, root: Element): boolean {
  const el = target instanceof Element ? target : target instanceof Node ? target.parentElement : null;
  if (!el || el === root || !root.contains(el)) return false;
  const island = el.closest('[contenteditable="false"]');
  if (!island || !root.contains(island)) return false;
  const control = el.closest(INTERACTIVE);
  return !(control && island.contains(control));
}

/** The innermost node under the pointer is an atom (image, rule, chip). */
function overAtom(view: EditorView, event: MouseEvent): boolean {
  try {
    const hit = view.posAtCoords({ left: event.clientX, top: event.clientY });
    if (!hit || hit.inside < 0) return false;
    return view.state.doc.nodeAt(hit.inside)?.isAtom === true;
  } catch {
    // No layout to measure (a test DOM): nothing to tell an atom by.
    return false;
  }
}

export const editorChromeClickKey = new PluginKey('editor-chrome-click');

export function createEditorChromeClickPlugin(): Plugin {
  return new Plugin({
    key: editorChromeClickKey,
    // A plain DOM listener, not `handleDOMEvents`: a node view whose
    // `stopEvent` returns true (Crepe's code block does, for every event)
    // hides its events from ProseMirror's handlers, while the browser still
    // places the caret for them.
    view(view) {
      const onMouseDown = (event: MouseEvent) => {
        if (event.button !== 0 || event.defaultPrevented) return;
        if (!isEditorChrome(event.target, view.dom) || overAtom(view, event)) return;
        event.preventDefault();
      };
      view.dom.addEventListener('mousedown', onMouseDown);
      return {
        destroy() {
          view.dom.removeEventListener('mousedown', onMouseDown);
        },
      };
    },
  });
}

export const editorChromeClickPlugin = $prose(() => createEditorChromeClickPlugin());
