// ─────────────────────────────────────────────────────────────────────────
// Module-level references to mounted Milkdown editors.
//
// `active` is the most recently focused (or, failing that, mounted) editor,
// for global keyboard
// handlers (e.g. Ctrl+K for link insertion in `App.tsx`) that dispatch
// commands without prop-drilling. The per-page registry lets the version
// history restore a page through its live ProseMirror view (a forward edit
// that the collab binding turns into a minimal Yjs delta) instead of
// rewriting the Y.Doc underneath everyone's cursors.
// ─────────────────────────────────────────────────────────────────────────

import type { Editor } from '@milkdown/core';

let active: Editor | null = null;
const byPage = new Map<string, Editor>();

export function setActiveMilkdownEditor(editor: Editor | null): void {
  active = editor;
}

/**
 * An editor is going away: forget it only if it is still the active one (a
 * newer editor may have taken over meanwhile), and fall back to the most
 * recently registered page editor that is still mounted, so keybinds keep
 * working in the remaining pane of a split.
 */
export function clearActiveMilkdownEditor(editor: Editor): void {
  if (active !== editor) return;
  let fallback: Editor | null = null;
  for (const e of byPage.values()) if (e !== editor) fallback = e;
  active = fallback;
}

export function getActiveMilkdownEditor(): Editor | null {
  return active;
}

export function registerPageEditor(pageId: string, editor: Editor): void {
  byPage.set(pageId, editor);
}

export function unregisterPageEditor(pageId: string, editor: Editor): void {
  if (byPage.get(pageId) === editor) byPage.delete(pageId);
}

/** The mounted editor for a page, if that page is open in a tab. */
export function getPageEditor(pageId: string): Editor | null {
  return byPage.get(pageId) ?? null;
}

/**
 * True if there is a non-empty selection inside any element matching the
 * Milkdown ProseMirror host. Used to decide whether the global Ctrl+K
 * binding should open the link prompt instead of the command palette.
 */
export function hasMilkdownSelection(): boolean {
  if (typeof window === 'undefined') return false;
  const sel = window.getSelection();
  if (!sel || sel.isCollapsed || sel.rangeCount === 0) return false;
  const anchor = sel.anchorNode;
  const el = anchor && anchor.nodeType === Node.ELEMENT_NODE
    ? (anchor as Element)
    : anchor?.parentElement;
  if (!el) return false;
  // The read-only version viewer is a ProseMirror too, but not an editor:
  // Ctrl+K there should reach the command palette.
  if (el.closest('.history-viewer')) return false;
  return !!el.closest('.milkdown-host .ProseMirror');
}
