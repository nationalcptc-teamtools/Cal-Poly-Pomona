// ─────────────────────────────────────────────────────────────────────────
// Inline link editing (Notion-style).
//
// Crepe ships a link tooltip component with an inline "Paste link..." input
// anchored at the selection. Its API lives in a Milkdown ctx slice named
// `linkTooltipAPICtx`. We look the slice up by that name because the client
// doesn't depend on `@milkdown/components` directly (it arrives via Crepe),
// and a name lookup always resolves to the instance Crepe registered.
//
// `openLinkEditor` replaces the old `window.prompt('Link URL')` flow: the
// link button / Mod+K / the link keybind now open the same inline input a
// user gets when editing an existing link, which is how Notion behaves.
// Toggle semantics match Crepe's own toolbar: a selection that is already
// entirely a link gets the link removed instead.
// ─────────────────────────────────────────────────────────────────────────

import { editorViewCtx, type Editor } from '@milkdown/core';

interface LinkTooltipAPILike {
  addLink: (from: number, to: number) => void;
  removeLink: (from: number, to: number) => void;
}

/**
 * Open the inline link editor on the current selection (or unlink it when
 * the whole selection is already linked). No-op on an empty selection.
 * Returns true when it acted.
 */
export function openLinkEditor(editor: Editor): boolean {
  let acted = false;
  try {
    editor.action((ctx) => {
      const view = ctx.get(editorViewCtx);
      const { state } = view;
      const { from, to, empty } = state.selection;
      if (empty) return;
      const linkType = state.schema.marks['link'];
      if (!linkType) return;
      const api = ctx.get('linkTooltipAPICtx') as LinkTooltipAPILike;
      if (state.doc.rangeHasMark(from, to, linkType)) {
        api.removeLink(from, to);
      } else {
        api.addLink(from, to);
      }
      acted = true;
    });
  } catch {
    // Editor mid-teardown or the tooltip feature absent: quietly do nothing.
    return false;
  }
  return acted;
}
