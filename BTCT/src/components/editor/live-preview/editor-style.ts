// ─────────────────────────────────────────────────────────────────────────
// "Editor style" preference: Live preview (Obsidian) or Blocks (Notion).
//
// The pref is stored with the other per-account editor prefs
// (`prefs.editorStyle`, validated by `resolvePrefs` in lib/editor-prefs.ts
// and by the profile route in server/index.mjs). Applying it never rebuilds
// an editor (invariant #3): the choice lives in a module-level value, is
// mirrored onto `<html data-editor-style>` for the CSS that hides the Notion
// chrome, and every mounted live-preview plugin subscribes to it and
// refreshes its decorations with a meta-only transaction.
//
// This module is deliberately free of ProseMirror imports so the shell
// (App.tsx, the profile dialog, the command palette) can use it without
// pulling editor code into the entry bundle.
// ─────────────────────────────────────────────────────────────────────────

export type EditorStyle = 'live' | 'blocks';

export const EDITOR_STYLES: readonly EditorStyle[] = ['live', 'blocks'];

/** New accounts and accounts that never chose get the Obsidian-style editor. */
export const DEFAULT_EDITOR_STYLE: EditorStyle = 'live';

export const EDITOR_STYLE_LABELS: Record<EditorStyle, string> = {
  live: 'Live preview (Obsidian)',
  blocks: 'Blocks (Notion)',
};

/** Validate a stored value: anything that is not a known style is the default. */
export function resolveEditorStyle(raw: unknown): EditorStyle {
  return (EDITOR_STYLES as readonly unknown[]).includes(raw) ? (raw as EditorStyle) : DEFAULT_EDITOR_STYLE;
}

export function otherEditorStyle(style: EditorStyle): EditorStyle {
  return style === 'live' ? 'blocks' : 'live';
}

let current: EditorStyle = DEFAULT_EDITOR_STYLE;
// Source mode (Obsidian's "Toggle Live Preview/Source mode"): every line's
// markdown shows, not only the cursor line's. Per browser session, like a
// view setting, and only meaningful in the Live preview style.
let sourceMode = false;
const listeners = new Set<(style: EditorStyle) => void>();

function notify(): void {
  for (const fn of [...listeners]) {
    try {
      fn(current);
    } catch {
      /* an editor mid-teardown must not stop the others */
    }
  }
}

export function getEditorStyle(): EditorStyle {
  return current;
}

/** True while the Obsidian-style editor is the active style. */
export function isLivePreview(): boolean {
  return current === 'live';
}

/**
 * Switch the editor style everywhere, live. Writes the `<html>` attribute and
 * tells every mounted editor to recompute its decorations. A no-op when the
 * style is already active (apart from re-stamping the attribute).
 */
export function applyEditorStyle(style: EditorStyle): void {
  const next = resolveEditorStyle(style);
  if (typeof document !== 'undefined') {
    document.documentElement.setAttribute('data-editor-style', next);
  }
  if (next === current) return;
  current = next;
  notify();
}

/** True while Source mode is on (it only shows in the Live preview style). */
export function isSourceMode(): boolean {
  return sourceMode;
}

/** Turn Source mode on or off in every mounted editor, live. */
export function setSourceMode(on: boolean): void {
  if (on === sourceMode) return;
  sourceMode = on;
  notify();
}

/** Subscribe to style and Source mode changes; returns the unsubscribe function. */
export function subscribeEditorStyle(fn: (style: EditorStyle) => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/** Test helper: back to the default with no subscribers. */
export function __resetEditorStyleForTests(): void {
  current = DEFAULT_EDITOR_STYLE;
  sourceMode = false;
  listeners.clear();
  if (typeof document !== 'undefined') document.documentElement.removeAttribute('data-editor-style');
}
