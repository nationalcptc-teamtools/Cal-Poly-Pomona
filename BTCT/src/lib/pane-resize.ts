// ─────────────────────────────────────────────────────────────────────────
// Width math for the Typst tab's three-pane layout (editor | preview |
// assets).
//
// The two side panes are sized in pixels and the preview takes the slack.
// Pixels rather than percentages because a side rail is a *content* width:
// you size it so the thumbnails or the code fit, and it should stay put when
// the window resizes, the way an IDE sidebar does.
//
// Pure and DOM-free so the clamping rules (the part that's easy to get
// subtly wrong when two panes fight over the same space) can be tested
// directly. The drag handling that calls into this lives in TypstView.
// ─────────────────────────────────────────────────────────────────────────

export type PaneKind = 'editor' | 'assets';

/**
 * Minimum widths. The preview's minimum is what stops a greedy drag on
 * either side rail from squeezing the rendered page to nothing.
 */
export const PANE_MIN = {
  editor: 260,
  assets: 170,
  preview: 280,
} as const;

export const PANE_DEFAULT = {
  editor: 520,
  assets: 240,
} as const;

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(Math.max(n, lo), hi);
}

/**
 * Clamp a proposed side-pane width so every *visible* pane keeps its minimum.
 *
 * `otherWidth` is the width of the opposite side pane, or 0 when it's hidden:
 * so hiding the code editor immediately lets the assets rail expand into the
 * space it freed, rather than staying bound by a pane that isn't on screen.
 *
 * When the container is too narrow to satisfy everything at once, the pane's
 * own minimum wins over the preview's. Returning something below `min` would
 * let a rail collapse to an unusable sliver with no way to drag it back.
 */
export function clampPaneWidth(
  which: PaneKind,
  proposed: number,
  containerWidth: number,
  otherWidth: number,
): number {
  const min = PANE_MIN[which];
  const max = containerWidth - otherWidth - PANE_MIN.preview;
  return clamp(proposed, min, Math.max(min, max));
}

/**
 * Re-clamp both rails after the container itself changed size (window resize,
 * sidebar toggle, pane split).
 *
 * Shrinks proportionally when the two rails together no longer fit, so a
 * narrowed window degrades gracefully instead of shoving the preview out.
 */
export function fitPanes(
  widths: { editor: number; assets: number },
  visible: { editor: boolean; assets: boolean },
  containerWidth: number,
): { editor: number; assets: number } {
  const editorVisible = visible.editor;
  const assetsVisible = visible.assets;

  let editor = editorVisible ? widths.editor : 0;
  let assets = assetsVisible ? widths.assets : 0;

  const available = containerWidth - PANE_MIN.preview;
  const used = editor + assets;

  if (used > available && used > 0) {
    // Scale both down together, then enforce each pane's own floor.
    const scale = Math.max(0, available) / used;
    if (editorVisible) editor = Math.max(PANE_MIN.editor, Math.floor(editor * scale));
    if (assetsVisible) assets = Math.max(PANE_MIN.assets, Math.floor(assets * scale));
  }

  return {
    editor: editorVisible ? editor : widths.editor,
    assets: assetsVisible ? assets : widths.assets,
  };
}

// ── persistence ──────────────────────────────────────────────────────────

const LAYOUT_KEY = 'btct.typst.layout.v1';

export interface TypstLayout {
  editor: number;
  assets: number;
  showEditor: boolean;
  showAssets: boolean;
}

export const DEFAULT_LAYOUT: TypstLayout = {
  editor: PANE_DEFAULT.editor,
  assets: PANE_DEFAULT.assets,
  showEditor: true,
  showAssets: true,
};

/** Read the persisted layout, falling back to defaults on anything unexpected. */
export function loadTypstLayout(): TypstLayout {
  try {
    const raw = localStorage.getItem(LAYOUT_KEY);
    if (!raw) return DEFAULT_LAYOUT;
    const parsed = JSON.parse(raw) as Partial<TypstLayout>;
    return {
      editor: typeof parsed.editor === 'number' && parsed.editor > 0
        ? Math.max(PANE_MIN.editor, parsed.editor)
        : DEFAULT_LAYOUT.editor,
      assets: typeof parsed.assets === 'number' && parsed.assets > 0
        ? Math.max(PANE_MIN.assets, parsed.assets)
        : DEFAULT_LAYOUT.assets,
      showEditor: typeof parsed.showEditor === 'boolean' ? parsed.showEditor : true,
      showAssets: typeof parsed.showAssets === 'boolean' ? parsed.showAssets : true,
    };
  } catch {
    return DEFAULT_LAYOUT;
  }
}

export function saveTypstLayout(layout: TypstLayout): void {
  try {
    localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout));
  } catch {
    /* private mode / quota: layout just won't persist */
  }
}
