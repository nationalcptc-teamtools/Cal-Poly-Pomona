// Interface zoom: scales the whole app with CSS `zoom` on <html>, so the tiny
// fixed-px text in the rails and dialogs grows with everything else.
//
// It is a per-device setting (localStorage), not an account pref: the right
// scale depends on the screen, and a laptop and a 4K monitor want different ones.
//
// Chrome applies `zoom` to viewport units and to `position: fixed` offsets, so
// two kinds of code have to know about it:
// - viewport-relative sizes use the `--vh`/`--vw` vars from index.css (one vh
//   divided by the zoom) and the `.h-viewport`/`.w-viewport` classes, never
//   raw `vh`/`vw` or `h-screen`/`w-screen`;
// - anything that turns pointer coordinates or getBoundingClientRect values
//   (screen px) into a CSS length divides by `getUiZoom()` first (`toLayoutPx`).

export const UI_ZOOM_STEPS: readonly number[] = [0.8, 0.9, 1, 1.1, 1.25, 1.4, 1.5, 1.75, 2];
export const DEFAULT_UI_ZOOM = 1;
export const MIN_UI_ZOOM = 0.8;
export const MAX_UI_ZOOM = 2;
const STORAGE_KEY = 'btct.uiZoom';

let current = DEFAULT_UI_ZOOM;
const listeners = new Set<(zoom: number) => void>();

/** Validate a stored zoom: anything that is not one of the steps falls back to 100%. */
export function resolveUiZoom(raw: unknown): number {
  const n = typeof raw === 'string' ? Number(raw) : raw;
  return typeof n === 'number' && UI_ZOOM_STEPS.includes(n) ? n : DEFAULT_UI_ZOOM;
}

/** The next step up (dir 1) or down (dir -1) from `zoom`, clamped to the ends. */
export function stepUiZoom(zoom: number, dir: 1 | -1): number {
  const i = UI_ZOOM_STEPS.indexOf(zoom);
  if (i === -1) return DEFAULT_UI_ZOOM;
  return UI_ZOOM_STEPS[Math.min(UI_ZOOM_STEPS.length - 1, Math.max(0, i + dir))] ?? zoom;
}

export function getUiZoom(): number {
  return current;
}

/**
 * True when the browser honours CSS `zoom`. Firefox only shipped it in 126,
 * and an older ESR ignores the inline style while `toLayoutPx` and `--vh`
 * would still divide by the saved zoom, which misplaces every drag and
 * floating toolbar. Without support the zoom stays at 1 and the Profile
 * control is hidden. A runtime with no `CSS.supports` (jsdom) counts as
 * supporting it.
 */
export function uiZoomSupported(): boolean {
  if (typeof CSS === 'undefined' || typeof CSS.supports !== 'function') return true;
  try { return CSS.supports('zoom', '1.25'); } catch { return true; }
}

/** Screen px (clientX, a bounding rect) to the CSS px a style length needs. */
export function toLayoutPx(screenPx: number): number {
  return screenPx / current;
}

/** Apply a zoom to the page now, and remember it on this device when `persist`. */
export function applyUiZoom(zoom: number, persist = true): void {
  current = uiZoomSupported() ? resolveUiZoom(zoom) : DEFAULT_UI_ZOOM;
  if (typeof document !== 'undefined') {
    const root = document.documentElement;
    root.style.setProperty('--ui-zoom', String(current));
    if (current === 1) root.style.removeProperty('zoom');
    else root.style.setProperty('zoom', String(current));
  }
  if (persist) {
    try { localStorage.setItem(STORAGE_KEY, String(current)); } catch { /* private mode: still applies */ }
  }
  for (const fn of listeners) fn(current);
}

/** Apply whatever this device saved last. Call once, before the first render. */
export function restoreUiZoom(): void {
  let saved: string | null = null;
  try { saved = localStorage.getItem(STORAGE_KEY); } catch { /* ignore */ }
  applyUiZoom(resolveUiZoom(saved), false);
}

export function onUiZoomChange(fn: (zoom: number) => void): () => void {
  listeners.add(fn);
  return () => { listeners.delete(fn); };
}
