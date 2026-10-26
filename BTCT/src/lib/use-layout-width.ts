import { useSyncExternalStore } from 'react';
import { onUiZoomChange, toLayoutPx } from '@/lib/ui-zoom';

/**
 * Shell breakpoints, in layout px (CSS px after the interface zoom, so a
 * 1440px window at 200% zoom lays out like a 720px one).
 *
 * - under NARROW_MAX the sidebar is an overlay drawer, a split layout shows
 *   one pane at a time with a switcher, and the properties pane overlays;
 * - from NARROW_MAX up the sidebar is docked (full or the 44px rail).
 */
export const NARROW_MAX = 900;

/** The window width in layout px. */
export function layoutWidth(): number {
  if (typeof window === 'undefined') return 1440;
  return toLayoutPx(window.innerWidth);
}

/** True when the shell should use its narrow-screen layout. */
export function isNarrowWidth(width: number): boolean {
  return width < NARROW_MAX;
}

function subscribe(onChange: () => void): () => void {
  if (typeof window === 'undefined') return () => {};
  window.addEventListener('resize', onChange);
  const offZoom = onUiZoomChange(onChange);
  return () => {
    window.removeEventListener('resize', onChange);
    offZoom();
  };
}

const narrowSnapshot = () => isNarrowWidth(layoutWidth());

/** Re-renders only when the narrow/docked decision flips, not on every resize. */
export function useNarrowLayout(): boolean {
  return useSyncExternalStore(subscribe, narrowSnapshot, () => false);
}
