/**
 * Light palette, per device. Light mode has more than one set of colours
 * (src/themes/tokens.css): Paper is the default on `:root`, the others are
 * `:root[data-light-palette="..."]:not(.dark)` blocks. The choice lives in
 * localStorage `btct.lightPalette` and is applied as the `data-light-palette`
 * attribute on <html>; the inline script in index.html applies the same key
 * before the first paint, so keep the key and the ids in step with it.
 *
 * Dark mode ignores the attribute. Like the colour mode, this is an
 * attribute change only: every colour reads a token, so nothing remounts
 * (invariant #3).
 */
export const LIGHT_PALETTES = ['paper', 'linen', 'dimmed', 'classic'] as const;
export type LightPalette = (typeof LIGHT_PALETTES)[number];

export const LIGHT_PALETTE_KEY = 'btct.lightPalette';
export const LIGHT_PALETTE_ATTR = 'data-light-palette';
export const DEFAULT_LIGHT_PALETTE: LightPalette = 'paper';

export const LIGHT_PALETTE_LABELS: Record<LightPalette, { label: string; hint: string }> = {
  paper: { label: 'Paper', hint: 'Warm cream panes and ink text (default)' },
  linen: { label: 'Linen', hint: 'Neutral warm grey, barely tinted' },
  dimmed: { label: 'Dimmed', hint: 'Every surface a few steps darker, for a bright screen in a dim room' },
  classic: { label: 'Classic', hint: 'The earlier light theme: white panes on a pale grey canvas' },
};

export function parseLightPalette(raw: unknown): LightPalette {
  return (LIGHT_PALETTES as readonly unknown[]).includes(raw) ? (raw as LightPalette) : DEFAULT_LIGHT_PALETTE;
}

/** Stored palette, or the default when nothing (or junk) is stored or storage throws. */
export function readStoredLightPalette(): LightPalette {
  try {
    return parseLightPalette(localStorage.getItem(LIGHT_PALETTE_KEY));
  } catch {
    return DEFAULT_LIGHT_PALETTE;
  }
}

/** The palette <html> currently shows in light mode. */
export function currentLightPalette(): LightPalette {
  if (typeof document === 'undefined') return DEFAULT_LIGHT_PALETTE;
  return parseLightPalette(document.documentElement.getAttribute(LIGHT_PALETTE_ATTR) ?? DEFAULT_LIGHT_PALETTE);
}

/** Show `palette` and remember it for this device. The default removes the attribute. */
export function setLightPalette(palette: LightPalette): void {
  if (typeof document !== 'undefined') {
    const el = document.documentElement;
    if (palette === DEFAULT_LIGHT_PALETTE) el.removeAttribute(LIGHT_PALETTE_ATTR);
    else el.setAttribute(LIGHT_PALETTE_ATTR, palette);
  }
  try {
    if (palette === DEFAULT_LIGHT_PALETTE) localStorage.removeItem(LIGHT_PALETTE_KEY);
    else localStorage.setItem(LIGHT_PALETTE_KEY, palette);
  } catch {
    /* private window or blocked storage: the palette still applies for this load */
  }
}
