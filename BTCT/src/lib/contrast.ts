/**
 * WCAG 2.x contrast helpers. Used wherever text sits on a colour a person
 * chose at runtime (the admin accent behind primary buttons, a user's
 * presence colour behind their cursor flag), so the text picks black or
 * white by whichever reads better instead of being fixed white.
 */

/** Parse `#rgb` or `#rrggbb` into 0..255 channels; null for anything else. */
export function parseHex(hex: string): [number, number, number] | null {
  const m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(hex.trim());
  if (!m?.[1]) return null;
  let h = m[1];
  if (h.length === 3) h = h.split('').map((c) => c + c).join('');
  const n = parseInt(h, 16);
  return [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
}

/** Relative luminance (WCAG 2.1, sRGB), 0 for black to 1 for white. */
export function relativeLuminance(hex: string): number | null {
  const rgb = parseHex(hex);
  if (!rgb) return null;
  const [r, g, b] = rgb.map((c) => {
    const v = c / 255;
    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** Contrast ratio between two colours, 1 to 21; null when either is not hex. */
export function contrastRatio(a: string, b: string): number | null {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  if (la === null || lb === null) return null;
  const [hi, lo] = la > lb ? [la, lb] : [lb, la];
  return (hi + 0.05) / (lo + 0.05);
}

/** The near-black the theme uses for text on light fills (--primary-foreground in dark mode). */
export const ON_LIGHT = '#121212';
export const ON_DARK = '#ffffff';

/**
 * Black-ish or white text for a fill, whichever has the higher contrast.
 * An unparseable fill gets white, the old fixed behaviour.
 */
export function readableTextOn(fill: string): typeof ON_LIGHT | typeof ON_DARK {
  const dark = contrastRatio(ON_LIGHT, fill);
  const light = contrastRatio(ON_DARK, fill);
  if (dark === null || light === null) return ON_DARK;
  return dark >= light ? ON_LIGHT : ON_DARK;
}
