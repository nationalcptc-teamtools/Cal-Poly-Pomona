/**
 * Theme color helpers. The whole app is built around HSL CSS variables
 * (src/themes/tokens.css): `--primary` and `--ring` drive every accent
 * surface, focus ring, link colour and the active-item bar. An admin accent
 * rewrites those two on `:root` plus a `--primary-foreground` picked by
 * contrast; with no accent chosen the inline values are removed and the
 * theme's own coral shows (a different shade per light/dark mode). Hex is
 * what users (and the SQLite settings row) speak, so we convert at the edge.
 *
 * Note heading colours work the same way through `--heading-color` and
 * `--heading-1`..`--heading-6` (see the heading rules in index.css). They
 * come from three places with a fixed precedence, resolved by
 * `resolveEffectiveHeadings`: the admin hard-lock beats everything, then a
 * user's own prefs, then the admin defaults, then "inherit". Applying is a
 * CSS-variable rewrite, never an editor rebuild (invariant #3).
 */
import {
  HEADING_LEVELS,
  isThemeCustomized,
  type ThemePrefs,
} from '@/lib/editor-prefs';

import { ON_DARK, readableTextOn } from '@/lib/contrast';

/**
 * No accent chosen: the empty string. The theme's primary (coral) then
 * applies, per mode. The server answers the same '' when its `theme_color`
 * setting is unset.
 */
export const DEFAULT_THEME_COLOR = '';

/** The theme's own primary per mode (tokens.css), for pickers that need a hex. */
export const THEME_PRIMARY = { light: '#c33b22', dark: '#ff6c52' } as const;

export interface Hsl {
  h: number; // 0-360
  s: number; // 0-100
  l: number; // 0-100
}

export function hexToHsl(hex: string): Hsl | null {
  const m = /^#([0-9a-f]{6})$/i.exec(hex.trim());
  const captured = m?.[1];
  if (!captured) return null;
  const n = parseInt(captured, 16);
  const r = ((n >> 16) & 0xff) / 255;
  const g = ((n >> 8) & 0xff) / 255;
  const b = (n & 0xff) / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  let h = 0;
  let s = 0;
  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case r: h = (g - b) / d + (g < b ? 6 : 0); break;
      case g: h = (b - r) / d + 2; break;
      case b: h = (r - g) / d + 4; break;
    }
    h *= 60;
  }
  return { h: Math.round(h), s: Math.round(s * 100), l: Math.round(l * 100) };
}

// CSS variables in index.css are written as raw HSL triplets (e.g.
// `0 78% 52%`) so callers can do `hsl(var(--primary) / 0.5)`. We must
// match that exact shape.
function hslTriplet(hex: string): string | null {
  const hsl = hexToHsl(hex);
  if (!hsl) return null;
  return `${hsl.h} ${hsl.s}% ${hsl.l}%`;
}

/** HSL triplet of the text colour that reads best on `hex`. */
export function accentForegroundTriplet(hex: string): string {
  return readableTextOn(hex) === ON_DARK ? '0 0% 100%' : '0 0% 7%';
}

/**
 * Paint the admin accent. An empty or invalid value clears the override so
 * the theme primary shows. Accepts a target for tests.
 */
export function applyThemeColor(hex: string | null | undefined, target?: StyleTarget): void {
  const style = target ?? (typeof document !== 'undefined' ? document.documentElement.style : null);
  if (!style) return;
  const triplet = hex ? hslTriplet(hex) : null;
  if (!hex || !triplet) {
    style.removeProperty('--primary');
    style.removeProperty('--ring');
    style.removeProperty('--primary-foreground');
    return;
  }
  style.setProperty('--primary', triplet);
  style.setProperty('--ring', triplet);
  style.setProperty('--primary-foreground', accentForegroundTriplet(hex));
}

// ── Heading colours ──────────────────────────────────────────────────────

/** The admin side of heading theming, as served by GET /api/settings. */
export interface ThemePolicy {
  /** Admin-chosen heading colours: the default for everyone, or forced when `lock` is on. */
  headings: ThemePrefs;
  /** When true, users' own heading colours are ignored. */
  lock: boolean;
}

export interface EffectiveHeadings {
  headings: ThemePrefs;
  /** True when the admin lock decided the result (UI disables the user controls). */
  locked: boolean;
}

/**
 * Precedence: lock → user prefs (as a whole, once customised) → admin
 * defaults → inherit. A customised user theme replaces the admin default
 * entirely rather than merging per level, so "I set all my headings to
 * white" is not silently undercut by an admin's per-level override.
 */
export function resolveEffectiveHeadings(
  policy: ThemePolicy | null | undefined,
  user: ThemePrefs,
): EffectiveHeadings {
  if (policy?.lock) return { headings: policy.headings, locked: true };
  if (isThemeCustomized(user)) return { headings: user, locked: false };
  return { headings: policy?.headings ?? { headingColor: null, headings: {} }, locked: false };
}

/** The subset of CSSStyleDeclaration we write; injectable for tests. */
export interface StyleTarget {
  setProperty(name: string, value: string): void;
  removeProperty(name: string): string | void;
}

/**
 * Paint heading colours onto :root. Every variable is either set or removed
 * so a level that was coloured before and is not any more falls back to
 * inherit instead of keeping a stale value.
 */
export function applyHeadingColors(theme: ThemePrefs, target?: StyleTarget): void {
  const style = target ?? (typeof document !== 'undefined' ? document.documentElement.style : null);
  if (!style) return;
  if (theme.headingColor) style.setProperty('--heading-color', theme.headingColor);
  else style.removeProperty('--heading-color');
  HEADING_LEVELS.forEach((level, i) => {
    const v = theme.headings[level];
    const name = '--heading-' + (i + 1);
    if (v) style.setProperty(name, v);
    else style.removeProperty(name);
  });
}
