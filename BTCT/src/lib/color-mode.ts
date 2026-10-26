/**
 * Light / dark mode, per device. The choice lives in localStorage
 * `btct.colorMode` and is applied as the `dark` class on <html>. The inline
 * script in index.html applies the same key before the first paint (so a
 * light device never flashes dark, and the login screen follows it); keep
 * the key and the default in step with that script.
 *
 * Mode is a CSS-class change only: every colour reads a token, so nothing
 * remounts (invariant #3).
 */
export type ColorMode = 'light' | 'dark';

export const COLOR_MODE_KEY = 'btct.colorMode';
/** The chosen theme's defaultMode. */
export const DEFAULT_COLOR_MODE: ColorMode = 'dark';

export function parseColorMode(raw: unknown): ColorMode {
  return raw === 'light' || raw === 'dark' ? raw : DEFAULT_COLOR_MODE;
}

/** Stored mode, or the default when nothing (or junk) is stored or storage throws. */
export function readStoredColorMode(): ColorMode {
  try {
    return parseColorMode(localStorage.getItem(COLOR_MODE_KEY));
  } catch {
    return DEFAULT_COLOR_MODE;
  }
}

/** The mode <html> currently shows. */
export function currentColorMode(): ColorMode {
  if (typeof document === 'undefined') return DEFAULT_COLOR_MODE;
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light';
}

/** Show `mode` and remember it for this device. */
export function setColorMode(mode: ColorMode): void {
  if (typeof document !== 'undefined') {
    document.documentElement.classList.toggle('dark', mode === 'dark');
  }
  try {
    localStorage.setItem(COLOR_MODE_KEY, mode);
  } catch {
    /* private window or blocked storage: the mode still applies for this load */
  }
}
