import { hexToHsl } from './theme';
import { DEFAULT_CODE_ACCENT } from './editor-prefs';

/**
 * Change syntax colours without loading or rebuilding an editor. The
 * untouched default (DEFAULT_CODE_ACCENT, the pre-redesign GitHub red)
 * clears the override instead, so the theme's own light and dark keyword
 * colours from tokens.css show; any other pick tints both modes.
 */
export function applyCodeAccent(hex: string): void {
  if (typeof document === 'undefined' || !hexToHsl(hex)) return;
  const style = document.documentElement.style;
  if (hex.toLowerCase() === DEFAULT_CODE_ACCENT) {
    style.removeProperty('--code-accent');
    style.removeProperty('--code-keyword');
    return;
  }
  style.setProperty('--code-accent', hex);
  style.setProperty('--code-keyword', hex);
}
