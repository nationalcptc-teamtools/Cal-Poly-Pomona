import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  DEFAULT_LIGHT_PALETTE, LIGHT_PALETTES, LIGHT_PALETTE_ATTR, LIGHT_PALETTE_KEY,
  currentLightPalette, parseLightPalette, readStoredLightPalette, setLightPalette,
} from '@/lib/light-palette';

describe('light palette', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute(LIGHT_PALETTE_ATTR);
  });

  it('defaults to Paper and ignores junk', () => {
    expect(DEFAULT_LIGHT_PALETTE).toBe('paper');
    expect(readStoredLightPalette()).toBe('paper');
    expect(parseLightPalette('sepia')).toBe('paper');
    expect(currentLightPalette()).toBe('paper');
  });

  it('applies the attribute and remembers the choice per device', () => {
    setLightPalette('dimmed');
    expect(document.documentElement.getAttribute(LIGHT_PALETTE_ATTR)).toBe('dimmed');
    expect(localStorage.getItem(LIGHT_PALETTE_KEY)).toBe('dimmed');
    expect(currentLightPalette()).toBe('dimmed');
    // Back to the default clears both, so <html> carries nothing extra.
    setLightPalette('paper');
    expect(document.documentElement.hasAttribute(LIGHT_PALETTE_ATTR)).toBe(false);
    expect(localStorage.getItem(LIGHT_PALETTE_KEY)).toBeNull();
  });

  it('index.html applies the same key and ids before first paint', () => {
    const html = readFileSync(join(process.cwd(), 'index.html'), 'utf8');
    expect(html).toContain(`localStorage.getItem('${LIGHT_PALETTE_KEY}')`);
    expect(html.indexOf(LIGHT_PALETTE_KEY)).toBeLessThan(html.indexOf('/src/main.tsx'));
    for (const id of LIGHT_PALETTES.filter((p) => p !== DEFAULT_LIGHT_PALETTE)) {
      expect(html, id).toContain(`lp === '${id}'`);
    }
  });

  it('tokens.css has a block for every palette but the default, light mode only', () => {
    const css = readFileSync(join(process.cwd(), 'src', 'themes', 'tokens.css'), 'utf8');
    for (const id of LIGHT_PALETTES.filter((p) => p !== DEFAULT_LIGHT_PALETTE)) {
      expect(css, id).toContain(`:root[data-light-palette="${id}"]:not(.dark) {`);
    }
  });
});
