import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_UI_ZOOM, applyUiZoom, getUiZoom, toLayoutPx, uiZoomSupported } from '@/lib/ui-zoom';

// CLI-15: Firefox before 126 ignores CSS zoom, so a saved zoom must not make
// toLayoutPx divide pointer coordinates by a scale the page never got.
afterEach(() => {
  vi.unstubAllGlobals();
  applyUiZoom(DEFAULT_UI_ZOOM);
  localStorage.clear();
});

describe('ui zoom without CSS zoom support', () => {
  it('forces 1 and leaves the root style alone', () => {
    vi.stubGlobal('CSS', { supports: (prop: string) => prop !== 'zoom' });
    expect(uiZoomSupported()).toBe(false);
    applyUiZoom(1.25);
    expect(getUiZoom()).toBe(1);
    expect(toLayoutPx(500)).toBe(500);
    expect(document.documentElement.style.getPropertyValue('zoom')).toBe('');
  });

  it('still applies the zoom where the browser supports it', () => {
    vi.stubGlobal('CSS', { supports: () => true });
    expect(uiZoomSupported()).toBe(true);
    applyUiZoom(1.25);
    expect(getUiZoom()).toBe(1.25);
    expect(toLayoutPx(500)).toBe(400);
  });
});
