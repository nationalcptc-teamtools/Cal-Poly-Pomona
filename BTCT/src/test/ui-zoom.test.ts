import { afterEach, describe, expect, it } from 'vitest';
import {
  DEFAULT_UI_ZOOM, MAX_UI_ZOOM, MIN_UI_ZOOM, UI_ZOOM_STEPS,
  applyUiZoom, getUiZoom, onUiZoomChange, resolveUiZoom, restoreUiZoom, stepUiZoom, toLayoutPx,
} from '@/lib/ui-zoom';

afterEach(() => {
  applyUiZoom(DEFAULT_UI_ZOOM);
  localStorage.clear();
});

describe('ui zoom', () => {
  it('accepts only the listed steps, from storage strings too', () => {
    expect(resolveUiZoom(1.25)).toBe(1.25);
    expect(resolveUiZoom('1.5')).toBe(1.5);
    for (const junk of [0, 1.3, '3', 'abc', null, undefined, NaN, {}]) {
      expect(resolveUiZoom(junk)).toBe(DEFAULT_UI_ZOOM);
    }
  });

  it('steps up and down and stops at the ends', () => {
    expect(UI_ZOOM_STEPS[0]).toBe(MIN_UI_ZOOM);
    expect(UI_ZOOM_STEPS[UI_ZOOM_STEPS.length - 1]).toBe(MAX_UI_ZOOM);
    expect(stepUiZoom(1, 1)).toBe(1.1);
    expect(stepUiZoom(1, -1)).toBe(0.9);
    expect(stepUiZoom(MAX_UI_ZOOM, 1)).toBe(MAX_UI_ZOOM);
    expect(stepUiZoom(MIN_UI_ZOOM, -1)).toBe(MIN_UI_ZOOM);
    expect(stepUiZoom(1.3, 1)).toBe(DEFAULT_UI_ZOOM);
  });

  it('sets zoom and --ui-zoom on <html>, clears zoom at 100%, and persists', () => {
    const root = document.documentElement;
    applyUiZoom(1.25);
    expect(root.style.getPropertyValue('zoom')).toBe('1.25');
    expect(root.style.getPropertyValue('--ui-zoom')).toBe('1.25');
    expect(localStorage.getItem('btct.uiZoom')).toBe('1.25');
    expect(getUiZoom()).toBe(1.25);
    expect(toLayoutPx(125)).toBe(100);
    applyUiZoom(1);
    expect(root.style.getPropertyValue('zoom')).toBe('');
    expect(root.style.getPropertyValue('--ui-zoom')).toBe('1');
  });

  it('restores the saved zoom and tells listeners', () => {
    localStorage.setItem('btct.uiZoom', '1.5');
    const seen: number[] = [];
    const off = onUiZoomChange((z) => seen.push(z));
    restoreUiZoom();
    off();
    applyUiZoom(1.1);
    expect(seen).toEqual([1.5]);
  });
});
