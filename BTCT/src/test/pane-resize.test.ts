import { describe, it, expect } from 'vitest';
import { clampPaneWidth, fitPanes, PANE_MIN } from '@/lib/pane-resize';

const BOTH = { editor: 520, assets: 240 };
const BOTH_VISIBLE = { editor: true, assets: true };

describe('clampPaneWidth', () => {
  it('passes a comfortable width straight through', () => {
    expect(clampPaneWidth('editor', 500, 1600, 240)).toBe(500);
  });

  it('enforces each pane\'s own minimum', () => {
    expect(clampPaneWidth('editor', 50, 1600, 240)).toBe(PANE_MIN.editor);
    expect(clampPaneWidth('assets', 10, 1600, 520)).toBe(PANE_MIN.assets);
  });

  it('reserves room for the preview', () => {
    expect(clampPaneWidth('editor', 99999, 1600, 240)).toBe(1600 - 240 - PANE_MIN.preview);
  });

  it('lets a rail expand into a hidden sibling\'s space', () => {
    expect(clampPaneWidth('editor', 99999, 1600, 0)).toBe(1600 - PANE_MIN.preview);
  });

  it('prefers the pane\'s minimum over the preview\'s when space runs out', () => {
    // A rail collapsing below its minimum would be unusable and impossible to
    // drag back, so it wins over the preview in an impossible container.
    expect(clampPaneWidth('editor', 100, 400, 240)).toBe(PANE_MIN.editor);
  });

  it('never returns NaN for a degenerate container', () => {
    expect(Number.isFinite(clampPaneWidth('assets', 300, 0, 0))).toBe(true);
  });
});

describe('fitPanes', () => {
  it('leaves a layout that already fits alone', () => {
    expect(fitPanes(BOTH, BOTH_VISIBLE, 1600)).toEqual(BOTH);
  });

  it('shrinks both rails to make room when the container narrows', () => {
    const fitted = fitPanes(BOTH, BOTH_VISIBLE, 900);
    expect(fitted.editor + fitted.assets).toBeLessThanOrEqual(900 - PANE_MIN.preview);
  });

  it('respects both floors while shrinking', () => {
    const fitted = fitPanes(BOTH, BOTH_VISIBLE, 900);
    expect(fitted.editor).toBeGreaterThanOrEqual(PANE_MIN.editor);
    expect(fitted.assets).toBeGreaterThanOrEqual(PANE_MIN.assets);
  });

  it('degrades to the floors in an impossibly narrow container', () => {
    expect(fitPanes(BOTH, BOTH_VISIBLE, 300)).toEqual({
      editor: PANE_MIN.editor,
      assets: PANE_MIN.assets,
    });
  });

  it('remembers a hidden rail\'s width instead of shrinking it', () => {
    const fitted = fitPanes(BOTH, { editor: true, assets: false }, 900);
    expect(fitted.assets).toBe(240);
    expect(fitted.editor).toBe(520);
  });

  it('is idempotent, so a ResizeObserver loop settles', () => {
    const once = fitPanes(BOTH, BOTH_VISIBLE, 900);
    expect(fitPanes(once, BOTH_VISIBLE, 900)).toEqual(once);
  });
});
