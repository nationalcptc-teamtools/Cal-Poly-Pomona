import { describe, it, expect } from 'vitest';
import { HIGHLIGHT_COLORS, highlightMark, toggleHighlightCommand, highlightPlugin } from '@/lib/highlight-plugin';

describe('highlight-plugin', () => {
  it('exports the expected palette of colours', () => {
    expect(HIGHLIGHT_COLORS).toEqual(['yellow', 'green', 'blue', 'pink', 'orange', 'purple', 'red']);
  });

  it('declares a highlight mark', () => {
    expect(highlightMark).toBeDefined();
  });

  it('declares the ToggleHighlight command', () => {
    expect(toggleHighlightCommand).toBeDefined();
    // Milkdown 7.20 assigns `.key` only once an editor runs the plugin, so a
    // module-level check can only assert the slice is a plugin function.
    expect(typeof toggleHighlightCommand).toBe('function');
  });

  it('exports the plugin as a flat array containing both pieces', () => {
    expect(Array.isArray(highlightPlugin)).toBe(true);
    expect(highlightPlugin.length).toBeGreaterThanOrEqual(2);
  });
});
