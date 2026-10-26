import { describe, it, expect, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { allLeaves, createLeaf, topRightLeaf } from '@/lib/pane-layout';
import { isNarrowWidth, NARROW_MAX } from '@/lib/use-layout-width';
import { Splitter } from '@/components/ui/Splitter';
import type { PaneNode } from '@/types';

const a = createLeaf(['t1'], 't1');
const b = createLeaf(['t2'], 't2');
const c = createLeaf(['t3'], 't3');
// [a | (b over c)]
const layout: PaneNode = {
  type: 'split', id: 's1', direction: 'horizontal', ratio: 0.5,
  children: [a, { type: 'split', id: 's2', direction: 'vertical', ratio: 0.5, children: [b, c] }],
};

describe('shell pane helpers', () => {
  it('lists leaves in reading order', () => {
    expect(allLeaves(layout).map((l) => l.id)).toEqual([a.id, b.id, c.id]);
    expect(allLeaves(a)).toEqual([a]);
  });

  it('finds the top-right leaf that carries the clock and properties toggle', () => {
    expect(topRightLeaf(layout).id).toBe(b.id);
    expect(topRightLeaf(a).id).toBe(a.id);
    const stacked: PaneNode = { type: 'split', id: 's3', direction: 'vertical', ratio: 0.5, children: [a, b] };
    expect(topRightLeaf(stacked).id).toBe(a.id);
  });

  it('switches to the narrow layout under 900 layout px', () => {
    expect(NARROW_MAX).toBe(900);
    expect(isNarrowWidth(899)).toBe(true);
    expect(isNarrowWidth(900)).toBe(false);
    expect(isNarrowWidth(400)).toBe(true);
  });
});

describe('Splitter', () => {
  it('is a labelled separator that steps with the arrow keys and resets on Enter', () => {
    const step = vi.fn();
    const reset = vi.fn();
    render(<Splitter orientation="vertical" label="Resize the sidebar" onMouseDown={() => {}} onKeyStep={step} onReset={reset} valueNow={280} />);
    const sep = screen.getByRole('separator', { name: 'Resize the sidebar' });
    expect(sep.getAttribute('aria-orientation')).toBe('vertical');
    expect(sep.getAttribute('aria-valuenow')).toBe('280');
    fireEvent.keyDown(sep, { key: 'ArrowLeft' });
    fireEvent.keyDown(sep, { key: 'ArrowRight' });
    fireEvent.keyDown(sep, { key: 'ArrowUp' });
    expect(step.mock.calls).toEqual([[-1], [1]]);
    fireEvent.keyDown(sep, { key: 'Enter' });
    expect(reset).toHaveBeenCalledOnce();
  });
});
