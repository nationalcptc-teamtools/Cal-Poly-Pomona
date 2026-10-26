import { describe, it, expect } from 'vitest';
import { createLeaf, moveWithin, reorderTabInLeaf, splitLeaf, findLeaf } from '@/lib/pane-layout';

const ids = (xs: { id: string }[]) => xs.map((x) => x.id);

describe('moveWithin', () => {
  const list = [{ id: 'a' }, { id: 'b' }, { id: 'c' }, { id: 'd' }];
  const key = (x: { id: string }) => x.id;

  it('places an item before or after a target', () => {
    expect(ids(moveWithin(list, 'd', 'b', 'before', key))).toEqual(['a', 'd', 'b', 'c']);
    expect(ids(moveWithin(list, 'a', 'c', 'after', key))).toEqual(['b', 'c', 'a', 'd']);
  });

  it('moving next to a neighbour is stable in both directions', () => {
    expect(ids(moveWithin(list, 'b', 'a', 'after', key))).toEqual(['a', 'b', 'c', 'd']);
    expect(ids(moveWithin(list, 'b', 'c', 'before', key))).toEqual(['a', 'b', 'c', 'd']);
    expect(ids(moveWithin(list, 'b', 'c', 'after', key))).toEqual(['a', 'c', 'b', 'd']);
  });

  it('is a no-op for the same item or an unknown id', () => {
    expect(moveWithin(list, 'a', 'a', 'after', key)).toBe(list);
    expect(moveWithin(list, 'zz', 'a', 'after', key)).toBe(list);
    expect(moveWithin(list, 'a', 'zz', 'after', key)).toBe(list);
  });
});

describe('reorderTabInLeaf', () => {
  it('reorders only the named leaf and keeps the active tab', () => {
    const left = createLeaf(['t1', 't2', 't3'], 't2');
    const root = splitLeaf(left, left.id, 'horizontal', 't4', 'after');
    const next = reorderTabInLeaf(root, left.id, 't3', 't1', 'before');
    expect(findLeaf(next, left.id)?.tabIds).toEqual(['t3', 't1', 't2']);
    expect(findLeaf(next, left.id)?.activeTabId).toBe('t2');
    // the other leaf is untouched
    const other = (next as { children: [unknown, { tabIds: string[] }] }).children[1];
    expect(other.tabIds).toEqual(['t4']);
  });
});
