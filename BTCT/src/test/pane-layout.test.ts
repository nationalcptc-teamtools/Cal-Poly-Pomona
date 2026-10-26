import { describe, it, expect } from 'vitest';
import {
  createLeaf,
  findLeaf,
  findLeafContainingTab,
  firstLeaf,
  isSplit,
  addTabToPane,
  setActiveInPane,
  removeTab,
  removeTabsWhere,
  collapse,
  splitLeaf,
  updateRatio,
  moveTab,
} from '@/lib/pane-layout';
import type { LeafPane, SplitPane } from '@/types';

describe('pane-layout', () => {
  it('createLeaf produces an empty leaf with a unique id', () => {
    const a = createLeaf();
    const b = createLeaf();
    expect(a.type).toBe('leaf');
    expect(a.tabIds).toEqual([]);
    expect(a.activeTabId).toBeNull();
    expect(a.id).not.toBe(b.id);
  });

  it('findLeaf locates a leaf by id and returns null otherwise', () => {
    const leaf = createLeaf(['t1']);
    expect(findLeaf(leaf, leaf.id)).toBe(leaf);
    expect(findLeaf(leaf, 'nope')).toBeNull();
  });

  it('findLeafContainingTab walks splits', () => {
    const left = createLeaf(['a']);
    const right = createLeaf(['b']);
    const split: SplitPane = {
      type: 'split', id: 's', direction: 'horizontal', children: [left, right], ratio: 0.5,
    };
    expect(findLeafContainingTab(split, 'a')).toBe(left);
    expect(findLeafContainingTab(split, 'b')).toBe(right);
    expect(findLeafContainingTab(split, 'missing')).toBeNull();
  });

  it('firstLeaf returns the deepest first child leaf', () => {
    const l1 = createLeaf(['a']);
    const l2 = createLeaf(['b']);
    const split: SplitPane = {
      type: 'split', id: 's', direction: 'vertical', children: [l1, l2], ratio: 0.5,
    };
    expect(firstLeaf(split)).toBe(l1);
  });

  it('isSplit discriminates leaves from splits', () => {
    const leaf = createLeaf();
    expect(isSplit(leaf)).toBe(false);
    const split: SplitPane = {
      type: 'split', id: 's', direction: 'horizontal', children: [leaf, leaf], ratio: 0.5,
    };
    expect(isSplit(split)).toBe(true);
  });

  it('addTabToPane appends to the right leaf and sets active', () => {
    const leaf = createLeaf(['a']);
    const next = addTabToPane(leaf, leaf.id, 'b') as LeafPane;
    expect(next.tabIds).toEqual(['a', 'b']);
    expect(next.activeTabId).toBe('b');
  });

  it('addTabToPane is idempotent for an existing tab', () => {
    const leaf = createLeaf(['a']);
    const next = addTabToPane(leaf, leaf.id, 'a') as LeafPane;
    expect(next.tabIds).toEqual(['a']);
    expect(next.activeTabId).toBe('a');
  });

  it('setActiveInPane updates only the matching pane', () => {
    const leaf = createLeaf(['a', 'b'], 'a');
    const next = setActiveInPane(leaf, leaf.id, 'b') as LeafPane;
    expect(next.activeTabId).toBe('b');
  });

  it('removeTab drops the tab and reassigns active', () => {
    const leaf = createLeaf(['a', 'b', 'c'], 'b');
    const next = removeTab(leaf, 'b') as LeafPane;
    expect(next.tabIds).toEqual(['a', 'c']);
    expect(next.activeTabId).toBe('a');
  });

  it('removeTab on missing tab is a no-op', () => {
    const leaf = createLeaf(['a'], 'a');
    const next = removeTab(leaf, 'missing');
    expect(next).toBe(leaf);
  });

  it('removeTabsWhere prunes by predicate', () => {
    const leaf = createLeaf(['keep', 'kill1', 'kill2'], 'kill1');
    const next = removeTabsWhere(leaf, (id) => id.startsWith('kill')) as LeafPane;
    expect(next.tabIds).toEqual(['keep']);
    expect(next.activeTabId).toBe('keep');
  });

  it('collapse removes empty leaves under a split', () => {
    const empty = createLeaf();
    const full = createLeaf(['a']);
    const split: SplitPane = {
      type: 'split', id: 's', direction: 'horizontal', children: [empty, full], ratio: 0.5,
    };
    expect(collapse(split)).toBe(full);
  });

  it('splitLeaf wraps a leaf in a split pane', () => {
    const leaf = createLeaf(['a']);
    const out = splitLeaf(leaf, leaf.id, 'horizontal', 'b', 'after') as SplitPane;
    expect(out.type).toBe('split');
    expect(out.direction).toBe('horizontal');
    expect((out.children[0] as LeafPane).tabIds).toEqual(['a']);
    expect((out.children[1] as LeafPane).tabIds).toEqual(['b']);
  });

  it('splitLeaf with position=before places new leaf first', () => {
    const leaf = createLeaf(['a']);
    const out = splitLeaf(leaf, leaf.id, 'vertical', 'b', 'before') as SplitPane;
    expect((out.children[0] as LeafPane).tabIds).toEqual(['b']);
    expect((out.children[1] as LeafPane).tabIds).toEqual(['a']);
  });

  it('updateRatio clamps to [0.15, 0.85]', () => {
    const leaf = createLeaf(['a']);
    const split = splitLeaf(leaf, leaf.id, 'horizontal', 'b', 'after') as SplitPane;
    expect((updateRatio(split, split.id, 0.01) as SplitPane).ratio).toBe(0.15);
    expect((updateRatio(split, split.id, 0.99) as SplitPane).ratio).toBe(0.85);
    expect((updateRatio(split, split.id, 0.5) as SplitPane).ratio).toBe(0.5);
  });

  it('moveTab to center adds to the target pane', () => {
    const a = createLeaf(['t1', 't2']);
    const b = createLeaf();
    const split: SplitPane = {
      type: 'split', id: 's', direction: 'horizontal', children: [a, b], ratio: 0.5,
    };
    const out = moveTab(split, 't1', b.id, 'center');
    const newB = findLeafContainingTab(out, 't1');
    expect(newB).not.toBeNull();
    expect(newB!.tabIds).toContain('t1');
  });

  it('moveTab to a side splits the target pane', () => {
    const a = createLeaf(['t1']);
    const b = createLeaf(['t2']);
    const split: SplitPane = {
      type: 'split', id: 's', direction: 'horizontal', children: [a, b], ratio: 0.5,
    };
    const out = moveTab(split, 't1', b.id, 'right');
    expect(findLeafContainingTab(out, 't1')).not.toBeNull();
    expect(findLeafContainingTab(out, 't2')).not.toBeNull();
  });
});
