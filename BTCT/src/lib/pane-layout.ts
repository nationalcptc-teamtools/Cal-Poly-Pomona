import { v4 as uuidv4 } from 'uuid';
import type { PaneNode, LeafPane, SplitPane, SplitDirection, DropPosition } from '@/types';

// ── Factories ──

export function createLeaf(tabIds: string[] = [], activeTabId: string | null = null): LeafPane {
  return { type: 'leaf', id: uuidv4(), tabIds, activeTabId };
}

// ── Queries ──

export function findLeaf(root: PaneNode, paneId: string): LeafPane | null {
  if (root.type === 'leaf') return root.id === paneId ? root : null;
  return findLeaf(root.children[0], paneId) ?? findLeaf(root.children[1], paneId);
}

export function findLeafContainingTab(root: PaneNode, tabId: string): LeafPane | null {
  if (root.type === 'leaf') return root.tabIds.includes(tabId) ? root : null;
  return findLeafContainingTab(root.children[0], tabId) ?? findLeafContainingTab(root.children[1], tabId);
}

export function firstLeaf(root: PaneNode): LeafPane {
  if (root.type === 'leaf') return root;
  return firstLeaf(root.children[0]);
}

/** Every leaf, left to right and top to bottom (reading order). */
export function allLeaves(root: PaneNode): LeafPane[] {
  if (root.type === 'leaf') return [root];
  return [...allLeaves(root.children[0]), ...allLeaves(root.children[1])];
}

/**
 * The leaf whose header sits in the top-right corner of the layout: the one
 * that carries the shell's trailing tools (clock, properties toggle).
 */
export function topRightLeaf(root: PaneNode): LeafPane {
  if (root.type === 'leaf') return root;
  return topRightLeaf(root.direction === 'horizontal' ? root.children[1] : root.children[0]);
}

export function isSplit(root: PaneNode): boolean {
  return root.type === 'split';
}

// ── Immutable updates ──

function mapLeaf(root: PaneNode, paneId: string, fn: (leaf: LeafPane) => LeafPane): PaneNode {
  if (root.type === 'leaf') return root.id === paneId ? fn(root) : root;
  return {
    ...root,
    children: [mapLeaf(root.children[0], paneId, fn), mapLeaf(root.children[1], paneId, fn)] as [PaneNode, PaneNode],
  };
}

/** Add a tab to a specific leaf pane. */
export function addTabToPane(root: PaneNode, paneId: string, tabId: string): PaneNode {
  return mapLeaf(root, paneId, (leaf) => ({
    ...leaf,
    tabIds: leaf.tabIds.includes(tabId) ? leaf.tabIds : [...leaf.tabIds, tabId],
    activeTabId: tabId,
  }));
}

/** Set the active tab in a specific leaf pane. */
export function setActiveInPane(root: PaneNode, paneId: string, tabId: string): PaneNode {
  return mapLeaf(root, paneId, (leaf) => ({ ...leaf, activeTabId: tabId }));
}

/** Remove a tab from whichever leaf contains it, adjusting the active tab. */
export function removeTab(root: PaneNode, tabId: string): PaneNode {
  if (root.type === 'leaf') {
    if (!root.tabIds.includes(tabId)) return root;
    const idx = root.tabIds.indexOf(tabId);
    const newIds = root.tabIds.filter((id) => id !== tabId);
    return {
      ...root,
      tabIds: newIds,
      activeTabId:
        root.activeTabId === tabId ? (newIds[Math.max(0, idx - 1)] ?? null) : root.activeTabId,
    };
  }
  return {
    ...root,
    children: [removeTab(root.children[0], tabId), removeTab(root.children[1], tabId)] as [PaneNode, PaneNode],
  };
}

/** Remove tabs matching a predicate from all leaves. */
export function removeTabsWhere(root: PaneNode, predicate: (tabId: string) => boolean): PaneNode {
  if (root.type === 'leaf') {
    const newIds = root.tabIds.filter((id) => !predicate(id));
    if (newIds.length === root.tabIds.length) return root;
    return {
      ...root,
      tabIds: newIds,
      activeTabId: root.activeTabId && predicate(root.activeTabId) ? (newIds[0] ?? null) : root.activeTabId,
    };
  }
  return {
    ...root,
    children: [removeTabsWhere(root.children[0], predicate), removeTabsWhere(root.children[1], predicate)] as [PaneNode, PaneNode],
  };
}

/** Collapse empty leaves: if a split has an empty-leaf child, replace the split with the other child. */
export function collapse(root: PaneNode): PaneNode {
  if (root.type === 'leaf') return root;
  const left = collapse(root.children[0]);
  const right = collapse(root.children[1]);
  const leftEmpty = left.type === 'leaf' && left.tabIds.length === 0;
  const rightEmpty = right.type === 'leaf' && right.tabIds.length === 0;
  if (leftEmpty && rightEmpty) return left;
  if (leftEmpty) return right;
  if (rightEmpty) return left;
  return { ...root, children: [left, right] as [PaneNode, PaneNode] };
}

/** Split a leaf, placing the new tab in an adjacent new leaf. */
export function splitLeaf(
  root: PaneNode,
  targetPaneId: string,
  direction: SplitDirection,
  tabId: string,
  position: 'before' | 'after',
): PaneNode {
  if (root.type === 'leaf') {
    if (root.id !== targetPaneId) return root;
    const newLeaf = createLeaf([tabId], tabId);
    return {
      type: 'split',
      id: uuidv4(),
      direction,
      children: position === 'before' ? [newLeaf, root] : [root, newLeaf],
      ratio: 0.5,
    } as SplitPane;
  }
  return {
    ...root,
    children: [
      splitLeaf(root.children[0], targetPaneId, direction, tabId, position),
      splitLeaf(root.children[1], targetPaneId, direction, tabId, position),
    ] as [PaneNode, PaneNode],
  };
}

/** Update the ratio of a specific split node. */
export function updateRatio(root: PaneNode, splitId: string, ratio: number): PaneNode {
  const clamped = Math.max(0.15, Math.min(0.85, ratio));
  if (root.type === 'leaf') return root;
  if (root.id === splitId) return { ...root, ratio: clamped };
  return {
    ...root,
    children: [updateRatio(root.children[0], splitId, ratio), updateRatio(root.children[1], splitId, ratio)] as [PaneNode, PaneNode],
  };
}

/** High-level: move a tab to a target pane at a drop position. */
export function moveTab(
  root: PaneNode,
  tabId: string,
  targetPaneId: string,
  position: DropPosition,
): PaneNode {
  const from = findLeafContainingTab(root, tabId);
  // Dropping a tab onto the centre of its own pane is a no-op.
  if (position === 'center' && from && from.id === targetPaneId) return root;
  // The target has to exist before the tab leaves its pane: removing first
  // and collapsing could delete the very leaf we are about to add to, and
  // addTabToPane/splitLeaf silently no-op on an unknown pane id, which used
  // to strand the tab in store.tabs with no pane rendering it.
  if (!findLeaf(root, targetPaneId)) return root;
  let layout = removeTab(root, tabId);

  if (position === 'center') {
    // Add to target pane
    layout = addTabToPane(layout, targetPaneId, tabId);
  } else {
    // Split the target pane
    const directionMap: Record<string, SplitDirection> = { left: 'horizontal', right: 'horizontal', top: 'vertical', bottom: 'vertical' };
    const positionMap: Record<string, 'before' | 'after'> = { left: 'before', right: 'after', top: 'before', bottom: 'after' };
    layout = splitLeaf(layout, targetPaneId, directionMap[position]!, tabId, positionMap[position]!);
  }

  // Collapse last, so an emptied source pane disappears without taking the
  // target with it.
  return collapse(layout);
}

// ── Reordering within a strip ──

/**
 * Move the item `id` next to `targetId` in a list (before or after it). A
 * no-op when either id is missing or they are the same item.
 */
export function moveWithin<T>(
  list: T[],
  id: string,
  targetId: string,
  place: 'before' | 'after',
  key: (item: T) => string,
): T[] {
  if (id === targetId) return list;
  const item = list.find((x) => key(x) === id);
  if (!item || !list.some((x) => key(x) === targetId)) return list;
  const without = list.filter((x) => key(x) !== id);
  const idx = without.findIndex((x) => key(x) === targetId);
  const at = place === 'before' ? idx : idx + 1;
  return [...without.slice(0, at), item, ...without.slice(at)];
}

/** Reorder a tab inside one leaf's strip (dragged left or right past `targetTabId`). */
export function reorderTabInLeaf(
  root: PaneNode,
  paneId: string,
  tabId: string,
  targetTabId: string,
  place: 'before' | 'after',
): PaneNode {
  return mapLeaf(root, paneId, (leaf) => ({
    ...leaf,
    tabIds: moveWithin(leaf.tabIds, tabId, targetTabId, place, (id) => id),
  }));
}
