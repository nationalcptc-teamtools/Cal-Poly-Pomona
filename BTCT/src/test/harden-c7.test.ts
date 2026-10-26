import 'fake-indexeddb/auto';
import { describe, expect, it, vi } from 'vitest';

// C7 (invariant 8): a page-ref chip must not redo its lookup and rewrite its
// DOM on store writes that do not touch the pages it shows.
vi.mock('@milkdown/utils', () => ({ $node: () => ({}), $view: (_s: unknown, f: () => unknown) => f() }));
vi.mock('@milkdown/core', () => ({ commandsCtx: {}, editorViewCtx: {} }));
vi.mock('@milkdown/preset-commonmark', () => ({ clearTextInCurrentBlockCommand: { key: {} } }));
import { useAppStore } from '@/stores';
import { pageRefView } from '@/lib/page-ref';

describe('C7 page-ref chip store subscription', () => {
  it('does not re-render on unrelated store writes', async () => {
    useAppStore.setState({
      pages: [{ id: 'P', workspaceId: 'w', parentId: null, title: 'Target', slug: 'p', icon: '', tags: [], content: '', sortOrder: 0, isGraphPage: false, createdAt: 1, updatedAt: 1 }],
    });
    const mount = pageRefView as unknown as (n: never) => { dom: HTMLElement; destroy: () => void };
    const view = mount({ attrs: { pageId: 'P' }, type: {} } as never);
    expect(view.dom.textContent).toBe('Target');
    let mutations = 0;
    const mo = new MutationObserver((records) => { mutations += records.length; });
    mo.observe(view.dom, { childList: true, characterData: true, subtree: true });
    for (let i = 0; i < 100; i++) useAppStore.setState({ editingAssetId: i % 2 ? 'x' : null });
    await new Promise((r) => setTimeout(r, 0));
    mo.disconnect();
    expect(mutations).toBe(0);
    view.destroy();
  });
});
