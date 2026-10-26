import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { useAppStore } from '@/stores';
import { LeftSidebar } from '@/components/sidebar/LeftSidebar';
import type { Page } from '@/types';

// C6: a page whose parent no longer exists (concurrent delete of the parent)
// or that sits in a parent cycle (two concurrent moves) is still in the
// shared doc, so the sidebar must still list it somewhere instead of hiding it.
function page(id: string, parentId: string | null): Page {
  return {
    id, workspaceId: 'ws-c6', parentId, title: `Page ${id}`, slug: id, icon: '', tags: [],
    content: '', sortOrder: 0, isGraphPage: false, createdAt: 1, updatedAt: 1,
  };
}

describe('C6 sidebar shows orphaned and cyclic pages', () => {
  it('lists a page with a missing parent and one page of a parent cycle', () => {
    useAppStore.setState({
      activeWorkspaceId: 'ws-c6',
      pages: [page('A', null), page('B', 'gone'), page('C', 'D'), page('D', 'C')],
    });
    render(<LeftSidebar />);
    expect(screen.getAllByText('Page A').length).toBeGreaterThan(0);
    expect(screen.queryAllByText('Page B').length).toBeGreaterThan(0);
    const cyc = screen.queryAllByText('Page C').length + screen.queryAllByText('Page D').length;
    expect(cyc).toBeGreaterThan(0);
  });
});
