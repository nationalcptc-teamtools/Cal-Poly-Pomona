import { describe, expect, it } from 'vitest';
import {
  buildPageTreeSnapshot, collectSubtree, pagesFromDeleteSnapshot, pickPruneIds, shouldLogContentSave,
  CONTENT_LOG_WINDOW_MS,
} from '@/lib/change-log-policy';
import type { ChangeLogEntry, Page } from '@/types';

// CLI-9 / C11 and CLI-5.
const page = (id: string, parentId: string | null, content = 'body'): Page => ({
  id, workspaceId: 'w', parentId, title: `T-${id}`, slug: id, icon: '', tags: [], content,
  sortOrder: 0, isGraphPage: false, createdAt: 0, updatedAt: 0,
});
const entry = (id: string, timestamp: number, reversible = false): ChangeLogEntry => ({
  id, workspaceId: 'w', action: 'update', target: 'page', targetId: 'p', summary: 's', timestamp,
  userId: 1, userName: 'u', userColor: null, field: null, prevValue: null, newValue: null, reversible,
});

describe('content-save coalescing', () => {
  it('two users alternating 100 saves on 2 pages log at most one entry per page per window each', () => {
    const userA = new Map<string, number>();
    const userB = new Map<string, number>();
    let logged = 0;
    for (let i = 0; i < 100; i++) {
      const now = i * 3000; // a save every 3 s, 5 minutes total
      const pageId = i % 4 < 2 ? 'p1' : 'p2';
      if (shouldLogContentSave(i % 2 ? userA : userB, pageId, now)) logged++;
    }
    expect(logged).toBeLessThanOrEqual(4);
    expect(logged).toBeGreaterThanOrEqual(2);
  });

  it('logs again once the window has passed', () => {
    const m = new Map<string, number>();
    expect(shouldLogContentSave(m, 'p', 0)).toBe(true);
    expect(shouldLogContentSave(m, 'p', CONTENT_LOG_WINDOW_MS - 1)).toBe(false);
    expect(shouldLogContentSave(m, 'p', CONTENT_LOG_WINDOW_MS)).toBe(true);
  });
});

describe('pickPruneIds', () => {
  it('does nothing within cap plus slack', () => {
    const e = Array.from({ length: 2100 }, (_, i) => entry(String(i), i));
    expect(pickPruneIds(e, 2000, 100)).toEqual([]);
  });

  it('drops the oldest non-reversible entries first, back to the cap', () => {
    const e = Array.from({ length: 2101 }, (_, i) => entry(String(i), i, i < 5));
    const ids = pickPruneIds(e, 2000, 100);
    expect(ids).toHaveLength(101);
    expect(ids).not.toContain('0');
    expect(ids[0]).toBe('5');
  });
});

describe('page tree delete snapshot', () => {
  const pages = [page('root', null), page('a', 'root'), page('b', 'root'), page('a1', 'a'), page('other', null)];

  it('collects the subtree root first and ignores other pages', () => {
    expect(collectSubtree(pages, 'root').map((p) => p.id)).toEqual(['root', 'a', 'b', 'a1']);
    expect(collectSubtree(pages, 'missing')).toEqual([]);
  });

  it('survives a parent cycle', () => {
    const cyc = [page('x', 'y'), page('y', 'x')];
    expect(collectSubtree(cyc, 'x').map((p) => p.id)).toEqual(['x', 'y']);
  });

  it('round-trips every record, and bounds bodies', () => {
    const removed = collectSubtree(pages, 'root');
    removed[3] = { ...removed[3]!, content: 'x'.repeat(50) };
    const snap = JSON.parse(JSON.stringify(buildPageTreeSnapshot(removed, 10)));
    const back = pagesFromDeleteSnapshot(snap);
    expect(back.map((p) => p.id)).toEqual(['root', 'a', 'b', 'a1']);
    expect(back[0]!.content).toBe('body');
    expect(back[3]!.content).toBe('');
    expect('contentDropped' in back[3]!).toBe(false);
  });

  it('still restores the single record older builds logged', () => {
    const back = pagesFromDeleteSnapshot(JSON.parse(JSON.stringify(page('old', null, 'legacy body'))));
    expect(back).toHaveLength(1);
    expect(back[0]!.content).toBe('legacy body');
    expect(pagesFromDeleteSnapshot(null)).toEqual([]);
    expect(pagesFromDeleteSnapshot({ kind: 'pageTree', pages: [{ nope: 1 }] })).toEqual([]);
  });
});
