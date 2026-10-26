import 'fake-indexeddb/auto';
import { afterAll, describe, expect, it, vi } from 'vitest';
import * as Y from 'yjs';
import { Awareness } from 'y-protocols/awareness';

vi.mock('@/auth/auth-store', () => ({
  WS_URL: 'ws://test.invalid',
  probeSession: async () => 'ok',
  useAuthStore: {
    getState: () => ({ token: 'test', user: { id: 1, username: 'qa', color: '#fff', isAdmin: true } }),
    subscribe: () => () => {},
  },
}));
vi.mock('y-websocket', () => ({
  WebsocketProvider: class {
    synced = false;
    wsconnected = false;
    awareness: Awareness;
    constructor(_url: string, _room: string, doc: Y.Doc) { this.awareness = new Awareness(doc); }
    on() {} off() {} disconnect() {}
    destroy() { this.awareness.destroy(); }
  },
}));
import { disposeSharedDoc, getSharedDoc, textKey } from '@/realtime/shared-doc';
import { useAppStore } from '@/stores/app-store';

// CLI-5: deleting a page with subpages and restoring it from the change log
// brings back every page, with title/slug Y.Texts so inline edits bind.
afterAll(() => disposeSharedDoc());

describe('delete and restore a page tree', () => {
  it('restores 3 pages and their 6 Y.Texts', async () => {
    const ws = await useAppStore.getState().createWorkspace('W', '');
    useAppStore.setState({ activeWorkspaceId: ws.id });
    const st = () => useAppStore.getState();
    const parent = await st().createPage(null, 'Parent');
    const c1 = await st().createPage(parent.id, 'Child one');
    const c2 = await st().createPage(parent.id, 'Child two');
    const c = getSharedDoc();
    const ids = [parent.id, c1.id, c2.id];
    let pageEvents = 0;
    const count = () => { pageEvents++; };
    c.tables.pages.observe(count);
    await st().deletePage(parent.id);
    c.tables.pages.unobserve(count);
    expect(pageEvents).toBe(1); // the whole cascade is one transaction
    for (const id of ids) {
      expect(c.tables.pages.has(id)).toBe(false);
      expect(c.texts.has(textKey('page', id, 'title'))).toBe(false);
    }
    await vi.waitFor(() => expect(st().changeLogs.some((e) => e.action === 'delete' && e.targetId === parent.id)).toBe(true));
    const del = st().changeLogs.find((e) => e.action === 'delete' && e.targetId === parent.id)!;
    expect(del.summary).toMatch(/and 2 subpages/);

    expect(await st().restoreFromLog(del.id)).toBe(true);
    for (const id of ids) {
      expect(c.tables.pages.has(id)).toBe(true);
      expect(c.texts.has(textKey('page', id, 'title'))).toBe(true);
      expect(c.texts.has(textKey('page', id, 'slug'))).toBe(true);
    }
    expect(c.texts.get(textKey('page', c1.id, 'title'))!.toString()).toBe('Child one');
    expect((c.tables.pages.get(c2.id) as { parentId: string }).parentId).toBe(parent.id);
  });
});
