// @vitest-environment node
import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Awareness } from 'y-protocols/awareness';
import type * as Y from 'yjs';

vi.mock('@/auth/auth-store', () => ({
  WS_URL: 'ws://test.invalid',
  useAuthStore: { getState: () => ({ token: 'test', user: null }), subscribe: () => () => {} },
}));
vi.mock('@/realtime/page-history-api', () => ({ attachUserMapping: vi.fn() }));
vi.mock('y-websocket', () => ({
  WebsocketProvider: class {
    synced = true;
    awareness: Awareness;
    constructor(_url: string, _room: string, doc: Y.Doc) { this.awareness = new Awareness(doc); }
    on() {} off() {} disconnect() {}
    destroy() { this.awareness.destroy(); }
  },
}));
import { disposeAllPageDocs, getPageYContext, retainPageYContext, syncOpenPageDocs, withPageYContext } from '@/realtime/yjs-providers';

afterEach(async () => { disposeAllPageDocs(); await new Promise((r) => setTimeout(r, 20)); });

describe('page document lifetime', () => {
  it('releases a closed page only after its offline edits are durable', async () => {
    const id = crypto.randomUUID();
    syncOpenPageDocs([id]);
    const first = getPageYContext(id);
    await first.whenFullySynced;
    first.doc.getText('body').insert(0, 'Unsynced field notes');
    syncOpenPageDocs([]);
    await vi.waitFor(() => expect(first.doc.isDestroyed).toBe(true));
    syncOpenPageDocs([id]);
    const reopened = getPageYContext(id);
    await reopened.whenFullySynced;
    expect(reopened).not.toBe(first);
    expect(reopened.doc.getText('body').toString()).toBe('Unsynced field notes');
  });

  it('keeps a page alive while any page or history tab still owns it', async () => {
    const id = crypto.randomUUID();
    syncOpenPageDocs([id, id]);
    const ctx = getPageYContext(id);
    await ctx.whenFullySynced;
    syncOpenPageDocs([id]);
    await new Promise((r) => setTimeout(r, 20));
    expect(ctx.doc.isDestroyed).toBe(false);
    syncOpenPageDocs([]);
    await vi.waitFor(() => expect(ctx.doc.isDestroyed).toBe(true));
  });

  it('does not destroy a context during editor cleanup or a rapid reopen', async () => {
    const id = crypto.randomUUID();
    syncOpenPageDocs([id]);
    const ctx = getPageYContext(id);
    const release = retainPageYContext(id);
    await ctx.whenFullySynced;
    syncOpenPageDocs([]);
    await new Promise((r) => setTimeout(r, 20));
    expect(ctx.doc.isDestroyed).toBe(false);
    release(); release();
    syncOpenPageDocs([id]);
    await new Promise((r) => setTimeout(r, 20));
    expect(getPageYContext(id)).toBe(ctx);
    syncOpenPageDocs([]);
    await vi.waitFor(() => expect(ctx.doc.isDestroyed).toBe(true));
  });

  it('releases temporary export contexts after the operation completes', async () => {
    let ctx: ReturnType<typeof getPageYContext> | undefined;
    await withPageYContext(crypto.randomUUID(), async (page) => {
      ctx = page;
      await page.whenFullySynced;
      await new Promise((r) => setTimeout(r, 20));
      expect(page.doc.isDestroyed).toBe(false);
    });
    await vi.waitFor(() => expect(ctx?.doc.isDestroyed).toBe(true));
  });

  it('preserves a page in memory when offline persistence fails', async () => {
    const id = crypto.randomUUID();
    syncOpenPageDocs([id]);
    const ctx = getPageYContext(id);
    await ctx.whenFullySynced;
    // Something to save: an unchanged page has nothing to persist and closes at once.
    ctx.doc.getText('body').insert(0, 'Unsaved notes');
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const transaction = vi.spyOn(ctx.persistence.db!, 'transaction').mockImplementation(() => { throw new Error('quota'); });
    syncOpenPageDocs([]);
    await vi.waitFor(() => expect(warning).toHaveBeenCalled());
    expect(ctx.doc.isDestroyed).toBe(false);
    transaction.mockRestore(); warning.mockRestore();
    syncOpenPageDocs([]);
    await vi.waitFor(() => expect(ctx.doc.isDestroyed).toBe(true));
  });
});
