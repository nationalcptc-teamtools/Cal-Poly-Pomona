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
    wsconnected = true;
    awareness: Awareness;
    constructor(_url: string, _room: string, doc: Y.Doc) { this.awareness = new Awareness(doc); }
    on() {} off() {} disconnect() {}
    destroy() { this.awareness.destroy(); }
  },
}));
import { disposeAllPageDocs, getPageYContext, syncOpenPageDocs } from '@/realtime/yjs-providers';

// CLI-13: open/close cycles must not append a full state per close.
afterEach(async () => { disposeAllPageDocs(); await new Promise((r) => setTimeout(r, 20)); });

function countRecords(name: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(name);
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction('updates', 'readonly');
      const c = tx.objectStore('updates').count();
      c.onsuccess = () => { db.close(); resolve(c.result); };
      c.onerror = () => reject(c.error);
    };
    req.onerror = () => reject(req.error);
  });
}

async function cycle(id: string, edit?: string): Promise<Y.Doc> {
  syncOpenPageDocs([id]);
  const ctx = getPageYContext(id);
  await ctx.whenFullySynced;
  if (edit) ctx.doc.getText('body').insert(ctx.doc.getText('body').length, edit);
  syncOpenPageDocs([]);
  await vi.waitFor(() => expect(ctx.doc.isDestroyed).toBe(true));
  return ctx.doc;
}

describe('page offline cache compaction', () => {
  it('stays at a handful of records over 41 open/close cycles, edits kept', async () => {
    const id = crypto.randomUUID();
    await cycle(id, 'x'.repeat(40_000));
    for (let i = 0; i < 40; i++) await cycle(id, i % 5 === 0 ? `-${i}` : undefined);
    expect(await countRecords(`btct-page-${id}`)).toBeLessThanOrEqual(3);
    syncOpenPageDocs([id]);
    const ctx = getPageYContext(id);
    await ctx.whenFullySynced;
    const text = ctx.doc.getText('body').toString();
    expect(text.startsWith('x'.repeat(40_000))).toBe(true);
    expect(text.endsWith('-35')).toBe(true);
  });
});
