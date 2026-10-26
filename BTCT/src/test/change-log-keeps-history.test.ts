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
import { disposeSharedDoc, getSharedDoc } from '@/realtime/shared-doc';
import { changeLogRepo } from '@/db';
import { CHANGE_LOG_CAP } from '@/lib/change-log-policy';

// Review 2026-10-12: the writer pruned the log to 2000 on every add, so the
// first edit after restoring or importing a 6000-entry log deleted 4000.
afterAll(() => disposeSharedDoc());

describe('change log writes', () => {
  it('never delete existing entries, however many there are', async () => {
    const { doc, tables } = getSharedDoc();
    const n = CHANGE_LOG_CAP * 3;
    doc.transact(() => {
      for (let i = 0; i < n; i++) {
        tables.changeLogs.set(`cl-${i}`, {
          id: `cl-${i}`, workspaceId: 'w1', action: 'update', target: 'page', targetId: 'p1',
          summary: `edit ${i}`, timestamp: 1_000 + i, reversible: i % 3 === 0,
        });
      }
    });
    await changeLogRepo.add('w1', 'update', 'page', 'p1', 'one more edit');
    const kept = [...tables.changeLogs.values()].filter((e) => (e as { workspaceId: string }).workspaceId === 'w1');
    expect(kept.length).toBe(n + 1);
  });
});
