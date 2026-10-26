import 'fake-indexeddb/auto';
import { afterAll, describe, expect, it, vi } from 'vitest';
import * as Y from 'yjs';
import { Awareness } from 'y-protocols/awareness';

// C10 (invariant 1): `whenReady` also resolves 250 ms after "connected" and
// on its own 4 s cap, so it cannot authorize seeding a Y.Text. The post-load
// migration must wait for the provider's real `sync`, or a stale client
// writes a second Y.Text into a slot the server already holds.
const prov = vi.hoisted(() => ({ handlers: new Map<string, Array<(...a: unknown[]) => void>>(), synced: false }));
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
    wsconnected = false;
    awareness: Awareness;
    get synced() { return prov.synced; }
    constructor(_url: string, _room: string, doc: Y.Doc) { this.awareness = new Awareness(doc); }
    on(ev: string, fn: (...a: unknown[]) => void) { const l = prov.handlers.get(ev) ?? []; l.push(fn); prov.handlers.set(ev, l); }
    off(ev: string, fn: (...a: unknown[]) => void) { prov.handlers.set(ev, (prov.handlers.get(ev) ?? []).filter((f) => f !== fn)); }
    emit(ev: string, ...a: unknown[]) { for (const f of prov.handlers.get(ev) ?? []) f(...a); }
    disconnect() {}
    destroy() { this.awareness.destroy(); }
  },
}));
import { disposeSharedDoc, getSharedDoc, textKey } from '@/realtime/shared-doc';

const emit = (ev: string, ...a: unknown[]) => { for (const f of prov.handlers.get(ev) ?? []) f(...a); };
afterAll(() => disposeSharedDoc());

describe('C10 post-load Y.Text seed waits for a real sync', () => {
  it('does not seed while the provider is connected but not synced', async () => {
    const c = getSharedDoc();
    // A record from before the text registry, cached locally; the server
    // holds its Y.Text but has not sent it yet.
    c.tables.pages.set('legacy', { id: 'legacy', workspaceId: 'w', parentId: null, title: 'Old title', slug: 'old', icon: '' });
    emit('status', { status: 'connected' });
    await new Promise((r) => setTimeout(r, 4500));
    expect(c.texts.has(textKey('page', 'legacy', 'title'))).toBe(false);
    prov.synced = true;
    emit('sync', true);
    await new Promise((r) => setTimeout(r, 50));
    expect(c.texts.has(textKey('page', 'legacy', 'title'))).toBe(true);
  }, 15_000);
});
