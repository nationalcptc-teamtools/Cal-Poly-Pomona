import 'fake-indexeddb/auto';
import { afterAll, describe, expect, it, vi } from 'vitest';
import * as Y from 'yjs';
import { Awareness } from 'y-protocols/awareness';

vi.mock('@/auth/auth-store', () => ({
  WS_URL: 'ws://test.invalid',
  probeSession: async () => 'ok',
  useAuthStore: { getState: () => ({ token: 'test', user: null }), subscribe: () => () => {} },
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

// CLI-6 / C10: only the client whose transaction changed a title writes the
// record back, so a bystander never rewrites a record (content included)
// from its own possibly stale copy.
afterAll(() => disposeSharedDoc());
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('Y.Text to record mirror', () => {
  it('a remote title edit does not make this client write the record', async () => {
    const c = getSharedDoc();
    const id = 'page-remote';
    // Shared starting state, as if synced from the server.
    const remote = new Y.Doc();
    remote.transact(() => {
      remote.getMap('pages').set(id, { id, title: 'Old', content: 'v1 body' });
      const t = new Y.Text();
      t.insert(0, 'Old');
      remote.getMap<Y.Text>('texts').set(textKey('page', id, 'title'), t);
    });
    Y.applyUpdate(c.doc, Y.encodeStateAsUpdate(remote));

    let localWrites = 0;
    c.doc.on('update', (_u: Uint8Array, _o: unknown, _d: Y.Doc, tr: Y.Transaction) => { if (tr.local) localWrites++; });

    // The typist renames it remotely.
    const before = Y.encodeStateVector(remote);
    remote.getMap<Y.Text>('texts').get(textKey('page', id, 'title'))!.insert(3, ' renamed');
    Y.applyUpdate(c.doc, Y.encodeStateAsUpdate(remote, before));
    await wait(250);
    expect(localWrites).toBe(0);
    expect((c.tables.pages.get(id) as { content: string }).content).toBe('v1 body');
  });

  it('a local title edit still updates only that field of the record', async () => {
    const c = getSharedDoc();
    const id = 'page-local';
    c.doc.transact(() => {
      c.tables.pages.set(id, { id, title: 'A', slug: 'a', content: 'body' });
      const t = new Y.Text();
      t.insert(0, 'A');
      c.texts.set(textKey('page', id, 'title'), t);
    });
    c.texts.get(textKey('page', id, 'title'))!.insert(1, 'B');
    await wait(250);
    const rec = c.tables.pages.get(id) as { title: string; slug: string; content: string };
    expect(rec.title).toBe('AB');
    expect(rec.slug).toBe('a');
    expect(rec.content).toBe('body');
  });
});
