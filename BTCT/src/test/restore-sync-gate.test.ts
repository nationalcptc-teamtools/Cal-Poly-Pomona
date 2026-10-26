// @vitest-environment node
import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as Y from 'yjs';
import { Awareness } from 'y-protocols/awareness';

const providers: Array<{ synced: boolean; emit: (s: boolean) => void }> = [];
vi.mock('@/auth/auth-store', () => ({
  WS_URL: 'ws://test.invalid',
  useAuthStore: { getState: () => ({ token: 'test', user: null }), subscribe: () => () => {} },
}));
vi.mock('@/realtime/page-history-api', () => ({ attachUserMapping: vi.fn() }));
vi.mock('@/lib/active-editor', () => ({ getPageEditor: () => null }));
vi.mock('y-websocket', () => ({
  WebsocketProvider: class {
    synced = false;
    wsconnected = true;
    awareness: Awareness;
    private fns = new Set<(s: boolean) => void>();
    constructor(_url: string, _room: string, doc: Y.Doc) {
      this.awareness = new Awareness(doc);
      providers.push(this as unknown as { synced: boolean; emit: (s: boolean) => void });
    }
    emit(s: boolean) { this.synced = s; for (const f of [...this.fns]) f(s); }
    on(ev: string, fn: (s: boolean) => void) { if (ev === 'sync') this.fns.add(fn); }
    off(ev: string, fn: (s: boolean) => void) { if (ev === 'sync') this.fns.delete(fn); }
    disconnect() {}
    destroy() { this.awareness.destroy(); }
  },
}));
import { disposeAllPageDocs, getPageYContext, syncOpenPageDocs } from '@/realtime/yjs-providers';
import { restoreFromState, restorePageVersion } from '@/realtime/page-snapshots';

// CLI-2: a version restore must never act on a doc that has only passed the
// 3 s fallback; the stored body would merge back in beside the version.
afterEach(async () => { disposeAllPageDocs(); await new Promise((r) => setTimeout(r, 20)); });

function versionBytes(text: string): Uint8Array {
  const d = new Y.Doc();
  const p = new Y.XmlElement('paragraph');
  p.insert(0, [new Y.XmlText(text)]);
  d.getXmlFragment('prosemirror').push([p]);
  return Y.encodeStateAsUpdate(d);
}

describe('restore waits for a real server sync', () => {
  it('refuses synchronously on an unsynced page', () => {
    const id = crypto.randomUUID();
    syncOpenPageDocs([id]);
    getPageYContext(id);
    expect(() => restoreFromState(id, versionBytes('old'))).toThrow(/not synced/);
  });

  it('waits for sync, then replaces the stored body instead of adding to it', async () => {
    const id = crypto.randomUUID();
    syncOpenPageDocs([id]);
    const ctx = getPageYContext(id);
    const provider = providers[providers.length - 1]!;
    const pending = restorePageVersion(id, versionBytes('old version'), 2000);
    // The server's stored body arrives, then the sync completes.
    Y.applyUpdate(ctx.doc, versionBytes('current body'));
    provider.emit(true);
    await expect(pending).resolves.toBe('yjs');
    const frag = ctx.doc.getXmlFragment('prosemirror');
    expect(frag.length).toBe(1);
    expect(frag.toString()).toContain('old version');
    expect(frag.toString()).not.toContain('current body');
  });

  it('gives up with an error when the page never syncs', async () => {
    const id = crypto.randomUUID();
    syncOpenPageDocs([id]);
    getPageYContext(id);
    await expect(restorePageVersion(id, versionBytes('x'), 50)).rejects.toThrow(/not synced/);
  });
});
