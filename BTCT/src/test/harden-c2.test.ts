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
import { disposeSharedDoc, getOrInitYText, textKey } from '@/realtime/shared-doc';
import { db } from '@/db';
import { useAppStore } from '@/stores';
import type { TypstAsset } from '@/types';

// C2: a rename from the Assets tab or the note image editor goes through the
// store action only. The report must keep resolving the renamed file, so the
// store's rename has to repoint `/assets/<old>` in the report source too.
afterAll(() => disposeSharedDoc());

describe('C2 rename keeps report references', () => {
  it('renameTypstAsset rewrites /assets/<old> in the workspace report', async () => {
    const ws = 'ws-c2';
    const asset: TypstAsset = {
      id: 'asset-c2', workspaceId: ws, kind: 'image', filename: 'a.png', mime: 'image/png', size: 4,
      createdAt: 1, updatedAt: 1,
    };
    await db.typstAssets.add(asset);
    const report = getOrInitYText(textKey('typst', ws, 'source'), '#image("/assets/a.png")\n');
    useAppStore.setState({ activeWorkspaceId: ws, typstAssets: [asset] });
    const name = await useAppStore.getState().renameTypstAsset(asset.id, 'b');
    // Let the change-log write settle before the environment tears down.
    await new Promise((r) => setTimeout(r, 50));
    expect(name).toBe('b.png');
    expect(report.toString()).toContain('/assets/b.png');
    expect(report.toString()).not.toContain('/assets/a.png');
  });
});
