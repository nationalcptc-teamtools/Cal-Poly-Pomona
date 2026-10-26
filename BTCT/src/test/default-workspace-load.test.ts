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
import { disposeSharedDoc } from '@/realtime/shared-doc';
import { typstAssetRepo } from '@/db';
import { assetFolderRepo } from '@/db/asset-folder-repo';
import { useAppStore } from '@/stores/app-store';

// QA 2026-10-12: in a fresh browser the default workspace was chosen by
// loadWorkspaces(), which set activeWorkspaceId without loading the
// workspace's assets or asset folders, so every note image read "image not
// found in assets" and the Assets panel stayed empty until a switch.
afterAll(() => disposeSharedDoc());

describe('choosing the default workspace at boot', () => {
  it('loads its assets, asset folders and other lists, as a switch does', async () => {
    const ws = await useAppStore.getState().createWorkspace('Alpha', '');
    await typstAssetRepo.create({
      id: 'a1', workspaceId: ws.id, kind: 'image', filename: 'shot.png', mime: 'image/png', size: 10,
    });
    await assetFolderRepo.create({ workspaceId: ws.id, name: 'Screens' });
    // A fresh profile: nothing persisted, nothing loaded.
    useAppStore.setState({ activeWorkspaceId: null, typstAssets: [], assetFolders: [], pages: [] });

    await useAppStore.getState().loadWorkspaces();

    const s = useAppStore.getState();
    expect(s.activeWorkspaceId).toBe(ws.id);
    expect(s.typstAssets.map((a) => a.id)).toEqual(['a1']);
    expect(s.assetFolders.map((f) => f.name)).toEqual(['Screens']);
  });
});
