import * as Y from 'yjs';
import { WebsocketProvider } from 'y-websocket';
import { IndexeddbPersistence } from 'y-indexeddb';
import { useAuthStore, WS_URL } from '@/auth/auth-store';
import { withPageYContext } from '@/realtime/yjs-providers';
import { restoreEpochParams } from '@/realtime/restore-epoch';

import { stateVectorCovers } from './page-body-codec';
import type { PageBodyIO } from './body-sync';

export type { PageBodyIO } from './body-sync';

// ─────────────────────────────────────────────────────────────────────────
// Reading and writing page bodies for export and import.
//
// Reading opens each page room READ-ONLY (`?ro=1`, so the server keeps no
// history twin for the connection) with no IndexedDB persistence and no
// BroadcastChannel, so an export of 300 pages leaves no 300 IndexedDB
// databases behind and never takes a body from another tab instead of the
// server. The server answers sync only once a room has loaded (invariant
// #20), and every body is still checked: one that comes back empty while its
// markdown mirror is not is read again, then listed as possibly incomplete.
//
// Writing goes through a leased page context (`withPageYContext`), four at a
// time, and a body counts as written only when a separate read-only
// connection sees the server's state vector cover it. Release happens only
// after that, so a body is never left only in this browser's IndexedDB.
// ─────────────────────────────────────────────────────────────────────────

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function readOnlyProvider(pageId: string, doc: Y.Doc): WebsocketProvider {
  const provider = new WebsocketProvider(`${WS_URL}/yjs`, pageId, doc, {
    // The restore epoch too, or the relay refuses the reader after a restore.
    params: { token: useAuthStore.getState().token ?? '', ro: '1', ...restoreEpochParams() },
    connect: false,
    disableBc: true,
  });
  // No presence: a reader is not a collaborator.
  provider.awareness.setLocalState(null);
  return provider;
}

/** Open the room read-only, wait for the server's sync, return its state. */
async function readServerDoc(pageId: string, timeoutMs: number): Promise<Y.Doc | null> {
  const doc = new Y.Doc();
  const provider = readOnlyProvider(pageId, doc);
  const synced = await new Promise<boolean>((resolve) => {
    const finish = (v: boolean) => { clearTimeout(timer); provider.off('sync', onSync); resolve(v); };
    const onSync = (s: boolean) => { if (s) finish(true); };
    const timer = setTimeout(() => finish(false), timeoutMs);
    provider.on('sync', onSync);
    provider.connect();
  });
  provider.destroy();
  if (!synced) { doc.destroy(); return null; }
  return doc;
}

async function hasLocalDatabase(name: string): Promise<boolean> {
  const idb = globalThis.indexedDB as (IDBFactory & { databases?: () => Promise<Array<{ name?: string }>> }) | undefined;
  if (!idb) return false;
  if (typeof idb.databases !== 'function') return true; // cannot tell: try it
  try { return (await idb.databases()).some((d) => d.name === name); }
  catch { return true; }
}

function waitForProviderSync(provider: WebsocketProvider, timeoutMs: number): Promise<boolean> {
  if (provider.synced) return Promise.resolve(true);
  return new Promise((resolve) => {
    const finish = (v: boolean) => { clearTimeout(timer); provider.off('sync', onSync); resolve(v); };
    const onSync = (s: boolean) => { if (s) finish(true); };
    const timer = setTimeout(() => finish(false), timeoutMs);
    provider.on('sync', onSync);
  });
}

export function browserPageBodyIO(): PageBodyIO {
  return {
    async readFromServer(pageId, timeoutMs) {
      const doc = await readServerDoc(pageId, timeoutMs);
      if (!doc) return null;
      try { return Y.encodeStateAsUpdate(doc); }
      finally { doc.destroy(); }
    },

    async readLocal(pageId) {
      const name = `btct-page-${pageId}`;
      if (!(await hasLocalDatabase(name))) return null;
      const doc = new Y.Doc();
      const persistence = new IndexeddbPersistence(name, doc);
      try {
        await Promise.race([persistence.whenSynced, sleep(5_000)]);
        return Y.encodeStateAsUpdate(doc);
      } finally {
        // destroy() closes the database; it never deletes it.
        await persistence.destroy().catch(() => undefined);
        doc.destroy();
      }
    },

    async write(pageId, update, timeoutMs) {
      const want = Y.encodeStateVectorFromUpdate(update);
      return withPageYContext(pageId, async (ctx) => {
        Y.applyUpdate(ctx.doc, update, 'btct-import');
        const deadline = Date.now() + timeoutMs;
        if (!(await waitForProviderSync(ctx.provider, timeoutMs))) return false;
        // The writer's socket gives no acknowledgement: ask the server, on a
        // second read-only connection, until its state covers the update.
        while (Date.now() < deadline) {
          const server = await readServerDoc(pageId, Math.max(1_000, Math.min(10_000, deadline - Date.now())));
          if (server) {
            const covered = stateVectorCovers(Y.encodeStateVector(server), want);
            server.destroy();
            if (covered) return true;
          }
          await sleep(500);
        }
        return false;
      });
    },
  };
}
