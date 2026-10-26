import * as Y from 'yjs';
import { IndexeddbPersistence } from 'y-indexeddb';
import { WebsocketProvider } from 'y-websocket';
import type { Awareness } from 'y-protocols/awareness';
import { useAuthStore, WS_URL } from '@/auth/auth-store';
import { restoreEpochParams } from './restore-epoch';
import { attachUserMapping } from './page-history-api';
import { markIdbUnavailable } from './connection-status';
import { whenIdbLoaded } from './idb-ready';

export interface PageYContext {
  doc: Y.Doc;
  persistence: IndexeddbPersistence;
  provider: WebsocketProvider;
  awareness: Awareness;
  unsubscribeAuth: () => void;
  /** IndexedDB has loaded (or could not open, see `idbReady`). */
  whenSynced: Promise<void>;
  /** True once IndexedDB loaded; false if it could not open (memory-only). */
  idbReady: Promise<boolean>;
  /** IndexedDB and initial server sync, with a 3s offline fallback. */
  whenFullySynced: Promise<void>;
}
interface Entry {
  ctx: PageYContext;
  leases: number;
  closing: boolean;
  destroyed: boolean;
  cancelSync: () => void;
  /** The doc changed since it loaded (or since the last offline save). */
  dirty: boolean;
  /** IndexedDB could not open for this page. */
  memoryOnly: boolean;
  stopDirtyWatch: () => void;
}
const cache = new Map<string, Entry>();
let openPages = new Set<string>();

function applyAwarenessUser(awareness: Awareness): void {
  const user = useAuthStore.getState().user;
  awareness.setLocalStateField('user', user ? { id: user.id, name: user.username, color: user.color } : null);
}

/** Keep open page/history tabs, including those behind the selected tab. */
export function syncOpenPageDocs(pageIds: Iterable<string>): void {
  openPages = new Set(pageIds);
  for (const [id, entry] of cache) scheduleRelease(id, entry);
}
function unused(id: string, entry: Entry): boolean {
  return !openPages.has(id) && entry.leases === 0 && !entry.destroyed && cache.get(id) === entry;
}

/**
 * Save the page to its offline cache before the context closes, in ONE
 * IndexedDB transaction that commits before we resolve.
 *
 * It used to append a full state record on every close (and y-indexeddb adds
 * another on every open), with nothing trimming them until a live edit pushed
 * the store past 500 records, so a page reopened often built up hundreds of
 * full copies and every open read and applied them all. Now:
 * - a doc that did not change since it loaded writes nothing;
 * - otherwise the transaction reads every stored record (applying any this
 *   doc has not seen, such as another tab's), writes one full state, and
 *   deletes the records that state replaces.
 * The persistent cache itself is never deleted.
 */
export function persistBeforeClose(ctx: Pick<PageYContext, 'doc' | 'persistence'>, dirty = true): Promise<void> {
  const db = ctx.persistence.db;
  if (!db) return Promise.reject(new Error('Page offline cache is unavailable'));
  if (!dirty) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('updates', 'readwrite');
    const store = tx.objectStore('updates');
    const keysReq = store.getAllKeys();
    const valsReq = store.getAll();
    valsReq.onsuccess = () => {
      const keys = keysReq.result as IDBValidKey[];
      const vals = valsReq.result as Uint8Array[];
      if (!ctx.doc.isDestroyed && vals.length > 0) {
        // Origin = the persistence, so y-indexeddb does not store these again.
        Y.transact(ctx.doc, () => { for (const v of vals) Y.applyUpdate(ctx.doc, v); }, ctx.persistence, false);
      }
      store.add(Y.encodeStateAsUpdate(ctx.doc));
      const last = keys[keys.length - 1];
      if (last !== undefined) store.delete(IDBKeyRange.upperBound(last));
    };
    tx.oncomplete = () => resolve();
    tx.onabort = tx.onerror = () => reject(tx.error ?? new Error('Could not save page offline'));
  });
}

/**
 * Whether a context may be dropped. With an offline cache: once the save
 * committed. Without one (IndexedDB could not open), only while the server
 * link is up and synced, since the server then holds every edit; otherwise
 * the doc stays in memory and a later tab change retries.
 */
async function saveForClose(entry: Entry): Promise<void> {
  if (entry.memoryOnly) {
    if (!entry.ctx.provider.wsconnected || !entry.ctx.provider.synced) {
      throw new Error('Page has unsynced edits and no offline cache');
    }
    return;
  }
  await persistBeforeClose(entry.ctx, needsSave(entry));
  entry.dirty = false;
}

/**
 * Worth a write: the doc changed, or the store holds more records than one
 * compacted state plus the small one y-indexeddb adds on every open.
 */
const COMPACT_ABOVE_RECORDS = 2;
function needsSave(entry: Entry): boolean {
  const stored = (entry.ctx.persistence as unknown as { _dbsize?: number })._dbsize ?? 0;
  return entry.dirty || stored > COMPACT_ABOVE_RECORDS;
}
function destroy(entry: Entry): void {
  entry.destroyed = true;
  entry.cancelSync();
  entry.stopDirtyWatch();
  entry.ctx.unsubscribeAuth();
  entry.ctx.provider.destroy();
  void entry.ctx.persistence.destroy().catch(() => undefined);
  entry.ctx.doc.destroy();
}
function scheduleRelease(id: string, entry: Entry): void {
  if (!unused(id, entry) || entry.closing) return;
  entry.closing = true;
  // Let React detach the editor. Also absorb StrictMode and split-pane moves.
  setTimeout(() => {
    void (async () => {
      try {
        await entry.ctx.whenFullySynced;
        if (!unused(id, entry)) return;
        await saveForClose(entry);
        if (!unused(id, entry)) return;
        cache.delete(id);
        destroy(entry);
      } catch (error) {
        // Preserve unsaved work if IndexedDB is full/blocked. Later tab changes retry.
        console.warn('[page-cache] Could not release a page safely:', error);
      } finally {
        entry.closing = false;
      }
    })();
  }, 0);
}

/** Temporary callers use withPageYContext to hold the document through their work. */
export function getPageYContext(pageId: string): PageYContext {
  const cached = cache.get(pageId);
  if (cached) return cached.ctx;
  const doc = new Y.Doc();
  const persistence = new IndexeddbPersistence(`btct-page-${pageId}`, doc);
  const provider = new WebsocketProvider(`${WS_URL}/yjs`, pageId, doc, {
    params: { token: useAuthStore.getState().token ?? '', ...restoreEpochParams() }, connect: true,
  });
  const awareness = provider.awareness;
  applyAwarenessUser(awareness);
  const unsubscribeAuth = useAuthStore.subscribe((state, prev) => {
    if (state.user !== prev.user) {
      applyAwarenessUser(awareness);
      if (state.user && !doc.isDestroyed) attachUserMapping(doc);
    }
  });
  let cancelSync = () => {};
  const whenWsSynced = new Promise<void>((resolve) => {
    const finish = () => { clearTimeout(timer); provider.off('sync', onSync); resolve(); };
    const onSync = (synced: boolean) => { if (synced) finish(); };
    const timer = setTimeout(finish, 3000);
    cancelSync = finish;
    if (provider.synced) finish();
    else provider.on('sync', onSync);
  });
  let entry: Entry | null = null;
  const idbReady = whenIdbLoaded(persistence, (reason) => {
    if (entry) entry.memoryOnly = true;
    // A page database that failed to open says storage is blocked. One that
    // is only slow (many opening at once, as in a workspace import) says
    // nothing about the others: this context goes on from memory and the
    // server, and uses the cache again if it opens after all. The shared
    // doc's own check still raises the banner for a store that never opens.
    if (reason === 'failed') {
      markIdbUnavailable();
      return;
    }
    persistence.whenSynced.then(() => { if (entry && !entry.destroyed) entry.memoryOnly = false; }, () => {});
  });
  const whenSynced = idbReady.then(() => undefined);
  const whenFullySynced = Promise.all([whenSynced, whenWsSynced]).then(() => undefined);
  const ctx: PageYContext = { doc, persistence, provider, awareness, unsubscribeAuth, whenSynced, idbReady, whenFullySynced };
  // Anything but the cache's own replay makes the next close worth saving.
  const onUpdate = (_u: Uint8Array, origin: unknown) => { if (origin !== persistence && entry) entry.dirty = true; };
  doc.on('update', onUpdate);
  entry = {
    ctx, leases: 0, closing: false, destroyed: false, cancelSync,
    dirty: false, memoryOnly: false, stopDirtyWatch: () => doc.off('update', onUpdate),
  };
  cache.set(pageId, entry);
  const created = entry;
  void whenFullySynced.then(() => { if (!created.destroyed) attachUserMapping(doc); });
  scheduleRelease(pageId, created);
  return ctx;
}
/** Hold a document until an editor has detached or a temporary operation finishes. */
export function retainPageYContext(pageId: string): () => void {
  getPageYContext(pageId);
  const entry = cache.get(pageId)!;
  entry.leases++;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    entry.leases--;
    scheduleRelease(pageId, entry);
  };
}
export async function withPageYContext<T>(pageId: string, work: (ctx: PageYContext) => T | Promise<T>): Promise<T> {
  const release = retainPageYContext(pageId);
  try { return await work(getPageYContext(pageId)); }
  finally { release(); }
}

/** Detach network access immediately at logout; save before freeing the old doc. */
export function disposeAllPageDocs(): void {
  const entries = [...cache.values()];
  cache.clear();
  openPages.clear();
  for (const entry of entries) {
    entry.ctx.unsubscribeAuth();
    entry.ctx.provider.disconnect();
    entry.cancelSync();
    void entry.ctx.whenSynced.then(() => (entry.memoryOnly ? undefined : persistBeforeClose(entry.ctx, needsSave(entry))))
      .catch((error) => console.warn('[page-cache] Offline save failed during logout:', error))
      .finally(() => destroy(entry));
  }
}

/**
 * Resolve once the page's provider has really synced with the server (no
 * timer fallback), or reject after `timeoutMs`. The relay answers sync only
 * after the room's stored state has loaded (invariant #20), so this is the
 * point where an empty fragment means an empty page. Rewrites that replace
 * the body (a version restore) must wait for it: on the 3 s fallback of
 * `whenFullySynced` they act on an empty doc and the real body merges back in.
 */
export function whenServerSynced(ctx: Pick<PageYContext, 'provider'>, timeoutMs = 15_000): Promise<void> {
  const provider = ctx.provider;
  if (provider.synced) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const onSync = (synced: boolean) => {
      if (!synced) return;
      clearTimeout(timer);
      provider.off('sync', onSync);
      resolve();
    };
    const timer = setTimeout(() => {
      provider.off('sync', onSync);
      reject(new Error('the page has not synced with the server yet'));
    }, timeoutMs);
    provider.on('sync', onSync);
  });
}
