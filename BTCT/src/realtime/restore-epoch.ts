/**
 * Restore epoch: keeps a server restore from being undone by browser caches.
 *
 * Every Yjs doc this client opens is also cached in IndexedDB (`btct-*`
 * databases). A Yjs merge is a union, so after an admin restores the server
 * to an earlier backup, the first browser that reconnects with a newer cache
 * would push the post-backup edits (and deletions) straight back in.
 *
 * `server/restore.mjs` therefore writes a new `restore_epoch` whenever it
 * rolls rooms back, and `GET /api/settings` reports it as `restoreEpoch`.
 * Before any IndexedDB-backed doc is opened (`main.tsx` awaits
 * `prepareClientCaches()` before the first render), the client compares it
 * with the epoch it stored last time and, on a mismatch, deletes its `btct-*`
 * databases first. The websocket sends the accepted epoch (`epoch` query
 * param) and the relay refuses any other while an epoch is set, so a tab that
 * stayed open across the restore cannot sync its old state either; it
 * reloads as soon as it notices (poll, or a message from a fresh tab).
 *
 * Restoring with `--keep-browser-caches` keeps the epoch, so caches DO merge
 * back in: that is a recovery onto a new box, where the caches refill
 * whatever changed after the backup.
 */
import { pollWhileVisible } from '@/lib/visible-poll';

const STORAGE_KEY = 'btct.restoreEpoch';
const CHANNEL = 'btct-restore-epoch';
const FETCH_TIMEOUT_MS = 2500;
const POLL_MS = 30_000;
/** A refused websocket asks for the epoch at most this often. */
export const EPOCH_RECHECK_MS = 5_000;

export type EpochAction = 'keep' | 'clear';

/**
 * What to do with the local caches. `server` is undefined when the server
 * could not be asked (offline, slow): keep everything and work offline.
 * A server without an epoch has never been rolled back.
 */
export function decideEpochAction(stored: string | null, server: string | null | undefined): EpochAction {
  if (!server) return 'keep';
  return stored === server ? 'keep' : 'clear';
}

/** The IndexedDB databases y-indexeddb creates for this app. */
export function isCacheDatabase(name: string | null | undefined): boolean {
  return typeof name === 'string' && name.startsWith('btct-');
}

let accepted: string | null = null;
let seenAtStart: string | null = null;

/** Extra websocket params for every provider: the epoch this client's cache matches. */
export function restoreEpochParams(): Record<string, string> {
  return accepted ? { epoch: accepted } : {};
}

function apiBase(): string {
  const env = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, '');
  if (env) return env;
  return typeof window === 'undefined' ? '' : window.location.origin;
}

function readStored(): string | null {
  try { return localStorage.getItem(STORAGE_KEY); } catch { return null; }
}

function writeStored(epoch: string): void {
  try { localStorage.setItem(STORAGE_KEY, epoch); } catch { /* private mode: the check repeats next load */ }
}

/** The server's epoch, null when it has none, undefined when it could not be asked. */
export async function fetchServerEpoch(): Promise<string | null | undefined> {
  const ctl = typeof AbortController === 'undefined' ? null : new AbortController();
  const timer = setTimeout(() => ctl?.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(`${apiBase()}/api/settings`, { signal: ctl?.signal, cache: 'no-store' });
    if (!res.ok) return undefined;
    const body = (await res.json()) as { restoreEpoch?: unknown };
    return typeof body?.restoreEpoch === 'string' && body.restoreEpoch ? body.restoreEpoch : null;
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

function deleteDatabase(idb: IDBFactory, name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = idb.deleteDatabase(name);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    // onblocked: another tab still has it open. y-indexeddb closes on
    // versionchange and that tab reloads on our broadcast, so just wait.
  });
}

/** Delete every `btct-*` IndexedDB database. Returns how many were removed. */
export async function deleteCacheDatabases(idb: IDBFactory | undefined = globalThis.indexedDB): Promise<number> {
  if (!idb) return 0;
  let names: string[];
  if (typeof idb.databases === 'function') {
    names = (await idb.databases()).map((d) => d.name).filter(isCacheDatabase) as string[];
  } else {
    // No enumeration (very old browsers): the shared doc is the one that
    // holds records and deletions; page caches remain until site data is cleared.
    names = ['btct-btct-shared'];
  }
  await Promise.all(names.map((n) => deleteDatabase(idb, n)));
  return names.length;
}

function announce(epoch: string): void {
  try {
    const bc = new BroadcastChannel(CHANNEL);
    bc.postMessage({ epoch });
    bc.close();
  } catch { /* no BroadcastChannel: other tabs notice on their next poll */ }
}

/**
 * Run once at startup, before anything opens a Yjs doc. Never throws; on any
 * doubt it keeps the cache (offline work must keep working).
 */
export async function prepareClientCaches(): Promise<void> {
  const stored = readStored();
  accepted = stored;
  seenAtStart = stored;
  const server = await fetchServerEpoch();
  if (server === undefined) return;
  seenAtStart = server;
  if (decideEpochAction(stored, server) === 'clear' && server) {
    announce(server);
    try {
      const n = await deleteCacheDatabases();
      console.info(`[btct] the server was restored from a backup; cleared ${n} cached database(s).`);
    } catch (e) {
      // Keep the old epoch: the relay refuses this tab rather than letting
      // the stale cache merge back in, and the next load tries again.
      console.warn('[btct] the server was restored, but the local cache could not be cleared:', e);
      return;
    }
    writeStored(server);
  }
  if (server) accepted = server;
}

/**
 * Reload this tab when the server's epoch moves on (a restore while the tab
 * was open) or another tab reports a newer one. Returns a stop function.
 */
function reloadIfNew(epoch: string | null | undefined, reload: () => void = () => window.location.reload()): boolean {
  if (epoch && epoch !== seenAtStart) { reload(); return true; }
  return false;
}

let lastRecheck = Number.NEGATIVE_INFINITY;
let rechecking = false;

/**
 * Ask for the epoch now, because a websocket connect just failed. The relay
 * answers 409 to a stale epoch, but a browser's WebSocket cannot read the
 * status of a refused upgrade, so without this a tab open across a restore
 * waited for the 30 s poll. Rate-limited to one request per
 * EPOCH_RECHECK_MS; resolves true when it reloads.
 */
export async function checkRestoreEpochNow(
  { now = Date.now(), reload }: { now?: number; reload?: () => void } = {},
): Promise<boolean> {
  if (rechecking || now - lastRecheck < EPOCH_RECHECK_MS) return false;
  lastRecheck = now;
  rechecking = true;
  try {
    return reloadIfNew(await fetchServerEpoch(), reload);
  } finally {
    rechecking = false;
  }
}

/** Test hook: forget the rate limit and the epoch seen at start. */
export function resetRestoreEpochForTests(): void {
  lastRecheck = Number.NEGATIVE_INFINITY;
  rechecking = false;
  accepted = null;
  seenAtStart = null;
}

export function watchRestoreEpoch(): () => void {
  let bc: BroadcastChannel | null = null;
  try {
    bc = new BroadcastChannel(CHANNEL);
    bc.onmessage = (e: MessageEvent<{ epoch?: string }>) => { reloadIfNew(e.data?.epoch); };
  } catch { bc = null; }
  const stopPoll = pollWhileVisible(async () => { reloadIfNew(await fetchServerEpoch()); }, POLL_MS);
  return () => { stopPoll(); bc?.close(); };
}
