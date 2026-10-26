/**
 * Wait for a y-indexeddb persistence to load, without hanging when the
 * database cannot open.
 *
 * y-indexeddb resolves `whenSynced` only from inside `openDB().then(...)` and
 * has no rejection path, so a blocked or broken IndexedDB (site data blocked,
 * profile out of disk, a corrupt profile) left every `whenSynced` pending and
 * the shell on "Connecting..." for good. This resolves `false` when the open
 * fails, or when the database has still not opened after `openTimeoutMs`; the
 * caller then runs from memory and the server. A database that opened but is
 * still reading a large cache is waited for: giving up then would let the app
 * seed Y.Texts on top of state that is about to arrive (invariant #1).
 */
import type { IndexeddbPersistence } from 'y-indexeddb';

export const IDB_OPEN_TIMEOUT_MS = 3000;

/**
 * Why a cache was given up on: the open failed (IndexedDB is blocked or
 * broken), or it had not opened in time. Only the first is evidence that
 * storage is unavailable. A slow open is often just load: a workspace import
 * opens about 300 page databases four at a time, and Firefox let one of them
 * cross 3 s, which used to raise the global "Offline cache unavailable"
 * banner until a reload.
 */
export type IdbUnavailableReason = 'failed' | 'timeout';

export function whenIdbLoaded(
  persistence: IndexeddbPersistence,
  onUnavailable?: (reason: IdbUnavailableReason) => void,
  openTimeoutMs = IDB_OPEN_TIMEOUT_MS,
): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    let done = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (ok: boolean, reason: IdbUnavailableReason = 'failed') => {
      if (done) return;
      done = true;
      if (timer !== undefined) clearTimeout(timer);
      if (!ok) onUnavailable?.(reason);
      resolve(ok);
    };
    persistence.whenSynced.then(() => finish(true), () => finish(false));
    const opening = (persistence as unknown as { _db?: Promise<unknown> })._db;
    if (opening && typeof opening.then === 'function') opening.then(undefined, () => finish(false));
    timer = setTimeout(() => { if (!persistence.db) finish(false, 'timeout'); }, openTimeoutMs);
  });
}
