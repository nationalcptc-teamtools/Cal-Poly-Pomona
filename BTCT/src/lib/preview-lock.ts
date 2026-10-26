// ─────────────────────────────────────────────────────────────────────────
// Report preview lock, per account and per workspace.
//
// A locked preview ignores clicks for navigation: no jump to the code and no
// asset reveal, so the rendered report can be read, selected and copied
// freely. It is a viewing preference of one operator, never workspace data:
// it lives in this browser's localStorage under a key that carries the
// account id, so two people who share a browser keep separate locks, and it
// never touches the shared Yjs doc, so a teammate's preview is unaffected.
//
// The value is the list of locked workspace ids. A workspace that is not in
// it is unlocked, which is the default.
// ─────────────────────────────────────────────────────────────────────────

const KEY_PREFIX = 'btct.typst.previewLock.v1.';

/** Upper bound on stored ids, so a long-lived browser cannot grow the entry without limit. */
export const MAX_LOCKED_WORKSPACES = 200;

/** The localStorage key for one account's locks. */
export function previewLockKey(userId: number | string): string {
  return `${KEY_PREFIX}${userId}`;
}

function defaultStorage(): Storage | null {
  try { return typeof localStorage === 'undefined' ? null : localStorage; } catch { return null; }
}

/** The workspace ids `userId` has locked. Anything unreadable reads as "none". */
export function loadLockedWorkspaces(userId: number | string | null | undefined, storage: Storage | null = defaultStorage()): Set<string> {
  if (userId === null || userId === undefined || !storage) return new Set();
  try {
    const raw = storage.getItem(previewLockKey(userId));
    const parsed: unknown = raw ? JSON.parse(raw) : null;
    if (!Array.isArray(parsed)) return new Set();
    return new Set(parsed.filter((id): id is string => typeof id === 'string' && id.length > 0));
  } catch {
    return new Set();
  }
}

/** Store `userId`'s locks. Without an account there is nobody to key them on, so nothing is written. */
export function saveLockedWorkspaces(userId: number | string | null | undefined, locked: ReadonlySet<string>, storage: Storage | null = defaultStorage()): void {
  if (userId === null || userId === undefined || !storage) return;
  try {
    const key = previewLockKey(userId);
    if (locked.size === 0) { storage.removeItem(key); return; }
    // Newest last, so a capped list drops the oldest locks first.
    storage.setItem(key, JSON.stringify([...locked].slice(-MAX_LOCKED_WORKSPACES)));
  } catch { /* private mode, quota: the lock still holds for this session */ }
}

/** A new set with `workspaceId` flipped. */
export function toggleLocked(locked: ReadonlySet<string>, workspaceId: string): Set<string> {
  const next = new Set(locked);
  if (next.has(workspaceId)) next.delete(workspaceId); else next.add(workspaceId);
  return next;
}

/** Whether a `storage` event is about `userId`'s locks (another tab of the same account). */
export function isPreviewLockKey(key: string | null, userId: number | string | null | undefined): boolean {
  return key !== null && userId !== null && userId !== undefined && key === previewLockKey(userId);
}
