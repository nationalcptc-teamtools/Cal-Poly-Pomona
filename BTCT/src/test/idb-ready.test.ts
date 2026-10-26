import { describe, expect, it, vi } from 'vitest';
import type { IndexeddbPersistence } from 'y-indexeddb';
import { whenIdbLoaded } from '@/realtime/idb-ready';

// CLI-12 / C14: a blocked IndexedDB must not leave the app on "Connecting...".
function fakePersistence(opts: { open: Promise<unknown>; synced?: Promise<unknown>; db?: unknown }) {
  return {
    _db: opts.open,
    db: opts.db ?? null,
    whenSynced: opts.synced ?? new Promise(() => {}),
  } as unknown as IndexeddbPersistence;
}

describe('whenIdbLoaded', () => {
  it('resolves false at once when the open fails', async () => {
    const onUnavailable = vi.fn();
    const open = Promise.reject(new Error('blocked'));
    open.catch(() => undefined);
    await expect(whenIdbLoaded(fakePersistence({ open }), onUnavailable, 10_000)).resolves.toBe(false);
    expect(onUnavailable).toHaveBeenCalledOnce();
    expect(onUnavailable).toHaveBeenCalledWith('failed');
  });

  it('names a slow open a timeout, not a failure, so a busy import raises no storage banner', async () => {
    vi.useFakeTimers();
    const onUnavailable = vi.fn();
    const p = whenIdbLoaded(fakePersistence({ open: new Promise(() => {}) }), onUnavailable, 3000);
    await vi.advanceTimersByTimeAsync(3000);
    await expect(p).resolves.toBe(false);
    expect(onUnavailable).toHaveBeenCalledWith('timeout');
    vi.useRealTimers();
  });

  it('resolves false when the database never opens', async () => {
    vi.useFakeTimers();
    const p = whenIdbLoaded(fakePersistence({ open: new Promise(() => {}) }), undefined, 3000);
    await vi.advanceTimersByTimeAsync(3000);
    await expect(p).resolves.toBe(false);
    vi.useRealTimers();
  });

  it('keeps waiting for a database that opened and is still loading', async () => {
    vi.useFakeTimers();
    let done!: () => void;
    const synced = new Promise<void>((r) => { done = r; });
    const p = whenIdbLoaded(fakePersistence({ open: Promise.resolve({}), synced, db: {} }), undefined, 3000);
    await vi.advanceTimersByTimeAsync(10_000);
    done();
    await expect(p).resolves.toBe(true);
    vi.useRealTimers();
  });
});
