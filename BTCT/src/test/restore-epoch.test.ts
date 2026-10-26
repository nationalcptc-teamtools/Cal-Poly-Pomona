import { afterEach, describe, expect, it, vi } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import {
  decideEpochAction,
  isCacheDatabase,
  deleteCacheDatabases,
  prepareClientCaches,
  restoreEpochParams,
  checkRestoreEpochNow,
  resetRestoreEpochForTests,
  EPOCH_RECHECK_MS,
} from '@/realtime/restore-epoch';

function openDb(idb: IDBFactory, name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = idb.open(name, 1);
    req.onupgradeneeded = () => { req.result.createObjectStore('updates'); };
    req.onsuccess = () => { req.result.close(); resolve(); };
    req.onerror = () => reject(req.error);
  });
}

async function names(idb: IDBFactory): Promise<string[]> {
  return (await idb.databases()).map((d) => d.name ?? '').sort();
}

function serverSays(epoch: string | null | 'offline') {
  vi.stubGlobal('fetch', vi.fn(async () => {
    if (epoch === 'offline') throw new TypeError('network down');
    return new Response(JSON.stringify({ features: {}, restoreEpoch: epoch }), { status: 200 });
  }));
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  localStorage.clear();
});

describe('decideEpochAction', () => {
  it('keeps the cache when the server cannot be asked or was never restored', () => {
    expect(decideEpochAction('a', undefined)).toBe('keep');
    expect(decideEpochAction(null, null)).toBe('keep');
    expect(decideEpochAction('a', null)).toBe('keep');
  });
  it('keeps a matching cache and clears on any other epoch', () => {
    expect(decideEpochAction('a', 'a')).toBe('keep');
    expect(decideEpochAction('a', 'b')).toBe('clear');
    // A cache from before this client stored epochs predates the restore.
    expect(decideEpochAction(null, 'b')).toBe('clear');
  });
});

describe('isCacheDatabase', () => {
  it('matches only the app databases', () => {
    expect(isCacheDatabase('btct-btct-shared')).toBe(true);
    expect(isCacheDatabase('btct-page-123')).toBe(true);
    expect(isCacheDatabase('other-app')).toBe(false);
    expect(isCacheDatabase(undefined)).toBe(false);
  });
});

describe('prepareClientCaches', () => {
  it('deletes the btct-* databases after a restore and remembers the new epoch', async () => {
    const idb = new IDBFactory();
    vi.stubGlobal('indexedDB', idb);
    await openDb(idb, 'btct-btct-shared');
    await openDb(idb, 'btct-page-p1');
    await openDb(idb, 'unrelated');
    localStorage.setItem('btct.restoreEpoch', 'old');
    serverSays('new');
    await prepareClientCaches();
    expect(await names(idb)).toEqual(['unrelated']);
    expect(localStorage.getItem('btct.restoreEpoch')).toBe('new');
    expect(restoreEpochParams()).toEqual({ epoch: 'new' });
  });

  it('leaves a matching cache alone', async () => {
    const idb = new IDBFactory();
    vi.stubGlobal('indexedDB', idb);
    await openDb(idb, 'btct-btct-shared');
    localStorage.setItem('btct.restoreEpoch', 'same');
    serverSays('same');
    await prepareClientCaches();
    expect(await names(idb)).toEqual(['btct-btct-shared']);
    expect(restoreEpochParams()).toEqual({ epoch: 'same' });
  });

  it('keeps the cache offline and sends the stored epoch', async () => {
    const idb = new IDBFactory();
    vi.stubGlobal('indexedDB', idb);
    await openDb(idb, 'btct-btct-shared');
    localStorage.setItem('btct.restoreEpoch', 'stored');
    serverSays('offline');
    await prepareClientCaches();
    expect(await names(idb)).toEqual(['btct-btct-shared']);
    expect(restoreEpochParams()).toEqual({ epoch: 'stored' });
  });

  it('sends no epoch to a server that was never restored', async () => {
    vi.stubGlobal('indexedDB', new IDBFactory());
    serverSays(null);
    await prepareClientCaches();
    expect(restoreEpochParams()).toEqual({});
  });
});

describe('deleteCacheDatabases', () => {
  it('is a no-op without IndexedDB', async () => {
    expect(await deleteCacheDatabases(undefined)).toBe(0);
  });
});

describe('checkRestoreEpochNow (a websocket connect failed)', () => {
  afterEach(() => resetRestoreEpochForTests());

  it('reloads when the server moved to a new epoch, and asks at most once per interval', async () => {
    vi.stubGlobal('indexedDB', undefined);
    serverSays('e1');
    await prepareClientCaches();
    resetRestoreEpochForTests();
    serverSays('e1');
    await prepareClientCaches();
    const reload = vi.fn();
    expect(await checkRestoreEpochNow({ now: 1_000, reload })).toBe(false);
    expect(reload).not.toHaveBeenCalled();
    // The relay now answers 409: a restore moved the epoch on.
    serverSays('e2');
    expect(await checkRestoreEpochNow({ now: 1_000 + EPOCH_RECHECK_MS - 1, reload })).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
    expect(await checkRestoreEpochNow({ now: 1_000 + EPOCH_RECHECK_MS, reload })).toBe(true);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('does nothing while the server cannot be asked or was never restored', async () => {
    const reload = vi.fn();
    serverSays('offline');
    expect(await checkRestoreEpochNow({ now: 0, reload })).toBe(false);
    serverSays(null);
    expect(await checkRestoreEpochNow({ now: EPOCH_RECHECK_MS, reload })).toBe(false);
    expect(reload).not.toHaveBeenCalled();
  });
});
