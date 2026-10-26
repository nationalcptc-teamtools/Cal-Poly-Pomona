import { describe, it, expect, afterEach } from 'vitest';
import * as Y from 'yjs';
import { createRelayPersistence, mergeUpdatesBounded, type RelayPersistence } from '../../server/relay-persistence.mjs';

// A stand-in for y-leveldb: one serial queue for every room, each stored
// update its own entry, and a failing write resolving null (that is what
// y-leveldb's queue does with an error).
function fakeLdb() {
  const entries = new Map<string, Uint8Array[]>();
  const fake = {
    entries,
    failWrites: false,
    failReads: false,
    writes: 0,
    compactions: 0,
    tr: Promise.resolve() as Promise<unknown>,
    _transact<T>(f: () => Promise<T> | T): Promise<T | null> {
      const prev = fake.tr;
      const next = (async () => {
        await prev;
        try { return await f(); } catch { return null; }
      })();
      fake.tr = next;
      return next;
    },
    getYDoc(name: string) {
      return fake._transact(async () => {
        if (fake.failReads) throw new Error('read failed');
        const doc = new Y.Doc();
        for (const u of entries.get(name) ?? []) Y.applyUpdate(doc, u);
        return doc;
      });
    },
    storeUpdate(name: string, update: Uint8Array) {
      return fake._transact(async () => {
        if (fake.failWrites) throw new Error('ENOSPC');
        const list = entries.get(name) ?? [];
        list.push(update);
        entries.set(name, list);
        fake.writes++;
        return list.length - 1;
      });
    },
    flushDocument(name: string) {
      return fake._transact(async () => {
        const list = entries.get(name) ?? [];
        entries.set(name, [Y.mergeUpdates(list)]);
        fake.compactions++;
      });
    },
  };
  return fake;
}

function textOf(updates: Uint8Array[] | undefined) {
  const doc = new Y.Doc();
  for (const u of updates ?? []) Y.applyUpdate(doc, u);
  const s = doc.getText('t').toString();
  doc.destroy();
  return s;
}

const silent = { error: () => {}, warn: () => {} };
const quiet: RelayPersistence[] = [];

function make(ldb: ReturnType<typeof fakeLdb>, extra: Record<string, unknown> = {}) {
  const p = createRelayPersistence({ ldb, Y, flushMs: 20, retryMs: 30, compactMs: 0, log: silent, ...extra });
  quiet.push(p);
  return p;
}

type LoadedDoc = Y.Doc & { whenLoaded: Promise<void>; loaded?: boolean };

afterEach(async () => {
  while (quiet.length) await quiet.pop()!.close();
});

describe('relay persistence', () => {
  it('loads the stored state before whenLoaded resolves and does not store it again', async () => {
    const ldb = fakeLdb();
    const seed = new Y.Doc();
    seed.getText('t').insert(0, 'stored body');
    ldb.entries.set('room', [Y.encodeStateAsUpdate(seed)]);
    const p = make(ldb);
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    expect(doc.loaded).toBeFalsy();
    await doc.whenLoaded;
    expect(doc.loaded).toBe(true);
    expect(doc.getText('t').toString()).toBe('stored body');
    await p.drain();
    expect(ldb.writes).toBe(0);
  });

  it('coalesces a burst of updates into one stored entry', async () => {
    const ldb = fakeLdb();
    const p = make(ldb);
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    await doc.whenLoaded;
    for (let i = 0; i < 200; i++) doc.getText('t').insert(i, 'x');
    await p.drain();
    expect(ldb.writes).toBe(1);
    expect(textOf(ldb.entries.get('room'))).toBe('x'.repeat(200));
  });

  it('writes a long buffer as a diff from the doc, not a merge, and never restores the stored state', async () => {
    const ldb = fakeLdb();
    const seed = new Y.Doc();
    seed.getText('t').insert(0, 'S'.repeat(5000));
    ldb.entries.set('room', [Y.encodeStateAsUpdate(seed)]);
    const p = make(ldb);
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    await doc.whenLoaded;
    const other = new Y.Doc();
    Y.applyUpdate(other, Y.encodeStateAsUpdate(doc));
    // Two writers and a delete, one transaction per keystroke.
    for (let i = 0; i < 3000; i++) doc.getText('t').insert(0, 'a');
    other.on('update', (u: Uint8Array) => Y.applyUpdate(doc, u, 'remote'));
    for (let i = 0; i < 3000; i++) other.getText('t').insert(other.getText('t').length, 'b');
    doc.getText('t').delete(0, 10);
    await p.drain();
    const stored = ldb.entries.get('room')!;
    expect(stored.length).toBeGreaterThanOrEqual(2);
    // The new entries carry the 6000 inserts, not the 5000 stored ones again.
    const fresh = new Y.Doc();
    for (const u of stored.slice(1)) Y.applyUpdate(fresh, u);
    expect(fresh.getText('t').toString()).not.toContain('S');
    expect(textOf(stored)).toBe(doc.getText('t').toString());
    expect(textOf(stored)).toBe('a'.repeat(2990) + 'S'.repeat(5000) + 'b'.repeat(3000));
  });

  it('flushes on a count of buffered updates, not only on bytes or time', async () => {
    const ldb = fakeLdb();
    const p = make(ldb, { flushMs: 60_000, maxPendingUpdates: 100 });
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    await doc.whenLoaded;
    for (let i = 0; i < 250; i++) doc.getText('t').insert(i, 'x');
    await ldb.tr;
    await new Promise((r) => setTimeout(r, 0));
    expect(ldb.writes).toBeGreaterThanOrEqual(1);
    await p.drain();
    expect(textOf(ldb.entries.get('room'))).toBe('x'.repeat(250));
  });

  it('a long buffer that began before the load is merged and stored whole', async () => {
    const ldb = fakeLdb();
    const seed = new Y.Doc();
    seed.getText('t').insert(0, 'stored');
    ldb.entries.set('room', [Y.encodeStateAsUpdate(seed)]);
    const p = make(ldb);
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    for (let i = 0; i < 300; i++) doc.getMap('m').set(`k${i}`, i);
    await doc.whenLoaded;
    for (let i = 0; i < 300; i++) doc.getText('t').insert(0, 'z');
    await p.drain();
    const back = new Y.Doc();
    for (const u of ldb.entries.get('room')!) Y.applyUpdate(back, u);
    expect(back.getMap('m').size).toBe(300);
    expect(back.getText('t').toString()).toBe('z'.repeat(300) + 'stored');
  });

  it('mergeUpdatesBounded gives the same document as one merge', () => {
    const doc = new Y.Doc();
    const updates: Uint8Array[] = [];
    doc.on('update', (u: Uint8Array) => updates.push(u));
    for (let i = 0; i < 1000; i++) doc.getText('t').insert(i % 7, String(i % 10));
    doc.getText('t').delete(3, 50);
    const a = new Y.Doc();
    Y.applyUpdate(a, mergeUpdatesBounded(Y, updates, 16)!);
    expect(a.getText('t').toString()).toBe(doc.getText('t').toString());
    expect(mergeUpdatesBounded(Y, [])).toBeNull();
  });

  it('keeps an update written before the load finished', async () => {
    const ldb = fakeLdb();
    const p = make(ldb);
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    doc.getText('t').insert(0, 'early');
    await doc.whenLoaded;
    await p.drain();
    expect(textOf(ldb.entries.get('room'))).toBe('early');
  });

  it('writeState stores the buffer at once, ahead of the room loading again', async () => {
    const ldb = fakeLdb();
    const p = make(ldb, { flushMs: 60_000 });
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    await doc.whenLoaded;
    doc.getText('t').insert(0, 'closing');
    const closing = p.writeState('room', doc);
    // The room reopens before the close write has finished.
    const again = new Y.Doc() as LoadedDoc;
    p.bindState('room', again);
    await closing;
    await again.whenLoaded;
    expect(again.getText('t').toString()).toBe('closing');
  });

  it('stores at once an update that reaches a room after writeState, ahead of a reload and in drain', async () => {
    // y-websocket's broadcast runs before this binding's update listener; a
    // send to a socket that already closed calls closeConn, which hands the
    // room to writeState with an empty buffer. The update arrives after.
    const ldb = fakeLdb();
    const p = make(ldb, { flushMs: 60_000 });
    const doc = new Y.Doc() as LoadedDoc;
    let closeOnUpdate = false;
    let closing: Promise<void> | null = null;
    doc.on('update', () => { if (closeOnUpdate && !closing) closing = p.writeState('room', doc); });
    p.bindState('room', doc);
    await doc.whenLoaded;
    closeOnUpdate = true;
    doc.getText('t').insert(0, 'last edit');
    expect(closing).not.toBeNull();
    // A second client loads the room before any timer could fire.
    const again = new Y.Doc() as LoadedDoc;
    p.bindState('room', again);
    await again.whenLoaded;
    expect(again.getText('t').toString()).toBe('last edit');
    expect(p.status().inflight + ldb.writes).toBeGreaterThan(0);
    await closing;
    doc.destroy();
    again.destroy();
    expect(await p.drain()).toBe(true);
    expect(textOf(ldb.entries.get('room'))).toBe('last edit');
  });

  it('drain stores an update that reached a closed room even with a long flush interval', async () => {
    const ldb = fakeLdb();
    const p = make(ldb, { flushMs: 60_000 });
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    await doc.whenLoaded;
    await p.writeState('room', doc);
    doc.getText('t').insert(0, 'late');
    expect(await p.drain()).toBe(true);
    await p.close();
    expect(textOf(ldb.entries.get('room'))).toBe('late');
  });

  it('stays failing after a failed write until the log is sealed, and seals again if a failure overtakes the seal', async () => {
    const ldb = fakeLdb();
    const seals: Array<(ok: boolean) => void> = [];
    let auto = false;
    const sealLog = () => (auto ? Promise.resolve(true) : new Promise<boolean>((resolve) => { seals.push(resolve); }));
    const p = make(ldb, { sealLog, retryMs: 10 });
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    await doc.whenLoaded;
    ldb.failWrites = true;
    doc.getText('t').insert(0, 'a');
    await p.drain().catch(() => false);
    expect(p.status().failing).toBe(true);
    // The disk is freed: the retry writes the full state and succeeds, but
    // the status stays failing while the seal runs.
    ldb.failWrites = false;
    await new Promise((r) => setTimeout(r, 40));
    expect(ldb.writes).toBeGreaterThan(0);
    expect(seals.length).toBe(1);
    expect(p.status().failing).toBe(true);
    expect(p.status().sealing).toBe(true);
    // A failure while the seal runs: this seal does not count.
    ldb.failWrites = true;
    doc.getText('t').insert(1, 'b');
    await new Promise((r) => setTimeout(r, 40));
    ldb.failWrites = false;
    seals[0]!(true);
    await new Promise((r) => setTimeout(r, 60));
    expect(p.status().failing).toBe(true);
    expect(seals.length).toBeGreaterThanOrEqual(2);
    // A seal that fails keeps it failing too.
    seals[seals.length - 1]!(false);
    await new Promise((r) => setTimeout(r, 60));
    expect(p.status().failing).toBe(true);
    // Then a clean seal ends it.
    auto = true;
    for (const s of seals) s(true);
    expect(await p.drain()).toBe(true);
    expect(p.status().failing).toBe(false);
    expect(textOf(ldb.entries.get('room'))).toBe('ab');
  });

  it('reports a failing write, keeps the data and stores it once writes work again', async () => {
    const ldb = fakeLdb();
    const p = make(ldb);
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    await doc.whenLoaded;
    ldb.failWrites = true;
    doc.getText('t').insert(0, 'kept');
    expect(await p.drain()).toBe(false);
    expect(p.status().failing).toBe(true);
    expect(p.status().failures).toBeGreaterThan(0);
    ldb.failWrites = false;
    await new Promise((r) => setTimeout(r, 80));
    await p.drain();
    expect(p.status().failing).toBe(false);
    expect(textOf(ldb.entries.get('room'))).toBe('kept');
  });

  it('keeps the state of a room that closed while failing and puts it back when it reopens', async () => {
    const ldb = fakeLdb();
    const p = make(ldb, { retryMs: 60_000 });
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    await doc.whenLoaded;
    ldb.failWrites = true;
    doc.getText('t').insert(0, 'orphan');
    await p.writeState('room', doc);
    doc.destroy();
    expect(p.status().unsavedClosedRooms).toBe(1);
    ldb.failWrites = false;
    const again = new Y.Doc() as LoadedDoc;
    p.bindState('room', again);
    await again.whenLoaded;
    expect(again.getText('t').toString()).toBe('orphan');
    expect(await p.drain()).toBe(true);
    expect(p.status().unsavedClosedRooms).toBe(0);
    expect(textOf(ldb.entries.get('room'))).toBe('orphan');
  });

  it('rejects whenLoaded when the stored state cannot be read', async () => {
    const ldb = fakeLdb();
    ldb.failReads = true;
    const p = make(ldb);
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    await expect(doc.whenLoaded).rejects.toThrow(/could not read room/);
    expect(p.status().readFailures).toBe(1);
    expect(p.status().failing).toBe(true);
  });

  it('compacts a room that stays open once it has enough stored entries', async () => {
    const ldb = fakeLdb();
    const p = make(ldb, { flushMs: 1, compactMinWrites: 3 });
    const doc = new Y.Doc() as LoadedDoc;
    p.bindState('room', doc);
    await doc.whenLoaded;
    for (let i = 0; i < 4; i++) {
      doc.getText('t').insert(0, String(i));
      await p.drain();
    }
    expect(ldb.entries.get('room')!.length).toBe(4);
    await p.compactOpenRooms();
    expect(ldb.entries.get('room')!.length).toBe(1);
    expect(textOf(ldb.entries.get('room'))).toBe('3210');
    expect(p.status().compactions).toBe(1);
  });
});
