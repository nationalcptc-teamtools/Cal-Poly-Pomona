// ─────────────────────────────────────────────────────────────────────────
// The relay's LevelDB persistence (replaces y-websocket's own binding
// through setPersistence; see server/index.mjs).
//
// y-websocket stores every update as its own LevelDB entry through one
// global serial queue, and each write starts with a reverse iterator. A
// typing burst across many rooms outruns it, and the backlog lives only in
// memory, so a stop or crash drops it. Its binding also answers a cold
// room's first sync before the stored state is loaded, swallows write
// errors, and only compacts a room when it loads, so a room that never
// closes (btct-shared) grows an entry per update all day.
//
// This binding:
//   • records the load as `doc.whenLoaded` (and `doc.loaded`), so callers
//     can wait for the stored state before answering or reading;
//   • buffers each room's updates and writes them as ONE update at most
//     every `flushMs`, sooner when the buffer is large (bytes or count),
//     with at most one write per room in flight. Y.mergeUpdates is
//     quadratic in the number of updates (30,000 took 18.4 s), and an
//     unbounded merge under a write backlog blocked the event loop for
//     minutes, SIGTERM included. So a buffer of up to 1000 updates is merged
//     in groups of 64 (mergeUpdatesBounded), and a longer one is encoded from
//     the doc as the difference to the state vector taken before its first
//     update (Y.encodeStateAsUpdate(doc, sv), 26 ms for those 30,000);
//   • keeps a failed write: the room is marked to store its full state on
//     the next attempt (retried every `retryMs`), and a room that closed
//     while failing keeps its state in memory until a write succeeds or the
//     room reopens;
//   • reports failures through status() so /healthz can say so, and after
//     a failure stays "failing" until the LevelDB write-ahead log has been
//     sealed (`sealLog`, see createLevelDbLogSealer below), not merely
//     until the next write succeeds;
//   • compacts rooms that stay open (`compactMs`);
//   • drain() flushes every buffer, waits for rooms still loading, and
//     waits for y-leveldb's own queue, for backups and shutdown.
//
// `Y` is injected so the server passes the same CJS instance y-websocket
// uses (invariant #6) and tests can pass their own.
// ─────────────────────────────────────────────────────────────────────────

/** Origin of the stored state applied into a room on load; not re-stored. */
const LOAD_ORIGIN = Symbol('relay-persistence-load');

/**
 * A key no y-leveldb entry uses (its keys are encoded arrays, which never
 * start with 0xff), so compacting [SEAL_KEY, SEAL_KEY] rewrites no table
 * and costs only the memtable flush that LevelDB's CompactRange does first.
 */
const SEAL_KEY = Buffer.from([0xff, 0xff, 0xff, 0xff]);

/** The numbered write-ahead logs in a LevelDB directory (not `LOG`). */
function walFiles(fs, dir) {
  return fs.readdirSync(dir).filter((f) => /^\d+\.log$/.test(f));
}

/**
 * Seal LevelDB's write-ahead log: move the memtable into a table file and
 * start a new log, then check that every log that existed before is gone.
 *
 * Why: a log append that fails half way (ENOSPC) leaves a torn record in the
 * log. LevelDB does not stop: it reports that write as failed, keeps
 * appending after the torn bytes and serves reads from its memtable, so the
 * server looks healthy. On the next open, recovery drops everything from the
 * torn record on ("dropping N bytes; Corruption: checksum mismatch"), which
 * silently lost every edit written after a disk-full episode. Once the
 * memtable is in a table file and the old log deleted, nothing depends on
 * the torn log any more.
 *
 * CompactRange returns no status (a failed log switch or memtable flush is
 * only visible as the old log still being there), hence the file check.
 * Runs inside y-leveldb's queue so no write interleaves. Resolves true when
 * sealed, false otherwise; never rejects.
 *
 * @param {any} ldb y-leveldb's LeveldbPersistence
 * @param {string} dir the LevelDB directory
 * @param {typeof import('node:fs')} fs
 */
export function createLevelDbLogSealer(ldb, dir, fs) {
  return async function sealLog() {
    const res = await ldb._transact(async (db) => {
      // levelup -> encoding-down -> leveldown; leveldown takes raw buffers.
      // leveldown's compactRange skips levelup's deferred open, and on a
      // handle that is not open yet it crashes the process (a null pointer
      // in the native binding), so make sure it is open first.
      if (typeof db?.isOpen !== 'function') throw new Error('no levelup handle');
      if (!db.isOpen()) {
        // Still opening: levelup's open() waits for it. Closed: give up.
        if (!db._isOpening?.()) throw new Error('LevelDB is not open');
        await new Promise((resolve, reject) => db.open((err) => (err ? reject(err) : resolve())));
      }
      const down = db?._db?.db;
      if (typeof down?.compactRange !== 'function') throw new Error('no compactRange on the LevelDB handle');
      const before = walFiles(fs, dir);
      await new Promise((resolve, reject) => {
        down.compactRange(SEAL_KEY, SEAL_KEY, (err) => (err ? reject(err) : resolve()));
      });
      const after = new Set(walFiles(fs, dir));
      const left = before.filter((f) => after.has(f));
      if (left.length) throw new Error(`write-ahead log ${left.join(', ')} is still there (the memtable flush failed)`);
      return true;
    });
    return res === true;
  };
}

/**
 * Up to this many buffered updates a write is a merge in groups of
 * MERGE_GROUP; above it, a state-vector diff. A diff always carries the
 * whole delete set (a walk of the entire doc), so it pays off only for a
 * long buffer; a grouped merge costs about the same per update whatever the
 * doc's size. Measured on 0.5 CPU, 150,000 churn edits: grouped merges in
 * flushes of 500 took 4.1 s, diffs 6.4 s; in flushes of 2000, 3.4 s against
 * 2.0 s; one plain mergeUpdates of 2000 took 22.6 s.
 */
const DIFF_MIN_UPDATES = 1000;
const MERGE_GROUP = 64;

/**
 * Merge many updates without mergeUpdates' quadratic cost: merge groups of
 * `group`, then the results, until one is left. Used only when the
 * state-vector diff is not available (updates buffered before the load).
 */
export function mergeUpdatesBounded(Y, updates, group = MERGE_GROUP) {
  let level = updates;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += group) {
      const part = level.slice(i, i + group);
      next.push(part.length === 1 ? part[0] : Y.mergeUpdates(part));
    }
    level = next;
  }
  return level[0] ?? null;
}

export function createRelayPersistence({
  ldb,
  Y,
  flushMs = 300,
  maxPendingBytes = 2 * 1024 * 1024,
  maxPendingUpdates = 2000,
  retryMs = 5_000,
  compactMs = 15 * 60_000,
  compactMinWrites = 100,
  log = console,
  sealLog = null,
} = {}) {
  if (!ldb || !Y) throw new Error('createRelayPersistence needs ldb and Y');

  /** doc -> room state. Keyed by doc, not name: a room can close and reopen
   * (a new doc with the same name) while the old doc's last write is out. */
  const rooms = new Map();
  /** name -> full state of a room that closed while its writes failed. */
  const orphans = new Map();
  /** whenLoaded promises of rooms still reading LevelDB. */
  const loading = new Set();
  /** Every write promise not settled yet. */
  const inflight = new Set();

  const stats = {
    failing: false,
    failures: 0,
    readFailures: 0,
    lastError: null,
    lastFailureAt: 0,
    lastSuccessAt: 0,
    writes: 0,
    compactions: 0,
  };

  let orphanTimer = null;
  let closed = false;
  /** Bumped on every failure, so a seal that a failure overtook is redone. */
  let failGen = 0;
  /** The seal in progress, if any. */
  let sealing = null;
  let sealTimer = null;

  function noteFailure(kind, name, err) {
    stats.failing = true;
    stats.failures++;
    failGen++;
    if (kind === 'read') stats.readFailures++;
    stats.lastFailureAt = Date.now();
    stats.lastError = `${kind} ${name}: ${err?.message || err || 'LevelDB returned no result'}`;
    log.error(`[persistence] ${stats.lastError}`);
  }

  function noteSuccess() {
    stats.lastSuccessAt = Date.now();
    stats.writes++;
    if (stats.failing) recover();
  }

  /** A room or a closed room still holds data a failed write did not store. */
  function unsavedAfterFailure() {
    if (orphans.size) return true;
    for (const room of rooms.values()) if (room.needsFull) return true;
    return false;
  }

  /**
   * Leave the failing state. Without a sealer, at the first write that
   * succeeds. With one, only once the write-ahead log has been sealed with
   * no failure since the seal started and nothing is left to retry: until
   * then the writes that succeeded live only in LevelDB's memtable and in a
   * log a restart may cut short.
   */
  function recover() {
    if (!stats.failing || sealing) return sealing;
    if (!sealLog) {
      stats.failing = false;
      log.warn('[persistence] writes are succeeding again');
      return null;
    }
    if (sealTimer) { clearTimeout(sealTimer); sealTimer = null; }
    const gen = failGen;
    sealing = (async () => {
      let ok = false;
      try { ok = await sealLog(); } catch (err) {
        log.error('[persistence] sealing the LevelDB log failed:', err?.message || err);
      }
      sealing = null;
      if (ok && gen === failGen) {
        // A room still waiting for its retry recovers on that write's success.
        if (unsavedAfterFailure()) return false;
        stats.failing = false;
        log.warn('[persistence] writes are succeeding again; the LevelDB log was sealed into a table');
        return true;
      }
      if (!ok) log.error('[persistence] could not seal the LevelDB log after a failed write; still failing, retrying');
      if (!closed && !sealTimer) {
        sealTimer = setTimeout(() => { sealTimer = null; void recover(); }, retryMs);
        sealTimer.unref?.();
      }
      return false;
    })();
    return sealing;
  }

  /** One write through y-leveldb; resolves true on success, never rejects. */
  function store(name, update) {
    const p = (async () => {
      try {
        // y-leveldb's queue swallows errors and resolves null; a stored
        // update resolves its clock (a number).
        const clock = await ldb.storeUpdate(name, update);
        if (typeof clock !== 'number') { noteFailure('write', name, null); return false; }
        noteSuccess();
        return true;
      } catch (err) {
        noteFailure('write', name, err);
        return false;
      }
    })();
    inflight.add(p);
    p.finally(() => inflight.delete(p));
    return p;
  }

  function schedule(room, ms) {
    if (room.timer || closed) return;
    room.timer = setTimeout(() => { room.timer = null; void flushRoom(room); }, ms);
    room.timer.unref?.();
  }

  /**
   * Write what the room has buffered. `final` (room closing, drain) skips
   * the one-write-in-flight rule so the write is queued in LevelDB before
   * anything that follows, such as the same room loading again.
   */
  function flushRoom(room, { final = false } = {}) {
    if (room.timer) { clearTimeout(room.timer); room.timer = null; }
    if (!final && room.writing) { room.again = true; return room.writing; }
    let payload = null;
    if (room.needsFull) {
      try { payload = Y.encodeStateAsUpdate(room.doc); } catch { payload = null; }
      if (payload) room.needsFull = false;
    }
    if (!payload && room.pending.length) {
      if (room.pending.length === 1) payload = room.pending[0];
      else if (room.pending.length > DIFF_MIN_UPDATES && room.baseSV && !room.doc.isDestroyed) {
        payload = Y.encodeStateAsUpdate(room.doc, room.baseSV);
      } else {
        payload = mergeUpdatesBounded(Y, room.pending);
      }
    }
    room.pending = [];
    room.pendingBytes = 0;
    room.baseSV = null;
    if (!payload) return room.writing || Promise.resolve(true);
    const p = store(room.name, payload).then((ok) => {
      if (room.writing === p) room.writing = null;
      if (ok) {
        room.writesSinceCompact++;
      } else if (!room.closing && !room.doc.isDestroyed && rooms.get(room.doc) === room) {
        // Keep the data: the next attempt writes the whole state, which
        // covers this update and anything buffered after it.
        room.needsFull = true;
        schedule(room, retryMs);
      } else {
        keepOrphan(room.name, payload);
      }
      if (room.again || room.pending.length) {
        room.again = false;
        if (room.pending.length || room.needsFull) schedule(room, flushMs);
      }
      return ok;
    });
    room.writing = p;
    return p;
  }

  function keepOrphan(name, update) {
    const prev = orphans.get(name);
    orphans.set(name, prev ? Y.mergeUpdates([prev, update]) : update);
    if (!orphanTimer && !closed) {
      orphanTimer = setTimeout(retryOrphans, retryMs);
      orphanTimer.unref?.();
    }
  }

  async function retryOrphans() {
    orphanTimer = null;
    for (const [name, update] of [...orphans]) {
      if (orphans.get(name) !== update) continue;
      orphans.delete(name);
      const ok = await store(name, update);
      if (!ok) keepOrphan(name, update);
    }
  }

  function onUpdate(room, update, origin) {
    if (origin === LOAD_ORIGIN) return;
    room.pending.push(update);
    room.pendingBytes += update.length;
    // A room already handed to writeState (its last socket closed) can still
    // get an update: y-websocket broadcasts to every conn at the end of a
    // transaction before this listener runs, and a send to a socket that is
    // no longer open calls closeConn, which closes the room. Store it now,
    // queued ahead of any reload of the room, and seen by drain() through
    // `inflight`; a timer would leave it out of both.
    if (room.closing || rooms.get(room.doc) !== room) { void flushRoom(room, { final: true }); return; }
    if (room.pendingBytes >= maxPendingBytes || room.pending.length >= maxPendingUpdates) void flushRoom(room);
    else schedule(room, flushMs);
  }

  function bindState(name, doc) {
    const room = {
      name,
      doc,
      pending: [],
      pendingBytes: 0,
      timer: null,
      writing: null,
      again: false,
      needsFull: false,
      closing: false,
      writesSinceCompact: 0,
      // State vector taken just before the first buffered update, so a long
      // buffer can be written as the doc's difference to it. Null while the
      // buffer is empty, and stays null for a buffer that began before the
      // load (the diff would then rewrite the stored state).
      baseSV: null,
    };
    rooms.set(doc, room);
    doc.on('beforeTransaction', (tr) => {
      if (room.baseSV || room.pending.length || room.needsFull) return;
      if (!doc.loaded || tr.origin === LOAD_ORIGIN) return;
      room.baseSV = Y.encodeStateVector(doc);
    });
    // Listen from the start: an update the server writes before the load
    // finishes is buffered and stored after the load's read in LevelDB's
    // queue. The stored state itself is applied with LOAD_ORIGIN and skipped.
    doc.on('update', (update, origin) => onUpdate(room, update, origin));
    doc.on('destroy', () => {
      if (rooms.get(doc) !== room) return;
      room.closing = true;
      void flushRoom(room, { final: true }).finally(() => {
        if (rooms.get(doc) === room) rooms.delete(doc);
      });
    });

    const whenLoaded = (async () => {
      let persisted;
      try {
        persisted = await ldb.getYDoc(name);
      } catch (err) {
        noteFailure('read', name, err);
        throw err;
      }
      // y-leveldb resolves null instead of throwing when a read fails.
      if (!persisted) {
        const err = new Error(`could not read room ${name} from LevelDB`);
        noteFailure('read', name, err);
        throw err;
      }
      try {
        Y.applyUpdate(doc, Y.encodeStateAsUpdate(persisted), LOAD_ORIGIN);
      } finally {
        persisted.destroy();
      }
      // A room that closed while its writes were failing: put that state
      // back, as an ordinary update, so it is stored with this room.
      const orphan = orphans.get(name);
      if (orphan) {
        orphans.delete(name);
        Y.applyUpdate(doc, orphan);
        room.needsFull = true;
        schedule(room, flushMs);
      }
      doc.loaded = true;
    })();
    doc.whenLoaded = whenLoaded;
    loading.add(whenLoaded);
    // Callers await it; this only keeps a failure from being unhandled.
    whenLoaded.catch(() => {}).finally(() => loading.delete(whenLoaded));
  }

  /** Called by y-websocket when a room's last connection closes. */
  function writeState(_name, doc) {
    const room = rooms.get(doc);
    if (!room) return Promise.resolve();
    room.closing = true;
    return flushRoom(room, { final: true }).then(() => {
      if (rooms.get(doc) === room) rooms.delete(doc);
    });
  }

  /** Merge the stored entries of rooms that stay open (btct-shared). */
  async function compactOpenRooms() {
    for (const room of [...rooms.values()]) {
      if (closed) return;
      if (!room.doc.loaded || room.writesSinceCompact < compactMinWrites) continue;
      // Queue the buffer first, so the merged entry includes it.
      flushRoom(room, { final: true });
      const n = room.writesSinceCompact;
      try {
        await ldb.flushDocument(room.name);
        room.writesSinceCompact = Math.max(0, room.writesSinceCompact - n);
        stats.compactions++;
      } catch (err) {
        log.warn(`[persistence] compaction of ${room.name} failed:`, err?.message || err);
      }
    }
  }
  const compactTimer = compactMs > 0 ? setInterval(() => { void compactOpenRooms(); }, compactMs) : null;
  compactTimer?.unref?.();

  /**
   * Store everything buffered and wait until LevelDB has it: rooms still
   * loading, every room's buffer, writes in flight, and y-leveldb's queue.
   * Resolves true when nothing failed.
   */
  async function drain() {
    for (let round = 0; round < 5; round++) {
      if (loading.size) await Promise.allSettled([...loading]);
      const writes = [];
      for (const room of rooms.values()) {
        if (room.pending.length || room.needsFull) writes.push(flushRoom(room, { final: true }));
      }
      if (orphans.size) writes.push(retryOrphans());
      writes.push(...inflight);
      await Promise.allSettled(writes);
      // y-leveldb's own serial queue (reads and compactions included).
      try { await ldb.tr; } catch { /* its entries never reject */ }
      const busy = loading.size || inflight.size
        || [...rooms.values()].some((r) => r.pending.length || r.needsFull);
      if (!busy) break;
    }
    // A failure earlier in this process may have torn the write-ahead log;
    // what was written since is safe only once the seal has finished.
    if (sealing) await sealing;
    return !stats.failing && orphans.size === 0;
  }

  function status() {
    let pendingBytes = 0;
    let pendingRooms = 0;
    for (const room of rooms.values()) {
      if (room.pending.length || room.needsFull) pendingRooms++;
      pendingBytes += room.pendingBytes;
    }
    for (const u of orphans.values()) pendingBytes += u.length;
    return {
      failing: stats.failing,
      sealing: !!sealing,
      failures: stats.failures,
      readFailures: stats.readFailures,
      lastError: stats.lastError,
      lastFailureAt: stats.lastFailureAt,
      lastSuccessAt: stats.lastSuccessAt,
      writes: stats.writes,
      compactions: stats.compactions,
      openRooms: rooms.size,
      loadingRooms: loading.size,
      pendingRooms,
      pendingBytes,
      unsavedClosedRooms: orphans.size,
      inflight: inflight.size,
    };
  }

  /** Stop the timers and close LevelDB (after drain). */
  async function close() {
    closed = true;
    if (compactTimer) clearInterval(compactTimer);
    if (orphanTimer) { clearTimeout(orphanTimer); orphanTimer = null; }
    if (sealTimer) { clearTimeout(sealTimer); sealTimer = null; }
    if (sealing) { try { await sealing; } catch { /* reported */ } }
    for (const room of rooms.values()) if (room.timer) { clearTimeout(room.timer); room.timer = null; }
    if (typeof ldb.destroy === 'function') await ldb.destroy();
  }

  return {
    provider: ldb,
    bindState,
    writeState,
    drain,
    status,
    compactOpenRooms,
    close,
  };
}
