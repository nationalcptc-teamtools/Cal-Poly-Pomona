// ─────────────────────────────────────────────────────────────────────────
// Page version history (Google Docs style).
//
// The live page docs are garbage-collected: once text is deleted and every
// client has seen the deletion, the bytes are gone, so nothing in the relay
// can say who wrote what. This module keeps a GC-off "twin" of every open
// page room, fed by the relay doc's `update` events, and persisted as one
// file per page under HISTORY_DIR. Versions are cheap Yjs snapshots (a
// state vector plus a delete set) stored in SQLite; rendering a version, or
// the difference between two versions coloured per user, needs only the
// twin plus the snapshot bytes, which is exactly what y-prosemirror's
// snapshot renderer consumes on the client.
//
// Policy (no thinning; every version is kept until someone deletes it):
//   • auto: 2 minutes after the last edit, or every 10 minutes during
//     continuous editing, and when the room closes with unsaved changes;
//     skipped when the body did not change
//   • named: POST /api/pages/:id/versions { name }
//   • restore: the client rewrites the live doc as a normal edit, then
//     records a version so the rollback itself shows up in the timeline
//   • import: the pre-history `pageSnapshots` CRDT rows, converted on first
//     read into full-state versions (renderable, not diffable)
//
// The server still knows nothing about what a page says (invariant #4): it
// moves bytes, reads the workspace id off the page record for the index,
// and maps clientIDs to accounts.
// ─────────────────────────────────────────────────────────────────────────
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import {
  getUserById,
  insertPageVersion,
  listPageVersions,
  getPageVersion,
  latestDiffableVersion,
  deletePageVersion,
  renamePageVersion,
} from './db.mjs';
import { changedUsersBetween } from './history-diff.mjs';

// Same CJS instance as y-websocket (invariant #6).
const require = createRequire(import.meta.url);
const Y = require('yjs');
const { docs, getYDoc } = require('y-websocket/bin/utils');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const HISTORY_DIR = process.env.HISTORY_DIR
  ? path.resolve(process.env.HISTORY_DIR)
  : path.join(
      process.env.DB_PATH ? path.dirname(path.resolve(process.env.DB_PATH)) : __dirname,
      'history',
    );
fs.mkdirSync(HISTORY_DIR, { recursive: true });

const SHARED_ROOM = 'btct-shared';
const FRAGMENT = 'prosemirror';
const IDLE_MS = 2 * 60_000;
const CONTINUOUS_MS = 10 * 60_000;
const TICK_MS = 30_000;
const FLUSH_MS = 5_000;
const ROOM_RE = /^[A-Za-z0-9_-]{1,128}$/;

/** pageId -> { twin, pud, relayDoc, lastUpdateAt, lastVersionAt, dirty, unflushed, flushTimer, ... } */
const tracked = new Map();

/** Counters for historyStatus(). */
const counters = { corruptTwins: 0, lastCorrupt: null, flushFailures: 0, lastFlushError: null };
/** Twin writes that have not finished (async flushes). */
const pendingWrites = new Set();
/** pageId -> { t, bytes } of the newest async write still out, so a sync
 * flush (backup, shutdown) can land those bytes without waiting for it. */
const unsettled = new Map();

function twinPath(pageId) {
  return path.join(HISTORY_DIR, `${pageId}.ydoc`);
}

// A write goes to `<id>.ydoc.tmp-<n>` and is renamed over the twin; one a
// crash left behind is never complete and never read, so clear them on boot.
try {
  for (const f of fs.readdirSync(HISTORY_DIR)) {
    if (/\.ydoc\.tmp(-\d+)?$/.test(f)) fs.rmSync(path.join(HISTORY_DIR, f), { force: true });
  }
} catch { /* an unreadable dir shows up on the first flush */ }

/**
 * Move a twin that cannot be read out of the way, so the next flush does not
 * overwrite the only copy of the page's history (every snapshot version is
 * rebuilt from it). Returns the new name, or null if it could not be moved.
 */
function quarantineTwin(pageId, err) {
  const file = twinPath(pageId);
  const dest = `${file}.corrupt-${Date.now()}`;
  counters.corruptTwins++;
  try {
    fs.renameSync(file, dest);
    counters.lastCorrupt = { pageId, file: path.basename(dest), at: Date.now(), error: String(err?.message || err) };
    console.error(`[history] twin for ${pageId} is unreadable (${err?.message || err}); kept as ${path.basename(dest)}, starting a new one`);
    return dest;
  } catch (renameErr) {
    counters.lastCorrupt = { pageId, file: null, at: Date.now(), error: String(err?.message || err) };
    console.error(`[history] twin for ${pageId} is unreadable and could not be moved aside (${renameErr?.message || renameErr}); it will not be overwritten`);
    return null;
  }
}

/**
 * Read a page's twin. `state` is 'ok', 'missing', 'corrupt' (moved aside,
 * a fresh twin returned) or 'locked' (unreadable and could not be moved,
 * so the caller must never write over it).
 */
function loadTwin(pageId) {
  let bytes;
  try {
    bytes = fs.readFileSync(twinPath(pageId));
  } catch (err) {
    if (err?.code === 'ENOENT') return { twin: new Y.Doc({ gc: false }), state: 'missing' };
    return { twin: new Y.Doc({ gc: false }), state: quarantineTwin(pageId, err) ? 'corrupt' : 'locked' };
  }
  const twin = new Y.Doc({ gc: false });
  if (!bytes.length) return { twin, state: 'missing' };
  try {
    Y.applyUpdate(twin, new Uint8Array(bytes));
    return { twin, state: 'ok' };
  } catch (err) {
    // A half-applied doc is not a twin; start from nothing.
    twin.destroy();
    return { twin: new Y.Doc({ gc: false }), state: quarantineTwin(pageId, err) ? 'corrupt' : 'locked' };
  }
}

function noteFlushFailure(pageId, err) {
  counters.flushFailures++;
  counters.lastFlushError = { pageId, at: Date.now(), error: String(err?.message || err) };
  console.warn(`[history] flush failed for ${pageId}:`, err?.message || err);
}

/**
 * Rename a finished temp file over the twin, unless a newer write already
 * landed. Synchronous on purpose: every rename of one twin happens in
 * order on the event loop, so an older async write can never replace a
 * newer one.
 */
function commitTwinWrite(pageId, t, seq, tmp) {
  if (seq < t.committedSeq) {
    fs.rmSync(tmp, { force: true });
    return;
  }
  fs.renameSync(tmp, twinPath(pageId));
  t.committedSeq = seq;
}

function takeTwinBytes(pageId, t) {
  if (t.flushTimer) { clearTimeout(t.flushTimer); t.flushTimer = null; }
  t.unflushed = false;
  const seq = ++t.writeSeq;
  return { seq, bytes: Y.encodeStateAsUpdate(t.twin), tmp: `${twinPath(pageId)}.tmp-${seq}` };
}

/** Write the twin now, fsynced, then rename (backups, shutdown). */
function flushTwinSync(pageId, t) {
  if (t.locked) return;
  if (!t.unflushed && !t.writing) {
    if (t.flushTimer) { clearTimeout(t.flushTimer); t.flushTimer = null; }
    return;
  }
  const { seq, bytes, tmp } = takeTwinBytes(pageId, t);
  writeTwinBytesSync(pageId, t, seq, bytes, tmp);
}

function writeTwinBytesSync(pageId, t, seq, bytes, tmp) {
  try {
    const fd = fs.openSync(tmp, 'w');
    try {
      fs.writeSync(fd, bytes);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    commitTwinWrite(pageId, t, seq, tmp);
  } catch (err) {
    t.unflushed = true;
    fs.rmSync(tmp, { force: true });
    noteFlushFailure(pageId, err);
  }
}

/** The same write off the event loop (the periodic flush). */
function flushTwin(pageId, t) {
  if (t.locked || !t.unflushed) {
    if (t.flushTimer) { clearTimeout(t.flushTimer); t.flushTimer = null; }
    return;
  }
  const { seq, bytes, tmp } = takeTwinBytes(pageId, t);
  t.writing++;
  const entry = { t, bytes };
  unsettled.set(pageId, entry);
  const p = (async () => {
    let fh;
    try {
      fh = await fs.promises.open(tmp, 'w');
      await fh.writeFile(bytes);
      await fh.sync();
      await fh.close();
      fh = null;
      commitTwinWrite(pageId, t, seq, tmp);
    } catch (err) {
      try { await fh?.close(); } catch { /* already closed */ }
      fs.rmSync(tmp, { force: true });
      // Retry later unless a newer write has already replaced this one.
      if (seq > t.committedSeq && tracked.get(pageId) === t) {
        t.unflushed = true;
        scheduleFlush(pageId, t);
      }
      noteFlushFailure(pageId, err);
    } finally {
      t.writing--;
      if (unsettled.get(pageId) === entry) unsettled.delete(pageId);
    }
  })();
  pendingWrites.add(p);
  p.finally(() => pendingWrites.delete(p));
}

function scheduleFlush(pageId, t) {
  if (t.flushTimer) return;
  t.flushTimer = setTimeout(() => { t.flushTimer = null; flushTwin(pageId, t); }, FLUSH_MS);
  t.flushTimer.unref?.();
}

/**
 * Start (or keep) following a relay doc. Idempotent; called for every room
 * the websocket layer opens. The shared metadata doc is not a page.
 *
 * The twin is written only when it changed: an update the twin already
 * holds (a client re-sending what it has, an export that only reads) fires
 * no `update` on the twin, so opening a page never rewrites its file.
 */
export function trackPageDoc(pageId, relayDoc) {
  if (pageId === SHARED_ROOM || !ROOM_RE.test(pageId) || tracked.has(pageId)) return;
  const { twin, state } = loadTwin(pageId);
  const t = {
    twin,
    pud: new Y.PermanentUserData(twin),
    relayDoc,
    lastUpdateAt: 0,
    lastVersionAt: Date.now(),
    dirty: false,
    unflushed: false,
    flushTimer: null,
    onUpdate: null,
    writeSeq: 0,
    committedSeq: 0,
    writing: 0,
    // Unreadable and could not be moved aside: never write over it.
    locked: state === 'locked',
    loading: true,
  };
  twin.on('update', () => {
    t.unflushed = true;
    if (!t.loading) {
      t.lastUpdateAt = Date.now();
      t.dirty = true;
    }
    scheduleFlush(pageId, t);
  });
  // What the relay holds that the twin does not (a new twin, or edits that
  // reached LevelDB while the twin was not tracking) is written, but is not
  // an edit made in this session, so it does not make a version by itself.
  Y.applyUpdate(twin, Y.encodeStateAsUpdate(relayDoc));
  t.loading = false;
  t.onUpdate = (update) => {
    try {
      Y.applyUpdate(twin, update);
    } catch (err) {
      console.warn(`[history] twin update failed for ${pageId}:`, err?.message || err);
    }
  };
  relayDoc.on('update', t.onUpdate);
  relayDoc.on('destroy', () => untrack(pageId));
  tracked.set(pageId, t);
}

function untrack(pageId) {
  const t = tracked.get(pageId);
  if (!t) return;
  tracked.delete(pageId);
  try { t.relayDoc.off('update', t.onUpdate); } catch { /* already gone */ }
  if (t.dirty) {
    try { createVersion(pageId, t, { trigger: 'auto' }); } catch (err) {
      console.warn(`[history] close version failed for ${pageId}:`, err?.message || err);
    }
  }
  // Off the event loop: the bytes are encoded before the twin is destroyed,
  // and flushAllTwins() lands them at once if a backup needs the file first.
  flushTwin(pageId, t);
  t.twin.destroy();
}

/**
 * Close every tracked twin as if its room closed: record the close version
 * when it changed and write the file. Resolves once every twin write is on
 * disk. For shutdown: call it while btct-shared is still in the relay map,
 * since a version looks up its page's workspace there.
 */
export async function closeAllTwins() {
  for (const pageId of [...tracked.keys()]) untrack(pageId);
  await drainTwinWrites();
}

function lookupWorkspaceId(pageId) {
  try {
    const shared = docs.get(SHARED_ROOM) ?? getYDoc(SHARED_ROOM);
    const page = shared.getMap('pages').get(pageId);
    return page && typeof page.workspaceId === 'string' ? page.workspaceId : null;
  } catch {
    return null;
  }
}

function userIdsFromDescriptions(descriptions) {
  const ids = [];
  for (const d of descriptions) {
    const n = Number(d);
    if (Number.isInteger(n) && n > 0) ids.push(n);
    else if (d === 'unknown' || d == null) ids.push(0);
  }
  return [...new Set(ids)];
}

/**
 * Snapshot the twin into a version row. Auto versions are dropped when the
 * body is unchanged since the last diffable version; named and restore
 * versions are always written (the user asked for a marker).
 */
export function createVersion(pageId, t, { trigger = 'auto', name = null, createdBy = null } = {}) {
  const snapshot = Y.snapshot(t.twin);
  const prev = latestDiffableVersion(pageId);
  const prevSnapshot = prev ? Y.decodeSnapshot(new Uint8Array(prev.snapshot)) : Y.emptySnapshot;
  const diff = changedUsersBetween(Y, t.twin, FRAGMENT, prevSnapshot, snapshot, t.pud);
  t.dirty = false;
  if (trigger === 'auto' && !diff.changed) return null;
  const changedBy = userIdsFromDescriptions(diff.users);
  if (trigger !== 'auto' && createdBy != null && !changedBy.length) changedBy.push(createdBy);
  const row = {
    id: randomUUID(),
    pageId,
    workspaceId: lookupWorkspaceId(pageId),
    createdAt: Date.now(),
    trigger,
    name: typeof name === 'string' && name.trim() ? name.trim().slice(0, 120) : null,
    createdBy,
    changedBy: JSON.stringify(changedBy),
    snapshot: Buffer.from(Y.encodeSnapshot(snapshot)),
    state: null,
    size: Y.encodeStateVector(t.twin).length,
  };
  insertPageVersion(row);
  t.lastVersionAt = row.createdAt;
  flushTwin(pageId, t);
  return row;
}

function tick() {
  const now = Date.now();
  for (const [pageId, t] of tracked) {
    if (!t.dirty) continue;
    const idle = now - t.lastUpdateAt >= IDLE_MS;
    const longSession = now - t.lastVersionAt >= CONTINUOUS_MS;
    if (!idle && !longSession) continue;
    try {
      createVersion(pageId, t, { trigger: 'auto' });
    } catch (err) {
      console.warn(`[history] auto version failed for ${pageId}:`, err?.message || err);
    }
  }
}
const ticker = setInterval(tick, TICK_MS);
ticker.unref?.();

/**
 * Write every open twin that has changes or a write still out, synchronously,
 * so the files match what the server holds when this returns (the backup
 * engine calls it right before it copies HISTORY_DIR).
 */
export function flushAllTwins() {
  for (const [pageId, t] of tracked) flushTwinSync(pageId, t);
  // Twins of rooms that closed with their last write still out.
  for (const [pageId, { t, bytes }] of [...unsettled]) {
    if (tracked.get(pageId) === t) continue;
    unsettled.delete(pageId);
    const seq = ++t.writeSeq;
    writeTwinBytesSync(pageId, t, seq, bytes, `${twinPath(pageId)}.tmp-${seq}`);
  }
}

/** Wait for the async twin writes that are out (tests, shutdown). */
export async function drainTwinWrites() {
  await Promise.allSettled([...pendingWrites]);
}

export function historyStatus() {
  return {
    dir: HISTORY_DIR,
    tracked: tracked.size,
    writesInFlight: pendingWrites.size,
    corruptTwins: counters.corruptTwins,
    lastCorrupt: counters.lastCorrupt,
    flushFailures: counters.flushFailures,
    lastFlushError: counters.lastFlushError,
  };
}

// ── Legacy import ─────────────────────────────────────────────────────────
// Pre-history clients wrote full-state captures into the shared doc's
// `pageSnapshots` map. The first time a page's history is listed, those
// rows become `import` versions (restorable, not diffable) and leave the
// CRDT, which was never meant to carry bytes (invariant #4b).
function importLegacySnapshots(pageId) {
  let shared;
  try { shared = docs.get(SHARED_ROOM) ?? getYDoc(SHARED_ROOM); } catch { return; }
  const map = shared.getMap('pageSnapshots');
  const legacy = [];
  map.forEach((v, k) => { if (v && typeof v === 'object' && v.pageId === pageId) legacy.push([k, v]); });
  if (!legacy.length) return;
  for (const [key, v] of legacy) {
    let state = null;
    try { state = Buffer.from(String(v.updateBase64 || ''), 'base64'); } catch { state = null; }
    if (!state || !state.length) continue;
    const uid = Number.isInteger(v.userId) ? v.userId : null;
    insertPageVersion({
      id: typeof v.id === 'string' ? v.id : key,
      pageId,
      workspaceId: typeof v.workspaceId === 'string' ? v.workspaceId : null,
      createdAt: Number(v.timestamp) || Date.now(),
      trigger: 'import',
      name: typeof v.label === 'string' && v.label ? v.label : null,
      createdBy: uid,
      changedBy: JSON.stringify(uid != null ? [uid] : []),
      snapshot: null,
      state,
      size: state.length,
    });
  }
  shared.transact(() => { for (const [key] of legacy) map.delete(key); });
}

// ── HTTP handlers ─────────────────────────────────────────────────────────

function publicUserRef(id) {
  if (!id) return { id: 0, username: 'Unknown', color: '#888888' };
  const u = getUserById(id);
  return u
    ? { id: u.id, username: u.username, color: u.color || '#888888' }
    : { id, username: `user ${id}`, color: '#888888' };
}

function publicVersion(row) {
  let changedBy = [];
  try { changedBy = JSON.parse(row.changed_by || '[]'); } catch { changedBy = []; }
  return {
    id: row.id,
    pageId: row.page_id,
    workspaceId: row.workspace_id,
    createdAt: row.created_at,
    trigger: row.trigger,
    name: row.name,
    createdBy: row.created_by,
    changedBy,
    diffable: !!row.has_snapshot,
    size: row.size,
  };
}

export function handleVersionList(req, res, pageId, { sendJson }) {
  if (!ROOM_RE.test(pageId)) return sendJson(res, 400, { error: 'bad page id' });
  try { importLegacySnapshots(pageId); } catch (err) {
    console.warn(`[history] legacy import failed for ${pageId}:`, err?.message || err);
  }
  const rows = listPageVersions(pageId).map(publicVersion);
  const ids = new Set();
  for (const v of rows) {
    if (v.createdBy) ids.add(v.createdBy);
    for (const id of v.changedBy) ids.add(id);
  }
  const users = {};
  for (const id of ids) users[id] = publicUserRef(id);
  const t = tracked.get(pageId);
  return sendJson(res, 200, {
    versions: rows,
    users,
    tracked: !!t,
    dirty: !!t?.dirty,
    twinExists: !!t || fs.existsSync(twinPath(pageId)),
  });
}

export async function handleVersionCreate(req, res, pageId, { user, sendJson, readJsonBody }) {
  if (!ROOM_RE.test(pageId)) return sendJson(res, 400, { error: 'bad page id' });
  let body;
  try { body = await readJsonBody(req); } catch { return sendJson(res, 400, { error: 'invalid JSON' }); }
  const trigger = body?.trigger === 'restore' ? 'restore' : 'named';
  const name = typeof body?.name === 'string' ? body.name : null;
  const t = tracked.get(pageId);
  if (!t) return sendJson(res, 409, { error: 'page is not open on the server; open it in a tab and try again' });
  const row = createVersion(pageId, t, { trigger, name, createdBy: user.id });
  const stored = getPageVersion(pageId, row.id);
  return sendJson(res, 201, { version: publicVersion({ ...stored, has_snapshot: stored.snapshot ? 1 : 0 }) });
}

export function handleVersionGet(req, res, pageId, versionId, { sendJson }) {
  if (!ROOM_RE.test(pageId)) return sendJson(res, 400, { error: 'bad page id' });
  const row = getPageVersion(pageId, versionId);
  if (!row) return sendJson(res, 404, { error: 'version not found' });
  let state = row.state ? Buffer.from(row.state) : null;
  if (!state && row.snapshot) {
    const open = tracked.get(pageId);
    let twin = open?.twin;
    if (!twin) {
      const loaded = loadTwin(pageId);
      if (loaded.state !== 'ok') {
        loaded.twin.destroy();
        return sendJson(res, 410, {
          error: loaded.state === 'missing'
            ? 'the history file for this page is missing, so this version cannot be rebuilt'
            : 'the history file for this page is damaged (kept aside on the server), so this version cannot be rebuilt',
        });
      }
      twin = loaded.twin;
    }
    try {
      const doc = Y.createDocFromSnapshot(twin, Y.decodeSnapshot(new Uint8Array(row.snapshot)));
      state = Buffer.from(Y.encodeStateAsUpdate(doc));
      doc.destroy();
    } catch (err) {
      return sendJson(res, 500, { error: `could not rebuild this version: ${err?.message || err}` });
    } finally {
      if (!tracked.get(pageId)) twin.destroy();
    }
  }
  return sendJson(res, 200, {
    version: publicVersion({ ...row, has_snapshot: row.snapshot ? 1 : 0 }),
    snapshot: row.snapshot ? Buffer.from(row.snapshot).toString('base64') : null,
    state: state ? state.toString('base64') : null,
  });
}

export function handleVersionDelete(req, res, pageId, versionId, { user, sendJson }) {
  const row = getPageVersion(pageId, versionId);
  if (!row) return sendJson(res, 404, { error: 'version not found' });
  const mine = row.created_by != null && row.created_by === user.id;
  const named = !!row.name;
  if (!(user.is_admin || (named && mine))) {
    return sendJson(res, 403, { error: named ? 'only its author or an admin can delete a named version' : 'only an admin can delete automatic versions' });
  }
  deletePageVersion(pageId, versionId);
  return sendJson(res, 200, { ok: true });
}

export async function handleVersionRename(req, res, pageId, versionId, { user, sendJson, readJsonBody }) {
  const row = getPageVersion(pageId, versionId);
  if (!row) return sendJson(res, 404, { error: 'version not found' });
  let body;
  try { body = await readJsonBody(req); } catch { return sendJson(res, 400, { error: 'invalid JSON' }); }
  const name = typeof body?.name === 'string' ? body.name.trim().slice(0, 120) : '';
  if (row.name && !(user.is_admin || row.created_by === user.id)) {
    return sendJson(res, 403, { error: 'only its author or an admin can rename a named version' });
  }
  renamePageVersion(pageId, versionId, name || null, name ? user.id : row.created_by);
  const updated = getPageVersion(pageId, versionId);
  return sendJson(res, 200, { version: publicVersion({ ...updated, has_snapshot: updated.snapshot ? 1 : 0 }) });
}

/** The GC-off twin as one Yjs update, gzipped when the client accepts it. */
export function handleTwinGet(req, res, pageId, { sendJson }) {
  if (!ROOM_RE.test(pageId)) return sendJson(res, 400, { error: 'bad page id' });
  const t = tracked.get(pageId);
  let bytes;
  if (t) {
    bytes = Buffer.from(Y.encodeStateAsUpdate(t.twin));
  } else {
    try { bytes = fs.readFileSync(twinPath(pageId)); } catch { return sendJson(res, 404, { error: 'no history for this page yet' }); }
  }
  const gzip = /\bgzip\b/.test(String(req.headers['accept-encoding'] || '')) && bytes.length > 4096;
  const out = gzip ? zlib.gzipSync(bytes) : bytes;
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Length': out.length,
    'Cache-Control': 'no-store',
    ...(gzip ? { 'Content-Encoding': 'gzip' } : {}),
  });
  res.end(out);
}
