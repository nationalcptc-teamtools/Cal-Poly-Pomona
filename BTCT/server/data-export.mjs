// ─────────────────────────────────────────────────────────────────────────
// Consistent read access to everything under /data, for backups.
//
// The rules this module exists to enforce (see README "Backups"):
//   • Never copy the live SQLite file. In WAL mode the newest commits live in
//     `-wal`; a bare copy can be torn. `VACUUM INTO` writes a consistent
//     snapshot without blocking writers.
//   • Never copy the live LevelDB directory. It is held open (LOCK) and has
//     no checkpoint API; a copy can capture a torn log or manifest. Export
//     each room as one Yjs update instead, from the in-memory doc when the
//     room is open (y-websocket persists every update immediately, so the
//     two are equivalent) or from y-leveldb when it is cold.
//   • Assets are immutable uuid-named blobs: copy by id.
//
// Yjs and y-websocket's utils are loaded through the SAME CJS require the
// relay uses (invariant #6), so `docs` is the relay's live map.
// ─────────────────────────────────────────────────────────────────────────
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { Database } from 'bun:sqlite';
import { db } from './db.mjs';
import { ASSETS_DIR } from './assets.mjs';

const require = createRequire(import.meta.url);
const { docs, getPersistence } = require('y-websocket/bin/utils');
const Y = require('yjs');

export const SHARED_ROOM = 'btct-shared';

// Room names are 'btct-shared' or page uuids. Anything else is refused so a
// room name can never become a path.
const ROOM_RE = /^[A-Za-z0-9_-]{1,128}$/;

/** Consistent snapshot of the live database at `dest` (must not exist). Returns its size. */
export function exportSqliteTo(dest) {
  if (fs.existsSync(dest)) fs.unlinkSync(dest);
  db.run('VACUUM INTO ?', [dest]);
  return fs.statSync(dest).size;
}

/**
 * Wait until the persistence has written what it was handed. The relay's
 * persistence (server/index.mjs) may expose `drain()`; without it there is
 * nothing to wait on and this resolves at once. Resolves false when the
 * persistence reports failing writes: a room that closed while LevelDB was
 * refusing writes is then held in memory only, and a read of LevelDB misses
 * its latest edits.
 */
export async function drainPersistence() {
  const p = getPersistence();
  if (typeof p?.drain === 'function') return (await p.drain()) !== false;
  return true;
}

/**
 * Every room the relay knows about: open in memory, stored in LevelDB, or
 * named by a history twin (a page whose room went cold before its first
 * write reached LevelDB still has a twin). `extraNames` adds the twins.
 */
export async function listDocNames(extraNames = []) {
  const names = new Set();
  for (const n of docs.keys()) names.add(n);
  for (const n of extraNames) names.add(n);
  const p = getPersistence();
  if (p?.provider?.getAllDocNames) {
    for (const n of await p.provider.getAllDocNames()) names.add(n);
  }
  return [...names].filter((n) => ROOM_RE.test(n)).sort();
}

/** One room as a full Yjs update (Uint8Array), or null when it does not exist. */
export async function exportDocUpdate(name) {
  if (!ROOM_RE.test(name)) return null;
  const live = docs.get(name);
  if (live) {
    // A room someone just opened is in the relay map while its stored state
    // is still loading (server/index.mjs bindState); encoding it now would
    // back up an empty or partial room. Wait for the load, and fall back to
    // reading LevelDB directly if that load failed.
    // Without persistence (YPERSISTENCE unset) there is nothing to load, and
    // Yjs's own whenLoaded never resolves on a root doc.
    let loaded = true;
    if (getPersistence()) {
      try { await live.whenLoaded; } catch { loaded = false; }
    }
    if (loaded && !live.isDestroyed) return Y.encodeStateAsUpdate(live);
  }
  const p = getPersistence();
  if (p?.provider?.getYDoc) {
    const ydoc = await p.provider.getYDoc(name);
    // y-leveldb resolves null when the read fails.
    if (!ydoc) throw new Error(`room ${name} could not be read from LevelDB`);
    try { return Y.encodeStateAsUpdate(ydoc); } finally { ydoc.destroy(); }
  }
  return null;
}

/** True for an update that carries nothing (an empty or never-written room). */
export function isEmptyUpdate(update) {
  return !update || update.byteLength <= 2;
}

const ASSET_COLUMNS = 'id, workspace_id, kind, filename, mime, size, uploaded_by, created_at';

/** Asset rows of the live database (id and size; used for the space estimate). */
export function listAssetRows() {
  return db.query(`SELECT ${ASSET_COLUMNS} FROM assets ORDER BY created_at`).all();
}

/**
 * Asset rows of a snapshot file written by exportSqliteTo, opened read-only.
 * A backup copies exactly these blobs, so every row in the backed-up
 * database has its bytes and nothing uploaded after the snapshot is listed.
 */
export function listAssetRowsFrom(snapshotPath) {
  const snap = new Database(snapshotPath, { readonly: true });
  try {
    return snap.query(`SELECT ${ASSET_COLUMNS} FROM assets ORDER BY created_at`).all();
  } finally {
    snap.close();
  }
}

export function assetPath(id) {
  return path.join(ASSETS_DIR, id);
}

export { ASSETS_DIR };
