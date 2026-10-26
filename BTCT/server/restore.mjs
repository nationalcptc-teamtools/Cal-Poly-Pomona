// ─────────────────────────────────────────────────────────────────────────
// Restore a backup written by backup.mjs into /data.
//
//   bun restore.mjs <backup.zip | backup-dir> [--yes] [--partial] [--keep-browser-caches]
//   bun restore.mjs --verify <backup.zip | backup-dir>
//
// A run is one `btct-backup-YYYYMMDD-HHMMSS.zip`; a folder of the same name
// (written by builds before 2026-10-12) is still accepted.
//
// The image's working directory is /app/server, so it is `bun restore.mjs`
// (or `bun /app/server/restore.mjs`), never `bun server/restore.mjs`. Run it
// with the server STOPPED, with the same DB_PATH / YPERSISTENCE / ASSETS_DIR /
// HISTORY_DIR the server uses. In Docker:
//
//   docker compose stop btct
//   docker compose run --rm btct bun restore.mjs /backups/btct-backup-YYYYMMDD-HHMMSS.zip --yes
//   docker compose start btct
//
// What it does, in order:
//   1. Re-hashes every file against the manifest and checks every id that
//      becomes a file name (asset ids, room names, history page ids). A ZIP
//      is read in place (its member names are checked, every CRC32 too, and
//      nothing is written). Then every payload is decoded the way staging
//      will (restore-checks.mjs: the SQLite snapshot through quick_check in
//      a temp copy, every room's update applied and read back; a ZIP's
//      members are read straight from the archive). Refuses on any problem.
//      `--verify` stops here: exit 0 when the backup is usable, 2 when it is
//      not, 5 when this user cannot read the copy at all (EACCES/EPERM, so
//      nothing was checked), and nothing under /data is touched either way.
//   2. Refuses if the server is running: whether another process holds a
//      lock on LevelDB's LOCK file, the SQLite file or its -shm is asked
//      with fcntl(F_GETLK), which writes nothing, whatever categories the
//      backup holds. Only where that cannot be asked (not Linux, no libc) it
//      falls back to opening both stores, which compacts LevelDB's log and
//      checkpoints SQLite's WAL (no data changes, but files are rewritten).
//   3. Checks free space on the data volume. A ZIP's members are then
//      streamed out to <data>/.restore-unpack/ (only the ones the plan
//      restores, each re-hashed on the way; removed again on any exit), and
//      the new data is built in <data>/.restore-staging/: the SQLite
//      snapshot (no -wal/-shm), a fresh
//      LevelDB rebuilt from the per-room updates (each room is read back and
//      its state vector compared with the backup's), the assets and the
//      history twins. A failure here leaves /data exactly as it was.
//   4. Swaps: moves each current file or folder into <data>/pre-restore-<stamp>/
//      (never deleted) and renames the staged one into place. A failed swap
//      is undone.
//   The restored database keeps THIS box's backup_* settings (schedule,
//   includes, token, last run), and gets a new restore_epoch when rooms are
//   restored, so browsers drop their IndexedDB caches instead of merging
//   newer state back in (rollback). --keep-browser-caches keeps the epoch,
//   so caches refill whatever changed since the backup (recovery onto a new
//   box). --partial accepts a backup that excluded a category and keeps the
//   current data for it.
//
// Exit codes: 0 done, 1 failed or bad usage (nothing changed unless it says
// otherwise), 2 refused (verification, unsafe manifest, --partial needed, bad setup),
// 3 the server is running, 4 not enough free space, 5 the backup copy cannot
// be read by this user, so it was not checked (nothing changed).
//
// Deliberately does NOT import db.mjs: that would open (and migrate) the live
// database through the server's connection.
// ─────────────────────────────────────────────────────────────────────────
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import readline from 'node:readline';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { pipeline } from 'node:stream/promises';
import { Database } from 'bun:sqlite';
import { openZip, extractEntryTo } from './zip-stream.mjs';
import {
  verifyBackup,
  formatBytes,
  restorePlan,
  restoreSpaceNeeded,
  sameStateVector,
  mergeBackupSettings,
  chooseRestoreEpoch,
} from './backup-format.mjs';
import { checkBackupPayloads, createPosixLockProbe, zipMemberReader } from './restore-checks.mjs';

const require = createRequire(import.meta.url);
const { LeveldbPersistence } = require('y-leveldb');
const level = require('level');
const Y = require('yjs');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.resolve(process.env.DB_PATH || path.join(__dirname, 'data.sqlite'));
const DATA_DIR = path.dirname(DB_PATH);
const YPERSISTENCE = process.env.YPERSISTENCE ? path.resolve(process.env.YPERSISTENCE) : null;
const ASSETS_DIR = process.env.ASSETS_DIR ? path.resolve(process.env.ASSETS_DIR) : path.join(DATA_DIR, 'assets');
const HISTORY_DIR = process.env.HISTORY_DIR ? path.resolve(process.env.HISTORY_DIR) : path.join(DATA_DIR, 'history');

const SHARED_ROOM = 'btct-shared';
const STAGING = '.restore-staging';
const UNPACK = '.restore-unpack';
const RESERVE_BYTES = 64 * 1024 * 1024;

// 5: the backup copy could not be read, so it was not checked and nothing
// was changed (a permissions problem on the copy, not a bad backup).
const EXIT = { OK: 0, FAILED: 1, REFUSED: 2, RUNNING: 3, NO_SPACE: 4, UNREADABLE: 5 };

function usage(code = EXIT.FAILED) {
  console.error('usage: bun restore.mjs <backup.zip|backup-dir> [--yes] [--partial] [--keep-browser-caches]');
  console.error('       bun restore.mjs --verify <backup.zip|backup-dir>');
  process.exit(code);
}

function parseArgs(argv) {
  const out = { dir: null, yes: false, partial: false, verify: false, keepCaches: false };
  for (const a of argv) {
    if (a === '--yes' || a === '-y') out.yes = true;
    else if (a === '--partial') out.partial = true;
    else if (a === '--verify' || a === '--verify-only') out.verify = true;
    else if (a === '--keep-browser-caches') out.keepCaches = true;
    else if (a.startsWith('-')) usage();
    else if (!out.dir) out.dir = a;
    else usage();
  }
  if (!out.dir) usage();
  return out;
}

async function confirm(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolve) => rl.question(question, resolve));
  rl.close();
  return answer.trim().toLowerCase() === 'restore';
}

async function gunzipTo(src, dest) {
  await pipeline(fs.createReadStream(src), zlib.createGunzip(), fs.createWriteStream(dest));
}

function dirSize(dir) {
  let total = 0;
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) total += dirSize(p);
    else if (ent.isFile()) total += fs.statSync(p).size;
  }
  return total;
}

function freeBytes(dir) {
  try {
    const s = fs.statfsSync(dir);
    return Number(s.bavail) * Number(s.bsize);
  } catch {
    return null;
  }
}

/** fcntl(F_GETLK) probe from restore-checks.mjs, or null where it cannot ask. */
async function loadLockProbe() {
  try {
    return createPosixLockProbe({ fs, ffi: await import('bun:ffi') });
  } catch {
    return null;
  }
}

/**
 * Files of the live data another process holds a lock on (the server
 * running), asked without opening either store. Null when it cannot ask.
 */
async function lockedDataFiles() {
  const holder = await loadLockProbe();
  if (!holder) return null;
  const files = [
    YPERSISTENCE && path.join(YPERSISTENCE, 'LOCK'),
    DB_PATH,
    `${DB_PATH}-shm`,
  ].filter(Boolean);
  try {
    return files.filter((f) => holder(f).locked);
  } catch {
    return null;
  }
}

// Fallback only (see lockedDataFiles). Open-and-close the LevelDB through level's callback form. A locked store
// (the server still running) then surfaces as a plain error here instead of
// the unhandled 'error' event levelup emits when y-leveldb opens it without
// a callback, which would crash the process mid-message.
function probeLevelDb(dir) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (err) => { if (!settled) { settled = true; resolve(err || null); } };
    try {
      const db = level(dir, { valueEncoding: 'binary' }, (err) => {
        if (err) return done(err);
        db.close(() => done(null));
      });
      db.on('error', done);
    } catch (e) {
      done(e);
    }
  });
}

// Fallback only. A running server holds the database open in WAL mode. An exclusive
// locking-mode transaction fails then ("database is locked"); a plain
// BEGIN EXCLUSIVE would not, because WAL lets it share with an idle reader.
function probeSqlite(file) {
  let d = null;
  try {
    d = new Database(file, { readwrite: true });
    d.run('PRAGMA busy_timeout = 0');
    d.run('PRAGMA locking_mode = EXCLUSIVE');
    d.run('BEGIN EXCLUSIVE');
    d.run('COMMIT');
    return null;
  } catch (e) {
    return e;
  } finally {
    try { d?.close(); } catch { /* ignore */ }
  }
}

function settingsOf(d) {
  const backup = new Map();
  for (const r of d.query("SELECT key, value FROM settings WHERE key LIKE 'backup\\_%' ESCAPE '\\'").all()) backup.set(r.key, r.value);
  const epoch = d.query("SELECT value FROM settings WHERE key = 'restore_epoch'").get();
  return { backup, epoch: epoch ? epoch.value : null };
}

/**
 * This box's backup_* settings and restore epoch, read before anything
 * moves. Read from a copy of the database (and its -wal) in a temp folder:
 * even a read-only open of a WAL database writes to its -shm, and a restore
 * that then fails must leave /data as it was.
 */
function readCurrentSettings() {
  if (!fs.existsSync(DB_PATH)) return null;
  let d = null;
  let work = null;
  try {
    work = fs.mkdtempSync(path.join(os.tmpdir(), 'btct-restore-'));
    const copy = path.join(work, 'current.sqlite');
    fs.copyFileSync(DB_PATH, copy);
    if (fs.existsSync(`${DB_PATH}-wal`)) fs.copyFileSync(`${DB_PATH}-wal`, `${copy}-wal`);
    d = new Database(copy, { readwrite: true });
    const hasTable = d.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'settings'").get();
    if (!hasTable) return { backup: new Map(), epoch: null };
    return settingsOf(d);
  } catch (e) {
    console.warn(`[restore] could not read the current settings (${e?.message || e}); the backup's own backup settings are kept.`);
    return null;
  } finally {
    try { d?.close(); } catch { /* ignore */ }
    if (work) { try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* ignore */ } }
  }
}

function setSettingIn(d, key, value) {
  d.query('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, value);
}

/**
 * Finish the staged SQLite file: check it, keep this box's backup_* settings,
 * set the restore epoch, and add any asset row the backup's blobs have but
 * its snapshot lacks (backups taken before the BKP-2 order fix).
 */
function finishStagedSqlite(file, { current, manifest, plan, keepCaches, newEpoch }) {
  const d = new Database(file, { readwrite: true });
  try {
    // Self-contained file: no -wal beside it to leave behind in staging.
    // The server switches it back to WAL when it opens it.
    d.run('PRAGMA journal_mode = DELETE');
    const check = d.query('PRAGMA quick_check').get();
    const verdict = check ? Object.values(check)[0] : 'no answer';
    if (verdict !== 'ok') throw new Error(`the restored database fails quick_check: ${verdict}`);
    d.run('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
    const restored = settingsOf(d);
    const merge = mergeBackupSettings(restored.backup, current ? current.backup : null);
    const epoch = chooseRestoreEpoch({
      restoresRooms: plan.restore.yjsShared || plan.restore.yjsPages,
      keepCaches,
      currentEpoch: current ? current.epoch : null,
      backupEpoch: restored.epoch,
      newEpoch,
    });
    let addedRows = 0;
    d.transaction(() => {
      for (const k of merge.del) d.query('DELETE FROM settings WHERE key = ?').run(k);
      for (const [k, v] of merge.set) setSettingIn(d, k, v);
      if (epoch) setSettingIn(d, 'restore_epoch', epoch);
      if (plan.restore.assets) {
        const hasAssets = d.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'assets'").get();
        const created = Date.parse(manifest.createdAt) || Date.now();
        const ins = hasAssets ? d.query(
          'INSERT OR IGNORE INTO assets (id, workspace_id, kind, filename, mime, size, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)',
        ) : null;
        for (const a of ins ? manifest.assets : []) {
          if (!a.present) continue;
          if (![a.workspaceId, a.kind, a.filename, a.mime].every((v) => typeof v === 'string' && v)) continue;
          const r = ins.run(a.id, a.workspaceId, a.kind, a.filename, a.mime, Number(a.size) || 0, created);
          addedRows += r.changes || 0;
        }
      }
    })();
    return { kept: current ? merge.set.length : 0, epoch, addedRows };
  } finally {
    d.close();
  }
}

/** Write the rooms into a staged LevelDB and read every one back (SRV-16). */
async function stageRooms(stagedDir, { dir, manifest, plan }) {
  const full = plan.restore.yjsShared && plan.restore.yjsPages;
  if (!full && YPERSISTENCE && fs.existsSync(YPERSISTENCE)) {
    // Keep the rooms this backup does not replace. The server is stopped
    // (probed above), so the store is closed and a file copy is consistent.
    fs.cpSync(YPERSISTENCE, stagedDir, { recursive: true });
  } else {
    fs.mkdirSync(stagedDir, { recursive: true });
  }
  const ldb = new LeveldbPersistence(stagedDir);
  const expected = new Map();
  try {
    for (const d of manifest.docs) {
      const wanted = d.name === SHARED_ROOM ? plan.restore.yjsShared : plan.restore.yjsPages;
      if (!wanted) continue;
      const update = new Uint8Array(zlib.gunzipSync(fs.readFileSync(path.join(dir, 'yjs', `${d.name}.yupdate.gz`))));
      if (!full) await ldb.clearDocument(d.name);
      await ldb.storeUpdate(d.name, update);
      await ldb.flushDocument(d.name);
      expected.set(d.name, Y.decodeStateVector(Y.encodeStateVectorFromUpdate(update)));
    }
    // y-leveldb swallows write errors (it resolves null), so read every
    // room back and compare its state vector with the backup's update.
    const bad = [];
    for (const [name, sv] of expected) {
      const doc = await ldb.getYDoc(name);
      if (!doc) { bad.push(name); continue; }
      try {
        if (!sameStateVector(Y.decodeStateVector(Y.encodeStateVector(doc)), sv)) bad.push(name);
      } finally {
        doc.destroy();
      }
    }
    if (bad.length) {
      throw new Error(`${bad.length} room(s) did not read back as written: ${bad.slice(0, 10).join(', ')}`);
    }
  } finally {
    await ldb.destroy();
  }
  return expected.size;
}

function stageCopies(stagedDir, srcDir, names, { move = false } = {}) {
  fs.mkdirSync(stagedDir, { recursive: true });
  let n = 0;
  for (const [srcName, destName] of names) {
    const src = path.join(srcDir, srcName);
    const dest = path.join(stagedDir, destName);
    // Files unpacked from a ZIP are ours to move (same volume); a folder
    // backup is copied, never moved, so it stays a backup.
    let moved = false;
    if (move) {
      try { fs.renameSync(src, dest); moved = true; } catch (e) { if (e?.code !== 'EXDEV') throw e; }
    }
    if (!moved) fs.copyFileSync(src, dest);
    n += 1;
  }
  return n;
}

/** The manifest paths a restore of `plan` reads (and so unpacks from a ZIP). */
function filesForPlan(m, plan) {
  const want = new Set();
  const inc = plan.restore;
  if (inc.sqlite) want.add('sqlite/data.sqlite.gz');
  for (const d of m.docs) if (d.name === SHARED_ROOM ? inc.yjsShared : inc.yjsPages) want.add(`yjs/${d.name}.yupdate.gz`);
  if (inc.assets) for (const a of m.assets) if (a.present) want.add(`assets/${a.id}`);
  if (inc.history) for (const h of m.history || []) want.add(`history/${h.pageId}.ydoc`);
  return m.files.filter((f) => want.has(f.path));
}

/**
 * Stream the listed members of a backup ZIP into `destDir`, each re-hashed
 * against the manifest (the ZIP was verified, but it could have changed
 * since). The member names were checked by the reader and every path is a
 * manifest entry that validateManifestEntries accepted.
 */
async function unpackZip(zipPath, destDir, files) {
  const zip = await openZip(zipPath);
  try {
    fs.mkdirSync(destDir, { recursive: true, mode: 0o700 });
    const root = path.resolve(destDir) + path.sep;
    for (const f of files) {
      const entry = zip.entry(f.path);
      if (!entry) throw new Error(`missing from the archive: ${f.path}`);
      const dest = path.resolve(destDir, f.path);
      if (!dest.startsWith(root)) throw new Error(`refusing a path outside the unpack folder: ${f.path}`);
      const got = await extractEntryTo(zip, entry, dest);
      if (got.bytes !== f.bytes || got.sha256 !== f.sha256) throw new Error(`checksum mismatch while unpacking: ${f.path}`);
    }
  } finally {
    await zip.close();
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const source = path.resolve(args.dir);
  let isZip = false;
  try { isZip = fs.statSync(source).isFile(); } catch { /* verifyBackup reports it */ }
  // A folder backup is read in place; a ZIP is unpacked into `dir` below.
  const dir = isZip ? path.join(DATA_DIR, UNPACK) : source;

  console.log(`[restore] verifying ${source}`);
  const v = await verifyBackup(source);
  if (!v.ok) {
    for (const e of v.errors.slice(0, 50)) console.error(`[restore]   ${e}`);
    if (v.errors.length > 50) console.error(`[restore]   ... and ${v.errors.length - 50} more`);
    if (v.unreadable) {
      // Not a bad backup: this process may not open the copy (typically a
      // ZIP copied by root, which keeps the run's 0600; the image is uid 1000).
      console.error('[restore] cannot read the backup copy, so it was not checked; nothing was changed. Make it readable by this user (chown 1000:1000 <file>, or chmod a+r <file> and its folder) and run again.');
      process.exit(EXIT.UNREADABLE);
    }
    console.error('[restore] backup failed verification; nothing was changed.');
    process.exit(EXIT.REFUSED);
  }
  const m = v.manifest;
  // Hashes match; now decode what staging will decode, so a backup that
  // cannot be restored is refused here (exit 2) and --verify says so.
  // A ZIP is read in place here (nothing is unpacked before the plan says
  // what to restore); a folder run is read from its own files.
  let payloadErrors;
  const zipForChecks = isZip ? await openZip(source) : null;
  try {
    const read = zipForChecks ? zipMemberReader(zipForChecks) : undefined;
    payloadErrors = await checkBackupPayloads({ dir: source, read, manifest: m, Y, Database, fs, zlib, tmpDir: os.tmpdir() });
  } catch (err) {
    payloadErrors = [`cannot read the backup (${err?.message || err})`];
  } finally {
    await zipForChecks?.close();
  }
  if (payloadErrors.length) {
    for (const e of payloadErrors.slice(0, 50)) console.error(`[restore]   ${e}`);
    if (payloadErrors.length > 50) console.error(`[restore]   ... and ${payloadErrors.length - 50} more`);
    console.error('[restore] backup cannot be restored (a payload does not decode); nothing was changed.');
    process.exit(EXIT.REFUSED);
  }
  const plan = restorePlan(m.includes);
  const failedDocs = Array.isArray(m.failedDocs) ? m.failedDocs : [];
  const inc = plan.restore;

  if (args.verify) {
    console.log(`[restore] OK: ${m.createdAt} (${m.trigger}), ${m.files.length} files, ${formatBytes(m.totalBytes)}, rooms ${m.docs.length}, assets ${m.assets.filter((a) => a.present).length}, history ${(m.history || []).length}`);
    if (failedDocs.length) console.warn(`[restore] warning: the run could not read ${failedDocs.length} room(s); they are not in this backup: ${failedDocs.slice(0, 10).map((d) => d.name).join(', ')}`);
    process.exit(EXIT.OK);
  }

  if (plan.excluded.length && !args.partial) {
    console.error(`[restore] this backup excluded: ${plan.excluded.join(', ')}. Pass --partial to restore what it has and keep the current data for the rest.`);
    process.exit(EXIT.REFUSED);
  }
  console.log(`[restore] ${m.createdAt} (${m.trigger}) from instance ${m.instanceId || '?'}: ${m.files.length} files, ${formatBytes(m.totalBytes)}`);
  console.log(`[restore]   sqlite=${inc.sqlite} shared-doc=${inc.yjsShared} page-docs=${inc.yjsPages} assets=${inc.assets} history=${inc.history}`);
  if (plan.absent.length) {
    console.log(`[restore]   this backup predates: ${plan.absent.join(', ')}; the current data for ${plan.absent.length === 1 ? 'it' : 'them'} is kept.`);
  }
  if (failedDocs.length) {
    console.warn(`[restore] warning: the backup run could not read ${failedDocs.length} room(s), so they will be missing: ${failedDocs.slice(0, 10).map((d) => d.name).join(', ')}`);
  }
  const restoresRooms = inc.yjsShared || inc.yjsPages;
  if (restoresRooms && !YPERSISTENCE) {
    console.error('[restore] YPERSISTENCE is not set, so Yjs rooms cannot be restored. Set it to the server\'s value (e.g. /data/yjs).');
    process.exit(EXIT.REFUSED);
  }

  // Refuse while the server runs, whatever this backup restores (BKP-9).
  const locked = await lockedDataFiles();
  if (locked && locked.length) {
    console.error(`[restore] another process holds ${locked.join(', ')} open.`);
    console.error('[restore] the server appears to be running. Stop it first (docker compose stop btct).');
    process.exit(EXIT.RUNNING);
  }
  if (!locked) console.warn('[restore] cannot ask the kernel for file locks here; probing by opening the stores instead (this rewrites LevelDB\'s log and SQLite\'s WAL files, without changing data).');
  if (!locked && YPERSISTENCE && fs.existsSync(YPERSISTENCE)) {
    const lockErr = await probeLevelDb(YPERSISTENCE);
    if (lockErr) {
      console.error(`[restore] cannot open ${YPERSISTENCE}: ${lockErr?.message || lockErr}`);
      console.error('[restore] the server appears to be running. Stop it first (docker compose stop btct).');
      process.exit(EXIT.RUNNING);
    }
  }
  if (!locked && fs.existsSync(DB_PATH)) {
    const sqlErr = probeSqlite(DB_PATH);
    if (sqlErr) {
      console.error(`[restore] cannot lock ${DB_PATH}: ${sqlErr?.message || sqlErr}`);
      console.error('[restore] the server appears to be running. Stop it first (docker compose stop btct).');
      process.exit(EXIT.RUNNING);
    }
  }

  const targets = [
    inc.sqlite && { key: 'sqlite', path: DB_PATH, label: path.basename(DB_PATH) },
    restoresRooms && { key: 'yjs', path: YPERSISTENCE, label: 'yjs' },
    inc.assets && { key: 'assets', path: ASSETS_DIR, label: 'assets' },
    inc.history && { key: 'history', path: HISTORY_DIR, label: 'history' },
  ].filter(Boolean);
  if (!targets.length) {
    console.error('[restore] this backup holds nothing to restore.');
    process.exit(EXIT.REFUSED);
  }
  for (const t of targets) {
    t.parent = path.dirname(t.path);
    t.staged = path.join(t.parent, STAGING, path.basename(t.path));
    fs.mkdirSync(t.parent, { recursive: true });
    if (fs.existsSync(t.path) && fs.statSync(t.path).dev !== fs.statSync(t.parent).dev) {
      console.error(`[restore] ${t.path} is a mount point; it cannot be swapped by a rename. Restore into a layout where it is a plain folder.`);
      process.exit(EXIT.REFUSED);
    }
  }

  // Free space: everything is staged on the data volume before the swap.
  const currentYjsBytes = restoresRooms && !(inc.yjsShared && inc.yjsPages) && fs.existsSync(YPERSISTENCE) ? dirSize(YPERSISTENCE) : 0;
  // A ZIP is unpacked on the data volume first. Its assets and twins are
  // then moved into staging (no second copy); the gzipped database and
  // rooms stay in the unpack folder until the end.
  const unpackFiles = isZip ? filesForPlan(m, plan) : [];
  const unpackExtra = unpackFiles
    .filter((f) => !f.path.startsWith('assets/') && !f.path.startsWith('history/'))
    .reduce((n, f) => n + (Number(f.bytes) || 0), 0);
  const needed = restoreSpaceNeeded(m, plan, { currentYjsBytes }) + unpackExtra + RESERVE_BYTES;
  for (const parent of new Set(targets.map((t) => t.parent))) {
    const free = freeBytes(parent);
    if (free !== null && free < needed) {
      console.error(`[restore] not enough space in ${parent}: ${formatBytes(free)} free, about ${formatBytes(needed)} needed. Nothing was changed.`);
      process.exit(EXIT.NO_SPACE);
    }
  }

  if (!args.yes) {
    console.log(`[restore] this replaces the data under ${DATA_DIR}. The current files are kept in a pre-restore folder.`);
    if (!(await confirm("Type 'restore' to continue: "))) {
      console.log('[restore] cancelled.');
      process.exit(EXIT.OK);
    }
  }

  const current = readCurrentSettings();
  const newEpoch = crypto.randomUUID();
  const stagingRoots = [...new Set(targets.map((t) => path.join(t.parent, STAGING)))];
  const clearStaging = () => { for (const r of stagingRoots) fs.rmSync(r, { recursive: true, force: true }); };
  const summary = [];
  let sqliteInfo = null;

  // ── Stage: nothing under /data changes until every part is built ──
  const clearUnpack = () => { if (isZip) fs.rmSync(dir, { recursive: true, force: true }); };
  if (isZip) process.on('exit', () => { try { clearUnpack(); } catch { /* best effort */ } });
  try {
    clearStaging(); // a leftover from an earlier failed attempt is ours
    clearUnpack();
    if (isZip) {
      console.log(`[restore] unpacking ${unpackFiles.length} files from ${path.basename(source)}`);
      await unpackZip(source, dir, unpackFiles);
    }
    for (const r of stagingRoots) fs.mkdirSync(r, { recursive: true });
    for (const t of targets) {
      if (t.key === 'sqlite') {
        await gunzipTo(path.join(dir, 'sqlite', 'data.sqlite.gz'), t.staged);
        sqliteInfo = finishStagedSqlite(t.staged, { current, manifest: m, plan, keepCaches: args.keepCaches, newEpoch });
        summary.push(`sqlite: ${formatBytes(fs.statSync(t.staged).size)}`);
      } else if (t.key === 'yjs') {
        summary.push(`yjs rooms: ${await stageRooms(t.staged, { dir, manifest: m, plan })} (each read back)`);
      } else if (t.key === 'assets') {
        const n = stageCopies(t.staged, path.join(dir, 'assets'), m.assets.filter((a) => a.present).map((a) => [a.id, a.id]), { move: isZip });
        summary.push(`assets: ${n}`);
      } else if (t.key === 'history') {
        const n = stageCopies(t.staged, path.join(dir, 'history'), (m.history || []).map((h) => [`${h.pageId}.ydoc`, `${h.pageId}.ydoc`]), { move: isZip });
        summary.push(`history twins: ${n}`);
      }
    }
  } catch (e) {
    try { clearStaging(); } catch { /* reported below */ }
    try { clearUnpack(); } catch { /* removed on exit */ }
    console.error(`[restore] failed while preparing the restore: ${e?.message || e}`);
    console.error('[restore] nothing was changed.');
    process.exit(EXIT.FAILED);
  }

  // ── Swap: move the current data aside, rename the staged data in ──
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const asideOf = (t) => path.join(t.parent, `pre-restore-${stamp}`);
  const moves = [];
  const mv = (from, to) => {
    fs.mkdirSync(path.dirname(to), { recursive: true });
    fs.renameSync(from, to);
    moves.push([from, to]);
  };
  try {
    for (const t of targets) {
      const aside = asideOf(t);
      if (t.key === 'sqlite') {
        for (const suffix of ['', '-wal', '-shm', '-journal']) {
          if (fs.existsSync(`${t.path}${suffix}`)) mv(`${t.path}${suffix}`, path.join(aside, `${t.label}${suffix}`));
        }
      } else if (fs.existsSync(t.path)) {
        mv(t.path, path.join(aside, t.label));
      }
      mv(t.staged, t.path);
    }
  } catch (e) {
    console.error(`[restore] failed while swapping the data in: ${e?.message || e}`);
    const stuck = [];
    for (const [from, to] of moves.reverse()) {
      try { fs.renameSync(to, from); } catch { stuck.push([from, to]); }
    }
    if (!stuck.length) {
      try { clearStaging(); } catch { /* harmless leftovers */ }
      console.error('[restore] the swap was undone; the data is as it was before.');
    } else {
      console.error('[restore] the swap could NOT be fully undone. Move these back by hand (server stopped):');
      for (const [from, to] of stuck) console.error(`[restore]   mv '${to}' '${from}'`);
    }
    process.exit(EXIT.FAILED);
  }
  try { clearStaging(); } catch { /* empty folders */ }
  try { clearUnpack(); } catch { /* removed on exit */ }

  // Rooms restored without the database: the epoch goes into the live one.
  const notes = [];
  if (sqliteInfo) {
    if (current) notes.push(`kept this box's backup settings (${sqliteInfo.kept} keys)`);
    else notes.push("took the backup's own backup settings, host token and instance id (no settings of this box to keep, so it takes the place of the box that made the backup; regenerate the backup token in the admin panel if that box keeps running) and cleared its run history");
    if (sqliteInfo.addedRows) notes.push(`added ${sqliteInfo.addedRows} missing asset row(s)`);
    if (restoresRooms && !args.keepCaches) notes.push('new restore epoch: browsers drop their cached copies on next load');
  } else if (restoresRooms && !args.keepCaches) {
    if (fs.existsSync(DB_PATH)) {
      try {
        const d = new Database(DB_PATH, { readwrite: true });
        try {
          d.run('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
          setSettingIn(d, 'restore_epoch', newEpoch);
        } finally { d.close(); }
        notes.push('new restore epoch: browsers drop their cached copies on next load');
      } catch (e) {
        notes.push(`could not write a new restore epoch (${e?.message || e}); ask everyone to clear site data before reconnecting`);
      }
    } else {
      notes.push('no database yet, so no restore epoch was written; browsers that cached this server keep their copies');
    }
  }
  if (restoresRooms && args.keepCaches) notes.push('restore epoch kept (--keep-browser-caches): browsers merge their cached copies back in');

  console.log(`[restore] done: ${summary.join(', ')}`);
  for (const n of notes) console.log(`[restore] ${n}.`);
  for (const parent of new Set(targets.map((t) => t.parent))) {
    const aside = path.join(parent, `pre-restore-${stamp}`);
    if (fs.existsSync(aside)) console.log(`[restore] previous data kept in ${aside}; delete it once you are happy.`);
  }
  console.log('[restore] start the server again (docker compose start btct) and check /healthz.');
}

main().catch((e) => {
  console.error(`[restore] failed: ${e?.stack || e}`);
  console.error('[restore] if this happened during the swap, the data may be mixed: compare the pre-restore folder with /data.');
  process.exit(EXIT.FAILED);
});
