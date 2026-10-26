// ─────────────────────────────────────────────────────────────────────────
// Backup engine: scheduled, consistent snapshots of the whole instance into
// a host folder (BACKUP_DIR, bind-mounted from the Docker host).
//
// One run = one self-contained ZIP `btct-backup-YYYYMMDD-HHMMSS.zip` (layout
// and manifest in backup-format.mjs), streamed entry by entry into
// `<name>.zip.tmp` (zip-stream.mjs: bounded memory, whatever the size),
// fsynced and renamed into place only after the manifest is its last entry,
// so a half-finished run is never mistaken for a backup. Data is read
// through data-export.mjs (VACUUM INTO, per-room Yjs updates, asset reads),
// never by copying live files.
//
// Config lives in the SQLite settings table (admin UI), the scheduler in
// scheduler.mjs. Every ZIP is a full copy, so "keep the last N runs"
// (backup_keep_last) defaults to KEEP_LAST_DEFAULT; an explicit 0 keeps all.
// Folders written by older builds (hard-linked assets) are listed, counted
// for keep-last and restorable alongside.
//
// This module is a deliberate exception to "the server is dumb about domain
// data" (invariant #4): it moves bytes and knows room names, never meaning.
// ─────────────────────────────────────────────────────────────────────────
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { getSetting, setSetting } from './db.mjs';
import { createJob } from './scheduler.mjs';
import {
  MANIFEST_FILE,
  ZIP_EXT,
  ENTRY_ID_RE,
  normalizeBackupConfig,
  normalizeKeepLast,
  backupName,
  backupNameTime,
  parseBackupEntryName,
  isStaleTmpRun,
  buildManifest,
  readManifest,
  readZipManifest,
  estimateRunBytes,
  runsToPrune,
  withTimeout,
  sha256File,
  formatBytes,
} from './backup-format.mjs';
import {
  SHARED_ROOM,
  drainPersistence,
  exportSqliteTo,
  listDocNames,
  exportDocUpdate,
  isEmptyUpdate,
  listAssetRows,
  listAssetRowsFrom,
  assetPath,
} from './data-export.mjs';
import { HISTORY_DIR, flushAllTwins } from './history.mjs';
import { ZipWriter, openZip } from './zip-stream.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const T = {
  ENABLED: 'backup_enabled',
  INTERVAL: 'backup_full_interval_min',
  INCLUDES: 'backup_includes',
  KEEP_LAST: 'backup_keep_last',
  TOKEN: 'backup_token',
  INSTANCE: 'backup_instance_id',
  LAST_RUN: 'backup_last_run_at',
  LAST_RESULT: 'backup_last_result',
  LAST_GOOD: 'backup_last_good',
};

// Written by restore.mjs (a new uuid per restore that rolls rooms back).
// Not a backup_* key: restore keeps the box's own backup_* settings.
const RESTORE_EPOCH = 'restore_epoch';

// Where backups land. In Docker this is /backups (compose bind-mounts
// BACKUP_HOST_DIR, default ./backups, there); in dev it defaults to a `backups/` folder beside the DB.
export const BACKUP_DIR = process.env.BACKUP_DIR
  ? path.resolve(process.env.BACKUP_DIR)
  : path.join(path.dirname(path.resolve(process.env.DB_PATH || path.join(__dirname, 'data.sqlite'))), 'backups');

// The host folder compose bind-mounts at BACKUP_DIR (BACKUP_HOST_DIR in
// .env), passed in as BACKUP_HOST_DIR_LABEL for display in the admin panel
// only. Nothing reads or writes it; null outside compose.
export const BACKUP_HOST_DIR_LABEL = (() => {
  const v = String(process.env.BACKUP_HOST_DIR_LABEL || '').replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return v ? v.slice(0, 512) : null;
})();

const DB_FILE = path.resolve(process.env.DB_PATH || path.join(__dirname, 'data.sqlite'));

function envNumber(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

// A run that has not finished by the deadline is abandoned (its .tmp is
// removed and lastError says why), so a stuck LevelDB read can never hold
// `running` forever and block every later run with 409. One room that does
// not answer within the room timeout is recorded as failed and skipped.
const RUN_DEADLINE_MS = envNumber('BACKUP_DEADLINE_S', 30 * 60) * 1000;
const ROOM_TIMEOUT_MS = envNumber('BACKUP_ROOM_TIMEOUT_S', 60) * 1000;
// Free space left on the backup disk after a run. ./backups usually shares a
// disk with the Docker volume, and a full disk also hits live persistence.
const MIN_FREE_BYTES = envNumber('BACKUP_MIN_FREE_MB', 256) * 1024 * 1024;
// A failed scheduled run is retried after this (or the interval, if shorter).
const RETRY_MS = 5 * 60 * 1000;

const RUN_DIR_MODE = 0o700;
const FILE_MODE = 0o600;

const genToken = () => crypto.randomBytes(32).toString('hex');

function ensureDir() {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

function dirWritable() {
  try {
    ensureDir();
    fs.accessSync(BACKUP_DIR, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

function freeBytes(dir) {
  try {
    const s = fs.statfsSync(dir);
    return Number(s.bavail) * Number(s.bsize);
  } catch {
    return null;
  }
}

function instanceId() {
  let id = getSetting(T.INSTANCE);
  if (!id) {
    id = crypto.randomUUID();
    setSetting(T.INSTANCE, id);
  }
  return id;
}

function readJsonSetting(key) {
  try { return JSON.parse(getSetting(key) || 'null'); } catch { return null; }
}

/**
 * A complete run whose result SQLite could not store (a full /data). Kept
 * in memory so status and the last-good summary still show it.
 */
let unrecordedGood = null;

const newer = (a, b) => (b && (!a || (Number(b.at) || 0) >= (Number(a.at) || 0)) ? b : a);

function lastResult() {
  return newer(readJsonSetting(T.LAST_RESULT), unrecordedGood);
}

/** The newest successful run, kept apart from the last result so a failure does not hide it. */
function lastGood() {
  const good = newer(readJsonSetting(T.LAST_GOOD), unrecordedGood);
  if (good) return good;
  const last = lastResult(); // boxes from before backup_last_good existed
  return last?.ok ? last : null;
}

/** The restore epoch browsers compare their IndexedDB caches against (null until a restore). */
export function currentRestoreEpoch() {
  return getSetting(RESTORE_EPOCH) || null;
}

// ── Config ─────────────────────────────────────────────────────────────

export function getBackupConfig() {
  const cfg = normalizeBackupConfig({
    enabled: getSetting(T.ENABLED),
    fullIntervalMin: getSetting(T.INTERVAL),
    includes: getSetting(T.INCLUDES),
  });
  return {
    ...cfg,
    keepLast: normalizeKeepLast(getSetting(T.KEEP_LAST)),
    dir: BACKUP_DIR,
    hostDir: BACKUP_HOST_DIR_LABEL,
    token: getSetting(T.TOKEN) || null,
    configured: !!getSetting(T.TOKEN),
    instanceId: instanceId(),
  };
}

export function setBackupConfig(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('body must be an object');
  if (body.enabled !== undefined && typeof body.enabled !== 'boolean') throw new Error('enabled must be a boolean');
  if (body.fullIntervalMin !== undefined && !Number.isFinite(Number(body.fullIntervalMin))) {
    throw new Error('fullIntervalMin must be a number of minutes');
  }
  if (body.includes !== undefined && (typeof body.includes !== 'object' || body.includes === null || Array.isArray(body.includes))) {
    throw new Error('includes must be an object');
  }
  if (body.keepLast !== undefined && !(Number.isFinite(Number(body.keepLast)) && Number(body.keepLast) >= 0)) {
    throw new Error('keepLast must be a number of runs (0 = keep all)');
  }
  const current = getBackupConfig();
  const merged = normalizeBackupConfig({
    enabled: body.enabled ?? current.enabled,
    fullIntervalMin: body.fullIntervalMin ?? current.fullIntervalMin,
    includes: body.includes ? { ...current.includes, ...body.includes } : current.includes,
  });
  setSetting(T.ENABLED, merged.enabled ? '1' : '0');
  setSetting(T.INTERVAL, String(merged.fullIntervalMin));
  setSetting(T.INCLUDES, JSON.stringify(merged.includes));
  if (body.keepLast !== undefined) setSetting(T.KEEP_LAST, String(normalizeKeepLast(body.keepLast)));
  if (merged.enabled && !getSetting(T.TOKEN)) setSetting(T.TOKEN, genToken()); // mint on first enable
  if (job) job.reschedule();
  return getBackupConfig();
}

export function regenerateBackupToken() {
  const t = genToken();
  setSetting(T.TOKEN, t);
  return t;
}

/** True when the request carries the static backup token (for host schedulers). */
export function matchesBackupToken(req) {
  const token = getSetting(T.TOKEN);
  if (!token) return false;
  const h = req.headers?.authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  if (!m) return false;
  const a = Buffer.from(m[1].trim());
  const b = Buffer.from(token);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ── Running a backup ───────────────────────────────────────────────────


function dirSize(dir) {
  let total = 0;
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) total += dirSize(p);
    else if (ent.isFile()) total += fs.statSync(p).size;
  }
  return total;
}

function twinNames() {
  if (!fs.existsSync(HISTORY_DIR)) return [];
  return fs.readdirSync(HISTORY_DIR).filter((f) => f.endsWith('.ydoc')).map((f) => f.slice(0, -'.ydoc'.length));
}

/** The manifest of a complete run (a ZIP or an older folder), or null. */
async function manifestOf(name) {
  const p = parseBackupEntryName(name);
  if (!p || p.partial) return null;
  const abs = path.join(BACKUP_DIR, name);
  if (p.kind === 'dir') return readManifest(abs).manifest || null;
  let zip;
  try {
    zip = await openZip(abs);
    return (await readZipManifest(zip)).manifest || null;
  } catch {
    return null;
  } finally {
    await zip?.close();
  }
}

/**
 * The newest complete run that holds assets (for the space estimate), or
 * null. A run that left assets out is skipped, so one sqlite-only run does
 * not make the next estimate miss the non-asset bytes of a full run.
 */
async function newestCompleteManifest() {
  for (const b of await listBackups()) {
    if (b.partial || b.includes?.assets === false) continue;
    const manifest = await manifestOf(b.name);
    if (manifest) return { name: b.name, manifest };
  }
  return null;
}

let inProgress = false;
let runningSince = null;

/**
 * Write one backup directory. Throws on failure (the .tmp dir is removed).
 *
 * Order matters (BKP-2): Yjs rooms first, then the SQLite snapshot, then the
 * assets listed in that SNAPSHOT, then the history twins. A screenshot pasted
 * during the run is referenced by a room only once its row exists, so every
 * asset a backed-up room points at has a row in the backed-up database, and
 * every row has its blob (or is recorded present:false when retention or a
 * delete removed it in between). Twins stay a superset of page_versions.
 */
export async function runBackup({ trigger = 'manual' } = {}) {
  if (inProgress) {
    const e = new Error('a backup is already running');
    e.code = 'BUSY';
    throw e;
  }
  inProgress = true;
  const startedAt = Date.now();
  runningSince = startedAt;
  const ctl = { aborted: false, tmpDir: null, tmpZip: null, writer: null, name: null };
  try {
    return await withTimeout(writeRun(trigger, startedAt, ctl), RUN_DEADLINE_MS, 'backup');
  } catch (e) {
    ctl.aborted = true;
    // The ZIP may still be open when the deadline fires: close it, then
    // remove the partial file and the scratch folder.
    if (ctl.writer) await ctl.writer.abort();
    if (ctl.tmpZip) fs.rmSync(ctl.tmpZip, { force: true });
    if (ctl.tmpDir) fs.rmSync(ctl.tmpDir, { recursive: true, force: true });
    // Best effort: the error may be SQLite itself being unwritable, and the
    // run's own error is the one to report.
    try {
      setSetting(T.LAST_RESULT, JSON.stringify({ ok: false, at: startedAt, trigger, error: String(e?.message || e) }));
    } catch (recordErr) {
      console.warn(`[backup] could not record the failed run: ${recordErr?.message || recordErr}`);
    }
    throw e;
  } finally {
    inProgress = false;
    runningSince = null;
    if (ctl.name) {
      for (const n of [ctl.name, `${ctl.name}.tmp`, `${ctl.name}${ZIP_EXT}`, `${ctl.name}${ZIP_EXT}.tmp`]) summaryCache.delete(n);
    }
  }
}

/** fsync a directory so a rename in it survives a power cut (best effort). */
function syncDir(dir) {
  let fd = null;
  try {
    fd = fs.openSync(dir, 'r');
    fs.fsyncSync(fd);
  } catch { /* not supported here (some bind mounts) */ } finally {
    if (fd !== null) try { fs.closeSync(fd); } catch { /* ignore */ }
  }
}

async function writeRun(trigger, startedAt, ctl) {
  // After the deadline the outer call has already given up and removed the
  // partial files; a step that wakes up late must not write anything more.
  const alive = () => {
    if (ctl.aborted) throw new Error('backup abandoned after its deadline');
  };
  const cfg = getBackupConfig();
  const name = backupName(new Date(startedAt));
  ctl.name = name;
  const fileName = `${name}${ZIP_EXT}`;
  const finalZip = path.join(BACKUP_DIR, fileName);
  const tmpZip = `${finalZip}.tmp`;
  // Scratch space for the raw SQLite snapshot while it is gzipped into the
  // ZIP; a crash leaves it as `<name>.tmp`, which boot cleanup removes.
  const tmpDir = path.join(BACKUP_DIR, `${name}.tmp`);
  const files = [];
  const docsMeta = [];
  const failedDocs = [];
  const assetsMeta = [];
  const historyMeta = [];
  let sqliteMeta = null;

  ensureDir();
  if (fs.existsSync(finalZip) || fs.existsSync(path.join(BACKUP_DIR, name))) {
    throw new Error(`${name} already exists (two runs in the same second)`);
  }

  // Space precheck (BKP-8): fail fast instead of filling the disk the live
  // data is probably on. Every run is a full copy, assets included.
  const prev = await newestCompleteManifest();
  alive();
  const liveAssets = cfg.includes.assets ? listAssetRows() : [];
  let dbBytes = 0;
  try { dbBytes = fs.statSync(DB_FILE).size; } catch { /* no database file yet */ }
  let fallbackBytes = dbBytes;
  try { if (cfg.includes.history && fs.existsSync(HISTORY_DIR)) fallbackBytes += dirSize(HISTORY_DIR); } catch { /* best effort */ }
  const estimate = estimateRunBytes({
    prevManifest: prev?.manifest, assets: liveAssets, fallbackBytes, scratchBytes: cfg.includes.sqlite ? dbBytes : 0,
  });
  const free = freeBytes(BACKUP_DIR);
  if (free !== null && free < estimate + MIN_FREE_BYTES) {
    const e = new Error(`not enough space in ${BACKUP_DIR}: ${formatBytes(free)} free, this run needs about ${formatBytes(estimate)} plus ${formatBytes(MIN_FREE_BYTES)} kept free (lower "keep last" or delete old backups)`);
    e.code = 'NO_SPACE';
    throw e;
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });
  fs.rmSync(tmpZip, { force: true });
  ctl.tmpDir = tmpDir;
  fs.mkdirSync(tmpDir, { recursive: true, mode: RUN_DIR_MODE });
  fs.chmodSync(tmpDir, RUN_DIR_MODE);
  ctl.tmpZip = tmpZip;
  const zip = await ZipWriter.create(tmpZip, { mode: FILE_MODE, date: new Date(startedAt) });
  if (ctl.aborted) { await zip.abort(); fs.rmSync(tmpZip, { force: true }); alive(); }
  ctl.writer = zip;
  const record = (r) => { files.push({ path: r.name, bytes: r.bytes, sha256: r.sha256 }); };

  // 1. Yjs rooms. Wait for the persistence to write what it holds, then read
  //    every room; a room that cannot be read is listed in the manifest and
  //    skipped instead of failing the run (SRV-7). One room is gzipped in
  //    memory at a time (a room is at most a few MB).
  if (cfg.includes.yjsShared || cfg.includes.yjsPages) {
    if (!(await drainPersistence())) {
      console.warn('[btct-backup] the relay persistence is failing writes; rooms closed since then may be missing their latest edits in this run (see /api/admin/status)');
    }
    alive();
    const names = await listDocNames(cfg.includes.yjsPages ? twinNames() : []);
    alive();
    for (const docName of names) {
      const wanted = docName === SHARED_ROOM ? cfg.includes.yjsShared : cfg.includes.yjsPages;
      if (!wanted) continue;
      let update;
      try {
        update = await withTimeout(exportDocUpdate(docName), ROOM_TIMEOUT_MS, `room ${docName}`);
      } catch (e) {
        alive();
        failedDocs.push({ name: docName, error: String(e?.message || e).slice(0, 200) });
        continue;
      }
      alive();
      if (isEmptyUpdate(update)) continue;
      record(await zip.addBuffer(`yjs/${docName}.yupdate.gz`, zlib.gzipSync(Buffer.from(update), { level: 6 })));
      docsMeta.push({ name: docName, bytes: update.byteLength });
      alive();
    }
  }

  // 2. SQLite snapshot, and the asset list read from that snapshot. The
  //    snapshot is gzipped straight into the ZIP.
  let assetRows = cfg.includes.assets ? liveAssets : [];
  if (cfg.includes.sqlite) {
    const raw = path.join(tmpDir, 'data.sqlite');
    const rawBytes = exportSqliteTo(raw);
    if (cfg.includes.assets) assetRows = listAssetRowsFrom(raw);
    alive();
    const src = fs.createReadStream(raw, { highWaterMark: 1024 * 1024 });
    const gz = zlib.createGzip({ level: 6 });
    src.on('error', (e) => gz.destroy(e));
    try {
      record(await zip.addIterable('sqlite/data.sqlite.gz', src.pipe(gz), { sizeHint: rawBytes + 64 * 1024 }));
    } finally {
      src.destroy();
      gz.destroy();
    }
    alive();
    fs.unlinkSync(raw);
    sqliteMeta = { rawBytes };
  }

  // 3. Asset blobs, streamed from ASSETS_DIR.
  if (cfg.includes.assets) {
    for (const row of assetRows) {
      if (!ENTRY_ID_RE.test(String(row.id))) continue;
      const meta = {
        id: row.id, filename: row.filename, mime: row.mime, size: row.size,
        workspaceId: row.workspace_id, kind: row.kind, present: false,
      };
      assetsMeta.push(meta);
      let r;
      try {
        r = await zip.addFile(`assets/${row.id}`, assetPath(row.id));
      } catch (e) {
        // Deleted since the snapshot (retention, the Assets Manager): the
        // reader fails before the entry's header is written.
        if (e?.code === 'ENOENT') continue;
        throw e;
      }
      meta.present = true;
      record(r);
      alive();
    }
  }

  // 4. History twins: flush the open ones so the files match what the
  //    running server holds.
  if (cfg.includes.history) {
    flushAllTwins();
    for (const pageId of twinNames()) {
      if (!ENTRY_ID_RE.test(pageId)) continue;
      let r;
      try {
        r = await zip.addFile(`history/${pageId}.ydoc`, path.join(HISTORY_DIR, `${pageId}.ydoc`));
      } catch (e) {
        if (e?.code === 'ENOENT') continue;
        throw e;
      }
      historyMeta.push({ pageId, bytes: r.bytes });
      record(r);
      alive();
    }
  }

  const manifest = buildManifest({
    instanceId: cfg.instanceId,
    createdAt: new Date(startedAt).toISOString(),
    trigger,
    includes: cfg.includes,
    files,
    docs: docsMeta,
    failedDocs,
    sqlite: sqliteMeta,
    assets: assetsMeta,
    history: historyMeta,
    linkedBytes: 0,
    app: { name: 'btct', hostname: os.hostname() },
  });
  alive();
  await zip.addBuffer(MANIFEST_FILE, Buffer.from(JSON.stringify(manifest)));
  alive();
  const zipBytes = await zip.finish();
  ctl.writer = null;
  alive();
  fs.chmodSync(tmpZip, FILE_MODE);
  fs.renameSync(tmpZip, finalZip);
  ctl.tmpZip = null;
  syncDir(BACKUP_DIR);
  fs.rmSync(tmpDir, { recursive: true, force: true });
  ctl.tmpDir = null;

  const result = {
    ok: true,
    name: fileName,
    at: startedAt,
    trigger,
    bytes: zipBytes,
    newBytes: zipBytes,
    files: files.length,
    docs: docsMeta.length,
    assets: assetsMeta.filter((a) => a.present).length,
    history: historyMeta.length,
    failedRooms: failedDocs.map((d) => d.name),
    durationMs: Date.now() - startedAt,
  };
  // The run is complete and on disk from here on. A full /data must not
  // turn it into a failure: that skipped keep-last pruning, so every retry
  // (each a complete archive) piled up, and status said every run failed.
  try {
    setSetting(T.LAST_RESULT, JSON.stringify(result));
    setSetting(T.LAST_GOOD, JSON.stringify(result));
    unrecordedGood = null;
  } catch (e) {
    unrecordedGood = result;
    console.warn(`[backup] ${fileName} is complete, but its result could not be saved in SQLite (${e?.message || e}); status shows it until a restart`);
  }
  const warn = failedDocs.length ? `; ${failedDocs.length} room(s) could not be read: ${failedDocs.slice(0, 5).map((d) => d.name).join(', ')}` : '';
  console.log(`[backup] wrote ${fileName}: ${files.length} files, ${formatBytes(zipBytes)}, ${result.durationMs} ms (${trigger})${warn}`);
  await pruneOldRuns(fileName, cfg.keepLast);
  return result;
}

/** Retention: keep the newest `keepLast` complete runs, ZIPs and older folders alike (0 = keep all). */
async function pruneOldRuns(justWritten, keepLast) {
  if (!keepLast) return;
  const complete = (await listBackups()).filter((b) => !b.partial).map((b) => b.name);
  for (const old of runsToPrune(complete, keepLast, justWritten)) {
    try {
      deleteBackup(old);
      console.log(`[backup] removed ${old} (keeping the last ${keepLast})`);
    } catch (e) {
      console.warn(`[backup] could not remove ${old}: ${e?.message || e}`);
    }
  }
}

/**
 * Remove what a crash or restart left behind, once it is an hour old: a
 * `<name>.zip.tmp` file, a `<name>.tmp` scratch folder, or a `<name>.tmp`
 * run folder from an older build.
 */
export function removeStaleTmpRuns(now = Date.now()) {
  if (!fs.existsSync(BACKUP_DIR)) return [];
  const removed = [];
  for (const ent of fs.readdirSync(BACKUP_DIR, { withFileTypes: true })) {
    if (!ent.isDirectory() && !ent.isFile()) continue;
    const p = path.join(BACKUP_DIR, ent.name);
    let mtimeMs;
    try { mtimeMs = fs.statSync(p).mtimeMs; } catch { continue; }
    if (!isStaleTmpRun(ent.name, mtimeMs, now)) continue;
    try {
      fs.rmSync(p, { recursive: true, force: true });
      summaryCache.delete(ent.name);
      removed.push(ent.name);
    } catch (e) {
      console.warn(`[backup] could not remove ${ent.name}: ${e?.message || e}`);
    }
  }
  return removed;
}

// ── Inventory ──────────────────────────────────────────────────────────
//
// Status and list used to parse every manifest on every call (about 400 KB
// each at competition size, so 100 runs stalled the relay for 165-322 ms per
// admin-panel poll). A finished run never changes, so its summary is cached
// by name, mtime and size; runBackup and deleteBackup drop entries.

const summaryCache = new Map(); // name -> { mtimeMs, size, summary }

async function summarize(entName, abs, info, st) {
  const manifest = info.partial ? null : await manifestOf(entName);
  const bytes = info.kind === 'zip' ? st.size : manifest ? manifest.totalBytes : dirSize(abs);
  return {
    name: entName,
    format: info.kind === 'zip' ? 'zip' : 'folder',
    createdAt: manifest?.createdAt || new Date(backupNameTime(info.base) || 0).toISOString(),
    bytes,
    // Disk the run adds: a ZIP is a full copy; an older folder's unchanged
    // assets were hard links to the run before it.
    newBytes: info.kind === 'zip' ? bytes : manifest ? manifest.totalBytes - (Number(manifest.linkedBytes) || 0) : 0,
    files: manifest ? manifest.files.length : 0,
    includes: manifest ? manifest.includes : null,
    trigger: manifest ? manifest.trigger : null,
    failedRooms: manifest && Array.isArray(manifest.failedDocs) ? manifest.failedDocs.length : 0,
    partial: info.partial || !manifest,
  };
}

/** Every run in BACKUP_DIR, newest first: `<name>.zip` files and older `<name>/` folders, `.tmp` ones as partial. */
export async function listBackups() {
  if (!fs.existsSync(BACKUP_DIR)) { summaryCache.clear(); return []; }
  const out = [];
  const seen = new Set();
  for (const ent of fs.readdirSync(BACKUP_DIR, { withFileTypes: true })) {
    const info = parseBackupEntryName(ent.name);
    if (!info) continue;
    // A ZIP run is a file; a folder run (or an older build's .tmp) a folder.
    // `<name>.tmp` folders of a ZIP run are scratch space: not listed.
    if (info.kind === 'zip' ? !ent.isFile() : !ent.isDirectory()) continue;
    if (info.kind === 'dir' && info.partial && fs.existsSync(path.join(BACKUP_DIR, `${info.base}${ZIP_EXT}.tmp`))) continue;
    const abs = path.join(BACKUP_DIR, ent.name);
    let st;
    try { st = fs.statSync(abs); } catch { continue; }
    seen.add(ent.name);
    const cached = summaryCache.get(ent.name);
    if (cached && cached.mtimeMs === st.mtimeMs && cached.size === st.size) { out.push(cached.summary); continue; }
    let summary;
    try { summary = await summarize(ent.name, abs, info, st); } catch { continue; } // removed while listing
    summaryCache.set(ent.name, { mtimeMs: st.mtimeMs, size: st.size, summary });
    out.push(summary);
  }
  for (const name of summaryCache.keys()) if (!seen.has(name)) summaryCache.delete(name);
  const key = (b) => parseBackupEntryName(b.name)?.base || b.name;
  return out.sort((a, b) => (key(a) === key(b) ? (a.name < b.name ? 1 : -1) : key(a) < key(b) ? 1 : -1));
}

/** Delete one run by its listed name (`<name>.zip`, an older `<name>` folder, or either with `.tmp`). */
export function deleteBackup(name) {
  const info = parseBackupEntryName(name);
  if (!info) throw new Error('invalid backup name');
  const abs = path.join(BACKUP_DIR, name);
  let st;
  try { st = fs.lstatSync(abs); } catch { st = null; }
  if (!st || (info.kind === 'zip' ? !st.isFile() : !st.isDirectory())) {
    const e = new Error('backup not found');
    e.code = 'NOT_FOUND';
    throw e;
  }
  fs.rmSync(abs, { recursive: true, force: true });
  summaryCache.delete(name);
}

/**
 * Open a finished ZIP run for download: `{ fd, size, name }`. Only
 * `<name>.zip` files qualify; an older folder run or a run still being
 * written is refused with code `NOT_ZIP`, a missing one with `NOT_FOUND`.
 * The file is opened before it is measured, so a run pruned in between is
 * either streamed whole from the open descriptor or reported missing.
 */
export function openBackupArchive(name) {
  const info = parseBackupEntryName(name);
  if (!info) throw new Error('invalid backup name');
  if (info.kind !== 'zip' || info.partial) {
    const e = new Error('only finished .zip runs can be downloaded; restore an older folder run from the host folder');
    e.code = 'NOT_ZIP';
    throw e;
  }
  const abs = path.join(BACKUP_DIR, name);
  let fd = null;
  try {
    // O_NOFOLLOW: a symlink planted in the backup folder is not followed.
    fd = fs.openSync(abs, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new Error('not a file');
    return { fd, size: st.size, name, path: abs };
  } catch {
    if (fd !== null) { try { fs.closeSync(fd); } catch { /* already closed */ } }
    const e = new Error('backup not found');
    e.code = 'NOT_FOUND';
    throw e;
  }
}

export async function backupUsage() {
  const list = await listBackups();
  return {
    count: list.length,
    totalBytes: list.reduce((n, b) => n + b.bytes, 0),
    // Roughly what the runs occupy: hard-linked assets of older folder runs are counted once.
    newBytes: list.reduce((n, b) => n + (b.partial ? b.bytes : b.newBytes), 0),
  };
}

// ── Scheduler + status ─────────────────────────────────────────────────

let job = null;

export function startBackupScheduler() {
  if (job) return job;
  try {
    const removed = removeStaleTmpRuns();
    if (removed.length) console.log(`[backup] removed ${removed.length} interrupted run(s): ${removed.join(', ')}`);
  } catch (e) {
    console.warn(`[backup] could not check for interrupted runs: ${e?.message || e}`);
  }
  job = createJob({
    name: 'backup.full',
    intervalMs: () => getBackupConfig().fullIntervalMin * 60_000,
    enabled: () => getBackupConfig().enabled,
    run: ({ trigger }) => runBackup({ trigger }),
    initialLastRunAt: Number(getSetting(T.LAST_RUN) || 0) || null,
    retryMs: () => RETRY_MS,
    onStatus: (s) => { if (s.lastRunAt) setSetting(T.LAST_RUN, String(s.lastRunAt)); },
    log: (line) => console.warn(line),
  });
  job.start();
  const cfg = getBackupConfig();
  console.log(`[backup] folder ${BACKUP_DIR} (${dirWritable() ? 'writable' : 'NOT writable'}); schedule ${cfg.enabled ? `every ${cfg.fullIntervalMin} min` : 'off'}${cfg.keepLast ? `, keeping the last ${cfg.keepLast}` : ''}`);
  return job;
}

/** Run now (admin button / host scheduler). Resolves with the run's result. */
export async function runBackupNow(reason = 'manual') {
  if (!job) startBackupScheduler();
  const r = await job.trigger(reason);
  if (!r.ran) return { ran: false, reason: r.reason };
  // The run's own outcome, never the stored last result: when SQLite cannot
  // be written (a full /data), the stored result is stale and a failed run
  // answered 200 {"ran":true}.
  if (r.error) {
    const e = new Error(r.error);
    e.code = 'FAILED';
    throw e;
  }
  return { ran: true, ...(r.result || {}) };
}

export async function backupStatus() {
  const cfg = getBackupConfig();
  const s = job ? job.status() : null;
  const last = lastResult();
  const good = lastGood();
  return {
    enabled: cfg.enabled,
    fullIntervalMin: cfg.fullIntervalMin,
    includes: cfg.includes,
    keepLast: cfg.keepLast,
    dir: BACKUP_DIR,
    hostDir: BACKUP_HOST_DIR_LABEL,
    dirWritable: dirWritable(),
    freeBytes: freeBytes(BACKUP_DIR),
    running: s ? s.running : inProgress,
    runningSince: s?.runningSince ?? runningSince,
    lastRunAt: s?.lastRunAt ?? last?.at ?? null,
    lastSuccessAt: s?.lastSuccessAt ?? good?.at ?? null,
    lastDurationMs: s?.lastDurationMs ?? last?.durationMs ?? null,
    lastError: s?.lastError ?? (last && !last.ok ? last.error : null),
    nextRunAt: s?.nextRunAt ?? null,
    lastBackup: good
      ? {
        name: good.name, bytes: good.bytes, newBytes: good.newBytes ?? good.bytes, files: good.files, docs: good.docs,
        assets: good.assets, at: good.at, trigger: good.trigger, durationMs: good.durationMs,
        failedRooms: Array.isArray(good.failedRooms) ? good.failedRooms : [],
      }
      : null,
    usage: await backupUsage(),
  };
}
