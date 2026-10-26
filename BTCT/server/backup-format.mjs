// ─────────────────────────────────────────────────────────────────────────
// Backup format: pure helpers shared by the engine (backup.mjs), the restore
// CLI (restore.mjs) and the unit tests. No Bun-only imports in here so the
// file loads under Node/vitest too.
//
// A backup is ONE self-contained ZIP per run (since 2026-10-12):
//
//   <BACKUP_DIR>/btct-backup-YYYYMMDD-HHMMSS.zip
//     yjs/btct-shared.yupdate.gz    the shared metadata doc as one Yjs update
//     yjs/<pageId>.yupdate.gz       one per page body
//     sqlite/data.sqlite.gz         VACUUM INTO snapshot, gzipped
//     assets/<id>                   uploaded blobs, as-is
//     history/<pageId>.ydoc         GC-off history twin per page (version diffs)
//     manifest.json                 what is inside + sha256 of every file (last)
//
// Entries are STORED (zip-stream.mjs): the members that compress well are
// gzipped one by one, images are compressed already. The archive is written
// as `<name>.zip.tmp`, fsynced and renamed, so a `.zip` is always complete.
//
// Older builds wrote the same layout as a DIRECTORY per run
// (`btct-backup-YYYYMMDD-HHMMSS/`), with unchanged assets hard-linked to the
// previous run. Those still list, verify, restore and count for keep-last.
// ─────────────────────────────────────────────────────────────────────────
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { openZip, hashEntry } from './zip-stream.mjs';

export const BACKUP_SCHEMA_VERSION = 1;
export const BACKUP_NAME_PREFIX = 'btct-backup-';
export const MANIFEST_FILE = 'manifest.json';
export const ZIP_EXT = '.zip';
/** Largest manifest.json read out of a ZIP (about 400 KB at competition size). */
export const MAX_MANIFEST_BYTES = 64 * 1024 * 1024;

// Full-archive cadence, in minutes. Floor 1 (local disk can take it), ceiling
// a week so a typo like 100000 cannot silently disable backups.
export const FULL_INTERVAL_MIN_FLOOR = 1;
export const FULL_INTERVAL_MIN_CEIL = 7 * 24 * 60;
export const FULL_INTERVAL_MIN_DEFAULT = 60;

export const INCLUDE_KEYS = ['sqlite', 'yjsShared', 'yjsPages', 'assets', 'history'];

export const DEFAULT_BACKUP_CONFIG = Object.freeze({
  enabled: false,
  fullIntervalMin: FULL_INTERVAL_MIN_DEFAULT,
  includes: Object.freeze({ sqlite: true, yjsShared: true, yjsPages: true, assets: true, history: true }),
});

/** Which categories a backup covers. Anything missing or non-boolean means "include it". */
export function normalizeIncludes(raw) {
  let src = raw;
  if (typeof src === 'string') {
    try { src = JSON.parse(src); } catch { src = null; }
  }
  const out = {};
  for (const k of INCLUDE_KEYS) {
    const v = src && typeof src === 'object' && !Array.isArray(src) ? src[k] : undefined;
    out[k] = typeof v === 'boolean' ? v : true;
  }
  return out;
}

function toBool(v) {
  if (typeof v === 'boolean') return v;
  if (v === '1' || v === 'true') return true;
  if (v === '0' || v === 'false') return false;
  return undefined;
}

/**
 * Validate a config from anywhere (the settings table stores strings, the
 * admin API sends JSON). Always returns a complete config.
 */
export function normalizeBackupConfig(raw) {
  const src = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const enabled = toBool(src.enabled);
  const rawInterval = src.fullIntervalMin;
  // '' and null coerce to 0, which the floor would turn into a backup every
  // minute; a blank value means "default".
  let interval = rawInterval === '' || rawInterval == null ? NaN : Number(rawInterval);
  if (!Number.isFinite(interval)) interval = FULL_INTERVAL_MIN_DEFAULT;
  interval = Math.floor(interval);
  if (interval < FULL_INTERVAL_MIN_FLOOR) interval = FULL_INTERVAL_MIN_FLOOR;
  if (interval > FULL_INTERVAL_MIN_CEIL) interval = FULL_INTERVAL_MIN_CEIL;
  return {
    enabled: enabled === undefined ? DEFAULT_BACKUP_CONFIG.enabled : enabled,
    fullIntervalMin: interval,
    includes: normalizeIncludes(src.includes),
  };
}

const pad = (n, w = 2) => String(n).padStart(w, '0');

/** `btct-backup-YYYYMMDD-HHMMSS`, UTC, so names sort chronologically everywhere. */
export function backupName(date = new Date()) {
  const d = date;
  return (
    BACKUP_NAME_PREFIX +
    `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}` +
    `-${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`
  );
}

const NAME_RE = /^btct-backup-\d{8}-\d{6}(-[a-z0-9]+)?$/;

/** Only plain backup directory names may reach the filesystem layer (no paths, no `.tmp`). */
export function isBackupName(name) {
  return typeof name === 'string' && NAME_RE.test(name);
}

/**
 * What an entry of BACKUP_DIR is: `{ base, kind: 'zip' | 'dir', partial }`,
 * or null when it is not a backup. `<base>.zip` and `<base>/` are complete
 * runs (a folder still needs its manifest); `<base>.zip.tmp` and `<base>.tmp`
 * are runs being written or left behind by a crash.
 */
export function parseBackupEntryName(name) {
  if (typeof name !== 'string') return null;
  let rest = name;
  let partial = false;
  if (rest.endsWith('.tmp')) { partial = true; rest = rest.slice(0, -4); }
  let kind = 'dir';
  if (rest.endsWith(ZIP_EXT)) { kind = 'zip'; rest = rest.slice(0, -ZIP_EXT.length); }
  if (!isBackupName(rest)) return null;
  return { base: rest, kind, partial };
}

/** A name the API may hand to delete or restore: `<base>.zip`, `<base>`, or either with `.tmp`. */
export function isBackupEntryName(name) {
  return parseBackupEntryName(name) !== null;
}

/** Timestamp encoded in a backup name, as ms since epoch (UTC), or null. */
export function backupNameTime(name) {
  const m = /^btct-backup-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})/.exec(name || '');
  if (!m) return null;
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
}

export function sha256File(absPath) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(absPath)
      .on('data', (c) => h.update(c))
      .on('error', reject)
      .on('end', () => resolve(h.digest('hex')));
  });
}

/**
 * The manifest written last into every backup directory. `files` is the
 * authoritative inventory: restore refuses anything not listed, and verify
 * re-hashes every entry.
 */
export function buildManifest({ instanceId, createdAt, trigger, includes, files, docs, failedDocs, sqlite, assets, history, linkedBytes, app }) {
  return {
    schemaVersion: BACKUP_SCHEMA_VERSION,
    format: 'btct-backup',
    instanceId: String(instanceId || ''),
    createdAt: createdAt || new Date().toISOString(),
    trigger: trigger || 'manual',
    app: app || {},
    includes: normalizeIncludes(includes),
    sqlite: sqlite || null,
    docs: Array.isArray(docs) ? docs : [],
    assets: Array.isArray(assets) ? assets : [],
    history: Array.isArray(history) ? history : [],
    // Rooms the run could not read (listed, not fatal): restoring this
    // backup leaves them out, so restore and the admin panel say so.
    failedDocs: Array.isArray(failedDocs) ? failedDocs : [],
    files: (files || []).map((f) => ({ path: f.path, bytes: f.bytes, sha256: f.sha256 })),
    totalBytes: (files || []).reduce((n, f) => n + (f.bytes || 0), 0),
    // Of totalBytes, what is hard-linked to an earlier run (no new disk space).
    linkedBytes: Number(linkedBytes) || 0,
  };
}

/** Parse + sanity-check manifest JSON text; returns { manifest } or { error }. */
export function parseManifest(text) {
  let m;
  try { m = JSON.parse(text); } catch (e) { return { error: `unreadable manifest: ${e?.message || e}` }; }
  if (!m || m.format !== 'btct-backup' || !Array.isArray(m.files)) return { error: 'manifest is not a BTCT backup' };
  if (m.schemaVersion !== BACKUP_SCHEMA_VERSION) return { error: `unsupported backup schema ${m.schemaVersion}` };
  for (const f of m.files) {
    if (!f || typeof f.path !== 'string' || f.path.includes('..') || path.isAbsolute(f.path) || f.path.includes('\\') || f.path === MANIFEST_FILE) {
      return { error: `manifest lists an unsafe path: ${String(f && f.path)}` };
    }
  }
  return { manifest: m };
}

/** Read + sanity-check the manifest of a backup folder; returns { manifest } or { error }. */
export function readManifest(dir) {
  const p = path.join(dir, MANIFEST_FILE);
  if (!fs.existsSync(p)) return { error: `no ${MANIFEST_FILE} in ${dir}` };
  let text;
  try { text = fs.readFileSync(p, 'utf8'); } catch (e) { return { error: `unreadable manifest: ${e?.message || e}` }; }
  return parseManifest(text);
}

/** The manifest of an open backup ZIP (see openZip); returns { manifest } or { error }. */
export async function readZipManifest(zip) {
  const entry = zip.entry(MANIFEST_FILE);
  if (!entry) return { error: `no ${MANIFEST_FILE} in the archive` };
  let buf;
  try { buf = await zip.readEntry(entry, MAX_MANIFEST_BYTES); } catch (e) { return { error: `unreadable manifest: ${e?.message || e}` }; }
  return parseManifest(buf.toString('utf8'));
}

// Asset ids, room names and history page ids become file names on restore.
// Anything but a plain id is refused, so a hand-edited manifest cannot
// write outside the data directories (same rule as data-export.mjs ROOM_RE).
export const ENTRY_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

/**
 * Check every entry restore turns into a path: each id must be plain and its
 * file must be listed in manifest.files (so it is hashed by verify). Returns
 * a list of errors, empty when the manifest is usable.
 */
export function validateManifestEntries(m) {
  const errors = [];
  if (!m || typeof m !== 'object') return ['manifest is not an object'];
  const listed = new Set((Array.isArray(m.files) ? m.files : []).map((f) => f && f.path));
  const need = (rel, what) => { if (!listed.has(rel)) errors.push(`${what} is not listed in manifest.files: ${rel}`); };
  const check = (arr, key, field, relOf, what) => {
    if (arr === undefined) return;
    if (!Array.isArray(arr)) { errors.push(`manifest.${key} is not a list`); return; }
    for (const e of arr) {
      const id = e && typeof e === 'object' ? e[field] : undefined;
      if (typeof id !== 'string' || !ENTRY_ID_RE.test(id)) {
        errors.push(`manifest.${key} has an unsafe ${field}: ${JSON.stringify(id)?.slice(0, 80)}`);
        continue;
      }
      if (relOf(e)) need(relOf(e), what);
    }
  };
  check(m.docs, 'docs', 'name', (d) => `yjs/${d.name}.yupdate.gz`, 'room');
  check(m.assets, 'assets', 'id', (a) => (a.present ? `assets/${a.id}` : null), 'asset');
  check(m.history, 'history', 'pageId', (h) => `history/${h.pageId}.ydoc`, 'history twin');
  if (m.includes && m.includes.sqlite === true) need('sqlite/data.sqlite.gz', 'sqlite snapshot');
  return errors;
}

/**
 * What a restore of this manifest writes. A category the manifest explicitly
 * excluded needs --partial; a key an older schema-1 manifest never had
 * (history before 2026-08-28) just means "nothing to restore there".
 */
export function restorePlan(includes) {
  const src = includes && typeof includes === 'object' && !Array.isArray(includes) ? includes : {};
  const restore = {};
  const excluded = [];
  const absent = [];
  for (const k of INCLUDE_KEYS) {
    restore[k] = src[k] === true;
    if (src[k] === false) excluded.push(k);
    else if (src[k] !== true) absent.push(k);
  }
  return { restore, excluded, absent };
}

/**
 * True for an error that says this process may not read a path (EACCES,
 * EPERM). Verify reports those as "cannot read the copy", not as a bad
 * backup: a ZIP copied as root keeps the 0600 the backup run gave it, and
 * the image runs as uid 1000.
 */
export function isAccessError(e) {
  return e?.code === 'EACCES' || e?.code === 'EPERM';
}

function unreadableResult(p, e) {
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  const who = uid == null ? 'this process' : `uid ${uid}`;
  return {
    ok: false,
    unreadable: true,
    errors: [`cannot read ${p}: ${e?.code || 'permission denied'} (running as ${who}); this says nothing about the backup itself`],
    manifest: null,
  };
}

/** Re-hash every listed file and check the entries restore turns into paths. */
export async function verifyBackupDir(dir) {
  const errors = [];
  try { fs.accessSync(path.join(dir, MANIFEST_FILE), fs.constants.R_OK); } catch (e) {
    if (isAccessError(e)) return unreadableResult(path.join(dir, MANIFEST_FILE), e);
  }
  const { manifest, error } = readManifest(dir);
  if (error) return { ok: false, errors: [error], manifest: null };
  const entryErrors = validateManifestEntries(manifest);
  if (entryErrors.length) return { ok: false, errors: entryErrors, manifest };
  for (const f of manifest.files) {
    const abs = path.join(dir, f.path);
    if (!fs.existsSync(abs)) { errors.push(`missing: ${f.path}`); continue; }
    const size = fs.statSync(abs).size;
    if (size !== f.bytes) { errors.push(`size mismatch: ${f.path} (${size} != ${f.bytes})`); continue; }
    let sum;
    try { sum = await sha256File(abs); } catch (e) {
      if (isAccessError(e)) return { ...unreadableResult(abs, e), manifest };
      errors.push(`unreadable: ${f.path} (${e?.message || e})`);
      continue;
    }
    if (sum !== f.sha256) errors.push(`checksum mismatch: ${f.path}`);
  }
  return { ok: errors.length === 0, errors, manifest };
}

/**
 * The ZIP counterpart of verifyBackupDir: re-hash every listed entry straight
 * out of the archive (nothing is written to disk). The reader has already
 * refused unsafe or duplicate member names and checks each CRC32.
 */
export async function verifyBackupZip(zipPath) {
  let zip;
  try { zip = await openZip(zipPath); } catch (e) {
    if (isAccessError(e)) return unreadableResult(zipPath, e);
    return { ok: false, errors: [String(e?.message || e)], manifest: null };
  }
  try {
    const { manifest, error } = await readZipManifest(zip);
    if (error) return { ok: false, errors: [error], manifest: null };
    const entryErrors = validateManifestEntries(manifest);
    if (entryErrors.length) return { ok: false, errors: entryErrors, manifest };
    const errors = [];
    for (const f of manifest.files) {
      const entry = zip.entry(f.path);
      if (!entry || entry.isDir) { errors.push(`missing: ${f.path}`); continue; }
      if (entry.size !== f.bytes) { errors.push(`size mismatch: ${f.path} (${entry.size} != ${f.bytes})`); continue; }
      try {
        const got = await hashEntry(zip, entry);
        if (got.sha256 !== f.sha256) errors.push(`checksum mismatch: ${f.path}`);
      } catch (e) {
        errors.push(`unreadable: ${f.path} (${e?.message || e})`);
      }
    }
    return { ok: errors.length === 0, errors, manifest };
  } finally {
    await zip.close();
  }
}

/** Verify a backup given as a ZIP file or a folder (older builds). */
export async function verifyBackup(p) {
  let st;
  try { st = fs.statSync(p); } catch (e) {
    if (isAccessError(e)) return unreadableResult(p, e);
    return { ok: false, errors: [`no such backup: ${p}`], manifest: null };
  }
  return st.isDirectory() ? verifyBackupDir(p) : verifyBackupZip(p);
}

export function formatBytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let x = v / 1024;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
  return `${x.toFixed(1)} ${units[i]}`;
}

// ── Retention, dedupe and space (pure; backup.mjs does the I/O) ─────────

export const KEEP_LAST_MAX = 1000;
/**
 * Runs kept when the admin never set "keep the last N". Every ZIP is a full
 * copy (no hard links between runs), so keeping every run fills the disk in
 * a long engagement: a 500-screenshot instance is a 192 MB ZIP, so hourly
 * runs are 4.6 GB a day. Twelve runs of that size are 2.3 GB. An explicit 0
 * still keeps everything.
 */
export const KEEP_LAST_DEFAULT = 12;

/** "Keep the last N runs". 0 keeps everything; unset (null, '') means KEEP_LAST_DEFAULT. */
export function normalizeKeepLast(v) {
  const n = v === '' || v == null ? KEEP_LAST_DEFAULT : Number(v);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(Math.floor(n), KEEP_LAST_MAX);
}

/**
 * Complete runs to delete so that only the newest `keepLast` remain. Names
 * sort chronologically. `protect` (the run just written) is never returned.
 */
export function runsToPrune(names, keepLast, protect = null) {
  const n = normalizeKeepLast(keepLast);
  if (!n) return [];
  // Complete runs only (a ZIP or a folder); sorted by the time in the name,
  // so a folder from an older build and a newer ZIP compare correctly.
  const complete = [...new Set(names)].filter((name) => {
    const p = parseBackupEntryName(name);
    return p && !p.partial;
  });
  const key = (name) => parseBackupEntryName(name).base;
  const sorted = complete.sort((a, b) => (key(a) === key(b) ? (a < b ? 1 : -1) : key(a) < key(b) ? 1 : -1));
  return sorted.slice(n).filter((name) => name !== protect);
}

/** A `.tmp` run left by a crash or restart, old enough that nothing is still writing it. */
export function isStaleTmpRun(name, mtimeMs, now = Date.now(), maxAgeMs = 60 * 60 * 1000) {
  const p = parseBackupEntryName(name);
  if (!p || !p.partial) return false;
  return Number.isFinite(mtimeMs) && now - mtimeMs > maxAgeMs;
}

/** path -> { bytes, sha256 } for a manifest's files. */
export function fileIndex(manifest) {
  const out = new Map();
  for (const f of (manifest && Array.isArray(manifest.files) ? manifest.files : [])) {
    if (f && typeof f.path === 'string') out.set(f.path, { bytes: f.bytes, sha256: f.sha256 });
  }
  return out;
}

/**
 * Bytes the next run is expected to write. A ZIP run is a full copy, so:
 * the previous run's non-asset bytes plus 20% (or, without a previous run,
 * `fallbackBytes`: the live database and twins), plus every asset, plus
 * `scratchBytes` (the raw SQLite snapshot that lives beside the ZIP while it
 * is gzipped into it), plus about 200 bytes of ZIP headers per entry.
 */
export function estimateRunBytes({ prevManifest = null, assets = [], fallbackBytes = 0, scratchBytes = 0 }) {
  const prev = prevManifest ? fileIndex(prevManifest) : null;
  let prevAssetBytes = 0;
  if (prev) for (const [p, f] of prev) if (p.startsWith('assets/')) prevAssetBytes += Number(f.bytes) || 0;
  let assetBytes = 0;
  for (const a of assets) assetBytes += Number(a && a.size) || 0;
  const base = prev ? Math.max(0, (Number(prevManifest.totalBytes) || 0) - prevAssetBytes) : Math.max(0, Number(fallbackBytes) || 0);
  const entries = (prev ? prev.size : 0) + assets.length + 1;
  return Math.ceil(base * 1.2) + assetBytes + Math.max(0, Number(scratchBytes) || 0) + entries * 200;
}

/** Resolve with `promise`, or reject with a timeout error after `ms` (0 = no limit). */
export function withTimeout(promise, ms, label = 'operation') {
  if (!ms || ms <= 0) return Promise.resolve(promise);
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const e = new Error(`${label} timed out after ${ms < 1000 ? `${ms} ms` : `${Math.round(ms / 1000)} s`}`);
      e.code = 'TIMEOUT';
      reject(e);
    }, ms);
    if (typeof timer.unref === 'function') timer.unref();
  });
  return Promise.race([Promise.resolve(promise), timeout]).finally(() => clearTimeout(timer));
}

// ── Restore helpers (pure; restore.mjs does the I/O) ─────────────────────

/** Two decoded Yjs state vectors (Map<clientId, clock>) hold the same clocks. */
export function sameStateVector(a, b) {
  if (!a || !b || a.size !== b.size) return false;
  for (const [client, clock] of a) if (b.get(client) !== clock) return false;
  return true;
}

/**
 * The backup_* keys that record the source box's own runs. They name ZIPs
 * in the source box's backup folder, so a fresh box must not inherit them.
 */
export const BACKUP_RUN_HISTORY_KEYS = ['backup_last_result', 'backup_last_good', 'backup_last_run_at'];

/**
 * Which `backup_*` settings the restored database ends up with. The box keeps
 * its own backup config, token, instance id and run history (a restore must
 * not switch the schedule off or revert a rotated token). On a fresh box
 * (no current database) the backup's config, token and instance id are kept
 * (the restore is a move: the new box takes the old one's place), but its run
 * history (last result, last good run, last run time) is dropped: it describes
 * ZIPs in the other box's folder.
 * `restored` and `current` are Map<key, value> of the backup_* rows.
 */
export function mergeBackupSettings(restored, current) {
  const set = [];
  const del = [];
  if (current) {
    for (const k of restored.keys()) if (!current.has(k)) del.push(k);
    for (const [k, v] of current) set.push([k, v]);
  } else {
    for (const k of BACKUP_RUN_HISTORY_KEYS) if (restored.has(k)) del.push(k);
  }
  return { set, del };
}

/**
 * The restore epoch to store. Rolling back Yjs rooms needs a new one, so
 * every browser drops its IndexedDB cache instead of merging newer state
 * back in. Otherwise (no rooms restored, or --keep-browser-caches) the
 * browsers' caches stay valid: keep this box's epoch, else the backup's.
 * null means "leave the setting as it is".
 */
export function chooseRestoreEpoch({ restoresRooms, keepCaches, currentEpoch, backupEpoch, newEpoch }) {
  if (restoresRooms && !keepCaches) return newEpoch;
  return currentEpoch || backupEpoch || null;
}

/** Bytes a restore stages on the data volume before swapping it in. */
export function restoreSpaceNeeded(manifest, plan, { currentYjsBytes = 0 } = {}) {
  const files = fileIndex(manifest);
  let n = 0;
  const sum = (prefix) => { let t = 0; for (const [p, f] of files) if (p.startsWith(prefix)) t += Number(f.bytes) || 0; return t; };
  if (plan.restore.sqlite) {
    const raw = Number(manifest.sqlite && manifest.sqlite.rawBytes) || 0;
    n += raw || sum('sqlite/') * 10;
  }
  if (plan.restore.yjsShared || plan.restore.yjsPages) {
    const docs = (Array.isArray(manifest.docs) ? manifest.docs : []).reduce((t, d) => t + (Number(d && d.bytes) || 0), 0);
    const full = plan.restore.yjsShared && plan.restore.yjsPages;
    n += docs * 3 + (full ? 0 : currentYjsBytes);
  }
  if (plan.restore.assets) n += sum('assets/');
  if (plan.restore.history) n += sum('history/');
  return n;
}
