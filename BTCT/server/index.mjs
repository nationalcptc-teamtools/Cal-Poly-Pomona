// First: fixes the environment before anything loads y-websocket.
import './env.mjs';
import http from 'node:http';
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import { createRequire } from 'node:module';

import { hashPassword, verifyPassword, signToken, verifyToken, signTicket, redeemTicket } from './auth.mjs';
import {
  createUser,
  getUserByUsername,
  getUserById,
  publicUser,
  listUsers,
  deleteUser,
  setUserAdmin,
  updateUserPassword,
  updateUsername,
  updateUserColor,
  updateUserPrefs,
  adminCount,
  getSetting,
  setSetting,
  closeDb,
} from './db.mjs';
import {
  primaryAdminName, parseSeedNames, envPasswordFor, DEFAULT_SEED_PASSWORD,
  planSeedAccounts,
} from './seed-accounts.mjs';
import { publishPublicBlur, publishPublicSettings } from './yjs-data.mjs';
import {
  getBackupConfig, setBackupConfig, regenerateBackupToken, runBackupNow,
  listBackups, deleteBackup, openBackupArchive, backupStatus, matchesBackupToken, startBackupScheduler,
  currentRestoreEpoch,
} from './backup.mjs';
import {
  getCmdlogConfig,
  setCmdlogConfig,
  regenerateCmdlogToken,
  handleCmdlogEvents,
  handleCmdlogWhitelist,
  handleCmdlogQuery,
  handleCmdlogManual,
  handleCmdlogClear,
  handleCmdlogExport,
  handleCmdlogImport,
} from './cmdlog.mjs';
import {
  getScanConfig,
  setScanConfig,
  regenerateScanToken,
  handleNmapUpload,
  handleToolUpload,
} from './scan-ingest.mjs';
import {
  handleAssetUpload,
  handleAssetGet,
  handleAssetList,
  handleAssetDelete,
  streamFileTo,
} from './assets.mjs';
import {
  getRetentionConfig, setRetentionConfig, retentionStatus, pruneNow, pruneHistoryRange, startRetentionScheduler,
} from './retention.mjs';
import {
  trackPageDoc,
  handleVersionList,
  handleVersionCreate,
  handleVersionGet,
  handleVersionDelete,
  handleVersionRename,
  handleTwinGet,
  historyStatus,
  closeAllTwins,
  drainTwinWrites,
} from './history.mjs';
import { createRelayPersistence, createLevelDbLogSealer } from './relay-persistence.mjs';
import { createRelayInbox } from './relay-inbox.mjs';

const HEX_COLOR_RE = /^#[0-9a-fA-F]{6}$/;
// No accent chosen: '' tells clients to use the theme's own primary (see
// src/lib/theme.ts). POST /api/settings/theme with color '' clears it.
const DEFAULT_THEME_COLOR = '';

// ── Theme policy (note heading colours + hard-lock) ─────────────────────
// Same shape the client's resolveThemePrefs() accepts:
//   { headingColor: '#RRGGBB' | null, headings: { h1..h6: '#RRGGBB' } }
// Stored as JSON in settings.theme_headings; settings.theme_lock ('1'/'0')
// forces it on every account; settings.theme_updated_at lets clients drop a
// stale copy of the live mirror (see publishPublicSettings in yjs-data.mjs).
const HEADING_LEVELS = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'];

function validateThemePrefs(t) {
  if (typeof t !== 'object' || t === null || Array.isArray(t)) return 'must be an object';
  if (t.headingColor !== undefined && t.headingColor !== null &&
      !(typeof t.headingColor === 'string' && HEX_COLOR_RE.test(t.headingColor))) {
    return 'headingColor must be null or a #RRGGBB hex value';
  }
  if (t.headings !== undefined) {
    const h = t.headings;
    if (typeof h !== 'object' || h === null || Array.isArray(h)) return 'headings must be an object';
    for (const [k, v] of Object.entries(h)) {
      if (!HEADING_LEVELS.includes(k)) return `headings.${k} is not a heading level`;
      if (!(typeof v === 'string' && HEX_COLOR_RE.test(v))) return `headings.${k} must be a #RRGGBB hex value`;
    }
  }
  return null;
}

function normalizeThemePrefs(t) {
  const out = { headingColor: null, headings: {} };
  if (validateThemePrefs(t)) return out;
  if (typeof t.headingColor === 'string') out.headingColor = t.headingColor;
  for (const k of HEADING_LEVELS) {
    if (t.headings && typeof t.headings[k] === 'string') out.headings[k] = t.headings[k];
  }
  return out;
}

// The public (unauthenticated) view of the theme: what GET /api/settings
// returns and what the live mirror carries.
const BLUR_STRENGTH_MIN = 0.25;
const BLUR_STRENGTH_MAX = 3;

function clampBlurStrength(v, fallback) {
  return typeof v === 'number' && Number.isFinite(v)
    ? Math.min(Math.max(v, BLUR_STRENGTH_MIN), BLUR_STRENGTH_MAX)
    : fallback;
}

// Workspace default strength for new blur (redaction) regions, per style.
// A user's own prefs.blurDefaults wins over this; it is only the fallback.
// Mirrors DEFAULT_BLUR_STRENGTH in src/lib/blur-math.ts (the server is plain
// .mjs with no build step, so it cannot import it). Keep the two in step.
const DEFAULT_BLUR_STRENGTH = 0.4;
function publicBlurSettings() {
  let blurDefaults = { gaussian: DEFAULT_BLUR_STRENGTH, pixelate: DEFAULT_BLUR_STRENGTH };
  try {
    const raw = getSetting('blur_defaults');
    if (raw) {
      const parsed = JSON.parse(raw);
      blurDefaults = {
        gaussian: clampBlurStrength(parsed?.gaussian, DEFAULT_BLUR_STRENGTH),
        pixelate: clampBlurStrength(parsed?.pixelate, DEFAULT_BLUR_STRENGTH),
      };
    }
  } catch { /* malformed row: fall back to the built-in default */ }
  return { blurDefaults, blurUpdatedAt: Number(getSetting('blur_updated_at') || 0) };
}

function publicThemeSettings() {
  let themeHeadings = { headingColor: null, headings: {} };
  try {
    const raw = getSetting('theme_headings');
    if (raw) themeHeadings = normalizeThemePrefs(JSON.parse(raw));
  } catch { /* malformed row: fall back to inherit */ }
  return {
    themeColor: getSetting('theme_color') || DEFAULT_THEME_COLOR,
    themeHeadings,
    themeLock: getSetting('theme_lock') === '1',
    themeUpdatedAt: Number(getSetting('theme_updated_at') || 0),
    ...publicBlurSettings(),
  };
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// y-websocket ships its server helpers as CJS: load via createRequire.
const require = createRequire(import.meta.url);
const {
  setupWSConnection, docs: relayDocs, getYDoc, getPersistence, setPersistence,
} = require('y-websocket/bin/utils');
const Y = require('yjs');

// y-websocket's own LevelDB binding answers a cold room's sync before the
// stored state has loaded, writes one LevelDB entry per update through a
// queue that a typing burst outruns, swallows write errors and crashes when
// LevelDB hands back null. server/relay-persistence.mjs replaces it: the
// load is recorded as `doc.whenLoaded` (awaited by the upgrade handler, the
// backup export and yjs-data.mjs), updates are merged per room and stored
// at most every 300 ms, a failed write is kept and retried and reported to
// /healthz, rooms that stay open are compacted, and drain() lets backups
// and shutdown wait until LevelDB has everything.
const defaultPersistence = getPersistence();
/** @type {ReturnType<typeof createRelayPersistence> | null} */
const relayPersistence = defaultPersistence
  ? createRelayPersistence({
    ldb: defaultPersistence.provider,
    Y,
    // After a failed write (ENOSPC tears the log), stay "failing" until the
    // memtable is in a table file and the torn log is gone.
    sealLog: createLevelDbLogSealer(defaultPersistence.provider, path.resolve(process.env.YPERSISTENCE), fs),
  })
  : null;
if (relayPersistence) setPersistence(relayPersistence);

/**
 * The relay doc for a room, once its stored state is in memory. A room that
 * failed to load is dropped from the relay map so the next attempt reads
 * LevelDB again instead of serving an empty doc.
 */
async function loadRelayDoc(room) {
  const doc = getYDoc(room);
  // Without persistence (YPERSISTENCE unset) a room has nothing to load, and
  // a plain Y.Doc's own `whenLoaded` is Yjs's subdocument promise, which
  // never resolves: awaiting it hung every upgrade.
  if (!relayPersistence) return doc;
  try {
    await doc.whenLoaded;
    return doc;
  } catch (err) {
    if (relayDocs.get(room) === doc && doc.conns.size === 0) {
      relayDocs.delete(room);
      doc.destroy();
    }
    throw err;
  }
}

/**
 * Drop a room an upgrade loaded but never attached a socket to (the client
 * went away mid-load), so abandoned upgrades cannot pin Y.Docs in memory.
 */
function releaseIdleRoom(room) {
  const d = relayDocs.get(room);
  if (!d || d.conns.size > 0) return;
  relayDocs.delete(room);
  if (relayPersistence && d.loaded) relayPersistence.writeState(room, d)?.catch?.(() => {});
  try { d.destroy(); } catch { /* already gone */ }
}

const PORT = Number(process.env.PORT || 1234);
const HOST = process.env.HOST || '127.0.0.1';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || ''; // empty = same-origin only
const STATIC_DIR = process.env.STATIC_DIR
  ? path.resolve(process.env.STATIC_DIR)
  : null;

// Feature switch for the Typst report tab. Env only, never a setting: a small
// box must not be switchable from the UI.
//
// comp-ready: the report feature is removed on this branch. It is forced off
// here regardless of ENABLE_TYPST, so GET /api/settings reports it off, the
// /api/typst/ export route 404s, and the client hides the Report tab. The
// compiler/export code is left in the tree (code-split, never in the entry
// bundle per invariant 17) so the diff stays small and the removal reverts by
// restoring this one line; the comp-ready-with-knowledge-base branch is
// untouched and still honours the env var.
const ENABLE_TYPST = false;
// An image built with WITH_TYPST_CLIENT=0 has no compiler wasm in dist/, and
// the SPA fallback would answer its URL with index.html, so the tab is
// reported off there whatever the flag says. Without STATIC_DIR (vite dev)
// the client is served elsewhere and is assumed whole.
const TYPST_TAB = ENABLE_TYPST && (!STATIC_DIR || (() => {
  try {
    return fs.readdirSync(path.join(STATIC_DIR, 'assets')).some((f) => /^typst_ts_web_compiler_bg.*\.wasm$/.test(f));
  } catch { return false; }
})());
if (ENABLE_TYPST && !TYPST_TAB) console.warn('[btct-server] ENABLE_TYPST is on but this image was built without the Typst client (WITH_TYPST_CLIENT=0); the Report tab stays off');

// Loaded once, on the first Typst request, and only with the flag on: a small
// box never imports server/typst/ (or jimp behind it). A failed import clears
// the cache so a later request retries instead of inheriting the rejection.
let typstModule = null;
const loadTypst = () => (typstModule ??= import('./typst/index.mjs').catch((err) => {
  typstModule = null;
  throw err;
}));

// ─────────────────────────────────────────────────────────────────────────
// Default accounts. Every boot makes sure the primary admin (ADMIN_USERNAME,
// default Roberto) and the SEED_USERS names exist, all as admins; see
// server/seed-accounts.mjs for the rules. A missing account is created, an
// existing one (any case) is left exactly as it is. A password comes from
// ADMIN_PASSWORD / SEED_PASSWORD_<NAME> when set and is then never printed;
// otherwise the account gets the shared DEFAULT_SEED_PASSWORD
// (seed-accounts.mjs), which is never printed either.
// ─────────────────────────────────────────────────────────────────────────

// Failed-login throttle (see the /api/login route). Window resets on
// success or expiry; the map is pruned so it can't grow unbounded.
const LOGIN_MAX_FAILURES = 10;
const LOGIN_WINDOW_MS = 60_000;
const LOGIN_MAP_CAP = 1000;
const LOGIN_KEY_MAX = 128; // a username is at most 32 chars; the rest is the IP
const loginFailures = new Map(); // key -> { count, resetAt }

function loginThrottled(key) {
  key = key.slice(0, LOGIN_KEY_MAX);
  const e = loginFailures.get(key);
  if (!e) return false;
  if (Date.now() > e.resetAt) { loginFailures.delete(key); return false; }
  return e.count >= LOGIN_MAX_FAILURES;
}

function recordLoginFailure(key) {
  key = key.slice(0, LOGIN_KEY_MAX);
  const now = Date.now();
  const e = loginFailures.get(key);
  if (e && now <= e.resetAt) { e.count++; return; }
  // A new key at the cap: sweep expired entries once, then evict the oldest
  // (Map insertion order) so the map never exceeds the cap.
  if (!e && loginFailures.size >= LOGIN_MAP_CAP) {
    for (const [k, x] of loginFailures) if (now > x.resetAt) loginFailures.delete(k);
    while (loginFailures.size >= LOGIN_MAP_CAP) loginFailures.delete(loginFailures.keys().next().value);
  }
  loginFailures.set(key, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
}

async function ensureSeedAccounts() {
  const env = process.env;
  const primary = primaryAdminName(env);
  const { names: seeds, invalid } = parseSeedNames(env.SEED_USERS);
  for (const bad of invalid) {
    console.warn(`[btct-server] SEED_USERS: skipping '${bad}' (3-32 chars: letters, numbers, . _ -)`);
  }
  const plan = planSeedAccounts({ primary, seeds, existing: listUsers() });
  for (const step of plan) {
    if (step.action === 'keep') continue;
    if (step.action === 'promote') {
      const existing = getUserByUsername(step.username);
      if (existing) {
        setUserAdmin(existing.id, true);
        console.warn(`[btct-server] promoted existing user '${existing.username}' to admin (the box had no admin)`);
      }
      continue;
    }
    // A user created since listUsers() (none at boot, but cheap to check).
    if (getUserByUsername(step.username)) continue;
    const fromEnv = envPasswordFor(step.username, env, { primary: step.primary });
    const password = fromEnv ? fromEnv.value : DEFAULT_SEED_PASSWORD;
    const hashRecord = await hashPassword(password);
    createUser({
      username: step.username,
      salt: hashRecord.salt,
      hash: hashRecord.hash,
      iter: hashRecord.iter,
      isAdmin: true,
    });
    if (fromEnv) {
      if (fromEnv.value.length < 8) console.warn(`[btct-server] ${fromEnv.source} is shorter than 8 characters`);
      console.warn(`[btct-server] created admin '${step.username}' with the password from ${fromEnv.source}`);
    } else {
      console.warn(`[btct-server] created admin '${step.username}' with the default team password`);
    }
  }
}
await ensureSeedAccounts();

// ─────────────────────────────────────────────────────────────────────────
// REST helpers
// ─────────────────────────────────────────────────────────────────────────
function setCors(res) {
  if (!ALLOWED_ORIGIN) return; // same-origin deployment: no CORS headers needed
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '600');
}

function sendJson(res, status, body) {
  setCors(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function readJsonBody(req, limit = 8 * 1024) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > limit) {
        const err = new Error('payload too large');
        err.status = 413;
        reject(err);
        // Stop reading but keep the socket, so the 413 can actually be sent;
        // the error handler closes the connection once the response is out.
        req.pause();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (!text) return resolve({});
      try { resolve(JSON.parse(text)); } catch { reject(new Error('invalid json')); }
    });
    req.on('error', reject);
  });
}

function authFromHeader(req) {
  const h = req.headers.authorization;
  if (!h || !h.toLowerCase().startsWith('bearer ')) return null;
  return verifyToken(h.slice(7).trim());
}

function requireAdmin(req) {
  const claims = authFromHeader(req);
  if (!claims) return { error: 'unauthorized', status: 401 };
  const user = getUserById(claims.uid);
  if (!user) return { error: 'unauthorized', status: 401 };
  if (!user.is_admin) return { error: 'forbidden', status: 403 };
  return { user };
}

// ── Health ───────────────────────────────────────────────────────────────
// /healthz answers 503 while relay persistence is failing (a write or a read
// of LevelDB failed and nothing has succeeded since), so the container's
// healthcheck and anyone watching it see what used to be a log line only.
// Free space is read from the data directory every time (one statfs call);
// under LOW_DISK_BYTES it is reported, and logged at most every 10 minutes,
// but does not fail the check on its own.
const DATA_DIR = process.env.YPERSISTENCE
  ? path.resolve(process.env.YPERSISTENCE)
  : path.dirname(path.resolve(process.env.DB_PATH || path.join(__dirname, 'data.sqlite')));
const LOW_DISK_BYTES = 1024 ** 3;
let lowDiskLoggedAt = 0;
let shuttingDown = false;

function diskReport() {
  try {
    const s = fs.statfsSync(DATA_DIR);
    const freeBytes = Number(s.bavail) * Number(s.bsize);
    const totalBytes = Number(s.blocks) * Number(s.bsize);
    const lowDisk = freeBytes < LOW_DISK_BYTES;
    if (lowDisk && Date.now() - lowDiskLoggedAt > 10 * 60_000) {
      lowDiskLoggedAt = Date.now();
      console.warn(`[btct-server] low disk: ${Math.round(freeBytes / 1048576)} MB free under ${DATA_DIR}`);
    }
    return { freeBytes, totalBytes, lowDisk };
  } catch {
    return { freeBytes: null, totalBytes: null, lowDisk: false };
  }
}

function healthReport() {
  const failing = !!relayPersistence?.status().failing;
  const { freeBytes, lowDisk } = diskReport();
  return {
    ok: !failing && !shuttingDown,
    persistence: relayPersistence ? (failing ? 'failing' : 'ok') : 'off',
    freeBytes,
    ...(lowDisk ? { warning: 'low disk' } : {}),
    ...(shuttingDown ? { shuttingDown: true } : {}),
  };
}

function adminStatus() {
  return {
    ok: healthReport().ok,
    persistence: relayPersistence ? relayPersistence.status() : null,
    disk: { path: DATA_DIR, ...diskReport(), lowDiskBytes: LOW_DISK_BYTES },
    history: historyStatus(),
    relay: { rooms: relayDocs.size },
    uptimeS: Math.round(process.uptime()),
  };
}

/**
 * Status and run-now accept an admin session or the static backup token.
 * The admin is checked against the users table (requireAdmin), never the
 * token's own `admin` claim, so a deleted or demoted admin loses it at once.
 */
function backupCaller(req) {
  return !requireAdmin(req).error || matchesBackupToken(req);
}

/** How long a backup download ticket stays valid: one click's worth. */
const BACKUP_TICKET_TTL_S = 60;

/** The decoded archive name from a backup route's path segment, or null when it cannot be one. */
function backupArchiveName(segment) {
  let name;
  try { name = decodeURIComponent(segment); } catch { return null; }
  return name && !name.includes('/') && !name.includes('\\') ? name : null;
}

function isDiskFull(err) {
  const code = String(err?.code || '');
  return code === 'ENOSPC' || code === 'EDQUOT' || code.startsWith('SQLITE_FULL')
    || /SQLITE_FULL|database or disk is full/i.test(String(err?.message || ''));
}

// Last line of defence. Every route is awaited inside the handler's
// try/catch, but anything that still escapes (a timer, a stream, a library
// callback) must not take the relay, and every editor's unsaved session,
// down with it. Log it and keep serving.
process.on('unhandledRejection', (reason) => {
  console.error('[btct-server] unhandled rejection (kept running):', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[btct-server] uncaught exception (kept running):', err);
});

// ─────────────────────────────────────────────────────────────────────────
// HTTP routes
// ─────────────────────────────────────────────────────────────────────────
const VALID_USERNAME = /^[a-zA-Z0-9_.-]{3,32}$/;

const httpServer = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    setCors(res);
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    if (req.method === 'GET' && req.url === '/healthz') {
      const h = healthReport();
      return sendJson(res, h.ok ? 200 : 503, h);
    }

    // Admin view of the same signals plus the counters behind them.
    if (req.method === 'GET' && req.url === '/api/admin/status') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      return sendJson(res, 200, adminStatus());
    }

    // User creation is admin-only. The bootstrap admin is the seed account;
    // every subsequent account must be created from an authenticated admin
    // session via POST /api/admin/users.
    if (req.method === 'POST' && req.url === '/api/admin/users') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const body = await readJsonBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      const isAdmin = !!body.isAdmin;
      if (!VALID_USERNAME.test(username)) {
        return sendJson(res, 400, { error: 'invalid username (3-32 chars: letters, numbers, . _ -)' });
      }
      if (password.length < 8) {
        return sendJson(res, 400, { error: 'password must be at least 8 characters' });
      }
      if (getUserByUsername(username)) {
        return sendJson(res, 409, { error: 'username already taken' });
      }
      const hashRecord = await hashPassword(password);
      const user = createUser({
        username,
        salt: hashRecord.salt,
        hash: hashRecord.hash,
        iter: hashRecord.iter,
        isAdmin,
      });
      return sendJson(res, 201, { user: publicUser(user) });
    }

    if (req.method === 'GET' && req.url === '/api/admin/users') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      return sendJson(res, 200, { users: listUsers() });
    }

    if (req.method === 'DELETE' && req.url?.startsWith('/api/admin/users/')) {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const idStr = req.url.slice('/api/admin/users/'.length);
      const id = Number(idStr);
      if (!Number.isInteger(id) || id <= 0) {
        return sendJson(res, 400, { error: 'invalid user id' });
      }
      if (id === gate.user.id) {
        return sendJson(res, 400, { error: 'cannot delete your own account' });
      }
      const target = getUserById(id);
      if (!target) return sendJson(res, 404, { error: 'user not found' });
      // Prevent removing the last admin so the system never locks itself out.
      if (target.is_admin && adminCount() <= 1) {
        return sendJson(res, 400, { error: 'cannot delete the last admin' });
      }
      deleteUser(id);
      // The upgrade check refuses the account's token from now on; sockets
      // it already has open are cut too, or they keep reading and writing.
      const cut = closeUserSockets(id);
      if (cut) console.log(`[relay] closed ${cut} socket(s) of deleted user ${id}`);
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'POST' && req.url?.startsWith('/api/admin/users/') && req.url.endsWith('/password')) {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const idStr = req.url.slice('/api/admin/users/'.length, req.url.length - '/password'.length);
      const id = Number(idStr);
      if (!Number.isInteger(id) || id <= 0) {
        return sendJson(res, 400, { error: 'invalid user id' });
      }
      const target = getUserById(id);
      if (!target) return sendJson(res, 404, { error: 'user not found' });
      const body = await readJsonBody(req);
      const password = String(body.password || '');
      if (password.length < 8) {
        return sendJson(res, 400, { error: 'password must be at least 8 characters' });
      }
      const hashRecord = await hashPassword(password);
      updateUserPassword(id, hashRecord);
      return sendJson(res, 200, { ok: true });
    }

    // Rename any account's username, including the admin's own. Auth is
    // re-checked against the DB by user id on every request (never the
    // token's embedded username), so this is safe against sessions already
    // issued; only the JWT's own username claim is stale until next login.
    if (req.method === 'PATCH' && req.url?.startsWith('/api/admin/users/')) {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const idStr = req.url.slice('/api/admin/users/'.length);
      const id = Number(idStr);
      if (!Number.isInteger(id) || id <= 0) {
        return sendJson(res, 400, { error: 'invalid user id' });
      }
      const target = getUserById(id);
      if (!target) return sendJson(res, 404, { error: 'user not found' });
      const body = await readJsonBody(req);
      const username = String(body.username || '').trim();
      if (!VALID_USERNAME.test(username)) {
        return sendJson(res, 400, { error: 'invalid username (3-32 chars: letters, numbers, . _ -)' });
      }
      const existing = getUserByUsername(username);
      if (existing && existing.id !== id) {
        return sendJson(res, 409, { error: 'username already taken' });
      }
      updateUsername(id, username);
      return sendJson(res, 200, { user: publicUser(getUserById(id)) });
    }

    if (req.method === 'POST' && req.url === '/api/login') {
      const body = await readJsonBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      // Throttle FAILED attempts per username+IP: each verification costs
      // ~100ms of PBKDF2 CPU, so an unauthenticated retry loop would starve
      // the Yjs relay this process also runs.
      const throttleKey = `${username.toLowerCase().slice(0, 64)}|${req.socket.remoteAddress || ''}`;
      if (loginThrottled(throttleKey)) {
        return sendJson(res, 429, { error: 'too many attempts, try again shortly' });
      }
      const row = getUserByUsername(username);
      if (!row || !(await verifyPassword(password, row.salt, row.hash, row.iter))) {
        recordLoginFailure(throttleKey);
        // Same response for both cases to avoid username enumeration.
        return sendJson(res, 401, { error: 'invalid username or password' });
      }
      loginFailures.delete(throttleKey);
      const token = signToken({ uid: row.id, username: row.username, admin: !!row.is_admin });
      return sendJson(res, 200, { token, user: publicUser(row) });
    }

    if (req.method === 'GET' && req.url === '/api/me') {
      const claims = authFromHeader(req);
      if (!claims) return sendJson(res, 401, { error: 'unauthorized' });
      const user = getUserById(claims.uid);
      if (!user) return sendJson(res, 401, { error: 'unauthorized' });
      return sendJson(res, 200, { user: publicUser(user) });
    }

    // Self-service profile update: any authenticated user can change
    // their own display color.
    if (req.method === 'POST' && req.url === '/api/me/profile') {
      const claims = authFromHeader(req);
      if (!claims) return sendJson(res, 401, { error: 'unauthorized' });
      const user = getUserById(claims.uid);
      if (!user) return sendJson(res, 401, { error: 'unauthorized' });
      const body = await readJsonBody(req, 4 * 1024);
      if (typeof body.color === 'string') {
        const color = body.color.trim();
        if (!/^#[0-9a-fA-F]{6}$/.test(color)) {
          return sendJson(res, 400, { error: 'color must be a #RRGGBB hex value' });
        }
        updateUserColor(user.id, color);
      }
      // Optional per-account editor preferences (code-block accent + keybinds).
      // Validate the shape so a malformed client can't poison the JSON blob.
      if (body.prefs !== undefined) {
        const prefs = body.prefs;
        if (typeof prefs !== 'object' || prefs === null || Array.isArray(prefs)) {
          return sendJson(res, 400, { error: 'prefs must be an object' });
        }
        if (prefs.codeAccent !== undefined &&
            !(typeof prefs.codeAccent === 'string' && HEX_COLOR_RE.test(prefs.codeAccent))) {
          return sendJson(res, 400, { error: 'prefs.codeAccent must be a #RRGGBB hex value' });
        }
        if (prefs.keybinds !== undefined) {
          const kb = prefs.keybinds;
          if (typeof kb !== 'object' || kb === null || Array.isArray(kb) ||
              !Object.values(kb).every((v) => typeof v === 'string')) {
            return sendJson(res, 400, { error: 'prefs.keybinds must be a map of strings' });
          }
        }
        // Live-follow preferences (presence / spectate feature).
        if (prefs.follow !== undefined) {
          const f = prefs.follow;
          if (typeof f !== 'object' || f === null || Array.isArray(f)) {
            return sendJson(res, 400, { error: 'prefs.follow must be an object' });
          }
          if (f.defaultPrecision !== undefined &&
              f.defaultPrecision !== 'precise' && f.defaultPrecision !== 'view') {
            return sendJson(res, 400, { error: 'prefs.follow.defaultPrecision must be "precise" or "view"' });
          }
          if (f.panePlacement !== undefined && f.panePlacement !== null &&
              f.panePlacement !== 'split' && f.panePlacement !== 'takeover') {
            return sendJson(res, 400, { error: 'prefs.follow.panePlacement invalid' });
          }
          if (f.precisionByUserId !== undefined) {
            const m = f.precisionByUserId;
            if (typeof m !== 'object' || m === null || Array.isArray(m) ||
                !Object.values(m).every((v) => v === 'precise' || v === 'view')) {
              return sendJson(res, 400, { error: 'prefs.follow.precisionByUserId must map user ids to "precise"/"view"' });
            }
          }
        }
        // Note heading colours (per-account theme). Same validator the admin
        // policy uses; a bad blob is rejected rather than stored.
        if (prefs.theme !== undefined) {
          const themeErr = validateThemePrefs(prefs.theme);
          if (themeErr) return sendJson(res, 400, { error: `prefs.theme ${themeErr}` });
        }
        // Interface theme id. The client registry (src/themes/registry.ts)
        // decides what ids exist; the server only keeps it a short slug, and
        // an unknown id falls back to the default on the client.
        if (prefs.uiTheme !== undefined &&
            !(typeof prefs.uiTheme === 'string' && /^[a-z][a-z0-9-]{0,31}$/.test(prefs.uiTheme))) {
          return sendJson(res, 400, { error: 'prefs.uiTheme must be a short lowercase slug' });
        }
        // Per-account default strength for new blur regions: {gaussian, pixelate},
        // each null (inherit the workspace default) or a number in 0.25..3.
        if (prefs.blurDefaults !== undefined) {
          const b = prefs.blurDefaults;
          if (typeof b !== 'object' || b === null || Array.isArray(b)) {
            return sendJson(res, 400, { error: 'prefs.blurDefaults must be an object' });
          }
          for (const key of ['gaussian', 'pixelate']) {
            const v = b[key];
            if (v !== undefined && v !== null &&
                !(typeof v === 'number' && Number.isFinite(v) && v >= 0.25 && v <= 3)) {
              return sendJson(res, 400, { error: `prefs.blurDefaults.${key} must be null or a number between 0.25 and 3` });
            }
          }
        }
        // How wide the note content column renders.
        if (prefs.noteWidth !== undefined &&
            !['narrow', 'default', 'wide', 'full'].includes(prefs.noteWidth)) {
          return sendJson(res, 400, { error: 'prefs.noteWidth must be one of "narrow", "default", "wide", "full"' });
        }
        // Editor style: Obsidian-style live preview (default) or Notion blocks.
        if (prefs.editorStyle !== undefined && !['live', 'blocks'].includes(prefs.editorStyle)) {
          return sendJson(res, 400, { error: 'prefs.editorStyle must be "live" or "blocks"' });
        }
        updateUserPrefs(user.id, JSON.stringify(prefs));
      }
      const fresh = getUserById(user.id);
      return sendJson(res, 200, { user: publicUser(fresh) });
    }

    // Public settings (no auth): needed on the login screen so the
    // primary theme color matches the rest of the app from first paint.
    // Also carries the admin heading-colour policy (defaults + hard-lock).
    if (req.method === 'GET' && req.url === '/api/settings') {
      // restoreEpoch: browsers drop their IndexedDB caches when it changes
      // (src/realtime/restore-epoch.ts; written by restore.mjs).
      return sendJson(res, 200, { ...publicThemeSettings(), features: { typst: TYPST_TAB }, restoreEpoch: currentRestoreEpoch() });
    }

    // Admin-only: update the workspace theme policy. `color` is the accent
    // every client paints with; `headings` are the default note heading
    // colours for every account; `lock` forces them on everyone. Stored in
    // the SQLite settings table, then mirrored into the shared doc so
    // connected clients re-theme without a reload.
    if (req.method === 'POST' && req.url === '/api/settings/theme') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const body = await readJsonBody(req, 8 * 1024);
      if (body.color !== undefined) {
        const color = typeof body.color === 'string' ? body.color.trim() : null;
        if (color === null || (color !== '' && !HEX_COLOR_RE.test(color))) {
          return sendJson(res, 400, { error: 'color must be a #RRGGBB hex value or empty' });
        }
        setSetting('theme_color', color);
      }
      if (body.headings !== undefined) {
        const headingsErr = validateThemePrefs(body.headings);
        if (headingsErr) return sendJson(res, 400, { error: `headings ${headingsErr}` });
        setSetting('theme_headings', JSON.stringify(normalizeThemePrefs(body.headings)));
      }
      if (body.lock !== undefined) {
        if (typeof body.lock !== 'boolean') return sendJson(res, 400, { error: 'lock must be a boolean' });
        setSetting('theme_lock', body.lock ? '1' : '0');
      }
      setSetting('theme_updated_at', String(Date.now()));
      const pub = publicThemeSettings();
      publishPublicSettings(pub).catch((e) => console.warn('[theme] live mirror failed:', e?.message || e));
      return sendJson(res, 200, pub);
    }

    // Admin-only: workspace default strength for new blur regions
    // ({gaussian?, pixelate?}, each 0.25..3). Mirrored into the shared doc
    // (settingsPublic.blur) so connected clients follow without a reload.
    if (req.method === 'POST' && req.url === '/api/settings/blur') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const body = await readJsonBody(req, 4 * 1024);
      const next = { ...publicBlurSettings().blurDefaults };
      for (const key of ['gaussian', 'pixelate']) {
        if (body[key] === undefined) continue;
        if (!(typeof body[key] === 'number' && Number.isFinite(body[key]) &&
              body[key] >= BLUR_STRENGTH_MIN && body[key] <= BLUR_STRENGTH_MAX)) {
          return sendJson(res, 400, { error: `${key} must be a number between 0.25 and 3` });
        }
        next[key] = body[key];
      }
      setSetting('blur_defaults', JSON.stringify(next));
      setSetting('blur_updated_at', String(Date.now()));
      const pubBlur = publicBlurSettings();
      publishPublicBlur(pubBlur).catch((e) => console.warn('[blur] live mirror failed:', e?.message || e));
      return sendJson(res, 200, pubBlur);
    }

    // ── Binary assets (Typst screenshots + custom fonts) ───────────────
    // Any authenticated user can upload/read; deletes are restricted to the
    // uploader or an admin (enforced in the handler). Bodies are raw bytes,
    // so these routes bypass readJsonBody entirely.
    if (req.url?.split('?')[0] === '/api/assets') {
      const claims = authFromHeader(req);
      if (!claims) return sendJson(res, 401, { error: 'unauthorized' });
      const user = getUserById(claims.uid);
      if (!user) return sendJson(res, 401, { error: 'unauthorized' });
      if (req.method === 'POST') {
        return await handleAssetUpload(req, res, { user, sendJson });
      }
      if (req.method === 'GET') {
        return await handleAssetList(req, res, { sendJson });
      }
    }
    // ── Page version history (server/history.mjs). Any account may read
    // and create versions; deleting follows the author-or-admin rule. ──
    if (req.url?.startsWith('/api/pages/')) {
      const claims = authFromHeader(req);
      if (!claims) return sendJson(res, 401, { error: 'unauthorized' });
      const user = getUserById(claims.uid);
      if (!user) return sendJson(res, 401, { error: 'unauthorized' });
      const parts = req.url.slice('/api/pages/'.length).split('?')[0].split('/').map((p) => decodeURIComponent(p));
      const pageId = parts[0] || '';
      if (parts[1] === 'versions') {
        const versionId = parts[2] || '';
        if (!versionId && req.method === 'GET') return await handleVersionList(req, res, pageId, { sendJson });
        if (!versionId && req.method === 'POST') return await handleVersionCreate(req, res, pageId, { user, sendJson, readJsonBody });
        if (versionId && parts[3] === 'name' && req.method === 'POST') {
          return await handleVersionRename(req, res, pageId, versionId, { user, sendJson, readJsonBody });
        }
        if (versionId && !parts[3] && req.method === 'GET') return await handleVersionGet(req, res, pageId, versionId, { sendJson });
        if (versionId && !parts[3] && req.method === 'DELETE') return await handleVersionDelete(req, res, pageId, versionId, { user, sendJson });
      }
      if (parts[1] === 'history' && parts[2] === 'twin' && req.method === 'GET') {
        return await handleTwinGet(req, res, pageId, { sendJson });
      }
      return sendJson(res, 404, { error: 'not found' });
    }

    if (req.url?.startsWith('/api/assets/')) {
      const claims = authFromHeader(req);
      if (!claims) return sendJson(res, 401, { error: 'unauthorized' });
      const user = getUserById(claims.uid);
      if (!user) return sendJson(res, 401, { error: 'unauthorized' });
      const id = decodeURIComponent(req.url.slice('/api/assets/'.length).split('?')[0]);
      if (!id) return sendJson(res, 400, { error: 'missing asset id' });
      if (req.method === 'GET' || req.method === 'HEAD') {
        return await handleAssetGet(req, res, id, { sendJson });
      }
      if (req.method === 'DELETE') {
        return await handleAssetDelete(req, res, id, { user, sendJson });
      }
    }

    // ── Command log (team pentest command activity from btct-cmdlog agents) ──
    // Ingest + whitelist authenticate with the static ingest token (checked in
    // the handlers). Query is any-authenticated-user. Config is admin-only.
    if (req.method === 'POST' && req.url === '/api/cmdlog/events') {
      return await handleCmdlogEvents(req, res, { sendJson, readJsonBody });
    }
    if (req.method === 'GET' && req.url?.split('?')[0] === '/api/cmdlog/whitelist') {
      return await handleCmdlogWhitelist(req, res, { sendJson });
    }
    if (req.method === 'GET' && req.url?.split('?')[0] === '/api/cmdlog/query') {
      const claims = authFromHeader(req);
      if (!claims) return sendJson(res, 401, { error: 'unauthorized' });
      if (!getUserById(claims.uid)) return sendJson(res, 401, { error: 'unauthorized' });
      return await handleCmdlogQuery(req, res, { sendJson });
    }
    if ((req.method === 'GET' || req.method === 'POST') && (req.url?.split('?')[0] === '/api/cmdlog/export' || req.url === '/api/cmdlog/import')) {
      const claims = authFromHeader(req);
      if (!claims || !getUserById(claims.uid)) return sendJson(res, 401, { error: 'unauthorized' });
      if (req.method === 'GET' && req.url?.split('?')[0] === '/api/cmdlog/export') return await handleCmdlogExport(req, res, { sendJson, setCors });
      if (req.method === 'POST' && req.url === '/api/cmdlog/import') return await handleCmdlogImport(req, res, { sendJson, readJsonBody });
    }
    if (req.method === 'POST' && req.url === '/api/cmdlog/manual') {
      const claims = authFromHeader(req);
      if (!claims) return sendJson(res, 401, { error: 'unauthorized' });
      if (!getUserById(claims.uid)) return sendJson(res, 401, { error: 'unauthorized' });
      return await handleCmdlogManual(req, res, { sendJson, readJsonBody });
    }
    if (req.method === 'GET' && req.url === '/api/cmdlog/config') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      return sendJson(res, 200, getCmdlogConfig());
    }
    if (req.method === 'POST' && req.url === '/api/cmdlog/config') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const body = await readJsonBody(req, 32 * 1024);
      try { return sendJson(res, 200, setCmdlogConfig(body)); }
      catch (e) { return sendJson(res, 400, { error: String(e?.message || e) }); }
    }
    if (req.method === 'POST' && req.url === '/api/cmdlog/token') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      return sendJson(res, 200, { token: regenerateCmdlogToken() });
    }
    if (req.method === 'DELETE' && req.url?.split('?')[0] === '/api/cmdlog/logs') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      return await handleCmdlogClear(req, res, { sendJson });
    }

    // ── Scan ingest (nmap + web/app tool uploads) ─────────────────────
    // Upload endpoints gate themselves (open by default, optional token; see
    // scan-ingest.mjs). Config is admin-only. The nmap route also reads a raw
    // body (it may be nmap -oX XML), so it owns its own body reader.
    if (req.method === 'POST' && req.url?.split('?')[0] === '/api/scans/nmap') {
      const claims = authFromHeader(req);
      const authed = !!(claims && getUserById(claims.uid));
      return await handleNmapUpload(req, res, { sendJson, authed });
    }
    if (req.method === 'POST' && req.url === '/api/scans/tool') {
      const claims = authFromHeader(req);
      const authed = !!(claims && getUserById(claims.uid));
      return await handleToolUpload(req, res, { sendJson, authed });
    }
    if (req.method === 'GET' && req.url === '/api/scans/config') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      return sendJson(res, 200, getScanConfig());
    }
    if (req.method === 'POST' && req.url === '/api/scans/config') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const body = await readJsonBody(req, 32 * 1024);
      try { return sendJson(res, 200, setScanConfig(body)); }
      catch (e) { return sendJson(res, 400, { error: String(e?.message || e) }); }
    }
    if (req.method === 'POST' && req.url === '/api/scans/token') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      return sendJson(res, 200, { token: regenerateScanToken() });
    }

    // ── Backups (host folder target; see server/backup.mjs) ───────────
    // Config and the inventory are admin-only. Status and "run now" also
    // accept the static backup token so a host scheduler (Task Scheduler,
    // cron, systemd) can drive them without an admin session.
    // ── Data retention (admin only) ─────────────────────────────────
    if (req.method === 'GET' && req.url === '/api/retention/config') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      return sendJson(res, 200, retentionStatus());
    }
    if (req.method === 'POST' && req.url === '/api/retention/config') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const body = await readJsonBody(req, 4 * 1024);
      if (body.days !== undefined && !(Number.isFinite(Number(body.days)) && Number(body.days) >= 0)) {
        return sendJson(res, 400, { error: 'days must be a non-negative number (0 = off)' });
      }
      setRetentionConfig({ days: body.days });
      return sendJson(res, 200, retentionStatus());
    }
    if (req.method === 'POST' && req.url === '/api/retention/run') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      return sendJson(res, 200, await pruneNow());
    }
    if (req.method === 'POST' && req.url === '/api/retention/history-range') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const body = await readJsonBody(req, 4 * 1024);
      const after = Number(body.after) || 0;
      const before = Number(body.before) || Date.now();
      return sendJson(res, 200, pruneHistoryRange(after, before));
    }

    if (req.method === 'GET' && req.url === '/api/backup/config') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      return sendJson(res, 200, getBackupConfig());
    }
    if (req.method === 'POST' && req.url === '/api/backup/config') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const body = await readJsonBody(req, 8 * 1024);
      try { return sendJson(res, 200, setBackupConfig(body)); }
      catch (e) { return sendJson(res, 400, { error: String(e?.message || e) }); }
    }
    if (req.method === 'POST' && req.url === '/api/backup/token') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      return sendJson(res, 200, { token: regenerateBackupToken() });
    }
    if (req.method === 'GET' && req.url === '/api/backup/status') {
      if (!backupCaller(req)) return sendJson(res, 401, { error: 'unauthorized' });
      return sendJson(res, 200, await backupStatus());
    }
    if (req.method === 'POST' && req.url === '/api/backup/run') {
      if (!backupCaller(req)) return sendJson(res, 401, { error: 'unauthorized' });
      try {
        const r = await runBackupNow('manual');
        if (!r.ran) return sendJson(res, 409, { ...r, error: 'a backup is already running' });
        return sendJson(res, 200, r);
      } catch (e) {
        return sendJson(res, 500, { error: String(e?.message || e) });
      }
    }
    if (req.method === 'GET' && req.url === '/api/backup/list') {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      return sendJson(res, 200, { backups: await listBackups() });
    }
    // Download one finished ZIP run. An admin session or the backup token in
    // the Authorization header, or a one-time ticket from the route below in
    // `?ticket=` (for a browser that downloads a plain link itself and so
    // cannot send the header). Never the session token in a URL.
    if (req.method === 'POST' && req.url?.startsWith('/api/backup/archives/') && req.url.split('?')[0].endsWith('/ticket')) {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const name = backupArchiveName(req.url.split('?')[0].slice('/api/backup/archives/'.length, -'/ticket'.length));
      if (!name) return sendJson(res, 400, { error: 'invalid backup name' });
      try {
        const { fd } = openBackupArchive(name);
        fs.closeSync(fd);
      } catch (e) {
        return sendJson(res, e?.code === 'NOT_FOUND' ? 404 : 400, { error: String(e?.message || e) });
      }
      return sendJson(res, 200, { ticket: signTicket('backup-archive', { uid: gate.user.id, name }, BACKUP_TICKET_TTL_S), expiresIn: BACKUP_TICKET_TTL_S });
    }
    if (req.method === 'GET' && req.url?.startsWith('/api/backup/archives/')) {
      const [pathPart, query = ''] = req.url.split('?');
      const name = backupArchiveName(pathPart.slice('/api/backup/archives/'.length));
      const ticket = new URLSearchParams(query).get('ticket');
      if (ticket !== null) {
        const claims = redeemTicket('backup-archive', ticket);
        if (!claims || !name || claims.name !== name) return sendJson(res, 401, { error: 'unauthorized' });
        const user = getUserById(claims.uid);
        if (!user) return sendJson(res, 401, { error: 'unauthorized' });
        if (!user.is_admin) return sendJson(res, 403, { error: 'forbidden' });
      } else {
        const gate = requireAdmin(req);
        if (gate.error && !matchesBackupToken(req)) return sendJson(res, gate.status, { error: gate.error });
      }
      if (!name) return sendJson(res, 400, { error: 'invalid backup name' });
      let archive;
      try { archive = openBackupArchive(name); }
      catch (e) { return sendJson(res, e?.code === 'NOT_FOUND' ? 404 : 400, { error: String(e?.message || e) }); }
      setCors(res);
      res.writeHead(200, {
        'Content-Type': 'application/zip',
        'Content-Length': archive.size,
        'Content-Disposition': `attachment; filename="${archive.name}"`,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      streamFileTo(req, res, fs.createReadStream(archive.path, { fd: archive.fd }), `backup ${archive.name}`);
      return;
    }
    if (req.method === 'DELETE' && req.url?.startsWith('/api/backup/archives/')) {
      const gate = requireAdmin(req);
      if (gate.error) return sendJson(res, gate.status, { error: gate.error });
      const name = decodeURIComponent(req.url.slice('/api/backup/archives/'.length).split('?')[0]);
      try { deleteBackup(name); return sendJson(res, 200, { ok: true }); }
      catch (e) { return sendJson(res, e?.code === 'NOT_FOUND' ? 404 : 400, { error: String(e?.message || e) }); }
    }

    // ── Typst report export (server/typst/), env-flagged ──────────────
    // The flag is checked before anything else, auth included: with it off
    // this is not a route, so it answers 404 without loading the module.
    if (req.url?.startsWith('/api/typst/')) {
      if (!ENABLE_TYPST) return sendJson(res, 404, { error: 'not found' });
      let typst;
      try {
        typst = await loadTypst();
      } catch (err) {
        console.error('[typst] the export module failed to load:', err);
        return sendJson(res, 500, { error: 'export unavailable' });
      }
      // Same rule as the asset and history routes: a token is not enough, the
      // account row has to still exist, so a deleted account loses export
      // access at once. Any authenticated account may export any workspace,
      // because the shared doc already lets it read every workspace.
      const claims = authFromHeader(req);
      const user = claims ? getUserById(claims.uid) : null;
      if (await typst.handleTypst(req, res, { user, sendJson, setCors })) return;
    }

    if (tryServeStatic(req, res)) return;

    return sendJson(res, 404, { error: 'not found' });
  } catch (err) {
    // Validation errors thrown by handlers stay 400 with their message; a
    // programming error (TypeError, ReferenceError, ...) is a 500 with a
    // generic body and a server-side log, never its internals.
    // A full disk (a write's ENOSPC, SQLite's SQLITE_FULL) is a 507 the
    // client can show; any other system error (it carries a `code`) is a 500,
    // so its path and message stay in the log.
    const diskFull = isDiskFull(err);
    const status = err && Number.isInteger(err.status) ? err.status
      : diskFull ? 507
        : err instanceof TypeError || err instanceof ReferenceError || err instanceof RangeError
          || (err && typeof err.code === 'string') ? 500 : 400;
    if (status >= 500) console.error('[btct-server] request failed:', err);
    // The handler may have started the response (a streamed download).
    if (res.headersSent) { res.destroy(); return; }
    const msg = diskFull ? 'the server disk is full'
      : status >= 500 ? 'internal error' : (err && err.message ? err.message : 'request failed');
    if (status === 413) {
      res.setHeader('Connection', 'close');
      res.once('finish', () => req.socket?.destroy());
    }
    return sendJson(res, status, { error: msg });
  }
});

// ────────────────────────────────────────────────────────────────────────
// Static client (optional). When STATIC_DIR is set, serve the built Vite
// client from disk so the whole app runs on a single port. Path traversal
// is blocked by resolving requests under STATIC_DIR and rejecting any
// resolved path that escapes that root. Unknown extensionless paths fall
// back to index.html so client-side routing keeps working; a missing file
// (anything under /assets/, or any path with an extension) is a 404.
// ────────────────────────────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.mjs':  'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.webp': 'image/webp',
  '.wasm': 'application/wasm',
  '.ico':  'image/x-icon',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
  '.ttf':  'font/ttf',
  '.otf':  'font/otf',
  '.map':  'application/json; charset=utf-8',
  '.txt':  'text/plain; charset=utf-8',
};

function tryServeStatic(req, res) {
  if (!STATIC_DIR) return false;
  if (req.method !== 'GET' && req.method !== 'HEAD') return false;

  let urlPath;
  try { urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname); }
  catch { return false; }
  // `/mcp` is listed with the live API paths on purpose: the hosted MCP server
  // is gone, and an old client pointed at it should get a clean 404 rather
  // than the SPA's index.html and a confusing parse error.
  if (urlPath.startsWith('/api/') || urlPath === '/healthz'
      || urlPath.startsWith('/yjs/') || urlPath === '/mcp') {
    return false;
  }

  let filePath = path.join(STATIC_DIR, urlPath === '/' ? '/index.html' : urlPath);
  filePath = path.resolve(filePath);
  if (!filePath.startsWith(STATIC_DIR + path.sep) && filePath !== STATIC_DIR) {
    res.writeHead(403);
    res.end();
    return true;
  }

  let stat;
  try { stat = fs.statSync(filePath); } catch { stat = null; }
  if (!stat || !stat.isFile()) {
    // A missing file is a 404, not index.html: a browser still on an old
    // build asks for a hashed chunk under /assets/ that the new image no
    // longer has, and HTML with a 200 surfaced as a module parse error and a
    // blank pane. The SPA fallback is only for extensionless routes.
    if (urlPath.startsWith('/assets/') || path.extname(urlPath) !== '') {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(req.method === 'HEAD' ? undefined : 'not found');
      return true;
    }
    filePath = path.join(STATIC_DIR, 'index.html');
    try { stat = fs.statSync(filePath); } catch { return false; }
  }

  const ext = path.extname(filePath).toLowerCase();

  // Conditional GET: non-hashed files (index.html) get an mtime+size ETag
  // so navigations revalidate with a 304 instead of a re-download.
  const etag = `"${stat.size}-${Math.round(stat.mtimeMs)}"`;
  if (req.headers['if-none-match'] === etag) {
    res.writeHead(304, { ETag: etag });
    res.end();
    return true;
  }

  // Serve a build-time precompressed sibling when the client accepts gzip.
  // The main bundle is ~2.4 MB raw vs ~730 KB gzipped (the wasm compiler
  // 28 MB vs 11 MB); compressing per request would spend that CPU on the
  // event loop the Yjs relay shares, so the Dockerfile compresses ahead of
  // time and plain local runs just fall through to the raw file.
  let encoding = null;
  if (/\bgzip\b/.test(String(req.headers['accept-encoding'] || ''))) {
    try {
      const gzStat = fs.statSync(filePath + '.gz');
      if (gzStat.isFile()) {
        filePath += '.gz';
        stat = gzStat;
        encoding = 'gzip';
      }
    } catch { /* no precompressed sibling */ }
  }

  res.writeHead(200, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    'Content-Length': stat.size,
    ETag: etag,
    Vary: 'Accept-Encoding',
    ...(encoding ? { 'Content-Encoding': encoding } : {}),
    // Only Vite's content-hashed files under /assets/ are immutable; index.html
    // and the unhashed public/ files (logo, favicon) revalidate via the ETag.
    'Cache-Control': /[\\/]assets[\\/]/.test(filePath)
      ? 'public, max-age=31536000, immutable'
      : 'no-cache',
  });
  if (req.method === 'HEAD') { res.end(); return true; }
  // Not .pipe: a file that vanishes after the stat would exit the process,
  // and an aborted download would keep the file open (see streamFileTo).
  streamFileTo(req, res, fs.createReadStream(filePath), `static ${path.basename(filePath)}`);
  return true;
}

// ─────────────────────────────────────────────────────────────────────────
// WebSocket: /yjs/<roomname>?token=<jwt>
// ─────────────────────────────────────────────────────────────────────────
const wss = new WebSocketServer({ noServer: true });

// Refusing an upgrade. Under Bun the upgrade's socket is not the TCP
// connection: socket.write() followed by destroy() (or end()) never sent
// the status line, so every refusal reached the client as an empty reply
// and a script could not tell a bad token (401) or a stale restore epoch
// (409) from a network failure. Bun's ws module answers through the
// request's own response, so a refusal goes through ws: a server per status
// whose verifyClient says no. (Node's ws writes the same response to the
// socket.) Browsers cannot read this status either way; the client finds
// out through /api/me (401) and the restore epoch (409), see
// src/realtime/connection-status.ts and restore-epoch.ts.
const refusers = new Map();
function refuseUpgrade(req, socket, head, code) {
  if (socket.destroyed) return;
  let r = refusers.get(code);
  if (!r) {
    const text = http.STATUS_CODES[code] || 'Refused';
    r = new WebSocketServer({ noServer: true, verifyClient: (_info, cb) => cb(false, code, text) });
    refusers.set(code, r);
  }
  try {
    r.handleUpgrade(req, socket, head, () => {});
  } catch {
    try { socket.destroy(); } catch { /* already gone */ }
  }
}

httpServer.on('upgrade', async (req, socket, head) => {
  let url;
  try { url = new URL(req.url, 'http://x'); } catch { socket.destroy(); return; }

  if (!url.pathname.startsWith('/yjs/')) {
    refuseUpgrade(req, socket, head, 404);
    return;
  }

  // A valid signature is not enough: the account has to still exist, the
  // same rule the REST routes apply, so a deleted account loses the relay
  // at once instead of when its 7-day token expires.
  const token = url.searchParams.get('token');
  const claims = verifyToken(token);
  if (!claims || !getUserById(claims.uid)) {
    refuseUpgrade(req, socket, head, 401);
    return;
  }

  // After a restore, a client still holding pre-restore state (an open tab,
  // an old bundle) would merge it back in. Clients send the restore epoch
  // they cleared their cache for; anything else is refused until it reloads.
  const restoreEpoch = currentRestoreEpoch();
  if (restoreEpoch && url.searchParams.get('epoch') !== restoreEpoch) {
    refuseUpgrade(req, socket, head, 409);
    return;
  }

  // Stash the room name on the request so setupWSConnection picks it up.
  // y-websocket's helper reads the room from req.url's pathname after the
  // first "/", so rewrite to just "/<roomname>".
  const roomName = url.pathname.slice('/yjs/'.length);
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(roomName)) {
    refuseUpgrade(req, socket, head, 400);
    return;
  }
  req.url = '/' + roomName;
  req.userClaims = claims;
  // A read-only reader (the workspace export) asks with ?ro=1: no history
  // twin is kept for it. A hint, not a permission: a writer that connects
  // later is tracked from the room's state at that moment.
  req.btctReadOnly = url.searchParams.get('ro') === '1';

  // Answer the client's first sync only once the room's stored state is in
  // memory (see loadRelayDoc). A room LevelDB cannot read is refused with a
  // 503, and the client retries, rather than served empty.
  try {
    await loadRelayDoc(roomName);
  } catch (err) {
    console.error(`[relay] room ${roomName} failed to load:`, err?.message || err);
    if (!socket.destroyed) {
      refuseUpgrade(req, socket, head, 503);
    }
    return;
  }
  if (socket.destroyed) { releaseIdleRoom(roomName); return; }
  // The account can be deleted while its room loads; check again.
  if (!getUserById(claims.uid)) {
    releaseIdleRoom(roomName);
    refuseUpgrade(req, socket, head, 401);
    return;
  }
  if (shuttingDown) {
    releaseIdleRoom(roomName);
    refuseUpgrade(req, socket, head, 503);
    return;
  }

  try {
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req);
    });
  } catch (err) {
    console.error('[relay] upgrade failed:', err?.message || err);
    releaseIdleRoom(roomName);
    socket.destroy();
  }
});

wss.on('connection', (ws, req) => {
  // The room can unload between the upgrade's load and this point (its last
  // socket closed), and setupWSConnection would then create a fresh doc and
  // answer sync before it loads. Close with "try again later"; the client's
  // provider reconnects through the upgrade handler, which loads it again.
  const target = (req.url || '').slice(1).split('?')[0];
  if (defaultPersistence && !relayDocs.get(target)?.loaded) {
    ws.close(1013, 'room unloaded, reconnect');
    releaseIdleRoom(target);
    return;
  }
  setupRelayConnection(ws, req, target);
  watchSocket(ws, target, req.userClaims);
  // Every page room gets a GC-off history twin (server/history.mjs). The
  // shared metadata room is skipped inside trackPageDoc.
  const room = (req.url || '').slice(1).split('?')[0];
  const relayDoc = relayDocs.get(room);
  if (relayDoc && !req.btctReadOnly) trackPageDoc(room, relayDoc);
});

/**
 * y-websocket's setupWSConnection, with its message listener behind a
 * per-socket inbox (server/relay-inbox.mjs). Bun hands a socket's buffered
 * messages to the listener without returning to the event loop while more
 * data waits, so a client that typed faster than the box could apply kept
 * the loop busy until it stopped sending: no timers, no LevelDB write
 * completions, no SIGTERM handler. The inbox queues the bytes and applies
 * them a batch per turn, each batch in one transaction of the room's doc
 * (origin: the socket, as y-websocket's own apply uses). y-websocket's
 * close listener runs after the inbox has applied what is left, so edits
 * that arrived before a client closed are kept.
 */
function setupRelayConnection(ws, req, room) {
  let yMessage = null;
  const yClose = [];
  const hadOwnOn = Object.prototype.hasOwnProperty.call(ws, 'on');
  const ownOn = ws.on;
  const on = ws.on.bind(ws);
  ws.on = (event, fn) => {
    if (event === 'message' && !yMessage) { yMessage = fn; return ws; }
    if (event === 'close') { yClose.push(fn); return ws; }
    on(event, fn);
    return ws;
  };
  try {
    setupWSConnection(ws, req);
  } finally {
    if (hadOwnOn) ws.on = ownOn; else delete ws.on;
  }
  const doc = relayDocs.get(room);
  const inbox = createRelayInbox({
    isOpen: () => ws.readyState === 1,
    deliver(batch) {
      if (!yMessage || !doc || doc.isDestroyed) return;
      doc.transact(() => { for (const m of batch) yMessage(m); }, ws);
    },
    onOverflow({ messages, bytes }) {
      console.warn(`[relay] room ${room}: user ${req.userClaims?.uid ?? '?'} had ${messages} messages (${bytes} bytes) waiting to be applied; closed the socket, the client resends its edits when it reconnects`);
      try { ws.terminate(); } catch { /* already gone */ }
    },
  });
  ws.btctInbox = inbox;
  ws.on('message', (m) => { inbox.push(m); });
  ws.on('close', (...args) => {
    try { inbox.flush(); } catch (err) {
      console.error(`[relay] room ${room}: applying queued messages on close failed:`, err?.message || err);
    }
    for (const fn of yClose) fn(...args);
  });
}

/** Apply every open socket's queued messages now (shutdown, before the rooms close). */
function flushRelayInboxes() {
  for (const doc of relayDocs.values()) {
    for (const ws of doc.conns.keys()) {
      try { ws.btctInbox?.flush(); } catch (err) {
        console.error('[relay] applying queued messages failed:', err?.message || err);
      }
    }
  }
}

// Bun closes a websocket whose single message is over 16 MiB (code 1006,
// reason "Received too big message") and the update in it is lost; the
// client then reconnects and resends in a loop. Nothing was logged. Log
// that close with the room and the account, any other abnormal close
// except a bare 1006 (a closed laptop lid, a dropped network), and any
// single message over WS_LARGE_MESSAGE_BYTES, so the cause can be found.
const WS_LARGE_MESSAGE_BYTES = 4 * 1024 * 1024;
const WS_NORMAL_CLOSES = new Set([1000, 1001, 1005]);

/** uid -> open relay sockets, so a deleted account can be cut off at once. */
const socketsByUser = new Map();

/** Terminate every relay socket of `uid` (no close handshake, so nothing it
 * sends afterwards is applied). Returns how many were open. */
function closeUserSockets(uid) {
  const set = socketsByUser.get(uid);
  if (!set) return 0;
  socketsByUser.delete(uid);
  for (const ws of set) {
    ws.btctInbox?.discard();
    try { ws.terminate(); } catch { /* already gone */ }
  }
  return set.size;
}

function watchSocket(ws, room, claims) {
  const openedAt = Date.now();
  const uid = claims?.uid;
  if (uid !== undefined && uid !== null) {
    let set = socketsByUser.get(uid);
    if (!set) socketsByUser.set(uid, (set = new Set()));
    set.add(ws);
    ws.on('close', () => {
      const cur = socketsByUser.get(uid);
      if (!cur) return;
      cur.delete(ws);
      if (!cur.size) socketsByUser.delete(uid);
    });
  }
  let messages = 0;
  let bytes = 0;
  let largest = 0;
  ws.on('message', (m) => {
    const n = m?.byteLength ?? m?.length ?? 0;
    messages++;
    bytes += n;
    if (n > largest) largest = n;
    if (n >= WS_LARGE_MESSAGE_BYTES) {
      console.warn(`[relay] room ${room}: user ${claims?.uid ?? '?'} sent one ${(n / 1048576).toFixed(1)} MiB message (the limit is 16 MiB)`);
    }
  });
  ws.on('close', (code, reason) => {
    if (WS_NORMAL_CLOSES.has(code) || shuttingDown) return;
    const why = reason && reason.length ? String(reason) : '';
    const tooBig = code === 1009 || /too big|too large/i.test(why);
    if (code === 1006 && !why && largest < WS_LARGE_MESSAGE_BYTES) return;
    const stats = `after ${Math.round((Date.now() - openedAt) / 1000)} s, ${messages} messages, ${bytes} bytes, largest ${largest} bytes`;
    if (tooBig) {
      console.error(
        `[relay] room ${room}: refused a message over 16 MiB from user ${claims?.uid ?? '?'} and closed the socket (code ${code}, ${why || 'too big'}); `
        + `that change was NOT stored (a very large paste or import). ${stats}`,
      );
    } else {
      console.warn(`[relay] room ${room}: socket of user ${claims?.uid ?? '?'} closed abnormally, code ${code}${why ? ` (${why})` : ''}, ${stats}`);
    }
  });
}

// Slow-header connections are dropped; requestTimeout is left alone so a
// 200 MB import over a slow link is not cut off.
httpServer.headersTimeout = 30_000;

httpServer.listen(PORT, HOST, () => {
  console.log(`[btct-server] HTTP/WS listening on http://${HOST}:${PORT}`);
  if (STATIC_DIR) console.log(`[btct-server] serving static client from ${STATIC_DIR}`);
  console.log(`[btct-server] CORS allowed origin: ${ALLOWED_ORIGIN || '(same-origin only)'}`);
  // Scheduled backups (server/backup.mjs). Persisted last-run means an
  // overdue backup fires right after a restart instead of a full interval later.
  startBackupScheduler();
startRetentionScheduler();
});

// ─────────────────────────────────────────────────────────────────────────
// Clean shutdown (SIGTERM from `docker stop`, SIGINT from a terminal).
// Without a handler Bun, as PID 1, ignores SIGTERM: docker waited 10 s and
// SIGKILLed it, dropping unwritten LevelDB updates and the versions that
// rooms record when they close. Order: refuse new work, close every room
// (its twin records a close version and is written, its buffered updates
// are queued), drain LevelDB, close LevelDB and SQLite, exit 0. A timer
// forces exit 1 before docker's own grace period runs out
// (SHUTDOWN_TIMEOUT_MS, default 8 s against docker's default 10 s; raise
// both together when compose sets stop_grace_period).
// ─────────────────────────────────────────────────────────────────────────
const SHUTDOWN_TIMEOUT_MS = Math.max(1000, Number(process.env.SHUTDOWN_TIMEOUT_MS) || 8000);

function detachSockets(doc) {
  const conns = [...doc.conns.keys()];
  doc.conns.clear();
  for (const ws of conns) {
    try { ws.close(1001, 'server shutting down'); } catch { /* already gone */ }
  }
}

/** Send a close frame to every socket of the rooms `pick` selects, then
 * wait (up to `ms`) until those rooms have left the relay map. */
async function closeSocketsAndWait(pick, ms) {
  const names = [...relayDocs.keys()].filter(pick);
  for (const name of names) {
    for (const ws of relayDocs.get(name)?.conns.keys() ?? []) {
      try { ws.close(1001, 'server shutting down'); } catch { /* already gone */ }
    }
  }
  const until = Date.now() + ms;
  while (Date.now() < until && names.some((n) => relayDocs.get(n)?.conns.size)) {
    await new Promise((r) => setTimeout(r, 25));
  }
}

function closeRoomForShutdown(name, doc) {
  relayDocs.delete(name);
  detachSockets(doc);
  const written = relayPersistence ? relayPersistence.writeState(name, doc) : Promise.resolve();
  try { doc.destroy(); } catch (err) {
    console.warn(`[btct-server] closing room ${name} failed:`, err?.message || err);
  }
  return written;
}

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  const t0 = Date.now();
  console.log(`[btct-server] ${signal}: shutting down`);
  const force = setTimeout(() => {
    console.error(`[btct-server] shutdown did not finish in ${SHUTDOWN_TIMEOUT_MS} ms; exiting anyway`);
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);
  force.unref?.();

  let clean = true;
  try {
    const roomsAtStart = relayDocs.size;
    // Stop accepting connections; the ones open are closed below.
    httpServer.close();
    httpServer.closeIdleConnections?.();

    // 1. Close every page room's sockets and let each room close the way
    //    it always does (y-websocket's close handler: queue the room's
    //    buffered updates, destroy it, which records its history version
    //    and writes its twin). A client answers our close frame only after
    //    the messages it already sent, so waiting for the handshake keeps
    //    the edits that were still in flight. btct-shared goes last, since a
    //    page's version looks up its workspace there.
    await closeSocketsAndWait((name) => name !== 'btct-shared', 2000);
    await closeSocketsAndWait(() => true, 1000);

    // 2. Whatever did not close in time: record the remaining history
    //    versions and start writing the twins, then close the rooms
    //    ourselves: detach the sockets, queue the buffer (writeState) and
    //    destroy. LevelDB is drained before the twins are awaited, since the
    //    room data matters most if the force timer fires.
    flushRelayInboxes();
    for (const doc of relayDocs.values()) detachSockets(doc);
    const twinsWritten = closeAllTwins();
    const writes = [];
    for (let pass = 0; pass < 3 && relayDocs.size; pass++) {
      for (const [name, doc] of [...relayDocs.entries()]) writes.push(closeRoomForShutdown(name, doc));
    }
    await Promise.allSettled(writes);
    const tRooms = Date.now();
    if (relayPersistence) {
      const drained = await relayPersistence.drain();
      if (!drained) {
        clean = false;
        console.error('[btct-server] some Yjs updates could not be written to LevelDB:', relayPersistence.status().lastError);
      }
      await relayPersistence.close();
    }
    const tLdb = Date.now();
    await twinsWritten;
    // A room y-websocket closed is destroyed (and its twin write started)
    // only after its LevelDB write resolved; give those a turn, then wait.
    await new Promise((r) => setImmediate(r));
    await drainTwinWrites();
    console.log(`[btct-server] closed ${roomsAtStart} rooms in ${tRooms - t0} ms (${writes.length} without a close handshake), LevelDB drained in ${tLdb - tRooms} ms, history twins written in ${Date.now() - tLdb} ms`);
    closeDb();
  } catch (err) {
    clean = false;
    console.error('[btct-server] shutdown error:', err);
  }
  console.log(`[btct-server] stopped in ${Date.now() - t0} ms (${clean ? 'clean' : 'with errors'})`);
  process.exit(clean ? 0 : 1);
}

process.on('SIGTERM', () => { void shutdown('SIGTERM'); });
process.on('SIGINT', () => { void shutdown('SIGINT'); });
