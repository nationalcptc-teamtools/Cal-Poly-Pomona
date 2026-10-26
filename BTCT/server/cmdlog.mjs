// ─────────────────────────────────────────────────────────────────────────
// Team command log: ingest + config for the btct-cmdlog agent.
//
// Each operator runs a small Python agent (see ../cmdlog-agent) on their Kali
// box that captures whitelisted pentest commands from their shell and POSTs
// them here. Events land in two places:
//   • SQLite `command_logs` (db.mjs): the durable, unbounded archive.
//   • the shared Yjs doc `commandLogs` map (yjs-data.mjs): a bounded live
//     window so every open browser sees new commands push in with no polling.
//
// This is the THIRD deliberate exception to "the server is dumb about domain
// data" (alongside the AI assistant and assets.mjs): the ingest endpoint writes
// workspace content. It stays as dumb as possible: it validates/clamps and
// stores, and knows nothing about what a command means.
//
// Auth mirrors mcp.mjs: a static bearer ingest token in the settings KV,
// admin-generated, checked with a timing-safe compare, gated behind an enabled
// flag. Operator identity is self-asserted (the --operator arg): appropriate
// for a trusted competition team, not for adversarial auditing.
// ─────────────────────────────────────────────────────────────────────────
import crypto from 'node:crypto';
import { db, getSetting, setSetting, upsertCommandLog, upsertCommandLogBatch, queryCommandLogs, clearCommandLogs } from './db.mjs';
import { appendCommandLogs, listWorkspaces } from './yjs-data.mjs';
import { startsWithZipSignature } from './zip-stream.mjs';

const T_ENABLED = 'cmdlog_enabled';
const T_TOKEN = 'cmdlog_token';
const T_WHITELIST = 'cmdlog_whitelist';   // JSON array of tool names
const T_WORKSPACE = 'cmdlog_workspace';   // default target workspace id

const MAX_BATCH = 200;
const MAX_CMD_LEN = 4096;
const MAX_FIELD_LEN = 512;

const genToken = () => 'btct_ing_' + crypto.randomBytes(24).toString('hex');

// Sensible default pentest toolset. Admins can override the list in the UI;
// the agent fetches whichever list is stored (or this default if unset).
export const DEFAULT_WHITELIST = [
  'nmap', 'masscan', 'rustscan', 'gobuster', 'feroxbuster', 'ffuf', 'dirb', 'dirbuster',
  'nikto', 'whatweb', 'wpscan', 'hydra', 'medusa', 'ncrack', 'sqlmap', 'crackmapexec',
  'nxc', 'netexec', 'evil-winrm', 'responder', 'bloodhound-python', 'enum4linux',
  'enum4linux-ng', 'smbclient', 'smbmap', 'rpcclient', 'ldapsearch', 'kerbrute',
  'impacket-secretsdump', 'impacket-psexec', 'impacket-wmiexec', 'impacket-GetUserSPNs',
  'impacket-GetNPUsers', 'secretsdump.py', 'psexec.py', 'wmiexec.py', 'GetUserSPNs.py',
  'GetNPUsers.py', 'hashcat', 'john', 'msfconsole', 'msfvenom', 'searchsploit', 'curl',
  'wget', 'ssh', 'nc', 'ncat', 'netcat', 'socat', 'proxychains', 'proxychains4', 'ping',
];

// ── Admin config ──
// The token IS returned to admins (like MCP) so it can be copied into the agent
// invocation. It grants ingest: treat it like a password.
export function getCmdlogConfig() {
  return {
    enabled: getSetting(T_ENABLED) === '1',
    configured: !!getSetting(T_TOKEN),
    token: getSetting(T_TOKEN) || null,
    whitelist: getWhitelist(),
    workspaceId: getSetting(T_WORKSPACE) || null,
  };
}

export function setCmdlogConfig(body) {
  if (typeof body.enabled === 'boolean') {
    setSetting(T_ENABLED, body.enabled ? '1' : '0');
    if (body.enabled && !getSetting(T_TOKEN)) setSetting(T_TOKEN, genToken()); // mint on first enable
  }
  if (body.whitelist !== undefined) {
    if (!Array.isArray(body.whitelist)) throw new Error('whitelist must be an array of tool names');
    const tools = [...new Set(
      body.whitelist
        .map((t) => String(t || '').trim().toLowerCase())
        .filter((t) => t && t.length <= 64 && !/\s/.test(t)),
    )];
    setSetting(T_WHITELIST, JSON.stringify(tools));
  }
  if (body.workspaceId !== undefined) {
    setSetting(T_WORKSPACE, body.workspaceId ? String(body.workspaceId) : '');
  }
  return getCmdlogConfig();
}

export function regenerateCmdlogToken() {
  const t = genToken();
  setSetting(T_TOKEN, t);
  return t;
}

export function getWhitelist() {
  const raw = getSetting(T_WHITELIST);
  if (!raw) return DEFAULT_WHITELIST;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) && parsed.length ? parsed : DEFAULT_WHITELIST;
  } catch {
    return DEFAULT_WHITELIST;
  }
}

// ── Bearer gate (identical shape to mcp.mjs) ──
function constantEq(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// Returns true if the request carries a valid ingest token AND cmdlog is
// enabled; otherwise writes a 401 and returns false. Enabled is checked before
// the token so a disabled integration is closed even if a token still exists.
function requireIngest(req, res, sendJson) {
  const token = getSetting(T_TOKEN);
  if (getSetting(T_ENABLED) !== '1' || !token) {
    sendJson(res, 401, { error: 'command log ingest disabled' });
    return false;
  }
  const h = req.headers.authorization || '';
  const provided = h.toLowerCase().startsWith('bearer ') ? h.slice(7).trim() : '';
  if (!provided || !constantEq(provided, token)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return false;
  }
  return true;
}

// ── Field coercion ──
// Only scalars become text: String() of an object calls its toString, and
// {"toString":1} makes that throw, so anything else is treated as absent.
const clampStr = (v, max = MAX_FIELD_LEN) =>
  (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')
    ? String(v).slice(0, max)
    : null;
const isObjectBody = (b) => b !== null && typeof b === 'object' && !Array.isArray(b);
const clampInt = (v) =>
  ((typeof v === 'number' || typeof v === 'string') && Number.isFinite(Number(v)) ? Math.trunc(Number(v)) : null);
// The widest time a JS Date can hold (+-8.64e15 ms). A startedAt outside it
// stored fine but made `new Date(...).toISOString()` throw in the CSV export.
const MAX_DATE_MS = 8.64e15;
const clampTime = (v) => {
  const n = clampInt(v);
  return n === null || Math.abs(n) > MAX_DATE_MS ? null : n;
};

// Normalize one raw agent event into a storable record, or null if it's missing
// required fields. `workspaceId` is resolved by the caller (batch-level).
function normalizeEvent(ev, workspaceId, receivedAt) {
  if (!ev || typeof ev !== 'object') return null;
  const id = clampStr(ev.id, 128);
  const operator = clampStr(ev.operator, 128);
  const command = clampStr(ev.command, MAX_CMD_LEN);
  const tool = clampStr(ev.tool, 128);
  const startedAt = clampTime(ev.startedAt);
  if (!id || !operator || !command || !tool || startedAt === null) return null;
  return {
    id,
    workspaceId,
    operator,
    command,
    tool,
    cwd: clampStr(ev.cwd),
    host: clampStr(ev.host, 256),
    localUser: clampStr(ev.localUser, 128),
    shellPid: clampInt(ev.shellPid),
    startedAt,
    receivedAt,
    exitCode: clampInt(ev.exitCode),
    durationMs: clampInt(ev.durationMs),
    redacted: ev.redacted === false ? false : true,
  };
}

// Best-effort tool name from a command line (mirrors the agent's matcher, but
// simple): skip env assignments + sudo/doas, then take the basename.
function deriveTool(command) {
  const parts = String(command).trim().split(/\s+/).filter(Boolean);
  let i = 0;
  while (i < parts.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(parts[i])) i++;
  if (parts[i] === "sudo" || parts[i] === "doas") {
    i++;
    while (i < parts.length && parts[i].startsWith("-")) i++;
  }
  const prog = parts[i] || "manual";
  return prog.split("/").pop() || "manual";
}

// ── Route handlers (called from index.mjs) ──

// POST /api/cmdlog/manual: a BTCT user hand-enters one command-log record
// (JWT-gated in index.mjs). Goes through the same durable path as agent ingest
// (SQLite archive + CRDT live window) so manual entries survive and show up in
// archive queries. Not gated by the ingest token / enabled flag: this is a
// first-class in-app action for any authenticated user. Never redacted: the
// user typed it here deliberately.
export async function handleCmdlogManual(req, res, { sendJson, readJsonBody }) {
  // Size (413) and parse (400) errors go to the router's catch.
  const body = await readJsonBody(req, 32 * 1024);
  if (!isObjectBody(body)) return sendJson(res, 400, { error: 'expected a JSON object' });

  const operator = clampStr(body.operator, 128);
  const command = clampStr(body.command, MAX_CMD_LEN);
  if (!operator || !command) return sendJson(res, 400, { error: 'operator and command are required' });

  let workspaceId = clampStr(body.workspaceId, 128) || getSetting(T_WORKSPACE) || '';
  if (!workspaceId) {
    try { workspaceId = (await listWorkspaces())[0]?.id || ''; } catch { /* leave empty */ }
  }
  if (!workspaceId) return sendJson(res, 409, { error: 'no target workspace' });

  const now = Date.now();
  const startedAt = clampTime(body.startedAt);
  const rec = {
    id: crypto.randomUUID(),
    workspaceId,
    operator,
    command,
    tool: clampStr(body.tool, 128) || deriveTool(command),
    cwd: clampStr(body.cwd),
    host: clampStr(body.host, 256),
    localUser: clampStr(body.localUser, 128),
    shellPid: clampInt(body.shellPid),
    startedAt: startedAt === null ? now : startedAt,
    receivedAt: now,
    exitCode: clampInt(body.exitCode),
    durationMs: clampInt(body.durationMs),
    redacted: false,
  };

  const merged = upsertCommandLog(rec);
  try { await appendCommandLogs([merged]); } catch (e) { console.warn('[cmdlog] CRDT append failed:', e?.message || e); }
  return sendJson(res, 201, { log: merged });
}

// POST /api/cmdlog/events: batch ingest. Body: { workspace?, events: [...] }.
export async function handleCmdlogEvents(req, res, { sendJson, readJsonBody }) {
  if (!requireIngest(req, res, sendJson)) return;
  const body = await readJsonBody(req, 512 * 1024);
  if (!isObjectBody(body)) return sendJson(res, 400, { error: 'expected a JSON object' });

  const events = Array.isArray(body.events) ? body.events.slice(0, MAX_BATCH) : [];
  if (!events.length) return sendJson(res, 200, { accepted: 0, skipped: 0 });

  // Resolve the target workspace: batch override → configured default → first
  // workspace in the doc. Without any workspace we can't scope the rows.
  let workspaceId = clampStr(body.workspace, 128) || getSetting(T_WORKSPACE) || '';
  if (!workspaceId) {
    try { workspaceId = (await listWorkspaces())[0]?.id || ''; } catch { /* leave empty */ }
  }
  if (!workspaceId) return sendJson(res, 409, { error: 'no target workspace (set a default in Command Log settings)' });

  const receivedAt = Date.now();
  const records = [];
  let skipped = 0;
  for (const ev of events) {
    const rec = normalizeEvent(ev, workspaceId, receivedAt);
    if (!rec) { skipped++; continue; }
    records.push(rec);
  }

  // SQLite is the source of truth: write it first (merged row reflects prior
  // start/completion halves), then push the merged records into the live CRDT
  // window. If the CRDT write fails (e.g. cold doc), the archive still has them.
  const merged = upsertCommandLogBatch(records);
  try { await appendCommandLogs(merged); } catch (e) { console.warn('[cmdlog] CRDT append failed:', e?.message || e); }

  return sendJson(res, 200, { accepted: records.length, skipped });
}

// GET /api/cmdlog/whitelist: the agent fetches the tool list on start + refresh.
export function handleCmdlogWhitelist(req, res, { sendJson }) {
  if (!requireIngest(req, res, sendJson)) return;
  return sendJson(res, 200, { tools: getWhitelist() });
}

// GET /api/cmdlog/query?workspaceId&operator&tool&host&from&to&q&status&limit
// JWT-authenticated read of the durable archive (auth enforced in index.mjs).
export function handleCmdlogQuery(req, res, { sendJson }) {
  const url = new URL(req.url, 'http://x');
  const p = url.searchParams;
  const workspaceId = String(p.get('workspaceId') || '').trim();
  if (!workspaceId) return sendJson(res, 400, { error: 'workspaceId required' });
  const rows = queryCommandLogs({
    workspaceId,
    operator: p.get('operator') || undefined,
    tool: p.get('tool') || undefined,
    host: p.get('host') || undefined,
    from: p.get('from') ? Number(p.get('from')) : undefined,
    to: p.get('to') ? Number(p.get('to')) : undefined,
    q: p.get('q') || undefined,
    status: p.get('status') || undefined,
    limit: p.get('limit') ? Number(p.get('limit')) : undefined,
  });
  return sendJson(res, 200, { logs: rows });
}

// DELETE /api/cmdlog/logs?workspaceId: admin purge of a workspace's archive.
// (The CRDT live window ages out on its own as new events arrive.)
export function handleCmdlogClear(req, res, { sendJson }) {
  const url = new URL(req.url, 'http://x');
  const workspaceId = String(url.searchParams.get('workspaceId') || '').trim();
  if (!workspaceId) return sendJson(res, 400, { error: 'workspaceId required' });
  clearCommandLogs(workspaceId);
  return sendJson(res, 200, { ok: true });
}

// ── Uncapped export and import (workspace archive) ──
// The Command Log tab's query stops at 5000 rows. The workspace export and
// "Export the whole archive" read through here instead: rows stream oldest
// first in pages of 500 (keyset on started_at, id), so 100k commands never
// sit in memory as one array, no SQLite statement stays open across an await,
// and the response honours backpressure.

const IMPORT_MAX_BATCH = 1000;

/**
 * One CSV cell, the same rule as the client's `csvCell`
 * (src/lib/cmdlog-filter.ts): a text cell starting with = + - @ tab or CR
 * gets a leading apostrophe so a spreadsheet never runs it as a formula.
 */
function csvCell(v) {
  let s = v === null || v === undefined ? '' : String(v);
  if (typeof v === 'string' && /^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** ISO time of a stored startedAt; a row written before the range check keeps its raw number. */
function isoTime(ms) {
  return typeof ms === 'number' && Number.isFinite(ms) && Math.abs(ms) <= MAX_DATE_MS
    ? new Date(ms).toISOString()
    : String(ms ?? '');
}

const CSV_HEADER = 'startedAt,operator,host,tool,command,cwd,exitCode,durationMs';
function csvRow(r) {
  return [
    isoTime(r.startedAt), r.operator, r.host ?? '', r.tool, r.command, r.cwd ?? '',
    r.exitCode ?? '', r.durationMs ?? '',
  ].map(csvCell).join(',');
}

function rowToRecord(r) {
  return {
    id: r.id,
    workspaceId: r.workspace_id,
    operator: r.operator,
    command: r.command,
    tool: r.tool,
    cwd: r.cwd,
    host: r.host,
    localUser: r.local_user,
    shellPid: r.shell_pid,
    startedAt: r.started_at,
    receivedAt: r.received_at,
    exitCode: r.exit_code,
    durationMs: r.duration_ms,
    redacted: !!r.redacted,
  };
}

/** Write a chunk, waiting for 'drain' when the socket buffer is full. Resolves false once the client is gone. */
function writeChunk(res, chunk) {
  if (res.destroyed || res.writableEnded) return Promise.resolve(false);
  if (res.write(chunk)) return Promise.resolve(true);
  return new Promise((resolve) => {
    const done = (ok) => { res.off('drain', onDrain); res.off('close', onClose); resolve(ok); };
    const onDrain = () => done(true);
    const onClose = () => done(false);
    res.on('drain', onDrain);
    res.on('close', onClose);
  });
}

const EXPORT_PAGE_ROWS = 500;
const EXPORT_COLS = 'SELECT * FROM command_logs WHERE workspace_id = ?';
const exportPageFirst = db.query(`${EXPORT_COLS} ORDER BY started_at ASC, id ASC LIMIT ?`);
const exportPageAfter = db.query(
  `${EXPORT_COLS} AND (started_at > ? OR (started_at = ? AND id > ?)) ORDER BY started_at ASC, id ASC LIMIT ?`,
);

// GET /api/cmdlog/export?workspaceId&format=json|csv|count (JWT, checked in index.mjs).
export async function handleCmdlogExport(req, res, { sendJson, setCors }) {
  const url = new URL(req.url, 'http://x');
  const workspaceId = clampStr(url.searchParams.get('workspaceId'), 128);
  const format = String(url.searchParams.get('format') || 'json');
  if (!workspaceId) return sendJson(res, 400, { error: 'workspaceId required' });
  if (format === 'count') {
    const row = db.query('SELECT COUNT(*) AS n FROM command_logs WHERE workspace_id = ?').get(workspaceId);
    return sendJson(res, 200, { total: row?.n ?? 0 });
  }
  if (format !== 'json' && format !== 'csv') return sendJson(res, 400, { error: 'format must be json, csv or count' });

  let gone = false;
  req.on('close', () => { gone = true; });
  setCors(res);
  const safeWs = workspaceId.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64);
  res.writeHead(200, {
    'Content-Type': format === 'csv' ? 'text/csv; charset=utf-8' : 'application/json; charset=utf-8',
    'Content-Disposition': `attachment; filename="command-log-${safeWs}.${format}"`,
    'Cache-Control': 'no-store',
  });
  // Read in pages that each run to completion, never one cursor held across
  // the awaits below: a bun:sqlite statement left mid-iteration (client gone,
  // a throw) stays active on the shared connection, and VACUUM INTO then
  // fails every backup with "SQL statements in progress" until a restart.
  let buf = format === 'csv' ? `${CSV_HEADER}\n` : '[';
  let first = true;
  let after = null;
  for (;;) {
    const rows = after
      ? exportPageAfter.all(workspaceId, after.startedAt, after.startedAt, after.id, EXPORT_PAGE_ROWS)
      : exportPageFirst.all(workspaceId, EXPORT_PAGE_ROWS);
    for (const r of rows) {
      const rec = rowToRecord(r);
      if (format === 'csv') buf += `${csvRow(rec)}\n`;
      else { buf += (first ? '' : ',') + JSON.stringify(rec); first = false; }
      if (buf.length >= 64 * 1024) {
        if (gone) return;
        const ok = await writeChunk(res, buf);
        buf = '';
        if (!ok) return;
      }
    }
    if (rows.length < EXPORT_PAGE_ROWS) break;
    const last = rows[rows.length - 1];
    after = { startedAt: last.started_at, id: last.id };
    if (gone) return;
  }
  if (format === 'json') buf += ']';
  if (!(await writeChunk(res, buf))) return;
  res.end();
}

/** An id for an imported row whose own id already belongs to another workspace: stable, so a re-import is a no-op. */
function importedId(workspaceId, id) {
  return 'imp-' + crypto.createHash('sha256').update(`${workspaceId}\0${id}`).digest('hex').slice(0, 40);
}

const ownerStmt = db.query('SELECT workspace_id FROM command_logs WHERE id = ?');

// POST /api/cmdlog/import  Body: { workspaceId, logs: [...] } (JWT, checked in index.mjs).
// Rows are upserted by id in one transaction. A row whose id is already used
// by ANOTHER workspace (an "import as new" next to its original) is stored
// under importedId(), so neither copy overwrites the other and running the
// same import twice writes nothing new. SQLite only: the live CRDT window
// is for new commands, and the Command Log tab reads the archive over REST.
export async function handleCmdlogImport(req, res, { sendJson, readJsonBody }) {
  // A command-log download (command-log_<date>_csv.zip / _json.zip) is not
  // an import format; say what the route takes instead of "invalid json".
  // Told by the Content-Type, or by the body's first bytes when a client
  // sends it as application/octet-stream (curl --data-binary, a script).
  const zipRefusal = {
    error: `this route takes JSON {"workspaceId", "logs": [...]} (at most ${IMPORT_MAX_BATCH} rows), not a ZIP; `
      + 'a command log is imported back as part of a workspace ZIP (Export / Import)',
  };
  const type = String(req.headers?.['content-type'] || '').toLowerCase();
  if (type.includes('zip')) {
    req.resume?.();
    return sendJson(res, 415, zipRefusal);
  }
  let head = Buffer.alloc(0);
  const peek = (chunk) => {
    if (head.length < 4) head = Buffer.concat([head, Buffer.from(chunk).subarray(0, 4 - head.length)]);
  };
  req.on('data', peek);
  let body;
  try {
    body = await readJsonBody(req, 8 * 1024 * 1024);
  } catch (err) {
    if (!startsWithZipSignature(head)) throw err;
    if (err?.status === 413) {
      // readJsonBody stopped reading mid-body; close once the answer is out.
      res.setHeader('Connection', 'close');
      res.once('finish', () => req.socket?.destroy());
    }
    return sendJson(res, 415, zipRefusal);
  } finally {
    req.off('data', peek);
  }
  if (!isObjectBody(body)) return sendJson(res, 400, { error: 'expected a JSON object' });
  const workspaceId = clampStr(body.workspaceId, 128);
  if (!workspaceId) return sendJson(res, 400, { error: 'workspaceId required' });
  if (!Array.isArray(body.logs)) return sendJson(res, 400, { error: 'logs must be an array' });
  if (body.logs.length > IMPORT_MAX_BATCH) return sendJson(res, 413, { error: `at most ${IMPORT_MAX_BATCH} rows per request` });

  const now = Date.now();
  const records = [];
  let skipped = 0;
  let remapped = 0;
  for (const ev of body.logs) {
    const receivedAt = clampInt(ev?.receivedAt);
    const rec = normalizeEvent(ev, workspaceId, receivedAt === null ? now : receivedAt);
    if (!rec) { skipped++; continue; }
    if (ev.redacted === false) rec.redacted = false;
    const owner = ownerStmt.get(rec.id);
    if (owner && owner.workspace_id !== workspaceId) {
      rec.id = importedId(workspaceId, rec.id);
      remapped++;
    }
    records.push(rec);
  }
  upsertCommandLogBatch(records);
  return sendJson(res, 200, { imported: records.length, remapped, skipped });
}
