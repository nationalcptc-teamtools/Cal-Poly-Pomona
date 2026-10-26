// ─────────────────────────────────────────────────────────────────────────
// Server-side access to the shared Yjs workspace document ("btct-shared").
//
// The whole app state (workspaces, pages, nmap scans/hosts, command logs,
// change log) lives in ONE Yjs doc that every browser client edits
// collaboratively. y-websocket keeps that doc resident in this process
// (utils' `docs` map / `getYDoc`), so the few server features that must touch
// workspace data (command-log ingest, the public settings mirror, asset
// retention, and the Typst report export) read and write it in-process;
// writes broadcast to every connected client.
//
// Records are plain JSON keyed by id in a per-table Y.Map (last-writer-wins).
// Wrap writes in `doc.transact` so observers fire once. This file reads one
// collaborative Y.Text field (the Typst report source) and writes none, so
// the client's Y.Text invariant does not come into play here; if a write is
// added, it must set BOTH the Y.Text and the record.
// ─────────────────────────────────────────────────────────────────────────
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

// Reach the live doc through the SAME CJS module instance y-websocket uses
// internally. Importing Yjs via ESM here would create a second Yjs instance
// ("Yjs was already imported"), whose classes the shared doc would not
// recognize. The scan-ingest writers below construct a Y.Text (for a new nmap
// scan name / machine hostname), so Yjs itself is pulled in through the SAME
// CJS require, never an ESM import, for the same reason.
const require = createRequire(import.meta.url);
const { getYDoc, getPersistence, docs } = require('y-websocket/bin/utils');
const Y = require('yjs');

const ROOM = 'btct-shared';
const TABLE_NAMES = [
  'workspaces', 'pages', 'changeLogs', 'nmapScans', 'nmapMachines',
  'commandLogs', 'settingsPublic',
];

// The shared doc holds only a bounded live window of command logs per workspace
// (the durable archive is SQLite). Keep memory + render cost small on clients.
const CMDLOG_LIVE_CAP = 500;

// Resolve the live shared doc + its table maps, once the room's stored
// state is in memory (server/relay-persistence.mjs sets `doc.whenLoaded`).
// After that load the doc is authoritative: an empty `workspaces` map means
// the box has no workspace yet, so there is nothing to poll for (a 2 s poll
// here made every command-log POST on a fresh box take 2 s). Without
// persistence (YPERSISTENCE unset, a dev run) there is nothing to load, and
// Yjs's own `whenLoaded` (a subdocument promise) would never resolve, so it
// is not awaited. A room LevelDB cannot read is dropped from the relay map
// and the call throws, rather than writing into a doc nobody will store.
// Cache the resolved handles per doc instance: helpers call shared() several
// times per request. Keyed weakly by the doc so a recreated room re-resolves.
const sharedCache = new WeakMap();

async function shared() {
  const doc = getYDoc(ROOM);
  const hit = sharedCache.get(doc);
  if (hit) return hit;
  if (getPersistence()) {
    try {
      await doc.whenLoaded;
    } catch (err) {
      if (docs.get(ROOM) === doc && doc.conns.size === 0) {
        docs.delete(ROOM);
        doc.destroy();
      }
      throw new Error(`the shared workspace room could not be loaded: ${err?.message || err}`);
    }
  }
  const tables = {};
  for (const name of TABLE_NAMES) tables[name] = doc.getMap(name);
  const texts = doc.getMap('texts');
  const resolved = { doc, tables, texts };
  sharedCache.set(doc, resolved);
  return resolved;
}

function values(map) {
  return [...map.values()];
}

export async function listWorkspaces() {
  const { tables } = await shared();
  return values(tables.workspaces).map((w) => ({
    id: w.id, name: w.name, description: w.description,
  }));
}

// ── Command log (team pentest command activity) ──
// Batch-upsert records into the live window. These records have NO Y.Text
// fields (like typstAssets): every field is plain LWW JSON, so invariant #1
// doesn't apply. A completion event (exitCode/durationMs) is
// merged over the existing start record by id. After each batch we prune the
// oldest entries per workspace beyond CMDLOG_LIVE_CAP so the doc stays bounded.
export async function appendCommandLogs(records) {
  if (!records || !records.length) return;
  const { doc, tables } = await shared();
  doc.transact(() => {
    for (const r of records) {
      const existing = tables.commandLogs.get(r.id);
      tables.commandLogs.set(r.id, existing ? { ...existing, ...r } : r);
    }
    pruneCommandLogs(tables.commandLogs);
  });
}

// Public settings mirror. The server writes the admin theme policy (accent,
// heading colours, hard-lock) under `settingsPublic.theme` so every connected
// client re-themes live; the REST `GET /api/settings` response is the seed on
// load, and `themeUpdatedAt` lets a client ignore a stale copy replayed from
// its IndexedDB cache. LWW JSON with no Y.Text fields, so invariant #1 does
// not apply. Never put anything secret here: the whole doc reaches every user.
export async function publishPublicSettings(theme) {
  const { doc, tables } = await shared();
  doc.transact(() => {
    tables.settingsPublic.set('theme', theme);
  });
}

/** Asset ids whose shared record was retired (soft-deleted) before `cutoffMs`. */
export async function collectRetiredAssets(cutoffMs) {
  const { doc } = await shared();
  // Read the map directly (typstAssets isn't in the server's TABLE_NAMES).
  const assets = doc.getMap('typstAssets');
  const ids = [];
  assets.forEach((rec, id) => {
    if (rec && typeof rec.deletedAt === 'number' && rec.deletedAt > 0 && rec.deletedAt < cutoffMs) ids.push(id);
  });
  return ids;
}

/** Remove asset metadata records from the shared doc (after their bytes are gone). */
export async function removeAssetRecords(ids) {
  if (!ids.length) return;
  const { doc } = await shared();
  const assets = doc.getMap('typstAssets');
  doc.transact(() => { for (const id of ids) assets.delete(id); });
}

/** Mirror the public blur-defaults policy (same pattern as the theme). */
export async function publishPublicBlur(blur) {
  const { doc, tables } = await shared();
  doc.transact(() => {
    tables.settingsPublic.set('blur', blur);
  });
}

// ── Typst report export (server/typst/) ──
// Read-only. The report source is a Y.Text in `texts`; `typstAssets` is not
// in TABLE_NAMES (the server never needed it as a table), so it is read
// straight off the doc like the retention pair above.
export async function readTypstSource(workspaceId) {
  const { texts } = await shared();
  const t = texts.get(`typst:${workspaceId}:source`);
  return t ? t.toString() : null;
}

export async function listAssetRecords(workspaceId) {
  const { doc } = await shared();
  return [...doc.getMap('typstAssets').values()].filter((a) => a && a.workspaceId === workspaceId && !a.deletedAt);
}

function pruneCommandLogs(map) {
  // Under the cap in total means under the cap for every workspace; skip
  // the full materialize-and-sort on the common (bounded) path.
  if (map.size <= CMDLOG_LIVE_CAP) return;
  const byWs = new Map();
  map.forEach((rec, key) => {
    // Any client can write any JSON here: drop non-objects instead of throwing.
    if (!rec || typeof rec !== 'object') { map.delete(key); return; }
    const ws = rec.workspaceId ?? '';
    const arr = byWs.get(ws) || [];
    arr.push([key, rec]);
    byWs.set(ws, arr);
  });
  for (const arr of byWs.values()) {
    if (arr.length <= CMDLOG_LIVE_CAP) continue;
    arr.sort((a, b) => (Number(a[1].startedAt) || 0) - (Number(b[1].startedAt) || 0)); // oldest first
    for (const [key] of arr.slice(0, arr.length - CMDLOG_LIVE_CAP)) map.delete(key);
  }
}

// ── Scan ingest (server/scan-ingest.mjs) ──
// The FOURTH exception to "the server is dumb about domain data": the scan
// upload endpoints write nmap scans, hosts and tool findings into the shared
// doc, which broadcasts so every client's Yjs->Dexie mirror reloads the nmap
// tables (no polling). `nmapScan.name` and `nmapMachine.hostname` ARE
// collaborative Y.Texts, so a NEWLY created record seeds BOTH the JSON record
// field and its Y.Text (invariant #1 and this file's header): a record-only
// write would be reverted by the client mirror on the next sync. `toolFindings`
// is plain LWW JSON (like `ports`), so it needs no Y.Text.

/** Seed a Y.Text for a new record's collaborative field (no-op if it exists). */
function seedText(texts, key, value) {
  if (texts.has(key)) return;
  const t = new Y.Text();
  if (value) t.insert(0, String(value));
  texts.set(key, t);
}

/** Merge port lists by protocol/port, incoming wins. */
function mergePorts(existing, incoming) {
  const byKey = new Map((Array.isArray(existing) ? existing : []).map((p) => [`${p.protocol}/${p.port}`, p]));
  for (const p of incoming) byKey.set(`${p.protocol}/${p.port}`, p);
  return [...byKey.values()];
}

/**
 * Upsert hosts (by IP) into a find-or-create nmap scan group.
 * @param {{ workspaceId: string, scanName: string, hosts: Array<{ip,hostname,os,ports}> }} input
 * @returns {Promise<{ scanId: string, added: number, updated: number }>}
 */
export async function importNmapHosts({ workspaceId, scanName, hosts }) {
  const { doc, tables, texts } = await shared();
  let added = 0;
  let updated = 0;
  let scanId = null;
  doc.transact(() => {
    for (const s of tables.nmapScans.values()) {
      if (s && s.workspaceId === workspaceId && s.name === scanName) { scanId = s.id; break; }
    }
    if (!scanId) {
      scanId = crypto.randomUUID();
      tables.nmapScans.set(scanId, { id: scanId, workspaceId, name: scanName, importedAt: Date.now() });
      seedText(texts, `nmapScan:${scanId}:name`, scanName);
    }
    const byIp = new Map();
    for (const m of tables.nmapMachines.values()) {
      if (m && m.scanId === scanId) byIp.set(m.ip, m);
    }
    const now = Date.now();
    for (const h of hosts) {
      const ex = byIp.get(h.ip);
      if (ex) {
        tables.nmapMachines.set(ex.id, {
          ...ex,
          ports: mergePorts(ex.ports, h.ports),
          hostname: h.hostname || ex.hostname,
          os: h.os !== 'unknown' ? h.os : ex.os,
          updatedAt: now,
        });
        updated++;
      } else {
        const id = crypto.randomUUID();
        tables.nmapMachines.set(id, {
          id, scanId, ip: h.ip, hostname: h.hostname, os: h.os, ports: h.ports,
          createdAt: now, updatedAt: now,
        });
        seedText(texts, `nmapMachine:${id}:hostname`, h.hostname);
        byIp.set(h.ip, tables.nmapMachines.get(id));
        added++;
      }
    }
  });
  return { scanId, added, updated };
}

const TOOL_UPLOAD_GROUP = 'Tool uploads';

/**
 * Attach tool findings to the machine with `ip` in `workspaceId`. If no machine
 * has that IP yet, one is created in a "Tool uploads" group so nothing is lost.
 * Findings dedupe by tool + url + title.
 * @returns {Promise<{ machineId: string, matched: boolean, added: number, deduped: number, total: number }>}
 */
export async function attachToolFindings({ workspaceId, ip, tool, findings, hostname }) {
  const { doc, tables, texts } = await shared();
  let machineId = null;
  let matched = false;
  let hostnameSet = false;
  let added = 0;
  let deduped = 0;
  let total = 0;
  doc.transact(() => {
    const scanIds = new Set();
    for (const s of tables.nmapScans.values()) if (s && s.workspaceId === workspaceId) scanIds.add(s.id);
    let machine = null;
    for (const m of tables.nmapMachines.values()) {
      if (m && scanIds.has(m.scanId) && m.ip === ip) { machine = m; break; }
    }
    if (machine) {
      matched = true;
    } else {
      let groupId = null;
      for (const s of tables.nmapScans.values()) {
        if (s && s.workspaceId === workspaceId && s.name === TOOL_UPLOAD_GROUP) { groupId = s.id; break; }
      }
      if (!groupId) {
        groupId = crypto.randomUUID();
        tables.nmapScans.set(groupId, { id: groupId, workspaceId, name: TOOL_UPLOAD_GROUP, importedAt: Date.now() });
        seedText(texts, `nmapScan:${groupId}:name`, TOOL_UPLOAD_GROUP);
      }
      const id = crypto.randomUUID();
      machine = { id, scanId: groupId, ip, hostname: '', os: 'unknown', ports: [], createdAt: Date.now(), updatedAt: Date.now() };
      tables.nmapMachines.set(id, machine);
      seedText(texts, `nmapMachine:${id}:hostname`, '');
    }
    machineId = machine.id;
    // A vhost discovered during web enum (e.g. an HTTP redirect) can be
    // attached here, but only when the host has no hostname yet: never clobber
    // a name a teammate typed. The field starts empty, so this is an insert.
    if (hostname && !(machine.hostname && machine.hostname.trim())) {
      const key = `nmapMachine:${machine.id}:hostname`;
      const t = texts.get(key);
      if (t) { if (t.length) t.delete(0, t.length); t.insert(0, hostname); }
      else seedText(texts, key, hostname);
      machine = { ...machine, hostname };
      hostnameSet = true;
    }
    const existing = Array.isArray(machine.toolFindings) ? machine.toolFindings : [];
    const seen = new Set(existing.map((f) => `${f.tool}|${f.url || ''}|${f.title}`));
    const next = existing.slice();
    for (const f of findings) {
      const key = `${f.tool}|${f.url || ''}|${f.title}`;
      if (seen.has(key)) { deduped++; continue; }
      seen.add(key);
      next.push({ ...f, id: crypto.randomUUID() });
      added++;
    }
    total = next.length;
    tables.nmapMachines.set(machine.id, { ...machine, toolFindings: next, updatedAt: Date.now() });
  });
  return { machineId, matched, hostnameSet, added, deduped, total };
}
