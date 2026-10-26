// ─────────────────────────────────────────────────────────────────────────
// Scan ingest: HTTP upload of nmap scans and web/app tool output.
//
// Two endpoints (wired in index.mjs):
//   • POST /api/scans/nmap  takes raw `nmap -oX` XML OR a hosts JSON payload,
//     and upserts hosts (by IP) into a named nmap scan group.
//   • POST /api/scans/tool  takes findings from gobuster / sqlmap / sstimap /
//     dalfox and attaches them to the machine whose IP they target (the one
//     the nmap upload created), creating a stub machine if that IP is new.
//
// Both write the live shared Yjs doc through yjs-data.mjs, exactly like the
// command-log ingest: the write broadcasts to every open browser, whose
// Yjs->Dexie mirror reloads the nmap tables, so the scan view updates with no
// polling. This is the FOURTH deliberate exception to "the server is dumb
// about domain data" (alongside the command log, the public settings mirror
// and assets).
//
// Auth: open by default (a trusted competition LAN, see the admin's call).
// An admin may set an optional bearer token in the settings KV; when set it is
// required (timing-safe compare), when empty the endpoints accept anyone who
// can reach the box. A disabled flag closes both endpoints regardless.
// ─────────────────────────────────────────────────────────────────────────
import crypto from 'node:crypto';
import { getSetting, setSetting } from './db.mjs';
import { importNmapHosts, attachToolFindings, listWorkspaces } from './yjs-data.mjs';

const T_ENABLED = 'scan_ingest_enabled';   // '1' / '0'; unset means enabled
const T_TOKEN = 'scan_ingest_token';       // optional bearer; empty means open
const T_WORKSPACE = 'scan_ingest_workspace'; // optional default target workspace id

const MAX_HOSTS = 2000;
const MAX_PORTS_PER_HOST = 5000;
const MAX_FINDINGS = 2000;
const MAX_TITLE = 512;
const MAX_EVIDENCE = 64 * 1024;
const MAX_DETAIL_KEYS = 40;
const MAX_DETAIL_LEN = 2048;
const BODY_LIMIT = 16 * 1024 * 1024;       // nmap -oX of a /24 with -sC is big

const TOOLS = new Set([
  'gobuster', 'sqlmap', 'sstimap', 'dalfox', 'openvas', 'nuclei', 'bbot',
  'wpscan', 'nikto', 'gitleaks', 'secretfinder',
]);
const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);
const OS_VALUES = new Set(['windows', 'linux', 'attacker', 'unknown']);

const genToken = () => 'btct_scan_' + crypto.randomBytes(24).toString('hex');

// ── Admin config ──
export function getScanConfig() {
  return {
    enabled: getSetting(T_ENABLED) !== '0',       // default on
    token: getSetting(T_TOKEN) || null,            // null means open
    workspaceId: getSetting(T_WORKSPACE) || null,
  };
}

export function setScanConfig(body) {
  if (typeof body.enabled === 'boolean') setSetting(T_ENABLED, body.enabled ? '1' : '0');
  if (body.workspaceId !== undefined) setSetting(T_WORKSPACE, body.workspaceId ? String(body.workspaceId) : '');
  // token: null/'' clears it (open), a string sets it verbatim (admin-chosen).
  if (body.token !== undefined) setSetting(T_TOKEN, body.token ? String(body.token).slice(0, 128) : '');
  return getScanConfig();
}

export function regenerateScanToken() {
  const t = genToken();
  setSetting(T_TOKEN, t);
  return t;
}

// ── Bearer gate ──
function constantEq(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// Returns true when the request may ingest. A logged-in app user (`authed`,
// checked in index.mjs) is always allowed: it drives the in-app upload UI and
// is already trusted to write the workspace. Otherwise: disabled -> 403; a
// token set -> it must match; no token -> open. Writes its own error on refusal.
function requireScanIngest(req, res, sendJson, authed) {
  if (authed) return true;
  if (getSetting(T_ENABLED) === '0') {
    sendJson(res, 403, { error: 'scan ingest disabled' });
    return false;
  }
  const token = getSetting(T_TOKEN);
  if (token) {
    const h = req.headers.authorization || '';
    const provided = h.toLowerCase().startsWith('bearer ') ? h.slice(7).trim() : '';
    if (!provided || !constantEq(provided, token)) {
      sendJson(res, 401, { error: 'unauthorized' });
      return false;
    }
  }
  return true;
}

// ── Body reader (raw text; nmap may send XML, tools send JSON) ──
function readRawBody(req, limit = BODY_LIMIT) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > limit) {
        const err = new Error('payload too large');
        err.status = 413;
        reject(err);
        req.pause();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// ── Coercion helpers ──
const str = (v, max = MAX_DETAIL_LEN) =>
  (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')
    ? String(v).slice(0, max)
    : '';
const isObj = (b) => b !== null && typeof b === 'object' && !Array.isArray(b);
const intOrNull = (v) =>
  ((typeof v === 'number' || typeof v === 'string') && Number.isFinite(Number(v)))
    ? Math.trunc(Number(v)) : null;

function normOs(v) {
  const s = String(v || '').trim().toLowerCase();
  return OS_VALUES.has(s) ? s : 'unknown';
}

function normPort(raw) {
  const port = intOrNull(raw?.port);
  if (port === null || port < 0 || port > 65535) return null;
  const scripts = Array.isArray(raw?.scripts)
    ? raw.scripts
        .map((s) => ({ id: str(s?.id, 256), output: str(s?.output, MAX_EVIDENCE) }))
        .filter((s) => s.id)
    : [];
  const proto = String(raw?.protocol || 'tcp').trim().toLowerCase() || 'tcp';
  return {
    port,
    protocol: proto,
    state: String(raw?.state || 'open').trim().toLowerCase() || 'open',
    service: str(raw?.service, 256),
    version: str(raw?.version, 512),
    ...(scripts.length ? { scripts } : {}),
  };
}

function normHost(raw) {
  const ip = str(raw?.ip, 128).trim();
  if (!ip) return null;
  const ports = Array.isArray(raw?.ports)
    ? raw.ports.slice(0, MAX_PORTS_PER_HOST).map(normPort).filter(Boolean)
    : [];
  return {
    ip,
    hostname: str(raw?.hostname, 256).trim(),
    os: normOs(raw?.os),
    ports,
  };
}

function normFinding(raw) {
  const title = str(raw?.title, MAX_TITLE).trim();
  if (!title) return null;
  const sevRaw = String(raw?.severity || 'info').trim().toLowerCase();
  const severity = SEVERITIES.has(sevRaw) ? sevRaw : 'info';
  const out = { title, severity, createdAt: Date.now() };
  const url = str(raw?.url, 2048).trim();
  if (url) out.url = url;
  const port = intOrNull(raw?.port);
  if (port !== null && port >= 0 && port <= 65535) out.port = port;
  if (isObj(raw?.details)) {
    const details = {};
    let n = 0;
    for (const [k, v] of Object.entries(raw.details)) {
      if (n >= MAX_DETAIL_KEYS) break;
      if (v === null || v === undefined) continue;
      if (typeof v === 'object') continue; // flat only
      details[str(k, 128)] = typeof v === 'number' || typeof v === 'boolean' ? v : str(v, MAX_DETAIL_LEN);
      n++;
    }
    if (n) out.details = details;
  }
  const evidence = str(raw?.evidence, MAX_EVIDENCE);
  if (evidence) out.evidence = evidence;
  return out;
}

// ── Minimal nmap -oX parser (Bun has no DOMParser) ──
// Handles the standard `nmap -oX` shape: <host> blocks with <address>,
// <hostname>, <os><osmatch>/<osclass>, and <port><state><service><script>.
// The browser parser (src/lib/nmap-parser.ts) is the reference; this is a
// tolerant string scan for the server, and JSON is the recommended path.
function decodeXml(s) {
  return String(s)
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}
const attr = (tag, name) => {
  const m = new RegExp(`\\b${name}="([^"]*)"`).exec(tag);
  return m ? decodeXml(m[1]) : '';
};
function guessOsFromName(name) {
  const l = name.toLowerCase();
  if (l.includes('windows')) return 'windows';
  if (/(linux|ubuntu|debian|centos|fedora|red hat)/.test(l)) return 'linux';
  return 'unknown';
}

export function parseNmapXml(xml) {
  const hosts = [];
  const hostRe = /<host\b[\s\S]*?<\/host>/g;
  let hm;
  while ((hm = hostRe.exec(xml)) && hosts.length < MAX_HOSTS) {
    const block = hm[0];
    const status = /<status\b[^>]*\bstate="([^"]*)"/.exec(block);
    if (status && status[1] !== 'up') continue;

    let ip = '';
    const addrRe = /<address\b[^>]*>/g;
    let am;
    while ((am = addrRe.exec(block))) {
      const t = am[0];
      const type = attr(t, 'addrtype');
      if (type === 'ipv4' || type === 'ipv6') { ip = attr(t, 'addr'); break; }
    }
    if (!ip) continue;

    const hn = /<hostname\b[^>]*\bname="([^"]*)"/.exec(block);
    const hostname = hn ? decodeXml(hn[1]) : '';

    let os = 'unknown';
    const osm = /<osmatch\b[^>]*\bname="([^"]*)"/.exec(block);
    if (osm) os = guessOsFromName(decodeXml(osm[1]));
    if (os === 'unknown') {
      const oc = /<osclass\b[^>]*\bosfamily="([^"]*)"/.exec(block);
      if (oc) os = guessOsFromName(decodeXml(oc[1]));
    }

    const ports = [];
    const portRe = /<port\b([^>]*)>([\s\S]*?)<\/port>/g;
    let pm;
    while ((pm = portRe.exec(block)) && ports.length < MAX_PORTS_PER_HOST) {
      const pAttrs = pm[1];
      const inner = pm[2];
      const portid = intOrNull(attr(`<port ${pAttrs}>`, 'portid'));
      if (portid === null) continue;
      const stateTag = /<state\b[^>]*>/.exec(inner);
      const serviceTag = /<service\b[^>]*>/.exec(inner);
      const scripts = [];
      const scriptRe = /<script\b([^>]*)(?:\/>|>[\s\S]*?<\/script>)/g;
      let sm;
      while ((sm = scriptRe.exec(inner))) {
        const sTag = `<script ${sm[1]}>`;
        const id = attr(sTag, 'id');
        const output = attr(sTag, 'output');
        if (id) scripts.push({ id, output });
      }
      const sv = serviceTag ? serviceTag[0] : '';
      const version = [attr(sv, 'product'), attr(sv, 'version'), attr(sv, 'extrainfo')]
        .filter(Boolean).join(' ');
      ports.push({
        port: portid,
        protocol: attr(`<port ${pAttrs}>`, 'protocol') || 'tcp',
        state: stateTag ? attr(stateTag[0], 'state') || 'unknown' : 'unknown',
        service: serviceTag ? attr(sv, 'name') : '',
        version,
        ...(scripts.length ? { scripts } : {}),
      });
    }

    // Fallback OS inference from port/service signatures (mirror the client).
    if (os === 'unknown') {
      const open = new Set(ports.filter((p) => p.state === 'open').map((p) => p.port));
      const svcs = new Set(ports.map((p) => p.service));
      if (svcs.has('msrpc') || svcs.has('microsoft-ds') || (open.has(135) && open.has(445))) os = 'windows';
      else if ((open.has(22) || svcs.has('ssh')) && !open.has(135) && !open.has(445)) os = 'linux';
    }

    hosts.push({ ip, hostname, os, ports });
  }
  return hosts;
}

// ── Workspace resolution: body value (id OR exact name), else default, else first. ──
async function resolveWorkspace(raw) {
  const want = String(raw || '').trim();
  let workspaces = [];
  try { workspaces = await listWorkspaces(); } catch { /* cold doc: fall through */ }
  if (want) {
    const byId = workspaces.find((w) => w.id === want);
    if (byId) return byId.id;
    const byName = workspaces.find((w) => (w.name || '').toLowerCase() === want.toLowerCase());
    if (byName) return byName.id;
    return null; // asked for a specific workspace that does not exist
  }
  const dflt = getSetting(T_WORKSPACE);
  if (dflt && workspaces.some((w) => w.id === dflt)) return dflt;
  return workspaces[0]?.id || null;
}

// ── Route handlers ──

// POST /api/scans/nmap  (raw nmap -oX XML, or JSON { workspace?, scan?, hosts[] })
// On the XML path, ?workspace= and ?scan= query params set the target.
export async function handleNmapUpload(req, res, { sendJson, authed }) {
  if (!requireScanIngest(req, res, sendJson, authed)) return;
  const text = await readRawBody(req);
  const trimmed = text.trimStart();
  const type = String(req.headers['content-type'] || '').toLowerCase();

  let workspaceRaw = '';
  let scanName = '';
  let hosts = [];
  let received = 0;

  if (trimmed.startsWith('<') || type.includes('xml')) {
    hosts = parseNmapXml(text);
    received = hosts.length;
    const url = new URL(req.url, 'http://x');
    workspaceRaw = url.searchParams.get('workspace') || '';
    scanName = url.searchParams.get('scan') || '';
  } else {
    let body;
    try { body = JSON.parse(text || '{}'); } catch { return sendJson(res, 400, { error: 'invalid json' }); }
    if (!isObj(body)) return sendJson(res, 400, { error: 'expected a JSON object or nmap XML' });
    workspaceRaw = body.workspace || '';
    scanName = str(body.scan, 200).trim();
    const rawHosts = Array.isArray(body.hosts) ? body.hosts : [];
    received = rawHosts.length;
    if (received > MAX_HOSTS) return sendJson(res, 413, { error: `too many hosts in one request (max ${MAX_HOSTS}); split the upload` });
    hosts = rawHosts.map(normHost).filter(Boolean);
  }

  if (!hosts.length) return sendJson(res, 400, { error: 'no valid hosts in upload (each host needs an ip)' });

  const workspaceId = await resolveWorkspace(workspaceRaw);
  if (!workspaceId) {
    return sendJson(res, 409, {
      error: workspaceRaw
        ? `no workspace matches "${String(workspaceRaw).slice(0, 80)}" (use its id or exact name; the app does not create workspaces from an upload)`
        : 'no target workspace yet (create one in the app, or set a default in Scan Upload settings)',
    });
  }
  if (!scanName) scanName = `Scan ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`;

  let result;
  try { result = await importNmapHosts({ workspaceId, scanName, hosts }); }
  catch (e) { return sendJson(res, 500, { error: `import failed: ${e?.message || e}` }); }

  return sendJson(res, 200, {
    workspaceId,
    scanId: result.scanId,
    scan: scanName,
    hostsReceived: received,
    hostsValid: hosts.length,
    hostsSkipped: received - hosts.length,
    added: result.added,       // new hosts created in the group
    updated: result.updated,   // existing hosts whose ports were merged
  });
}

// POST /api/scans/tool
// JSON { workspace?, tool, target:{ ip, port?, url?, hostname? }, findings[] }
export async function handleToolUpload(req, res, { sendJson, authed }) {
  if (!requireScanIngest(req, res, sendJson, authed)) return;
  const text = await readRawBody(req);
  let body;
  try { body = JSON.parse(text || '{}'); } catch { return sendJson(res, 400, { error: 'invalid json' }); }
  if (!isObj(body)) return sendJson(res, 400, { error: 'expected a JSON object' });

  const tool = String(body.tool || '').trim().toLowerCase();
  if (!tool) return sendJson(res, 400, { error: 'tool is required' });
  if (!TOOLS.has(tool) && tool.length > 32) return sendJson(res, 400, { error: 'unknown tool' });

  const target = isObj(body.target) ? body.target : {};
  const ip = str(target.ip, 128).trim();
  if (!ip) return sendJson(res, 400, { error: 'target.ip is required (the machine the findings sync to)' });

  const rawFindings = Array.isArray(body.findings) ? body.findings : [];
  const received = rawFindings.length;
  if (received > MAX_FINDINGS) return sendJson(res, 413, { error: `too many findings in one request (max ${MAX_FINDINGS}); send in chunks` });
  const findings = rawFindings.map(normFinding).filter(Boolean);
  if (!findings.length) return sendJson(res, 400, { error: 'no valid findings (each needs a title)' });

  const workspaceId = await resolveWorkspace(body.workspace || '');
  if (!workspaceId) {
    return sendJson(res, 409, {
      error: body.workspace
        ? `no workspace matches "${String(body.workspace).slice(0, 80)}" (use its id or exact name; the app does not create workspaces from an upload)`
        : 'no target workspace yet (upload an nmap scan first, or set a default)',
    });
  }

  // Carry the scan's base port/url onto findings that omit their own.
  const targetPort = intOrNull(target.port);
  const targetUrl = str(target.url, 2048).trim();
  const hostname = str(target.hostname, 256).trim();
  for (const f of findings) {
    if (f.port === undefined && targetPort !== null && targetPort >= 0 && targetPort <= 65535) f.port = targetPort;
    if (!f.url && targetUrl) f.url = targetUrl;
    f.tool = tool;
  }

  let result;
  try { result = await attachToolFindings({ workspaceId, ip, tool, findings, hostname }); }
  catch (e) { return sendJson(res, 500, { error: `attach failed: ${e?.message || e}` }); }

  return sendJson(res, 200, {
    workspaceId,
    machineId: result.machineId,
    ip,
    tool,
    matched: result.matched,          // true if the IP already had a machine (false = a stub was created)
    hostnameSet: result.hostnameSet,  // true if target.hostname filled an empty hostname
    received,                         // findings in the request
    added: result.added,              // new findings stored
    deduped: result.deduped,          // skipped as duplicates (same tool+url+title)
    skipped: received - findings.length, // dropped as invalid (no title / bad shape)
    total: result.total,              // findings now on the machine
  });
}
