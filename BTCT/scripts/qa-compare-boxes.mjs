// Compare everything a reimport needs between two BTCT servers, field by
// field: every shared-doc map (live and retired tables, texts), every page
// body, every asset's bytes, page versions and twins, accounts, settings,
// and the command-log archive. Usage:
//   bun qa-compare-boxes.mjs <urlA> <tokenA> <urlB> <tokenB> [epochB]
//
// It needs yjs and lib0 from the server's node_modules, so run it inside the
// image: docker run --rm --network host -v $PWD/scripts:/app/server/qa \
//   --entrypoint bun <image> qa/qa-compare-boxes.mjs ...
// Pass box B's restore epoch (GET /api/settings restoreEpoch) after a restore.
// Exits 0 when nothing differs. Used for the 2026-10-12 backup-to-a-new-box
// check (docs/competition-fixes-2026-10-12/fixup-round1.md).
import { createRequire } from 'node:module';
import crypto from 'node:crypto';
const require = createRequire(import.meta.url);
const Y = require('yjs'); const enc = require('lib0/encoding'); const dec = require('lib0/decoding');
const [A, TA, B, TB, EB] = process.argv.slice(2);
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex').slice(0, 16);
const problems = [];
const note = (m) => { problems.push(m); if (problems.length < 40) console.log('DIFF', m); };

function room(base, token, name, epoch) {
  return new Promise((resolve, reject) => {
    const u = new URL(`${base.replace('http', 'ws')}/yjs/${encodeURIComponent(name)}`);
    u.searchParams.set('token', token); u.searchParams.set('ro', '1'); if (epoch) u.searchParams.set('epoch', epoch);
    const ws = new WebSocket(u); ws.binaryType = 'arraybuffer';
    const doc = new Y.Doc(); let done = false;
    const finish = () => { if (done) return; done = true; ws.close(); resolve(doc); };
    const t = setTimeout(() => { if (!done) { done = true; ws.close(); reject(new Error(`no sync for ${name}`)); } }, 20000);
    ws.onopen = () => { const e = enc.createEncoder(); enc.writeVarUint(e, 0); enc.writeVarUint(e, 0); enc.writeVarUint8Array(e, Y.encodeStateVector(doc)); ws.send(enc.toUint8Array(e)); };
    ws.onmessage = (m) => {
      const d = dec.createDecoder(new Uint8Array(m.data)); if (dec.readVarUint(d) !== 0) return;
      const ty = dec.readVarUint(d); if (ty === 1) { Y.applyUpdate(doc, dec.readVarUint8Array(d)); clearTimeout(t); finish(); }
    };
    ws.onerror = () => { if (!done) { done = true; clearTimeout(t); reject(new Error(`socket error for ${name}`)); } };
  });
}
async function get(base, token, path, raw = false) {
  const r = await fetch(`${base}${path}`, { headers: { authorization: `Bearer ${token}` } });
  if (!r.ok) return { status: r.status };
  return raw ? new Uint8Array(await r.arrayBuffer()) : r.json();
}
const canon = (v) => JSON.stringify(v, Object.keys(v ?? {}).sort());
function mapDump(doc, name) {
  const m = doc.getMap(name); const out = {};
  for (const [k, v] of m) out[k] = v instanceof Y.AbstractType ? v.toJSON() : v;
  return out;
}

const sa = await room(A, TA, 'btct-shared'); const sb = await room(B, TB, 'btct-shared', EB);
const names = new Set([...sa.share.keys(), ...sb.share.keys()]);
const counts = {};
for (const n of names) {
  const a = mapDump(sa, n), b = mapDump(sb, n);
  counts[n] = Object.keys(a).length;
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  let d = 0;
  for (const k of keys) if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) { d++; if (d <= 3) note(`map ${n} key ${k}`); }
  if (d) note(`map ${n}: ${d} of ${keys.size} entries differ`);
}
console.log('shared-doc maps (entries on A):', JSON.stringify(counts));

const pages = Object.values(mapDump(sa, 'pages'));
let bodies = 0, nonEmpty = 0;
for (let i = 0; i < pages.length; i += 8) {
  await Promise.all(pages.slice(i, i + 8).map(async (p) => {
    const [da, db] = await Promise.all([room(A, TA, p.id), room(B, TB, p.id, EB)]);
    const fa = da.getXmlFragment('prosemirror').toString(), fb = db.getXmlFragment('prosemirror').toString();
    bodies++; if (fa.length) nonEmpty++;
    if (fa !== fb) note(`page body ${p.id} (${p.title}) differs: ${fa.length} vs ${fb.length} chars`);
  }));
}
console.log(`page bodies compared: ${bodies} (${nonEmpty} non-empty)`);

const assets = Object.values(mapDump(sa, 'typstAssets'));
let assetBytes = 0, assetsMissing = 0;
for (let i = 0; i < assets.length; i += 16) {
  await Promise.all(assets.slice(i, i + 16).map(async (a) => {
    const [ba, bb] = await Promise.all([get(A, TA, `/api/assets/${a.id}`, true), get(B, TB, `/api/assets/${a.id}`, true)]);
    if (!(ba instanceof Uint8Array)) { assetsMissing++; return; }
    assetBytes += ba.length;
    if (!(bb instanceof Uint8Array) || sha(ba) !== sha(bb)) note(`asset ${a.id} bytes differ or missing on B`);
  }));
}
console.log(`asset blobs compared: ${assets.length} (${(assetBytes / 1048576).toFixed(1)} MB; ${assetsMissing} with no blob on A either)`);

let versions = 0, twins = 0;
for (let i = 0; i < pages.length; i += 8) {
  await Promise.all(pages.slice(i, i + 8).map(async (p) => {
    const [va, vb] = await Promise.all([get(A, TA, `/api/pages/${p.id}/versions`), get(B, TB, `/api/pages/${p.id}/versions`)]);
    const ia = (va.versions ?? []).map((v) => `${v.id}:${v.trigger}:${v.name ?? ''}`).join(','), ib = (vb.versions ?? []).map((v) => `${v.id}:${v.trigger}:${v.name ?? ''}`).join(',');
    versions += (va.versions ?? []).length;
    if (ia !== ib) note(`versions of ${p.id} differ`);
    const [ta, tb] = await Promise.all([get(A, TA, `/api/pages/${p.id}/history/twin`, true), get(B, TB, `/api/pages/${p.id}/history/twin`, true)]);
    if (ta instanceof Uint8Array) { twins++; if (!(tb instanceof Uint8Array) || sha(ta) !== sha(tb)) note(`twin of ${p.id} differs`); }
  }));
}
console.log(`page versions compared: ${versions}, twins compared: ${twins}`);

const ua = await get(A, TA, '/api/admin/users'), ub = await get(B, TB, '/api/admin/users');
const strip = (u) => (u.users ?? []).map(({ id, username, isAdmin, is_admin, color }) => ({ id, username, admin: isAdmin ?? is_admin, color }));
if (JSON.stringify(strip(ua)) !== JSON.stringify(strip(ub))) note('accounts differ');
console.log(`accounts compared: ${(ua.users ?? []).length}`);
const sA = await get(A, TA, '/api/settings'), sB = await get(B, TB, '/api/settings');
for (const k of Object.keys(sA)) if (k !== 'restoreEpoch' && JSON.stringify(sA[k]) !== JSON.stringify(sB[k])) note(`settings.${k} differs`);
for (const p of ['/api/cmdlog/config', '/api/retention/config']) {
  const a = await get(A, TA, p), b = await get(B, TB, p);
  if (JSON.stringify(a) !== JSON.stringify(b)) note(`${p} differs`);
}
let cmd = 0;
for (const w of Object.keys(mapDump(sa, 'workspaces')).concat(['w-orphan'])) {
  const a = await get(A, TA, `/api/cmdlog/export?workspaceId=${w}&format=json`), b = await get(B, TB, `/api/cmdlog/export?workspaceId=${w}&format=json`);
  cmd += Array.isArray(a) ? a.length : 0;
  if (JSON.stringify(a) !== JSON.stringify(b)) note(`command log of ${w} differs`);
}
console.log(`command-log rows compared: ${cmd}`);
console.log(problems.length ? `RESULT: ${problems.length} difference(s)` : 'RESULT: identical');
process.exit(problems.length ? 1 : 0);
