// @vitest-environment node
// Live round trip of the workspace archive against real servers.
//
// Skipped by `bun run test`. Run one phase at a time with a server URL, a
// token and an output folder (see docs/competition-fixes-2026-10-12/exports.md):
//
//   BTCT_LIVE_PHASE=seed|export|import|verify BTCT_LIVE_URL=http://127.0.0.1:8134 \
//   BTCT_LIVE_TOKEN=<jwt> BTCT_LIVE_OUT=/out bunx vitest run src/test/live-exports.test.ts
//
// It drives the same client code the dialog does (the shared doc, the page
// body reader and writer, uploads, the command-log routes) over real
// websockets. The only stand-in is the image render, which needs a browser
// canvas: here `modified` is the original bytes.
//
// Node environment, not jsdom: jsdom's Blob is not one the runtime's fetch
// can send, so an upload would post the text "[object Blob]".
import 'fake-indexeddb/auto';
import { describe, expect, it, vi } from 'vitest';

vi.hoisted(() => {
  // The shared doc's mirror schedules with window.setTimeout.
  const g = globalThis as unknown as { window?: unknown };
  if (!g.window) g.window = globalThis;
});
import fs from 'node:fs';
import * as Y from 'yjs';

const env = (k: string) => (typeof process !== 'undefined' ? process.env[k] : undefined) ?? '';
const PHASE = env('BTCT_LIVE_PHASE');
const OUT = env('BTCT_LIVE_OUT') || '/tmp';

vi.mock('@/auth/auth-store', () => {
  const base = (typeof process !== 'undefined' && process.env.BTCT_LIVE_URL) || 'http://127.0.0.1:1';
  const state = { token: (typeof process !== 'undefined' && process.env.BTCT_LIVE_TOKEN) || '', user: null };
  return { API_URL: base, WS_URL: base.replace(/^http/, 'ws'), useAuthStore: { getState: () => state, subscribe: () => () => {} }, probeSession: async () => 'ok' };
});
vi.mock('@/realtime/page-history-api', () => ({ attachUserMapping: vi.fn() }));
vi.mock('@/lib/assets', async (orig) => ({
  ...(await orig<typeof import('@/lib/assets')>()),
  renderAssetBytes: async (_a: unknown, raw: Uint8Array) => raw,
}));

import { getSharedDoc, seedMissingYTexts } from '@/realtime/shared-doc';
import { exportWorkspaceFromApp, importWorkspaceIntoApp } from '@/export/export-workspace';
import { parseWorkspaceZip } from '@/export/workspace-zip';
import { browserPageBodyIO } from '@/export/page-bodies';
import { importCommandLogs, countCommandLogArchive } from '@/export/cmdlog-io';
import { uploadAsset } from '@/lib/assets';
import type { Page, TypstAsset } from '@/types';

// A real 1x1 PNG, so the server's format sniff accepts it.
const PNG = Uint8Array.from(atob('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=='), (c) => c.charCodeAt(0));
const PAGES = Number(env('BTCT_LIVE_PAGES')) || 30;
const LOGS = 6000;
const CHANGES = 6000;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond: () => boolean, ms = 20_000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) throw new Error('timed out waiting'); await sleep(100); }
}

function body(text: string, assetIds: string[]): Uint8Array {
  const doc = new Y.Doc();
  const p = new Y.XmlElement('paragraph');
  p.insert(0, [new Y.XmlText(text)]);
  const imgs = assetIds.map((id) => { const el = new Y.XmlElement('asset_image'); el.setAttribute('assetId', id); return el; });
  doc.getXmlFragment('prosemirror').insert(0, [p, ...imgs]);
  return Y.encodeStateAsUpdate(doc);
}

function fragmentAssetIds(update: Uint8Array): { blocks: number; ids: string[] } {
  const doc = new Y.Doc();
  Y.applyUpdate(doc, update);
  const frag = doc.getXmlFragment('prosemirror');
  const ids = [...frag.createTreeWalker((n) => n instanceof Y.XmlElement && n.nodeName === 'asset_image')]
    .map((n) => (n as Y.XmlElement).getAttribute('assetId') as string);
  return { blocks: frag.length, ids };
}

async function sharedReady(): Promise<void> {
  await getSharedDoc().whenReady;
  await waitFor(() => getSharedDoc().provider.synced, 20_000);
}

/** A second connection's view of the shared doc, to prove writes reached the server. */
async function serverShared(): Promise<Y.Doc> {
  const { WebsocketProvider } = await import('y-websocket');
  const doc = new Y.Doc();
  const base = env('BTCT_LIVE_URL').replace(/^http/, 'ws');
  const p = new WebsocketProvider(`${base}/yjs`, 'btct-shared', doc, { params: { token: env('BTCT_LIVE_TOKEN'), ro: '1' }, disableBc: true });
  await new Promise<void>((resolve) => p.on('sync', (s: boolean) => { if (s) resolve(); }));
  p.destroy();
  return doc;
}

describe.skipIf(!PHASE)('live workspace archive round trip', () => {
  it.runIf(PHASE === 'seed')('seeds a workspace on the source server', async () => {
    await sharedReady();
    const { doc, tables } = getSharedDoc();
    const ws = crypto.randomUUID();
    const now = Date.now();
    const io = browserPageBodyIO();

    const folder = crypto.randomUUID();
    const assets: TypstAsset[] = [];
    for (let i = 0; i < 6; i++) {
      const up = await uploadAsset(new Blob([PNG], { type: 'image/png' }), { workspaceId: ws, kind: 'image', filename: `shot-${i}.png` });
      assets.push({ id: up.id, workspaceId: ws, kind: 'image', filename: up.filename, mime: up.mime, size: up.size, width: 1, height: 1,
        crop: i === 1 ? { x: 0, y: 0, w: 1, h: 1 } : null, blurs: i === 2 ? [{ x: 0, y: 0, w: 1, h: 1, style: 'pixelate', strength: 0.4 }] : null,
        fontFamily: null, folderId: i >= 4 ? folder : null, createdAt: now, updatedAt: now });
    }
    const pages: Page[] = [];
    for (let i = 0; i < PAGES; i++) {
      const parent = i >= 10 ? pages[i % 10]!.id : null;
      const title = i % 3 === 0 ? 'Untitled' : `Host ${i % 10}`;
      const own = assets[i % 4]!;
      pages.push({ id: crypto.randomUUID(), workspaceId: ws, parentId: parent, title, slug: '', icon: '', tags: [],
        content: `note ${i}\n\n![s](asset:${own.id})`, sortOrder: i, isGraphPage: false, createdAt: now, updatedAt: now });
    }
    doc.transact(() => {
      tables.workspaces.set(ws, { id: ws, name: 'Live QA', description: '', createdAt: now, updatedAt: now });
      tables.assetFolders.set(folder, { id: folder, workspaceId: ws, name: 'Figures', parentId: null, createdAt: now, updatedAt: now });
      for (const a of assets) tables.typstAssets.set(a.id, a);
      for (const p of pages) tables.pages.set(p.id, p);
      getSharedDoc().texts.set(`typst:${ws}:source`, new Y.Text(`#image("/assets/${assets[4]!.filename}")`));
    });
    for (let c = 0; c < CHANGES; c += 1000) {
      doc.transact(() => {
        for (let i = c; i < c + 1000; i++) tables.changeLogs.set(`${ws}-cl-${i}`, { id: `${ws}-cl-${i}`, workspaceId: ws, action: 'update', target: 'page', targetId: pages[i % PAGES]!.id, summary: `edit ${i}`, timestamp: now + i });
      });
    }
    seedMissingYTexts(getSharedDoc());

    for (const p of pages) {
      const i = pages.indexOf(p);
      const ok = await io.write(p.id, body(`body of ${p.title} ${i}`, [assets[i % 4]!.id]), 30_000);
      expect(ok).toBe(true);
    }
    const logs = Array.from({ length: LOGS }, (_, i) => ({
      id: `${ws}-cmd-${i}`, workspaceId: ws, operator: i % 2 ? 'rob' : 'eve', command: i === 0 ? '=HYPERLINK("http://x")' : `nmap -p ${i} 10.0.0.${i % 255}`,
      tool: 'nmap', startedAt: now + i, receivedAt: now, exitCode: 0,
    }));
    const res = await importCommandLogs(ws, logs);
    expect(res.imported).toBe(LOGS);
    expect(await countCommandLogArchive(ws)).toBe(LOGS);

    // Wait for the shared doc to reach the server.
    let seen = 0;
    for (let t = 0; t < 30 && seen < CHANGES; t++) {
      const s = await serverShared();
      seen = [...s.getMap('changeLogs').values()].filter((v) => (v as { workspaceId?: string }).workspaceId === ws).length;
      if (seen < CHANGES) await sleep(1000);
    }
    expect(seen).toBe(CHANGES);
    fs.writeFileSync(`${OUT}/seed.json`, JSON.stringify({ ws, pages: pages.map((p) => p.id), assets: assets.map((a) => a.id) }));
  }, 300_000);

  it.runIf(PHASE === 'export')('exports the workspace from cold rooms', async () => {
    const seed = JSON.parse(fs.readFileSync(`${OUT}/seed.json`, 'utf8')) as { ws: string };
    await sharedReady();
    await waitFor(() => getSharedDoc().tables.workspaces.has(seed.ws));
    const started = Date.now();
    const { blob, report, commandLogNote } = await exportWorkspaceFromApp(seed.ws, () => undefined);
    const ms = Date.now() - started;
    fs.writeFileSync(`${OUT}/export.zip`, new Uint8Array(await blob.arrayBuffer()));
    fs.writeFileSync(`${OUT}/export-report.json`, JSON.stringify({ ms, bytes: blob.size, report, commandLogNote }, null, 2));
    expect(report.notes).toBe(PAGES);
    expect(report.incompletePages).toEqual([]);
    expect(report.images).toBe(6);
    expect(report.failedImages).toEqual([]);
    expect(report.commandLogs).toBe(LOGS);
    expect(commandLogNote).toBeNull();
    const parsed = await parseWorkspaceZip(blob);
    expect(parsed.changeLogs).toHaveLength(CHANGES);
    // Every body came back with its block and image.
    for (const [id, b64] of Object.entries(parsed.pageYjsUpdates)) {
      const { blocks, ids } = fragmentAssetIds(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
      expect(blocks, id).toBe(2);
      expect(ids).toHaveLength(1);
    }
    expect(Object.keys(parsed.pageYjsUpdates)).toHaveLength(PAGES);
  }, 300_000);

  it.runIf(PHASE === 'import')('imports the archive as a new workspace and confirms every body', async () => {
    await sharedReady();
    const blob = new Blob([new Uint8Array(fs.readFileSync(`${OUT}/export.zip`))]);
    const parsed = await parseWorkspaceZip(blob);
    expect(parsed.problems).toEqual([]);
    const started = Date.now();
    const report = await importWorkspaceIntoApp(parsed, 'new', () => undefined);
    const ms = Date.now() - started;
    fs.writeFileSync(`${OUT}/import-report-${env('BTCT_LIVE_TAG') || 'b'}.json`, JSON.stringify({ ms, report }, null, 2));
    expect(report.bodies.unconfirmed).toEqual([]);
    expect(report.bodies.failed).toEqual([]);
    expect(report.assets.failed).toEqual([]);
    expect(report.assets.uploaded).toBe(6);
    expect(report.commandLogs?.imported).toBe(LOGS);
    // The records reached the server.
    let pages = 0;
    for (let t = 0; t < 30 && pages < PAGES; t++) {
      const s = await serverShared();
      pages = [...s.getMap('pages').values()].filter((p) => (p as Page).workspaceId === report.workspaceId).length;
      if (pages < PAGES) await sleep(1000);
    }
    expect(pages).toBe(PAGES);
  }, 300_000);

  it.runIf(PHASE === 'verify')('reads the imported workspace back from a fresh client', async () => {
    const report = JSON.parse(fs.readFileSync(`${OUT}/import-report-${env('BTCT_LIVE_TAG') || 'b'}.json`, 'utf8')).report as { workspaceId: string; sourceWorkspaceId: string };
    const s = await serverShared();
    const pages = [...s.getMap('pages').values()].map((p) => p as Page).filter((p) => p.workspaceId === report.workspaceId);
    const assets = [...s.getMap('typstAssets').values()].map((a) => a as TypstAsset).filter((a) => a.workspaceId === report.workspaceId);
    expect(pages).toHaveLength(PAGES);
    expect(assets).toHaveLength(6);
    expect(assets.some((a) => a.blurs?.length)).toBe(true);
    const assetIds = new Set(assets.map((a) => a.id));
    const byId = new Map(pages.map((p) => [p.id, p] as const));
    for (const p of pages) if (p.parentId) expect(byId.has(p.parentId)).toBe(true);
    const io = browserPageBodyIO();
    for (const p of pages) {
      const u = await io.readFromServer(p.id, 15_000);
      expect(u, p.id).not.toBeNull();
      const { blocks, ids } = fragmentAssetIds(u!);
      expect(blocks).toBe(2);
      expect(ids.every((id) => assetIds.has(id))).toBe(true);
      expect(typeof p.content === 'string' && [...p.content.matchAll(/asset:([0-9a-f-]{36})/g)].every((m) => assetIds.has(m[1]!))).toBe(true);
    }
    const base = env('BTCT_LIVE_URL');
    for (const a of assets) {
      const r = await fetch(`${base}/api/assets/${a.id}`, { headers: { Authorization: `Bearer ${env('BTCT_LIVE_TOKEN')}` } });
      expect(r.status).toBe(200);
      expect(new Uint8Array(await r.arrayBuffer())).toEqual(PNG);
    }
    expect(await countCommandLogArchive(report.workspaceId)).toBe(LOGS);
    const changes = [...s.getMap('changeLogs').values()].filter((c) => (c as { workspaceId?: string }).workspaceId === report.workspaceId);
    expect(changes).toHaveLength(CHANGES);
    if (report.sourceWorkspaceId) {
      // Import next to the original: the original still has all its pages.
      const orig = [...s.getMap('pages').values()].filter((p) => (p as Page).workspaceId === report.sourceWorkspaceId);
      if (orig.length) expect(orig).toHaveLength(PAGES);
    }
    fs.writeFileSync(`${OUT}/verify-${env('BTCT_LIVE_TAG') || 'b'}.json`, JSON.stringify({ pages: pages.length, assets: assets.length, changes: changes.length, ok: true }));
  }, 300_000);
});
