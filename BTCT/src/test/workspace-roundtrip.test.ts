// Round trip of the workspace archive through the real shared doc: gather,
// export (schema 3), parse, import as new and replace. The network is faked
// at its three seams: page bodies (a Map of server rooms), asset bytes and
// uploads (a Map of server blobs) and the command-log routes.
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import JSZip from 'jszip';
import * as Y from 'yjs';

vi.mock('@/auth/auth-store', () => ({
  API_URL: 'http://test.invalid',
  WS_URL: 'ws://test.invalid',
  useAuthStore: { getState: () => ({ token: 'test', user: null }), subscribe: () => () => {} },
  probeSession: async () => 'ok',
}));
vi.mock('y-indexeddb', () => ({
  IndexeddbPersistence: class { whenSynced = Promise.resolve(this); db = null; on() {} off() {} destroy() { return Promise.resolve(); } },
}));
vi.mock('y-websocket', async () => {
  const { Awareness } = await import('y-protocols/awareness');
  return { WebsocketProvider: class {
    awareness; synced = true;
    constructor(_u: string, _r: string, doc: Y.Doc) { this.awareness = new Awareness(doc); }
    on() {} off() {} destroy() {} disconnect() {} connect() {}
  } };
});

// ── fake server ──
const rooms = new Map<string, Y.Doc>();
const blobs = new Map<string, { bytes: Uint8Array; filename: string; workspaceId: string }>();
const cmdlogs: Array<Record<string, unknown>> = [];
const imported: Array<{ workspaceId: string; rows: Array<Record<string, unknown>> }> = [];
let uploads = 0;

vi.mock('@/export/page-bodies', async () => {
  const Yjs = await import('yjs');
  return {
    browserPageBodyIO: () => ({
      readFromServer: async (id: string) => Yjs.encodeStateAsUpdate(rooms.get(id) ?? new Yjs.Doc()),
      readLocal: async () => null,
      write: async (id: string, update: Uint8Array) => {
        const doc = rooms.get(id) ?? new Yjs.Doc();
        rooms.set(id, doc);
        Yjs.applyUpdate(doc, update);
        return true;
      },
    }),
  };
});
vi.mock('@/export/cmdlog-io', () => ({
  fetchCommandLogArchive: async (ws: string) => cmdlogs.filter((r) => r.workspaceId === ws),
  importCommandLogs: async (workspaceId: string, rows: Array<Record<string, unknown>>) => {
    imported.push({ workspaceId, rows });
    return { imported: rows.length, remapped: 0, skipped: 0 };
  },
}));
vi.mock('@/lib/assets', async (orig) => ({
  ...(await orig<typeof import('@/lib/assets')>()),
  fetchAssetBytesUncached: async (id: string) => {
    const b = blobs.get(id);
    if (!b) throw new Error('asset not found');
    return b.bytes;
  },
  // A stand-in render: blurred assets come back reversed, so the test can
  // tell modified from original without a canvas.
  renderAssetBytes: async (asset: { blurs?: unknown[] | null }, raw: Uint8Array) =>
    (asset.blurs?.length ? raw.slice().reverse() : raw),
  uploadAsset: async (file: Blob, opts: { workspaceId: string; filename: string }) => {
    uploads++;
    const id = crypto.randomUUID();
    // The server corrects a mislabelled extension.
    const filename = opts.filename === 'b.jpg' ? 'b.png' : opts.filename;
    const bytes = new Uint8Array(await file.arrayBuffer());
    blobs.set(id, { bytes, filename, workspaceId: opts.workspaceId });
    return { id, workspaceId: opts.workspaceId, kind: 'image', filename, mime: 'image/png', size: bytes.length };
  },
}));

import { getSharedDoc, seedMissingYTexts, setYTextValue, textKey } from '@/realtime/shared-doc';
import { exportWorkspaceFromApp, importWorkspaceIntoApp } from '@/export/export-workspace';
import { parseWorkspaceZip } from '@/export/workspace-zip';
import { importWorkspace } from '@/export/import-workspace';
import type { ChangeLogEntry, Page, TypstAsset } from '@/types';
import { disposeAllPageDocs } from '@/realtime/yjs-providers';

const WS = '11111111-0000-4000-8000-000000000000';
const uuid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const A = uuid(1); // blurred png in folder F2, in Host 0's markdown twice
const B = uuid(2); // mislabelled jpg, in Host 0's markdown
const C = uuid(3); // only in Deep's Yjs body
const D = uuid(4); // font, unreferenced, in F1
const E = uuid(5); // retired and unreferenced: does not travel
const G = uuid(6); // retired but referenced: travels
const now = 1_760_000_000_000;

function page(id: string, title: string, parentId: string | null, content = '', sortOrder = 0): Page {
  return { id, workspaceId: WS, parentId, title, slug: '', icon: '', tags: [], content, sortOrder, isGraphPage: false, createdAt: now, updatedAt: now };
}
function asset(id: string, filename: string, extra: Partial<TypstAsset> = {}): TypstAsset {
  return { id, workspaceId: WS, kind: 'image', filename, mime: 'image/png', size: 4, width: 2, height: 2, crop: null, blurs: null, fontFamily: null, folderId: null, createdAt: now, updatedAt: now, ...extra };
}
function bodyWith(text: string, assetIds: string[] = []): Y.Doc {
  const doc = new Y.Doc();
  const p = new Y.XmlElement('paragraph');
  p.insert(0, [new Y.XmlText(text)]);
  const imgs = assetIds.map((id) => { const el = new Y.XmlElement('asset_image'); el.setAttribute('assetId', id); return el; });
  doc.getXmlFragment('prosemirror').insert(0, [p, ...imgs]);
  return doc;
}
function assetIdsInRoom(id: string): string[] {
  const doc = rooms.get(id);
  if (!doc) return [];
  return [...doc.getXmlFragment('prosemirror').createTreeWalker((n) => n instanceof Y.XmlElement && n.nodeName === 'asset_image')]
    .map((n) => (n as Y.XmlElement).getAttribute('assetId') as string);
}
function rows<T>(table: string, pred: (r: T) => boolean): T[] {
  return [...getSharedDoc().doc.getMap<T>(table).values()].filter(pred);
}

const P_HOST = uuid(100), P_UNT1 = uuid(101), P_UNT2 = uuid(102), P_CHILD = uuid(103), P_DEEP = uuid(104),
  P_ATT = uuid(105), P_COLD = uuid(106), P_DEV = uuid(107), P_LOOP1 = uuid(108), P_LOOP2 = uuid(109);

let archive: Blob;
let exportPaths: string[] = [];

beforeAll(() => {
  const { doc, tables } = getSharedDoc();
  doc.transact(() => {
    tables.workspaces.set(WS, { id: WS, name: 'CPTC Team5', description: '', createdAt: now, updatedAt: now });
    for (const p of [
      page(P_HOST, 'Host 0', null, `# Recon\n![shot](asset:${A}) ![b](asset:${B}) ![again](asset:${A}) ![gone](asset:${G}) ![nope](asset:${uuid(999)})`, 1),
      page(P_UNT1, 'Untitled', null, 'one', 2),
      page(P_UNT2, 'untitled', null, 'two', 3),
      page(P_CHILD, 'Host 0.attachments', P_HOST, 'child named like the attachments folder'),
      page(P_DEEP, 'Deep', P_CHILD, 'deep body'),
      page(P_ATT, 'a/b\\c:d*e?f"g<h>i|j%k\u0007', null, 'odd'),
      page(P_COLD, 'Cold', null, 'markdown that the server body lacks'),
      page(P_DEV, 'CON', null, ''),
      page(P_LOOP1, 'Loop 1', P_LOOP2, ''),
      page(P_LOOP2, 'Loop 2', P_LOOP1, ''),
    ]) tables.pages.set(p.id, p);
    tables.assetFolders.set('f1', { id: 'f1', workspaceId: WS, name: 'Report figures', parentId: null, createdAt: now, updatedAt: now });
    tables.assetFolders.set('f2', { id: 'f2', workspaceId: WS, name: 'Web', parentId: 'f1', createdAt: now + 1, updatedAt: now });
    tables.typstAssets.set(A, asset(A, 'a.png', { folderId: 'f2', blurs: [{ x: 0, y: 0, w: 0.5, h: 0.5, style: 'pixelate', strength: 0.4 }], crop: { x: 0, y: 0, w: 1, h: 1 } }));
    tables.typstAssets.set(B, asset(B, 'b.jpg', { mime: 'image/jpeg' }));
    tables.typstAssets.set(C, asset(C, 'c.png'));
    tables.typstAssets.set(D, asset(D, 'Inter Bold.ttf', { kind: 'font', mime: 'font/ttf', fontFamily: 'Inter', folderId: 'f1' }));
    tables.typstAssets.set(E, asset(E, 'e.png', { deletedAt: now }));
    tables.typstAssets.set(G, asset(G, 'g.png', { deletedAt: now }));
    // 6000 change-log rows: the old export kept the newest 5000.
    for (let i = 0; i < 6000; i++) {
      tables.changeLogs.set(`cl-${i}`, { id: `cl-${i}`, workspaceId: WS, action: 'update', target: 'page', targetId: P_HOST, summary: `edit ${i}`, timestamp: now + i } as ChangeLogEntry);
    }
    tables.changeLogs.set('cl-del', {
      id: 'cl-del', workspaceId: WS, action: 'delete', target: 'page', targetId: uuid(200), summary: 'Deleted page', timestamp: now,
      prevValue: JSON.stringify(page(uuid(200), 'Deleted one', P_HOST, `![x](asset:${A})`)), reversible: true,
    } as ChangeLogEntry);
    // The page-tree delete snapshot the client logs since the client-stream fix.
    tables.changeLogs.set('cl-deltree', {
      id: 'cl-deltree', workspaceId: WS, action: 'delete', target: 'page', targetId: uuid(201), summary: 'Deleted page tree', timestamp: now,
      prevValue: JSON.stringify({ kind: 'pageTree', version: 1, pages: [
        page(uuid(201), 'Deleted parent', P_HOST, `![y](asset:${A})`),
        page(uuid(202), 'Deleted child', uuid(201), ''),
      ] }), reversible: true,
    } as ChangeLogEntry);
    tables.nmapScans.set('scan-1', { id: 'scan-1', workspaceId: WS, name: 'Internal', importedAt: now });
    tables.nmapMachines.set('m-1', { id: 'm-1', scanId: 'scan-1', ip: '10.0.0.5', hostname: 'dc01', os: 'windows', ports: [], linkedNodeId: 'node-1', createdAt: now, updatedAt: now });
    tables.pageSnapshots.set('snap-1', { id: 'snap-1', pageId: P_HOST, workspaceId: WS, timestamp: now, updateBase64: '', byteLength: 0 });
    doc.getMap('graphs').set('g-1', { id: 'g-1', workspaceId: WS, name: 'Old graph' });
    doc.getMap('graphNodes').set('node-1', { id: 'node-1', graphId: 'g-1', linkedPageId: P_HOST });
    getSharedDoc().texts.set(textKey('typst', WS, 'source'), new Y.Text('#image("/assets/a.png")\n#image("/assets/b.jpg")\n#image("/assets/b.jpgx")'));
  });
  seedMissingYTexts(getSharedDoc());
  for (const [id, bytes] of [[A, [1, 2, 3, 4]], [B, [5, 6, 7, 8]], [C, [9, 9, 9, 9]], [D, [0, 1, 0, 0]], [E, [7, 7]], [G, [6, 6]]] as const) {
    blobs.set(id, { bytes: new Uint8Array(bytes), filename: 'x', workspaceId: WS });
  }
  rooms.set(P_HOST, bodyWith('host body', [A, B, A, G]));
  rooms.set(P_DEEP, bodyWith('deep body', [C]));
  rooms.set(P_UNT1, bodyWith('one'));
  rooms.set(P_UNT2, bodyWith('two'));
  rooms.set(P_CHILD, bodyWith('child'));
  rooms.set(P_ATT, bodyWith('odd'));
  // P_COLD has markdown but its room is empty: the export must say so.
  cmdlogs.push(
    { id: 'c1', workspaceId: WS, operator: 'rob', command: '=HYPERLINK("http://x")', tool: 'curl', startedAt: now, receivedAt: now, exitCode: 0 },
    { id: 'c2', workspaceId: WS, operator: 'rob', command: 'nmap -sV 10.0.0.5', tool: 'nmap', startedAt: now + 1, receivedAt: now, exitCode: 0 },
    { id: 'c3', workspaceId: 'other', operator: 'eve', command: 'id', tool: 'id', startedAt: now, receivedAt: now },
  );
});

afterAll(() => { disposeAllPageDocs(); });

describe('workspace archive round trip', () => {
  it('exports a browsable tree with every note, picture and table', async () => {
    const { blob, report } = await exportWorkspaceFromApp(WS, () => undefined);
    archive = blob;
    const zip = await JSZip.loadAsync(blob);
    exportPaths = Object.keys(zip.files).filter((p) => !zip.files[p]!.dir).sort();
    const root = report.root;
    expect(root).toMatch(/^CPTC Team5_\d{4}-\d{2}-\d{2}_\d{4}$/);
    expect(exportPaths.every((p) => p.startsWith(`${root}/`))).toBe(true);
    const rel = exportPaths.map((p) => p.slice(root.length + 1));

    // One markdown file per page, none lost to a name collision.
    const md = rel.filter((p) => p.startsWith('notes/') && p.endsWith('.md'));
    expect(md).toHaveLength(10);
    expect(rel).toContain('notes/Host 0/Host 0.md');
    expect(rel).toContain('notes/Untitled/Untitled.md');
    expect(rel).toContain('notes/untitled-2/untitled-2.md');
    expect(rel).toContain('notes/Host 0/Host 0.attachments-2/Host 0.attachments-2.md');
    expect(rel).toContain('notes/Host 0/Host 0.attachments-2/Deep/Deep.md');
    expect(rel).toContain('notes/CON_/CON_.md');
    expect(rel).toContain('notes/a_b_c_d_e_f_g_h_i_j_k_/a_b_c_d_e_f_g_h_i_j_k_.md');
    expect(rel).toContain('notes/Command log.csv');

    // Pictures in note order, both files each; the same image twice is one folder.
    expect(rel).toContain('notes/Host 0/Host 0.attachments/01-a/modified.png');
    expect(rel).toContain('notes/Host 0/Host 0.attachments/01-a/original.png');
    expect(rel).toContain('notes/Host 0/Host 0.attachments/02-b/original.jpg');
    expect(rel).toContain('notes/Host 0/Host 0.attachments/03-g/original.png');
    expect(rel).toContain('notes/Host 0/Host 0.attachments-2/Deep/Deep.attachments/01-c/modified.png');
    expect(rel.filter((p) => p.includes('/01-a/'))).toHaveLength(2);
    // Unreferenced ones under their folder; a retired, unreferenced one not at all.
    expect(rel).toContain('assets/Report figures/Inter Bold.ttf');
    expect(rel.some((p) => p.includes('/e/') || p.endsWith('e.png'))).toBe(false);

    // Modified carries the blur, original is the upload.
    const modified = await zip.file(`${root}/notes/Host 0/Host 0.attachments/01-a/modified.png`)!.async('uint8array');
    const original = await zip.file(`${root}/notes/Host 0/Host 0.attachments/01-a/original.png`)!.async('uint8array');
    expect([...original]).toEqual([1, 2, 3, 4]);
    expect([...modified]).toEqual([4, 3, 2, 1]);

    // Links point at the modified picture; an unknown id stays as written.
    const hostMd = await zip.file(`${root}/notes/Host 0/Host 0.md`)!.async('string');
    expect(hostMd).toContain('![shot](Host%200.attachments/01-a/modified.png)');
    expect(hostMd).toContain(`![nope](asset:${uuid(999)})`);

    // Text deflated, pictures stored.
    const method = (p: string) => (zip.files[`${root}/${p}`] as unknown as { _data: { compression: { magic: string } } })._data.compression.magic;
    expect(method('.btct/pages.json')).toBe('\u0008\u0000');
    expect(method('notes/Host 0/Host 0.attachments/01-a/original.png')).toBe('\u0000\u0000');

    // Honest report and README.
    expect(report.notes).toBe(10);
    expect(report.images).toBe(4);
    expect(report.fonts).toBe(1);
    expect(report.incompletePages.map((p) => p.pageId)).toEqual([P_COLD]);
    expect(report.missingImages.map((m) => m.assetId)).toEqual([uuid(999)]);
    const readme = await zip.file(`${root}/README.md`)!.async('string');
    expect(readme).toContain('## Possibly incomplete pages');
    expect(readme).toContain('Cold');
    expect(readme).toContain('unredacted');

    // CSV guards formulas; the command log is the workspace's only.
    const csv = await zip.file(`${root}/notes/Command log.csv`)!.async('string');
    expect(csv).toContain(`"'=HYPERLINK(""http://x"")"`);
    expect(csv).not.toContain('eve');

    const manifest = JSON.parse(await zip.file(`${root}/.btct/manifest.json`)!.async('string'));
    expect(manifest.schemaVersion).toBe(3);
    expect(manifest.counts.changeLogs).toBe(6002);
    expect(manifest.counts.assets).toBe(5);
  });

  it('imports as new with fresh ids everywhere and leaves the original alone', async () => {
    const before = JSON.stringify(rows<Page>('pages', (p) => p.workspaceId === WS).sort((a, b) => a.id.localeCompare(b.id)));
    const roomCountBefore = rooms.size;
    const parsed = await parseWorkspaceZip(archive);
    expect(parsed.sourceSchema).toBe(3);
    expect(parsed.problems).toEqual([]);
    expect(parsed.changeLogs).toHaveLength(6002);

    let updates = 0;
    const onUpdate = () => { updates++; };
    getSharedDoc().doc.on('update', onUpdate);
    const report = await importWorkspaceIntoApp(parsed, 'new', () => undefined);
    getSharedDoc().doc.off('update', onUpdate);

    const nws = report.workspaceId;
    expect(nws).not.toBe(WS);
    expect(JSON.stringify(rows<Page>('pages', (p) => p.workspaceId === WS).sort((a, b) => a.id.localeCompare(b.id)))).toBe(before);

    const copies = rows<Page>('pages', (p) => p.workspaceId === nws);
    expect(copies).toHaveLength(10);
    const origIds = new Set([P_HOST, P_UNT1, P_UNT2, P_CHILD, P_DEEP, P_ATT, P_COLD, P_DEV, P_LOOP1, P_LOOP2]);
    expect(copies.some((p) => origIds.has(p.id))).toBe(false);
    const byTitle = new Map(copies.map((p) => [p.title, p] as const));
    const host = byTitle.get('Host 0')!;
    expect(byTitle.get('Host 0.attachments')!.parentId).toBe(host.id);
    expect(byTitle.get('Deep')!.parentId).toBe(byTitle.get('Host 0.attachments')!.id);

    // Assets: uploaded under new ids, framing kept, retired flag cleared, folders remapped.
    const newAssets = rows<TypstAsset>('typstAssets', (a) => a.workspaceId === nws);
    expect(newAssets).toHaveLength(5);
    const newA = newAssets.find((a) => a.filename === 'a.png')!;
    expect(newA.id).not.toBe(A);
    expect(newA.blurs).toHaveLength(1);
    expect(newA.deletedAt).toBeNull();
    const folders = rows<{ id: string; name: string; parentId: string | null; workspaceId: string }>('assetFolders', (f) => f.workspaceId === nws);
    const web = folders.find((f) => f.name === 'Web')!;
    expect(newA.folderId).toBe(web.id);
    expect(folders.find((f) => f.id === web.parentId)!.name).toBe('Report figures');
    expect(newAssets.find((a) => a.filename === 'b.png')).toBeTruthy();

    // Bodies went to the NEW rooms with asset ids rewritten; the old rooms are untouched.
    expect(rooms.size).toBeGreaterThan(roomCountBefore);
    expect(assetIdsInRoom(host.id)).toEqual([newA.id, newAssets.find((a) => a.filename === 'b.png')!.id, newA.id, newAssets.find((a) => a.filename === 'g.png')!.id]);
    expect(assetIdsInRoom(P_HOST)).toEqual([A, B, A, G]);
    expect(host.content).toContain(`asset:${newA.id}`);
    expect(host.content).not.toContain(`asset:${A}`);
    expect(report.bodies.unconfirmed).toEqual([]);

    // References in every table follow the new ids.
    const logs = rows<ChangeLogEntry>('changeLogs', (c) => c.workspaceId === nws);
    expect(logs).toHaveLength(6002);
    expect(logs.filter((c) => c.targetId === host.id)).toHaveLength(6000);
    const del = logs.find((c) => c.action === 'delete' && c.summary === 'Deleted page')!;
    expect(JSON.parse(del.prevValue!).id).toBe(del.targetId);
    expect(JSON.parse(del.prevValue!).workspaceId).toBe(nws);
    const delTree = logs.find((c) => c.summary === 'Deleted page tree')!;
    const tree = JSON.parse(delTree.prevValue!) as { kind: string; pages: Page[] };
    expect(tree.kind).toBe('pageTree');
    expect(tree.pages[0]!.id).toBe(delTree.targetId);
    expect(tree.pages[0]!.id).not.toBe(uuid(201));
    expect(tree.pages[0]!.parentId).toBe(host.id);
    expect(tree.pages[1]!.parentId).toBe(tree.pages[0]!.id);
    expect(tree.pages.every((p) => p.workspaceId === nws)).toBe(true);
    expect(tree.pages[0]!.content).toContain(`asset:${newA.id}`);
    const scan = rows<{ id: string; workspaceId: string }>('nmapScans', (s) => s.workspaceId === nws)[0]!;
    const machine = rows<{ scanId: string; linkedNodeId: string }>('nmapMachines', (m) => m.scanId === scan.id)[0]!;
    const node = rows<{ id: string; linkedPageId: string }>('graphNodes', (n) => n.id === machine.linkedNodeId)[0]!;
    expect(node.linkedPageId).toBe(host.id);
    expect(rows<{ pageId: string }>('pageSnapshots', (s) => s.pageId === host.id)).toHaveLength(1);

    // Report source follows the renamed file, and only the exact name.
    const src = getSharedDoc().texts.get(textKey('typst', nws, 'source'))!.toString();
    expect(src).toContain('/assets/b.png"');
    expect(src).toContain('/assets/b.jpgx');
    expect(report.renamedFiles).toEqual([{ from: 'b.jpg', to: 'b.png' }]);

    // Command log went to the server under the new workspace.
    expect(imported.at(-1)!.workspaceId).toBe(nws);
    expect(imported.at(-1)!.rows.map((r) => r.id).sort()).toEqual(['c1', 'c2']);

    // Titles are editable Y.Texts, and the records came in chunks, not one transaction each.
    expect(getSharedDoc().texts.get(textKey('page', host.id, 'title'))!.toString()).toBe('Host 0');
    expect(updates).toBeLessThan(40);
  });

  it('replace keeps surviving pages in place, removes extras and brings deleted ones back', async () => {
    const { tables } = getSharedDoc();
    // After the export: P renamed, Q deleted, R created.
    setYTextValue('page', P_UNT1, 'title', 'Renamed');
    tables.pages.set(P_UNT1, { ...(tables.pages.get(P_UNT1) as Page), title: 'Renamed' });
    tables.pages.delete(P_DEV);
    const R = uuid(300);
    tables.pages.set(R, page(R, 'Created later', null, 'new'));
    const uploadsBefore = uploads;

    const deletedIds: string[] = [];
    const watch = (e: Y.YMapEvent<unknown>) => { for (const [k, ch] of e.changes.keys) if (ch.action === 'delete') deletedIds.push(k); };
    tables.pages.observe(watch);
    const report = await importWorkspace(await parseWorkspaceZip(archive), 'replace', {
      bodies: { readFromServer: async () => null, readLocal: async () => null, write: async () => true },
      uploadAsset: async () => { throw new Error('should reuse'); },
      importCommandLogs: async (_ws, r) => ({ imported: r.length, remapped: 0, skipped: 0 }),
    });
    tables.pages.unobserve(watch);

    expect(report.replacedExisting).toBe(true);
    expect(deletedIds).toEqual([R]);
    expect(tables.pages.get(P_DEV)).toBeTruthy();
    expect(tables.pages.get(R)).toBeUndefined();
    expect((tables.pages.get(P_UNT1) as Page).title).toBe('Untitled');
    expect(getSharedDoc().texts.get(textKey('page', P_UNT1, 'title'))!.toString()).toBe('Untitled');
    expect(uploads).toBe(uploadsBefore);
    expect(report.assets.reused).toBe(5);
    expect(rows<Page>('pages', (p) => p.workspaceId === WS)).toHaveLength(10);
  });

  it('still imports schema 2 and schema 1 archives', async () => {
    const v2 = new JSZip();
    v2.file('manifest.json', JSON.stringify({ schemaVersion: 2, counts: { report: 0, pageYjsUpdates: 1 } }));
    v2.file('workspace.json', JSON.stringify({ id: 'v2-ws', name: 'Old' }));
    v2.file('pages.json', JSON.stringify([{ ...page('v2-p', 'Old page', null, 'x'), workspaceId: 'v2-ws' }]));
    v2.file('pageYjsUpdates.json', JSON.stringify({ 'v2-p': '' }));
    const p2 = await parseWorkspaceZip(await v2.generateAsync({ type: 'blob' }));
    expect(p2.sourceSchema).toBe(2);
    expect(p2.pages).toHaveLength(1);
    expect(p2.typstSource).toBeNull();

    const v1 = new JSZip();
    v1.file('workspace.json', JSON.stringify({ id: 'v1-ws', name: 'Older' }));
    v1.file('pages/_index.json', JSON.stringify([{ ...page('v1-p', 'Older page', null, 'y'), workspaceId: 'v1-ws' }]));
    v1.file('graphs/_index.json', JSON.stringify([{ id: 'gg', workspaceId: 'v1-ws' }]));
    v1.file('graphs/gg/nodes.json', JSON.stringify([{ id: 'nn', graphId: 'gg' }]));
    const p1 = await parseWorkspaceZip(await v1.generateAsync({ type: 'blob' }));
    expect(p1.sourceSchema).toBe(1);
    expect(p1.retired!.graphNodes).toHaveLength(1);
    const report = await importWorkspace(p1, 'new', {
      bodies: { readFromServer: async () => null, readLocal: async () => null, write: async () => true },
      uploadAsset: async () => { throw new Error('none'); },
      importCommandLogs: async () => ({ imported: 0, remapped: 0, skipped: 0 }),
    });
    expect(rows<Page>('pages', (p) => p.workspaceId === report.workspaceId).map((p) => p.title)).toEqual(['Older page']);
  });

  it('surfaces damaged archives instead of importing them silently', async () => {
    const bytes = new Uint8Array(await archive.arrayBuffer());
    await expect(parseWorkspaceZip(new Blob([bytes.slice(0, bytes.length - 1024)]))).rejects.toThrow(/Invalid workspace zip/);

    const zip = await JSZip.loadAsync(archive);
    const root = Object.keys(zip.files)[0]!.split('/')[0];
    zip.file(`${root}/.btct/pageYjsUpdates.json`, '{"truncated": ');
    const damaged = await parseWorkspaceZip(await zip.generateAsync({ type: 'blob' }));
    expect(damaged.problems.join(' ')).toMatch(/pageYjsUpdates\.json is damaged/);

    const notBtct = new JSZip();
    notBtct.file('hello.txt', 'hi');
    await expect(parseWorkspaceZip(await notBtct.generateAsync({ type: 'blob' }))).rejects.toThrow('Invalid workspace zip: missing workspace.json');
  });
});
