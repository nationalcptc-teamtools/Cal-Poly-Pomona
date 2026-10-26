import { describe, it, expect } from 'vitest';
import JSZip from 'jszip';
import {
  exportWorkspaceArchive, exportWorkspacesArchive, parseWorkspaceZip, parseWorkspaceZips, listWorkspacesInZip,
  type WorkspaceExportData, type ExportImageSource,
} from '@/export';
import { exportStatus, exportStatusMany } from '@/export/export-workspace';

const NOW = new Date(2026, 4, 3, 14, 5);

function ws(id: string, name: string, pageTitle: string, assetId: string): WorkspaceExportData {
  return {
    schemaVersion: 3, exportedAt: NOW.getTime(),
    workspace: { id, name } as WorkspaceExportData['workspace'],
    pages: [{ id: `${id}-p`, workspaceId: id, title: pageTitle, parentId: null, icon: '', tags: [], content: 'body', sortOrder: 0 } as unknown as WorkspaceExportData['pages'][number]],
    changeLogs: [], nmapScans: [], nmapMachines: [], pageSnapshots: [], pageYjsUpdates: {},
    assets: [{
      id: assetId, workspaceId: id, kind: 'image', filename: `${id}.png`, mime: 'image/png', size: 3,
    } as unknown as NonNullable<WorkspaceExportData['assets']>[number]],
  };
}

const images: ExportImageSource = {
  // The bytes encode the asset id, so a mix-up between workspaces shows.
  getOriginal: async (a) => new Uint8Array([...Buffer.from(`bytes:${a.id}`)]),
  getModified: async (_a, o) => o,
};

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const text = (b: Uint8Array | null) => (b ? Buffer.from(b).toString() : null);

describe('multi-workspace zip', () => {
  it('exports two workspaces in one zip and parses each back with its own bytes', async () => {
    const { blob, reports, fileName } = await exportWorkspacesArchive([
      { data: ws('w1', 'Alpha', 'Note A', A), opts: { images, now: NOW } },
      { data: ws('w2', 'Beta', 'Note B', B), opts: { images, now: NOW } },
    ], { now: NOW });
    expect(reports).toHaveLength(2);
    expect(fileName).toBe('btct-workspaces_2026-05-03_1405.zip');

    const parsed = await parseWorkspaceZips(blob);
    expect(parsed.map((p) => p.workspace.id).sort()).toEqual(['w1', 'w2']);
    const byId = new Map(parsed.map((p) => [p.workspace.id, p] as const));
    expect(byId.get('w1')!.pages.map((p) => p.title)).toEqual(['Note A']);
    expect(byId.get('w2')!.pages.map((p) => p.title)).toEqual(['Note B']);
    expect(text(await byId.get('w1')!.readAsset(A))).toBe(`bytes:${A}`);
    expect(text(await byId.get('w2')!.readAsset(B))).toBe(`bytes:${B}`);
    // Never the other workspace's asset.
    expect(await byId.get('w1')!.readAsset(B)).toBeNull();
    expect(await byId.get('w2')!.readAsset(A)).toBeNull();
  });

  it('gives same-named workspaces in the same minute distinct roots', async () => {
    const { blob, reports } = await exportWorkspacesArchive([
      { data: ws('w1', 'Same', 'One', A), opts: { images, now: NOW } },
      { data: ws('w2', 'Same', 'Two', B), opts: { images, now: NOW } },
    ], { now: NOW });
    expect(reports[0]!.root).not.toBe(reports[1]!.root);
    expect(reports[1]!.fileName).toBe(`${reports[1]!.root}.zip`);
    const zip = await JSZip.loadAsync(blob);
    expect(zip.file(`${reports[1]!.root}/README.md`)).not.toBeNull();
    const parsed = await parseWorkspaceZips(blob);
    expect(parsed.map((p) => p.workspace.id)).toEqual(['w1', 'w2']);
    expect(text(await parsed[1]!.readAsset(B))).toBe(`bytes:${B}`);
  });

  it('accepts an async producer', async () => {
    const seen: number[] = [];
    const { reports } = await exportWorkspacesArchive({
      count: 2,
      produce: async (i) => { seen.push(i); return { data: ws(`w${i}`, `N${i}`, 'P', i ? B : A), opts: { images, now: NOW } }; },
    }, { now: NOW });
    expect(seen).toEqual([0, 1]);
    expect(reports).toHaveLength(2);
  });

  it('a single workspace matches exportWorkspaceArchive', async () => {
    const data = ws('w1', 'Alpha', 'Note A', A);
    const one = await exportWorkspaceArchive(data, { images, now: NOW });
    const many = await exportWorkspacesArchive([{ data, opts: { images, now: NOW } }], { now: NOW });
    expect(many.fileName).toBe(one.report.fileName);
    expect(many.reports[0]!.root).toBe(one.report.root);
  });

  it('lists roots lazily: a damaged root fails alone', async () => {
    const { blob, reports } = await exportWorkspacesArchive([
      { data: ws('w1', 'Alpha', 'Note A', A), opts: { images, now: NOW } },
      { data: ws('w2', 'Beta', 'Note B', B), opts: { images, now: NOW } },
    ], { now: NOW });
    const zip = await JSZip.loadAsync(blob);
    zip.file(`${reports[1]!.root}/.btct/pages.json`, '[{"id":');
    const damaged = await zip.generateAsync({ type: 'blob' });

    const entries = await listWorkspacesInZip(damaged);
    expect(entries.map((e) => e.root)).toEqual([reports[0]!.root, reports[1]!.root]);
    expect((await entries[0]!.parse()).workspace.id).toBe('w1');
    await expect(entries[1]!.parse()).rejects.toThrow(/pages\.json/);
    await expect(parseWorkspaceZips(damaged)).rejects.toThrow();
  });

  it('parseWorkspaceZips returns exactly one for a single schema-3 archive', async () => {
    const { blob } = await exportWorkspaceArchive(ws('w1', 'Alpha', 'Note A', A), { images, now: NOW });
    const all = await parseWorkspaceZips(blob);
    expect(all).toHaveLength(1);
    expect(all[0]!.workspace.id).toBe('w1');
    expect((await parseWorkspaceZip(blob)).workspace.id).toBe('w1');
  });

  it('parseWorkspaceZips returns exactly one for a flat schema-2 archive', async () => {
    const zip = new JSZip();
    zip.file('manifest.json', JSON.stringify({ schemaVersion: 2, exportedAt: 1, workspaceId: 'w9' }));
    zip.file('workspace.json', JSON.stringify({ id: 'w9', name: 'Old' }));
    zip.file('pages.json', '[]');
    const all = await parseWorkspaceZips(await zip.generateAsync({ type: 'blob' }));
    expect(all).toHaveLength(1);
    expect(all[0]!.sourceSchema).toBe(2);
    expect(all[0]!.workspace.id).toBe('w9');
  });
});

describe('exportStatusMany', () => {
  it('equals exportStatus for one report', async () => {
    const { report } = await exportWorkspaceArchive(ws('w1', 'Alpha', 'Note A', A), { images, now: NOW });
    expect(exportStatusMany([report], [null])).toBe(exportStatus(report, null));
    expect(exportStatusMany([report], ['partial'])).toBe(exportStatus(report, 'partial'));
  });

  it('sums across workspaces and lists issues per workspace', async () => {
    const { reports } = await exportWorkspacesArchive([
      { data: ws('w1', 'Alpha', 'Note A', A), opts: { images, now: NOW } },
      { data: ws('w2', 'Beta', 'Note B', B), opts: { images, now: NOW } },
    ], { now: NOW });
    const clean = exportStatusMany(reports, [null, null]);
    expect(clean).toBe('Exported 2 workspaces: 2 notes and 2 images.');
    const withIssue = exportStatusMany(reports, [null, 'x']);
    expect(withIssue.split('\n')).toHaveLength(2);
    expect(withIssue).toContain(`${reports[1]!.root}: the command log is partial`);
  });
});
