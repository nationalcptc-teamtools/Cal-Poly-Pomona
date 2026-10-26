import { describe, it, expect } from 'vitest';
import JSZip from 'jszip';
import { exportWorkspaceZip, parseWorkspaceZip, type WorkspaceExportData } from '@/export';

const base = (): WorkspaceExportData => ({
  schemaVersion: 2, exportedAt: 1, workspace: { id: 'w1', name: 'W' } as WorkspaceExportData['workspace'],
  pages: [], changeLogs: [], nmapScans: [], nmapMachines: [], pageSnapshots: [], pageYjsUpdates: {},
});

describe('workspace zip: report.typ', () => {
  it('round-trips the Typst source and records it in the manifest', async () => {
    const blob = await exportWorkspaceZip({ ...base(), typstSource: '= Report\n#lorem(3)' });
    const out = await parseWorkspaceZip(blob);
    expect(out.typstSource).toBe('= Report\n#lorem(3)');

    const zip = await JSZip.loadAsync(blob);
    // Schema 3 keeps the manifest under <root>/.btct/.
    const manifest = JSON.parse(await zip.file(/\.btct\/manifest\.json$/)[0]!.async('string')) as { counts: { report: number } };
    expect(manifest.counts.report).toBe(1);
  });

  it('records a known-absent report as null (not undefined) and 0 in the manifest', async () => {
    const blob = await exportWorkspaceZip(base());
    const out = await parseWorkspaceZip(blob);
    expect(out.typstSource).toBeNull();

    const zip = await JSZip.loadAsync(blob);
    // Schema 3 keeps the manifest under <root>/.btct/.
    const manifest = JSON.parse(await zip.file(/\.btct\/manifest\.json$/)[0]!.async('string')) as { counts: { report: number } };
    expect(manifest.counts.report).toBe(0);
  });

  it('leaves typstSource undefined for an older-build zip whose manifest predates counts.report', async () => {
    const zip = new JSZip();
    zip.file('manifest.json', JSON.stringify({ schemaVersion: 2, exportedAt: 1, workspaceId: 'w1', counts: { pages: 0 } }));
    zip.file('workspace.json', JSON.stringify({ id: 'w1', name: 'W' }));
    const blob = await zip.generateAsync({ type: 'blob' });

    const out = await parseWorkspaceZip(blob);
    expect(out.typstSource).toBeUndefined();
  });

  it('leaves typstSource undefined for a zip with no manifest at all', async () => {
    const zip = new JSZip();
    zip.file('workspace.json', JSON.stringify({ id: 'w1', name: 'W' }));
    const blob = await zip.generateAsync({ type: 'blob' });

    const out = await parseWorkspaceZip(blob);
    expect(out.typstSource).toBeUndefined();
  });
});
