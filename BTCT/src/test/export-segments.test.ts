import { describe, expect, it } from 'vitest';
import { planWorkspaceExport, type WorkspaceExportData } from '@/export/workspace-zip';
import { NOTE_SEGMENT_BYTES, utf8Length } from '@/lib/export-names';
import type { Page, TypstAsset } from '@/types';

// QA 2026-10-12: a note title was capped at 60 bytes and then `.attachments`
// or `.md` was appended, so the archive held 72-byte segments; a long
// workspace name did the same to the root folder with its date stamp.
const now = 1_760_000_000_000;
const WS = 'ws-1';
const ASSET = '11111111-1111-4111-8111-111111111111';
const long = `${'L'.repeat(40)} very long title about the domain controller and its trusts`;

function page(id: string, title: string, parentId: string | null, content = ''): Page {
  return { id, workspaceId: WS, parentId, title, slug: '', icon: '', tags: [], content, sortOrder: 0, isGraphPage: false, createdAt: now, updatedAt: now };
}

describe('workspace export path segments', () => {
  it('keeps every segment, suffixes included, within NOTE_SEGMENT_BYTES', () => {
    const asset: TypstAsset = {
      id: ASSET, workspaceId: WS, kind: 'image', filename: `${'s'.repeat(80)}.png`, mime: 'image/png', size: 4,
      width: 2, height: 2, crop: null, blurs: null, fontFamily: null, folderId: null, createdAt: now, updatedAt: now,
    };
    const data = {
      schemaVersion: 3,
      exportedAt: now,
      workspace: { id: WS, name: 'W'.repeat(120), description: '', createdAt: now, updatedAt: now },
      pages: [
        page('p1', long, null, `![x](asset:${ASSET})`),
        page('p2', long, null),
        page('p3', `${long}.attachments`, 'p1', `![y](asset:${ASSET})`),
        page('p4', '\u{1F600}'.repeat(40), 'p3'),
      ],
      changeLogs: [], nmapScans: [], nmapMachines: [], pageSnapshots: [],
      pageYjsUpdates: {},
      assets: [asset],
      assetFolders: [],
      commandLogs: [{ id: 'c1', workspaceId: WS, operator: 'o', command: 'id', tool: 'id', startedAt: now, receivedAt: now }],
    } as unknown as WorkspaceExportData;

    const plan = planWorkspaceExport(data, new Date(2026, 9, 12, 9, 5));
    const paths = [plan.root];
    for (const n of plan.notes) {
      paths.push(`${plan.root}/${n.mdPath}`);
      for (const p of n.pictures) paths.push(`${plan.root}/${n.dir}/${p.rel}/original.png`);
    }
    const segments = paths.flatMap((p) => p.split('/'));
    const over = segments.filter((s) => utf8Length(s) > NOTE_SEGMENT_BYTES);
    expect(over).toEqual([]);
    // The two equal titles still get distinct folders.
    const dirs = plan.notes.map((n) => n.dir);
    expect(new Set(dirs).size).toBe(dirs.length);
  });
});
