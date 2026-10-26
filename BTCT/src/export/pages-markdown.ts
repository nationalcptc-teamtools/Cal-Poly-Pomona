import JSZip from 'jszip';
import type { Page, Workspace } from '@/types';
import { sanitizeSegment, NOTE_SEGMENT_BYTES } from '@/lib/export-names';
import { buildDownloadZip, downloadZipName } from '@/lib/download-zip';
import { pageToMarkdown } from './markdown';
import { planWorkspaceExport } from './workspace-zip';

/**
 * "All Pages → Markdown": the notes alone, as the same folder tree the
 * workspace ZIP's `notes/` holds (a folder per page, children inside their
 * parent, portable names deduplicated per folder), so no two pages can land
 * on one file. One page is its `<Title>.md` alone, still in a ZIP
 * (`<Title>_<date>_md.zip`, like every download). Image links stay
 * `asset:<id>`: the workspace ZIP is the export that carries pictures.
 */
export async function pagesMarkdownArchive(
  pages: Page[],
  workspace: Pick<Workspace, 'id' | 'name'>,
  now = new Date(),
): Promise<{ blob: Blob; fileName: string; files: number }> {
  if (pages.length === 1) {
    const page = pages[0]!;
    const mdName = `${sanitizeSegment(page.title, NOTE_SEGMENT_BYTES - '.md'.length)}.md`;
    return {
      blob: await buildDownloadZip([{ name: mdName, data: pageToMarkdown(page) }], now),
      fileName: downloadZipName(page.title || 'Untitled', now, 'md'),
      files: 1,
    };
  }
  const plan = planWorkspaceExport({
    schemaVersion: 3,
    exportedAt: now.getTime(),
    workspace: { id: workspace.id, name: workspace.name, description: '', createdAt: 0, updatedAt: 0 },
    pages,
    changeLogs: [],
    nmapScans: [],
    nmapMachines: [],
    pageSnapshots: [],
    pageYjsUpdates: {},
  }, now);
  const zip = new JSZip();
  const root = zip.folder(`${plan.root}_notes`)!;
  for (const note of plan.notes) root.file(note.mdPath.replace(/^notes\//, ''), pageToMarkdown(note.page));
  const blob = await zip.generateAsync({ type: 'blob', mimeType: 'application/zip', compression: 'DEFLATE', compressionOptions: { level: 6 } });
  return { blob, fileName: `${plan.root}_notes.zip`, files: plan.notes.length };
}
