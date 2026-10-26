import { db, pageRepo, workspaceRepo } from '@/db';
import { getSharedDoc, textKey } from '@/realtime/shared-doc';
import { fetchAssetBytesUncached, renderAssetBytes, uploadAsset } from '@/lib/assets';
import type { CommandLogEntry, NmapMachine } from '@/types';
import { collectRetired } from './retired';
import {
  exportWorkspaceArchive, exportWorkspacesArchive,
  type ExportReport, type ParsedWorkspaceZip, type WorkspaceExportData, type IncompletePage, type ExportImageSource,
} from './workspace-zip';
import { browserPageBodyIO } from './page-bodies';
import { readPageBodies } from './body-sync';
import { fetchCommandLogArchive, importCommandLogs } from './cmdlog-io';
import { importWorkspace, type ImportMode, type ImportReport } from './import-workspace';

// ─────────────────────────────────────────────────────────────────────────
// The browser side of the workspace export and import: gather from the
// shared doc and the server, then hand the pure layers their data. Kept out
// of ExportDialog so the dialog is only buttons and a status line.
// ─────────────────────────────────────────────────────────────────────────

/** A gathered workspace plus the export options that came out of gathering it. */
export interface GatheredWorkspace {
  data: WorkspaceExportData;
  incompletePages: IncompletePage[];
  commandLogNote: string | null;
}

/** Read one workspace from the local DB, the shared doc and the server. */
export async function gatherWorkspaceExport(
  workspaceId: string,
  onProgress: (message: string) => void,
): Promise<GatheredWorkspace> {
  const workspace = await workspaceRepo.getById(workspaceId);
  if (!workspace) throw new Error('Active workspace missing in DB');

  onProgress('Gathering workspace…');
  const pages = await pageRepo.getByWorkspace(workspaceId, true);
  // Uncapped: a "lossless" export used to stop at the newest 5000 entries.
  const changeLogs = (await db.changeLogs.where('workspaceId').equals(workspaceId).toArray())
    .sort((a, b) => a.timestamp - b.timestamp);
  const nmapScans = await db.nmapScans.where('workspaceId').equals(workspaceId).toArray();
  const scanIds = new Set(nmapScans.map((s) => s.id));
  const nmapMachines: NmapMachine[] = (await db.nmapMachines.toArray()).filter((m) => scanIds.has(m.scanId));
  // One scan, not one per page.
  const pageSnapshots = await db.pageSnapshots.where('workspaceId').equals(workspaceId).toArray();
  const assets = await db.typstAssets.where('workspaceId').equals(workspaceId).toArray();
  const assetFolders = await db.assetFolders.where('workspaceId').equals(workspaceId).toArray();

  let commandLogs: CommandLogEntry[] = [];
  let commandLogNote: string | null = null;
  onProgress('Reading the command log…');
  try {
    commandLogs = await fetchCommandLogArchive(workspaceId);
  } catch (e) {
    // The live window is better than nothing, but say that it is partial.
    commandLogs = await db.commandLogs.where('workspaceId').equals(workspaceId).toArray();
    commandLogNote = `The server's command-log archive could not be read (${e instanceof Error ? e.message : String(e)}); only the ${commandLogs.length} entries of the live window are included.`;
  }

  onProgress(`Reading page bodies (0/${pages.length})…`);
  const { updates, incomplete } = await readPageBodies(pages, browserPageBodyIO(), {
    onProgress: (n, total) => onProgress(`Reading page bodies (${n}/${total})…`),
  });

  return {
    data: {
      schemaVersion: 3,
      exportedAt: Date.now(),
      workspace,
      pages,
      changeLogs,
      nmapScans,
      nmapMachines,
      pageSnapshots,
      pageYjsUpdates: updates,
      retired: collectRetired(workspaceId),
      // Direct `.get`, not getOrInitYText: creating the Y.Text here would
      // seed an empty report in every exported workspace.
      typstSource: getSharedDoc().texts.get(textKey('typst', workspaceId, 'source'))?.toString() ?? null,
      assets,
      assetFolders,
      commandLogs,
    },
    incompletePages: incomplete,
    commandLogNote,
  };
}

const imageSource: ExportImageSource = {
  getOriginal: (asset) => fetchAssetBytesUncached(asset.id),
  getModified: (asset, original) => renderAssetBytes(asset, original),
};

/** Gather a workspace and build its archive. */
export async function exportWorkspaceFromApp(
  workspaceId: string,
  onProgress: (message: string) => void,
): Promise<{ blob: Blob; report: ExportReport; commandLogNote: string | null }> {
  const { data, incompletePages, commandLogNote } = await gatherWorkspaceExport(workspaceId, onProgress);
  const { blob, report } = await exportWorkspaceArchive(data, {
    images: imageSource,
    incompletePages,
    commandLogNote,
    onProgress,
  });
  return { blob, report, commandLogNote };
}

/**
 * Gather and archive several workspaces into ONE ZIP, one workspace at a
 * time. Progress messages are prefixed with the workspace name and (i/n).
 * `notes[i]` is report i's command-log note. With 2+ workspaces one that fails
 * to gather is skipped and listed in `failed`; if all fail this throws.
 */
export async function exportWorkspacesFromApp(
  workspaceIds: string[],
  onProgress: (message: string) => void,
): Promise<{ blob: Blob; reports: ExportReport[]; fileName: string; notes: Array<string | null>; failed: Array<{ name: string; error: string }> }> {
  const notes: Array<string | null> = [];
  const failed: Array<{ name: string; error: string }> = [];
  const total = workspaceIds.length;
  const { blob, reports, fileName } = await exportWorkspacesArchive({
    count: total,
    produce: async (i) => {
      const id = workspaceIds[i]!;
      const known = (await workspaceRepo.getById(id))?.name ?? 'Workspace';
      try {
      const prefix = total > 1 ? `${known} (${i + 1}/${total}): ` : '';
      const say = (m: string) => onProgress(`${prefix}${m}`);
      const { data, incompletePages, commandLogNote } = await gatherWorkspaceExport(id, say);
      notes.push(commandLogNote);
      return { data, opts: { images: imageSource, incompletePages, commandLogNote, onProgress: say } };
      } catch (e) {
        // One workspace failing to gather must not sink the rest.
        if (total === 1) throw e;
        failed.push({ name: known, error: e instanceof Error ? e.message : String(e) });
        return null;
      }
    },
  }, { onProgress });
  return { blob, reports, fileName, notes, failed };
}

/** The status line for an export, naming everything that did not make it. */
export function exportStatus(r: ExportReport, commandLogNote: string | null): string {
  let s = `Exported ${r.notes} notes and ${r.images} images${r.fonts ? ` and ${r.fonts} fonts` : ''}${r.commandLogs ? `, ${r.commandLogs} command-log entries` : ''}.`;
  const issues: string[] = [];
  if (r.incompletePages.length) issues.push(`${r.incompletePages.length} pages may be incomplete (${r.incompletePages.slice(0, 5).map((p) => p.title || p.pageId).join(', ')})`);
  if (r.failedImages.length) issues.push(`${r.failedImages.length} images failed`);
  if (r.missingImages.length) issues.push(`${r.missingImages.length} image links have no asset`);
  if (r.longPaths.length) issues.push(`${r.longPaths.length} paths are too long for Windows Explorer`);
  if (commandLogNote) issues.push('the command log is partial');
  if (issues.length) s += ` ${issues.join('; ')}. README.md in the ZIP lists them.`;
  return s;
}

/**
 * The status line for a multi-workspace export: one line with the totals,
 * then each workspace that had issues (its own `exportStatus`). One
 * workspace gives exactly `exportStatus`.
 */
export function exportStatusMany(reports: ExportReport[], notes: Array<string | null>): string {
  if (reports.length === 1) return exportStatus(reports[0]!, notes[0] ?? null);
  const sum = (f: (r: ExportReport) => number) => reports.reduce((n, r) => n + f(r), 0);
  const lines = [`Exported ${reports.length} workspaces: ${sum((r) => r.notes)} notes and ${sum((r) => r.images)} images.`];
  reports.forEach((r, i) => {
    const note = notes[i] ?? null;
    const hasIssues = r.incompletePages.length || r.failedImages.length || r.missingImages.length || r.longPaths.length || note;
    if (hasIssues) lines.push(`${r.root}: ${exportStatus(r, note).replace(/^Exported [^.]*\.\s*/, '')}`);
  });
  return lines.join('\n');
}

/** Import a parsed archive with the browser's network implementations. */
export function importWorkspaceIntoApp(
  data: ParsedWorkspaceZip,
  mode: ImportMode,
  onProgress: (message: string) => void,
): Promise<ImportReport> {
  return importWorkspace(data, mode, {
    bodies: browserPageBodyIO(),
    uploadAsset: async (bytes, opts) => {
      const up = await uploadAsset(new Blob([bytes.slice().buffer as ArrayBuffer], { type: opts.mime || 'application/octet-stream' }), {
        workspaceId: opts.workspaceId, kind: opts.kind, filename: opts.filename,
      });
      return { id: up.id, filename: up.filename, mime: up.mime, size: up.size };
    },
    importCommandLogs: (workspaceId, rows) => importCommandLogs(workspaceId, rows),
    onProgress,
  });
}
