import * as Y from 'yjs';
import { v4 as uuidv4 } from 'uuid';
import type {
  AssetFolder, ChangeLogEntry, CommandLogEntry, NmapMachine, NmapScan, Page, PageSnapshot, TypstAsset, Workspace,
} from '@/types';
import {
  getSharedDoc, getOrInitYText, seedMissingYTexts, setYTextValue, sharedTransact, textKey,
  TEXT_FIELDS_BY_ENTITY, type TableName,
} from '@/realtime/shared-doc';
import { replaceYTextContent } from '@/realtime/use-y-text';
import { buildPageForest, remapAssetIdsInMarkdown } from '@/lib/export-names';
import { collectRetired, remapRetiredRows, RETIRED_TABLES, type RetiredRecord } from './retired';
import { reportImportAction, type ParsedWorkspaceZip, type WorkspaceExportData } from './workspace-zip';
import { base64ToBytes, bytesToBase64, remapAssetIdsInUpdate } from './page-body-codec';
import { writePageBodies, type PageBodyIO } from './body-sync';
import type { CommandLogImportResult } from './cmdlog-io';

// ─────────────────────────────────────────────────────────────────────────
// Workspace import.
//
// "new" mints a fresh id for EVERY record (workspace, pages, change log,
// nmap scans and hosts, snapshots, retired rows, asset folders) and the
// server mints one for every uploaded asset, so a copy imported next to its
// original shares nothing with it: not a record, not a page room, not an
// asset. Every reference is rewritten through the same maps: parentId,
// targetId, scanId, linkedNodeId, folderId, `asset:<id>` in markdown and the
// `assetId` of every `asset_image` node in a page body.
//
// "replace" keeps the archive's ids. Records in the workspace that the
// archive does not have are deleted; every other record is overwritten in
// place, in the same chunked transactions, so a page that exists on both
// sides never disappears and teammates' tabs on it stay open. Page bodies
// are CRDT-merged, not reset: see `REPLACE_BODY_NOTE`. Assets and asset
// folders that the archive does not have are kept (a body merged from the
// live room may still show them).
//
// Records are written in transactions of about 1 MB of JSON: one per record
// reloaded every table on every client per record (O(n^2)), one per table can
// exceed the relay's 16 MiB websocket message cap.
// ─────────────────────────────────────────────────────────────────────────

export type ImportMode = 'new' | 'replace';

export const REPLACE_BODY_NOTE =
  'Replace restores records to the archive and merges page bodies: text added after the export stays, and a page\'s History tab can roll a body back.';

/** Bytes of JSON per shared-doc transaction. */
export const CHUNK_BYTES = 1_000_000;

export interface UploadedAssetInfo {
  id: string;
  filename: string;
  mime: string;
  size: number;
}

export interface ImportDeps {
  bodies: PageBodyIO;
  uploadAsset: (bytes: Uint8Array, opts: { workspaceId: string; kind: TypstAsset['kind']; filename: string; mime: string }) => Promise<UploadedAssetInfo>;
  importCommandLogs: (workspaceId: string, rows: CommandLogEntry[]) => Promise<CommandLogImportResult>;
  onProgress?: (message: string) => void;
  /** Override for tests. */
  newId?: () => string;
  bodyTimeoutMs?: number;
}

export interface ImportReport {
  mode: ImportMode;
  workspaceId: string;
  sourceWorkspaceId: string;
  /** Replace mode over an existing workspace. */
  replacedExisting: boolean;
  counts: {
    pages: number; changeLogs: number; nmapScans: number; nmapMachines: number; pageSnapshots: number;
    retired: number; assetFolders: number; commandLogs: number;
  };
  deleted: number;
  bodies: { written: number; unconfirmed: string[]; failed: Array<{ pageId: string; error: string }> };
  assets: { uploaded: number; reused: number; failed: Array<{ id: string; filename: string; error: string }>; kept: number };
  renamedFiles: Array<{ from: string; to: string }>;
  commandLogs: CommandLogImportResult | null;
  commandLogError: string | null;
  problems: string[];
}

type Row = { id: string };

function jsonSize(v: unknown): number {
  try { return JSON.stringify(v)?.length ?? 0; } catch { return 0; }
}

/** Write `rows` into `map` in transactions of about `CHUNK_BYTES` of JSON each. */
export function writeChunked<T extends Row>(
  map: Y.Map<unknown>,
  rows: T[],
  extra?: (row: T) => void,
  maxBytes = CHUNK_BYTES,
): number {
  let i = 0;
  let transactions = 0;
  while (i < rows.length) {
    let size = 0;
    const start = i;
    while (i < rows.length && (i === start || size + jsonSize(rows[i]) <= maxBytes)) {
      size += jsonSize(rows[i]);
      i++;
    }
    const batch = rows.slice(start, i);
    sharedTransact(() => {
      for (const r of batch) {
        map.set(r.id, { ...r });
        extra?.(r);
      }
    });
    transactions++;
  }
  return transactions;
}

const ENTITY_BY_TABLE = new Map<string, { entity: string; fields: string[] }>(
  Object.entries(TEXT_FIELDS_BY_ENTITY).map(([entity, info]) => [info.table, { entity, fields: info.fields }]),
);

/** Delete ids from a table (and their Y.Texts) in chunked transactions. */
function deleteChunked(map: Y.Map<unknown>, table: string, ids: string[]): number {
  const c = getSharedDoc();
  const text = ENTITY_BY_TABLE.get(table);
  for (let i = 0; i < ids.length; i += 2000) {
    const batch = ids.slice(i, i + 2000);
    sharedTransact(() => {
      for (const id of batch) {
        map.delete(id);
        if (text) for (const f of text.fields) {
          const key = textKey(text.entity, id, f);
          if (c.texts.has(key)) c.texts.delete(key);
        }
      }
    });
  }
  return ids.length;
}

/** In place: bring an existing record's collaborative texts to the archive's values (minimal splice). */
function syncTexts(table: TableName, row: Record<string, unknown>): void {
  const text = ENTITY_BY_TABLE.get(table);
  if (!text) return;
  const c = getSharedDoc();
  for (const f of text.fields) {
    const key = textKey(text.entity, String(row.id), f);
    const value = typeof row[f] === 'string' ? (row[f] as string) : '';
    const t = c.texts.get(key);
    if (t && t.toString() !== value) setYTextValue(text.entity, String(row.id), f, value);
  }
}

async function runLimited<T>(items: T[], limit: number, work: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (next < items.length) await work(items[next++]!);
  }));
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** `/assets/<old>` to `/assets/<new>` in a report source, one pass, so renames never chain. */
export function renameAssetPaths(source: string, renames: ReadonlyArray<{ from: string; to: string }>): string {
  if (!renames.length) return source;
  const byName = new Map(renames.map((r) => [r.from, r.to] as const));
  const alt = renames.map((r) => r.from.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).sort((a, b) => b.length - a.length).join('|');
  return source.replace(new RegExp(`/assets/(${alt})(?=["'\\s)\\]]|$)`, 'g'), (_m, name: string) => `/assets/${byName.get(name) ?? name}`);
}

function uniqueName(taken: Set<string>, filename: string): string {
  const lower = (s: string) => s.toLowerCase();
  if (!taken.has(lower(filename))) { taken.add(lower(filename)); return filename; }
  const dot = filename.lastIndexOf('.');
  const stem = dot > 0 ? filename.slice(0, dot) : filename;
  const ext = dot > 0 ? filename.slice(dot) : '';
  for (let n = 2; ; n++) {
    const c = `${stem}-${n}${ext}`;
    if (!taken.has(lower(c))) { taken.add(lower(c)); return c; }
  }
}

/**
 * Import a parsed archive into the shared doc and the server. Never throws
 * for a single bad part: everything that did not make it is in the report.
 */
export async function importWorkspace(
  data: ParsedWorkspaceZip | WorkspaceExportData,
  mode: ImportMode,
  deps: ImportDeps,
): Promise<ImportReport> {
  const c = getSharedDoc();
  const tables = c.tables;
  const newId = deps.newId ?? uuidv4;
  const progress = deps.onProgress ?? (() => undefined);
  const problems: string[] = [...('problems' in data ? data.problems : [])];
  const sourceWsId = data.workspace.id;
  const existing = tables.workspaces.get(sourceWsId) as Workspace | undefined;
  const replacedExisting = mode === 'replace' && !!existing;
  const wsId = mode === 'new' ? newId() : sourceWsId;

  // One id map for every record. Identity in replace mode.
  const ids = new Map<string, string>();
  const mapId = (id: string): string => {
    if (mode !== 'new') return id;
    let v = ids.get(id);
    if (!v) { v = newId(); ids.set(id, v); }
    return v;
  };
  // Asset ids come from the server; anything else goes through mapId.
  const assetIds = new Map<string, string>();
  const ref = (id: string): string => assetIds.get(id) ?? mapId(id);

  // ── Asset folders, parents before children ──
  progress('Importing asset folders…');
  const folderIds = new Set((data.assetFolders ?? []).map((f) => f.id));
  const folderOrder: AssetFolder[] = [];
  const flatten = (nodes: ReturnType<typeof buildPageForest<AssetFolder & { title: string }>>) => {
    for (const n of nodes) { folderOrder.push(n.page); flatten(n.children); }
  };
  flatten(buildPageForest((data.assetFolders ?? []).filter((f) => f && typeof f.id === 'string').map((f) => ({ ...f, title: f.name }))));
  const folders: AssetFolder[] = folderOrder.map((f) => {
    const { title: _title, ...rest } = f as AssetFolder & { title?: string };
    return {
      ...rest,
      id: mapId(f.id),
      workspaceId: wsId,
      parentId: f.parentId && folderIds.has(f.parentId) ? mapId(f.parentId) : null,
    };
  });

  // ── Assets: reuse what this workspace already has, upload the rest ──
  const archiveAssets = (data.assets ?? []).filter((a) => a && typeof a.id === 'string');
  const liveAssets = new Map<string, TypstAsset>();
  for (const v of tables.typstAssets.values()) {
    const a = v as TypstAsset;
    if (a && a.workspaceId === wsId) liveAssets.set(a.id, a);
  }
  const takenNames = new Set<string>();
  for (const a of liveAssets.values()) {
    if (!archiveAssets.some((x) => x.id === a.id)) takenNames.add(a.filename.toLowerCase());
  }
  const assetRows: TypstAsset[] = [];
  const failedAssets: ImportReport['assets']['failed'] = [];
  const renamedFiles: ImportReport['renamedFiles'] = [];
  let uploaded = 0;
  let reused = 0;
  let doneAssets = 0;
  const readAsset = 'readAsset' in data ? data.readAsset : async () => null;
  const now = Date.now();
  await runLimited(archiveAssets, 4, async (a) => {
    progress(`Uploading images (${++doneAssets}/${archiveAssets.length})…`);
    const folderId = a.folderId && folderIds.has(a.folderId) ? mapId(a.folderId) : null;
    const live = mode === 'replace' ? liveAssets.get(a.id) : undefined;
    if (live) {
      assetIds.set(a.id, a.id);
      takenNames.add(a.filename.toLowerCase());
      assetRows.push({ ...live, ...a, workspaceId: wsId, folderId, deletedAt: null, updatedAt: now });
      reused++;
      return;
    }
    let bytes: Uint8Array | null = null;
    try { bytes = await readAsset(a.id); }
    catch (e) { failedAssets.push({ id: a.id, filename: a.filename, error: `damaged in the archive: ${errText(e)}` }); return; }
    if (!bytes) { failedAssets.push({ id: a.id, filename: a.filename, error: 'bytes are not in the archive' }); return; }
    const wanted = uniqueName(takenNames, a.filename);
    try {
      const up = await deps.uploadAsset(bytes, { workspaceId: wsId, kind: a.kind, filename: wanted, mime: a.mime });
      assetIds.set(a.id, up.id);
      if (up.filename !== a.filename) renamedFiles.push({ from: a.filename, to: up.filename });
      takenNames.add(up.filename.toLowerCase());
      assetRows.push({
        ...a,
        id: up.id,
        workspaceId: wsId,
        filename: up.filename,
        mime: up.mime || a.mime,
        size: up.size || a.size,
        folderId,
        deletedAt: null,
        updatedAt: now,
      });
      uploaded++;
    } catch (e) {
      failedAssets.push({ id: a.id, filename: a.filename, error: errText(e) });
    }
  });

  // ── Records ──
  progress('Importing records…');
  const pageIdsInArchive = new Set(data.pages.map((p) => p.id));
  const remapContent = (content: Page['content']): Page['content'] =>
    typeof content === 'string' ? remapAssetIdsInMarkdown(content, assetIds) : content;
  const livePage = (id: string) => (mode === 'replace' ? (tables.pages.get(id) as Page | undefined) : undefined);
  const pages: Page[] = data.pages.filter((p) => p && typeof p.id === 'string').map((p) => {
    const live = livePage(p.id);
    return {
      ...p,
      id: mapId(p.id),
      workspaceId: wsId,
      parentId: p.parentId ? (pageIdsInArchive.has(p.parentId) || mode === 'replace' ? mapId(p.parentId) : null) : null,
      // A body merged into a live room keeps its later edits, so the live
      // markdown mirror describes it better than the archive's.
      content: live && live.workspaceId === wsId ? live.content : remapContent(p.content),
    };
  });

  const remapLogValue = (entry: ChangeLogEntry, value: string | null | undefined): string | null | undefined => {
    if (mode !== 'new' && !assetIds.size) return value;
    if (typeof value !== 'string' || entry.action !== 'delete' || entry.target !== 'page') return value;
    // One page record: what older builds logged, and each entry of the
    // page-tree snapshot this build logs ({kind:'pageTree', pages:[...]}).
    const remapPageRecord = (rec: Record<string, unknown>): Record<string, unknown> => ({
      ...rec,
      id: ref(rec.id as string),
      workspaceId: wsId,
      parentId: typeof rec.parentId === 'string' ? mapId(rec.parentId) : rec.parentId ?? null,
      content: typeof rec.content === 'string' ? remapAssetIdsInMarkdown(rec.content, assetIds) : rec.content,
    });
    try {
      const obj = JSON.parse(value) as Record<string, unknown> | null;
      if (!obj || typeof obj !== 'object') return value;
      if (obj.kind === 'pageTree' && Array.isArray(obj.pages)) {
        return JSON.stringify({
          ...obj,
          pages: obj.pages.map((p: unknown) => (p && typeof p === 'object' && typeof (p as Record<string, unknown>).id === 'string'
            ? remapPageRecord(p as Record<string, unknown>) : p)),
        });
      }
      if (typeof obj.id !== 'string') return value;
      return JSON.stringify(remapPageRecord(obj));
    } catch {
      return value;
    }
  };
  const changeLogs: ChangeLogEntry[] = data.changeLogs.filter((e) => e && typeof e.id === 'string').map((e) => ({
    ...e,
    id: mapId(e.id),
    workspaceId: wsId,
    targetId: typeof e.targetId === 'string' ? ref(e.targetId) : e.targetId,
    prevValue: remapLogValue(e, e.prevValue),
    newValue: remapLogValue(e, e.newValue),
  }));
  const nmapScans: NmapScan[] = data.nmapScans.filter((s) => s && typeof s.id === 'string')
    .map((s) => ({ ...s, id: mapId(s.id), workspaceId: wsId }));
  const nmapMachines: NmapMachine[] = data.nmapMachines.filter((m) => m && typeof m.id === 'string').map((m) => {
    const out: NmapMachine = { ...m, id: mapId(m.id), scanId: mapId(m.scanId) };
    if (m.linkedNodeId) out.linkedNodeId = mapId(m.linkedNodeId);
    return out;
  });
  const pageSnapshots: PageSnapshot[] = data.pageSnapshots.filter((s) => s && typeof s.id === 'string').map((s) => {
    let updateBase64 = s.updateBase64;
    if (assetIds.size && typeof updateBase64 === 'string') {
      try { updateBase64 = bytesToBase64(remapAssetIdsInUpdate(base64ToBytes(updateBase64), assetIds)); }
      catch { /* an unreadable legacy snapshot travels as it was */ }
    }
    return { ...s, id: mapId(s.id), pageId: mapId(s.pageId), workspaceId: wsId, updateBase64 };
  });
  const retiredRows = remapRetiredRows(data.retired, wsId, mapId);

  // Workspace first, then every table in ~1 MB transactions.
  const workspace: Workspace = { ...data.workspace, id: wsId };
  sharedTransact(() => {
    tables.workspaces.set(wsId, { ...workspace });
    if (replacedExisting) syncTexts('workspaces', workspace as unknown as Record<string, unknown>);
  });
  const textsFor = (table: TableName) => (row: Row) => { if (replacedExisting) syncTexts(table, row as unknown as Record<string, unknown>); };
  writeChunked(tables.assetFolders, folders);
  writeChunked(tables.typstAssets, assetRows);
  writeChunked(tables.pages, pages, textsFor('pages'));
  writeChunked(tables.nmapScans, nmapScans, textsFor('nmapScans'));
  writeChunked(tables.nmapMachines, nmapMachines, textsFor('nmapMachines'));
  writeChunked(tables.changeLogs, changeLogs);
  writeChunked(tables.pageSnapshots, pageSnapshots);
  for (const name of RETIRED_TABLES) {
    const rows = retiredRows.filter((r) => r.table === name).map((r) => r.row);
    if (rows.length) writeChunked(c.doc.getMap<RetiredRecord>(name) as Y.Map<unknown>, rows);
  }

  // Replace: now that every surviving record is in place, drop the ones the
  // archive does not have.
  let deleted = 0;
  if (replacedExisting) {
    const keep = (rows: Row[]) => new Set(rows.map((r) => r.id));
    const stale = (map: Y.Map<unknown>, keepIds: Set<string>, belongs: (v: Record<string, unknown>) => boolean) => {
      const out: string[] = [];
      for (const [id, v] of map.entries()) {
        if (v && typeof v === 'object' && belongs(v as Record<string, unknown>) && !keepIds.has(id)) out.push(id);
      }
      return out;
    };
    const inWs = (v: Record<string, unknown>) => v.workspaceId === wsId;
    const scanIds = new Set<string>();
    for (const [id, v] of tables.nmapScans.entries()) if (v && (v as NmapScan).workspaceId === wsId) scanIds.add(id);
    deleted += deleteChunked(tables.pages, 'pages', stale(tables.pages, keep(pages), inWs));
    deleted += deleteChunked(tables.changeLogs, 'changeLogs', stale(tables.changeLogs, keep(changeLogs), inWs));
    deleted += deleteChunked(tables.nmapMachines, 'nmapMachines',
      stale(tables.nmapMachines, keep(nmapMachines), (v) => typeof v.scanId === 'string' && scanIds.has(v.scanId)));
    deleted += deleteChunked(tables.nmapScans, 'nmapScans', stale(tables.nmapScans, keep(nmapScans), inWs));
    deleted += deleteChunked(tables.pageSnapshots, 'pageSnapshots', stale(tables.pageSnapshots, keep(pageSnapshots), inWs));
    const liveRetired = collectRetired(wsId);
    for (const name of RETIRED_TABLES) {
      const keepIds = new Set(retiredRows.filter((r) => r.table === name).map((r) => r.row.id));
      const ids = liveRetired[name].map((r) => r.id).filter((id) => !keepIds.has(id));
      if (ids.length) deleted += deleteChunked(c.doc.getMap(name) as Y.Map<unknown>, name, ids);
    }
  }
  const keptAssets = replacedExisting
    ? [...liveAssets.keys()].filter((id) => !archiveAssets.some((a) => a.id === id)).length
    : 0;

  // ── Report source ──
  const action = reportImportAction(data.typstSource, mode, replacedExisting);
  if (action === 'write' && data.typstSource) {
    replaceYTextContent(getOrInitYText(textKey('typst', wsId, 'source'), ''), renameAssetPaths(data.typstSource, renamedFiles));
  } else if (action === 'clear') {
    const existingReport = c.texts.get(textKey('typst', wsId, 'source'));
    if (existingReport) replaceYTextContent(existingReport, '');
  }

  // Imported records are plain JSON: seed their Y.Texts (invariant #16).
  seedMissingYTexts(c);

  // ── Page bodies, four at a time, each confirmed by the server ──
  const bodies: Array<{ pageId: string; update: Uint8Array }> = [];
  for (const [origPageId, b64] of Object.entries(data.pageYjsUpdates)) {
    try {
      const raw = base64ToBytes(b64);
      if (raw.byteLength <= 2) continue; // an empty doc: nothing to write
      bodies.push({ pageId: mapId(origPageId), update: remapAssetIdsInUpdate(raw, assetIds) });
    } catch (e) {
      problems.push(`page body ${origPageId} could not be decoded (${errText(e)})`);
    }
  }
  progress(`Writing page bodies (0/${bodies.length})…`);
  const bodyResult = await writePageBodies(bodies, deps.bodies, {
    timeoutMs: deps.bodyTimeoutMs,
    onProgress: (n, total) => progress(`Writing page bodies (${n}/${total})…`),
  });

  // ── Command log (SQLite on the server) ──
  let commandLogs: CommandLogImportResult | null = null;
  let commandLogError: string | null = null;
  const logs = (data.commandLogs ?? []).filter((r) => r && typeof r.id === 'string');
  if (logs.length) {
    progress(`Importing ${logs.length} command-log entries…`);
    try {
      commandLogs = await deps.importCommandLogs(wsId, logs.map((r) => ({ ...r, workspaceId: wsId })));
    } catch (e) {
      commandLogError = errText(e);
    }
  }

  return {
    mode,
    workspaceId: wsId,
    sourceWorkspaceId: sourceWsId,
    replacedExisting,
    counts: {
      pages: pages.length,
      changeLogs: changeLogs.length,
      nmapScans: nmapScans.length,
      nmapMachines: nmapMachines.length,
      pageSnapshots: pageSnapshots.length,
      retired: retiredRows.length,
      assetFolders: folders.length,
      commandLogs: logs.length,
    },
    deleted,
    bodies: { written: bodies.length - bodyResult.unconfirmed.length - bodyResult.failed.length, ...bodyResult },
    assets: { uploaded, reused, failed: failedAssets, kept: keptAssets },
    renamedFiles,
    commandLogs,
    commandLogError,
    problems,
  };
}

/** The status line for an import, naming everything that did not make it. */
export function importStatus(r: ImportReport): string {
  const parts: string[] = [];
  parts.push(r.mode === 'new'
    ? `Imported as a new workspace: ${r.counts.pages} notes`
    : r.replacedExisting ? `Workspace replaced: ${r.counts.pages} notes` : `Workspace imported: ${r.counts.pages} notes`);
  parts.push(`${r.assets.uploaded + r.assets.reused} images`);
  if (r.counts.commandLogs) parts.push(`${r.commandLogs ? r.commandLogs.imported : 0} of ${r.counts.commandLogs} command-log entries`);
  let s = `${parts.join(', ')}.`;
  if (r.replacedExisting) s += ` ${r.deleted} records not in the archive were removed; ${r.assets.kept} images not in the archive were kept. ${REPLACE_BODY_NOTE}`;
  const issues: string[] = [];
  if (r.bodies.unconfirmed.length) issues.push(`${r.bodies.unconfirmed.length} page bodies were not confirmed by the server (keep this tab open and reopen those pages)`);
  if (r.bodies.failed.length) issues.push(`${r.bodies.failed.length} page bodies failed`);
  if (r.assets.failed.length) issues.push(`${r.assets.failed.length} images failed: ${r.assets.failed.slice(0, 5).map((f) => `${f.filename} (${f.error})`).join('; ')}`);
  if (r.renamedFiles.length) issues.push(`${r.renamedFiles.length} image files were renamed (${r.renamedFiles.slice(0, 5).map((f) => `${f.from} to ${f.to}`).join(', ')}), report.typ updated`);
  if (r.commandLogError) issues.push(`command log not imported: ${r.commandLogError}`);
  for (const p of r.problems.slice(0, 5)) issues.push(p);
  if (r.problems.length > 5) issues.push(`${r.problems.length - 5} more problems`);
  if (issues.length) s += ` Problems: ${issues.join('; ')}.`;
  return s;
}
