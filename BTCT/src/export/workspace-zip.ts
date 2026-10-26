import { RETIRED_TABLES, emptyRetired, type RetiredData, type RetiredRecord } from './retired';
import JSZip from 'jszip';
import type {
  Workspace, Page, ChangeLogEntry, NmapScan, NmapMachine, PageSnapshot,
  TypstAsset, AssetFolder, CommandLogEntry,
} from '@/types';
import { pageToMarkdown } from './markdown';
import { assetIdsInUpdate, base64ToBytes, bytesToBase64 } from './page-body-codec';
import {
  DirectoryNames,
  NOTE_SEGMENT_BYTES,
  NOTE_TITLE_BYTES,
  ATTACHMENTS_SUFFIX,
  PICTURE_STEM_BYTES,
  WINDOWS_PATH_WARN,
  assetIdsInMarkdown,
  buildPageForest,
  encodeLinkPath,
  exportRootName,
  pictureNumber,
  rewriteAssetLinks,
  sanitizeFileName,
  sanitizeSegment,
  splitExtension,
  type TreeNode,
} from '@/lib/export-names';
import { toCsv } from '@/lib/cmdlog-filter';

// Re-exported for callers that only import this module.
export { bytesToBase64, base64ToBytes };

/**
 * Workspace archive: one ZIP that is both a browsable folder of notes and
 * images and a lossless archive another BTCT server imports.
 *
 * Schema 3 (this build) writes everything under one root folder:
 *
 *   <workspace>_<YYYY-MM-DD_HHMM>/
 *     README.md
 *     notes/<Title>/<Title>.md, <Title>.attachments/NN-<stem>/{modified,original}.<ext>
 *     notes/Command log.csv
 *     assets/<Assets Manager folders>/<stem>/{modified,original}.<ext>, <font file>
 *     .btct/manifest.json and the JSON tables
 *
 * The importer still reads schema 2 (flat top-level JSON) and schema 1
 * (`pages/_index.json`, `graphs/<id>/*.json`). The tables behind removed
 * features ride along in `retired` (see ./retired).
 */
export interface WorkspaceExportData {
  retired?: RetiredData;
  schemaVersion: 1 | 2 | 3;
  exportedAt: number;
  workspace: Workspace;
  pages: Page[];
  changeLogs: ChangeLogEntry[];
  nmapScans: NmapScan[];
  nmapMachines: NmapMachine[];
  pageSnapshots: PageSnapshot[];
  /** Map<pageId, base64 of Y.encodeStateAsUpdate(pageDoc)>. */
  pageYjsUpdates: Record<ID, string>;
  /**
   * The workspace's Typst report source. Three states, distinguished so a
   * replace-import can tell "there was truly no report" from "this archive
   * never recorded either way":
   *  - `string`: the report content.
   *  - `null`: known absent. This build (or a later one) wrote the
   *    manifest and recorded that the source workspace had no report, so
   *    a replace-import may safely clear an existing one.
   *  - `undefined`: unknown. An older build's zip (or one missing its
   *    manifest) never recorded whether a report existed, so a
   *    replace-import must leave any existing report untouched, since the
   *    report has no version history to recover it from.
   */
  typstSource?: string | null;
  /** Every asset record of the workspace (the export picks which ones travel). Schema 3. */
  assets?: TypstAsset[];
  /** Asset Manager folders. Schema 3. */
  assetFolders?: AssetFolder[];
  /** The whole command-log archive of the workspace. Schema 3. */
  commandLogs?: CommandLogEntry[];
}

type ID = string;

/** What an import should do with the destination workspace's report. */
export type ReportImportAction = 'write' | 'clear' | 'none';

/**
 * Decide the fate of the report on import. Pure, and tested per combination,
 * because this is the only place in the app that deliberately destroys report
 * content and the report has no version history to recover it from.
 *
 * `typstSource` carries the archive's three states (see `WorkspaceExportData`):
 * a string is a report to write, `null` means the archive positively recorded
 * that there was none, and `undefined` means it never said either way. Only
 * the positive "there was none" clears an existing report, and only when
 * replacing the workspace it belongs to. An empty string writes nothing and
 * clears nothing, which is what the truthiness check this replaced did.
 */
export function reportImportAction(
  typstSource: string | null | undefined,
  mode: 'new' | 'replace',
  hasExisting: boolean,
): ReportImportAction {
  if (typstSource) return 'write';
  if (typstSource === null && mode === 'replace' && hasExisting) return 'clear';
  return 'none';
}

export const CURRENT_SCHEMA = 3;
const COMMAND_LOG_CSV = 'Command log.csv';

// ── Export plan (pure) ───────────────────────────────────────────────────

export interface PlannedNote {
  page: Page;
  /** Folder of the note, relative to the root. */
  dir: string;
  mdPath: string;
  /** `<Title>.attachments` (relative to `dir`). */
  attachName: string;
  /** Pictures in note order: asset id and the picture folder relative to `dir`. */
  pictures: Array<{ assetId: string; rel: string }>;
  /** Image ids the note shows that have no exported record. */
  missing: string[];
}

export interface ExportPlan {
  root: string;
  notes: PlannedNote[];
  /** Asset records that travel (referenced by a note, or not retired). */
  assets: TypstAsset[];
  /** Image asset id → folders (relative to the root) that get modified/original. */
  imageDirs: Map<string, string[]>;
  /** Font (or other non-image) asset id → file paths relative to the root. */
  fontFiles: Map<string, string[]>;
  /** Asset id → file extension used for its picture files. */
  imageExt: Map<string, string>;
  commandLogCsv: string | null;
}

const EXT_BY_MIME: Record<string, string> = {
  'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp', 'image/svg+xml': 'svg',
  'font/ttf': 'ttf', 'font/otf': 'otf', 'font/woff': 'woff', 'font/woff2': 'woff2',
};

function assetExt(asset: TypstAsset): string {
  return splitExtension(asset.filename ?? '').ext || EXT_BY_MIME[(asset.mime ?? '').toLowerCase()] || 'bin';
}

/** Ids of every asset a page shows: its markdown first, then any only in its Yjs body. */
export function pageAssetIds(page: Page, updateBase64: string | undefined): string[] {
  const md = typeof page.content === 'string' ? page.content : '';
  const ids = assetIdsInMarkdown(md);
  if (updateBase64) {
    try {
      for (const id of assetIdsInUpdate(base64ToBytes(updateBase64))) if (!ids.includes(id)) ids.push(id);
    } catch { /* an unreadable body still exports its markdown */ }
  }
  return ids;
}

/**
 * Decide every path in the archive. Pure: no bytes are read here, so the
 * layout is unit-tested without a browser.
 */
export function planWorkspaceExport(data: WorkspaceExportData, now: Date, rootSuffix = ''): ExportPlan {
  const root = exportRootName(data.workspace.name ?? 'Workspace', now, rootSuffix);
  const assetsById = new Map((data.assets ?? []).map((a) => [a.id.toLowerCase(), a] as const));
  const imageDirs = new Map<string, string[]>();
  const fontFiles = new Map<string, string[]>();
  const imageExt = new Map<string, string>();
  const referenced = new Set<string>();
  const notes: PlannedNote[] = [];

  // Note folders are capped at NOTE_TITLE_BYTES, so `<name>.attachments` and
  // `<name>.md` stay within NOTE_SEGMENT_BYTES.
  const notesDir = new DirectoryNames(NOTE_TITLE_BYTES);
  const commandLogCsv = data.commandLogs?.length ? `notes/${COMMAND_LOG_CSV}` : null;
  if (commandLogCsv) notesDir.reserve(COMMAND_LOG_CSV);

  const visit = (node: TreeNode<Page>, parentPath: string, dir: DirectoryNames) => {
    const name = dir.claim(sanitizeSegment(node.page.title, NOTE_TITLE_BYTES));
    const path = `${parentPath}/${name}`;
    const own = new DirectoryNames(NOTE_TITLE_BYTES);
    const attachName = `${name}${ATTACHMENTS_SUFFIX}`;
    own.reserve(`${name}.md`);
    own.reserve(attachName);

    const ids = pageAssetIds(node.page, data.pageYjsUpdates[node.page.id]);
    const pictures: PlannedNote['pictures'] = [];
    const missing: string[] = [];
    const images = ids.filter((id) => {
      const a = assetsById.get(id);
      if (!a) { missing.push(id); return false; }
      referenced.add(id);
      if (a.kind !== 'image') return false; // a font in a note goes under assets/
      return true;
    });
    const pics = new DirectoryNames(PICTURE_STEM_BYTES + 4);
    images.forEach((id, i) => {
      const a = assetsById.get(id)!;
      const stem = sanitizeSegment(splitExtension(a.filename ?? '').stem, PICTURE_STEM_BYTES);
      const rel = `${attachName}/${pics.claim(`${pictureNumber(i, images.length)}-${stem}`)}`;
      pictures.push({ assetId: id, rel });
      imageExt.set(id, assetExt(a));
      const dirs = imageDirs.get(id) ?? [];
      dirs.push(`${path}/${rel}`);
      imageDirs.set(id, dirs);
    });
    notes.push({ page: node.page, dir: path, mdPath: `${path}/${name}.md`, attachName, pictures, missing });
    for (const child of node.children) visit(child, path, own);
  };
  for (const node of buildPageForest(data.pages)) visit(node, 'notes', notesDir);

  // Assets no note shows: under their Assets Manager folder, unless retired.
  const travelling = (data.assets ?? []).filter((a) => referenced.has(a.id.toLowerCase()) || !a.deletedAt);
  const folders = data.assetFolders ?? [];
  const folderForest = buildPageForest(folders.map((f) => ({ ...f, title: f.name, sortOrder: f.createdAt })));
  const folderPath = new Map<string, { path: string; names: DirectoryNames }>();
  const rootNames = new DirectoryNames(NOTE_SEGMENT_BYTES);
  const walkFolders = (nodes: TreeNode<AssetFolder & { title: string }>[], parent: string, names: DirectoryNames) => {
    for (const n of nodes) {
      const path = `${parent}/${names.claim(sanitizeSegment(n.page.name, NOTE_SEGMENT_BYTES))}`;
      const own = new DirectoryNames(NOTE_SEGMENT_BYTES);
      folderPath.set(n.page.id, { path, names: own });
      walkFolders(n.children, path, own);
    }
  };
  walkFolders(folderForest, 'assets', rootNames);

  for (const a of travelling) {
    const id = a.id.toLowerCase();
    const where = (a.folderId && folderPath.get(a.folderId)) || { path: 'assets', names: rootNames };
    if (a.kind === 'image') {
      if (referenced.has(id) && imageDirs.has(id)) continue;
      const stem = sanitizeSegment(splitExtension(a.filename ?? '').stem, PICTURE_STEM_BYTES);
      imageExt.set(id, assetExt(a));
      imageDirs.set(id, [`${where.path}/${where.names.claim(stem)}`]);
    } else {
      fontFiles.set(id, [`${where.path}/${where.names.claim(sanitizeFileName(a.filename, NOTE_SEGMENT_BYTES), true)}`]);
    }
  }

  return { root, notes, assets: travelling, imageDirs, fontFiles, imageExt, commandLogCsv };
}

// ── Export (bytes) ───────────────────────────────────────────────────────

/** Where the export gets image bytes. Injected so tests need no network or canvas. */
export interface ExportImageSource {
  /** The untouched upload. */
  getOriginal(asset: TypstAsset): Promise<Uint8Array>;
  /** The picture as notes show it (crop and blur applied). */
  getModified(asset: TypstAsset, original: Uint8Array): Promise<Uint8Array>;
}

export interface IncompletePage {
  pageId: string;
  reason: string;
}

export interface ExportOptions {
  images?: ExportImageSource;
  /** Pages whose body may be incomplete (from the body reader). */
  incompletePages?: IncompletePage[];
  /** Set when the command log could not be read in full. */
  commandLogNote?: string | null;
  now?: Date;
  concurrency?: number;
  onProgress?: (message: string) => void;
}

export interface ExportReport {
  root: string;
  fileName: string;
  notes: number;
  images: number;
  fonts: number;
  failedImages: Array<{ assetId: string; filename: string; error: string }>;
  missingImages: Array<{ pageId: string; title: string; assetId: string }>;
  incompletePages: Array<{ pageId: string; title: string; reason: string }>;
  longPaths: string[];
  commandLogs: number;
}

// Already-compressed formats are stored, everything else deflated.
const STORED_EXT = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'woff', 'woff2', 'zip', 'gz']);
function compressionFor(path: string): 'STORE' | 'DEFLATE' {
  return STORED_EXT.has(splitExtension(path.split('/').pop() ?? '').ext) ? 'STORE' : 'DEFLATE';
}

async function runLimited<T>(items: T[], limit: number, work: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (next < items.length) {
      const item = items[next++]!;
      await work(item);
    }
  });
  await Promise.all(workers);
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Lower-cased names of the zip's top-level folders. */
function topLevelFolders(zip: JSZip): Set<string> {
  const out = new Set<string>();
  zip.forEach((path) => {
    const i = path.indexOf('/');
    if (i > 0) out.add(path.slice(0, i).normalize('NFC').toLowerCase());
  });
  return out;
}

/**
 * Add one workspace to `zip` as its own root folder (everything
 * `exportWorkspaceArchive` does except generating the blob). When the zip
 * already has a top-level folder with the planned name (two workspaces with
 * the same name in the same minute) the root gets a `_2`, `_3`, ... suffix;
 * `report.root` and `report.fileName` carry the final root.
 */
export async function addWorkspaceToZip(
  zip: JSZip,
  data: WorkspaceExportData,
  opts: ExportOptions = {},
): Promise<ExportReport> {
  const now = opts.now ?? new Date(data.exportedAt || Date.now());
  const taken = topLevelFolders(zip);
  let plan = planWorkspaceExport(data, now);
  for (let n = 2; taken.has(plan.root.normalize('NFC').toLowerCase()); n++) {
    plan = planWorkspaceExport(data, now, String(n));
  }
  const files = new Map<string, Uint8Array | string>();
  const put = (path: string, content: Uint8Array | string) => { files.set(path, content); };
  const titleOf = new Map(data.pages.map((p) => [p.id, p.title] as const));

  // Images and fonts, four at a time, never through the session caches.
  const failedImages: ExportReport['failedImages'] = [];
  const failedModified = new Set<string>();
  const assetFiles: Record<string, string> = {};
  let images = 0;
  let fonts = 0;
  const jobs = plan.assets.filter((a) => plan.imageDirs.has(a.id.toLowerCase()) || plan.fontFiles.has(a.id.toLowerCase()));
  let done = 0;
  await runLimited(jobs, opts.concurrency ?? 4, async (asset) => {
    const id = asset.id.toLowerCase();
    opts.onProgress?.(`Exporting images (${++done}/${jobs.length})…`);
    if (!opts.images) { failedImages.push({ assetId: id, filename: asset.filename, error: 'no image source' }); failedModified.add(id); return; }
    let original: Uint8Array;
    try {
      original = await opts.images.getOriginal(asset);
    } catch (e) {
      failedImages.push({ assetId: id, filename: asset.filename, error: errText(e) });
      failedModified.add(id);
      return;
    }
    const fontPaths = plan.fontFiles.get(id);
    if (fontPaths) {
      for (const p of fontPaths) put(p, original);
      assetFiles[asset.id] = fontPaths[0]!;
      fonts++;
      return;
    }
    const ext = plan.imageExt.get(id) ?? 'bin';
    const dirs = plan.imageDirs.get(id) ?? [];
    for (const d of dirs) put(`${d}/original.${ext}`, original);
    assetFiles[asset.id] = `${dirs[0]}/original.${ext}`;
    images++;
    try {
      const modified = await opts.images.getModified(asset, original);
      for (const d of dirs) put(`${d}/modified.${ext}`, modified);
    } catch (e) {
      failedModified.add(id);
      failedImages.push({ assetId: id, filename: asset.filename, error: `render failed, original kept: ${errText(e)}` });
    }
  });

  // Notes, with image links pointing at the modified picture.
  const missingImages: ExportReport['missingImages'] = [];
  for (const note of plan.notes) {
    const pics = new Map(note.pictures.map((p) => [p.assetId, p.rel] as const));
    const ext = (id: string) => plan.imageExt.get(id) ?? 'bin';
    const { text } = rewriteAssetLinks(pageToMarkdown(note.page), (id) => {
      const rel = pics.get(id);
      if (!rel || failedModified.has(id)) return null;
      return encodeLinkPath(`${rel}/modified.${ext(id)}`);
    });
    put(note.mdPath, text);
    for (const id of note.missing) missingImages.push({ pageId: note.page.id, title: note.page.title, assetId: id });
  }

  if (plan.commandLogCsv && data.commandLogs) {
    put(plan.commandLogCsv, toCsv([...data.commandLogs].sort((a, b) => a.startedAt - b.startedAt)));
  }

  // The lossless half.
  const exportedAssetIds = new Set(Object.keys(assetFiles));
  const assetsJson = plan.assets;
  const assetFolders = data.assetFolders ?? [];
  const btct = '.btct';
  put(`${btct}/manifest.json`, JSON.stringify({
    schemaVersion: CURRENT_SCHEMA,
    format: 'btct-workspace',
    exportedAt: data.exportedAt,
    workspaceId: data.workspace.id,
    root: plan.root,
    counts: {
      pages: data.pages.length,
      changeLogs: data.changeLogs.length,
      nmapScans: data.nmapScans.length,
      nmapMachines: data.nmapMachines.length,
      pageSnapshots: data.pageSnapshots.length,
      pageYjsUpdates: Object.keys(data.pageYjsUpdates).length,
      report: data.typstSource ? 1 : 0,
      assets: assetsJson.length,
      assetFiles: exportedAssetIds.size,
      assetFolders: assetFolders.length,
      commandLogs: data.commandLogs?.length ?? 0,
      retired: Object.fromEntries(RETIRED_TABLES.map((t) => [t, data.retired?.[t].length ?? 0])),
    },
    incompletePages: (opts.incompletePages ?? []).map((p) => p.pageId),
  }, null, 2));
  put(`${btct}/workspace.json`, JSON.stringify(data.workspace, null, 2));
  put(`${btct}/pages.json`, JSON.stringify(data.pages));
  put(`${btct}/changeLogs.json`, JSON.stringify(data.changeLogs));
  put(`${btct}/nmapScans.json`, JSON.stringify(data.nmapScans));
  put(`${btct}/nmapMachines.json`, JSON.stringify(data.nmapMachines));
  put(`${btct}/pageSnapshots.json`, JSON.stringify(data.pageSnapshots));
  put(`${btct}/pageYjsUpdates.json`, JSON.stringify(data.pageYjsUpdates));
  put(`${btct}/assets.json`, JSON.stringify(assetsJson));
  put(`${btct}/assetFolders.json`, JSON.stringify(assetFolders));
  put(`${btct}/assetFiles.json`, JSON.stringify(assetFiles));
  put(`${btct}/commandLogs.json`, JSON.stringify(data.commandLogs ?? []));
  if (data.typstSource) put(`${btct}/report.typ`, data.typstSource);
  for (const key of RETIRED_TABLES) {
    if (data.retired?.[key].length) put(`${btct}/${key}.json`, JSON.stringify(data.retired[key]));
  }

  const incompletePages = (opts.incompletePages ?? []).map((p) => ({
    pageId: p.pageId, title: titleOf.get(p.pageId) ?? p.pageId, reason: p.reason,
  }));
  const longPaths: string[] = [];
  // README last, so it can list every long path (its own name is short).
  const readmePath = 'README.md';
  for (const path of [...files.keys(), readmePath]) {
    const full = `${plan.root}/${path}`;
    if (full.length > WINDOWS_PATH_WARN) longPaths.push(full);
  }
  const report: ExportReport = {
    root: plan.root,
    fileName: `${plan.root}.zip`,
    notes: plan.notes.length,
    images,
    fonts,
    failedImages,
    missingImages,
    incompletePages,
    longPaths,
    commandLogs: data.commandLogs?.length ?? 0,
  };
  put(readmePath, renderReadme(data, plan, report, now, opts.commandLogNote ?? null));

  const rootFolder = zip.folder(plan.root)!;
  for (const [path, content] of files) {
    rootFolder.file(path, content, { compression: compressionFor(path) });
  }
  return report;
}

function generateZip(zip: JSZip): Promise<Blob> {
  return zip.generateAsync({ type: 'blob', mimeType: 'application/zip', compression: 'DEFLATE', compressionOptions: { level: 6 } });
}

/**
 * Build the archive. Returns the ZIP and an honest report: pages whose body
 * may be incomplete, images that failed, links to images with no record and
 * paths too long for Windows Explorer are all listed, in the report and in
 * README.md.
 */
export async function exportWorkspaceArchive(
  data: WorkspaceExportData,
  opts: ExportOptions = {},
): Promise<{ blob: Blob; report: ExportReport }> {
  const zip = new JSZip();
  const report = await addWorkspaceToZip(zip, data, opts);
  opts.onProgress?.('Compressing…');
  return { blob: await generateZip(zip), report };
}

/** One workspace to export: its data plus the per-workspace export options. */
export interface WorkspaceExportItem {
  data: WorkspaceExportData;
  opts?: ExportOptions;
}

/** `btct-workspaces_<YYYY-MM-DD_HHMM>.zip`, the file name of a multi-workspace archive. */
export function multiExportFileName(at: Date): string {
  // exportRootName's stamp, without a workspace name.
  const root = exportRootName('x', at);
  return `btct-workspaces${root.slice(1)}.zip`;
}

/**
 * Several workspaces in ONE ZIP: each is a complete schema-3 root folder
 * side by side. `items` may be an array or an async producer; a producer is
 * called one workspace at a time (`next(i)` for i in 0..count-1) so only the
 * ZIP accumulates, not every workspace's gathered data. A producer may return
 * null to skip a workspace. One workspace gives exactly
 * `exportWorkspaceArchive`'s file name; none at all is an error.
 */
export async function exportWorkspacesArchive(
  items: WorkspaceExportItem[] | { count: number; produce: (index: number) => Promise<WorkspaceExportItem | null> },
  opts: { now?: Date; onProgress?: (message: string) => void } = {},
): Promise<{ blob: Blob; reports: ExportReport[]; fileName: string }> {
  const count = Array.isArray(items) ? items.length : items.count;
  const zip = new JSZip();
  const reports: ExportReport[] = [];
  for (let i = 0; i < count; i++) {
    const item = Array.isArray(items) ? items[i]! : await items.produce(i);
    if (!item) continue;
    const now = item.opts?.now ?? opts.now;
    reports.push(await addWorkspaceToZip(zip, item.data, { ...item.opts, ...(now ? { now } : {}) }));
  }
  if (reports.length === 0) throw new Error('No workspace could be exported');
  opts.onProgress?.('Compressing…');
  const blob = await generateZip(zip);
  const fileName = reports.length === 1
    ? reports[0]!.fileName
    : multiExportFileName(opts.now ?? new Date());
  return { blob, reports, fileName };
}

/** Back-compatible wrapper: the archive's bytes only. */
export async function exportWorkspaceZip(data: WorkspaceExportData, opts: ExportOptions = {}): Promise<Blob> {
  return (await exportWorkspaceArchive(data, opts)).blob;
}

function renderReadme(
  data: WorkspaceExportData,
  plan: ExportPlan,
  report: ExportReport,
  now: Date,
  commandLogNote: string | null,
): string {
  const lines: string[] = [];
  lines.push(`# ${data.workspace.name || 'Workspace'}`);
  lines.push('');
  lines.push(`Exported from BTCT on ${now.toISOString()} (archive schema ${CURRENT_SCHEMA}).`);
  lines.push('');
  lines.push(`- Notes: ${report.notes}`);
  lines.push(`- Images: ${report.images}, fonts: ${report.fonts}`);
  lines.push(`- Change log entries: ${data.changeLogs.length}`);
  lines.push(`- Nmap scans: ${data.nmapScans.length} (${data.nmapMachines.length} hosts)`);
  lines.push(`- Command log entries: ${report.commandLogs}${plan.commandLogCsv ? ` ([${plan.commandLogCsv}](${encodeLinkPath(plan.commandLogCsv)}))` : ''}`);
  if (data.typstSource) lines.push('- Report source: `.btct/report.typ`');
  lines.push('');
  lines.push('Every picture folder holds `modified.*` (crop and blur applied, as the note shows it) and `original.*`.');
  lines.push('**The `original.*` files are unredacted.** Do not hand this folder to anyone who must not see what a blur hides.');
  lines.push('');
  lines.push('`.btct/` is the lossless copy another BTCT server imports (Export / Import, Workspace ZIP).');
  lines.push('');
  lines.push('## Notes');
  lines.push('');
  const depth = (dir: string) => dir.split('/').length - 2;
  for (const n of plan.notes) {
    lines.push(`${'  '.repeat(depth(n.dir))}- [${(n.page.title || 'Untitled').replace(/[[\]]/g, '\\$&')}](${encodeLinkPath(n.mdPath)})`);
  }
  if (report.incompletePages.length) {
    lines.push('', '## Possibly incomplete pages', '');
    lines.push('These bodies could not be confirmed from the server; the markdown and the archived body may be missing recent edits.');
    lines.push('');
    for (const p of report.incompletePages) lines.push(`- ${p.title} (\`${p.pageId}\`): ${p.reason}`);
  }
  if (report.failedImages.length || report.missingImages.length) {
    lines.push('', '## Images that failed to export', '');
    for (const f of report.failedImages) lines.push(`- ${f.filename} (\`${f.assetId}\`): ${f.error}`);
    for (const m of report.missingImages) lines.push(`- \`asset:${m.assetId}\` in "${m.title}": no asset record in this workspace`);
  }
  if (commandLogNote) {
    lines.push('', '## Command log', '', commandLogNote);
  }
  if (report.longPaths.length) {
    lines.push('', '## Paths too long for Windows Explorer', '');
    lines.push('Extract these with 7-Zip or `tar -xf` instead of Explorer:');
    lines.push('');
    for (const p of report.longPaths) lines.push(`- \`${p}\``);
  }
  lines.push('');
  return lines.join('\n');
}

// ── Import (parse) ───────────────────────────────────────────────────────

export interface ParsedWorkspaceZip extends WorkspaceExportData {
  /** The schema the archive was written with (1, 2 or 3). */
  sourceSchema: number;
  /** Damaged or unreadable parts, worded for the status line. Never silently dropped. */
  problems: string[];
  /** Asset id → path of its original bytes in the archive (schema 3). */
  assetFiles: Record<string, string>;
  /** Read an asset's original bytes, or null when the archive does not have them. */
  readAsset: (assetId: string) => Promise<Uint8Array | null>;
}

/** Every `.btct/manifest.json` at the top level or one folder down, in zip order. */
function findSchema3Prefixes(zip: JSZip): string[] {
  const found: string[] = [];
  zip.forEach((path) => {
    const m = /^(?:([^/]+)\/)?\.btct\/manifest\.json$/.exec(path);
    if (m) found.push(m[1] ? `${m[1]}/` : '');
  });
  return found;
}

async function loadZip(blob: Blob): Promise<JSZip> {
  try {
    // An ArrayBuffer, not the Blob: JSZip reads a Blob through FileReader,
    // which only browsers have.
    return await JSZip.loadAsync(await blob.arrayBuffer(), { checkCRC32: true });
  } catch (e) {
    throw new Error(`Invalid workspace zip: the file is damaged or not a ZIP (${errText(e)})`);
  }
}

/**
 * Read a workspace ZIP. Schema 3 (root folder plus `.btct/`), schema 2 (flat
 * JSON at the top) and schema 1 (`pages/_index.json`) all load. A damaged
 * archive is an error with a message saying so; a damaged optional part is
 * listed in `problems` rather than dropped without a word.
 */
export async function parseWorkspaceZip(blob: Blob): Promise<ParsedWorkspaceZip> {
  const zip = await loadZip(blob);
  return parseWorkspaceFromZip(zip, findSchema3Prefixes(zip)[0] ?? null);
}

/**
 * Read every workspace in a ZIP: one per `<root>/.btct/manifest.json`, in zip
 * order. A ZIP with no or one such root loads as `parseWorkspaceZip` does
 * (including schema 2 and 1). Each workspace reads only inside its own root.
 */
export async function parseWorkspaceZips(blob: Blob): Promise<ParsedWorkspaceZip[]> {
  const entries = await listWorkspacesInZip(blob);
  const out: ParsedWorkspaceZip[] = [];
  for (const e of entries) out.push(await e.parse());
  return out;
}

/** One workspace root in a ZIP, parsed on demand so a damaged one fails alone. */
export interface ZipWorkspaceEntry {
  /** The root folder's name ('' for a flat archive). */
  root: string;
  parse: () => Promise<ParsedWorkspaceZip>;
}

/**
 * The workspaces in a ZIP, lazily. With 2+ roots nothing is parsed here: each
 * `parse()` can fail on its own (and be released after use). With 0 or 1 root
 * the single archive is parsed now, so a damaged one throws as
 * `parseWorkspaceZip` does.
 */
export async function listWorkspacesInZip(blob: Blob): Promise<ZipWorkspaceEntry[]> {
  const zip = await loadZip(blob);
  const prefixes = findSchema3Prefixes(zip);
  if (prefixes.length <= 1) {
    const parsed = await parseWorkspaceFromZip(zip, prefixes[0] ?? null);
    return [{ root: (prefixes[0] ?? '').replace(/\/$/, ''), parse: async () => parsed }];
  }
  return prefixes.map((prefix) => ({
    root: prefix.replace(/\/$/, ''),
    parse: () => parseWorkspaceFromZip(zip, prefix),
  }));
}

async function parseWorkspaceFromZip(zip: JSZip, prefix3: string | null): Promise<ParsedWorkspaceZip> {
  const problems: string[] = [];
  const base = prefix3 === null ? '' : `${prefix3}.btct/`;

  const readText = async (name: string): Promise<string | undefined> => {
    const f = zip.file(base + name);
    if (!f) return undefined;
    try { return await f.async('string'); }
    catch (e) { throw new Error(`Invalid workspace zip: ${name} is damaged (${errText(e)})`); }
  };
  const wsJson = await readText('workspace.json');
  if (!wsJson) throw new Error('Invalid workspace zip: missing workspace.json');
  let workspace: Workspace;
  try { workspace = JSON.parse(wsJson) as Workspace; }
  catch { throw new Error('Invalid workspace zip: workspace.json is not valid JSON'); }
  if (!workspace || typeof workspace !== 'object' || typeof workspace.id !== 'string') {
    throw new Error('Invalid workspace zip: workspace.json has no id');
  }

  // Required tables fail the import when damaged; optional ones are reported.
  const readJson = async <T>(name: string, opts: { legacy?: string; required?: boolean } = {}): Promise<T[]> => {
    let text: string | undefined;
    let from = name;
    try {
      text = await readText(name);
      if (text === undefined && opts.legacy) { from = opts.legacy; text = await readText(opts.legacy); }
    } catch (e) {
      if (opts.required) throw e;
      problems.push(errText(e).replace(/^Invalid workspace zip: /, ''));
      return [];
    }
    if (text === undefined) return [];
    try {
      const parsed = JSON.parse(text) as unknown;
      if (!Array.isArray(parsed)) throw new Error('not a list');
      return parsed as T[];
    } catch {
      if (opts.required) throw new Error(`Invalid workspace zip: ${from} is not valid JSON`);
      problems.push(`${from} is damaged and was skipped`);
      return [];
    }
  };

  const pages         = await readJson<Page>('pages.json', { legacy: 'pages/_index.json', required: true });
  const changeLogs    = await readJson<ChangeLogEntry>('changeLogs.json');
  const nmapScans     = await readJson<NmapScan>('nmapScans.json');
  const nmapMachines  = await readJson<NmapMachine>('nmapMachines.json');
  const pageSnapshots = await readJson<PageSnapshot>('pageSnapshots.json');
  const assets        = await readJson<TypstAsset>('assets.json');
  const assetFolders  = await readJson<AssetFolder>('assetFolders.json');
  const commandLogs   = await readJson<CommandLogEntry>('commandLogs.json');

  const retired: RetiredData = emptyRetired();
  for (const key of RETIRED_TABLES) {
    retired[key] = await readJson<RetiredRecord>(`${key}.json`, { legacy: key === 'graphs' ? 'graphs/_index.json' : undefined });
  }
  // v1 fallback: per-graph node/edge JSONs split by folder.
  if (retired.graphNodes.length === 0 && retired.graphEdges.length === 0) {
    for (const graph of retired.graphs) {
      retired.graphNodes = retired.graphNodes.concat(await readJson<RetiredRecord>(`graphs/${graph.id}/nodes.json`));
      retired.graphEdges = retired.graphEdges.concat(await readJson<RetiredRecord>(`graphs/${graph.id}/edges.json`));
    }
  }

  type Manifest = { schemaVersion?: number; counts?: Record<string, unknown> };
  let manifest: Manifest | null = null;
  try {
    const m = await readText('manifest.json');
    manifest = m ? (JSON.parse(m) as Manifest) : null;
  } catch {
    problems.push('manifest.json is damaged');
  }

  // Page bodies: a damaged file is reported, never silently dropped.
  let pageYjsUpdates: Record<ID, string> = {};
  try {
    const yjsJson = await readText('pageYjsUpdates.json');
    if (yjsJson !== undefined) {
      const parsed = JSON.parse(yjsJson) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
      for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof v === 'string') pageYjsUpdates[k] = v;
        else problems.push(`page body ${k} is damaged and was skipped`);
      }
    }
  } catch {
    pageYjsUpdates = {};
    problems.push('pageYjsUpdates.json is damaged: no page body could be read, pages import with their markdown only');
  }
  const expectedBodies = manifest?.counts?.pageYjsUpdates;
  if (typeof expectedBodies === 'number' && expectedBodies !== Object.keys(pageYjsUpdates).length && !problems.some((p) => p.startsWith('pageYjsUpdates'))) {
    problems.push(`the manifest lists ${expectedBodies} page bodies but the archive holds ${Object.keys(pageYjsUpdates).length}`);
  }

  let assetFiles: Record<string, string> = {};
  try {
    const af = await readText('assetFiles.json');
    if (af !== undefined) {
      const parsed = JSON.parse(af) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) if (typeof v === 'string') assetFiles[k] = v;
      }
    }
  } catch {
    assetFiles = {};
    problems.push('assetFiles.json is damaged: image bytes cannot be located');
  }

  // Known-absent (null) vs unknown (undefined). A report.typ file present
  // always means "there is a report". Its absence alone is ambiguous: an
  // older build's zip never wrote one either. The manifest's counts.report
  // disambiguates, since this build always writes it as 0 or 1: if it's
  // present and 0, the source workspace truly had no report, so a
  // replace-import may safely clear one. If the manifest is missing,
  // unparsable, or predates counts.report (older build), the answer is
  // unknown, so a replace-import must leave an existing report alone.
  let typstSource: string | null | undefined;
  try { typstSource = await readText('report.typ'); }
  catch (e) { problems.push(errText(e).replace(/^Invalid workspace zip: /, '')); typstSource = undefined; }
  if (typstSource === undefined && manifest?.counts && typeof manifest.counts.report === 'number') {
    typstSource = manifest.counts.report === 0 ? null : undefined;
  }

  const rootPrefix = prefix3 ?? '';
  const readAsset = async (assetId: string): Promise<Uint8Array | null> => {
    const rel = assetFiles[assetId];
    if (!rel || rel.startsWith('/') || rel.split('/').includes('..')) return null;
    // Paths come from the archive's own JSON: only ever look them up inside
    // the ZIP, never on a filesystem.
    const f = zip.file(rootPrefix + rel);
    if (!f) return null;
    return f.async('uint8array');
  };

  const sourceSchema = prefix3 !== null ? (Number(manifest?.schemaVersion) || CURRENT_SCHEMA)
    : zip.file('pages.json') ? 2 : 1;

  return {
    schemaVersion: CURRENT_SCHEMA,
    sourceSchema,
    exportedAt: Date.now(),
    workspace,
    pages,
    changeLogs,
    nmapScans,
    nmapMachines,
    pageSnapshots,
    pageYjsUpdates,
    typstSource,
    retired,
    assets,
    assetFolders,
    commandLogs,
    assetFiles,
    readAsset,
    problems,
  };
}
