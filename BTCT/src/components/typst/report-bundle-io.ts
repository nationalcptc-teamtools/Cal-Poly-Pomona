// ─────────────────────────────────────────────────────────────────────────
// Report import and export: the reading, uploading and zipping half.
//
// The decisions (which report, which files, collisions, path rewrites,
// caps) are pure and live in `lib/typst-report-bundle.ts`; this module
// turns a picked ZIP, folder or `.typ` into a list of files with lazy
// readers, runs a confirmed plan against the asset store, and builds the
// "Export report" ZIP. It sits in `components/typst/`, so JSZip and all of
// it load with the Report tab's lazy chunk (invariant 17).
// ─────────────────────────────────────────────────────────────────────────

import { isZipFile, readZipMember } from '@/lib/zip-upload';
import { exportRootName } from '@/lib/export-names';
import { downloadZipName, zipCompressionFor } from '@/lib/download-zip';
import { downloadBlob } from '@/lib/download';
import { fetchAssetBytesUncached, resolveAssetBytes } from '@/lib/assets';
import type { TypstAsset } from '@/types';
import {
  REPORT_ASSET_MAX_BYTES,
  REPORT_IMPORT_MAX_BYTES,
  REPORT_SOURCE_MAX_BYTES,
  baseName,
  checkBundleCaps,
  comparisonsNeeded,
  decodeReportSource,
  findReportCandidates,
  isClutter,
  normalizeMemberPath,
  planReportImport,
  referencedAssetFilenames,
  resolveReportPath,
  rewriteReportSource,
  sameBytes,
  sanitizeAssetFilename,
  selectReportFiles,
  type BundleFile,
  type ExistingAsset,
  type PlannedFile,
  type ReportCandidate,
  type ReportSelection,
} from '@/lib/typst-report-bundle';

/** A file of the picked input, with a reader that refuses more than `max` bytes. */
export interface BundleEntry extends BundleFile {
  read(max: number): Promise<Uint8Array>;
}

export interface ReportBundle {
  /** What the user picked, for headings ("BTCT-report-templates.zip"). */
  name: string;
  entries: BundleEntry[];
  /** Member names refused as unsafe (absolute, `..`). */
  unsafe: string[];
  candidates: ReportCandidate[];
}

async function fileBytes(file: Blob, max: number, label: string): Promise<Uint8Array> {
  if (file.size > max) throw new Error(`${label} is too large (${Math.round(file.size / 1024 / 1024)} MB).`);
  return new Uint8Array(await file.arrayBuffer());
}

function finish(name: string, entries: BundleEntry[], unsafe: string[]): ReportBundle {
  const candidates = findReportCandidates(entries.map((e) => e.path));
  if (!candidates.length) throw new Error(`${name} holds no .typ report.`);
  return { name, entries, unsafe, candidates };
}

/** A picked `.zip`: refused over 200 MB or 2000 entries before anything inflates. */
export async function bundleFromZip(file: File): Promise<ReportBundle> {
  const capped = checkBundleCaps({ bytes: file.size, entries: 0 });
  if (capped) throw new Error(capped);
  const { default: JSZip } = await import('jszip');
  let zip: InstanceType<typeof JSZip>;
  try {
    zip = await JSZip.loadAsync(file);
  } catch (e) {
    throw new Error(`${file.name} is not a readable ZIP (${e instanceof Error ? e.message : String(e)}).`);
  }
  const members = Object.values(zip.files).filter((f) => !f.dir);
  const tooMany = checkBundleCaps({ entries: members.length });
  if (tooMany) throw new Error(tooMany);
  const entries: BundleEntry[] = [];
  const unsafe: string[] = [];
  for (const m of members) {
    const raw = m.unsafeOriginalName ?? m.name;
    const path = normalizeMemberPath(raw);
    if (!path) { unsafe.push(raw); continue; }
    if (isClutter(path)) continue;
    // JSZip's declared size; the reader re-checks while inflating, since the
    // header is the archive's word, not a fact.
    const size = (m as unknown as { _data?: { uncompressedSize?: number } })._data?.uncompressedSize ?? 0;
    entries.push({
      path,
      size,
      read: (max) => readZipMember(m, max, `${path} is too large.`),
    });
  }
  return finish(file.name, entries, unsafe);
}

/**
 * Files with their relative paths: a folder from `<input webkitdirectory>`
 * (`webkitRelativePath`) or a drop (the paths `readDroppedItems` built).
 */
export function bundleFromFiles(name: string, files: { file: File; path: string }[]): ReportBundle {
  const tooMany = checkBundleCaps({ entries: files.length });
  if (tooMany) throw new Error(tooMany);
  const total = files.reduce((n, f) => n + f.file.size, 0);
  if (total > REPORT_IMPORT_MAX_BYTES) {
    throw new Error(`That folder holds ${Math.round(total / 1024 / 1024)} MB; a report import takes at most ${REPORT_IMPORT_MAX_BYTES / 1024 / 1024} MB.`);
  }
  const entries: BundleEntry[] = [];
  const unsafe: string[] = [];
  for (const { file, path: raw } of files) {
    const path = normalizeMemberPath(raw);
    if (!path) { unsafe.push(raw); continue; }
    if (isClutter(path)) continue;
    entries.push({ path, size: file.size, read: (max) => fileBytes(file, max, path) });
  }
  return finish(name, entries, unsafe);
}

/** Whatever was picked or dropped: one ZIP, one `.typ`, or a folder's files. */
export async function openBundle(name: string, files: { file: File; path: string }[]): Promise<ReportBundle> {
  if (files.length === 1) {
    const only = files[0]!.file;
    if (await isZipFile(only)) return bundleFromZip(only);
    if (!/\.typ$/i.test(only.name)) throw new Error(`${only.name} is not a .zip, a folder or a .typ file.`);
  }
  return bundleFromFiles(name, files);
}

/** A folder input's files, with the folder-relative path each one carries. */
export function filesFromInput(list: FileList): { file: File; path: string }[] {
  return Array.from(list).map((file) => ({ file, path: file.webkitRelativePath || file.name }));
}

type FsEntry = {
  isFile: boolean;
  isDirectory: boolean;
  name: string;
  fullPath: string;
  file?: (ok: (f: File) => void, fail: (e: unknown) => void) => void;
  createReader?: () => { readEntries: (ok: (es: FsEntry[]) => void, fail: (e: unknown) => void) => void };
};

/**
 * The files of a drop, folders walked (`webkitGetAsEntry`). Stops collecting
 * past the entry cap so a dropped home directory does not walk forever.
 */
export async function readDroppedItems(dt: DataTransfer): Promise<{ file: File; path: string }[]> {
  const out: { file: File; path: string }[] = [];
  const roots: FsEntry[] = [];
  for (const item of Array.from(dt.items ?? [])) {
    const entry = (item as unknown as { webkitGetAsEntry?: () => FsEntry | null }).webkitGetAsEntry?.();
    if (entry) roots.push(entry);
  }
  if (!roots.length) return Array.from(dt.files).map((file) => ({ file, path: file.name }));
  const limit = 2001;
  const walk = async (e: FsEntry): Promise<void> => {
    if (out.length >= limit) return;
    if (e.isFile && e.file) {
      const file = await new Promise<File>((ok, fail) => e.file!(ok, fail));
      out.push({ file, path: e.fullPath.replace(/^\/+/, '') });
      return;
    }
    if (e.isDirectory && e.createReader) {
      const reader = e.createReader();
      // readEntries hands back a batch at a time until it returns none.
      for (;;) {
        const batch = await new Promise<FsEntry[]>((ok, fail) => reader.readEntries(ok, fail));
        if (!batch.length) break;
        for (const child of batch) await walk(child);
        if (out.length >= limit) return;
      }
    }
  };
  for (const r of roots) await walk(r);
  return out;
}

function toExisting(a: TypstAsset): ExistingAsset {
  return {
    id: a.id,
    kind: a.kind === 'font' ? 'font' : 'image',
    filename: a.filename,
    size: a.size,
    framed: !!a.crop || !!(a.blurs && a.blurs.length),
    retired: !!a.deletedAt,
  };
}

export interface PreparedImport {
  bundle: ReportBundle;
  candidate: ReportCandidate;
  source: string;
  selection: ReportSelection;
  plan: PlannedFile[];
  /** Bundle fonts dropped because an earlier bundle font has the same bytes. */
  duplicateFonts: string[];
  /** Image paths the source names that neither the bundle nor the workspace holds. */
  unresolved: string[];
  /** Image paths the source names that the workspace already holds (and the bundle does not). */
  fromWorkspace: string[];
}

/**
 * Read the chosen report and decide everything: files, collisions (bytes
 * read and compared only where a name or a size says they might match),
 * and what the source names that nothing supplies.
 */
export async function prepareImport(
  bundle: ReportBundle,
  candidate: ReportCandidate,
  assets: TypstAsset[],
): Promise<PreparedImport> {
  const main = bundle.entries.find((e) => e.path === candidate.mainPath);
  if (!main) throw new Error(`${candidate.mainPath} is missing.`);
  if (main.size > REPORT_SOURCE_MAX_BYTES) throw new Error(`${candidate.mainPath} is larger than 5 MB.`);
  const source = decodeReportSource(await main.read(REPORT_SOURCE_MAX_BYTES));
  const selection = selectReportFiles(candidate, bundle.entries, source, bundle.unsafe);

  const byPath = new Map(bundle.entries.map((e) => [e.path, e]));
  const cache = new Map<string, Promise<Uint8Array>>();
  const bundleBytes = (path: string): Promise<Uint8Array> => {
    let p = cache.get(path);
    if (!p) { p = byPath.get(path)!.read(REPORT_ASSET_MAX_BYTES); cache.set(path, p); }
    return p;
  };

  // Fonts that are the same file twice in the bundle (a folder of copies).
  const duplicateFonts: string[] = [];
  const keptFonts: { path: string; size: number }[] = [];
  const files = [];
  for (const f of selection.files) {
    if (f.kind === 'font') {
      let dup = false;
      for (const k of keptFonts) {
        if (k.size === f.size && sameBytes(await bundleBytes(k.path), await bundleBytes(f.path))) { dup = true; break; }
      }
      if (dup) { duplicateFonts.push(f.path); continue; }
      keptFonts.push(f);
    }
    files.push(f);
  }

  const live = assets.filter((a) => a.kind === 'image' || a.kind === 'font');
  const existing = live.map(toExisting);
  const identical = new Map<string, string>();
  for (const { path, existingId } of comparisonsNeeded(files, existing)) {
    if (identical.has(path)) continue;
    try {
      const [mine, theirs] = await Promise.all([bundleBytes(path), fetchAssetBytesUncached(existingId)]);
      if (sameBytes(mine, theirs)) identical.set(path, existingId);
    } catch { /* unreadable either side: treat as different, which uploads a copy */ }
  }
  const plan = planReportImport(files, existing, identical);

  const names = new Set(live.filter((a) => a.kind === 'image').map((a) => a.filename.toLowerCase()));
  const unresolved: string[] = [];
  const fromWorkspace: string[] = [];
  for (const lit of selection.missing) {
    const lands = resolveReportPath('', lit);
    const inAssets = lands && lands.startsWith('assets/') && !lands.slice(7).includes('/') && names.has(lands.slice(7).toLowerCase());
    (inAssets ? fromWorkspace : unresolved).push(lit);
  }
  // Keep the cache only for what will be uploaded.
  for (const k of [...cache.keys()]) if (!plan.some((p) => p.path === k && p.action !== 'reuse')) cache.delete(k);
  prepared.set(bundle, bundleBytes);
  return { bundle, candidate, source, selection, plan, duplicateFonts, unresolved, fromWorkspace };
}

/** The byte reader of each prepared bundle, so the upload reuses what the comparison read. */
const prepared = new WeakMap<ReportBundle, (path: string) => Promise<Uint8Array>>();

const MIME_BY_EXT: Record<string, string> = {
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp',
  svg: 'image/svg+xml', ttf: 'font/ttf', otf: 'font/otf', woff: 'font/woff', woff2: 'font/woff2', ttc: 'font/collection',
};

function mimeFor(name: string): string {
  const ext = name.slice(name.lastIndexOf('.') + 1).toLowerCase();
  return MIME_BY_EXT[ext] ?? 'application/octet-stream';
}

export interface ImportCallbacks {
  uploadImage(file: File): Promise<TypstAsset>;
  uploadFont(file: File): Promise<void>;
  unretire(id: string): Promise<void>;
  /** Replace the report source (a minimal delta through `applySource`). */
  replaceSource(next: string): void;
  onProgress?(done: number, total: number): void;
}

export interface ImportResult {
  uploaded: number;
  reused: number;
  failed: string[];
  /** Planned names the server stored differently (it corrects an extension to the bytes). */
  renamedByServer: { from: string; to: string }[];
}

/**
 * Upload what the plan says, then write the source with every bundle image
 * literal pointed at the name its asset actually got. The source goes in
 * last, so the preview never compiles a report whose images are not there
 * yet; a failed upload is reported and the source still goes in (the user
 * confirmed the replacement, and Typst names the one missing path).
 */
export async function runImport(p: PreparedImport, cb: ImportCallbacks): Promise<ImportResult> {
  const read = prepared.get(p.bundle) ?? ((path: string) => p.bundle.entries.find((e) => e.path === path)!.read(REPORT_ASSET_MAX_BYTES));
  const names = new Map<string, string>();
  const failed: string[] = [];
  const renamedByServer: { from: string; to: string }[] = [];
  let uploaded = 0;
  let reused = 0;
  let done = 0;
  const total = p.plan.length;
  for (const f of p.plan) {
    try {
      if (f.action === 'reuse') {
        if (f.unretire && f.existingId) await cb.unretire(f.existingId);
        names.set(f.path, f.name);
        reused++;
      } else {
        const bytes = await read(f.path);
        const file = new File([bytes.slice().buffer as ArrayBuffer], f.name, { type: mimeFor(f.name) });
        if (f.kind === 'font') {
          await cb.uploadFont(file);
        } else {
          const asset = await cb.uploadImage(file);
          names.set(f.path, asset.filename);
          if (asset.filename !== f.name) renamedByServer.push({ from: f.name, to: asset.filename });
        }
        uploaded++;
      }
    } catch (e) {
      failed.push(`${baseName(f.path)}: ${e instanceof Error ? e.message : String(e)}`);
    }
    cb.onProgress?.(++done, total);
  }
  cb.replaceSource(rewriteReportSource(p.source, p.candidate.dir, names));
  prepared.delete(p.bundle);
  return { uploaded, reused, failed, renamedByServer };
}

// ── export ────────────────────────────────────────────────────────────────

export interface ExportResult {
  fileName: string | null;
  images: number;
  fonts: number;
  /** Asset names the source references that the workspace does not have. */
  missing: string[];
}

/**
 * `<workspace>_<date>_report.zip` holding `<workspace>_<date>_report/` with
 * `main.typ`, `assets/<file>` for every image the source names and
 * `fonts/<file>` for every uploaded font: the template layout, so it
 * imports back and compiles with `typst compile main.typ --font-path fonts`.
 *
 * Images are the RENDERED bytes (`resolveAssetBytes`: crop and blur baked,
 * the bytes the preview mounts), never the original upload, so a redaction
 * cannot leave in the export. An image whose render fails stops the export
 * rather than falling back to the original.
 *
 * Like the workspace archive this is one ZIP handed to `downloadBlob`, not
 * `downloadAsZip` (that would put a ZIP inside a ZIP; invariant 30).
 */
export async function exportReport(source: string, assets: TypstAsset[], workspaceName: string, at = new Date()): Promise<ExportResult> {
  const { default: JSZip } = await import('jszip');
  const zip = new JSZip();
  const root = exportRootName(workspaceName || 'report', at, 'report');
  zip.file(`${root}/main.typ`, source, { date: at, compression: 'DEFLATE' });

  const wanted = referencedAssetFilenames(source);
  const byName = new Map<string, TypstAsset>();
  for (const a of assets) {
    if (a.kind !== 'image' || !wanted.has(a.filename)) continue;
    const prev = byName.get(a.filename);
    // A live asset wins over a retired one of the same name.
    if (!prev || (prev.deletedAt && !a.deletedAt)) byName.set(a.filename, a);
  }
  const used = new Set<string>();
  let images = 0;
  for (const [name, a] of byName) {
    const safe = sanitizeAssetFilename(name);
    if (safe !== name || used.has(safe.toLowerCase())) continue;
    used.add(safe.toLowerCase());
    let bytes: Uint8Array;
    try {
      bytes = await resolveAssetBytes(a);
    } catch (e) {
      throw new Error(`${name} could not be rendered with its crop and blur (${e instanceof Error ? e.message : String(e)}); nothing was exported.`);
    }
    zip.file(`${root}/assets/${safe}`, bytes, { date: at, compression: zipCompressionFor(safe) });
    images++;
  }
  const fontNames = new Set<string>();
  let fonts = 0;
  for (const a of assets) {
    if (a.kind !== 'font') continue;
    const safe = sanitizeAssetFilename(a.filename);
    if (fontNames.has(safe.toLowerCase())) continue;
    fontNames.add(safe.toLowerCase());
    const bytes = await fetchAssetBytesUncached(a.id);
    zip.file(`${root}/fonts/${safe}`, bytes, { date: at, compression: zipCompressionFor(safe) });
    fonts++;
  }
  const missing = [...wanted].filter((n) => !byName.has(n)).sort();
  const blob = await zip.generateAsync({
    type: 'blob',
    mimeType: 'application/zip',
    compression: 'DEFLATE',
    compressionOptions: { level: 6 },
  });
  const fileName = downloadZipName(workspaceName || 'report', at, 'report');
  const outcome = await downloadBlob(blob, fileName, 'application/zip');
  return { fileName: outcome === 'cancelled' ? null : fileName, images, fonts, missing };
}
