// ─────────────────────────────────────────────────────────────────────────
// Report import and export: the pure half (no DOM, no network, no JSZip).
//
// A report bundle is the layout the CPTC templates ship in and the Report
// tab's "Export report" writes:
//
//   <name>/main.typ
//   <name>/fonts/*.ttf          (any font type the asset store takes)
//   <name>/assets/<image>       (cover.png and friends)
//
// `main.typ` sits at the compile root, so `"assets/cover.png"` and
// `"/assets/cover.png"` both name `<name>/assets/cover.png`, and BTCT mounts
// every image asset at `/assets/<filename>` beside a `/main.typ`, so a
// template imported with its images uploaded under their own names compiles
// unchanged. Everything here decides WHAT to do (which report of a GitHub
// "Download ZIP" with several, which files travel with it, what collides with
// the workspace's existing assets, how the source's paths are rewritten);
// `components/typst/report-bundle-io.ts` does the reading and uploading.
//
// Imported only from `components/typst/`, so it rides in the Report tab's
// lazy chunk (invariant 17). Tests: src/test/typst-report-bundle.test.ts.
// ─────────────────────────────────────────────────────────────────────────

/** A ZIP larger than this is refused before it is opened. */
export const REPORT_IMPORT_MAX_BYTES = 200 * 1024 * 1024;
/** A ZIP or folder with more entries than this is refused. */
export const REPORT_IMPORT_MAX_ENTRIES = 2000;
/** The report source itself. */
export const REPORT_SOURCE_MAX_BYTES = 5 * 1024 * 1024;
/** One image or font: the asset store's own cap (server/assets.mjs). */
export const REPORT_ASSET_MAX_BYTES = 25 * 1024 * 1024;

export const IMAGE_EXTS = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg'] as const;
export const FONT_EXTS = ['.ttf', '.otf', '.woff', '.woff2', '.ttc'] as const;

export type BundleKind = 'image' | 'font';

function extOf(path: string): string {
  const base = path.slice(path.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot).toLowerCase() : '';
}

/** 'image', 'font', or null for anything the asset store would not take. */
export function bundleKind(path: string): BundleKind | null {
  const ext = extOf(path);
  if ((IMAGE_EXTS as readonly string[]).includes(ext)) return 'image';
  if ((FONT_EXTS as readonly string[]).includes(ext)) return 'font';
  return null;
}

export function baseName(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1);
}

export function dirName(path: string): string {
  const i = path.lastIndexOf('/');
  return i < 0 ? '' : path.slice(0, i);
}

/**
 * A member name as a safe relative path (`a/b/c.png`), or null when it is
 * not one: absolute (`/x`, `C:\x`, `\\host`), climbing out (`..`), carrying a
 * NUL, or empty. Backslashes count as separators (a Windows-made ZIP), `.`
 * segments and doubled slashes are dropped, and a trailing slash (a folder
 * entry) leaves the path without it.
 */
export function normalizeMemberPath(raw: string): string | null {
  if (typeof raw !== 'string' || !raw || raw.includes('\0')) return null;
  const s = raw.replace(/\\/g, '/');
  if (s.startsWith('/') || /^[A-Za-z]:/.test(s)) return null;
  const out: string[] = [];
  for (const seg of s.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') return null;
    out.push(seg);
  }
  return out.length ? out.join('/') : null;
}

/** macOS and VCS clutter: never a report, never uploaded, not worth listing. */
export function isClutter(path: string): boolean {
  return path.split('/').some((seg) => seg === '__MACOSX' || seg === '.git' || seg === '.DS_Store' || seg.startsWith('._'));
}

/** A sentence for the user when the input is too big to read, else null. */
export function checkBundleCaps(input: { bytes?: number; entries: number }): string | null {
  if (input.bytes !== undefined && input.bytes > REPORT_IMPORT_MAX_BYTES) {
    return `That ZIP is ${mb(input.bytes)}; a report import takes at most ${mb(REPORT_IMPORT_MAX_BYTES)}.`;
  }
  if (input.entries > REPORT_IMPORT_MAX_ENTRIES) {
    return `That holds ${input.entries} files; a report import takes at most ${REPORT_IMPORT_MAX_ENTRIES}.`;
  }
  return null;
}

function mb(n: number): string {
  return `${Math.round((n / 1024 / 1024) * 10) / 10} MB`;
}

export interface ReportCandidate {
  /** Path of the `.typ` inside the bundle. */
  mainPath: string;
  /** Its folder ('' at the top level): the compile root. */
  dir: string;
  /** What the picker shows: the folder's own name, or the file name at the top. */
  label: string;
}

/**
 * The reports a bundle holds: every `main.typ`, or every `.typ` when there is
 * no `main.typ` at all (a single-file report under another name). Sorted by
 * path, so a GitHub ZIP lists its templates in the order the repo does.
 */
export function findReportCandidates(paths: string[]): ReportCandidate[] {
  const typ = paths.filter((p) => !isClutter(p) && extOf(p) === '.typ');
  const mains = typ.filter((p) => baseName(p).toLowerCase() === 'main.typ');
  const picked = (mains.length ? mains : typ).slice().sort((a, b) => a.localeCompare(b));
  return picked.map((mainPath) => {
    const dir = dirName(mainPath);
    return { mainPath, dir, label: dir ? baseName(dir) : baseName(mainPath) };
  });
}

/**
 * The shortest path that tells the candidates apart, for a picker with two
 * `design-a1` folders in different parents. Equal to `label` when that is
 * already unique.
 */
export function candidateDisplayNames(candidates: ReportCandidate[]): string[] {
  return candidates.map((c) => {
    const segs = c.mainPath.split('/');
    // Drop main.typ itself when there is a folder to name.
    const parts = segs.length > 1 && baseName(c.mainPath).toLowerCase() === 'main.typ' ? segs.slice(0, -1) : segs;
    for (let n = 1; n <= parts.length; n++) {
      const name = parts.slice(-n).join('/');
      const clash = candidates.some((o) => o !== c && suffixOf(o, n) === name);
      if (!clash) return name;
    }
    return c.mainPath;
  });
}

function suffixOf(c: ReportCandidate, n: number): string {
  const segs = c.mainPath.split('/');
  const parts = segs.length > 1 && baseName(c.mainPath).toLowerCase() === 'main.typ' ? segs.slice(0, -1) : segs;
  return parts.slice(-n).join('/');
}

/** One `"..."` string literal of the source, with its span (quotes included). */
export interface StringLiteral {
  value: string;
  from: number;
  to: number;
}

/**
 * Every string literal on one line, skipping `//` line comments and
 * `/* *\/` blocks. Escapes stay as written (a path with `\"` in it is not a
 * path anyone types), and raw blocks are not special-cased: a backticked
 * `"assets/x.png"` is matched, which at worst uploads nothing extra and
 * rewrites a sample in a code block the same way as the real path.
 */
export function stringLiterals(source: string): StringLiteral[] {
  const out: StringLiteral[] = [];
  let i = 0;
  const n = source.length;
  while (i < n) {
    const c = source[i];
    if (c === '/' && source[i + 1] === '/') {
      const nl = source.indexOf('\n', i);
      i = nl < 0 ? n : nl;
      continue;
    }
    if (c === '/' && source[i + 1] === '*') {
      const end = source.indexOf('*/', i + 2);
      i = end < 0 ? n : end + 2;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let ok = false;
      while (j < n) {
        const d = source[j];
        if (d === '\\') { j += 2; continue; }
        if (d === '\n') break;
        if (d === '"') { ok = true; break; }
        j++;
      }
      if (ok) {
        out.push({ value: source.slice(i + 1, j), from: i, to: j + 1 });
        i = j + 1;
        continue;
      }
      i = j;
      continue;
    }
    i++;
  }
  return out;
}

/**
 * The bundle path a literal names, read the way Typst does with `dir` as the
 * compile root: `/x` is `<dir>/x`, `x` and `./x` are `<dir>/x`, `..` climbs.
 * Null for a URL, an empty string, or a path climbing out of the bundle.
 * Climbing above `dir` but staying inside the bundle is allowed (Typst would
 * refuse it, but the import flattens the file to `/assets/` anyway).
 */
export function resolveReportPath(dir: string, literal: string): string | null {
  if (!literal || /^[a-z][a-z0-9+.-]*:/i.test(literal) || literal.includes('\0')) return null;
  const rel = literal.startsWith('/') ? literal.slice(1) : literal;
  const out = dir ? dir.split('/') : [];
  for (const seg of rel.replace(/\\/g, '/').split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (!out.length) return null;
      out.pop();
      continue;
    }
    out.push(seg);
  }
  return out.length ? out.join('/') : null;
}

/** Same rule as the server's `sanitizeFilename` (server/assets.mjs), so the plan predicts the stored name. */
export function sanitizeAssetFilename(raw: string): string {
  const base = baseName(String(raw || '').replace(/\\/g, '/'));
  const dot = base.lastIndexOf('.');
  const ext = dot > 0 ? base.slice(dot).toLowerCase() : '';
  const stem = dot > 0 ? base.slice(0, dot) : base;
  const safeStem = stem.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[.]+/, '').slice(0, 80);
  const safeExt = ext.replace(/[^A-Za-z0-9.]/g, '');
  return (safeStem || 'asset') + safeExt;
}

/** The first of `name`, `stem-2.ext`, ... not in `taken` (lower-cased); asset-repo's rule. */
export function uniqueName(taken: ReadonlySet<string>, filename: string): string {
  if (!taken.has(filename.toLowerCase())) return filename;
  const dot = filename.lastIndexOf('.');
  const stem = dot > 0 ? filename.slice(0, dot) : filename;
  const ext = dot > 0 ? filename.slice(dot) : '';
  for (let k = 2; k < 1000; k++) {
    const candidate = `${stem}-${k}${ext}`;
    if (!taken.has(candidate.toLowerCase())) return candidate;
  }
  return `${stem}-${Date.now()}${ext}`;
}

/** A file in the bundle, as the planner sees it (bytes are read later). */
export interface BundleFile {
  path: string;
  size: number;
}

/** The parts of an existing asset record the planner needs. */
export interface ExistingAsset {
  id: string;
  kind: 'image' | 'font';
  filename: string;
  size: number;
  /** A crop or blur makes the mounted bytes differ from the stored ones. */
  framed: boolean;
  retired: boolean;
}

export interface SelectedFile {
  path: string;
  size: number;
  kind: BundleKind;
  /** The sanitized base name it wants to be stored under. */
  wanted: string;
}

export interface ReportSelection {
  candidate: ReportCandidate;
  /** Images and fonts that travel with the report. */
  files: SelectedFile[];
  /** Image paths the source names that the bundle does not hold. */
  missing: string[];
  /** Files skipped, with the reason, for the confirm dialog. */
  ignored: { path: string; reason: string }[];
  /** Files outside the chosen report's folder (other templates of a repo ZIP). */
  outside: number;
}

/**
 * Which files of the bundle belong to `candidate`: everything under its
 * `assets/` and `fonts/` folders that the asset store takes, fonts beside the
 * `.typ`, and any image or font the source names by a path that resolves
 * inside the bundle (a `../shared/logo.png`, an `images/x.png`). Everything
 * else under the report's folder is listed as ignored; files elsewhere are
 * only counted.
 */
export function selectReportFiles(
  candidate: ReportCandidate,
  files: BundleFile[],
  source: string,
  unsafe: string[] = [],
): ReportSelection {
  const byPath = new Map(files.map((f) => [f.path, f]));
  const prefix = candidate.dir ? `${candidate.dir}/` : '';
  const chosen = new Map<string, SelectedFile>();
  const ignored: { path: string; reason: string }[] = unsafe.map((p) => ({ path: p, reason: 'unsafe name' }));
  const missing: string[] = [];

  const take = (f: BundleFile, kind: BundleKind): void => {
    if (chosen.has(f.path)) return;
    if (f.size > REPORT_ASSET_MAX_BYTES) {
      ignored.push({ path: f.path, reason: `larger than ${mb(REPORT_ASSET_MAX_BYTES)}` });
      return;
    }
    chosen.set(f.path, { path: f.path, size: f.size, kind, wanted: sanitizeAssetFilename(baseName(f.path)) });
  };

  // Referenced first, so a file named in the source keeps its document order.
  for (const lit of stringLiterals(source)) {
    const kind = bundleKind(lit.value);
    if (!kind) continue;
    const resolved = resolveReportPath(candidate.dir, lit.value);
    const f = resolved ? byPath.get(resolved) : undefined;
    if (f && !isClutter(f.path)) take(f, kind);
    else if (kind === 'image' && resolved && !missing.includes(lit.value)) missing.push(lit.value);
  }

  let outside = 0;
  for (const f of files) {
    if (f.path === candidate.mainPath || isClutter(f.path)) continue;
    if (prefix && !f.path.startsWith(prefix)) {
      if (!chosen.has(f.path)) outside++;
      continue;
    }
    const rel = f.path.slice(prefix.length);
    const kind = bundleKind(f.path);
    const top = rel.includes('/') ? rel.slice(0, rel.indexOf('/')).toLowerCase() : '';
    const sibling = (kind === 'image' && top === 'assets') || (kind === 'font' && (top === 'fonts' || !rel.includes('/')));
    if (kind && sibling) { take(f, kind); continue; }
    if (chosen.has(f.path)) continue;
    // A file inside another report of the same bundle belongs to that one.
    ignored.push({ path: f.path, reason: kind ? 'not in assets/ or fonts/ and not referenced' : 'not an image or font' });
  }

  return { candidate, files: [...chosen.values()], missing, ignored, outside };
}

export type PlannedAction =
  /** Upload under `name`. */
  | 'upload'
  /** Upload under `name`, because the wanted name holds different bytes. */
  | 'upload-renamed'
  /** The workspace already has these bytes as `name` (`existingId`): nothing to upload. */
  | 'reuse';

export interface PlannedFile extends SelectedFile {
  action: PlannedAction;
  /** The name it ends up under (planned; the upload confirms it). */
  name: string;
  existingId?: string;
  /** The existing asset was retired and is brought back by the import. */
  unretire?: boolean;
  /** The existing asset that keeps the wanted name, when renamed. */
  keptId?: string;
}

/**
 * Collision check, phase one: the bundle files whose bytes have to be
 * compared with an existing asset before the plan is final. An image is
 * compared with the existing image of the same name (case-insensitive), when
 * the sizes agree and that image carries no crop or blur (a framed image
 * mounts different bytes, so it can never be "the same"). A font is compared
 * with every existing font of the same size, whatever its name: Typst finds a
 * font by family, so a second copy of the same file only adds a duplicate.
 */
export function comparisonsNeeded(selected: SelectedFile[], existing: ExistingAsset[]): { path: string; existingId: string }[] {
  const out: { path: string; existingId: string }[] = [];
  for (const f of selected) {
    if (f.kind === 'image') {
      const same = existing.find((a) => a.kind === 'image' && a.filename.toLowerCase() === f.wanted.toLowerCase());
      if (same && !same.framed && same.size === f.size) out.push({ path: f.path, existingId: same.id });
    } else {
      for (const a of existing) {
        if (a.kind === 'font' && a.size === f.size) out.push({ path: f.path, existingId: a.id });
      }
    }
  }
  return out;
}

/**
 * Collision check, phase two. `identical` maps a bundle path to the existing
 * asset whose bytes matched it (from `comparisonsNeeded`).
 *
 * - Same bytes: reuse the existing asset, upload nothing (a retired one is
 *   brought back, so the Assets rail shows what the report uses).
 * - Same name, different bytes: the existing asset is KEPT untouched (a note
 *   or another workspace document may show it, and asset bytes are immutable
 *   per id, so "replacing" would mean deleting it) and the imported file is
 *   uploaded under the asset store's next free name (`cover-2.png`); the
 *   imported source is rewritten to that name, so both resolve.
 * - Two files of the bundle wanting one name get the same treatment.
 *
 * Bundle fonts with the same bytes as an earlier bundle font are dropped by
 * the caller before this (they hash equal), and are not seen here.
 */
export function planReportImport(
  selected: SelectedFile[],
  existing: ExistingAsset[],
  identical: ReadonlyMap<string, string>,
): PlannedFile[] {
  const taken = new Set(existing.map((a) => a.filename.toLowerCase()));
  const out: PlannedFile[] = [];
  for (const f of selected) {
    const sameId = identical.get(f.path);
    const same = sameId ? existing.find((a) => a.id === sameId) : undefined;
    if (same) {
      out.push({ ...f, action: 'reuse', name: same.filename, existingId: same.id, unretire: same.retired || undefined });
      continue;
    }
    const name = uniqueName(taken, f.wanted);
    taken.add(name.toLowerCase());
    if (name === f.wanted) {
      out.push({ ...f, action: 'upload', name });
    } else {
      const kept = existing.find((a) => a.filename.toLowerCase() === f.wanted.toLowerCase());
      out.push({ ...f, action: 'upload-renamed', name, keptId: kept?.id });
    }
  }
  return out;
}

/**
 * The imported source with every literal that names a bundle image pointed at
 * the asset that image became: `"/assets/<name>"`. A literal that already
 * resolves there is left exactly as written (`"assets/cover.png"` stays), so
 * a template imported into an empty workspace arrives byte for byte.
 * `names` maps a bundle path to the stored filename.
 */
export function rewriteReportSource(source: string, dir: string, names: ReadonlyMap<string, string>): string {
  let out = '';
  let at = 0;
  for (const lit of stringLiterals(source)) {
    if (bundleKind(lit.value) !== 'image') continue;
    const resolved = resolveReportPath(dir, lit.value);
    const name = resolved ? names.get(resolved) : undefined;
    if (!name) continue;
    const target = `/assets/${name}`;
    // Where the literal lands in BTCT, where main.typ is /main.typ.
    const lands = resolveReportPath('', lit.value);
    if (lands !== null && `/${lands}` === target) continue;
    out += source.slice(at, lit.from) + JSON.stringify(target);
    at = lit.to;
  }
  return out + source.slice(at);
}

/**
 * The report source as text: UTF-8 with a BOM dropped and CRLF made LF (the
 * editor writes LF, and a CRLF source would diff as a change on every line).
 */
export function decodeReportSource(bytes: Uint8Array): string {
  const text = new TextDecoder('utf-8').decode(bytes);
  return text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
}

/**
 * Basenames of the assets a report source names (`"assets/x"` or
 * `"/assets/x"`, the compile root's assets folder), for the export. Same
 * rule as the server export's `referencedAssetNames`, minus subfolders,
 * which BTCT never mounts.
 */
export function referencedAssetFilenames(source: string): Set<string> {
  const out = new Set<string>();
  for (const lit of stringLiterals(source)) {
    const p = resolveReportPath('', lit.value);
    if (p && p.startsWith('assets/') && !p.slice(7).includes('/')) out.add(p.slice(7));
  }
  return out;
}

/** Equal bytes, compared without converting either array. */
export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
  return true;
}
