// ─────────────────────────────────────────────────────────────────────────
// Every file and folder name an export writes, decided in one pure module.
//
// A ZIP is extracted on Linux (ext4: 255 bytes a name), Windows (device
// names, no trailing dot or space, case-insensitive, 260-character paths in
// Explorer) and macOS (case-insensitive, NFD on disk). JSZip silently
// replaces an entry that has the same name as an earlier one, so two pages
// called "Untitled" used to become one file. Everything here is DOM-free and
// unit-tested (src/test/export-names.test.ts).
// ─────────────────────────────────────────────────────────────────────────

/** Byte cap for any path segment an export writes. */
export const NOTE_SEGMENT_BYTES = 60;
/** What a note folder's name gets appended for its own files. */
export const ATTACHMENTS_SUFFIX = '.attachments';
/**
 * Byte cap for a note title: its folder name is also the stem of
 * `<Title>.md` and `<Title>.attachments`, and those must stay within
 * NOTE_SEGMENT_BYTES too (a 60-byte title made a 72-byte segment).
 */
export const NOTE_TITLE_BYTES = NOTE_SEGMENT_BYTES - ATTACHMENTS_SUFFIX.length;
/** Byte cap for a picture folder's stem. */
export const PICTURE_STEM_BYTES = 40;
/** Paths longer than this are listed in README.md (Windows Explorer chokes on them). */
export const WINDOWS_PATH_WARN = 240;

// `/ \ ? % * : | " < >`: illegal or awkward on at least one platform.
const ILLEGAL_RE = /[/\\?%*:|"<>]/g;
// C0 and C1 control characters and DEL.
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/g;
// A lone surrogate cannot be encoded as UTF-8 or passed to encodeURIComponent.
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;
const DEVICE_RE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;
const TRIM_RE = /^[\s.]+|[\s.]+$/g;

const encoder = new TextEncoder();

/** UTF-8 byte length of `s`. */
export function utf8Length(s: string): number {
  return encoder.encode(s).length;
}

/** Cut `s` to at most `maxBytes` UTF-8 bytes without splitting a code point. */
export function capUtf8(s: string, maxBytes: number): string {
  if (maxBytes <= 0) return '';
  let bytes = 0;
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    const n = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    if (bytes + n > maxBytes) break;
    bytes += n;
    out += ch;
  }
  return out;
}

function trimEnds(s: string): string {
  return s.replace(TRIM_RE, '');
}

function guardDevice(s: string): string {
  // "CON" and "con.txt" are both device names on Windows: put the mark on the
  // base name so an extension stays an extension.
  return DEVICE_RE.test(s) ? s.replace(/^([^.]*)/, '$1_') : s;
}

/**
 * One portable path segment: NFC, no illegal or control characters, single
 * spaces, no leading or trailing dots and spaces, never empty, never a
 * Windows device name, at most `maxBytes` UTF-8 bytes.
 */
export function sanitizeSegment(name: unknown, maxBytes = NOTE_SEGMENT_BYTES): string {
  let s = typeof name === 'string' ? name : name == null ? '' : String(name);
  s = s.replace(LONE_SURROGATE_RE, '_').normalize('NFC');
  s = s.replace(CONTROL_RE, '_').replace(ILLEGAL_RE, '_');
  s = s.replace(/\s+/g, ' ');
  s = trimEnds(s);
  if (!s) s = 'Untitled';
  s = guardDevice(s);
  s = trimEnds(capUtf8(s, maxBytes));
  if (!s) s = 'Untitled';
  return guardDevice(s);
}

/** Split `name.ext` (the extension without its dot, lowercased; '' if none). */
export function splitExtension(name: string): { stem: string; ext: string } {
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot === name.length - 1) return { stem: name, ext: '' };
  const ext = name.slice(dot + 1);
  if (!/^[A-Za-z0-9]{1,10}$/.test(ext)) return { stem: name, ext: '' };
  return { stem: name.slice(0, dot), ext: ext.toLowerCase() };
}

/** A file name whose stem is sanitized and capped and whose extension survives the cap. */
export function sanitizeFileName(name: unknown, maxBytes = NOTE_SEGMENT_BYTES): string {
  const raw = typeof name === 'string' ? name : '';
  const { stem, ext } = splitExtension(raw.trim());
  if (!ext) return sanitizeSegment(raw, maxBytes);
  const suffix = `.${ext}`;
  const base = sanitizeSegment(stem, Math.max(1, maxBytes - suffix.length));
  return `${base}${suffix}`;
}

function nameKey(name: string): string {
  return name.normalize('NFC').toLowerCase();
}

/**
 * The names already used in one directory, compared the way Windows and
 * macOS compare them (case-insensitively). `claim` returns the name itself
 * when it is free, else `name-2`, `name-3`, ... still within the byte cap.
 */
export class DirectoryNames {
  private readonly taken = new Set<string>();

  constructor(private readonly maxBytes = NOTE_SEGMENT_BYTES) {}

  /** Mark a name as used without claiming it through dedupe. */
  reserve(name: string): void {
    this.taken.add(nameKey(name));
  }

  has(name: string): boolean {
    return this.taken.has(nameKey(name));
  }

  /** `isFile`: keep a file's extension after the `-N` suffix (`font-2.ttf`, not `font.ttf-2`). */
  claim(name: string, isFile = false): string {
    if (!this.has(name)) {
      this.reserve(name);
      return name;
    }
    const { stem, ext } = isFile ? splitExtension(name) : { stem: name, ext: '' };
    const extPart = ext ? `.${ext}` : '';
    for (let n = 2; ; n++) {
      const suffix = `-${n}${extPart}`;
      const base = trimEnds(capUtf8(stem, this.maxBytes - utf8Length(suffix))) || 'Untitled';
      const candidate = `${base}${suffix}`;
      if (!this.has(candidate)) {
        this.reserve(candidate);
        return candidate;
      }
    }
  }
}

/** Sanitize then dedupe a list of names for one directory, in order. */
export function dedupeNames(names: string[], maxBytes = NOTE_SEGMENT_BYTES, reserved: string[] = []): string[] {
  const dir = new DirectoryNames(maxBytes);
  for (const r of reserved) dir.reserve(r);
  return names.map((n) => dir.claim(sanitizeSegment(n, maxBytes)));
}

// ── Page tree ────────────────────────────────────────────────────────────

export interface TreePage {
  id: string;
  parentId?: string | null;
  title?: string;
  sortOrder?: number;
}

export interface TreeNode<P extends TreePage> {
  page: P;
  children: TreeNode<P>[];
}

function siblingOrder(a: TreePage, b: TreePage): number {
  const sa = Number.isFinite(a.sortOrder) ? (a.sortOrder as number) : 0;
  const sb = Number.isFinite(b.sortOrder) ? (b.sortOrder as number) : 0;
  if (sa !== sb) return sa - sb;
  const t = (a.title ?? '').localeCompare(b.title ?? '');
  return t !== 0 ? t : a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/**
 * Nest pages under their parents. A page whose parent is missing, outside
 * the set, or part of a loop goes to the top level. Loops are found with a
 * visited set, never by recursion depth, and the walk itself is iterative.
 */
export function buildPageForest<P extends TreePage>(pages: P[]): TreeNode<P>[] {
  const byId = new Map(pages.map((p) => [p.id, p] as const));
  const children = new Map<string, P[]>();
  const roots: P[] = [];
  for (const p of pages) {
    const parent = p.parentId && p.parentId !== p.id ? byId.get(p.parentId) : undefined;
    if (!parent) { roots.push(p); continue; }
    const list = children.get(parent.id) ?? [];
    list.push(p);
    children.set(parent.id, list);
  }
  for (const list of children.values()) list.sort(siblingOrder);
  roots.sort(siblingOrder);

  const visited = new Set<string>();
  const out: TreeNode<P>[] = [];
  const attach = (rootPage: P): TreeNode<P> => {
    const root: TreeNode<P> = { page: rootPage, children: [] };
    visited.add(rootPage.id);
    const stack: TreeNode<P>[] = [root];
    while (stack.length) {
      const node = stack.pop()!;
      for (const child of children.get(node.page.id) ?? []) {
        if (visited.has(child.id)) continue;
        visited.add(child.id);
        const childNode: TreeNode<P> = { page: child, children: [] };
        node.children.push(childNode);
        stack.push(childNode);
      }
    }
    return root;
  };
  for (const r of roots) out.push(attach(r));
  // Whatever is left sits on (or under) a parent loop: lift the first page of
  // each loop to the top level and hang the rest of the loop under it.
  const rest = pages.filter((p) => !visited.has(p.id)).sort(siblingOrder);
  for (const p of rest) {
    if (!visited.has(p.id)) out.push(attach(p));
  }
  return out;
}

// ── Asset links in markdown ──────────────────────────────────────────────

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
/** `![alt](asset:<uuid>)` or `![alt](asset:<uuid> "title")`. */
const ASSET_IMAGE_RE = new RegExp(`!\\[((?:\\\\.|[^\\]\\\\])*)\\]\\(asset:(${UUID})(\\s+"[^"]*")?\\)`, 'g');

/** Asset ids a note's markdown shows as images, in order of first appearance. */
export function assetIdsInMarkdown(markdown: string): string[] {
  const seen = new Set<string>();
  for (const m of markdown.matchAll(ASSET_IMAGE_RE)) {
    const id = (m[2] ?? '').toLowerCase();
    if (id) seen.add(id);
  }
  return [...seen];
}

/**
 * Rewrite each `![alt](asset:<uuid>)` whose id `resolve` knows to its
 * relative path. Ids it does not know are left as written and returned in
 * `unresolved`. Non-asset images are not touched.
 */
export function rewriteAssetLinks(
  markdown: string,
  resolve: (assetId: string) => string | null | undefined,
): { text: string; unresolved: string[] } {
  const unresolved = new Set<string>();
  const text = markdown.replace(ASSET_IMAGE_RE, (whole, alt: string, id: string, title: string | undefined) => {
    const target = resolve(id.toLowerCase());
    if (!target) { unresolved.add(id.toLowerCase()); return whole; }
    return `![${alt}](${target}${title ?? ''})`;
  });
  return { text, unresolved: [...unresolved] };
}

/**
 * Replace `asset:<old>` with `asset:<new>` for every id in `map` (any id
 * shape; only mapped ids change). Used on import when uploads mint new ids.
 */
export function remapAssetIdsInMarkdown(markdown: string, map: ReadonlyMap<string, string>): string {
  if (!map.size || !markdown.includes('asset:')) return markdown;
  return markdown.replace(/asset:([A-Za-z0-9_-]+)/g, (whole, id: string) => {
    const next = map.get(id) ?? map.get(id.toLowerCase());
    return next ? `asset:${next}` : whole;
  });
}

/** A relative path made safe for a markdown link: each segment percent-encoded, parentheses included. */
export function encodeLinkPath(path: string): string {
  return path
    .split('/')
    .map((seg) => encodeURIComponent(seg).replace(/\(/g, '%28').replace(/\)/g, '%29'))
    .join('/');
}

// ── Root folder ──────────────────────────────────────────────────────────

function pad(n: number, width = 2): string {
  return String(n).padStart(width, '0');
}

/**
 * `<workspace name>_<YYYY-MM-DD_HHMM>` in local time: the ZIP's root folder
 * and file name. A `suffix` (already portable, for example `pdf`) is added
 * as `_<suffix>` after the stamp.
 */
export function exportRootName(workspaceName: string, at: Date, suffix = ''): string {
  const stamp = `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}_${pad(at.getHours())}${pad(at.getMinutes())}`;
  const tail = suffix ? `${stamp}_${suffix}` : stamp;
  // The whole root folder name is one segment, so the stamp counts against the cap.
  return `${sanitizeSegment(workspaceName, NOTE_SEGMENT_BYTES - tail.length - 1)}_${tail}`;
}

/** Zero-padded picture number: two digits, three when a note has 100 or more pictures. */
export function pictureNumber(index: number, total: number): string {
  return pad(index + 1, total >= 100 ? 3 : 2);
}
