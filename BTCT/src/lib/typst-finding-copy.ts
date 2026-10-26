// ─────────────────────────────────────────────────────────────────────────
// Copy a finding block and paste it into another report.
//
// The clipboard payload is plain text that is still the Typst block, so a
// paste into any editor or .typ file just works, with one comment line on
// top that says where it came from:
//
//   // @btct-finding-copy v=1 workspace=<source workspace id>
//   // @finding id=fb-k3x9q2 status=written
//   #finding(
//     level: "high",
//     ...
//   )
//
// A comment renders nothing, so the payload compiles as it is. Paste in the
// Findings rail recognises the header (or, without one, any text holding a
// `#finding(...)` call), gives every pasted block a new id that is free in
// the target report, keeps its status, fits its `#end-of-block` to the
// target and inserts it in its severity section. The workspace id lets the
// rail copy the screenshots the block names (`/assets/<file>`) from the
// source workspace's asset records; everything about assets here is pure
// path bookkeeping, the bytes are moved by FindingsPanel.
//
// Pure, and lazy with the Report tab (invariant 17).
// ─────────────────────────────────────────────────────────────────────────

import {
  allowNoSeverity,
  dedent,
  ensureCmdHelper,
  ensureFindingHelper,
  findFindings,
  findingAcceptsNoSeverity,
  findingText,
  hasEndOfBlock,
  insertFinding,
  isNoSeverity,
  markerLine,
  newFindingId,
  type FindingBlock,
  type SeverityPick,
} from './typst-findings';
import { ensureHelper } from './typst-placeholders';

export const FINDING_COPY_TAG = '@btct-finding-copy';
const HEADER_RE = /^[ \t]*\/\/[ \t]*@btct-finding-copy\b([^\n]*)$/m;

/** The clipboard text for one block of `src`. */
export function findingCopyPayload(src: string, f: FindingBlock, workspaceId: string | null): string {
  const ws = workspaceId && /^[A-Za-z0-9_-]{1,64}$/.test(workspaceId) ? ` workspace=${workspaceId}` : '';
  return `// ${FINDING_COPY_TAG} v=1${ws}\n${dedent(findingText(src, f))}\n`;
}

export interface FindingPayload {
  /** The workspace the blocks were copied from; null when the text carries no header. */
  workspaceId: string | null;
  /** Each block's text (marker, call and any `#end-of-block`), dedented. */
  blocks: string[];
}

/**
 * Read pasted text: the blocks it holds, and the source workspace when it
 * carries BTCT's header. Null when there is no complete `#finding(...)` call.
 */
export function parseFindingPayload(text: string): FindingPayload | null {
  const t = text.replace(/\r\n?/g, '\n');
  const blocks = findFindings(t);
  if (blocks.length === 0) return null;
  const header = HEADER_RE.exec(t);
  let workspaceId: string | null = null;
  if (header) {
    const m = /\bworkspace=([A-Za-z0-9_-]{1,64})\b/.exec(header[1]!);
    workspaceId = m ? m[1]! : null;
  }
  return { workspaceId, blocks: blocks.map((f) => dedent(findingText(t, f))) };
}

// ── asset paths ──────────────────────────────────────────────────────────

const PATH_RE = /"\/assets\/([^"\\\n/]+)"/g;

/** The file names a block references as `"/assets/<file>"`, in order, once each. */
export function assetFilesIn(text: string): string[] {
  const out: string[] = [];
  PATH_RE.lastIndex = 0;
  for (let m = PATH_RE.exec(text); m; m = PATH_RE.exec(text)) if (!out.includes(m[1]!)) out.push(m[1]!);
  return out;
}

/** `text` with every `"/assets/<old>"` that `renames` names pointed at the new file. */
export function rewriteAssetPaths(text: string, renames: ReadonlyMap<string, string>): string {
  if (renames.size === 0) return text;
  return text.replace(PATH_RE, (whole, file: string) => {
    const next = renames.get(file);
    return next ? `"/assets/${next}"` : whole;
  });
}

/** What to do with each referenced file when pasting into another workspace. */
export type AssetPlan =
  | { file: string; action: 'keep'; as?: string }
  | { file: string; action: 'copy'; sourceId: string }
  | { file: string; action: 'missing' };

export interface AssetLike {
  id: string;
  filename: string;
  kind?: string;
  deletedAt?: number | null;
}

/**
 * Decide, per referenced file, whether the target already has it (`keep`,
 * with `as` when the target's copy has another name, as an earlier paste's
 * renamed copy does), it has to be copied from the source workspace
 * (`copy`), or it cannot be found anywhere (`missing`). Same workspace, or
 * no source: never copies. `identical` names a target image that is the
 * same picture as a source one (bytes and framing), so pasting the same
 * finding twice copies nothing the second time; a same-named target file
 * that is a different image is a collision, and the copy gets a new name
 * (the caller's upload picks it).
 */
export function planAssetCopies(
  files: readonly string[],
  opts: {
    sourceWorkspaceId: string | null;
    targetWorkspaceId: string;
    source: readonly AssetLike[];
    target: readonly AssetLike[];
    identical?: (sourceId: string) => string | null;
  },
): AssetPlan[] {
  const live = (list: readonly AssetLike[]) => list.filter((a) => !a.deletedAt && (a.kind === undefined || a.kind === 'image'));
  const target = live(opts.target);
  const source = live(opts.source);
  const byName = (list: AssetLike[], file: string) =>
    list.find((a) => a.filename === file) ?? list.find((a) => a.filename.toLowerCase() === file.toLowerCase());
  const cross = opts.sourceWorkspaceId !== null && opts.sourceWorkspaceId !== opts.targetWorkspaceId;
  return files.map((file): AssetPlan => {
    const here = byName(target, file);
    if (!cross) return here ? { file, action: 'keep' } : { file, action: 'missing' };
    const there = byName(source, file);
    if (!there) return here ? { file, action: 'keep' } : { file, action: 'missing' };
    const same = opts.identical?.(there.id) ?? null;
    if (same !== null && target.some((a) => a.filename === same)) {
      return same === file ? { file, action: 'keep' } : { file, action: 'keep', as: same };
    }
    return { file, action: 'copy', sourceId: there.id };
  });
}

// ── into the report ──────────────────────────────────────────────────────

/** An id not used by any block of `src` (nor in `taken`). */
export function freshFindingId(src: string, taken: ReadonlySet<string> = new Set(), rand: () => number = Math.random): string {
  const used = new Set(findFindings(src).map((f) => f.id).filter((x): x is string => !!x));
  for (let i = 0; i < 1000; i++) {
    const id = newFindingId(rand);
    if (!used.has(id) && !taken.has(id)) return id;
  }
  return `fb-${Date.now().toString(36)}`;
}

/**
 * One pasted block made ready for `target`: a marker with a new id and the
 * block's status (its tag, else what it reads as), its `#end-of-block` kept
 * only when the target defines one (and added when it does), and the
 * severity it is filed under. Null when the text holds no block.
 */
export function reidentifyBlock(
  target: string,
  blockText: string,
  opts: { id: string },
): { text: string; severity: SeverityPick; noSeverity: boolean; title: string } | null {
  const t = dedent(blockText.replace(/\r\n?/g, '\n'));
  const [f] = findFindings(t);
  if (!f) return null;
  const status = f.tag ?? f.status;
  const call = t.slice(f.callStart, f.callClose + 1);
  const wantEnd = hasEndOfBlock(target);
  // The block's own page break (part of the block) is kept as it was, never added.
  const brk = f.pagebreakStart === null ? '' : `${t.slice(f.pagebreakStart, t.indexOf('\n', f.pagebreakStart)).trim()}\n`;
  const text = `${brk}${markerLine(opts.id, status)}\n${call}${wantEnd ? '\n\n#end-of-block' : ''}`;
  const noSeverity = f.severity === null && isNoSeverity(t, f);
  return { text, severity: f.severity, noSeverity, title: f.title };
}

export type PasteResult =
  | { ok: true; source: string; ids: string[]; titles: string[] }
  | { ok: false; reason: 'empty' | 'no-severity' };

/**
 * Insert pasted blocks into a report, as Add does: BTCT's `#finding` helper
 * when the report has none, the figure-slot and `cmd` helpers when a block
 * uses them, and the No severity rule (a report whose `#finding` cannot
 * draw `level: none` is taught to, else the paste is refused). Every block
 * gets a new id, so a paste into the same report is a duplicate, never a
 * second block with the same id.
 */
export function pasteFindings(
  current: string,
  blocks: readonly string[],
  opts: { rand?: () => number } = {},
): PasteResult {
  if (blocks.length === 0) return { ok: false, reason: 'empty' };
  let src = ensureFindingHelper(current).source;
  const ids: string[] = [];
  const titles: string[] = [];
  const taken = new Set<string>();
  for (const raw of blocks) {
    const id = freshFindingId(src, taken, opts.rand);
    const ready = reidentifyBlock(src, raw, { id });
    if (!ready) continue;
    if (ready.noSeverity && !findingAcceptsNoSeverity(src)) {
      const taught = allowNoSeverity(src);
      if (taught === null) return { ok: false, reason: 'no-severity' };
      src = taught;
    }
    if (ready.text.includes('#image-placeholder(')) src = ensureHelper(src).source;
    if (ready.text.includes('#cmd[') || ready.text.includes('#cmd(')) src = ensureCmdHelper(src).source;
    const pick: SeverityPick = ready.noSeverity ? null : ready.severity;
    src = insertFinding(src, ready.text, pick);
    taken.add(id);
    ids.push(id);
    titles.push(ready.title);
  }
  if (ids.length === 0) return { ok: false, reason: 'empty' };
  return { ok: true, source: src, ids, titles };
}
