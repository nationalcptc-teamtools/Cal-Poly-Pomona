// One export's working directory: main.typ, baked images under assets/, the
// workspace's own fonts under fonts/. Always removed by the caller's finally.
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readTypstSource, listAssetRecords } from '../yjs-data.mjs';
import { ASSETS_DIR } from '../data-export.mjs';
import { getAsset } from '../db.mjs';
import { vetAssetRecord } from './vet-asset.mjs';
import { imageSize, looksLikeSvg, svgRefusal } from './image-size.mjs';
import { createPixelBudget } from './pixel-budget.mjs';
import { referencedAssetNames } from './referenced-assets.mjs';
import { bakeFailureMessage, scrubPaths } from './diagnostics.mjs';
import { childEnv } from './child-env.mjs';
import { hasBlurs } from '../../src/lib/blur-math.ts';
import { isFullFrame } from '../../src/lib/crop-math.ts';

export class ExportError extends Error {
  constructor(status, message, diagnostics) { super(message); this.status = status; this.diagnostics = diagnostics; }
}

// Everything the report references plus its fonts has to fit in memory on a
// 1 GB box twice over (read, then bake), so there is a ceiling. Uploads are
// capped at 25 MB each, so this is a few dozen screenshots, far more than a
// real report places.
const MAX_STAGED_MB = 200;
const MAX_STAGED_BYTES = MAX_STAGED_MB * 1024 * 1024;

// File bytes say nothing about what a decode costs. A 6000x6000 PNG of flat
// colour encodes to 0.81 MB and measured 2192 MB of RSS through this server's
// own bakeImage, which is twice the target box. So every staged image is
// sized from its header first (typst decodes the un-baked ones itself, so the
// cap applies to those too), and one export gets a cumulative decode budget
// on top: the bakes are sequential, so this bounds time rather than peak
// memory, and it stops a report from parking a core for a minute.
//
// The per-image ceiling is measured, not guessed. Peak working set of this
// server for
// one export of a blurred PNG, each on a freshly started process whose
// baseline was 233 MB (2026-09-19, jimp 1.6, Windows):
//
//     3.7 MP (2560x1440)   405 MB
//     8.3 MP (3840x2160)   654 MB
//     9.0 MP (3000x3000)   689 MB
//    12.0 MP (3464x3464)   840 MB
//    16.0 MP (4000x4000)  1027 MB
//    25.0 MP (5000x5000)  1361 MB
//
// That is about 50 MB of peak per megapixel, on a box with 1 GB for
// everything including the Yjs relay. 10 MP is the first round number above
// a 4K screenshot (8.3 MP), which has to keep working, and it lands near
// 730 MB. A 5K screenshot is refused and exports from the browser instead.
const MAX_MEGAPIXELS = 10;
const MAX_PIXELS = MAX_MEGAPIXELS * 1_000_000;
const SVG_NAME = /\.svg$/i;

// Per image, not per export: the 120 s the compile gets was chosen for a
// whole document, and one 10 MP bake measured under three seconds. Before
// this, bakeImage had no timeout at all.
const BAKE_TIMEOUT_MS = 30_000;
// Resolved from this module's own URL, so it does not depend on cwd (the
// children run with their output directory as cwd).
const BAKE_WORKER = fileURLToPath(new URL('./bake-worker.mjs', import.meta.url));

function statOrNull(file) {
  try { return fs.statSync(file); } catch { return null; }
}

async function statOrNullAsync(file) {
  try { return await fs.promises.stat(file); } catch { return null; }
}

/**
 * Decide the whole export before any of it is done.
 *
 * Every refusal this function can reach lives here, in a loop that reads each
 * file once to size it from its header and then drops the buffer. Nothing is
 * decoded, nothing is baked, nothing is written, and no directory exists yet,
 * so a report the server will not export is refused in milliseconds. Before
 * this split the budget was charged as images were staged, and the
 * thirteenth screenshot's 422 arrived 10.6 s and 829 MiB after the first
 * twelve had already been baked.
 *
 * Returns the plan: one small entry per file, holding paths and numbers and
 * never bytes.
 */
async function planReport(workspaceId, source, records) {
  const referenced = referencedAssetNames(source);
  const plan = [];
  const claimed = new Set();
  const warnings = [];
  let skippedDuplicates = 0;
  let stagedBytes = 0;
  const budget = createPixelBudget();
  const account = (n) => {
    stagedBytes += n;
    if (stagedBytes > MAX_STAGED_BYTES) {
      throw new ExportError(422, `this report's images and fonts total more than ${MAX_STAGED_MB} MB, too much to export on this server`);
    }
  };

  for (const a of records) {
    // Every field that reaches the filesystem is vetted first, and `kind`
    // comes back from the server's own inventory rather than the record.
    // A record that fails is skipped without a word: it cannot be a real
    // upload, so there is nothing to tell the operator about.
    const id = typeof a?.id === 'string' ? a.id : '';
    const vetted = vetAssetRecord(a, id ? getAsset(id) : null, workspaceId, ASSETS_DIR);
    if (!vetted.ok) continue;
    const { from, name } = vetted;
    const stat = statOrNull(from);
    if (!stat || !stat.isFile()) continue; // Typst reports the unresolved path against its line
    const kind = vetted.kind === 'font' ? 'font' : 'image';
    if (kind !== 'font' && !referenced.has(name)) continue;
    // Two records can carry the same filename: the Assets Manager
    // de-duplicates on upload, but records sync through a CRDT any client
    // can write. Overwriting the first with the second's bytes would
    // silently put the wrong picture under a caption, so keep the first
    // and say so. Fonts and images land in different directories, so the
    // same name in both is not a clash.
    const slot = `${kind}/${name}`;
    if (claimed.has(slot)) {
      skippedDuplicates += 1;
      warnings.push(`Two assets are named ${name}; only the first was used.`);
      continue; // charged for nothing: pass 2 will not stage it either
    }
    claimed.add(slot);
    if (kind === 'font') {
      account(stat.size);
      plan.push({ from, name, kind, size: stat.size, mayBake: false, crop: null, blurs: null, dims: null });
      continue;
    }
    // Reading the file is cheap and bounded by the 25 MB upload cap;
    // decoding it is what has to be refused, so the header decides. The
    // buffer goes out of scope at the end of this iteration: nothing here
    // accumulates image bytes.
    const bytes = new Uint8Array(await fs.promises.readFile(from));
    const dims = imageSize(bytes);
    // Exactly what bakeImage acts on, from the same two predicates it uses,
    // so the parent's decision and the child's cannot drift. It has to be
    // exact in both directions: an image this calls bakeable and bakeImage
    // declines would fail the export, and one this calls plain while
    // bakeImage would have redacted it must not exist at all.
    const mayBake = (!!a.crop && !isFullFrame(a.crop)) || hasBlurs(a.blurs);
    // The .svg name is what buys the unsized exemption below, and typst
    // picks its decoder from that name too, so the bytes have to agree
    // with it either way, and an SVG that could hide a raster inside
    // itself does not get the exemption at all.
    if (SVG_NAME.test(name)) {
      const refusal = svgRefusal(bytes, name);
      if (refusal) throw new ExportError(422, refusal);
      if (!looksLikeSvg(bytes)) {
        throw new ExportError(422, `${name}: this file is named .svg but does not contain SVG, so it cannot be exported from the server.`);
      }
    }
    if (!dims) {
      // Nothing unsized reaches a decoder. An un-baked image is still
      // decoded, by the typst child rather than by jimp: a 5560-byte
      // 12000x12000 lossless WebP took it to a 958 MB working set, which
      // is the whole container. SVG is the single exemption, because it
      // has no pixel dimensions to read and rasterizes at the size the
      // layout asks for, and it has to look like SVG to claim it.
      if (!(SVG_NAME.test(name) && looksLikeSvg(bytes))) {
        throw new ExportError(422, `${name}: this image's size could not be read, so it cannot be exported from the server.`);
      }
      // Only an SVG reaches this line, so this is the SVG-with-a-redaction
      // refusal and it says so. A full-frame crop is not a redaction and no
      // longer trips it.
      if (mayBake) {
        throw new ExportError(422, `${name}: SVG images cannot be redacted on the server. Export the PDF from the browser instead.`);
      }
    } else if (dims.width * dims.height > MAX_PIXELS) {
      throw new ExportError(422, `${name} is too large to export from the server (${dims.width} x ${dims.height}). Export the PDF from the browser instead, or downscale the screenshot.`);
    }
    // Counted for every staged raster, redacted or not. This replaces a
    // budget that only counted images with a crop or a blur on them, which
    // left the common case (placed screenshots, nothing redacted) with no
    // total bound at all: typst holds each decoded bitmap while it writes
    // the PDF, so file bytes never stood in for it.
    const overBudget = budget.add(dims);
    if (overBudget) throw new ExportError(422, overBudget);
    account(stat.size);
    plan.push({ from, name, kind, size: stat.size, mayBake, crop: a.crop ?? null, blurs: a.blurs ?? null, dims });
  }

  return { plan, warnings, skippedDuplicates, account };
}

/** Run one bake worker to completion. Never rejects: it reports how it ended. */
function runBakeWorker(args, cwd) {
  return new Promise((resolve) => {
    // execFile, the asynchronous one. NEVER execFileSync or spawnSync: a
    // synchronous spawn blocks the event loop for the whole bake, which is
    // precisely the relay stall this child process exists to remove, only
    // with the memory cost moved and the pause left behind.
    execFile(process.execPath, args, {
      cwd, env: childEnv(), windowsHide: true, maxBuffer: 1024 * 1024,
      timeout: BAKE_TIMEOUT_MS, killSignal: 'SIGKILL',
    }, (err, _stdout, stderr) => {
      resolve({
        code: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
        killed: !!(err && err.killed), // and only this means our own timeout fired
        signal: err?.signal ?? null,
        stderr: String(stderr ?? ''),
      });
    });
  });
}

/**
 * Redact one image in a short-lived child, or stop the export.
 *
 * The parent never holds the original bytes for an image it is redacting:
 * the child is given the vetted absolute path and reads the file itself, and
 * it writes into a directory outside the typst compile root, so an
 * unredacted original is never written inside the root even for an instant.
 *
 * Success is BOTH a result file saying ok AND a non-empty output file.
 * Anything else is a 422. There is deliberately no branch that stages the
 * original instead, and there must never be one.
 */
async function bakeInChild(bakeRoot, item, index) {
  const dir = path.join(bakeRoot, String(index));
  await fs.promises.mkdir(dir);
  const meta = JSON.stringify({ crop: item.crop, blurs: item.blurs }); // small, so one argv value
  const child = await runBakeWorker([BAKE_WORKER, item.from, dir, item.name, meta], dir);

  // null means no result file at all, which is the only case where the
  // child's stderr is the best thing left to say.
  let resultOk = false;
  let resultMessage = null;
  try {
    const parsed = JSON.parse(await fs.promises.readFile(path.join(dir, 'result.json'), 'utf8'));
    resultOk = parsed?.ok === true;
    // The child names the file it was given, which is an absolute path under
    // ASSETS_DIR, and this message goes into a response body. Stays null when
    // there was no result file: that is what tells bakeFailureMessage to fall
    // back to the child's stderr.
    resultMessage = typeof parsed?.message === 'string' ? scrubPaths(parsed.message, ASSETS_DIR) : '';
  } catch { /* the child died before it could say anything */ }

  const out = path.join(dir, 'out.bin');
  const size = (await statOrNullAsync(out))?.size ?? 0;
  if (!resultOk || size <= 0) {
    throw new ExportError(422, bakeFailureMessage({
      code: child.code,
      killed: child.killed,
      signal: child.signal,
      // The child only ever sees paths under ASSETS_DIR and its own bake
      // directory; the second is handled by the staging marker.
      stderr: scrubPaths(child.stderr, ASSETS_DIR),
      resultOk,
      resultMessage,
      outputExists: size > 0,
    }, item.name));
  }
  return { file: out, size };
}

export async function stageReport(workspaceId) {
  const source = await readTypstSource(workspaceId);
  if (source === null) throw new ExportError(404, 'this workspace has no report yet');
  const records = await listAssetRecords(workspaceId);
  const { plan, warnings, skippedDuplicates, account } = await planReport(workspaceId, source, records);

  // Only now does anything land on disk. Nothing may sit between this line
  // and the try: the finally below is what removes the directory on every
  // failing path, and the caller's own finally only starts once this returns
  // the root successfully.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'btct-typst-'));
  // Where the bake children write. Outside the compile root on purpose, and
  // created only if something is actually redacted.
  let bakeRoot = null;
  let handedOver = false;
  try {
    fs.mkdirSync(path.join(root, 'assets'));
    fs.mkdirSync(path.join(root, 'fonts'));
    await fs.promises.writeFile(path.join(root, 'main.typ'), source);
    let baked = 0;
    for (let i = 0; i < plan.length; i += 1) {
      const item = plan[i];
      const dest = path.join(root, item.kind === 'font' ? 'fonts' : 'assets', item.name);
      // Nothing to apply: the file is copied as it is, and no child runs.
      // This is the one path on which original bytes reach the compile root,
      // and `mayBake` is what keeps a redacted image off it.
      if (!item.mayBake) { await fs.promises.copyFile(item.from, dest); continue; }
      bakeRoot ??= await fs.promises.mkdtemp(path.join(os.tmpdir(), 'btct-bake-'));
      // One child per image, sequential. Not pooled and not parallel:
      // serial.mjs and the admission gate already allow one export at a
      // time, and typst runs after every bake has finished.
      const out = await bakeInChild(bakeRoot, item, i);
      // The byte ceiling was charged from the file's size in pass 1; a
      // re-encode can grow, so the difference is charged here and "200 MB
      // of staged files" stays true.
      account(Math.max(0, out.size - item.size));
      await fs.promises.rename(out.file, dest);
      baked += 1;
    }
    handedOver = true;
    return { root, source, baked, skippedDuplicates, warnings };
  } finally {
    // The bake directory is finished with the moment staging is: every file
    // still in it is a leftover. The compile root belongs to the caller once
    // this function returns it, and to this finally until then.
    if (bakeRoot) await unstage(bakeRoot);
    if (!handedOver) await unstage(root);
  }
}

export async function unstage(root) {
  // Never throws: this runs from a finally, where a second error would
  // replace the one the caller needs to see. The retries are for Windows,
  // where a file a just-killed child had open answers EBUSY for a moment,
  // and giving up there would leave screenshots in the OS temp directory.
  // The promises form retries without the synchronous sleep rmSync does.
  try { await fs.promises.rm(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 }); }
  catch (err) { console.error('[typst] could not remove the staged directory', err); }
}
