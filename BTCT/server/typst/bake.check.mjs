// Run: bun server/typst/bake.check.mjs   (exits non-zero on failure)
//
// What this script proves, in four parts:
//
//   1. CORRELATION. The baked region no longer correlates with the pattern
//      that was there, and nothing outside the region moved.
//   2. THE PIXELATE BLOCK FLOOR. The output really is piecewise constant
//      over the block size `pixelParams` asks for, so the 8 px floor is
//      something bakeBlurs USES rather than something blur-math merely
//      returns.
//   3. THE GAUSSIAN DOWNSCALE. The real path differs by a wide margin from
//      a downscale-free control computed here, so dropping the two resizes
//      and keeping the blur fails.
//   4. THE WORKER HAND-OFF. The same image baked through a real
//      `bake-worker.mjs` child matches the in-process bytes, and an
//      un-bakeable input leaves no output file, a not-ok result and a
//      refusal from `bakeFailureMessage`. This is the only check that
//      guards the redaction guarantee across the process boundary.
//
// Part 1 alone is not enough, which is why parts 2 and 3 exist. A bake that
// does nothing scores 1.000 and a token blur (`piece.blur(1)`, no downscale)
// scores 0.464, so correlation catches a no-op and an obviously weak
// stand-in. It does NOT catch a weakened bake: measured on this pattern,
// a 2 px pixelate block scores 0.236 and a gaussian path that keeps the
// blur but drops the downscale scores 0.161, and both are under the 0.25
// limit. Parts 2 and 3 are aimed exactly at those two.
//
// The pattern is NON-PERIODIC on purpose: a periodic checkerboard can
// resonate with a fixed-size kernel and collapse to a flat extreme colour
// with zero correlation regardless of whether the blur is actually strong
// (a period-3 pattern averaged by a window-3 box blur did exactly that in
// an earlier review round). A seeded PRNG has no period a fixed kernel can
// exploit. 1px cells are the right scale because both blur paths operate
// at roughly 8px or coarser (pixelate's block-size floor; the gaussian
// downscale's effective stride).
//
// Every limit below is measured, not guessed (2026-09-19, jimp 1.6.1,
// against this pattern and this region):
//
//   real gaussian path (no `style`, the old-record fallback)  corr 0.003
//   real pixelate path (`style:'pixelate', strength:0.4`)     corr 0.033
//   downscale-free gaussian control, same radius              corr 0.161
//   2 px pixelate block                                       corr 0.236
//   no-op bakeBlurs                                           corr 1.000
//   `piece.blur(1)`, no downscale                             corr 0.464
//
//   pixelate blockPx from pixelParams                         8 px
//   runs across the 100 px region, real                       13x13, of 7 or 8 px
//   runs across the 100 px region, 2 px block                 21x25, shortest 2 px
//   gap between the real gaussian and the control             0.158
//   the same gap with the downscale dropped                   0.000
//
// The run-length rows are what part 2 asserts: 13 runs of 7 or 8 against 21
// with a 2 px minimum is a gap no rounding closes. Three negative controls
// were run against copies of bake.mjs and bake-worker.mjs, patched in place
// and restored, never committed: a 2 px block fails part 2 while scoring
// 0.236 on part 1, a downscale-free gaussian fails part 3 while scoring
// 0.161 on part 1, and a worker that writes the original bytes when
// bakeImage throws fails part 4 on "a failed bake must leave no output file
// at all".
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Jimp } from 'jimp';
import { bakeImage } from './bake.mjs';
import { blurParams, pixelParams } from '../../src/lib/blur-math.ts';
import { bakeFailureMessage } from './diagnostics.mjs';

// mulberry32: a small, fast, seeded PRNG. A fixed seed keeps the pattern,
// and therefore the numbers above, reproducible run to run.
function mulberry32(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Left 100x100 of a 200x100 canvas gets 1px black/white noise; the right
// half stays the canvas's white background, for the outside-region check.
const rand = mulberry32(0xc0ffee);
const img = new Jimp({ width: 200, height: 100, color: 0xffffffff });
for (let y = 0; y < 100; y += 1) for (let x = 0; x < 100; x += 1) if (rand() < 0.5) img.setPixelColor(0x000000ff, x, y);
const original = new Uint8Array(await img.getBuffer('image/png'));

function luma(color) {
  const r = (color >>> 24) & 0xff, g = (color >>> 16) & 0xff, b = (color >>> 8) & 0xff;
  return 0.299 * r + 0.587 * g + 0.114 * b;
}

function lumaGrid(jimpImg, x0, y0, x1, y1) {
  const values = [];
  for (let y = y0; y < y1; y += 1) for (let x = x0; x < x1; x += 1) values.push(luma(jimpImg.getPixelColor(x, y)));
  return values;
}

function pearson(a, b) {
  const n = a.length;
  const meanA = a.reduce((s, v) => s + v, 0) / n;
  const meanB = b.reduce((s, v) => s + v, 0) / n;
  let num = 0, denomA = 0, denomB = 0;
  for (let i = 0; i < n; i += 1) {
    const da = a[i] - meanA, db = b[i] - meanB;
    num += da * db;
    denomA += da * da;
    denomB += db * db;
  }
  const denom = Math.sqrt(denomA * denomB);
  return denom === 0 ? 0 : num / denom;
}

// Correlation between the baked output's luma and the original pattern's
// luma, over the region inset 8px on every edge to stay clear of the
// composite boundary.
function regionCorr(outImg) {
  return pearson(lumaGrid(outImg, 8, 8, 92, 92), lumaGrid(img, 8, 8, 92, 92));
}

// The whole right half of the canvas (never touched by any region in this
// script) must stay exactly the canvas background.
function assertUntouched(outImg, label) {
  for (let y = 0; y < 100; y += 1) {
    for (let x = 100; x < 200; x += 1) {
      if (outImg.getPixelColor(x, y) !== 0xffffffff) throw new Error(`${label}: pixel outside the region changed at (${x},${y})`);
    }
  }
}

const LIMIT = 0.25;
const REGION = { x: 0, y: 0, w: 0.5, h: 1 }; // the left half, exactly 100x100

// ── 1. correlation ───────────────────────────────────────────────────────

const same = await bakeImage(original, {}, 'a.png');
if (same !== null) throw new Error('no crop and no blur must return null');

const noBlurs = await bakeImage(original, { blurs: [] }, 'a.png');
if (noBlurs !== null) throw new Error('an empty blurs array must return null, same as no blurs at all');

const blurred = await bakeImage(original, { blurs: [REGION] }, 'a.png');
const out = await Jimp.read(Buffer.from(blurred));
const corrGaussian = regionCorr(out);
assertUntouched(out, 'gaussian');

const pixelated = await bakeImage(original, { blurs: [{ ...REGION, style: 'pixelate', strength: 0.4 }] }, 'a.png');
const outPixelated = await Jimp.read(Buffer.from(pixelated));
const corrPixelate = regionCorr(outPixelated);
assertUntouched(outPixelated, 'pixelate');

console.log(`gaussian: corr=${corrGaussian.toFixed(3)}  pixelate: corr=${corrPixelate.toFixed(3)}  (limit ${LIMIT})`);
if (Math.abs(corrGaussian) >= LIMIT) throw new Error(`gaussian region still correlates with the original pattern (corr=${corrGaussian.toFixed(3)})`);
if (Math.abs(corrPixelate) >= LIMIT) throw new Error(`pixelated region still correlates with the original pattern (corr=${corrPixelate.toFixed(3)})`);

// ── 2. the pixelate block floor ──────────────────────────────────────────
//
// blur-math's unit tests prove pixelParams returns a block of at least 8px.
// Nothing proved bakeBlurs uses it. The mosaic is a nearest-neighbour
// expansion of a round(100/blockPx) downscale, so the cell edges do not sit
// on an exact multiple of blockPx: over 100 px, a block of 8 comes out as 13
// runs of 7 or 8. A run shorter than blockPx - 1 means the floor is not in
// force, and a run count far over 100/blockPx means the same thing.

function runLengths(read, count) {
  const runs = [];
  let start = 0;
  let prev = read(0);
  for (let i = 1; i < count; i += 1) {
    const c = read(i);
    if (c !== prev) { runs.push(i - start); start = i; prev = c; }
  }
  runs.push(count - start);
  return runs;
}

const { blockPx } = pixelParams({ ...REGION, style: 'pixelate', strength: 0.4 }, 200, 100);
const rowRuns = runLengths((x) => outPixelated.getPixelColor(x, 50), 100);
const colRuns = runLengths((y) => outPixelated.getPixelColor(50, y), 100);
const shortestRun = Math.min(...rowRuns, ...colRuns);
const mostRuns = Math.max(rowRuns.length, colRuns.length);
const expectedRuns = Math.max(1, Math.round(100 / blockPx));
console.log(`pixelate: blockPx=${blockPx} runs=${rowRuns.length}x${colRuns.length} shortest=${shortestRun}px (2px blocks measured 21 runs, shortest 2)`);
if (blockPx < 8) throw new Error(`pixelParams returned a block below the 8px floor (${blockPx})`);
if (shortestRun < blockPx - 1) {
  throw new Error(`the mosaic has a ${shortestRun}px cell, under the ${blockPx}px block bakeBlurs was asked for`);
}
if (mostRuns > expectedRuns + 1) {
  throw new Error(`the mosaic has ${mostRuns} cells across 100px, more than the ${expectedRuns} a ${blockPx}px block gives`);
}
// Every cell is one pixel of the downscale, so it has to be flat in both
// directions, not just along a scanline. The cell edges come from the runs
// measured above, on both axes; nine cells is enough to say so.
const starts = (runs) => runs.reduce((acc, n) => [...acc, acc[acc.length - 1] + n], [0]);
const xEdges = starts(rowRuns);
const yEdges = starts(colRuns);
for (let cy = 0; cy < Math.min(3, colRuns.length); cy += 1) {
  for (let cx = 0; cx < Math.min(3, rowRuns.length); cx += 1) {
    const first = outPixelated.getPixelColor(xEdges[cx], yEdges[cy]);
    for (let y = yEdges[cy]; y < yEdges[cy + 1]; y += 1) {
      for (let x = xEdges[cx]; x < xEdges[cx + 1]; x += 1) {
        if (outPixelated.getPixelColor(x, y) !== first) {
          throw new Error(`mosaic cell at (${xEdges[cx]},${yEdges[cy]}) is not flat: (${x},${y}) differs from its first pixel`);
        }
      }
    }
  }
}

// ── 3. the gaussian downscale ────────────────────────────────────────────
//
// The downscale is what destroys the information; the gaussian only smooths
// the result so it reads as a blur. A bake that keeps `blur(radius/2)` and
// drops the two resizes scores 0.161 here, under the 0.25 limit, so the
// limit cannot see it. This control is that exact bake, computed in this
// script, and the real path has to beat it by a wide margin.

const { radiusPx } = blurParams(REGION, 200, 100);
const control = new Jimp({ width: 200, height: 100, color: 0xffffffff });
control.composite(img.clone(), 0, 0);
const flat = img.clone().crop({ x: 0, y: 0, w: 100, h: 100 });
flat.blur(Math.max(1, Math.round(radiusPx / 2))); // the same radius, no resizes
control.composite(flat, 0, 0);
const corrControl = regionCorr(control);
const gap = Math.abs(corrControl) - Math.abs(corrGaussian);
// Measured: control 0.161, real 0.003, gap 0.158. A bake that dropped the
// downscale would BE the control, so its gap would be 0.
const MIN_GAP = 0.10;
const MAX_REAL = 0.03;
console.log(`gaussian downscale: real=${corrGaussian.toFixed(3)} downscale-free control=${corrControl.toFixed(3)} gap=${gap.toFixed(3)} (min ${MIN_GAP})`);
if (gap < MIN_GAP) {
  throw new Error(`the gaussian path is no better than a downscale-free blur (real ${corrGaussian.toFixed(3)}, control ${corrControl.toFixed(3)})`);
}
if (Math.abs(corrGaussian) > MAX_REAL) {
  throw new Error(`the gaussian path retains ${corrGaussian.toFixed(3)} of the pattern, over the measured ${MAX_REAL}`);
}

// ── crop, formats ────────────────────────────────────────────────────────

const cropped = await bakeImage(original, { crop: { x: 0, y: 0, w: 0.5, h: 1 } }, 'a.png');
const c = await Jimp.read(Buffer.from(cropped));
if (c.bitmap.width !== 100 || c.bitmap.height !== 100) throw new Error(`crop size ${c.bitmap.width}x${c.bitmap.height}`);

let threw = false;
try { await bakeImage(original, { blurs: [{ x: 0, y: 0, w: 1, h: 1 }] }, 'a.webp'); } catch { threw = true; }
if (!threw) throw new Error('an un-bakeable format with a blur must throw, never pass through');

const uppercase = await bakeImage(original, { blurs: [REGION] }, 'shot.PNG');
if (uppercase === null) throw new Error('an uppercase extension must still be recognised and baked');

// ── 4. the worker hand-off ───────────────────────────────────────────────
//
// stage.mjs stages a redacted image only when the child's result.json says
// ok AND the output file is non-empty, and there is no branch that falls
// back to the original bytes. This runs a real child both ways.

const WORKER = fileURLToPath(new URL('./bake-worker.mjs', import.meta.url));

function runWorker(args, cwd) {
  return new Promise((resolve) => {
    execFile(process.execPath, args, { cwd, windowsHide: true, timeout: 30_000, killSignal: 'SIGKILL' }, (err, _stdout, stderr) => {
      resolve({
        code: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
        killed: !!(err && err.killed),
        signal: err?.signal ?? null,
        stderr: String(stderr ?? ''),
      });
    });
  });
}

async function bakeThroughChild(name, meta, dir) {
  fs.mkdirSync(dir, { recursive: true });
  const src = path.join(dir, 'in.png');
  fs.writeFileSync(src, original);
  const child = await runWorker([WORKER, src, dir, name, JSON.stringify(meta)], dir);
  const outFile = path.join(dir, 'out.bin');
  let resultOk = false;
  let resultMessage = null;
  try {
    const parsed = JSON.parse(fs.readFileSync(path.join(dir, 'result.json'), 'utf8'));
    resultOk = parsed?.ok === true;
    resultMessage = typeof parsed?.message === 'string' ? parsed.message : '';
  } catch { /* no result file */ }
  const bytes = fs.existsSync(outFile) ? new Uint8Array(fs.readFileSync(outFile)) : null;
  return { child, resultOk, resultMessage, bytes, leftovers: fs.readdirSync(dir).sort() };
}

const checkRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'btct-check-'));
try {
  const good = await bakeThroughChild('a.png', { crop: null, blurs: [REGION] }, path.join(checkRoot, 'good'));
  if (!good.resultOk || !good.bytes) {
    throw new Error(`the worker failed on an image it should bake: ${JSON.stringify(good.resultMessage)} ${good.child.stderr}`);
  }
  if (good.bytes.length !== blurred.length || !good.bytes.every((b, i) => b === blurred[i])) {
    throw new Error(`the worker's output differs from the in-process bake (${good.bytes.length} B vs ${blurred.length} B)`);
  }
  if (good.leftovers.includes('out.part')) throw new Error('the worker left a half-written out.part behind');

  const bad = await bakeThroughChild('a.webp', { crop: null, blurs: [REGION] }, path.join(checkRoot, 'bad'));
  if (bad.bytes !== null) throw new Error('a failed bake must leave no output file at all');
  if (bad.resultOk) throw new Error('a failed bake must not report ok');
  if (!bad.resultMessage) throw new Error('a failed bake must say why');
  const refusal = bakeFailureMessage({
    code: bad.child.code, killed: bad.child.killed, signal: bad.child.signal, stderr: bad.child.stderr,
    resultOk: bad.resultOk, resultMessage: bad.resultMessage, outputExists: false,
  }, 'a.webp');
  if (!/cannot be baked server-side/.test(refusal)) {
    throw new Error(`bakeFailureMessage did not turn the child's refusal into one: ${refusal}`);
  }
  console.log(`worker: ${good.bytes.length} B identical to the in-process bake; the webp case exits ${bad.child.code} with no output and says "${refusal.slice(0, 60)}…"`);
} finally {
  fs.rmSync(checkRoot, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}

console.log('bake: ok');
