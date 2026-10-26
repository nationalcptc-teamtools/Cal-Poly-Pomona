# Typst Tab, Step 2 (server PDF and DOCX export) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Export a workspace's Typst report to PDF (typst CLI) and DOCX (pandoc) on the server, with every crop and redaction baked into the images first, all behind `ENABLE_TYPST`.

**Architecture:** A new `server/typst/` directory, dynamically imported by `index.mjs` only when the flag is on. One export stages a temp directory (`main.typ`, baked images under `assets/`, fonts under `fonts/`), spawns one child process, streams the result back and deletes the directory. PDF and DOCX share the staged directory, so a Word file can never contain an unredacted original. The crop, blur and placeholder math is imported straight from `src/lib/*.ts` (Bun runs TypeScript), so the server and the browser cannot drift apart.

**Tech Stack:** Bun, `node:child_process`, `jimp` 1.x, typst CLI 0.14.2, pandoc 3.x, Yjs (through y-websocket's CJS instance), Vitest.

**Spec:** `docs/superpowers/specs/2026-09-18-typst-tab-design.md` (section 2). **Depends on:** `docs/superpowers/plans/2026-09-19-typst-tab-step1.md`, fully executed.

## Global Constraints

- `TS` means `/c/Users/rober/Desktop/university-tools/advanced-typst-editor`.
- Never add Claude as author or co-author to any commit. No `Co-Authored-By` trailer, no "Generated with" line.
- No em dashes anywhere you write. Check with `grep -c "$(printf '\342\200\224')" <file>`.
- With `ENABLE_TYPST` off: `server/typst/` is never imported, `jimp` is never loaded, no child process is spawned, and `/api/typst/*` returns 404.
- Shared-doc access lives only in `server/yjs-data.mjs` (invariant #4). Yjs is reached through the existing CJS `require` (invariant #6). This step only reads the shared doc; it writes nothing.
- A format that cannot be re-encoded (gif, webp, svg) with a crop or blur on it fails the export with a 422. It is never written out unredacted.
- The temp directory is removed in a `finally`. Exports run one at a time. Each child process has a 120 s timeout and is killed with `SIGKILL`.
- Spawns are asynchronous (`execFile`); nothing here blocks the event loop the Yjs relay runs on (the concern behind invariant #9).
- The Dockerfile copies server files individually. Every new file under `server/typst/` and every `src/lib/*.ts` file the server imports must be added to it, and a pure server module imported by `src/test` needs a `.d.mts` beside it.
- Report source key: `typst:<workspaceId>:source` in the shared doc's `texts` map. Asset paths inside the report are `/assets/<filename>`.
- The `.mjs` server is not covered by `tsc`. Syntax-check each new file with `bun build ./server/typst/<file>.mjs --target=bun --external jimp --external yjs --external y-websocket --outfile "$TEMP/x.js"`.

## File Structure

| File | Responsibility |
|---|---|
| `server/typst/diagnostics.mjs` + `.d.mts` | Pure: parse `typst --diagnostic-format short` stderr into records |
| `server/typst/serial.mjs` + `.d.mts` | Pure: a one-at-a-time promise queue |
| `server/typst/docx-source.mjs` + `.d.mts` | Pure: turn report source into what pandoc's Typst reader can follow |
| `server/typst/bake.mjs` | Crop and blur one image with `jimp`, using `src/lib` math |
| `server/typst/stage.mjs` | Build and tear down the staged directory |
| `server/typst/export.mjs` | `exportReport(workspaceId, format)`: stage, spawn, read bytes |
| `server/typst/index.mjs` | The HTTP handler `index.mjs` mounts |
| `server/yjs-data.mjs` (modify) | `readTypstSource`, `listAssetRecords` |
| `server/index.mjs` (modify) | Dynamic import and route, flag-gated |
| `src/lib/typst-export-api.ts` (create) | Client: capabilities and export fetch |
| `src/components/typst/TypstView.tsx` (modify) | Export menu: PDF, DOCX, PDF (server) |
| `Dockerfile` (modify) | `typst` and `pandoc` binaries, new `COPY` lines |

---

### Task 1: Diagnostics parser and serial queue (pure)

**Files:**
- Create: `server/typst/diagnostics.mjs`, `server/typst/diagnostics.d.mts`, `server/typst/serial.mjs`, `server/typst/serial.d.mts`
- Test: `src/test/typst-server-pure.test.ts`
- Modify: `Dockerfile` (client-build stage `.d.mts` copy)

**Interfaces:**
- Produces: `parseDiagnostics(stderr: string, root: string): Diagnostic[]` where `Diagnostic = { severity: 'error' | 'warning'; message: string; file: string | null; line: number | null; col: number | null }`; `createSerial(): <T>(job: () => Promise<T>) => Promise<T>`.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { parseDiagnostics } from '../../server/typst/diagnostics.mjs';
import { createSerial } from '../../server/typst/serial.mjs';

describe('parseDiagnostics', () => {
  it('reads file:line:col lines relative to the root', () => {
    const out = parseDiagnostics('/tmp/x/main.typ:12:3: error: unknown variable: foo\n', '/tmp/x');
    expect(out).toEqual([{ severity: 'error', message: 'unknown variable: foo', file: 'main.typ', line: 12, col: 3 }]);
  });
  it('reads bare error lines and skips noise', () => {
    const out = parseDiagnostics('\nwarning: layout did not converge\nsome noise\n', '/tmp/x');
    expect(out).toEqual([{ severity: 'warning', message: 'layout did not converge', file: null, line: null, col: null }]);
  });
});

describe('createSerial', () => {
  it('never overlaps jobs and keeps order', async () => {
    const run = createSerial();
    const log: string[] = [];
    const job = (n: string, ms: number) => run(async () => { log.push(`start ${n}`); await new Promise((r) => setTimeout(r, ms)); log.push(`end ${n}`); return n; });
    const results = await Promise.all([job('a', 20), job('b', 1)]);
    expect(results).toEqual(['a', 'b']);
    expect(log).toEqual(['start a', 'end a', 'start b', 'end b']);
  });
  it('keeps running after a job rejects', async () => {
    const run = createSerial();
    await expect(run(async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    await expect(run(async () => 'ok')).resolves.toBe('ok');
  });
});
```

- [ ] **Step 2: Run, expect FAIL** (modules not found)

Run: `bun run test -- src/test/typst-server-pure.test.ts`

- [ ] **Step 3: Implement**

`server/typst/diagnostics.mjs`:

```js
// Parses `typst compile --diagnostic-format short` stderr. Pure: no fs, no
// spawn, so src/test covers it through the .d.mts beside this file.
import path from 'node:path';

const LINE = /^(?:\\\\\?\\)?(.+?):(\d+):(\d+): (error|warning): (.*)$/;

export function parseDiagnostics(stderr, root) {
  const out = [];
  const rootAbs = path.resolve(root).replace(/^\\\\\?\\/, '');
  for (const raw of String(stderr).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const m = LINE.exec(line);
    if (m) {
      const abs = m[1].replace(/^\\\\\?\\/, '');
      const rel = path.isAbsolute(abs) ? path.relative(rootAbs, abs).split(path.sep).join('/') : abs.replace(/\\/g, '/');
      out.push({ severity: m[4], message: m[5], file: rel.startsWith('..') ? abs : rel, line: Number(m[2]), col: Number(m[3]) });
      continue;
    }
    const plain = /^(error|warning): (.*)$/.exec(line);
    if (plain) out.push({ severity: plain[1], message: plain[2], file: null, line: null, col: null });
  }
  return out;
}
```

`server/typst/diagnostics.d.mts`:

```ts
export interface Diagnostic { severity: 'error' | 'warning'; message: string; file: string | null; line: number | null; col: number | null }
export function parseDiagnostics(stderr: string, root: string): Diagnostic[];
```

`server/typst/serial.mjs`:

```js
// One export at a time: a compile is a CPU burst, and two in parallel on a
// small box would starve the Yjs relay. A rejected job must not wedge the queue.
export function createSerial() {
  let tail = Promise.resolve();
  return (job) => {
    const next = tail.then(job, job);
    tail = next.then(() => undefined, () => undefined);
    return next;
  };
}
```

`server/typst/serial.d.mts`:

```ts
export function createSerial(): <T>(job: () => Promise<T>) => Promise<T>;
```

The first test uses a POSIX root. On this Windows checkout `path.resolve('/tmp/x')` gains a drive letter, so `path.relative` still yields `main.typ` only if the input path resolves the same way; if the first test fails locally for that reason, build both paths in the test with `path.resolve` and `path.join` instead of string literals.

- [ ] **Step 4: Run, expect PASS.** Then in the Dockerfile's client-build stage add `COPY server/typst/*.d.mts ./server/typst/` next to the existing `COPY server/*.d.mts ./server/`, and run `bun run build`.

- [ ] **Step 5: Commit**

```bash
git add server/typst/diagnostics.* server/typst/serial.* src/test/typst-server-pure.test.ts Dockerfile
git commit -m "Add Typst diagnostics parser and serial export queue"
```

---

### Task 2: The source pandoc can follow (pure)

Pandoc's Typst reader evaluates a subset of Typst. It cannot be trusted to run the report's `#image-placeholder(...)` helper, and it resolves image paths against the filesystem, not against a Typst `--root`. So the DOCX path never feeds pandoc the raw report. It expands every figure slot into a plain `#figure(image(...), caption: [...])` and makes asset paths relative.

**Files:**
- Create: `server/typst/docx-source.mjs`, `server/typst/docx-source.d.mts`
- Test: `src/test/typst-docx-source.test.ts`

**Interfaces:**
- Consumes: `findScreenshotSlots(source): ScreenshotSlot[]` from `src/lib/typst-placeholders.ts` (`{ start, end, caption, path }` are the fields used).
- Produces: `toPandocSource(source: string): string`.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { toPandocSource } from '../../server/typst/docx-source.mjs';

describe('toPandocSource', () => {
  it('expands a placed slot into a plain figure with a relative path', () => {
    const src = '= Finding\n#image-placeholder("Login bypass", path: "/assets/login.png", height: 3in)\nAfter.';
    expect(toPandocSource(src)).toBe('= Finding\n#figure(image("assets/login.png"), caption: [Login bypass])\nAfter.');
  });
  it('turns an empty slot into a caption-only note', () => {
    expect(toPandocSource('#image-placeholder("Pending shot")')).toBe('_[Figure pending: Pending shot]_');
  });
  it('relativizes direct image calls and leaves other text alone', () => {
    expect(toPandocSource('#image("/assets/a.png", width: 50%)\n"/assets/" in prose')).toBe('#image("assets/a.png", width: 50%)\n"/assets/" in prose');
  });
  it('escapes brackets in captions', () => {
    expect(toPandocSource('#image-placeholder("a [b]", path: "/assets/x.png")')).toContain('caption: [a \\[b\\]]');
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

Run: `bun run test -- src/test/typst-docx-source.test.ts`

- [ ] **Step 3: Implement `server/typst/docx-source.mjs`**

```js
// The report, rewritten into Typst that pandoc's reader can follow: figure
// slots become plain #figure calls (pandoc does not evaluate the report's own
// #image-placeholder helper) and asset paths become relative to the staged
// directory (pandoc knows nothing of Typst's --root). Pure.
import { findScreenshotSlots } from '../../src/lib/typst-placeholders.ts';

const escapeContent = (s) => s.replace(/([\\\[\]#*_`$@<])/g, '\\$1');

export function toPandocSource(source) {
  let out = source;
  // Right to left, so earlier offsets stay valid.
  for (const slot of [...findScreenshotSlots(source)].reverse()) {
    const caption = escapeContent(slot.caption ?? 'Figure');
    const rel = slot.path ? slot.path.replace(/^\/+/, '') : null;
    const replacement = rel
      ? `#figure(image("${rel}"), caption: [${caption}])`
      : `_[Figure pending: ${caption}]_`;
    out = out.slice(0, slot.start) + replacement + out.slice(slot.end);
  }
  return out.replace(/(\bimage\(\s*")\/+/g, '$1');
}
```

`server/typst/docx-source.d.mts`:

```ts
export function toPandocSource(source: string): string;
```

If the fourth test's expected escaping does not match because `escapeContent` escapes more than brackets, that is fine: the assertion only checks the bracket form.

- [ ] **Step 4: Run, expect PASS.** `bun run build`.

- [ ] **Step 5: Commit**

```bash
git add server/typst/docx-source.* src/test/typst-docx-source.test.ts
git commit -m "Add the pandoc-ready source transform for DOCX export"
```

---

### Task 3: Reading the report and its assets from the shared doc

**Files:**
- Modify: `server/yjs-data.mjs`

**Interfaces:**
- Produces: `readTypstSource(workspaceId: string): Promise<string | null>`; `listAssetRecords(workspaceId: string): Promise<Array<{ id, workspaceId, kind: 'image' | 'font', filename, mime, crop?, blurs?, deletedAt? }>>`.

- [ ] **Step 1: Add both functions at the end of `server/yjs-data.mjs`**

```js
// ── Typst report export (server/typst/) ──
// Read-only. The report source is a Y.Text in `texts`; `typstAssets` is not
// in TABLE_NAMES (the server never needed it as a table), so it is read
// straight off the doc like the retention pair above.
export async function readTypstSource(workspaceId) {
  const { texts } = await shared();
  const t = texts.get(`typst:${workspaceId}:source`);
  return t ? t.toString() : null;
}

export async function listAssetRecords(workspaceId) {
  const { doc } = await shared();
  return [...doc.getMap('typstAssets').values()].filter((a) => a && a.workspaceId === workspaceId && !a.deletedAt);
}
```

Confirm the key format against the client: `grep -n "export function textKey" -A4 src/realtime/shared-doc.ts` must produce `<entity>:<id>:<field>`. If it differs, use the client's format here.

Update the file's header comment: the sentence listing what reads the doc gains "and the Typst report export".

- [ ] **Step 2: Syntax check and commit**

Run: `bun build ./server/yjs-data.mjs --target=bun --external y-websocket --outfile "$TEMP/x.js"`

```bash
git add server/yjs-data.mjs
git commit -m "Read the Typst source and asset records from the shared doc"
```

---

### Task 4: Baking crops and redactions

**Files:**
- Modify: `server/package.json`, `server/bun.lock`
- Create: `server/typst/bake.mjs`
- Test: `server/typst/bake.check.mjs` (a Bun script, not Vitest: it needs `jimp` from `server/node_modules`)

**Interfaces:**
- Consumes: from `src/lib/blur-math.ts`: `blurParams`, `effectiveStyle`, `hasBlurs`, `pixelParams`; from `src/lib/crop-math.ts`: `cropToPixels`, `isFullFrame`, `normalizeCrop`, `outputSize`; from `src/lib/image-format.ts`: `formatFromFilename`.
- Produces: `bakeImage(bytes: Uint8Array, meta: { crop?, blurs? }, filename: string): Promise<Uint8Array | null>`. `null` means nothing to apply. Throws for an un-bakeable format.

- [ ] **Step 1: Dependency**

```bash
cd server && bun add jimp@^1.6.1 && cd ..
```

- [ ] **Step 2: Port**

Copy `TS/server/bake.ts` to `server/typst/bake.mjs` and make it plain JavaScript:
- delete the two `import type` lines and the `type JimpImage` alias;
- remove every type annotation and the `as BlurRegion[]` and `!` assertions;
- change the three math imports to `'../../src/lib/blur-math.ts'`, `'../../src/lib/crop-math.ts'`, `'../../src/lib/image-format.ts'`.

Those modules import only types from `@/types`. Bun erases type-only imports, so the `@/` alias is never resolved at runtime. Confirm: `grep -n "^import" src/lib/blur-math.ts src/lib/crop-math.ts src/lib/image-format.ts` must show `import type` only. If any has a value import through `@/`, stop and report it.

Confirm `formatFromFilename` exists in BTCT's `image-format.ts` (`grep -n "export function formatFromFilename" src/lib/image-format.ts`). If BTCT's copy lacks it, copy that one function from `TS/src/lib/image-format.ts`; do not replace the file.

The math is imported, not mirrored, on purpose: the `effectiveStyle`/`effectiveStrength` fallbacks for old records live in one place.

- [ ] **Step 3: The redaction check**

`server/typst/bake.check.mjs`:

```js
// Run: bun server/typst/bake.check.mjs   (exits non-zero on failure)
import { Jimp } from 'jimp';
import { bakeImage } from './bake.mjs';

const img = new Jimp({ width: 200, height: 100, color: 0xffffffff });
for (let x = 0; x < 100; x += 1) for (let y = 0; y < 100; y += 1) if ((x + y) % 2) img.setPixelColor(0x000000ff, x, y);
const original = new Uint8Array(await img.getBuffer('image/png'));

const same = await bakeImage(original, {}, 'a.png');
if (same !== null) throw new Error('no crop and no blur must return null');

const blurred = await bakeImage(original, { blurs: [{ x: 0, y: 0, w: 0.5, h: 1 }] }, 'a.png');
const out = await Jimp.read(Buffer.from(blurred));
const px = out.getPixelColor(10, 10);
if (px === 0x000000ff || px === 0xffffffff) throw new Error('blurred region still shows the original checkerboard');
if (out.getPixelColor(150, 50) !== 0xffffffff) throw new Error('pixels outside the region changed');

const cropped = await bakeImage(original, { crop: { x: 0, y: 0, w: 0.5, h: 1 } }, 'a.png');
const c = await Jimp.read(Buffer.from(cropped));
if (c.bitmap.width !== 100 || c.bitmap.height !== 100) throw new Error(`crop size ${c.bitmap.width}x${c.bitmap.height}`);

let threw = false;
try { await bakeImage(original, { blurs: [{ x: 0, y: 0, w: 1, h: 1 }] }, 'a.webp'); } catch { threw = true; }
if (!threw) throw new Error('an un-bakeable format with a blur must throw, never pass through');
console.log('bake: ok');
```

- [ ] **Step 4: Run it**

Run: `bun server/typst/bake.check.mjs`. Expected: `bake: ok`.

- [ ] **Step 5: Commit**

```bash
git add server/package.json server/bun.lock server/typst/bake.mjs server/typst/bake.check.mjs
git commit -m "Bake crops and redactions server-side with the client's own math"
```

---

### Task 5: Stage, spawn, export

**Files:**
- Create: `server/typst/stage.mjs`, `server/typst/export.mjs`

**Interfaces:**
- Consumes: `readTypstSource`, `listAssetRecords` (Task 3); `assetPath(id)` from `server/data-export.mjs`; `bakeImage` (Task 4); `parseDiagnostics`, `createSerial` (Task 1); `toPandocSource` (Task 2).
- Produces: `capabilities(): { pdf: boolean; docx: boolean }`; `exportReport(workspaceId: string, format: 'pdf' | 'docx'): Promise<{ bytes: Uint8Array; baked: number }>`; `class ExportError extends Error { status: number; diagnostics?: Diagnostic[] }`.

- [ ] **Step 1: `server/typst/stage.mjs`**

```js
// One export's working directory: main.typ, baked images under assets/, the
// workspace's own fonts under fonts/. Always removed by the caller's finally.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readTypstSource, listAssetRecords } from '../yjs-data.mjs';
import { assetPath } from '../data-export.mjs';

export class ExportError extends Error {
  constructor(status, message, diagnostics) { super(message); this.status = status; this.diagnostics = diagnostics; }
}

// A filename comes from a shared-doc record any client can write: never let
// it climb out of the staged directory.
const safeName = (name) => {
  const base = path.basename(String(name));
  if (!base || base === '.' || base === '..') throw new ExportError(422, `bad asset filename: ${name}`);
  return base;
};

export async function stageReport(workspaceId) {
  const source = await readTypstSource(workspaceId);
  if (source === null) throw new ExportError(404, 'this workspace has no report yet');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'btct-typst-'));
  try {
    fs.mkdirSync(path.join(root, 'assets'));
    fs.mkdirSync(path.join(root, 'fonts'));
    fs.writeFileSync(path.join(root, 'main.typ'), source);
    const { bakeImage } = await import('./bake.mjs'); // jimp loads on first export, not at boot
    let baked = 0;
    for (const a of await listAssetRecords(workspaceId)) {
      const from = assetPath(a.id);
      if (!fs.existsSync(from)) continue; // Typst reports the unresolved path against its line
      const name = safeName(a.filename);
      if (a.kind === 'font') { fs.copyFileSync(from, path.join(root, 'fonts', name)); continue; }
      const bytes = new Uint8Array(fs.readFileSync(from));
      let out;
      try { out = await bakeImage(bytes, { crop: a.crop ?? null, blurs: a.blurs ?? null }, name); }
      catch (err) { throw new ExportError(422, `${name}: ${err instanceof Error ? err.message : String(err)}`); }
      fs.writeFileSync(path.join(root, 'assets', name), out ?? bytes);
      if (out) baked += 1;
    }
    return { root, source, baked };
  } catch (err) {
    fs.rmSync(root, { recursive: true, force: true });
    throw err;
  }
}

export function unstage(root) {
  fs.rmSync(root, { recursive: true, force: true });
}
```

- [ ] **Step 2: `server/typst/export.mjs`**

```js
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { parseDiagnostics } from './diagnostics.mjs';
import { createSerial } from './serial.mjs';
import { toPandocSource } from './docx-source.mjs';
import { stageReport, unstage, ExportError } from './stage.mjs';

export { ExportError };

const TIMEOUT_MS = 120_000;
const serial = createSerial();

function onPath(name) {
  const exts = process.platform === 'win32' ? ['.exe', ''] : [''];
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    for (const ext of exts) {
      const p = path.join(dir, name + ext);
      try { if (fs.statSync(p).isFile()) return p; } catch { /* next */ }
    }
  }
  return null;
}
const typstCli = () => process.env.TYPST_CLI || onPath('typst');
const pandocCli = () => process.env.PANDOC_CLI || onPath('pandoc');

export function capabilities() {
  return { pdf: !!typstCli(), docx: !!pandocCli() };
}

function run(cli, args, cwd) {
  return new Promise((resolve) => {
    execFile(cli, args, { cwd, windowsHide: true, maxBuffer: 16 * 1024 * 1024, timeout: TIMEOUT_MS, killSignal: 'SIGKILL' }, (err, _stdout, stderr) => {
      if (err && (err.killed || err.signal)) return resolve({ code: 124, stderr: `error: ${path.basename(cli)} timed out after 120 s` });
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stderr: String(stderr ?? '') });
    });
  });
}

// The 17 default faces the browser compiler uses, staged by scripts/fonts.ts.
const defaultFontDir = () => path.join(process.env.STATIC_DIR || path.resolve('..', 'dist'), 'fonts');

async function toPdf(root) {
  const cli = typstCli();
  if (!cli) throw new ExportError(501, 'typst CLI not found on this server');
  const out = path.join(root, 'out.pdf');
  const args = ['compile', '--root', root, '--ignore-system-fonts', '--diagnostic-format', 'short', '--font-path', path.join(root, 'fonts')];
  if (fs.existsSync(defaultFontDir())) args.push('--font-path', defaultFontDir());
  args.push(path.join(root, 'main.typ'), out);
  const { code, stderr } = await run(cli, args, root);
  const diagnostics = parseDiagnostics(stderr, root);
  if (code !== 0 || diagnostics.some((d) => d.severity === 'error') || !fs.existsSync(out)) {
    const first = diagnostics.find((d) => d.severity === 'error');
    throw new ExportError(422, first ? `Typst error at ${first.file ?? '?'}:${first.line ?? '?'}: ${first.message}` : (stderr.trim() || 'the report did not compile'), diagnostics);
  }
  return new Uint8Array(fs.readFileSync(out));
}

async function toDocx(root, source) {
  const cli = pandocCli();
  if (!cli) throw new ExportError(501, 'pandoc not found on this server');
  fs.writeFileSync(path.join(root, 'docx.typ'), toPandocSource(source));
  const { code, stderr } = await run(cli, ['docx.typ', '-f', 'typst', '-t', 'docx', '--resource-path', '.', '-o', 'out.docx'], root);
  const out = path.join(root, 'out.docx');
  if (code !== 0 || !fs.existsSync(out)) throw new ExportError(422, stderr.trim() || 'pandoc could not convert the report');
  return new Uint8Array(fs.readFileSync(out));
}

export function exportReport(workspaceId, format) {
  return serial(async () => {
    const { root, source, baked } = await stageReport(workspaceId);
    try {
      const bytes = format === 'docx' ? await toDocx(root, source) : await toPdf(root);
      return { bytes, baked };
    } finally {
      unstage(root);
    }
  });
}
```

- [ ] **Step 3: Syntax check both files**, then commit.

```bash
git add server/typst/stage.mjs server/typst/export.mjs
git commit -m "Stage a report with baked images and export it to PDF or DOCX"
```

---

### Task 6: The route, flag-gated

**Files:**
- Create: `server/typst/index.mjs`
- Modify: `server/index.mjs`

**Interfaces:**
- Produces: `GET /api/typst/capabilities` → `{ pdf: boolean, docx: boolean }`; `POST /api/typst/<workspaceId>/export?format=pdf|docx` → the file bytes with header `X-Baked-Images: <n>`, or `{ error, diagnostics? }` JSON with status 404, 422 or 501. Both need an account token. Both return 404 with the flag off.

- [ ] **Step 1: `server/typst/index.mjs`**

```js
// HTTP surface of the Typst server side. index.mjs imports this file
// dynamically, and only when ENABLE_TYPST is on.
import { capabilities, exportReport, ExportError } from './export.mjs';

const MIME = { pdf: 'application/pdf', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' };

// Returns true when it handled the request.
export async function handleTypst(req, res, { user, sendJson }) {
  const url = new URL(req.url, 'http://x');
  if (!url.pathname.startsWith('/api/typst/')) return false;
  if (!user) { sendJson(res, 401, { error: 'unauthorised' }); return true; }

  if (req.method === 'GET' && url.pathname === '/api/typst/capabilities') {
    sendJson(res, 200, capabilities());
    return true;
  }

  const m = /^\/api\/typst\/([^/]+)\/export$/.exec(url.pathname);
  if (req.method === 'POST' && m) {
    const format = url.searchParams.get('format');
    if (format !== 'pdf' && format !== 'docx') { sendJson(res, 400, { error: 'format must be pdf or docx' }); return true; }
    try {
      const { bytes, baked } = await exportReport(decodeURIComponent(m[1]), format);
      res.writeHead(200, { 'Content-Type': MIME[format], 'Content-Length': bytes.byteLength, 'X-Baked-Images': String(baked), 'Cache-Control': 'no-store' });
      res.end(Buffer.from(bytes));
    } catch (err) {
      if (err instanceof ExportError) sendJson(res, err.status, { error: err.message, diagnostics: err.diagnostics ?? [] });
      else { console.error('[typst] export failed', err); sendJson(res, 500, { error: 'export failed' }); }
    }
    return true;
  }

  sendJson(res, 404, { error: 'not found' });
  return true;
}
```

- [ ] **Step 2: Mount it in `server/index.mjs`**

Below the `ENABLE_TYPST` constant from step 1:

```js
// Loaded once, on the first Typst request, and only with the flag on: a small
// box never imports server/typst/ (or jimp behind it).
let typstModule = null;
const loadTypst = () => (typstModule ??= import('./typst/index.mjs'));
```

In the request handler's `if` chain, before the static-file fallback and after the auth routes:

```js
    if (req.url?.startsWith('/api/typst/')) {
      if (!ENABLE_TYPST) return sendJson(res, 404, { error: 'not found' });
      const { handleTypst } = await loadTypst();
      if (await handleTypst(req, res, { user: authFromHeader(req), sendJson })) return;
    }
```

Check how other routes in this file read the caller: `grep -n "authFromHeader(req)" server/index.mjs | head -3`. If they destructure a different shape (for example `const auth = authFromHeader(req); if (!auth) ...`), pass that same value as `user`; `handleTypst` only tests it for truthiness.

If the handler function is not already `async`, do not make it so: use `loadTypst().then(({ handleTypst }) => handleTypst(...))` with a `.catch` that sends a 500, and `return` right after.

- [ ] **Step 3: Verify by hand**

Install the two CLIs on this machine if missing (`winget install Typst.Typst`, `winget install JohnMacFarlane.Pandoc`), or set `TYPST_CLI` and `PANDOC_CLI`. Start the server on a throwaway DB with `ENABLE_TYPST=1` and `YPERSISTENCE` set, open the app at `127.0.0.1`, write a short report with one placed screenshot that has a blur region, then with your account token:

```bash
curl -s -H "Authorization: Bearer $TOKEN" 127.0.0.1:8080/api/typst/capabilities
curl -s -X POST -H "Authorization: Bearer $TOKEN" -D - -o out.pdf  "127.0.0.1:8080/api/typst/$WS/export?format=pdf"
curl -s -X POST -H "Authorization: Bearer $TOKEN" -D - -o out.docx "127.0.0.1:8080/api/typst/$WS/export?format=docx"
```

Expected: `{"pdf":true,"docx":true}`; two 200s with `X-Baked-Images: 1`; `out.pdf` opens and shows the blur.

The redaction guarantee, end to end:

```bash
mkdir -p docx-x && cd docx-x && unzip -o -q ../out.docx && ls word/media && cd ..
```

Open the image under `word/media`: the region must be blurred. Compare its hash with the original upload under `ASSETS_DIR`; they must differ.

Restart without `ENABLE_TYPST`: both URLs return 404, and `ls "$TEMP" | grep btct-typst` prints nothing.

If pandoc rejects `docx.typ`, read its stderr from the 422 body. The expected cause is Typst syntax outside pandoc's subset (a `#show` or `#set` rule, a custom `#let`). That is the documented fidelity limit, not a bug in the transform: confirm with a report that has only headings, text, a table and a figure, which must convert.

- [ ] **Step 4: Commit**

```bash
git add server/typst/index.mjs server/index.mjs
git commit -m "Mount the flag-gated Typst export routes"
```

---

### Task 7: The export menu

**Files:**
- Create: `src/lib/typst-export-api.ts`
- Modify: `src/components/typst/TypstView.tsx` (the toolbar's export buttons, near the `exportPdf` callback)
- Test: `src/test/typst-export-api.test.ts`

**Interfaces:**
- Consumes: `API_URL`, `useAuthStore` from `@/auth/auth-store`.
- Produces: `fetchExportCapabilities(): Promise<{ pdf: boolean; docx: boolean }>`; `exportOnServer(workspaceId: string, format: 'pdf' | 'docx'): Promise<{ blob: Blob; baked: number }>`, which throws `Error(message)` using the server's `error` field.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect, vi, afterEach } from 'vitest';
import { exportOnServer, fetchExportCapabilities } from '@/lib/typst-export-api';

afterEach(() => vi.unstubAllGlobals());

describe('typst export api', () => {
  it('reports no capabilities when the route is missing (flag off)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 404 })));
    expect(await fetchExportCapabilities()).toEqual({ pdf: false, docx: false });
  });
  it('returns the blob and the baked count', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: { 'X-Baked-Images': '2' } })));
    const out = await exportOnServer('w1', 'docx');
    expect(out.baked).toBe(2);
    expect(out.blob.size).toBe(3);
  });
  it('surfaces the server error message', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'Typst error at main.typ:3: boom' }), { status: 422 })));
    await expect(exportOnServer('w1', 'pdf')).rejects.toThrow('Typst error at main.typ:3: boom');
  });
});
```

- [ ] **Step 2: Run, expect FAIL.** `bun run test -- src/test/typst-export-api.test.ts`

- [ ] **Step 3: Implement `src/lib/typst-export-api.ts`**

```ts
// Client side of the server Typst export (server/typst/index.mjs).
import { API_URL, useAuthStore } from '@/auth/auth-store';

export interface ExportCapabilities { pdf: boolean; docx: boolean }

function authHeaders(): Record<string, string> {
  const token = useAuthStore.getState().token;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/** What the server can export. All false when the routes do not exist. */
export async function fetchExportCapabilities(): Promise<ExportCapabilities> {
  try {
    const res = await fetch(`${API_URL}/api/typst/capabilities`, { headers: authHeaders() });
    if (!res.ok) return { pdf: false, docx: false };
    const data = (await res.json()) as Partial<ExportCapabilities>;
    return { pdf: data.pdf === true, docx: data.docx === true };
  } catch {
    return { pdf: false, docx: false };
  }
}

export async function exportOnServer(workspaceId: string, format: 'pdf' | 'docx'): Promise<{ blob: Blob; baked: number }> {
  const res = await fetch(`${API_URL}/api/typst/${encodeURIComponent(workspaceId)}/export?format=${format}`, { method: 'POST', headers: authHeaders() });
  if (!res.ok) {
    const data = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(data.error || `export failed (${res.status})`);
  }
  return { blob: await res.blob(), baked: Number(res.headers.get('X-Baked-Images') ?? 0) };
}
```

- [ ] **Step 4: Run, expect PASS**

- [ ] **Step 5: The menu**

In `TypstView.tsx`, fetch capabilities once on mount into `const [caps, setCaps] = useState<ExportCapabilities>({ pdf: false, docx: false })`. Keep the existing browser `PDF` button as it is: it needs no server and stays the default. Beside it add, each rendered only when its capability is true:

```tsx
{caps.docx && <button type="button" onClick={() => void serverExport('docx')} disabled={exporting !== null} className={/* same classes as the PDF button */}><FileDown size={13} /> {exporting === 'docx' ? 'Converting…' : 'DOCX'}</button>}
{caps.pdf && <button type="button" onClick={() => void serverExport('pdf')} disabled={exporting !== null} title="Compiled by the server's typst CLI" className={/* same classes */}><FileDown size={13} /> {exporting === 'pdf' ? 'Compiling…' : 'PDF (server)'}</button>}
```

Copy the class string from the existing PDF button literally; do not invent styling. `serverExport`:

```tsx
const [exporting, setExporting] = useState<'pdf' | 'docx' | null>(null);
const serverExport = useCallback(async (format: 'pdf' | 'docx') => {
  setExporting(format);
  setExportError(null);
  try {
    const { blob } = await exportOnServer(workspaceId, format);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `report.${format}`; a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    setExportError(err instanceof Error ? err.message : String(err));
  } finally {
    setExporting(null);
  }
}, [workspaceId]);
```

`setExportError` is the view's existing error banner state. Under the DOCX button's `title`, say what the user gets: `title="Word file via pandoc. Headings, text, tables and figures carry over; custom Typst layout does not."`

If the view already has a filename helper for the browser PDF (it names the file after the workspace), use it for `a.download` instead of `report.<format>`.

- [ ] **Step 6: Verify and commit**

Run: `bun run build`. By hand with the flag on: the DOCX button downloads a file Word opens, with the screenshot blurred; break the report (`#nope`) and confirm the banner shows the Typst error with its line.

```bash
git add src/lib/typst-export-api.ts src/test/typst-export-api.test.ts src/components/typst/TypstView.tsx
git commit -m "Add DOCX and server PDF to the report's export menu"
```

---

### Task 8: Image, measurements, docs

**Files:**
- Modify: `Dockerfile`, `README.md`, `CLAUDE.md`, `docs/typst-tab-2026-09.md`

- [ ] **Step 1: Binaries, in a stage of their own**

Add before the runtime stage:

```dockerfile
# ─────────────────────────────────────────────────────────────────────────
# Report export binaries (only used when ENABLE_TYPST=1).
# ─────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS report-bins
ARG TYPST_VERSION=0.14.2
ARG PANDOC_VERSION=3.6.4
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in amd64) T=x86_64-unknown-linux-musl; P=amd64;; arm64) T=aarch64-unknown-linux-musl; P=arm64;; *) echo "unsupported arch"; exit 1;; esac; \
    curl -fsSL "https://github.com/typst/typst/releases/download/v${TYPST_VERSION}/typst-${T}.tar.xz" | tar -xJ -C /tmp; \
    install -m 0755 "/tmp/typst-${T}/typst" /usr/local/bin/typst; \
    curl -fsSL "https://github.com/jgm/pandoc/releases/download/${PANDOC_VERSION}/pandoc-${PANDOC_VERSION}-linux-${P}.tar.gz" | tar -xz -C /tmp; \
    install -m 0755 "/tmp/pandoc-${PANDOC_VERSION}/bin/pandoc" /usr/local/bin/pandoc; \
    typst --version; pandoc --version | head -1
```

Before relying on the pandoc version, confirm the release exists: `curl -sI https://github.com/jgm/pandoc/releases/download/3.6.4/pandoc-3.6.4-linux-amd64.tar.gz | head -1` must not be 404. If it is, take the latest 3.x from the releases page and use that number.

In the runtime stage, with the other server copies:

```dockerfile
COPY --from=report-bins /usr/local/bin/typst /usr/local/bin/pandoc /usr/local/bin/
COPY server/typst/ /app/server/typst/
# The server imports the crop, blur and placeholder math the browser uses.
COPY src/lib/blur-math.ts src/lib/crop-math.ts src/lib/image-format.ts src/lib/typst-placeholders.ts src/lib/typst-geometry.ts /app/src/lib/
```

`server/typst/` sits at `/app/server/typst/`, so `../../src/lib/` resolves to `/app/src/lib/`. Check every `src/lib` import those five files make is among the five: `grep -hn "^import" src/lib/blur-math.ts src/lib/crop-math.ts src/lib/image-format.ts src/lib/typst-placeholders.ts src/lib/typst-geometry.ts | grep -v "import type"`. Add any value import it shows to the `COPY` line.

- [ ] **Step 2: Build and exercise the image**

```bash
docker compose --env-file .env.preview -f docker-compose.preview.yml up -d --build
docker compose -f docker-compose.preview.yml exec btct sh -c "typst --version && pandoc --version | head -1"
```

With `ENABLE_TYPST=1` in `.env.preview`, repeat Task 6 step 3's three `curl` calls against `127.0.0.1:8081` and the `word/media` check.

- [ ] **Step 3: Measure, append to `docs/typst-tab-2026-09.md`**

| Metric | How | Pass condition |
|---|---|---|
| Image size, step 1 vs step 2 | `docker images` | recorded |
| Size of `typst` and `pandoc` in the image | `docker compose exec btct sh -c "ls -l /usr/local/bin/typst /usr/local/bin/pandoc"` | recorded |
| Flag-off idle RSS, step 1 vs step 2 | `docker stats --no-stream` after two idle minutes | no measurable change |
| Flag-off: is `server/typst` loaded | `POST /api/typst/x/export` returns 404 and idle RSS is unchanged after it | 404 |
| One PDF export: wall time, peak container memory | `time curl ...` with `docker stats` running | recorded |
| One DOCX export: wall time, peak container memory | same | recorded |

If peak memory of an export comes near the 1 GB limit, write that down plainly: it decides whether server export is ever safe on the range box, which is off by default there anyway.

- [ ] **Step 4: Docs**

README: "Report (Typst)" gains an export paragraph (browser PDF is the default; DOCX and server PDF need the binaries the image ships; what DOCX keeps and loses; redactions are baked before either). API table: the two routes. Env vars: `TYPST_CLI`, `PANDOC_CLI`. Key files map: `server/typst/`. "Running from source": how to install the two CLIs.

CLAUDE.md:
- Invariant #4 gains a fifth exception: `server/typst/` (stages a report and its images for export; knows the report key and asset records, reads only).
- The `yjs-data.mjs` sentence lists `readTypstSource` and `listAssetRecords`.
- New invariant: **server export bakes before it converts.** PDF and DOCX both come from one staged directory whose images already carry their crop and blur; an un-bakeable format with a redaction fails the export. The math is imported from `src/lib`, never copied, and the Dockerfile copies those files into `/app/src/lib/`.
- Commands: the Dockerfile note about individually copied server files mentions `server/typst/` and the `src/lib` copy line.

Run the em dash check on all four files.

- [ ] **Step 5: Final gate and commit**

Run: `bun run build && bun run test && bun server/typst/bake.check.mjs`. Test failures must equal the step 1 baseline.

```bash
git add Dockerfile README.md CLAUDE.md docs/typst-tab-2026-09.md
git commit -m "Ship typst and pandoc in the image, record export measurements, sync docs"
```
