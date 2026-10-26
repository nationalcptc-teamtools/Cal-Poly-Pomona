// ─────────────────────────────────────────────────────────────────────────
// Local (in-browser) Typst compiler: the main-thread client.
//
// The wasm lives in a Web Worker (typst-compiler.worker.ts, running
// typst-compiler.driver.ts). This module keeps the API the rest of the app
// has always used and turns each call into a request to the worker:
//
//  - calls are serialized, because the compiler carries per-compilation
//    state and interleaving two compiles would corrupt output;
//  - fonts and shadow files are pushed only when they change, right before
//    the compile that needs them, so a keystroke never re-sends an image;
//  - superseded previews are dropped before they cost a round trip.
//
// When `Worker` does not exist (jsdom, very old browsers) the driver runs
// inline on the main thread through the same code path.
// ─────────────────────────────────────────────────────────────────────────

import type {
  DriverCommand, DriverRequest, DriverResponse, PdfOutput, SvgOutput, TypstFontInfo, TypstShadowFile, TypstSvgResult,
} from './typst-compiler-types';
import type { TypstDriver } from './typst-compiler.driver';

export type { TypstDiagnostic, TypstShadowFile, TypstSvgResult } from './typst-compiler-types';

// Default virtual path for the document inside the compiler's in-memory FS.
// Callers pass their own when the file being edited isn't main.typ: every
// other .typ in the workspace is mounted as a shadow file, so any of them can
// be compiled as the main one.
const MAIN_PATH = '/main.typ';

// ── transport ────────────────────────────────────────────────────────────

interface Transport {
  /** Bumps every time a fresh worker replaces a crashed one. */
  generation: number;
  call<T>(cmd: DriverCommand): Promise<T>;
  /** Stop the worker/driver and settle anything still in flight. */
  dispose(): void;
}

function createWorkerTransport(): Transport {
  let worker: Worker | null = null;
  let seq = 0;
  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

  const transport: Transport = {
    generation: 0,
    call<T>(cmd: DriverCommand): Promise<T> {
      return new Promise<T>((resolve, reject) => {
        const w = worker ?? spawn();
        const id = ++seq;
        pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
        w.postMessage({ id, ...cmd } satisfies DriverRequest);
      });
    },
    dispose() {
      const w = worker;
      worker = null;
      transport.generation++;
      // Never leave a caller hanging on a worker that is about to stop.
      if (pending.size > 0) {
        const err = new Error('Typst compiler was released');
        for (const p of pending.values()) p.reject(err);
        pending.clear();
      }
      w?.terminate();
    },
  };

  const spawn = (): Worker => {
    const w = new Worker(new URL('./typst-compiler.worker.ts', import.meta.url), { type: 'module' });
    w.onmessage = (e: MessageEvent<DriverResponse>) => {
      const p = pending.get(e.data.id);
      if (!p) return;
      pending.delete(e.data.id);
      if (e.data.ok) p.resolve(e.data.value);
      else p.reject(new Error(e.data.error));
    };
    w.onerror = (e) => {
      const err = new Error(e.message || 'Typst worker crashed');
      for (const p of pending.values()) p.reject(err);
      pending.clear();
      w.terminate();
      if (worker === w) {
        worker = null;
        // Bump on crash (not lazily on the next spawn): syncState reads
        // `generation` before deciding whether to call anything, so the
        // next syncState must already see the bump in order to re-send
        // fonts and shadow files before touching the replacement worker.
        transport.generation++;
      }
    };
    worker = w;
    return w;
  };

  return transport;
}

function createInlineTransport(): Transport {
  let driver: Promise<TypstDriver> | null = null;

  const transport: Transport = {
    generation: 0,
    async call<T>(cmd: DriverCommand): Promise<T> {
      const { dispatch } = await import('./typst-compiler.driver');
      return dispatch(await getDriver(), cmd) as Promise<T>;
    },
    dispose() {
      // Nothing to terminate: the driver runs on this thread, so a call
      // already in flight finishes. Dropping the reference is what frees the
      // wasm instance and its fonts once that call returns.
      driver = null;
      transport.generation++;
    },
  };

  const getDriver = (): Promise<TypstDriver> => {
    if (!driver) {
      driver = import('./typst-compiler.driver').then((m) => m.createTypstDriver());
      driver.catch(() => {
        driver = null;
        // A replacement driver starts empty, so the next syncState re-sends fonts and shadow files.
        transport.generation++;
      });
    }
    return driver;
  };

  return transport;
}

let transport: Transport | null = null;
function getTransport(): Transport {
  return (transport ??= typeof Worker === 'undefined' ? createInlineTransport() : createWorkerTransport());
}

// ── idle release ─────────────────────────────────────────────────────────
// A worker that has been started holds the instantiated 28 MB wasm module,
// the 17 default faces and a copy of every image in the workspace for as
// long as the page lives, and closing the Report tab used to free none of
// it. So the tab hands the compiler back when it unmounts, and the release
// happens a few minutes later rather than immediately: a pane renders only
// its active tab, switching to a note and back is the normal workflow, and
// an immediate release would re-pay about 1.2 s of wasm instantiation plus
// 17 font fetches on every switch. `lib/typst-render-cache.ts` is left
// alone on purpose, which is what lets a reopened tab paint its last pages
// while the replacement worker starts.

const IDLE_RELEASE_MS = 5 * 60_000;
let releaseTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * Stop the compiler and forget everything that was pushed into it, leaving
 * the module able to start a fresh worker on the next call.
 *
 * The "already sent on this transport" bookkeeping is reset along with the
 * inputs themselves: a replacement worker starts empty, so the next compile
 * has to re-send fonts and shadow files before it runs. `TypstView`'s asset
 * sync effect re-pushes the workspace's files on its next mount.
 */
export function releaseTypstCompiler(): void {
  cancelTypstRelease();
  const t = transport;
  transport = null;
  t?.dispose();
  customFonts = [];
  shadowFiles = [];
  fontGeneration++;
  shadowGeneration++;
  sentOnTransport = -1;
  sentFontGeneration = -1;
  sentShadowGeneration = -1;
}

/** Release the compiler once it has been idle for `delayMs`. One timer. */
export function scheduleTypstRelease(delayMs: number = IDLE_RELEASE_MS): void {
  if (releaseTimer !== null) return;
  releaseTimer = setTimeout(() => {
    releaseTimer = null;
    releaseTypstCompiler();
  }, delayMs);
}

/** Called when a Report tab mounts: the compiler is wanted again. */
export function cancelTypstRelease(): void {
  if (releaseTimer === null) return;
  clearTimeout(releaseTimer);
  releaseTimer = null;
}

// ── mutable inputs ───────────────────────────────────────────────────────
// Custom fonts and shadow files are set by the Typst tab (see
// components/typst/TypstView.tsx) whenever the workspace's assets change.

let customFonts: Uint8Array[] = [];
let fontGeneration = 0;
let sentFontGeneration = 0;

let shadowFiles: TypstShadowFile[] = [];
let shadowGeneration = 0;
let sentShadowGeneration = 0;

let sentOnTransport = 0;

/** Push fonts / shadow files if the worker doesn't have the current set. Runs inside the queue. */
async function syncState(t: Transport): Promise<void> {
  if (sentOnTransport !== t.generation) {
    sentOnTransport = t.generation;
    sentFontGeneration = -1;
    sentShadowGeneration = -1;
  }
  if (sentFontGeneration !== fontGeneration) {
    await t.call({ op: 'setFonts', fonts: customFonts });
    sentFontGeneration = fontGeneration;
  }
  if (sentShadowGeneration !== shadowGeneration) {
    await t.call({ op: 'setShadow', files: shadowFiles });
    sentShadowGeneration = shadowGeneration;
  }
}

/**
 * Replace the set of files mounted into the compiler's virtual filesystem.
 *
 * Callers pass the *final* bytes: an image with a crop rect has already
 * been cropped by `lib/typst-assets.ts`, so from Typst's point of view the
 * file simply is the cropped image.
 *
 * Cheap to call repeatedly: the bytes only travel to the worker when the set
 * actually changes, not on every keystroke-triggered recompile.
 *
 * Returns true if the set actually changed, so callers can skip forcing a
 * re-render when nothing did.
 */
export function setTypstShadowFiles(files: TypstShadowFile[]): boolean {
  const changed =
    files.length !== shadowFiles.length ||
    files.some((f, i) => {
      const prev = shadowFiles[i];
      return !prev || f.path !== prev.path || f.bytes !== prev.bytes;
    });
  if (!changed) return false;
  shadowFiles = files;
  shadowGeneration++;
  return true;
}

/**
 * Replace the set of custom fonts available to the compiler.
 *
 * The default faces are always present; these are added on top. The worker
 * installs them with typst.ts's `setFonts`, so a change costs one font
 * resolver build (a few hundred ms), not a compiler rebuild.
 *
 * Returns true if the set actually changed.
 */
export function setTypstFonts(fonts: Uint8Array[]): boolean {
  const changed =
    fonts.length !== customFonts.length || fonts.some((f, i) => f !== customFonts[i]);
  if (!changed) return false;
  customFonts = fonts;
  fontGeneration++;
  return true;
}

// Serialize all compiler access: the compiler holds state across calls.
let queue: Promise<unknown> = Promise.resolve();
function enqueue<T>(task: () => Promise<T>): Promise<T> {
  const run = queue.then(task, task);
  // Keep the chain alive even if a task rejects.
  queue = run.then(() => undefined, () => undefined);
  return run;
}

function toMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  try { return JSON.stringify(err); } catch { return String(err); }
}

/**
 * Read a font file's metadata (family name, style, …) using typst.ts's own
 * parser, so the family name we show the operator is the one the compiler
 * will actually match in `#set text(font: "…")`.
 */
export function getFontInfo(bytes: Uint8Array): Promise<TypstFontInfo | null> {
  return enqueue(() => getTransport().call<TypstFontInfo | null>({ op: 'fontInfo', bytes }));
}

// Monotonic id for preview compiles, used to drop superseded ones before they
// do any work. Export compiles (PDF/SVG download) deliberately don't
// participate: an explicit export must always run.
let svgRequestSeq = 0;

/**
 * Compile Typst source to an SVG string, fully locally.
 *
 * Returns the rendered SVG plus any diagnostics. On a compile error there is
 * no SVG and `diagnostics` carries the errors (with source ranges). The
 * promise rejects only on an unexpected/internal failure (e.g. the wasm
 * couldn't be loaded at all).
 *
 * `mainPath` is where `source` is mounted and which file the compiler is
 * pointed at, so a document that `#include`s its neighbours resolves them
 * relative to the right place.
 */
export function compileTypstSvg(
  source: string,
  opts: { coalesce?: boolean } = {},
  mainPath: string = MAIN_PATH,
): Promise<TypstSvgResult> {
  // Coalesce superseded previews. The preview already debounces typing, but a
  // document that takes longer to compile than the debounce window will still
  // queue up compiles whose output is discarded the moment they finish. Since
  // only the newest preview can ever be shown, an older one that hasn't
  // started yet should cost nothing rather than a full round trip.
  //
  // Opt-in, because an *export* must never be skipped: it isn't superseded by
  // a preview that happens to be requested while it waits in the queue.
  const seq = opts.coalesce ? ++svgRequestSeq : -1;
  return enqueue(async () => {
    if (seq !== -1 && seq !== svgRequestSeq) return { diagnostics: [], superseded: true };
    const t = getTransport();
    await syncState(t);
    return t.call<SvgOutput>({ op: 'svg', source, mainPath });
  });
}

/**
 * Compile Typst source to PDF bytes, fully locally. Throws (rejects) with a
 * readable message if the document has compile errors.
 *
 * Compiles the same `mainPath` as the preview so relative paths (notably
 * `#image("/assets/…")`) resolve identically in both.
 */
export function compileTypstPdf(source: string, mainPath: string = MAIN_PATH): Promise<Uint8Array> {
  return enqueue(async () => {
    const t = getTransport();
    await syncState(t);
    const res = await t.call<PdfOutput>({ op: 'pdf', source, mainPath });
    if (!res.pdf) {
      const first = res.diagnostics.find((d) => d.severity === 'error');
      throw new Error(
        first
          ? `Typst error: ${first.message}`
          : 'Typst document has errors: fix them before exporting a PDF.',
      );
    }
    return res.pdf;
  });
}

/** Re-export so callers can resolve the message of a thrown error uniformly. */
export { toMessage as typstErrorMessage };
