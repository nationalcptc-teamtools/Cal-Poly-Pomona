// Spawns the compiler and the converter. Everything here is async on purpose:
// the process also runs the Yjs relay, and a synchronous compile would freeze
// every editor (the concern behind invariant #9).
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDiagnostics, scrubPaths, childFailureMessage, docxFailureMessage, truncate } from './diagnostics.mjs';
import { childEnv } from './child-env.mjs';
import { createSerial } from './serial.mjs';
import { createAdmission } from './admission.mjs';
import { findPackageSpec } from './package-spec.mjs';
import { stageReport, unstage, ExportError } from './stage.mjs';
import { runChild } from './run-child.mjs';
import { convertLimit } from './convert-limit.mjs';

export { ExportError };

// Not a real HTTP status: it says "the caller is gone", so the route knows
// there is nobody left to answer. Nginx uses 499 for the same thing.
export const CLIENT_GONE = 499;

const TIMEOUT_MS = 120_000;
// The PDF-to-Word child gets its own clock because it runs after the compile,
// not instead of it. It used to be a fixed 120 s, which failed a 119-page
// report outright (about four minutes on one core), so it is now whatever
// DOCX_CONVERT_TIMEOUT_S says and no cap when that is unset or 0. A child
// whose caller disconnects is killed either way (run-child.mjs), so an
// abandoned export never holds the queue. Read once at startup, like every
// other environment switch the server has.
const CONVERT_LIMIT = convertLimit(process.env.DOCX_CONVERT_TIMEOUT_S);
// A PDF that reaches this size is a runaway loop, not a report, and the
// bytes sit in the response buffer of a process that also relays Yjs.
const MAX_OUTPUT_MB = 100;
const MAX_OUTPUT_BYTES = MAX_OUTPUT_MB * 1024 * 1024;
// One warning line from the converter, and the number of them, both bounded:
// warnings.mjs caps the header again, but nothing should arrive unbounded.
const MAX_CONVERT_WARNINGS = 10;
const MAX_CONVERT_WARNING_CHARS = 300;
// A PDF this big is a report nobody will open in Word either, and the
// converter would spend minutes on it. The reference 23-page report with a
// cover and six fonts compiles to 1.8 MB, so this is more than ten times a
// real one.
const MAX_CONVERT_INPUT_MB = 25;
const MAX_CONVERT_INPUT_BYTES = MAX_CONVERT_INPUT_MB * 1024 * 1024;
const serial = createSerial();
// One running plus one waiting. A third caller is told to come back rather
// than being parked on an open socket behind a two-minute compile.
const admission = createAdmission(2);

// Resolved from this module's own URL, so it does not depend on cwd (the
// children run with the staged directory as cwd).
const CONVERTER = fileURLToPath(new URL('./pdf-to-docx/convert.py', import.meta.url));

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

// Resolving a CLI walks every PATH entry, so it is cached: the report tab
// asks for capabilities on every mount, and that must not turn into a few
// dozen stat calls per open. A minute is short enough that installing a CLI
// on a running server shows up without a restart.
const CLI_TTL_MS = 60_000;
let cliCache = null;

function clis() {
  const now = Date.now();
  if (cliCache && now - cliCache.at < CLI_TTL_MS) return cliCache;
  cliCache = { at: now, typst: process.env.TYPST_CLI || onPath('typst'), python: pythonCli() };
  return cliCache;
}

function pythonCli() {
  const explicit = process.env.PDF2DOCX_PYTHON;
  // An explicit interpreter is taken at its word only if it is there. The
  // image sets this variable to a virtualenv that is not installed when the
  // report binaries were left out, and spawning that path once a minute to
  // be told ENOENT is noise with no reader.
  if (explicit) {
    try { return fs.statSync(explicit).isFile() ? explicit : null; } catch { return null; }
  }
  return onPath('python3') || onPath('python');
}

// Whether an interpreter can actually import the converter's engine. This
// starts a Python process that loads pymupdf, numpy and OpenCV, which is a
// second or so and a few hundred MB of transient RSS, so a success is
// remembered for the life of the process: a package does not uninstall
// itself. A failure is remembered only as long as the CLI cache, so
// installing pdf2docx on a running server shows up without a restart.
let importProbe = null;

function canImportPdf2docx(python) {
  if (importProbe && importProbe.python === python && (importProbe.ok || Date.now() - importProbe.at < CLI_TTL_MS)) {
    return importProbe.promise;
  }
  const promise = new Promise((resolve) => {
    execFile(python, ['-I', '-B', '-c', 'import pdf2docx'], {
      env: childEnv(), windowsHide: true, maxBuffer: 256 * 1024, timeout: 60_000, killSignal: 'SIGKILL',
    }, (err) => {
      const ok = !err;
      if (importProbe && importProbe.promise === promise) importProbe.ok = ok;
      resolve(ok);
    });
  });
  importProbe = { at: Date.now(), python, ok: false, promise };
  return promise;
}

export async function capabilities() {
  const c = clis();
  const docx = !!c.python && fs.existsSync(CONVERTER) && (await canImportPdf2docx(c.python));
  return { pdf: !!c.typst, docx };
}

/** Why this format cannot be exported here, or null when it can. */
async function unavailable(format) {
  if (!clis().typst) return 'typst CLI not found on this server';
  if (format !== 'docx') return null;
  const { docx } = await capabilities();
  return docx ? null : 'the Word converter (Python with pdf2docx) is not installed on this server';
}

// An argument array, never a shell string: a caption or a filename from the
// shared doc must never be parsed by a shell.
// The caller going away is not a failure of the report, so it is its own
// status and never a 422 with a kill message in it.
async function run(cli, args, cwd, timeout, signal) {
  const result = await runChild(cli, args, cwd, { timeoutMs: timeout, signal });
  if (result.aborted) throw new ExportError(CLIENT_GONE, 'the caller disconnected during the export');
  return result;
}

/** The finished file, refused when it is too big to hand back. */
async function readOutput(file, label) {
  const stat = await fs.promises.stat(file);
  if (stat.size > MAX_OUTPUT_BYTES) {
    throw new ExportError(422, `The exported ${label} is too large (${Math.round(stat.size / 1024 / 1024)} MB).`);
  }
  // A Buffer, which goes straight to res.end: no Uint8Array round trip and no
  // second copy of a 100 MB file. Read asynchronously, because up to 100 MB
  // off the disk is not something to stop the Yjs relay for.
  return fs.promises.readFile(file);
}

// The 17 default faces the browser compiler uses, staged by scripts/fonts.ts.
const defaultFontDir = () => path.join(process.env.STATIC_DIR || path.resolve('..', 'dist'), 'fonts');

function assertNoPackages(source) {
  const spec = findPackageSpec(source);
  if (spec) {
    throw new ExportError(422, `This report imports or mentions a Typst package spec (${spec}). Packages are not available in server export; use the browser PDF export.`);
  }
}

/**
 * Compile the staged report. Returns the path of the PDF it wrote.
 *
 * Both formats come through here: the Word file is made from this PDF, so it
 * cannot disagree with it about redactions, figure numbers or page breaks.
 */
async function compilePdf(root, source, signal) {
  const cli = clis().typst;
  if (!cli) throw new ExportError(501, 'typst CLI not found on this server');
  assertNoPackages(source);
  const out = path.join(root, 'out.pdf');
  const args = [
    'compile', '--root', root, '--ignore-system-fonts', '--diagnostic-format', 'short',
    // One core. The default is every core, and the other one is running the
    // Yjs relay for the whole team.
    '-j', '1',
    // Defence in depth behind assertNoPackages: anything that still asks for
    // a package writes it inside the staged directory, which is deleted with
    // the export, instead of into the user data directory where it would
    // outlive the request.
    '--package-path', path.join(root, 'packages'),
    '--package-cache-path', path.join(root, 'packages'),
    '--font-path', path.join(root, 'fonts'),
  ];
  if (fs.existsSync(defaultFontDir())) args.push('--font-path', defaultFontDir());
  args.push(path.join(root, 'main.typ'), out);
  const result = await run(cli, args, root, TIMEOUT_MS, signal);
  if (result.code === 'ENOENT') throw new ExportError(501, `${path.basename(cli)} is no longer installed on this server`);
  // `-j 1` puts layout on the main thread, whose stack is smaller than a
  // worker's, so a very large document aborts there while it compiles with
  // the default job count. Measured with typst 0.14.2 on Windows: 2000
  // sections and a 4.2 MB PDF are fine, 3000 sections overflow. That panic
  // is a plain non-zero exit here and a signal death on Linux, and
  // childFailureMessage knows both shapes.
  const death = childFailureMessage(result, 'typst');
  if (death) throw new ExportError(422, death);
  // Every string that can reach a response body loses the staged path first:
  // it sits under the OS temp directory, which names the account.
  const diagnostics = parseDiagnostics(result.stderr, root).map((d) => ({
    ...d,
    message: scrubPaths(d.message, root),
    file: d.file && path.isAbsolute(d.file) ? scrubPaths(d.file, root) : d.file,
  }));
  if (result.code !== 0 || diagnostics.some((d) => d.severity === 'error') || !fs.existsSync(out)) {
    const first = diagnostics.find((d) => d.severity === 'error');
    throw new ExportError(422, first
      ? `Typst error at ${first.file ?? '?'}:${first.line ?? '?'}: ${first.message}`
      : (scrubPaths(result.stderr, root).trim() || 'the report did not compile'), diagnostics);
  }
  return out;
}

async function toPdf(root, source, signal) {
  return await readOutput(await compilePdf(root, source, signal), 'PDF');
}

/**
 * The finished PDF, converted to Word by a short-lived Python child.
 *
 * The converter reads a PDF this server's own typst produced, so what it
 * parses is attacker-influenced but typst-generated. It still gets the same
 * treatment as every other child here: an argv array, `childEnv()` (PATH and
 * nothing else, so AUTH_SECRET and the ingest tokens stay out of it), the
 * staged directory as cwd, a timeout with SIGKILL behind it, and a message
 * that has been scrubbed and capped before it can reach a response body.
 * `-I` puts Python in isolated mode, which ignores every PYTHON* variable and
 * the user site directory, and `-B` stops it writing .pyc files into the
 * image. It needs no network.
 */
async function toDocx(root, source, signal) {
  const python = clis().python;
  if (!python) throw new ExportError(501, 'no Python interpreter for the Word converter on this server');
  const pdf = await compilePdf(root, source, signal);
  // The conversion's cost follows what is on the pages rather than the
  // request, and neither the image budget nor the output cap sees a PDF full
  // of vector drawings, so the input gets its own ceiling before a child is
  // started. convert.py refuses on page count and per-page complexity too;
  // this is the cheap one the parent can do without reading the file.
  const size = (await fs.promises.stat(pdf)).size;
  if (size > MAX_CONVERT_INPUT_BYTES) {
    throw new ExportError(422, `This report's PDF is ${Math.round(size / 1024 / 1024)} MB, too large to convert to Word on this server. Export the PDF instead.`);
  }
  const out = path.join(root, 'out.docx');
  const resultFile = path.join(root, 'docx-result.json');
  // With a cap, the converter is told how long it has, so it can decline to
  // convert a second time rather than be SIGKILLed halfway through one.
  // Without one it gets no budget and runs every layout pass.
  const budgetArg = CONVERT_LIMIT.budgetSeconds === null ? [] : [String(CONVERT_LIMIT.budgetSeconds)];
  // The same two font directories the compile used, so the families the PDF
  // names can be found as files and carried into the Word file. Without them
  // a reader who lacks the report's fonts gets substitutes, and with the
  // PDF's own line endings reproduced a substitute re-wraps the page.
  const fontArgs = [path.join(root, 'fonts'), defaultFontDir()]
    .filter((dir) => fs.existsSync(dir))
    .map((dir) => `--fonts=${dir}`);
  const args = ['-I', '-B', CONVERTER, '--line-breaks=pdf', ...fontArgs, pdf, out, resultFile, ...budgetArg];
  const child = await run(python, args, root, CONVERT_LIMIT.timeoutMs, signal);
  if (child.code === 'ENOENT') throw new ExportError(501, 'the Word converter is no longer installed on this server');

  // null means no result file at all, which is the only case where the
  // child's stderr is the best thing left to say.
  let result = null;
  try { result = JSON.parse(await fs.promises.readFile(resultFile, 'utf8')); } catch { /* the child died before it could say anything */ }
  const outSize = fs.existsSync(out) ? (await fs.promises.stat(out)).size : 0;
  // Python names the interpreter in an import traceback, and in the image
  // that path is the virtualenv under /opt. Nothing about where this server
  // keeps its tools belongs in a response body.
  const scrub = (text) => pythonRoots(python).reduce((acc, dir) => scrubPaths(acc, dir), scrubPaths(text, root));
  if (result?.ok !== true || outSize <= 0) {
    throw new ExportError(422, docxFailureMessage({
      code: child.code,
      killed: child.killed,
      signal: child.signal,
      stderr: scrub(child.stderr),
      resultOk: result?.ok === true,
      resultMessage: result === null ? null : (typeof result.message === 'string' ? scrub(result.message) : ''),
      outputExists: outSize > 0,
    }));
  }
  const warnings = Array.isArray(result.warnings) ? result.warnings : [];
  return {
    bytes: await readOutput(out, 'Word file'),
    warnings: warnings
      .filter((w) => typeof w === 'string' && w.trim())
      .slice(0, MAX_CONVERT_WARNINGS)
      .map((w) => truncate(scrub(w), MAX_CONVERT_WARNING_CHARS)),
  };
}

// A system prefix is not a secret and scrubbing it makes a message worse:
// "/usr/bin/python3: cannot import" would become "./python3: cannot import".
// Only a directory that is longer than this and not one of these is worth
// removing, which is what leaves /opt/pdf2docx scrubbed and /usr alone.
const SYSTEM_PREFIXES = new Set(['/usr', '/bin', '/lib', '/opt', '/var', '/etc', '/', 'C:\\', 'C:']);
const MIN_SCRUB_ROOT_CHARS = 8;

/** The interpreter's own directory and the virtualenv above it, worth hiding. */
function pythonRoots(python) {
  const bin = path.dirname(python);
  const prefix = path.dirname(bin);
  return [bin, prefix].filter((dir, index, all) =>
    dir && all.indexOf(dir) === index && dir.length >= MIN_SCRUB_ROOT_CHARS && !SYSTEM_PREFIXES.has(dir));
}

/**
 * @param isCancelled asked once, when this job reaches the front of the queue:
 *   true means the caller has gone and the work is not worth doing.
 * @param signal aborted when the caller goes away mid-export: the compile or
 *   the converter child is killed at once and the job ends as CLIENT_GONE.
 */
export function exportReport(workspaceId, format, isCancelled = () => false, signal = null) {
  if (!admission.enter()) {
    return Promise.reject(new ExportError(429, 'Another export is already queued. Try again in a moment.'));
  }
  return serial(async () => {
    if (isCancelled()) throw new ExportError(CLIENT_GONE, 'the caller disconnected before the export started');
    // Before anything is read, baked or written: a box without the tools for
    // the format that was asked for answers 501 rather than spending a
    // minute staging a report it cannot finish.
    const missing = await unavailable(format);
    if (missing) throw new ExportError(501, missing);
    const { root, source, baked, warnings } = await stageReport(workspaceId);
    try {
      if (format === 'docx') {
        // Every warning the converter reports is passed on: a rebuilt table
        // of contents, a header it could not find, a page whose content did
        // not fit. The Word file is made from the PDF, so nothing about the
        // report's own content can be lost between the two.
        const docx = await toDocx(root, source, signal);
        return { bytes: docx.bytes, baked, warnings: [...warnings, ...docx.warnings] };
      }
      return { bytes: await toPdf(root, source, signal), baked, warnings };
    } finally {
      await unstage(root);
    }
  }).finally(() => admission.leave());
}
