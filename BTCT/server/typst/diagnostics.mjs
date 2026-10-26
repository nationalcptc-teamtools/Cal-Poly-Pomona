// Parses `typst compile --diagnostic-format short` stderr. Pure: no fs, no
// spawn, so src/test covers it through the .d.mts beside this file.
import path from 'node:path';

const LINE = /^(?:\\\\\?\\)?(.+?):(\d+):(\d+): (error|warning): (.*)$/;

/**
 * Replace every mention of the staged directory with `.`.
 *
 * A compiler quotes the path it tried, and the staged directory sits under
 * the OS temp folder, which on Windows carries the account name. The caller
 * runs this over diagnostic messages, over a `file` that stayed absolute, and
 * over the raw stderr it falls back to, so none of that reaches a response
 * body. Every form the two CLIs print is covered: either separator, and the
 * Windows extended-length `\\?\` prefix, matched without regard to case on
 * Windows because its paths are case insensitive.
 */
export function scrubPaths(text, root) {
  const out = typeof text === 'string' ? text : text == null ? '' : String(text);
  if (!out) return out;
  let replaced = out;
  if (root) {
    const resolved = path.resolve(root).replace(/^\\\\\?\\/, '');
    const forms = [];
    for (const body of new Set([resolved, resolved.replace(/\\/g, '/'), resolved.replace(/\//g, '\\')])) {
      if (body) forms.push(`\\\\?\\${body}`, body); // the prefixed form first, or it would leave the prefix behind
    }
    const flags = process.platform === 'win32' ? 'gi' : 'g';
    replaced = forms.reduce((acc, form) => acc.replace(new RegExp(form.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), flags), '.'), out);
  }
  // Last pass: anything still carrying the staging marker goes, whatever the
  // spelling. Windows quotes 8.3 short paths in some messages
  // (C:\Users\ROBER~1\...), where no form above matches character for
  // character, and mkdtemp's six characters are the one part that survives.
  // Brackets and quotes end the token so a message keeps its punctuation.
  // This pass runs with no root too, which is how a bake child's message is
  // scrubbed without the caller having to say which directory it ran in.
  return replaced.replace(STAGING_TOKEN, '.');
}

// Both temporary directories one export creates: the typst compile root and
// the bake children's output directory.
const STAGING_TOKEN = /[^\s"'()[\]]*btct-(?:typst|bake)-[A-Za-z0-9]{6,}[^\s"'()[\]]*/gi;

/** `text` cut to `max` characters, the last one an ellipsis when it was cut. */
export function truncate(text, max) {
  const out = typeof text === 'string' ? text : text == null ? '' : String(text);
  return out.length <= max ? out : `${out.slice(0, max - 1)}\u2026`;
}

/**
 * What to tell the operator when a child process died rather than failed.
 *
 * A Rust main-thread stack overflow and a cgroup OOM kill both end the
 * process by signal on Linux, and both arrive here looking like any other
 * non-zero exit. Saying "timed out after 120 s" three seconds into the
 * request, which is what a blanket signal check did, sends whoever reads the
 * message hunting for a slow compile that never happened.
 *
 * Returns null when there is nothing special to say: the child exited
 * normally with a non-zero status (its own stderr is the better message), or
 * the timeout killed it, which the caller already knows about because it
 * asked for it.
 *
 * Pure, so src/test can cover the cases this Windows box cannot produce.
 */
export function childFailureMessage(result, tool) {
  if (!result || result.killed) return null;
  const stderr = String(result.stderr ?? '');
  // Checked before the signal, because the same panic is a plain non-zero
  // exit on Windows and a signal death on Linux.
  if (/overflowed its stack/i.test(stderr)) {
    return 'This report is too large for the server compiler. Export the PDF from the browser instead.';
  }
  if (!result.signal) return null;
  if (result.signal === 'SIGKILL') {
    return 'The export ran out of memory on the server. Export the PDF from the browser instead.';
  }
  return `The exporter stopped unexpectedly (${tool}, ${result.signal}).`;
}

// A bake child's message is short by construction; this is the ceiling on a
// child that says something unexpected, so a report cannot push a kilobyte
// of its own text into an error banner.
const MAX_BAKE_MESSAGE_CHARS = 300;

/**
 * What to tell the operator when redacting one image failed.
 *
 * Every image with a crop or a blur on it is redacted in a child process of
 * its own, and the parent stages the result only when the child's
 * `result.json` says ok AND the output file is non-empty. Everything else
 * ends the export, so every other shape of failure ends up here. There is no
 * branch that returns "carry on with the original bytes", and there must
 * never be one: the whole feature exists to make sure a redaction that was
 * drawn is a redaction that ships.
 *
 * `resultMessage` distinguishes three states on purpose: a string is what
 * the child wrote, `''` is a result file that said nothing, and `null` is no
 * result file at all, which is the only case where the child's raw stderr is
 * the best clue left.
 *
 * Pure, so src/test covers the whole matrix through the .d.mts beside this
 * file.
 */
export function bakeFailureMessage(result, name) {
  const r = result ?? {};
  const label = String(name ?? 'this image');
  // `killed` and only `killed` means our own 30 s timeout fired.
  if (r.killed) {
    return `Redacting ${label} took too long on this server. Export the PDF from the browser instead.`;
  }
  // A signal death we did not cause. After the bake moved out of the relay
  // process, a cgroup OOM kill lands on the child, so SIGKILL here is the
  // 422 that used to be a dead server.
  const death = childFailureMessage({ code: r.code, killed: false, signal: r.signal ?? null, stderr: r.stderr ?? '' }, 'bake');
  if (death) return death;
  const said = typeof r.resultMessage === 'string' ? r.resultMessage.trim() : '';
  if (said) return truncate(scrubPaths(said, ''), MAX_BAKE_MESSAGE_CHARS);
  if (r.resultMessage === null || r.resultMessage === undefined) {
    const stderr = scrubPaths(String(r.stderr ?? ''), '').trim();
    if (stderr) return truncate(`${label}: the redaction step failed. ${stderr}`, MAX_BAKE_MESSAGE_CHARS);
  }
  return `${label}: the redaction step produced no image, so the export was stopped.`;
}

/**
 * What to tell the operator when the PDF could not be turned into Word.
 *
 * The same four shapes as a bake failure, because the child keeps the same
 * discipline: our own timeout, a death by signal (a cgroup OOM kill is the
 * one that matters on a 1 GB box), a non-zero exit that wrote a message into
 * `result.json`, and a clean exit that produced nothing usable. The PDF
 * itself is always still available, so every message says so.
 *
 * `resultMessage` distinguishes three states, as it does for a bake: a string
 * is what the converter wrote, `''` is a result file that said nothing, and
 * `null` is no result file at all, which is the only case where the child's
 * stderr is the best clue left.
 *
 * Pure, so src/test covers the matrix through the .d.mts beside this file.
 */
export function docxFailureMessage(result) {
  const r = result ?? {};
  // `killed` and only `killed` means our own timeout fired.
  if (r.killed) return 'Converting this report to Word took too long on this server. Export the PDF instead.';
  const death = childFailureMessage({ code: r.code, killed: false, signal: r.signal ?? null, stderr: r.stderr ?? '' }, 'pdf2docx');
  if (death) return death;
  const said = typeof r.resultMessage === 'string' ? r.resultMessage.trim() : '';
  if (said) return truncate(`The Word conversion failed. ${scrubPaths(said, '')}`, MAX_BAKE_MESSAGE_CHARS);
  if (r.resultMessage === null || r.resultMessage === undefined) {
    const stderr = scrubPaths(String(r.stderr ?? ''), '').trim();
    if (stderr) return truncate(`The Word conversion failed. ${stderr}`, MAX_BAKE_MESSAGE_CHARS);
  }
  return 'The Word conversion produced no file, so the export was stopped. Export the PDF instead.';
}

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
