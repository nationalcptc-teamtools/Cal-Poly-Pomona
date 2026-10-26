import path from 'node:path';
import { describe, it, expect } from 'vitest';
import { parseDiagnostics, scrubPaths, childFailureMessage, bakeFailureMessage, docxFailureMessage } from '../../server/typst/diagnostics.mjs';
import { createSerial } from '../../server/typst/serial.mjs';
import { findPackageSpec } from '../../server/typst/package-spec.mjs';
import { referencedAssetNames } from '../../server/typst/referenced-assets.mjs';
import { encodeWarnings } from '../../server/typst/warnings.mjs';

describe('parseDiagnostics', () => {
  it('reads file:line:col lines relative to the root', () => {
    const root = path.resolve('/tmp/x');
    const file = path.join(root, 'main.typ');
    const out = parseDiagnostics(`${file}:12:3: error: unknown variable: foo\n`, root);
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

describe('scrubPaths', () => {
  // A compiler message quotes the path it tried, and the staged directory
  // sits under the OS temp folder, which on Windows names the account.
  const root = path.resolve('/tmp/btct-typst-AbCdEf');

  it('removes the staged root in its native form', () => {
    // path.join('.', ...) would normalize the dot away, so the expectation
    // spells the separator out.
    expect(scrubPaths(`file not found (searched at ${path.join(root, 'Windows', 'win.ini')})`, root))
      .toBe(`file not found (searched at .${path.sep}Windows${path.sep}win.ini)`);
  });

  it('removes it in the other separator flavour too', () => {
    const forward = root.split(path.sep).join('/');
    const back = root.split(path.sep).join('\\');
    expect(scrubPaths(`at ${forward}/main.typ`, root)).toBe('at ./main.typ');
    expect(scrubPaths(`at ${back}\\main.typ`, root)).toBe('at .\\main.typ');
  });

  it('removes the Windows extended-length prefix with it', () => {
    const back = root.split(path.sep).join('\\');
    expect(scrubPaths(`searched at \\\\?\\${back}\\x`, root)).toBe('searched at .\\x');
  });

  it('ignores case on Windows, where paths are case insensitive', () => {
    if (process.platform !== 'win32') return;
    const shouty = root.split(path.sep).join('\\').toUpperCase();
    expect(scrubPaths(`at ${shouty}\\MAIN.TYP`, root)).toBe('at .\\MAIN.TYP');
  });

  it('leaves text that does not mention the root alone', () => {
    expect(scrubPaths('unknown variable: nope', root)).toBe('unknown variable: nope');
    expect(scrubPaths('', root)).toBe('');
  });

  it('is safe with a missing root or a non-string message', () => {
    expect(scrubPaths('x', '')).toBe('x');
    expect(scrubPaths(undefined as unknown as string, root)).toBe('');
  });

  it('removes every occurrence, not just the first', () => {
    const forward = root.split(path.sep).join('/');
    expect(scrubPaths(`${forward}/a and ${forward}/b`, root)).toBe('./a and ./b');
  });

  it('removes any path carrying the staging marker, whatever the spelling', () => {
    // Windows quotes 8.3 short paths in some messages, and then no part of
    // the directory we were given matches character for character. The
    // marker and the six characters mkdtemp appends are still there.
    expect(scrubPaths('file not found (searched at C:\\Users\\ROBER~1\\AppData\\Local\\Temp\\btct-typst-Qr8I8L\\assets\\x.png)', root))
      .toBe('file not found (searched at .)');
    expect(scrubPaths('could not read "/var/tmp/btct-typst-VmfxLw/main.typ"', root))
      .toBe('could not read "."');
    expect(scrubPaths('nothing to see here', root)).toBe('nothing to see here');
  });

  it('knows the bake children’s directory by the same marker', () => {
    // A bake child runs in its own temp directory, and its message reaches a
    // caller that never learns which one, so the marker pass has to work
    // with no root at all.
    expect(scrubPaths('open /var/tmp/btct-bake-Ab12Cd/3/out.part failed', '')).toBe('open . failed');
    expect(scrubPaths('open /var/tmp/btct-bake-Ab12Cd/3/out.part failed', root)).toBe('open . failed');
  });
});

describe('childFailureMessage', () => {
  // The shapes are what Bun hands execFile's callback. Verified on this
  // machine: a timeout kill sets killed true, signal SIGKILL, code null; an
  // ordinary failure sets killed false, signal null and a numeric code.
  // A Linux stack overflow or an OOM kill is a signal death we did not
  // cause, which is the case this function exists for.
  it('says nothing about a child we killed ourselves', () => {
    expect(childFailureMessage({ code: 124, killed: true, signal: 'SIGKILL', stderr: '' }, 'typst')).toBeNull();
  });

  it('says nothing about an ordinary non-zero exit', () => {
    expect(childFailureMessage({ code: 1, killed: false, signal: null, stderr: 'error: unknown variable' }, 'typst')).toBeNull();
    expect(childFailureMessage({ code: 0, killed: false, signal: null, stderr: '' }, 'typst')).toBeNull();
  });

  it('recognises a stack overflow however the process died', () => {
    const sentence = 'This report is too large for the server compiler. Export the PDF from the browser instead.';
    // Windows: a plain non-zero exit with the panic on stderr.
    expect(childFailureMessage({ code: 1, killed: false, signal: null, stderr: "\nthread 'main' has overflowed its stack\n" }, 'typst')).toBe(sentence);
    // Linux: the same panic, delivered as a signal.
    expect(childFailureMessage({ code: 1, killed: false, signal: 'SIGABRT', stderr: "thread 'main' has overflowed its stack" }, 'typst')).toBe(sentence);
    expect(childFailureMessage({ code: 1, killed: false, signal: 'SIGSEGV', stderr: 'thread MAIN has OVERFLOWED ITS STACK' }, 'typst')).toBe(sentence);
  });

  it('reads a SIGKILL we did not send as the memory killer', () => {
    expect(childFailureMessage({ code: 1, killed: false, signal: 'SIGKILL', stderr: '' }, 'typst'))
      .toBe('The export ran out of memory on the server. Export the PDF from the browser instead.');
  });

  it('names any other signal, with the tool that died', () => {
    expect(childFailureMessage({ code: 1, killed: false, signal: 'SIGSEGV', stderr: '' }, 'typst'))
      .toBe('The exporter stopped unexpectedly (typst, SIGSEGV).');
  });

  it('survives a result with missing fields', () => {
    expect(childFailureMessage({}, 'typst')).toBeNull();
    expect(childFailureMessage(null, 'typst')).toBeNull();
  });
});

describe('findPackageSpec', () => {
  // A package import makes the typst CLI fetch from packages.typst.org, from
  // the host the relay runs on. The match is on the quoted spec anywhere in
  // the source, not on an #import statement, because there are several ways
  // to hand the same string to the same loader.
  it('finds the plain import', () => {
    expect(findPackageSpec('#import "@preview/cetz:0.2.2": canvas\n= Report\n')).toBe('@preview/cetz:0.2.2');
    expect(findPackageSpec('#include "@local/house-style:1.0"')).toBe('@local/house-style:1.0');
  });

  it('finds the forms that route around an #import check', () => {
    expect(findPackageSpec('#let p = "@preview/cetz:0.2.2"\n#import p: canvas')).toBe('@preview/cetz:0.2.2');
    expect(findPackageSpec('#{ import "@preview/cetz:0.2.2": canvas }')).toBe('@preview/cetz:0.2.2');
    expect(findPackageSpec('#import("@preview/cetz:0.2.2")')).toBe('@preview/cetz:0.2.2');
    expect(findPackageSpec('#let specs = ("@preview/tablex:0.0.8",)\n#import specs.at(0)')).toBe('@preview/tablex:0.0.8');
  });

  it('leaves an ordinary report alone', () => {
    expect(findPackageSpec('= Findings\n#image("/assets/shot.png")\n#link("https://example.com")[x]\n')).toBeNull();
    expect(findPackageSpec('An email address like me@preview.example is not a package.')).toBeNull();
    expect(findPackageSpec('#import "helpers.typ": thing')).toBeNull();
    expect(findPackageSpec('')).toBeNull();
  });

  it('also catches a spec that is only quoted in prose, which is the accepted cost', () => {
    expect(findPackageSpec('We could not use "@preview/cetz:0.2.2" for this engagement.')).toBe('@preview/cetz:0.2.2');
  });

  it('will not run away on a long or multiline string', () => {
    expect(findPackageSpec(`#let x = "@preview/${'a'.repeat(200)}"`)).toBeNull();
    expect(findPackageSpec('#let x = "@preview/broken\nstill open"')).toBeNull();
  });
});

describe('referencedAssetNames', () => {
  // Staging every image in the workspace would cost a copy per unplaced
  // screenshot on every export, so only the names the report actually
  // mentions are staged. Over-inclusion is harmless (one extra file in a
  // directory that is deleted with the export); under-inclusion shows up as
  // a Typst "file not found" against the line that placed the image.
  const names = (source: string) => [...referencedAssetNames(source)].sort();

  it('finds a slot path and a hand-written image call', () => {
    const src = '#image-placeholder("Login", path: "/assets/login.png")\n#image("/assets/shell.png", width: 50%)\n';
    expect(names(src)).toEqual(['login.png', 'shell.png']);
  });

  it('finds a name with spaces in it', () => {
    expect(names('#image("/assets/my first shot.png")')).toEqual(['my first shot.png']);
  });

  it('lists a name referenced twice only once', () => {
    expect(names('#image("/assets/a.png")\n#image("/assets/a.png")\n')).toEqual(['a.png']);
  });

  it('matches a subfolder path by its basename, which stages the file flat', () => {
    // Typst would then fail to resolve /assets/sub/x.png, because staging is
    // flat. Staging the file anyway costs one copy and keeps the failure a
    // plain Typst diagnostic rather than a silent skip.
    expect(names('#image("/assets/sub/x.png")')).toEqual(['x.png']);
  });

  it('finds nothing in a bare /assets/ with no filename', () => {
    expect(names('The prefix is "/assets/" and nothing follows it.')).toEqual([]);
    expect(names('')).toEqual([]);
  });

  it('does not find a name whose string literal escapes a quote', () => {
    // The escape ends the match, so the file is not staged and Typst reports
    // the unresolved path. A filename carrying a double quote is the one
    // shape this scan gives up on, and it is the safe direction to fail.
    expect(names('#image("/assets/od\\"d.png")')).toEqual([]);
  });

  it('matches inside a comment or a raw block, which is accepted over-inclusion', () => {
    expect(names('// #image("/assets/old.png")')).toEqual(['old.png']);
    expect(names('```\n#image("/assets/sample.png")\n```')).toEqual(['sample.png']);
  });

  it('matches a relative reference, which resolves to the same file', () => {
    // A report written in Typst Studio spells it `assets/cover.png`, and from
    // a main.typ at the compile root that is the same file as
    // `/assets/cover.png`. It rendered in the browser and then failed on the
    // server with "file not found", because only the rooted spelling was
    // staged.
    expect(names('#image("assets/cover.png")')).toEqual(['cover.png']);
    expect(names('#image-placeholder("Login", path: "assets/login.png")')).toEqual(['login.png']);
    expect(names('#image("assets/a.png")\n#image("/assets/a.png")\n')).toEqual(['a.png']);
  });

  it('does not match a path that only ends in assets/', () => {
    // `"theme/assets/x.png"` is a different directory, and staging its
    // basename flat would put the wrong picture under a caption.
    expect(names('#image("theme/assets/x.png")')).toEqual([]);
    expect(names('#image("../assets/x.png")')).toEqual([]);
  });
});

describe('bakeFailureMessage', () => {
  // Every redaction runs in a child of its own, and anything other than
  // "result says ok AND a non-empty file" stops the export. This is what the
  // operator reads when that happens, and it is the only place that decides
  // it, so the whole matrix is here.
  const base = { code: 1, killed: false, signal: null, resultOk: false, resultMessage: null, outputExists: false, stderr: '' };

  it('names our own timeout as a timeout', () => {
    expect(bakeFailureMessage({ ...base, code: 124, killed: true, signal: 'SIGKILL' }, 'shot.png'))
      .toBe('Redacting shot.png took too long on this server. Export the PDF from the browser instead.');
  });

  it('reads a SIGKILL we did not send as the memory killer', () => {
    // After this change the kernel's OOM victim is the child, not the relay,
    // so a cgroup OOM during a bake becomes a 422 rather than a dead server.
    expect(bakeFailureMessage({ ...base, signal: 'SIGKILL' }, 'shot.png'))
      .toBe('The export ran out of memory on the server. Export the PDF from the browser instead.');
  });

  it('names any other signal death', () => {
    expect(bakeFailureMessage({ ...base, signal: 'SIGSEGV' }, 'shot.png'))
      .toBe('The exporter stopped unexpectedly (bake, SIGSEGV).');
  });

  it('passes the child result message through, which already starts with the filename', () => {
    expect(bakeFailureMessage({ ...base, resultMessage: 'shot.webp: webp images with crop or blur cannot be baked server-side; export from the app instead' }, 'shot.webp'))
      .toBe('shot.webp: webp images with crop or blur cannot be baked server-side; export from the app instead');
  });

  it('scrubs a staged path out of the child result message', () => {
    expect(bakeFailureMessage({ ...base, resultMessage: 'shot.png: ENOENT, open /var/tmp/btct-bake-Ab12Cd/0/out.part' }, 'shot.png'))
      .toBe('shot.png: ENOENT, open .');
  });

  it('caps an over-long child result message at 300 characters', () => {
    const long = `shot.png: ${'x'.repeat(500)}`;
    const out = bakeFailureMessage({ ...base, resultMessage: long }, 'shot.png');
    expect(out).toHaveLength(300);
    expect(out.endsWith('\u2026')).toBe(true);
  });

  it('says the step produced nothing when the child exited cleanly with no image', () => {
    expect(bakeFailureMessage({ ...base, code: 0, resultOk: true, resultMessage: '', outputExists: false }, 'shot.png'))
      .toBe('shot.png: the redaction step produced no image, so the export was stopped.');
    expect(bakeFailureMessage({ ...base, code: 0, resultOk: false, resultMessage: '' }, 'shot.png'))
      .toBe('shot.png: the redaction step produced no image, so the export was stopped.');
  });

  it('falls back to the child stderr only when there is no result file at all', () => {
    // resultMessage null means nothing was written; an empty string means a
    // result file that said nothing, and then the stderr is not the story.
    expect(bakeFailureMessage({ ...base, stderr: 'Segmentation fault' }, 'shot.png'))
      .toBe('shot.png: the redaction step failed. Segmentation fault');
    expect(bakeFailureMessage({ ...base, resultMessage: '', stderr: 'Segmentation fault' }, 'shot.png'))
      .toBe('shot.png: the redaction step produced no image, so the export was stopped.');
  });

  it('scrubs and caps the stderr fallback too', () => {
    const out = bakeFailureMessage({ ...base, stderr: `at /var/tmp/btct-bake-Ab12Cd/0 ${'y'.repeat(500)}` }, 'shot.png');
    expect(out).toHaveLength(300);
    expect(out).toContain('shot.png: the redaction step failed. at . ');
  });

  it('survives a result with missing fields', () => {
    expect(bakeFailureMessage({}, 'shot.png')).toBe('shot.png: the redaction step produced no image, so the export was stopped.');
    expect(bakeFailureMessage(null, 'shot.png')).toBe('shot.png: the redaction step produced no image, so the export was stopped.');
  });
});

describe('docxFailureMessage', () => {
  // The Word file is made by a Python child that converts the finished PDF.
  // Success is a result file saying ok AND a non-empty .docx; every other
  // shape ends up here, and the PDF is always still an option, so each
  // message says so.
  const base = { code: 1, killed: false, signal: null, resultOk: false, resultMessage: null, outputExists: false, stderr: '' };

  it('names our own timeout as a timeout', () => {
    expect(docxFailureMessage({ ...base, code: 124, killed: true, signal: 'SIGKILL' }))
      .toBe('Converting this report to Word took too long on this server. Export the PDF instead.');
  });

  it('reads a SIGKILL we did not send as the memory killer', () => {
    // pdf2docx holds a page's blocks and an OpenCV buffer at once, so on a
    // 1 GB box the cgroup killer lands on this child rather than the relay.
    expect(docxFailureMessage({ ...base, signal: 'SIGKILL' }))
      .toBe('The export ran out of memory on the server. Export the PDF from the browser instead.');
  });

  it('names any other signal death', () => {
    expect(docxFailureMessage({ ...base, signal: 'SIGSEGV' })).toBe('The exporter stopped unexpectedly (pdf2docx, SIGSEGV).');
  });

  it('quotes what the converter wrote in its result file', () => {
    expect(docxFailureMessage({ ...base, resultMessage: 'ValueError: the PDF has no pages' }))
      .toBe('The Word conversion failed. ValueError: the PDF has no pages');
  });

  it('scrubs a staged path out of the result message and caps it', () => {
    expect(docxFailureMessage({ ...base, resultMessage: 'OSError: /var/tmp/btct-typst-Ab12Cd/out.docx.part' }))
      .toBe('The Word conversion failed. OSError: .');
    const out = docxFailureMessage({ ...base, resultMessage: 'x'.repeat(500) });
    expect(out).toHaveLength(300);
    expect(out.endsWith('…')).toBe(true);
  });

  it('falls back to stderr only when no result file was written', () => {
    expect(docxFailureMessage({ ...base, stderr: 'Killed' })).toBe('The Word conversion failed. Killed');
    expect(docxFailureMessage({ ...base, resultMessage: '', stderr: 'Killed' }))
      .toBe('The Word conversion produced no file, so the export was stopped. Export the PDF instead.');
  });

  it('says nothing came out when the child exited cleanly with no file', () => {
    expect(docxFailureMessage({ ...base, code: 0, resultOk: true, resultMessage: '', outputExists: false }))
      .toBe('The Word conversion produced no file, so the export was stopped. Export the PDF instead.');
  });

  it('survives a result with missing fields', () => {
    expect(docxFailureMessage({})).toBe('The Word conversion produced no file, so the export was stopped. Export the PDF instead.');
    expect(docxFailureMessage(null)).toBe('The Word conversion produced no file, so the export was stopped. Export the PDF instead.');
  });
});

describe('encodeWarnings', () => {
  // The value of X-Export-Warnings. Report content reaches it, so it is
  // capped twice: each entry, and the whole encoded header, which has to
  // stay under a proxy's response-head limit.
  const decode = (header: string) => JSON.parse(decodeURIComponent(header)) as string[];

  it('is empty when there is nothing to report', () => {
    expect(encodeWarnings([])).toBe('');
    expect(encodeWarnings(undefined as unknown as string[])).toBe('');
  });

  it('deduplicates and keeps at most ten entries', () => {
    expect(decode(encodeWarnings(['a', 'a', 'b']))).toEqual(['a', 'b']);
    const many = Array.from({ length: 25 }, (_, i) => `warning ${i}`);
    expect(decode(encodeWarnings(many))).toHaveLength(10);
  });

  it('drops whole entries until the encoded header fits', () => {
    // Each entry is already at the 300-character per-entry cap, and a space
    // triples under encodeURIComponent, so ten of them do not fit.
    const list = Array.from({ length: 10 }, (_, i) => `${i} ${'a '.repeat(160)}`);
    const out = decode(encodeWarnings(list));
    expect(out.length).toBeGreaterThan(0);
    expect(out.length).toBeLessThan(10);
    expect(encodeWarnings(list).length).toBeLessThanOrEqual(4000);
  });

  it('truncates one over-long entry instead of dropping the header', () => {
    // Nothing that reaches the header has a length bound of its own.
    // Dropping one over-long entry took every other warning with it, and the
    // operator was told nothing at all.
    const out = decode(encodeWarnings([`shot.png: ${'x'.repeat(5000)}`, 'a second note']));
    expect(out).toHaveLength(2);
    expect(out[0]).toHaveLength(300);
    expect(out[0]!.endsWith('\u2026')).toBe(true);
    expect(out[1]).toBe('a second note');
  });

  it('survives non-ASCII text, which encodes to several characters each', () => {
    const out = decode(encodeWarnings(['Figure "café" was not included: naïve path ünicode ✓']));
    expect(out).toEqual(['Figure "café" was not included: naïve path ünicode ✓']);
    // Three-byte characters triple under encodeURIComponent, so the whole
    // cap still has to hold.
    expect(encodeWarnings(Array.from({ length: 10 }, (_, i) => `${i} ${'✓'.repeat(280)}`)).length).toBeLessThanOrEqual(4000);
  });
});
