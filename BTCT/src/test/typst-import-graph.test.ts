// Source-level guard for invariant #17: the Typst tab stays unreachable from
// the entry bundle.
//
// The build-time check (`grep -l typst_ts_web_compiler dist/assets/index-*.js`
// must find nothing) only runs against a built dist, and it fails long after
// the import that broke it was written. This reads the source instead: from
// outside the two Typst folders, every import that RESOLVES into
// `src/components/typst/` or to a `src/lib/typst-*` module has to be
// type-only or dynamic (what `lazy()` compiles to). A plain
// `import { … } from './typst-compiler'` in a module the shell already loads
// would pull the chunk AND its 28 MB wasm asset into the entry graph.
//
// Specifiers are resolved rather than pattern-matched, because the trap this
// exists to catch is `import { getFontInfo } from './typst-compiler'` inside
// `src/lib/assets.ts`, which contains neither "lib/typst-" nor
// "components/typst" as text.
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const SRC = path.resolve(process.cwd(), 'src');

/** Files that are allowed to reference Typst code directly. */
const EXEMPT_PREFIXES = ['components/typst/', 'lib/typst-', 'test/'];

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) sourceFiles(full, out);
    else if (/\.tsx?$/.test(entry.name)) out.push(full);
  }
  return out;
}

function toPosix(p: string): string {
  return p.split(path.sep).join('/');
}

/**
 * Drop comments, so a commented-out import is not reported. Line comments
 * are only stripped when they start a line, which leaves `https://` inside
 * a string literal alone.
 */
function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');
}

interface ImportRef {
  specifier: string;
  dynamic: boolean;
  /** The statement text, so type-only-ness survives a multi-line clause. */
  statement: string;
  line: number;
}

// Three shapes: a dynamic `import('x')`, an `import … from 'x'` or
// `export … from 'x'` (clause possibly spanning lines), and a bare
// `import 'x'` for side effects.
const IMPORT_RE =
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)|\b(?:import|export)\b[\s\S]{0,400}?\bfrom\s*['"]([^'"]+)['"]|\bimport\s+['"]([^'"]+)['"]/g;

function imports(text: string): ImportRef[] {
  const clean = stripComments(text);
  const found: ImportRef[] = [];
  for (const m of clean.matchAll(IMPORT_RE)) {
    const specifier = m[1] ?? m[2] ?? m[3];
    if (!specifier) continue;
    found.push({
      specifier,
      dynamic: m[1] !== undefined,
      statement: m[0],
      line: clean.slice(0, m.index).split('\n').length,
    });
  }
  return found;
}

/** Absolute path a specifier points at, or null for a bare package name. */
function resolveSpecifier(specifier: string, fromFile: string): string | null {
  if (specifier.startsWith('@/')) return path.resolve(SRC, specifier.slice(2));
  if (specifier.startsWith('./') || specifier.startsWith('../')) {
    return path.resolve(path.dirname(fromFile), specifier);
  }
  return null;
}

/** Does this resolved path land in the Typst tab's own code? */
function isTypstModule(absolute: string): boolean {
  const rel = toPosix(path.relative(SRC, absolute));
  if (rel.startsWith('..')) return false; // outside src/
  // The bare directory counts too: `import { X } from '@/components/typst'`
  // resolves to the folder, which a future index.ts barrel would answer.
  return (
    rel === 'components/typst' ||
    rel.startsWith('components/typst/') ||
    /^lib\/typst-/.test(rel)
  );
}

/** A reference that does not link Typst code into this module's graph. */
function isAllowed(ref: ImportRef): boolean {
  if (ref.dynamic) return true;
  return /^\s*(?:import|export)\s+type\b/.test(ref.statement);
}

describe('the Typst tab is unreachable from the entry bundle (invariant #17)', () => {
  const files = sourceFiles(SRC).filter((f) => {
    const rel = toPosix(path.relative(SRC, f));
    return !EXEMPT_PREFIXES.some((p) => rel.startsWith(p));
  });

  it('scans a meaningful number of files', () => {
    // Cheap guard against the walk silently finding nothing (a moved src/,
    // a changed cwd) and the suite passing for the wrong reason.
    expect(files.length).toBeGreaterThan(50);
  });

  it('imports Typst code only through type imports or dynamic imports', () => {
    const violations: string[] = [];
    for (const file of files) {
      for (const ref of imports(fs.readFileSync(file, 'utf8'))) {
        const target = resolveSpecifier(ref.specifier, file);
        if (!target || !isTypstModule(target)) continue;
        if (isAllowed(ref)) continue;
        violations.push(
          `${toPosix(path.relative(SRC, file))}:${ref.line}: imports '${ref.specifier}'`,
        );
      }
    }
    expect(violations).toEqual([]);
  });
});
