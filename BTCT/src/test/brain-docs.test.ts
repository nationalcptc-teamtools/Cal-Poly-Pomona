import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, dirname, resolve, relative } from 'node:path';

// Guards for the always-loaded CLAUDE.md and the optional, removable docs/brain/.
// The brain checks skip when docs/brain is absent (see its INDEX.md removal recipe).
const root = process.cwd();
const EM = '\u2014';
const CO_AUTHOR_RULE =
  'WHEN PUSHING TO GITHUB NEVER ADD CLAUDE AS CO AUTHOR AND ANY EVIDENCE OF IT BEING A AUTHOR OR CO CONTRIBUTOR OR AUTHOR REMOVE CLAUDE AS AN AUTHOR.';

const claudePath = join(root, 'CLAUDE.md');
const brainDir = join(root, 'docs', 'brain');
const converterDir = join(brainDir, 'converter');

function walkMd(dir: string, skip?: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (skip && p === skip) continue;
    if (statSync(p).isDirectory()) out.push(...walkMd(p, skip));
    else if (name.endsWith('.md')) out.push(p);
  }
  return out;
}

describe('root CLAUDE.md', () => {
  const text = readFileSync(claudePath, 'utf8');
  const lines = text.split('\n');

  it('stays within 200 lines and 20 KB', () => {
    expect(lines.length).toBeLessThanOrEqual(200);
    expect(Buffer.byteLength(text, 'utf8')).toBeLessThanOrEqual(20 * 1024);
  });

  it('keeps the heading and the verbatim co-author rule on lines 1 and 2', () => {
    expect(lines[0]).toBe('# CLAUDE.md');
    expect(lines[1]).toBe(CO_AUTHOR_RULE);
  });

  it('has no em dash outside the writing-style section', () => {
    let inStyle = false;
    const offenders: number[] = [];
    lines.forEach((line, i) => {
      if (line.startsWith('## ')) inStyle = line.startsWith('## Writing style');
      if (!inStyle && line.includes(EM)) offenders.push(i + 1);
    });
    expect(offenders).toEqual([]);
  });

  it('points at an existing docs/ARCHITECTURE.md', () => {
    expect(existsSync(join(root, 'docs', 'ARCHITECTURE.md'))).toBe(true);
    expect(text).toContain('docs/ARCHITECTURE.md#critical-invariants');
  });

  it('does not require the brain', () => {
    const brainLines = lines.filter((l) => l.includes('docs/brain'));
    for (const l of brainLines) expect(l).toMatch(/optional/i);
  });
});

describe.skipIf(!existsSync(brainDir))('docs/brain (optional)', () => {
  // Collected lazily: a skipped describe still runs its body during collection.
  const pages = () => walkMd(brainDir, converterDir);

  it('INDEX.md is at most 120 lines', () => {
    const index = readFileSync(join(brainDir, 'INDEX.md'), 'utf8');
    expect(index.split('\n').length).toBeLessThanOrEqual(120);
  });

  it('has no em dashes outside converter/', () => {
    const hits = pages().filter((p) => readFileSync(p, 'utf8').includes(EM)).map((p) => relative(root, p));
    expect(hits).toEqual([]);
  });

  it('reports em dash counts in the legacy converter notes', () => {
    if (!existsSync(converterDir)) return;
    let files = 0;
    let dashes = 0;
    for (const p of walkMd(converterDir)) {
      const n = readFileSync(p, 'utf8').split(EM).length - 1;
      if (n) { files++; dashes += n; }
    }
    console.info(`[brain-docs] converter notes: ${dashes} em dashes in ${files} files (legacy, not enforced)`);
    expect(dashes).toBeGreaterThanOrEqual(0);
  });

  it('every relative markdown link outside converter/ resolves', () => {
    const broken: string[] = [];
    for (const p of pages()) {
      const body = readFileSync(p, 'utf8').replace(/```[\s\S]*?```/g, '').replace(/`[^`\n]*`/g, '');
      for (const m of body.matchAll(/\[[^\]\n]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
        const target = m[1]!;
        if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('#')) continue;
        const file = decodeURI(target.split('#')[0]!);
        if (!existsSync(resolve(dirname(p), file))) broken.push(`${relative(root, p)} -> ${target}`);
      }
    }
    expect(broken).toEqual([]);
  });
});
