import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// The operations skin is plain CSS, so these are source-level guards for the rules
// a future edit could break without noticing in the base theme. Read from
// disk (vitest runs at the repo root): vitest hands CSS imports back empty.
const css = readFileSync(join(process.cwd(), 'src', 'themes', 'operations.css'), 'utf8');

/** Bodies of every `@media (prefers-reduced-motion: reduce)` block, brace-balanced. */
function reducedMotionBlocks(source: string): string[] {
  const blocks: string[] = [];
  const re = /@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source))) {
    let depth = 1;
    let i = m.index + m[0].length;
    const start = i;
    while (i < source.length && depth > 0) {
      if (source[i] === '{') depth++;
      else if (source[i] === '}') depth--;
      i++;
    }
    blocks.push(source.slice(start, i - 1));
  }
  return blocks;
}

/** `[selector, body]` pairs for the flat rules inside a block, comments stripped. */
function rules(block: string): Array<[string, string]> {
  const bare = block.replace(/\/\*[\s\S]*?\*\//g, '');
  return (bare.match(/[^{}]+\{[^}]*\}/g) ?? []).map((rule) => {
    const brace = rule.indexOf('{');
    return [rule.slice(0, brace).trim(), rule.slice(brace + 1, -1)];
  });
}

describe('operations theme stylesheet', () => {
  it('has a reduced-motion block that silences transitions and animations', () => {
    const blocks = reducedMotionBlocks(css);
    expect(blocks.length).toBeGreaterThan(0);
    const wildcard = blocks.flatMap(rules).filter(([selector]) => selector.includes('*'));
    expect(wildcard.length).toBeGreaterThan(0);
    for (const [, body] of wildcard) {
      expect(body).toMatch(/transition\s*:\s*none/);
      expect(body).toMatch(/animation\s*:\s*none/);
    }
  });

  it('never resets transform on a wildcard selector under reduced motion', () => {
    // The Typst preview is an SVG positioned entirely by `transform`
    // attributes, and the graph canvas pans, zooms and places nodes with
    // inline transforms. A CSS `transform: none` on `*` overrides the SVG
    // presentation attribute, so with reduced motion on every glyph collapsed
    // to the page origin at font-unit scale and rendered as a black blob.
    for (const block of reducedMotionBlocks(css)) {
      for (const [selector, body] of rules(block)) {
        if (selector.includes('*')) {
          expect(body, `wildcard rule "${selector}" must not touch transform`).not.toMatch(/transform\s*:/);
        }
      }
    }
  });
});
