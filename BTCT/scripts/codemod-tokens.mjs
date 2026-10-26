// One-off codemod for the token migration (redesign phase 2), kept so the
// rewrite can be re-run on a branch that predates it.
//
//   bun scripts/codemod-tokens.mjs [--check] [paths...]   (default: src)
//
// 1. Arbitrary token colours become the semantic utilities from
//    src/themes/tokens.css, keeping any opacity:
//      bg-[hsl(var(--card))]             -> bg-card
//      bg-[hsl(var(--primary))]/15        -> bg-primary/15
//      bg-[hsl(var(--muted)/0.4)]         -> bg-muted/40
// 2. Pixel font sizes become the named type scale:
//      text-[8px] text-[9px] -> text-micro, text-[10px] -> text-caption,
//      text-[11px] -> text-meta, text-[12px] -> text-xs, text-[13px] -> text-ui
//
// Only the Tailwind arbitrary-value shape `<utility>-[...]` is touched, so
// `hsl(var(--x))` inside a style object or a CodeMirror theme string is left
// alone. --check prints what would change and exits 1 if anything would.
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const TOKENS = new Set([
  'background', 'foreground', 'card', 'card-foreground', 'popover', 'popover-foreground',
  'primary', 'primary-foreground', 'secondary', 'secondary-foreground', 'muted', 'muted-foreground',
  'accent', 'accent-foreground', 'destructive', 'destructive-foreground', 'border', 'input', 'ring',
  'selection', 'status-green', 'status-blue', 'status-purple', 'status-amber', 'status-red',
]);
const SIZES = { '8px': 'micro', '9px': 'micro', '10px': 'caption', '11px': 'meta', '12px': 'xs', '13px': 'ui' };

const pct = (a) => {
  const n = Math.round(Number(a) * 1000) / 10;
  return Number.isInteger(n) ? String(n) : `[${a}]`;
};

export function rewrite(src) {
  let out = src.replace(
    /(?<![\w-])([a-z][\w-]*)-\[hsl\(var\(--([a-z-]+)\)(?:\s*\/\s*([\d.]+))?\)\](\/\d+)?/g,
    (whole, util, token, inner, outer) => {
      if (!TOKENS.has(token)) return whole;
      if (inner && outer) return whole; // two alphas: leave for a human
      return `${util}-${token}${inner ? '/' + pct(inner) : outer ?? ''}`;
    },
  );
  out = out.replace(/(?<![\w-])text-\[(\d+px)\]/g, (whole, px) => (SIZES[px] ? `text-${SIZES[px]}` : whole));
  return out;
}

function walk(p, files) {
  if (statSync(p).isDirectory()) {
    for (const f of readdirSync(p)) if (f !== 'node_modules' && f !== 'test') walk(join(p, f), files);
  } else if (/\.(tsx|ts)$/.test(p)) files.push(p);
  return files;
}

if (import.meta.main ?? process.argv[1]?.endsWith('codemod-tokens.mjs')) {
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  const roots = args.filter((a) => !a.startsWith('--'));
  const files = (roots.length ? roots : ['src']).flatMap((r) => walk(r, []));
  let changed = 0;
  for (const f of files) {
    const before = readFileSync(f, 'utf8');
    const after = rewrite(before);
    if (after === before) continue;
    changed++;
    if (check) console.log('would change', f);
    else writeFileSync(f, after);
  }
  console.log(`${changed} file(s) ${check ? 'need changes' : 'rewritten'}`);
  if (check && changed) process.exit(1);
}
