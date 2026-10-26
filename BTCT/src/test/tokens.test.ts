import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { hexToHsl } from '@/lib/theme';
import { cn } from '@/lib/utils';

// Source-level guards for the one token source (src/themes/tokens.css).
const root = process.cwd();
const css = readFileSync(join(root, 'src', 'themes', 'tokens.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');

/** Custom properties declared inside the first block whose selector is exactly `sel`. */
function block(sel: string, nth = 0): Map<string, string> {
  const re = new RegExp(`(^|\\n)${sel.replace('.', '\\.')}\\s*\\{([^}]*)\\}`, 'g');
  const bodies = [...css.matchAll(re)].map((m) => m[2]!);
  const out = new Map<string, string>();
  for (const m of (bodies[nth] ?? '').matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) out.set(m[1]!, m[2]!.trim());
  return out;
}

const light = block(':root', 1);
const dark = block('.dark');

/** A per-device light palette block (`:root[data-light-palette="x"]:not(.dark)`). */
function paletteBlock(name: string): Map<string, string> {
  const m = css.match(new RegExp(`:root\\[data-light-palette="${name}"\\]:not\\(\\.dark\\)\\s*\\{([^}]*)\\}`));
  const out = new Map<string, string>();
  for (const d of (m?.[1] ?? '').matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) out.set(d[1]!, d[2]!.trim());
  return out;
}
const PALETTE_NAMES = ['linen', 'dimmed', 'classic'] as const;
/** Every light palette as it resolves: the :root light block with the palette block on top. */
const lightPalettes: (readonly [string, Map<string, string>])[] = [
  ['paper', light],
  ...PALETTE_NAMES.map((n) => [n, new Map([...light, ...paletteBlock(n)])] as const),
];

describe('tokens.css', () => {
  it('light and dark declare the same colour tokens', () => {
    expect(light.size).toBeGreaterThan(30);
    expect([...dark.keys()].sort()).toEqual([...light.keys()].sort());
  });

  it('every Tailwind colour maps to a token both modes define', () => {
    const mapped = [...css.matchAll(/--color-([\w-]+):\s*([^;]+);/g)];
    expect(mapped.length).toBeGreaterThan(30);
    for (const [, name, value] of mapped) {
      for (const ref of value!.matchAll(/var\((--[\w-]+)\)/g)) {
        if (ref[1] === '--overlay-alpha') continue;
        expect(light.has(ref[1]!), `${name} -> ${ref[1]} (light)`).toBe(true);
        expect(dark.has(ref[1]!), `${name} -> ${ref[1]} (dark)`).toBe(true);
      }
    }
  });

  it('holds the chosen theme values (typst-studio-custom)', () => {
    const expectHex = (map: Map<string, string>, token: string, hex: string) => {
      const want = hexToHsl(hex)!;
      const [h, s, l] = map.get(token)!.replace(/%/g, '').split(/\s+/).map(Number);
      expect(Math.abs(l! - want.l), token).toBeLessThanOrEqual(1);
      if (want.s > 5) {
        expect(Math.abs(s! - want.s), token).toBeLessThanOrEqual(2);
        expect(Math.min(Math.abs(h! - want.h), 360 - Math.abs(h! - want.h)), token).toBeLessThanOrEqual(2);
      }
    };
    expectHex(dark, '--background', '#262626');
    expectHex(dark, '--card', '#2b2b2b');
    expectHex(dark, '--primary', '#ff6c52');
    // Contrast adjustments on top of the theme (4.5:1 for text on the
    // hover fill and on 10 to 15% status tints): dark muted text 61% -> 63%,
    // light coral 51% -> 45% (white on it 5.3:1).
    expectHex(dark, '--muted-foreground', '#a1a1a1');
    // Light is "Paper" (the paper-light study): cream panes on a deeper
    // canvas, the coral at 40.5% so it reads 4.5:1 on cream and on its tint.
    expectHex(light, '--background', '#eeeae1');
    expectHex(light, '--card', '#f9f7f2');
    expectHex(light, '--editor-bg', '#f5f2eb');
    expectHex(light, '--primary', '#b0351f');
    expectHex(light, '--border', '#ddd6c9');
    // Classic keeps the light theme from before Paper.
    const classic = paletteBlock('classic');
    expectHex(classic, '--background', '#f6f5f3');
    expectHex(classic, '--card', '#ffffff');
    expectHex(classic, '--primary', '#c33b22');
    expectHex(classic, '--border', '#e0ddd7');
  });

  it('every light palette block declares the full set of light colour tokens', () => {
    const shared = new Set(['--overlay', '--overlay-alpha', '--media', '--media-foreground', '--code-builtin']);
    const want = [...light.keys()].filter((k) => !shared.has(k)).sort();
    for (const n of PALETTE_NAMES) {
      expect([...paletteBlock(n).keys()].sort(), n).toEqual(want);
    }
  });

  it('no light palette but Classic paints a pure white surface', () => {
    for (const [name, map] of lightPalettes) {
      if (name === 'classic') continue;
      for (const t of ['--background', '--card', '--popover', '--secondary', '--muted', '--accent', '--editor-bg', '--code-bg']) {
        const l = Number(map.get(t)!.split(/\s+/)[2]!.replace('%', ''));
        expect(l, `${name} ${t}`).toBeLessThan(98);
      }
    }
  });

  it('keeps the editor surface darker than the card in dark mode', () => {
    const l = (v: string) => Number(v.split(/\s+/)[2]!.replace('%', ''));
    expect(l(dark.get('--editor-bg')!)).toBeLessThan(l(dark.get('--card')!));
    expect(l(dark.get('--editor-bg')!)).toBeLessThan(l(dark.get('--background')!));
  });

  it('the --op-* names are aliases of the HSL tokens, not a second palette', () => {
    const aliases = [...css.matchAll(/(--op-[\w-]+)\s*:\s*([^;]+);/g)];
    expect(aliases.length).toBeGreaterThan(0);
    for (const [, name, value] of aliases) {
      expect(value, name).not.toMatch(/#[0-9a-f]{3,6}/i);
    }
    const ops = readFileSync(join(root, 'src', 'themes', 'operations.css'), 'utf8');
    expect(ops).not.toMatch(/--op-[\w-]+\s*:/);
  });

  it('serves its fonts from the box, with licences', () => {
    const dir = join(root, 'public', 'ui-fonts');
    for (const m of css.matchAll(/url\("\/ui-fonts\/([^"]+)"\)/g)) {
      expect(existsSync(join(dir, m[1]!)), m[1]).toBe(true);
    }
    expect(readdirSync(dir).filter((f) => f.startsWith('OFL')).length).toBe(2);
    expect(css).not.toMatch(/fonts\.(googleapis|gstatic)\.com/);
  });

  it('cn keeps a named text size next to a text colour', () => {
    expect(cn('text-micro', 'text-muted-foreground')).toBe('text-micro text-muted-foreground');
    expect(cn('text-caption text-meta')).toBe('text-meta');
    expect(cn('text-xs', 'text-caption')).toBe('text-caption');
  });

  it('operations.css never targets Tailwind class names', () => {
    const ops = readFileSync(join(root, 'src', 'themes', 'operations.css'), 'utf8');
    expect(ops).not.toMatch(/\[class[~*^$|]?=/);
  });
});

describe('no hard-coded interface colours', () => {
  // Files allowed to carry literal colours, and why. Everything else in
  // src/ must go through a token or a Tailwind utility from tokens.css.
  const ALLOWED: Record<string, string> = {
    'lib/swatches.ts': 'preset colours people pick and save (data)',
    'lib/contrast.ts': 'the black/white text candidates',
    'lib/theme.ts': 'the theme primary as hex for the colour wheel',
    'lib/assets.ts': 'figure gap fill baked into exported images',
    'lib/editor-prefs.ts': 'legacy default code accent (data)',
    'components/ui/HeadingColorPicker.tsx': 'colour wheel start value',
    'components/assets/FigureViewport.tsx': 'figure paper and difference-blend crop guides on image content',
    'components/typst/TypstPreview.tsx': 'report pages are white paper in both modes',
    'lib/typst-findings.ts': 'the Typst finding-block helper is report source; its rgb() values are the printed report palette, not interface colours',
  };
  const literal = /(?<![\w-])(?:[\w:-]*:)?(?:text|bg|border|ring|outline|divide|fill|stroke)-(?:white|black)(?![\w-])|['"`(: ]#[0-9a-fA-F]{3,6}\b|rgba?\(\s*\d/;
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const f of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, f.name);
      if (f.isDirectory()) { if (f.name !== 'test') walk(p); } else if (/\.(tsx?|)$/.test(f.name) && /\.tsx?$/.test(f.name)) files.push(p);
    }
  };
  walk(join(root, 'src'));

  it.each(files.map((f) => [f.slice(join(root, 'src').length + 1)]))('%s', (rel) => {
    if (ALLOWED[rel]) return;
    const lines = readFileSync(join(root, 'src', rel), 'utf8').split('\n');
    const hits = lines.map((l, i) => [i + 1, l] as const).filter(([, l]) => literal.test(l));
    expect(hits.map(([n, l]) => `${n}: ${l.trim()}`)).toEqual([]);
  });
});

describe('editor and code colours', () => {
  const hslToRgb = (triplet: string): [number, number, number] => {
    const [h, s, l] = triplet.replace(/%/g, '').split(/\s+/).map(Number) as [number, number, number];
    const S = s / 100, L = l / 100;
    const k = (n: number) => (n + h / 30) % 12;
    const a = S * Math.min(L, 1 - L);
    const f = (n: number) => L - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
    return [f(0) * 255, f(8) * 255, f(4) * 255];
  };
  const hexToRgb = (hex: string): [number, number, number] => {
    const m = hex.replace('#', '');
    return [0, 2, 4].map((i) => parseInt(m.slice(i, i + 2), 16)) as [number, number, number];
  };
  const lum = ([r, g, b]: [number, number, number]) => {
    const f = (v: number) => { v /= 255; return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const ratio = (a: [number, number, number], b: [number, number, number]) => {
    const x = lum(a), y = lum(b);
    return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
  };
  // The 3.5% foreground wash code-chrome.ts paints on the focused line.
  const wash = (bg: [number, number, number], fg: [number, number, number]) =>
    bg.map((v, i) => v * 0.965 + fg[i]! * 0.035) as [number, number, number];

  it.each([...lightPalettes.map(([n, m]) => [`light ${n}`, m] as const), ['dark', dark] as const])('%s code colours read at 4.5:1 on a code block, the editor and the active line', (_mode, map) => {
    const fg = hexToRgb(map.get('--code-fg')!);
    const surfaces = {
      code: hslToRgb(map.get('--code-bg')!),
      editor: hslToRgb(map.get('--editor-bg')!),
    };
    const colours = [...map].filter(([k, v]) => /^--(code|term)-/.test(k) && /^#[0-9a-f]{6}$/i.test(v));
    expect(colours.length).toBeGreaterThan(20);
    for (const [token, value] of colours) {
      for (const [name, bg] of Object.entries(surfaces)) {
        expect(ratio(hexToRgb(value), bg), `${token} ${value} on ${name}`).toBeGreaterThanOrEqual(4.5);
        expect(ratio(hexToRgb(value), wash(bg, fg)), `${token} ${value} on ${name} active line`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  it.each([...lightPalettes.map(([n, m]) => [`light ${n}`, m] as const), ['dark', dark] as const])('%s green badge text reads at 4.5:1 on its 12% tint over a hovered row', (_mode, map) => {
    // Badge tone green is bg-status-green/12 text-status-green; an nmap host
    // row is a button with hover:bg-accent, so the tint sits on --accent.
    const green = hslToRgb(map.get('--status-green')!);
    for (const surface of ['--accent', '--card', '--background']) {
      const under = hslToRgb(map.get(surface)!);
      const tint = under.map((v, i) => v * 0.88 + green[i]! * 0.12) as [number, number, number];
      expect(ratio(green, tint), `status-green on its tint over ${surface}`).toBeGreaterThanOrEqual(4.5);
    }
  });

  // Findings rail "Tinted section" (BTCT Theme Studio variant B). Severity
  // colours are the CPTC report's; every section surface is pre-mixed per
  // palette, so the checks below read the real fills.
  const REPORT = { critical: '#674ea7', high: '#c0504d', medium: '#ef9b46', low: '#f5d979' } as const;
  const SOLID = { critical: '#674ea7', high: '#c0504d', medium: '#b1600f', low: '#8f710b' } as const;
  const SEV_TINT = { dark: { row: 0.08, head: 0.16, hover: 0.13 }, light: { row: 0.1, head: 0.2, hover: 0.16 } };
  const sevModes = [...lightPalettes.map(([n, m]) => [`light ${n}`, m, 'light'] as const), ['dark', dark, 'dark'] as const];
  it.each(sevModes)('%s severity sections keep their contrast', (_mode, map, kind) => {
    const rgb = (t: string) => hslToRgb(map.get(t)!);
    const near = (a: [number, number, number], b: [number, number, number], what: string) => {
      for (let i = 0; i < 3; i++) expect(Math.abs(a[i]! - b[i]!), what).toBeLessThanOrEqual(1.5);
    };
    const mixed = (c: [number, number, number], under: [number, number, number], t: number) =>
      under.map((v, i) => v * (1 - t) + c[i]! * t) as [number, number, number];
    for (const [sev, hex] of Object.entries(REPORT)) {
      const c = rgb(`--sev-${sev}`);
      near(c, hexToRgb(hex), `--sev-${sev} is the report colour`);
      const k = SEV_TINT[kind];
      const head = rgb(`--sev-${sev}-head`);
      const row = rgb(`--sev-${sev}-row`);
      const hover = rgb(`--sev-${sev}-hover`);
      near(head, mixed(c, rgb('--card'), k.head), `${sev} header tint`);
      near(row, mixed(c, rgb('--card'), k.row), `${sev} row tint`);
      near(hover, mixed(c, rgb('--accent'), k.hover), `${sev} hover tint`);
      // A filled label (badge, pressed severity chip) is white bold text on
      // -solid: the report colour where white reads at 4.5:1, else the same
      // hue and saturation darkened (Medium #b1600f, Low #8f710b).
      near(rgb(`--sev-${sev}-fg`), [255, 255, 255], `${sev} label text is white`);
      const solid = rgb(`--sev-${sev}-solid`);
      expect(ratio(rgb(`--sev-${sev}-fg`), solid), `${sev} badge text`).toBeGreaterThanOrEqual(4.5);
      near(solid, hexToRgb(SOLID[sev as keyof typeof SOLID]), `--sev-${sev}-solid`);
      const [h0, s0] = (map.get(`--sev-${sev}`)!).split(/\s+/).map(parseFloat);
      const [h1, s1] = (map.get(`--sev-${sev}-solid`)!).split(/\s+/).map(parseFloat);
      expect(Math.abs(h0! - h1!), `${sev} solid keeps the hue`).toBeLessThanOrEqual(0.5);
      expect(Math.abs(s0! - s1!), `${sev} solid keeps the saturation`).toBeLessThanOrEqual(0.5);
      expect(ratio(rgb(`--sev-${sev}-ink`), head), `${sev} chevron and count on the header`).toBeGreaterThanOrEqual(4.5);
      for (const [where, bg] of [['row', row], ['hover', hover], ['header', head]] as const) {
        expect(ratio(rgb(`--sev-${sev}-muted`), bg), `${sev} muted text on the ${where}`).toBeGreaterThanOrEqual(4.5);
        expect(ratio(rgb('--foreground'), bg), `${sev} title on the ${where}`).toBeGreaterThanOrEqual(4.5);
      }
      // A selected status pill: its status colour at 20% over the row.
      for (const st of ['--status-amber', '--status-blue', '--status-green']) {
        expect(ratio(rgb('--foreground'), mixed(rgb(st), row, 0.2)), `${sev} ${st} pill`).toBeGreaterThanOrEqual(4.5);
      }
    }
    // The count in a filter chip takes the chip's own text colour (it used to
    // be drawn at 60% opacity, 2.5 to 2.9:1): muted on the card, foreground
    // on a pressed chip (bg-primary/15 over the card).
    expect(ratio(rgb('--muted-foreground'), rgb('--card')), 'chip count').toBeGreaterThanOrEqual(4.5);
    expect(ratio(rgb('--foreground'), mixed(rgb('--primary'), rgb('--card'), 0.15)), 'chip count, pressed').toBeGreaterThanOrEqual(4.5);
  });

  // The candidate palettes were fitted to these rules (Classic predates
  // them and is pinned above as it shipped, so it is left out here).
  it.each(lightPalettes.filter(([n]) => n !== 'classic'))('light %s text, accent and status colours read at 4.5:1', (_n, map) => {
    const rgb = (t: string) => hslToRgb(map.get(t)!);
    const tint = (under: [number, number, number], c: [number, number, number], t: number) =>
      under.map((v, i) => v * (1 - t) + c[i]! * t) as [number, number, number];
    const surfaces = ['--card', '--popover', '--background', '--accent', '--muted', '--secondary', '--editor-bg'];
    for (const text of ['--foreground', '--muted-foreground']) {
      for (const s of surfaces) expect(ratio(rgb(text), rgb(s)), `${text} on ${s}`).toBeGreaterThanOrEqual(4.5);
    }
    expect(ratio(rgb('--muted-foreground'), rgb('--code-bg')), 'muted text on a code block').toBeGreaterThanOrEqual(4.5);
    expect(ratio(rgb('--foreground'), rgb('--selection')), 'text on the selection').toBeGreaterThanOrEqual(4.5);
    const white: [number, number, number] = [255, 255, 255];
    expect(ratio(white, rgb('--primary')), 'white on the accent').toBeGreaterThanOrEqual(4.5);
    expect(ratio(white, rgb('--destructive')), 'white on destructive').toBeGreaterThanOrEqual(4.5);
    for (const c of ['--primary', '--status-green', '--status-blue', '--status-purple', '--status-amber', '--status-red']) {
      for (const s of surfaces) expect(ratio(rgb(c), rgb(s)), `${c} on ${s}`).toBeGreaterThanOrEqual(4.5);
      // Badges and banners: a 10 to 15% tint on the card or the canvas; the
      // accent as text only sits on its 10% tint (bg-primary/10 text-primary).
      for (const s of ['--card', '--background']) {
        for (const t of c === '--primary' ? [0.1] : [0.1, 0.12, 0.15]) {
          expect(ratio(rgb(c), tint(rgb(s), rgb(c), t)), `${c} on its ${t * 100}% tint over ${s}`).toBeGreaterThanOrEqual(4.5);
        }
      }
    }
  });

  it('maps every Crepe colour variable Crepe uses onto a token', () => {
    const dir = join(root, 'node_modules', '@milkdown', 'crepe', 'lib', 'theme', 'common');
    const used = new Set<string>();
    for (const f of readdirSync(dir).filter((n) => n.endsWith('.css'))) {
      for (const m of readFileSync(join(dir, f), 'utf8').matchAll(/var\((--crepe-[\w-]+)/g)) used.add(m[1]!);
    }
    expect(used.size).toBeGreaterThan(10);
    for (const name of used) {
      const decl = css.match(new RegExp(`${name}:\\s*([^;]+);`));
      expect(decl, name).not.toBeNull();
      expect(decl![1], name).not.toMatch(/#[0-9a-f]{3,6}|rgba?\(/i);
    }
  });

  it('imports no Crepe colour theme, and the editor stylesheets carry no literal colours', () => {
    const sources: string[] = [];
    const walk = (dir: string) => {
      for (const f of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, f.name);
        if (f.isDirectory()) { if (f.name !== 'test') walk(p); } else if (/\.(tsx?|css)$/.test(f.name)) sources.push(p);
      }
    };
    walk(join(root, 'src'));
    for (const f of sources) {
      expect(readFileSync(f, 'utf8'), f).not.toMatch(/@milkdown\/crepe\/theme\/(?!common)/);
    }
    for (const rel of ['index.css', 'components/editor/live-preview/live-preview.css']) {
      const text = readFileSync(join(root, 'src', rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
      const hits = text.split('\n').filter((l) => /#[0-9a-fA-F]{3,6}\b|rgba?\(\s*\d/.test(l));
      expect(hits, rel).toEqual([]);
    }
  });
});
