// ─────────────────────────────────────────────────────────────────────────
// Working out how big a figure box will actually be on the page.
//
// The crop editor frames the image with the *real* figure box, so it needs
// that box's aspect ratio before the document has been compiled. The box is
// `width: 90%` of the text column by `height: <slot's height argument>`, so:
//
//     box width = (page width − left margin − right margin) × 0.9
//
// Everything is resolved to points (72 per inch), Typst's own absolute unit.
//
// This reads the document's `#set page(…)` rather than asking the compiler,
// because the frame has to reshape live as you drag the height control:
// round-tripping through a compile per keystroke would be far too slow. The
// parse covers the forms a report preamble realistically uses and falls back
// to Typst's own defaults (A4, 2.5/21 margins) when it can't tell.
// ─────────────────────────────────────────────────────────────────────────

/** Points per unit, for every absolute length Typst accepts. */
const UNIT_PT: Record<string, number> = {
  pt: 1,
  mm: 72 / 25.4,
  cm: 72 / 2.54,
  in: 72,
};

/** Typst's default page is A4. */
export const DEFAULT_PAGE_WIDTH_PT = 595.28;

/**
 * Typst's default margin is 2.5/21 of the smaller page dimension. For A4
 * that's ~70.87pt (2.5cm), which is what an unstyled document gets.
 */
const DEFAULT_MARGIN_RATIO = 2.5 / 21;

/** The `width: 90%` in the placeholder helper's block. */
export const FIGURE_WIDTH_FRACTION = 0.9;

/** Named paper sizes worth recognizing in a `#set page(paper: …)`. */
const PAPER_WIDTH_PT: Record<string, number> = {
  a3: 841.89,
  a4: 595.28,
  a5: 419.53,
  'us-letter': 612,
  letter: 612,
  'us-legal': 612,
  legal: 612,
  'us-tabloid': 792,
};

/** Parse a Typst ratio like `60%` as a fraction (0.6). Null if not one. */
export function parseRatio(text: string): number | null {
  const m = /^\s*(\d*\.?\d+)\s*%\s*$/.exec(text);
  if (!m) return null;
  const value = Number(m[1]) / 100;
  return Number.isFinite(value) && value > 0 ? value : null;
}

/** A fraction (0.6) as a Typst ratio (`60%`), to a whole percent. */
export function formatRatio(fraction: number): string {
  return `${Math.round(fraction * 100)}%`;
}

/** Parse an absolute Typst length like `1.5cm`, `2.2in`, `72pt`. */
export function parseLength(text: string): number | null {
  const m = /^\s*(-?\d*\.?\d+)\s*(pt|mm|cm|in)\s*$/i.exec(text);
  if (!m) return null;
  const value = Number(m[1]);
  const unit = UNIT_PT[m[2]!.toLowerCase()];
  if (!Number.isFinite(value) || unit === undefined) return null;
  return value * unit;
}

/** Format points back into a compact Typst length, in the requested unit. */
export function formatLength(pt: number, unit: 'in' | 'cm' | 'pt' = 'in'): string {
  const value = pt / UNIT_PT[unit]!;
  // Two decimals is finer than anyone positions a figure by, and avoids
  // writing floating-point noise into the document.
  const rounded = Math.round(value * 100) / 100;
  return `${rounded}${unit}`;
}

/** Extract the balanced argument text of the first `#set page(...)` call. */
function pageArgs(source: string): string | null {
  const at = source.indexOf('#set page(');
  if (at === -1) return null;
  const open = at + '#set page('.length - 1;
  let depth = 0;
  let inString = false;
  for (let i = open; i < source.length; i++) {
    const ch = source[i]!;
    if (inString) {
      if (ch === '\\') { i++; continue; }
      if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { inString = true; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return source.slice(open + 1, i);
    }
  }
  return null;
}

/** Read a top-level named argument's raw text out of an argument list. */
function namedArg(args: string, name: string): string | null {
  const re = new RegExp(`(^|,)\\s*${name}\\s*:`, 'g');
  const m = re.exec(args);
  if (!m) return null;
  let i = m.index + m[0].length;
  let depth = 0;
  let inString = false;
  const start = i;
  for (; i < args.length; i++) {
    const ch = args[i]!;
    if (inString) {
      if (ch === '\\') { i++; continue; }
      if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { inString = true; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    else if (ch === ',' && depth === 0) break;
  }
  return args.slice(start, i).trim();
}

/**
 * Total horizontal margin (left + right) implied by a `margin:` argument.
 *
 * Handles the three shapes a preamble actually uses: a bare length applied to
 * all sides, a dictionary with `x:`, and a dictionary with explicit
 * `left:`/`right:`. Anything else falls back to the default ratio.
 */
function horizontalMargin(marginArg: string | null, pageWidth: number): number {
  const fallback = pageWidth * DEFAULT_MARGIN_RATIO * 2;
  if (!marginArg) return fallback;

  const flat = parseLength(marginArg);
  if (flat !== null) return flat * 2;

  if (marginArg.startsWith('(')) {
    const inner = marginArg.slice(1, -1);
    const x = namedArg(inner, 'x');
    if (x) {
      const v = parseLength(x);
      if (v !== null) return v * 2;
    }
    const left = namedArg(inner, 'left');
    const right = namedArg(inner, 'right');
    const lv = left ? parseLength(left) : null;
    const rv = right ? parseLength(right) : null;
    if (lv !== null || rv !== null) {
      const rest = namedArg(inner, 'rest');
      const restV = rest ? parseLength(rest) : null;
      return (lv ?? restV ?? pageWidth * DEFAULT_MARGIN_RATIO)
        + (rv ?? restV ?? pageWidth * DEFAULT_MARGIN_RATIO);
    }
    const rest = namedArg(inner, 'rest');
    const restV = rest ? parseLength(rest) : null;
    if (restV !== null) return restV * 2;
  }

  return fallback;
}

export interface FigureBox {
  /** Width of the figure block, in points. */
  widthPt: number;
  /** Height of the figure block, in points. */
  heightPt: number;
  /** widthPt / heightPt: what the crop is locked to. */
  aspect: number;
}

/** Default figure height when a slot doesn't specify one (the helper's default). */
export const DEFAULT_FIGURE_HEIGHT_PT = 2.2 * 72;

/**
 * Width of the figure block for a document, in points.
 *
 * Best-effort: an exotic preamble (a `#set page` behind a conditional, a
 * custom `#show` rule that changes the column width) will give a slightly
 * wrong frame. The dialog shows the resulting dimensions so a mismatch is
 * visible, and the height control lets it be dialled in regardless.
 */
export function figureWidthPt(source: string, widthFraction = FIGURE_WIDTH_FRACTION): number {
  const args = pageArgs(source);

  let pageWidth = DEFAULT_PAGE_WIDTH_PT;
  if (args) {
    const widthArg = namedArg(args, 'width');
    const parsedWidth = widthArg ? parseLength(widthArg) : null;
    if (parsedWidth !== null && parsedWidth > 0) {
      pageWidth = parsedWidth;
    } else {
      // `paper` is positional in Typst: `#set page("us-letter")` is the form
      // the docs show, so accept it next to the named spelling.
      const paperArg = namedArg(args, 'paper') ?? (/^\s*"([a-z0-9-]+)"/i.exec(args)?.[1] ?? null);
      const paper = paperArg?.replace(/^"|"$/g, '').toLowerCase();
      if (paper && PAPER_WIDTH_PT[paper]) pageWidth = PAPER_WIDTH_PT[paper]!;
    }
  }

  const margins = horizontalMargin(args ? namedArg(args, 'margin') : null, pageWidth);
  const textWidth = Math.max(pageWidth - margins, 1);
  return textWidth * widthFraction;
}

/**
 * Resolve the full box for a slot whose `height:` argument is `heightPt` and
 * whose `width:` is `widthFraction` of the text width (the helper's 90% when
 * the slot does not set one).
 */
export function figureBox(
  source: string,
  heightPt = DEFAULT_FIGURE_HEIGHT_PT,
  widthFraction = FIGURE_WIDTH_FRACTION,
): FigureBox {
  const widthPt = figureWidthPt(source, widthFraction);
  const h = Math.max(heightPt, 1);
  return { widthPt, heightPt: h, aspect: widthPt / h };
}
