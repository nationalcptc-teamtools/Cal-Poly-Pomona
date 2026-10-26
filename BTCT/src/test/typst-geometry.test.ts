import { describe, it, expect } from 'vitest';
import {
  DEFAULT_FIGURE_HEIGHT_PT,
  figureBox,
  figureWidthPt,
  formatLength,
  parseLength,
} from '@/lib/typst-geometry';

/**
 * Ground truth measured from the real Typst compiler, via
 *   #layout(s => metadata((w: (0.9 * s.width).pt())))
 * The parser has to agree with these or the crop viewport frames the wrong
 * shape and the WYSIWYG guarantee breaks.
 */
const TYPST_TRUTH: { preamble: string; label: string; widthPt: number }[] = [
  { preamble: '#set page(margin: 1.5cm)', label: 'A4 + 1.5cm', widthPt: 459.2126 },
  { preamble: '', label: 'no page rule (defaults)', widthPt: 408.189 },
  { preamble: '#set page(paper: "us-letter", margin: 1in)', label: 'us-letter + 1in', widthPt: 421.2 },
  { preamble: '#set page(width: 400pt, height: 600pt, margin: 20pt)', label: 'explicit size', widthPt: 324 },
  { preamble: '#set page(margin: (x: 2cm, y: 3cm))', label: 'margin dict x/y', widthPt: 433.7008 },
  { preamble: '#set page(margin: (left: 1cm, right: 3cm, rest: 2cm))', label: 'margin dict l/r', widthPt: 433.7008 },
  { preamble: '#set page(paper: "a5", margin: 1cm)', label: 'a5 + 1cm', widthPt: 326.5512 },
];

describe('figureWidthPt', () => {
  for (const { preamble, label, widthPt } of TYPST_TRUTH) {
    it(`matches Typst for ${label}`, () => {
      expect(figureWidthPt(`${preamble}\n= Doc\n`)).toBeCloseTo(widthPt, 1);
    });
  }

  it('falls back to the A4 default for an unparseable preamble', () => {
    // Typst's own default is 2.5/21 margins on A4 → 408.19pt at 90%.
    expect(figureWidthPt('#set page(margin: auto)\n')).toBeCloseTo(408.189, 1);
  });
});

describe('parseLength', () => {
  it('converts every absolute unit to points', () => {
    expect(parseLength('2.2in')).toBeCloseTo(158.4, 6);
    expect(parseLength('1.5cm')).toBeCloseTo(42.5197, 3);
    expect(parseLength('25.4mm')).toBeCloseTo(72, 6);
    expect(parseLength('72pt')).toBeCloseTo(72, 6);
  });

  it('rejects relative and symbolic lengths', () => {
    // `auto`, `90%` and `1em` are not absolute, so there's nothing to frame.
    expect(parseLength('auto')).toBeNull();
    expect(parseLength('90%')).toBeNull();
    expect(parseLength('1em')).toBeNull();
    expect(parseLength('')).toBeNull();
  });
});

describe('formatLength', () => {
  it('round-trips through parseLength', () => {
    for (const pt of [158.4, 244.8, 432, 72]) {
      expect(parseLength(formatLength(pt, 'in'))).toBeCloseTo(pt, 1);
    }
  });

  it('does not write floating-point noise into the document', () => {
    expect(formatLength(158.4, 'in')).toBe('2.2in');
  });
});

describe('figureBox', () => {
  it('derives the aspect ratio from width and height', () => {
    const box = figureBox('#set page(margin: 1.5cm)\n', DEFAULT_FIGURE_HEIGHT_PT);
    expect(box.widthPt).toBeCloseTo(459.21, 1);
    expect(box.heightPt).toBeCloseTo(158.4, 1);
    expect(box.aspect).toBeCloseTo(2.899, 2);
  });

  it('gets squarer as the figure grows taller', () => {
    const src = '#set page(margin: 1.5cm)\n';
    expect(figureBox(src, 3.4 * 72).aspect).toBeCloseTo(1.876, 2);
    expect(figureBox(src, 6.0 * 72).aspect).toBeCloseTo(1.063, 2);
  });

  it('never divides by zero on a degenerate height', () => {
    expect(Number.isFinite(figureBox('', 0).aspect)).toBe(true);
  });
});
