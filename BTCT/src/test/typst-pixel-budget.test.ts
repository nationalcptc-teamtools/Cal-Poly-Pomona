import { describe, it, expect } from 'vitest';
import {
  DEFAULT_MAX_TOTAL_MP,
  MAX_TOTAL_MP_RANGE,
  parseMaxTotalMegapixels,
  createPixelBudget,
} from '../../server/typst/pixel-budget.mjs';

// Typst holds every decoded bitmap while it writes the PDF's image streams,
// about 3 bytes per pixel, so the cost of a report is the sum of its
// screenshots whether or not anything redacts them. Measured with
// `typst compile -j 1`: 8 distinct 3500x2820 PNGs took the child to 242 MB
// and 32 of them to 922 MB, on 1.2 MB of disk.

const MP = 1_000_000;

describe('parseMaxTotalMegapixels', () => {
  it('defaults to 120 when the variable is not set or is not a number', () => {
    for (const raw of [undefined, '', '   ', 'lots', 'NaN', '12x', null]) {
      expect(parseMaxTotalMegapixels(raw as string | undefined), JSON.stringify(raw)).toBe(DEFAULT_MAX_TOTAL_MP);
    }
    expect(DEFAULT_MAX_TOTAL_MP).toBe(120);
  });

  it('takes a value inside the accepted range', () => {
    expect(parseMaxTotalMegapixels('10')).toBe(10);
    expect(parseMaxTotalMegapixels('400')).toBe(400);
    expect(parseMaxTotalMegapixels('2000')).toBe(2000);
    expect(parseMaxTotalMegapixels(' 250 ')).toBe(250);
    expect(MAX_TOTAL_MP_RANGE).toEqual([10, 2000]);
  });

  it('falls back rather than trusting a value outside the range', () => {
    for (const raw of ['0', '9', '-100', '2001', '1e9', 'Infinity']) {
      expect(parseMaxTotalMegapixels(raw), raw).toBe(DEFAULT_MAX_TOTAL_MP);
    }
  });
});

describe('createPixelBudget', () => {
  it('counts every image it is given, redacted or not', () => {
    const budget = createPixelBudget(DEFAULT_MAX_TOTAL_MP);
    expect(budget.add({ width: 1920, height: 1080 })).toBeNull();
    expect(budget.add({ width: 3840, height: 2160 })).toBeNull();
    expect(budget.megapixels()).toBeCloseTo((1920 * 1080 + 3840 * 2160) / MP, 5);
  });

  it('counts a baked image once, the same as any other', () => {
    // stage.mjs adds each staged image exactly once, before the bake, so a
    // redacted screenshot must not be paid for twice.
    const baked = createPixelBudget(DEFAULT_MAX_TOTAL_MP);
    baked.add({ width: 3000, height: 3000 });
    const plain = createPixelBudget(DEFAULT_MAX_TOTAL_MP);
    plain.add({ width: 3000, height: 3000 });
    expect(baked.megapixels()).toBe(plain.megapixels());
    expect(baked.megapixels()).toBe(9);
  });

  it('charges nothing for an image with no dimensions, which is how SVG passes', () => {
    const budget = createPixelBudget(DEFAULT_MAX_TOTAL_MP);
    expect(budget.add(null)).toBeNull();
    expect(budget.add(undefined)).toBeNull();
    expect(budget.megapixels()).toBe(0);
  });

  it('refuses the megapixel that crosses the line, not the one before it', () => {
    const budget = createPixelBudget(DEFAULT_MAX_TOTAL_MP);
    for (let i = 0; i < 12; i += 1) {
      expect(budget.add({ width: 10 * MP, height: 1 }), `image ${i}`).toBeNull(); // 10 MP each
    }
    expect(budget.megapixels()).toBe(120);
    const refusal = budget.add({ width: 1 * MP, height: 1 });
    expect(refusal).toBe('This report places about 121 MP of screenshots and the server exports up to 120 MP at once. Export the PDF from the browser instead, or raise TYPST_EXPORT_MAX_TOTAL_MP on a server with more memory.');
  });

  it('keeps refusing once it is over, and reports the running total', () => {
    const budget = createPixelBudget(10);
    expect(budget.add({ width: 4000, height: 3000 })).toContain('about 12 MP');
    expect(budget.add({ width: 1000, height: 1000 })).toContain('about 13 MP');
  });

  it('honours a raised or lowered limit', () => {
    const big = createPixelBudget(2000);
    for (let i = 0; i < 40; i += 1) expect(big.add({ width: 3500, height: 2820 })).toBeNull();
    expect(big.megapixels()).toBeCloseTo(40 * 9.87, 1);

    const small = createPixelBudget(10);
    expect(small.add({ width: 3500, height: 2820 })).toBeNull(); // 9.87 MP fits
    expect(small.add({ width: 100, height: 100 })).toBeNull(); // 9.88 MP still fits
    expect(small.add({ width: 1000, height: 1000 })).toContain('up to 10 MP at once');
  });

  it('ignores a nonsense size rather than counting it backwards', () => {
    const budget = createPixelBudget(DEFAULT_MAX_TOTAL_MP);
    expect(budget.add({ width: -5, height: 100 })).toBeNull();
    expect(budget.add({ width: Number.NaN, height: 10 })).toBeNull();
    expect(budget.megapixels()).toBe(0);
  });
});
