// Property tests for the pure geometry helpers: crop, blur and pane-width math
// must stay inside their documented bounds for any finite input.
import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  cropToPixels,
  fitCropToBox,
  MAX_VISIBLE_FRACTION,
  MIN_VISIBLE_FRACTION,
  normalizeCrop,
  outputSize,
  zoomCrop,
  constrainToAspect,
  cropAspect,
} from '@/lib/crop-math';
import {
  blurParams,
  effectiveStrength,
  MAX_STRENGTH,
  MIN_STRENGTH,
  pixelParams,
  regionFromDrag,
  MIN_REGION_SIZE,
} from '@/lib/blur-math';
import { clampPaneWidth, PANE_MIN } from '@/lib/pane-resize';
import { clampImageWidth, MIN_IMAGE_WIDTH } from '@/lib/image-resize';

const RUNS = { numRuns: 200 };
const num = (min: number, max: number) => fc.double({ min, max, noNaN: true });
const crop = fc.record({ x: num(-20, 20), y: num(-20, 20), w: num(0.001, 12), h: num(0.001, 12) });
const dim = fc.integer({ min: 1, max: 20000 });
const region = fc.record({ x: num(0, 1), y: num(0, 1), w: num(0.005, 1), h: num(0.005, 1), strength: fc.option(num(-5, 50), { nil: undefined }) });

describe('crop-math', () => {
  it('normalizeCrop keeps every field inside the sanity bounds', () => {
    fc.assert(
      fc.property(fc.record({ x: num(-1e6, 1e6), y: num(-1e6, 1e6), w: num(-1e6, 1e6), h: num(-1e6, 1e6) }), (c) => {
        const n = normalizeCrop(c);
        for (const v of [n.w, n.h]) {
          expect(v).toBeGreaterThanOrEqual(MIN_VISIBLE_FRACTION);
          expect(v).toBeLessThanOrEqual(MAX_VISIBLE_FRACTION);
        }
        for (const v of [n.x, n.y]) expect(Math.abs(v)).toBeLessThanOrEqual(MAX_VISIBLE_FRACTION);
      }),
      RUNS,
    );
  });

  it('zoomCrop never leaves the visible-fraction range, keeps aspect and the anchor', () => {
    fc.assert(
      fc.property(
        fc.record({ x: num(-2, 2), y: num(-2, 2), w: num(MIN_VISIBLE_FRACTION, MAX_VISIBLE_FRACTION), h: num(MIN_VISIBLE_FRACTION, MAX_VISIBLE_FRACTION) }),
        num(0.001, 1000),
        num(0, 1),
        num(0, 1),
        (c, factor, ax, ay) => {
          const z = zoomCrop(c, factor, ax, ay);
          const eps = 1e-9;
          expect(z.w).toBeGreaterThan(0);
          expect(z.h).toBeGreaterThan(0);
          // Either both sides respect the range, or the input already broke it and was left alone.
          expect(z.w).toBeLessThanOrEqual(Math.max(MAX_VISIBLE_FRACTION, c.w) + eps);
          expect(z.h).toBeLessThanOrEqual(Math.max(MAX_VISIBLE_FRACTION, c.h) + eps);
          expect(z.w / z.h).toBeCloseTo(c.w / c.h, 6);
          expect(z.x + z.w * ax).toBeCloseTo(c.x + c.w * ax, 6);
          expect(z.y + z.h * ay).toBeCloseTo(c.y + c.h * ay, 6);
        },
      ),
      RUNS,
    );
  });

  it('cropToPixels and outputSize never return a zero or negative size', () => {
    fc.assert(
      fc.property(crop, dim, dim, fc.integer({ min: 16, max: 8192 }), (c, w, h, max) => {
        const p = cropToPixels(c, w, h);
        expect(p.sw).toBeGreaterThanOrEqual(1);
        expect(p.sh).toBeGreaterThanOrEqual(1);
        const o = outputSize(c, w, h, max);
        expect(o.width).toBeGreaterThanOrEqual(1);
        expect(o.height).toBeGreaterThanOrEqual(1);
        // Rounding after the scale can exceed the cap by at most one pixel.
        expect(Math.max(o.width, o.height)).toBeLessThanOrEqual(max + 1);
      }),
      RUNS,
    );
  });

  it('fitCropToBox matches the box aspect and cover/contain bracket the image', () => {
    fc.assert(
      fc.property(dim, dim, num(0.05, 20), fc.constantFrom('cover', 'contain'), (w, h, box, mode) => {
        const c = fitCropToBox(w, h, box, mode);
        expect(cropAspect(c, w, h)).toBeCloseTo(box, 6);
        if (mode === 'cover') {
          expect(Math.max(c.w, c.h)).toBeCloseTo(1, 9);
          expect(Math.min(c.w, c.h)).toBeLessThanOrEqual(1 + 1e-9);
        } else {
          expect(Math.min(c.w, c.h)).toBeGreaterThanOrEqual(1 - 1e-9);
        }
      }),
      RUNS,
    );
  });

  it('constrainToAspect lands on the requested pixel aspect', () => {
    fc.assert(
      fc.property(crop, dim, dim, num(0.05, 20), (c, w, h, box) => {
        expect(cropAspect(constrainToAspect(c, w, h, box), w, h)).toBeCloseTo(box, 6);
      }),
      RUNS,
    );
  });
});

describe('blur-math', () => {
  it('regionFromDrag is null or a region inside the unit square, whatever the corners', () => {
    fc.assert(
      fc.property(num(-5, 5), num(-5, 5), num(-5, 5), num(-5, 5), (x0, y0, x1, y1) => {
        const r = regionFromDrag(x0, y0, x1, y1);
        if (!r) return;
        expect(r.x).toBeGreaterThanOrEqual(0);
        expect(r.y).toBeGreaterThanOrEqual(0);
        expect(r.x + r.w).toBeLessThanOrEqual(1 + 1e-12);
        expect(r.y + r.h).toBeLessThanOrEqual(1 + 1e-12);
        expect(r.w).toBeGreaterThanOrEqual(MIN_REGION_SIZE);
        expect(r.h).toBeGreaterThanOrEqual(MIN_REGION_SIZE);
      }),
      RUNS,
    );
  });

  it('regionFromDrag does not depend on corner order', () => {
    fc.assert(
      fc.property(num(-2, 2), num(-2, 2), num(-2, 2), num(-2, 2), (x0, y0, x1, y1) => {
        expect(regionFromDrag(x0, y0, x1, y1)).toEqual(regionFromDrag(x1, y1, x0, y0));
      }),
      RUNS,
    );
  });

  it('effectiveStrength, blurParams and pixelParams stay in their clamps', () => {
    fc.assert(
      fc.property(region, dim, dim, (r, w, h) => {
        const s = effectiveStrength(r);
        expect(s).toBeGreaterThanOrEqual(MIN_STRENGTH);
        expect(s).toBeLessThanOrEqual(MAX_STRENGTH);
        const b = blurParams(r, w, h);
        expect(b.radiusPx).toBeGreaterThanOrEqual(2);
        expect(b.radiusPx).toBeLessThanOrEqual(80);
        expect(b.downscale).toBeGreaterThanOrEqual(1 / 32 - 1e-12);
        expect(b.downscale).toBeLessThanOrEqual(1 / 2);
        const p = pixelParams(r, w, h);
        const shortEdge = Math.max(1, Math.min(r.w * w, r.h * h));
        expect(p.blockPx).toBeGreaterThan(0);
        expect(p.blockPx).toBeLessThanOrEqual(Math.min(shortEdge, 96) + 1e-9);
      }),
      RUNS,
    );
  });
});

describe('width clamps', () => {
  it('clampPaneWidth never returns less than the pane minimum', () => {
    fc.assert(
      fc.property(fc.constantFrom('editor', 'assets'), num(-500, 5000), num(0, 4000), num(0, 1500), (which, proposed, container, other) => {
        const out = clampPaneWidth(which, proposed, container, other);
        expect(out).toBeGreaterThanOrEqual(PANE_MIN[which]);
        // Unless the pane minimum wins, the preview keeps its minimum too.
        if (out > PANE_MIN[which]) expect(out + other + PANE_MIN.preview).toBeLessThanOrEqual(container + 1e-9);
      }),
      RUNS,
    );
  });

  it('clampImageWidth is a whole number between the minimum and the column', () => {
    fc.assert(
      fc.property(num(0, 4000), num(-4000, 4000), num(0, 4000), (start, dx, max) => {
        const w = clampImageWidth(start, dx, max);
        expect(Number.isInteger(w)).toBe(true);
        expect(w).toBeGreaterThanOrEqual(MIN_IMAGE_WIDTH);
        expect(w).toBeLessThanOrEqual(Math.round(Math.max(MIN_IMAGE_WIDTH, max)));
      }),
      RUNS,
    );
  });
});
