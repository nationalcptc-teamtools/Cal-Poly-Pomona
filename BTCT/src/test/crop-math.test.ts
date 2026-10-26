import { describe, it, expect } from 'vitest';
import {
  constrainToAspect,
  cropAspect,
  cropToPixels,
  fitCropToBox,
  FULL_FRAME,
  isFullFrame,
  MAX_VISIBLE_FRACTION,
  MIN_VISIBLE_FRACTION,
  outputSize,
  panCrop,
  zoomCrop,
  zoomPercent,
  cropFromSelection,
  dragSelection,
  FULL_SELECTION,
  isFullSelection,
  MIN_SELECTION,
} from '@/lib/crop-math';

/** The real figure box: 459.21pt wide × 2.2in tall. */
const BOX = 459.21 / 158.4;
/** A 16:9 screenshot: narrower than the box. */
const W = 1920;
const H = 1080;

describe('fitCropToBox: cover', () => {
  const crop = fitCropToBox(W, H, BOX, 'cover');

  it('produces exactly the box aspect ratio', () => {
    expect(cropAspect(crop, W, H)).toBeCloseTo(BOX, 9);
  });

  it('uses the full width and crops the height for a narrower image', () => {
    expect(crop.w).toBeCloseTo(1, 9);
    expect(crop.h).toBeLessThan(1);
  });

  it('centres what it keeps', () => {
    expect(crop.y).toBeCloseTo((1 - crop.h) / 2, 9);
  });

  it('takes the full height when the box is narrower than the image', () => {
    const square = fitCropToBox(W, H, 1, 'cover');
    expect(square.h).toBeCloseTo(1, 9);
    expect(cropAspect(square, W, H)).toBeCloseTo(1, 9);
  });

  it('handles a portrait source', () => {
    const tall = fitCropToBox(1080, 1920, BOX, 'cover');
    expect(tall.w).toBeCloseTo(1, 9);
    expect(cropAspect(tall, 1080, 1920)).toBeCloseTo(BOX, 9);
  });
});

describe('fitCropToBox: contain', () => {
  const crop = fitCropToBox(W, H, BOX, 'contain');

  it('produces exactly the box aspect ratio', () => {
    expect(cropAspect(crop, W, H)).toBeCloseTo(BOX, 9);
  });

  it('shows the whole image, overflowing the frame sideways', () => {
    // Overflow past the image bounds is the point: it becomes grey padding.
    expect(crop.h).toBeCloseTo(1, 9);
    expect(crop.w).toBeGreaterThan(1);
    expect(crop.x).toBeLessThan(0);
  });
});

describe('panCrop', () => {
  it('translates without clamping to the image', () => {
    // Bleeding a screenshot off one edge is a legitimate composition.
    const moved = panCrop({ x: 0, y: 0, w: 1, h: 0.6 }, -0.5, -0.5);
    expect(moved.x).toBeCloseTo(-0.5, 9);
    expect(moved.y).toBeCloseTo(-0.5, 9);
  });

  it('leaves the size alone', () => {
    const moved = panCrop({ x: 0, y: 0, w: 0.7, h: 0.3 }, 0.2, 0.1);
    expect(moved.w).toBeCloseTo(0.7, 9);
    expect(moved.h).toBeCloseTo(0.3, 9);
  });
});

describe('zoomCrop', () => {
  const base = fitCropToBox(W, H, BOX, 'cover');

  it('scales the visible region by the factor', () => {
    expect(zoomCrop(base, 0.5).w).toBeCloseTo(base.w * 0.5, 9);
  });

  it('preserves the box aspect ratio', () => {
    expect(cropAspect(zoomCrop(base, 0.5), W, H)).toBeCloseTo(BOX, 9);
  });

  it('keeps the centre fixed when anchored at the centre', () => {
    const z = zoomCrop(base, 0.5);
    expect(z.x + z.w / 2).toBeCloseTo(base.x + base.w / 2, 9);
    expect(z.y + z.h / 2).toBeCloseTo(base.y + base.h / 2, 9);
  });

  it('keeps an off-centre anchor fixed', () => {
    const z = zoomCrop(base, 0.5, 0, 0);
    expect(z.x).toBeCloseTo(base.x, 9);
    expect(z.y).toBeCloseTo(base.y, 9);
  });

  it('clamps extreme zoom but never distorts the aspect', () => {
    // Clamping each axis independently would silently skew the ratio, which
    // is the one thing this model must never do.
    const out = zoomCrop(base, 1000);
    const inn = zoomCrop(base, 0.00001);
    expect(out.w).toBeLessThanOrEqual(MAX_VISIBLE_FRACTION + 1e-9);
    expect(inn.w).toBeGreaterThanOrEqual(MIN_VISIBLE_FRACTION - 1e-9);
    expect(cropAspect(out, W, H)).toBeCloseTo(BOX, 9);
    expect(cropAspect(inn, W, H)).toBeCloseTo(BOX, 9);
  });
});

describe('constrainToAspect', () => {
  it('reshapes an arbitrary rect to the box ratio', () => {
    const c = constrainToAspect({ x: 0.1, y: 0.1, w: 0.5, h: 0.5 }, W, H, BOX);
    expect(cropAspect(c, W, H)).toBeCloseTo(BOX, 9);
  });

  it('keeps the centre, so re-framing does not jump', () => {
    const c = constrainToAspect({ x: 0.1, y: 0.1, w: 0.5, h: 0.5 }, W, H, BOX);
    expect(c.x + c.w / 2).toBeCloseTo(0.35, 9);
    expect(c.y + c.h / 2).toBeCloseTo(0.35, 9);
  });

  it('is idempotent', () => {
    const once = constrainToAspect({ x: 0.1, y: 0.1, w: 0.5, h: 0.5 }, W, H, BOX);
    const twice = constrainToAspect(once, W, H, BOX);
    expect(twice.w).toBeCloseTo(once.w, 9);
    expect(twice.h).toBeCloseTo(once.h, 9);
  });
});

describe('cropToPixels', () => {
  it('maps a normal rect onto source pixels', () => {
    expect(cropToPixels({ x: 0.25, y: 0.25, w: 0.5, h: 0.5 }, 1920, 1080))
      .toEqual({ sx: 480, sy: 270, sw: 960, sh: 540 });
  });

  it('allows a source rect outside the image', () => {
    // The canvas clips the source and scales the destination in proportion,
    // leaving the pre-filled grey showing.
    const px = cropToPixels({ x: -0.25, y: 0, w: 1.5, h: 1 }, 100, 100);
    expect(px.sx).toBe(-25);
    expect(px.sw).toBe(150);
  });

  it('never yields a zero-sized region', () => {
    const px = cropToPixels({ x: 0, y: 0, w: 0.0001, h: 0.0001 }, 100, 100);
    expect(px.sw).toBe(1);
    expect(px.sh).toBe(1);
  });
});

describe('outputSize', () => {
  it('caps an enormous canvas', () => {
    const s = outputSize({ x: 0, y: 0, w: 8, h: 8 }, 4000, 4000, 4096);
    expect(Math.max(s.width, s.height)).toBe(4096);
  });

  it('keeps the aspect ratio when capping', () => {
    const s = outputSize({ x: 0, y: 0, w: 4, h: 2 }, 4000, 4000, 4096);
    expect(s.width / s.height).toBeCloseTo(2, 2);
  });
});

describe('isFullFrame / zoomPercent', () => {
  it('treats null and the identity rect as full-frame', () => {
    expect(isFullFrame(null)).toBe(true);
    expect(isFullFrame(FULL_FRAME)).toBe(true);
  });

  it('reports a framed crop as not full-frame', () => {
    expect(isFullFrame(fitCropToBox(W, H, BOX, 'cover'))).toBe(false);
  });

  it('reports zoom as the inverse of the visible width', () => {
    expect(zoomPercent({ x: 0, y: 0, w: 1, h: 1 })).toBe(100);
    expect(zoomPercent({ x: 0, y: 0, w: 0.5, h: 0.5 })).toBe(200);
  });
});

describe('crop handles', () => {
  it('moves only the edges a handle owns, inside the frame', () => {
    expect(dragSelection(FULL_SELECTION, 'e', 0.6, 0.9)).toEqual({ l: 0, t: 0, r: 0.6, b: 1 });
    expect(dragSelection(FULL_SELECTION, 'nw', -0.5, 0.25)).toEqual({ l: 0, t: 0.25, r: 1, b: 1 });
  });

  it('never lets a side cross its opposite', () => {
    const sel = dragSelection({ l: 0.5, t: 0, r: 1, b: 1 }, 'e', 0.2, 0);
    expect(sel.r).toBeCloseTo(0.5 + MIN_SELECTION);
  });

  it('turns a selection of the frame into a crop of the image', () => {
    const crop = cropFromSelection({ x: 0.1, y: 0.2, w: 0.5, h: 0.4 }, { l: 0.2, t: 0.5, r: 0.6, b: 1 });
    expect(crop.x).toBeCloseTo(0.2);
    expect(crop.y).toBeCloseTo(0.4);
    expect(crop.w).toBeCloseTo(0.2);
    expect(crop.h).toBeCloseTo(0.2);
    expect(isFullSelection(FULL_SELECTION)).toBe(true);
    expect(isFullSelection({ l: 0, t: 0, r: 0.9, b: 1 })).toBe(false);
  });
});
