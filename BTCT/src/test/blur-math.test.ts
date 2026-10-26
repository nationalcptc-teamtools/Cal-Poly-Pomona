import { describe, it, expect } from 'vitest';
import {
  blurParams,
  blursKey,
  effectiveStrength,
  effectiveStyle,
  frameToImage,
  hasBlurs,
  MAX_STRENGTH,
  MIN_REGION_SIZE,
  MIN_STRENGTH,
  pixelParams,
  regionFromDrag,
  regionIndexAt,
  regionToFrame,
} from '@/lib/blur-math';
import type { BlurRegion, CropRect } from '@/types';

/** A 16:9 screenshot, the common case. */
const W = 1920;
const H = 1080;

describe('regionFromDrag', () => {
  it('builds a region from two corners in drag order', () => {
    const r = regionFromDrag(0.2, 0.3, 0.6, 0.5);
    expect(r).toEqual({ x: 0.2, y: 0.3, w: expect.closeTo(0.4, 9), h: expect.closeTo(0.2, 9) });
  });

  it('normalizes a drag toward the top-left (reversed corners)', () => {
    const r = regionFromDrag(0.6, 0.5, 0.2, 0.3);
    expect(r).toEqual({ x: 0.2, y: 0.3, w: expect.closeTo(0.4, 9), h: expect.closeTo(0.2, 9) });
  });

  it('clamps the region to the unit square', () => {
    const r = regionFromDrag(-0.5, 0.5, 0.5, 1.5);
    expect(r).toEqual({ x: 0, y: 0.5, w: 0.5, h: 0.5 });
  });

  it('returns null for a click-sized drag', () => {
    expect(regionFromDrag(0.5, 0.5, 0.5 + MIN_REGION_SIZE / 2, 0.9)).toBeNull();
    expect(regionFromDrag(0.5, 0.5, 0.5, 0.5)).toBeNull();
  });

  it('returns null for a drag entirely outside the image', () => {
    expect(regionFromDrag(1.2, 0.1, 1.6, 0.4)).toBeNull();
  });
});

describe('frame ↔ image mapping', () => {
  const crop: CropRect = { x: 0.25, y: 0.1, w: 0.5, h: 0.6 };

  it('maps a frame point into image space through the crop', () => {
    // The frame's centre shows the centre of the visible rect.
    expect(frameToImage(0.5, 0.5, crop)).toEqual({ x: 0.5, y: expect.closeTo(0.4, 9) });
    expect(frameToImage(0, 0, crop)).toEqual({ x: 0.25, y: expect.closeTo(0.1, 9) });
  });

  it('works when the crop extends outside the unit square', () => {
    const wide: CropRect = { x: -0.25, y: 0, w: 1.5, h: 1 };
    expect(frameToImage(0, 0.5, wide)).toEqual({ x: -0.25, y: 0.5 });
  });

  it('regionToFrame is the inverse of frameToImage for a region', () => {
    const a = frameToImage(0.2, 0.3, crop);
    const b = frameToImage(0.7, 0.8, crop);
    const region: BlurRegion = { x: a.x, y: a.y, w: b.x - a.x, h: b.y - a.y };
    const f = regionToFrame(region, crop);
    expect(f.left).toBeCloseTo(0.2, 9);
    expect(f.top).toBeCloseTo(0.3, 9);
    expect(f.width).toBeCloseTo(0.5, 9);
    expect(f.height).toBeCloseTo(0.5, 9);
  });
});

describe('blurParams', () => {
  it('gives a small region a floor radius so text is still destroyed', () => {
    // A password field: ~200×30 px on a full-HD shot.
    const r = blurParams({ x: 0.4, y: 0.4, w: 200 / W, h: 30 / H }, W, H);
    expect(r.radiusPx).toBeGreaterThanOrEqual(4);
    expect(r.downscale).toBeLessThan(1);
  });

  it('scales the radius up with the region size', () => {
    const small = blurParams({ x: 0, y: 0, w: 0.1, h: 0.1 }, W, H);
    const large = blurParams({ x: 0, y: 0, w: 0.9, h: 0.9 }, W, H);
    expect(large.radiusPx).toBeGreaterThan(small.radiusPx);
  });

  it('caps the radius for huge regions', () => {
    const r = blurParams({ x: 0, y: 0, w: 1, h: 1 }, 8000, 8000);
    expect(r.radiusPx).toBeLessThanOrEqual(40);
  });

  it('downscale always keeps at least one pixel and never enlarges', () => {
    const tiny = blurParams({ x: 0, y: 0, w: 0.001, h: 0.001 }, 100, 100);
    expect(tiny.downscale).toBeGreaterThan(0);
    expect(tiny.downscale).toBeLessThanOrEqual(1);
    const big = blurParams({ x: 0, y: 0, w: 1, h: 1 }, 4000, 4000);
    expect(big.downscale).toBeGreaterThan(0);
    expect(big.downscale).toBeLessThanOrEqual(1);
  });
});

describe('blursKey', () => {
  it('is empty for null, undefined, or no regions', () => {
    expect(blursKey(null)).toBe('');
    expect(blursKey(undefined)).toBe('');
    expect(blursKey([])).toBe('');
  });

  it('is stable across float noise below the rounding precision', () => {
    const a: BlurRegion[] = [{ x: 0.1, y: 0.2, w: 0.3, h: 0.4 }];
    const b: BlurRegion[] = [{ x: 0.100004, y: 0.2, w: 0.3, h: 0.4 }];
    expect(blursKey(a)).toBe(blursKey(b));
  });

  it('differs for genuinely different regions and counts', () => {
    const one: BlurRegion[] = [{ x: 0.1, y: 0.2, w: 0.3, h: 0.4 }];
    const moved: BlurRegion[] = [{ x: 0.15, y: 0.2, w: 0.3, h: 0.4 }];
    const two: BlurRegion[] = [...one, { x: 0.5, y: 0.5, w: 0.1, h: 0.1 }];
    expect(blursKey(one)).not.toBe(blursKey(moved));
    expect(blursKey(one)).not.toBe(blursKey(two));
  });
});

describe('effectiveStyle / effectiveStrength', () => {
  it('defaults to gaussian at strength 1', () => {
    const r: BlurRegion = { x: 0, y: 0, w: 0.5, h: 0.5 };
    expect(effectiveStyle(r)).toBe('gaussian');
    expect(effectiveStrength(r)).toBe(1);
  });

  it('clamps strength to the supported range', () => {
    expect(effectiveStrength({ x: 0, y: 0, w: 0.5, h: 0.5, strength: 99 })).toBe(MAX_STRENGTH);
    expect(effectiveStrength({ x: 0, y: 0, w: 0.5, h: 0.5, strength: 0.01 })).toBe(MIN_STRENGTH);
  });
});

describe('blurParams with strength', () => {
  const base: BlurRegion = { x: 0.2, y: 0.2, w: 0.3, h: 0.3 };

  it('an omitted strength matches an explicit strength of 1', () => {
    expect(blurParams(base, W, H)).toEqual(blurParams({ ...base, strength: 1 }, W, H));
  });

  it('a stronger setting blurs harder: bigger radius, smaller downscale', () => {
    const light = blurParams({ ...base, strength: 0.5 }, W, H);
    const normal = blurParams(base, W, H);
    const heavy = blurParams({ ...base, strength: 3 }, W, H);
    expect(heavy.radiusPx).toBeGreaterThan(normal.radiusPx);
    expect(light.radiusPx).toBeLessThan(normal.radiusPx);
    expect(heavy.downscale).toBeLessThan(normal.downscale);
    expect(light.downscale).toBeGreaterThan(normal.downscale);
  });

  it('keeps a floor even at the lightest setting', () => {
    const r = blurParams(
      { x: 0.4, y: 0.4, w: 200 / W, h: 30 / H, strength: MIN_STRENGTH }, W, H,
    );
    expect(r.radiusPx).toBeGreaterThanOrEqual(2);
    expect(r.downscale).toBeLessThanOrEqual(1 / 2);
  });
});

describe('pixelParams', () => {
  it('block size grows with strength', () => {
    const base: BlurRegion = { x: 0, y: 0, w: 0.4, h: 0.4, style: 'pixelate' };
    const light = pixelParams({ ...base, strength: 0.5 }, W, H);
    const heavy = pixelParams({ ...base, strength: 3 }, W, H);
    expect(heavy.blockPx).toBeGreaterThan(light.blockPx);
  });

  it('never produces blocks small enough to be reversible', () => {
    const tiny = pixelParams(
      { x: 0, y: 0, w: 0.2, h: 0.05, style: 'pixelate', strength: MIN_STRENGTH }, W, H,
    );
    expect(tiny.blockPx).toBeGreaterThanOrEqual(8);
  });

  it('never exceeds the region short edge, so there is always at least one block', () => {
    const sliver = pixelParams(
      { x: 0, y: 0, w: 0.5, h: 5 / H, style: 'pixelate', strength: 3 }, W, H,
    );
    expect(sliver.blockPx).toBeLessThanOrEqual(5);
  });
});

describe('blursKey with style and strength', () => {
  const rect = { x: 0.1, y: 0.2, w: 0.3, h: 0.4 };

  it('treats omitted fields as gaussian at strength 1', () => {
    expect(blursKey([rect])).toBe(blursKey([{ ...rect, style: 'gaussian', strength: 1 }]));
  });

  it('differs when only the style differs', () => {
    expect(blursKey([{ ...rect, style: 'pixelate' }])).not.toBe(blursKey([rect]));
  });

  it('differs when only the strength differs', () => {
    expect(blursKey([{ ...rect, strength: 2 }])).not.toBe(blursKey([rect]));
  });
});

describe('regionIndexAt', () => {
  const blurs: BlurRegion[] = [
    { x: 0.1, y: 0.1, w: 0.4, h: 0.4 },
    { x: 0.3, y: 0.3, w: 0.4, h: 0.4 },
  ];

  it('finds the region containing a point', () => {
    expect(regionIndexAt(blurs, 0.15, 0.15)).toBe(0);
    expect(regionIndexAt(blurs, 0.6, 0.6)).toBe(1);
  });

  it('prefers the topmost (most recently drawn) region where they overlap', () => {
    expect(regionIndexAt(blurs, 0.4, 0.4)).toBe(1);
  });

  it('returns -1 outside every region', () => {
    expect(regionIndexAt(blurs, 0.9, 0.1)).toBe(-1);
    expect(regionIndexAt([], 0.5, 0.5)).toBe(-1);
  });
});

describe('hasBlurs', () => {
  it('is false for null, undefined, and empty', () => {
    expect(hasBlurs(null)).toBe(false);
    expect(hasBlurs(undefined)).toBe(false);
    expect(hasBlurs([])).toBe(false);
  });

  it('is true for at least one region', () => {
    expect(hasBlurs([{ x: 0, y: 0, w: 0.5, h: 0.5 }])).toBe(true);
  });
});
