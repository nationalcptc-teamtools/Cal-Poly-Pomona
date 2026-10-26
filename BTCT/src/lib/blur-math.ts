// ─────────────────────────────────────────────────────────────────────────
// Geometry and heuristics for blur (redaction) regions on Typst screenshots.
//
// A region lives in normalized coordinates relative to the *original* image
// (the same space as CropRect), clamped to the unit square. A redaction is
// anchored to the pixels it hides, so re-framing the figure never moves it.
//
// The blur itself is applied in lib/typst-assets.ts by downscaling the
// region and drawing it back with a gaussian filter; the numbers for that
// (radius, downscale factor) come from `blurParams` here so they are pure
// and testable, and so the editor preview and the compiled PDF use exactly
// the same strength.
//
// Pure and DOM-free, like crop-math.ts.
// ─────────────────────────────────────────────────────────────────────────

import type { BlurRegion, BlurStyle, CropRect } from '@/types';

/** Smallest edge a region may have, normalized. Rejects click-sized drags. */
export const MIN_REGION_SIZE = 0.005;

/**
 * Strength multiplier range. 1 is the original behavior; below it the effect
 * lightens (bounded so even the minimum still halves the detail), above it
 * the region is hit harder.
 */
export const MIN_STRENGTH = 0.25;
export const MAX_STRENGTH = 3;

/**
 * What a newly drawn region starts at when neither the account nor the admin
 * has set a default: pixelate at 0.4 (the UI reads it as 40%).
 *
 * This is the *new region* default only. It is deliberately not the fallback
 * inside `effectiveStrength`/`effectiveStyle` below, which exist to render
 * records written before those fields did, and must keep reproducing what
 * those records already look like. Changing them would silently re-render
 * every redaction anyone has ever saved.
 *
 * 0.4 is lighter than the old 1, but pixelate floors its block size at 8px
 * (see `pixelParams`) precisely so the lightest settings stay past the point
 * where mosaic-reversal tooling works, so it is a lighter look, not a weaker
 * redaction.
 */
export const DEFAULT_BLUR_STYLE: BlurStyle = 'pixelate';
export const DEFAULT_BLUR_STRENGTH = 0.4;

/** A region's style, with the pre-style default for older records. */
export function effectiveStyle(region: BlurRegion): BlurStyle {
  return region.style ?? 'gaussian';
}

/** A region's strength, defaulted and clamped to the supported range. */
export function effectiveStrength(region: BlurRegion): number {
  return Math.min(Math.max(region.strength ?? 1, MIN_STRENGTH), MAX_STRENGTH);
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(Math.max(n, lo), hi);
}

/**
 * Build a region from a drag's two corners (any order), clamped to the unit
 * square. Returns null when nothing meaningful survives the clamp (a bare
 * click, or a drag entirely off the image).
 */
export function regionFromDrag(
  x0: number,
  y0: number,
  x1: number,
  y1: number,
): BlurRegion | null {
  const left = clamp(Math.min(x0, x1), 0, 1);
  const right = clamp(Math.max(x0, x1), 0, 1);
  const top = clamp(Math.min(y0, y1), 0, 1);
  const bottom = clamp(Math.max(y0, y1), 0, 1);
  const w = right - left;
  const h = bottom - top;
  if (w < MIN_REGION_SIZE || h < MIN_REGION_SIZE) return null;
  return { x: left, y: top, w, h };
}

/**
 * Map a point in frame space (0..1 across the visible frame) into image
 * space through the crop. The crop may extend outside the unit square; the
 * result then can too; callers clamp via `regionFromDrag`.
 */
export function frameToImage(
  fx: number,
  fy: number,
  crop: CropRect,
): { x: number; y: number } {
  return { x: crop.x + fx * crop.w, y: crop.y + fy * crop.h };
}

/**
 * Where an image-space region sits in frame space, for overlay rendering.
 * All values are normalized frame units; a region cropped out of view simply
 * lands outside 0..1.
 */
export function regionToFrame(
  region: BlurRegion,
  crop: CropRect,
): { left: number; top: number; width: number; height: number } {
  const w = crop.w || 1;
  const h = crop.h || 1;
  return {
    left: (region.x - crop.x) / w,
    top: (region.y - crop.y) / h,
    width: region.w / w,
    height: region.h / h,
  };
}

/**
 * Blur strength for a region, in pixels of the natural image.
 *
 * `downscale` is applied first (the region is drawn at that scale and back
 * up), which is what actually destroys the information: a plain gaussian
 * of readable text can sometimes be deconvolved. The gaussian `radiusPx`
 * then smooths the block artifacts so the result reads as a blur, not a
 * mosaic. Both scale with the region's smaller edge: a password field gets
 * proportionally hit as hard as a full window.
 */
export function blurParams(
  region: BlurRegion,
  imageW: number,
  imageH: number,
): { radiusPx: number; downscale: number } {
  const s = effectiveStrength(region);
  const m = Math.max(1, Math.min(region.w * imageW, region.h * imageH));
  // Strength 1 reproduces the original numbers exactly; the strength then
  // multiplies the effect, with outer clamps so the lightest setting still
  // halves the detail and the heaviest can't allocate absurd radii.
  const baseRadius = clamp(m / 12, 4, 40);
  // Aim to leave ~10px of detail on the short edge, bounded so a huge
  // region still collapses (1/16) and a small one isn't a no-op (1/3).
  const baseDownscale = clamp(10 / m, 1 / 16, 1 / 3);
  return {
    radiusPx: clamp(baseRadius * s, 2, 80),
    downscale: clamp(baseDownscale / s, 1 / 32, 1 / 2),
  };
}

/**
 * Mosaic block size (in natural-image pixels) for a pixelated region.
 * Floored at 8px so blocks are never fine enough for mosaic-reversal
 * tooling, and capped at the region's short edge so there is always at
 * least one block.
 */
export function pixelParams(
  region: BlurRegion,
  imageW: number,
  imageH: number,
): { blockPx: number } {
  const s = effectiveStrength(region);
  const m = Math.max(1, Math.min(region.w * imageW, region.h * imageH));
  return { blockPx: Math.min(m, clamp((m / 8) * s, 8, 96)) };
}

/**
 * Topmost region containing an image-space point, or -1. Later regions win
 * where they overlap, matching their paint order in the editor.
 */
export function regionIndexAt(blurs: BlurRegion[], x: number, y: number): number {
  for (let i = blurs.length - 1; i >= 0; i--) {
    const b = blurs[i];
    if (!b) continue;
    if (x >= b.x && x <= b.x + b.w && y >= b.y && y <= b.y + b.h) return i;
  }
  return -1;
}

/**
 * Stable cache key for a set of regions, rounded to avoid float churn.
 * Empty (null/undefined/no regions) keys as ''.
 */
export function blursKey(blurs: BlurRegion[] | null | undefined): string {
  if (!blurs || blurs.length === 0) return '';
  const r = (n: number) => Math.round(n * 10000) / 10000;
  // Style/strength key by their *effective* values, so a record written
  // before those fields existed caches identically to an explicit default.
  return blurs
    .map((b) =>
      `${r(b.x)},${r(b.y)},${r(b.w)},${r(b.h)},` +
      `${effectiveStyle(b) === 'pixelate' ? 'p' : 'g'}${r(effectiveStrength(b))}`)
    .join('|');
}

/** True when the list actually blurs something. */
export function hasBlurs(blurs: BlurRegion[] | null | undefined): boolean {
  return !!blurs && blurs.length > 0;
}
