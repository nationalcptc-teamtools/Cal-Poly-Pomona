// ─────────────────────────────────────────────────────────────────────────
// Geometry for the Typst screenshot viewport editor.
//
// The editing model is a **fixed viewport**, not a free selection: the figure
// box as it will render in the PDF is the frame, and the image is panned and
// scaled behind it. Whatever lands inside the frame is what the figure shows;
// anything outside is clipped at the border.
//
// The stored `CropRect` is still "which part of the image is visible", in
// normalized image coordinates, but with two rules that the old free-crop
// model didn't have:
//
//   • its aspect ratio always matches the figure box, so the rendered bytes
//     drop into the box with no letterboxing and no distortion, and
//   • it MAY extend outside 0..1. A rect wider than the image means the image
//     has been scaled down inside the frame; the overhang renders as the
//     placeholder grey, baked into the output.
//
// That second rule is why nothing here clamps to the unit square: doing so
// would make it impossible to show a whole screenshot inside a box of a
// different shape.
//
// Pure and DOM-free so the rules are directly testable.
// ─────────────────────────────────────────────────────────────────────────

import type { CropRect } from '@/types';

/** The whole image: the identity crop. */
export const FULL_FRAME: CropRect = { x: 0, y: 0, w: 1, h: 1 };

/**
 * Bounds on how far the image may be scaled, expressed as the visible
 * fraction of it. A tiny `w`/`h` means zoomed deep in; a huge one means the
 * image is a speck in a sea of grey.
 */
export const MIN_VISIBLE_FRACTION = 0.02; // 50× zoom in
export const MAX_VISIBLE_FRACTION = 8; // image at 1/8 of the frame

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(Math.max(n, lo), hi);
}

/** Aspect ratio (w/h) of a crop rect in *pixel* terms for a given image. */
export function cropAspect(crop: CropRect, imageW: number, imageH: number): number {
  const h = crop.h * imageH;
  if (h <= 0) return 1;
  return (crop.w * imageW) / h;
}

/**
 * Constrain a rect to `boxAspect` (width/height of the figure box), keeping
 * its centre fixed.
 *
 * The rect is expressed in normalized image coordinates but the aspect
 * constraint is about *pixels*, so the image's own dimensions have to come
 * into it: a rect of w=h=0.5 on a 1600×900 image is not square.
 */
export function constrainToAspect(
  crop: CropRect,
  imageW: number,
  imageH: number,
  boxAspect: number,
): CropRect {
  if (imageW <= 0 || imageH <= 0 || boxAspect <= 0) return crop;
  const cx = crop.x + crop.w / 2;
  const cy = crop.y + crop.h / 2;

  // Preserve the visible area so a constrain doesn't jump the zoom level.
  const pxW = crop.w * imageW;
  const pxH = crop.h * imageH;
  const area = Math.max(pxW * pxH, 1);
  const newPxH = Math.sqrt(area / boxAspect);
  const newPxW = newPxH * boxAspect;

  const w = newPxW / imageW;
  const h = newPxH / imageH;
  return { x: cx - w / 2, y: cy - h / 2, w, h };
}

/**
 * Initial placement of an image in the box.
 *
 * `cover` scales until the frame is completely filled, cropping the overflow:
 * the default, because a full-bleed figure is what you want most of the time.
 * `contain` scales until the whole image is inside the frame, leaving grey
 * gaps on two sides.
 */
export function fitCropToBox(
  imageW: number,
  imageH: number,
  boxAspect: number,
  mode: 'cover' | 'contain' = 'cover',
): CropRect {
  if (imageW <= 0 || imageH <= 0 || boxAspect <= 0) return FULL_FRAME;
  const imageAspect = imageW / imageH;

  let w: number;
  let h: number;
  // Whether the image is wider or narrower than the box decides which axis is
  // the limiting one, and `cover`/`contain` swap that choice.
  const imageIsWider = imageAspect > boxAspect;
  const takeFullWidth = mode === 'cover' ? !imageIsWider : imageIsWider;

  if (takeFullWidth) {
    w = 1;
    h = (imageW / boxAspect) / imageH;
  } else {
    h = 1;
    w = (imageH * boxAspect) / imageW;
  }

  return { x: (1 - w) / 2, y: (1 - h) / 2, w, h };
}

/**
 * Translate the visible rect by a delta in normalized image units.
 *
 * Deliberately unclamped: panning the image partly out of the frame is a
 * legitimate composition (a screenshot bled off one edge), and the grey fill
 * handles whatever isn't covered.
 */
export function panCrop(crop: CropRect, dx: number, dy: number): CropRect {
  return { ...crop, x: crop.x + dx, y: crop.y + dy };
}

/**
 * Scale the visible rect about a normalized anchor point (0.5,0.5 = centre of
 * the frame), preserving aspect.
 *
 * `factor` > 1 shows *more* of the image (zoom out); < 1 shows less (zoom in).
 * Anchoring lets a wheel-zoom keep the point under the cursor stationary.
 */
export function zoomCrop(
  crop: CropRect,
  factor: number,
  anchorX = 0.5,
  anchorY = 0.5,
): CropRect {
  const limited = clamp(factor, 0.01, 100);
  // One factor for both axes (the aspect ratio must not change), limited so
  // that NEITHER side leaves [MIN, MAX]: clamping the width alone let the
  // height of a tall frame grow without bound.
  const base = crop.w > 0 && crop.h > 0 ? crop : { ...crop, w: Math.max(crop.w, 1e-6), h: Math.max(crop.h, 1e-6) };
  const maxFactor = Math.min(MAX_VISIBLE_FRACTION / base.w, MAX_VISIBLE_FRACTION / base.h);
  const minFactor = Math.max(MIN_VISIBLE_FRACTION / base.w, MIN_VISIBLE_FRACTION / base.h);
  const applied = minFactor > maxFactor ? 1 : clamp(limited, minFactor, maxFactor);
  const w = base.w * applied;
  const hKept = base.h * applied;

  // The anchor is a point inside the current rect that must not move.
  const ax = crop.x + crop.w * anchorX;
  const ay = crop.y + crop.h * anchorY;
  return {
    x: ax - w * anchorX,
    y: ay - hKept * anchorY,
    w,
    h: hKept,
  };
}

/** The zoom level implied by a crop, as a human-facing percentage. */
export function zoomPercent(crop: CropRect): number {
  if (crop.w <= 0) return 100;
  return Math.round((1 / crop.w) * 100);
}

/**
 * True when the crop shows the whole image and nothing else: meaning the
 * image happened to match the box exactly, so there's nothing to store.
 */
export function isFullFrame(crop: CropRect | null | undefined): boolean {
  if (!crop) return true;
  const EPS = 0.001;
  return (
    Math.abs(crop.x) < EPS &&
    Math.abs(crop.y) < EPS &&
    Math.abs(crop.w - 1) < EPS &&
    Math.abs(crop.h - 1) < EPS
  );
}

/**
 * Sanity bounds for a stored rect.
 *
 * Unlike the old free-crop clamp this does NOT force the rect inside the
 * image: it only stops a degenerate or absurd rect (zero width, a rect
 * thousands of times the image) from reaching the renderer.
 */
export function normalizeCrop(crop: CropRect): CropRect {
  const w = clamp(crop.w, MIN_VISIBLE_FRACTION, MAX_VISIBLE_FRACTION);
  const h = clamp(crop.h, MIN_VISIBLE_FRACTION, MAX_VISIBLE_FRACTION);
  const x = clamp(crop.x, -MAX_VISIBLE_FRACTION, MAX_VISIBLE_FRACTION);
  const y = clamp(crop.y, -MAX_VISIBLE_FRACTION, MAX_VISIBLE_FRACTION);
  return { x, y, w, h };
}

/**
 * Convert a normalized rect to source pixels for `drawImage`.
 *
 * The result may be negative or extend past the image; the canvas spec clips
 * the source rectangle and scales the destination in the same proportion, so
 * the overhang simply leaves the pre-filled background showing.
 */
export function cropToPixels(
  crop: CropRect,
  naturalWidth: number,
  naturalHeight: number,
): { sx: number; sy: number; sw: number; sh: number } {
  return {
    sx: Math.round(crop.x * naturalWidth),
    sy: Math.round(crop.y * naturalHeight),
    sw: Math.max(1, Math.round(crop.w * naturalWidth)),
    sh: Math.max(1, Math.round(crop.h * naturalHeight)),
  };
}

/**
 * Output pixel size for a crop, capped so a deep zoom-out on a huge source
 * can't allocate an enormous canvas.
 */
export function outputSize(
  crop: CropRect,
  naturalWidth: number,
  naturalHeight: number,
  maxDimension = 4096,
): { width: number; height: number } {
  let w = Math.max(1, Math.round(crop.w * naturalWidth));
  let h = Math.max(1, Math.round(crop.h * naturalHeight));
  const largest = Math.max(w, h);
  if (largest > maxDimension) {
    const scale = maxDimension / largest;
    w = Math.max(1, Math.round(w * scale));
    h = Math.max(1, Math.round(h * scale));
  }
  return { width: w, height: h };
}

// ── crop handles ─────────────────────────────────────────────────────────
//
// The frame's edge handles crop instead of pan: dragging one moves that side
// of the frame in over the image, and on release the part still inside
// becomes the new crop, at its own shape. The frame then takes that shape,
// so a crop changes the figure's proportions rather than being forced back
// into the old box.

/** A rectangle inside the frame, as fractions of it (0..1 on each side). */
export interface FrameSelection { l: number; t: number; r: number; b: number }

/** Which edge (or corner) of the frame a handle drags. */
export type CropHandle = 'n' | 's' | 'e' | 'w' | 'ne' | 'nw' | 'se' | 'sw';

export const CROP_HANDLES: readonly CropHandle[] = ['nw', 'n', 'ne', 'e', 'se', 's', 'sw', 'w'];

/** The whole frame: nothing cropped yet. */
export const FULL_SELECTION: FrameSelection = { l: 0, t: 0, r: 1, b: 1 };

/** The smallest selection a handle may leave, as a fraction of the frame. */
export const MIN_SELECTION = 0.04;

/**
 * Move the edges a handle owns to the frame point (fx, fy), keeping each side
 * inside the frame and at least `MIN_SELECTION` from its opposite.
 */
export function dragSelection(sel: FrameSelection, handle: CropHandle, fx: number, fy: number): FrameSelection {
  const next = { ...sel };
  if (handle.includes('w')) next.l = clamp(fx, 0, sel.r - MIN_SELECTION);
  if (handle.includes('e')) next.r = clamp(fx, sel.l + MIN_SELECTION, 1);
  if (handle.includes('n')) next.t = clamp(fy, 0, sel.b - MIN_SELECTION);
  if (handle.includes('s')) next.b = clamp(fy, sel.t + MIN_SELECTION, 1);
  return next;
}

/** True when a selection still covers (almost) the whole frame. */
export function isFullSelection(sel: FrameSelection): boolean {
  const EPS = 0.002;
  return sel.l < EPS && sel.t < EPS && sel.r > 1 - EPS && sel.b > 1 - EPS;
}

/** The crop that shows only the selected part of the current frame. */
export function cropFromSelection(crop: CropRect, sel: FrameSelection): CropRect {
  return normalizeCrop({
    x: crop.x + sel.l * crop.w,
    y: crop.y + sel.t * crop.h,
    w: (sel.r - sel.l) * crop.w,
    h: (sel.b - sel.t) * crop.h,
  });
}
