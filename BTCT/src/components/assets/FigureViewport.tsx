// ─────────────────────────────────────────────────────────────────────────
// The framing surface of the crop window.
//
// A fixed frame drawn to the figure box's real proportions: same rounded
// corners, same border, same placeholder grey, with the image floating
// behind it. Drag to pan, wheel or the zoom control to scale. Whatever falls
// inside the frame is exactly what the figure renders; the rest is dimmed to
// show it will be clipped at the border.
//
// The frame stays put and the image moves, rather than the other way round,
// because the frame *is* the output. Sizing the on-screen frame from the
// same aspect ratio the renderer uses is what makes this WYSIWYG.
//
// In blur mode the same drag gesture draws a redaction rectangle instead of
// panning: the drag is tracked in frame space, converted to image space
// through the current crop on release, and handed back as a BlurRegion. The
// committed regions arrive already baked into `imageUrl` (the dialog renders
// them through the real pipeline), so this component only draws the in-flight
// draft and, in blur mode, an outline with a delete button per region.
//
// With `onCropResize`, the frame also carries crop handles on its edges and
// corners. Dragging one pulls that side of the frame in over the image; on
// release the part still inside becomes the new crop, at its own shape, and
// the dialog re-sizes the frame to match. Panning and zooming stay as they
// were, so a crop can be widened again by zooming out.
//
// All the gestures follow invariant #3c: a pointer can fire several hundred
// events a second, so a drag writes geometry **straight to the DOM, once per
// animation frame**, and commits to React state only on pointer-up. Re-
// rendering per event meant a style recalc and layout over two full-size
// images for every sample, most of which the browser never got to paint.
// ─────────────────────────────────────────────────────────────────────────

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { X } from 'lucide-react';
import type { BlurRegion, CropRect } from '@/types';
import { frameToImage, regionFromDrag, regionIndexAt, regionToFrame } from '@/lib/blur-math';
import {
  CROP_HANDLES,
  cropFromSelection,
  dragSelection,
  FULL_SELECTION,
  isFullSelection,
  panCrop,
  zoomCrop,
  type CropHandle,
  type FrameSelection,
} from '@/lib/crop-math';
import { getUiZoom, toLayoutPx } from '@/lib/ui-zoom';

/** Padding between the frame and the edge of its container, in px. */
const FRAME_MARGIN = 48;

/** Where each handle sits on the selection, as fractions of it, and its cursor. */
const HANDLE_PLACE: Record<CropHandle, { x: number; y: number; cursor: string }> = {
  nw: { x: 0, y: 0, cursor: 'cursor-nwse-resize' },
  n: { x: 0.5, y: 0, cursor: 'cursor-ns-resize' },
  ne: { x: 1, y: 0, cursor: 'cursor-nesw-resize' },
  e: { x: 1, y: 0.5, cursor: 'cursor-ew-resize' },
  se: { x: 1, y: 1, cursor: 'cursor-nwse-resize' },
  s: { x: 0.5, y: 1, cursor: 'cursor-ns-resize' },
  sw: { x: 0, y: 1, cursor: 'cursor-nesw-resize' },
  w: { x: 0, y: 0.5, cursor: 'cursor-ew-resize' },
};

export function FigureViewport({
  imageUrl,
  crop,
  boxAspect,
  onCropChange,
  blurMode = false,
  blurs = [],
  onAddBlur,
  onRemoveBlur,
  selectedBlur = null,
  onSelectBlur,
  onCropResize,
}: {
  imageUrl: string;
  /** Visible region of the image, in normalized image coordinates. */
  crop: CropRect;
  /** width / height of the figure box: the frame's shape. */
  boxAspect: number;
  onCropChange: (next: CropRect) => void;
  /** When true, dragging draws a blur region instead of panning. */
  blurMode?: boolean;
  /** Committed regions (already baked into `imageUrl`), for outlines/delete. */
  blurs?: BlurRegion[];
  onAddBlur?: (region: BlurRegion) => void;
  onRemoveBlur?: (index: number) => void;
  /** Highlighted region, if any; a click-sized tap (re)selects. */
  selectedBlur?: number | null;
  onSelectBlur?: (index: number | null) => void;
  /**
   * Show crop handles on the frame. Called on release with the crop that
   * shows only what is left inside the handles, at its own aspect ratio.
   */
  onCropResize?: (next: CropRect) => void;
}) {
  const hostRef = useRef<HTMLDivElement>(null);
  const [frame, setFrame] = useState({ width: 0, height: 0 });

  // The wheel listener below is bound per frame size, so it reads the crop
  // through a ref rather than rebinding on every pan.
  const cropRef = useRef(crop);
  cropRef.current = crop;

  // Size the frame to fill the available space at the box's aspect ratio.
  useLayoutEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const measure = () => {
      // The frame is a CSS size; the rect is in screen px (interface zoom).
      const rect = host.getBoundingClientRect();
      const availW = Math.max(toLayoutPx(rect.width) - FRAME_MARGIN * 2, 40);
      const availH = Math.max(toLayoutPx(rect.height) - FRAME_MARGIN * 2, 40);
      // Fit the frame inside the available box without distorting it.
      const width = Math.min(availW, availH * boxAspect);
      setFrame({ width, height: width / boxAspect });
    };
    measure();
    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(measure);
    observer.observe(host);
    return () => observer.disconnect();
  }, [boxAspect]);

  // ── image placement ────────────────────────────────────────────────────
  // The crop says which part of the image the frame shows. Inverting that
  // gives where the image sits relative to the frame: the whole image spans
  // frame.width / crop.w, offset by -crop.x of that span.
  const imageWidth = frame.width / crop.w;
  const imageHeight = frame.height / crop.h;
  const imageLeft = -crop.x * imageWidth;
  const imageTop = -crop.y * imageHeight;

  // ── panning / blur drawing ─────────────────────────────────────────────
  const dragRef = useRef<{ x: number; y: number; start: CropRect } | null>(null);

  // A blur draft, in normalized frame coordinates. The rectangle is a real
  // DOM node we position by hand: nothing here goes through React until the
  // drag commits, so a fast mouse cannot outrun the render loop.
  type Draft = { x0: number; y0: number; x1: number; y1: number };
  const blurDraftRef = useRef<Draft | null>(null);
  const draftElRef = useRef<HTMLDivElement>(null);
  const rafRef = useRef(0);
  const frameRef = useRef(frame);
  frameRef.current = frame;

  // Pan / zoom coalescing. `onCropChange` re-renders the dialog above us, so
  // a raw pointermove or wheel burst would queue far more renders than the
  // display can show. One per frame, latest value wins.
  const pendingCropRef = useRef<CropRect | null>(null);
  const cropRafRef = useRef(0);
  const onCropChangeRef = useRef(onCropChange);
  onCropChangeRef.current = onCropChange;

  const flushCrop = useCallback(() => {
    cropRafRef.current = 0;
    const next = pendingCropRef.current;
    pendingCropRef.current = null;
    if (next) onCropChangeRef.current(next);
  }, []);

  const queueCrop = useCallback((next: CropRect) => {
    pendingCropRef.current = next;
    // Keep the ref current within the burst so the next sample builds on the
    // value we are about to commit, not on a stale render's crop.
    cropRef.current = next;
    if (!cropRafRef.current) cropRafRef.current = requestAnimationFrame(flushCrop);
  }, [flushCrop]);

  /** Paint the draft rectangle from the ref. One style write per frame. */
  const paintDraft = useCallback(() => {
    rafRef.current = 0;
    const el = draftElRef.current;
    const d = blurDraftRef.current;
    if (!el) return;
    if (!d) { el.style.display = 'none'; return; }
    const { width, height } = frameRef.current;
    el.style.display = 'block';
    el.style.left = `${Math.min(d.x0, d.x1) * width}px`;
    el.style.top = `${Math.min(d.y0, d.y1) * height}px`;
    el.style.width = `${Math.abs(d.x1 - d.x0) * width}px`;
    el.style.height = `${Math.abs(d.y1 - d.y0) * height}px`;
  }, []);

  const scheduleDraft = useCallback(() => {
    if (rafRef.current) return;
    rafRef.current = requestAnimationFrame(paintDraft);
  }, [paintDraft]);

  // A drag interrupted by an unmount must not leave a frame callback holding
  // a detached node, nor a crop update that lands after teardown.
  useEffect(() => () => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    if (cropRafRef.current) cancelAnimationFrame(cropRafRef.current);
  }, []);

  const framePoint = useCallback((e: React.PointerEvent): { fx: number; fy: number } => {
    const rect = (e.currentTarget as Element).getBoundingClientRect();
    return {
      fx: rect.width > 0 ? (e.clientX - rect.left) / rect.width : 0,
      fy: rect.height > 0 ? (e.clientY - rect.top) / rect.height : 0,
    };
  }, []);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    if (blurMode) {
      const { fx, fy } = framePoint(e);
      blurDraftRef.current = { x0: fx, y0: fy, x1: fx, y1: fy };
      paintDraft();
    } else {
      dragRef.current = { x: e.clientX, y: e.clientY, start: crop };
    }
    (e.currentTarget as Element).setPointerCapture?.(e.pointerId);
  }, [crop, blurMode, framePoint, paintDraft]);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (blurMode) {
      const draft = blurDraftRef.current;
      if (!draft) return;
      const { fx, fy } = framePoint(e);
      draft.x1 = fx;
      draft.y1 = fy;
      scheduleDraft();
      return;
    }
    const drag = dragRef.current;
    if (!drag || frame.width === 0) return;
    // Screen pixels → normalized image units. Dragging right moves the image
    // right, which means the visible window moves *left* across it.
    const dx = -(toLayoutPx(e.clientX - drag.x) / frame.width) * drag.start.w;
    const dy = -(toLayoutPx(e.clientY - drag.y) / frame.height) * drag.start.h;
    // Every sample is measured from the gesture's start, so dropping the
    // intermediate ones loses nothing: the last one before the frame boundary
    // is the truth.
    queueCrop(panCrop(drag.start, dx, dy));
  }, [frame.width, frame.height, blurMode, framePoint, scheduleDraft, queueCrop]);

  const endDrag = useCallback((e: React.PointerEvent) => {
    const draft = blurDraftRef.current;
    if (draft) {
      // Frame corners → image space through the crop that framed the drag.
      const a = frameToImage(draft.x0, draft.y0, cropRef.current);
      const b = frameToImage(draft.x1, draft.y1, cropRef.current);
      const region = regionFromDrag(a.x, a.y, b.x, b.y);
      if (region) {
        onAddBlur?.(region);
      } else {
        // A click-sized tap: select the region under the pointer (or clear
        // the selection when the tap lands on none).
        const i = regionIndexAt(blurs, b.x, b.y);
        onSelectBlur?.(i === -1 ? null : i);
      }
      blurDraftRef.current = null;
      if (rafRef.current) { cancelAnimationFrame(rafRef.current); rafRef.current = 0; }
      paintDraft();
    }
    if (dragRef.current && cropRafRef.current) {
      // Land the final position now rather than a frame later.
      cancelAnimationFrame(cropRafRef.current);
      flushCrop();
    }
    dragRef.current = null;
    (e.currentTarget as Element).releasePointerCapture?.(e.pointerId);
  }, [onAddBlur, onSelectBlur, blurs, paintDraft, flushCrop]);

  // ── crop handles ───────────────────────────────────────────────────────
  // The selection box (and the handles inside it) is a real node moved by
  // hand during the drag, like the blur draft; React only hears the result.
  const selElRef = useRef<HTMLDivElement>(null);
  const frameElRef = useRef<HTMLDivElement>(null);
  const handleDragRef = useRef<{ handle: CropHandle; sel: FrameSelection } | null>(null);
  const selRafRef = useRef(0);

  const paintSelection = useCallback(() => {
    selRafRef.current = 0;
    const el = selElRef.current;
    if (!el) return;
    const sel = handleDragRef.current?.sel ?? FULL_SELECTION;
    el.style.left = `${sel.l * 100}%`;
    el.style.top = `${sel.t * 100}%`;
    el.style.width = `${(sel.r - sel.l) * 100}%`;
    el.style.height = `${(sel.b - sel.t) * 100}%`;
    el.dataset.dragging = handleDragRef.current ? 'true' : 'false';
  }, []);

  useEffect(() => () => { if (selRafRef.current) cancelAnimationFrame(selRafRef.current); }, []);

  const onHandleDown = useCallback((handle: CropHandle) => (e: React.PointerEvent) => {
    e.preventDefault();
    e.stopPropagation();
    handleDragRef.current = { handle, sel: { ...FULL_SELECTION } };
    (e.currentTarget as Element).setPointerCapture?.(e.pointerId);
  }, []);

  const onHandleMove = useCallback((e: React.PointerEvent) => {
    const drag = handleDragRef.current;
    const frameEl = frameElRef.current;
    if (!drag || !frameEl) return;
    const rect = frameEl.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;
    const fx = (e.clientX - rect.left) / rect.width;
    const fy = (e.clientY - rect.top) / rect.height;
    drag.sel = dragSelection(drag.sel, drag.handle, fx, fy);
    if (!selRafRef.current) selRafRef.current = requestAnimationFrame(paintSelection);
  }, [paintSelection]);

  const onHandleUp = useCallback((e: React.PointerEvent) => {
    const drag = handleDragRef.current;
    handleDragRef.current = null;
    (e.currentTarget as Element).releasePointerCapture?.(e.pointerId);
    if (selRafRef.current) { cancelAnimationFrame(selRafRef.current); selRafRef.current = 0; }
    paintSelection();
    if (drag && !isFullSelection(drag.sel)) onCropResize?.(cropFromSelection(cropRef.current, drag.sel));
  }, [onCropResize, paintSelection]);

  // ── wheel zoom ─────────────────────────────────────────────────────────
  // Registered natively rather than via onWheel so it can be non-passive and
  // preventDefault the page scroll.
  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = host.getBoundingClientRect();
      // Anchor on the pointer so the point under the cursor stays put. All in
      // screen px: the frame's CSS size times the interface zoom.
      const z = getUiZoom();
      const fw = frame.width * z;
      const fh = frame.height * z;
      const frameLeft = rect.left + (rect.width - fw) / 2;
      const frameTop = rect.top + (rect.height - fh) / 2;
      const anchorX = fw > 0 ? (e.clientX - frameLeft) / fw : 0.5;
      const anchorY = fh > 0 ? (e.clientY - frameTop) / fh : 0.5;
      const factor = Math.exp(e.deltaY * 0.0015);
      queueCrop(zoomCrop(cropRef.current, factor, anchorX, anchorY));
    };
    host.addEventListener('wheel', onWheel, { passive: false });
    return () => host.removeEventListener('wheel', onWheel);
  }, [frame.width, frame.height, queueCrop]);

  return (
    <div
      ref={hostRef}
      className="relative flex h-full w-full touch-none select-none items-center justify-center overflow-hidden"
    >
      {frame.width > 0 && (
        <div
          ref={frameElRef}
          className={`relative ${blurMode ? 'cursor-crosshair' : 'cursor-grab active:cursor-grabbing'}`}
          style={{ width: frame.width, height: frame.height }}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={endDrag}
          onPointerCancel={endDrag}
        >
          {/* Everything outside the frame: the image continues, dimmed, so
              you can see what you're cutting off. */}
          <img
            src={imageUrl}
            alt=""
            draggable={false}
            aria-hidden
            className="pointer-events-none absolute max-w-none opacity-25"
            style={{
              width: imageWidth,
              height: imageHeight,
              left: imageLeft,
              top: imageTop,
            }}
          />

          {/* The frame itself, clipping the image to exactly what renders. */}
          <div
            className="absolute inset-0 overflow-hidden rounded"
            style={{
              backgroundColor: '#f5f5f5',
              // Matches the helper's `stroke: 1pt + luma(180)`.
              boxShadow: 'inset 0 0 0 1px #b4b4b4, 0 0 0 9999px hsl(var(--media) / 0.45)',
            }}
          >
            <img
              src={imageUrl}
              alt=""
              draggable={false}
              className="pointer-events-none absolute max-w-none"
              style={{
                width: imageWidth,
                height: imageHeight,
                left: imageLeft,
                top: imageTop,
              }}
            />
          </div>

          {/* Rule-of-thirds guides, inside the frame only. */}
          <div className="pointer-events-none absolute inset-0 overflow-hidden rounded opacity-30">
            <div className="absolute left-1/3 top-0 h-full w-px bg-white mix-blend-difference" />
            <div className="absolute left-2/3 top-0 h-full w-px bg-white mix-blend-difference" />
            <div className="absolute left-0 top-1/3 h-px w-full bg-white mix-blend-difference" />
            <div className="absolute left-0 top-2/3 h-px w-full bg-white mix-blend-difference" />
          </div>

          {/* Committed blur regions: outline + delete, only while editing
              blurs. The blur itself is already baked into the image. */}
          {blurMode && blurs.map((region, i) => {
            const f = regionToFrame(region, crop);
            const isSelected = selectedBlur === i;
            return (
              <div
                key={i}
                className="pointer-events-none absolute z-10"
                style={{
                  left: f.left * frame.width,
                  top: f.top * frame.height,
                  width: f.width * frame.width,
                  height: f.height * frame.height,
                }}
              >
                <div
                  className={
                    isSelected
                      ? 'absolute inset-0 rounded-sm border-2 border-status-purple'
                      : 'absolute inset-0 rounded-sm border border-dashed border-white/90 mix-blend-difference'
                  }
                />
                <button
                  onClick={() => onRemoveBlur?.(i)}
                  onPointerDown={(e) => e.stopPropagation()}
                  title="Remove this blur"
                  className="pointer-events-auto absolute -right-2 -top-2 rounded-full bg-media p-0.5 text-media-foreground hover:bg-status-red"
                >
                  <X size={10} />
                </button>
              </div>
            );
          })}

          {/* The in-flight drag. Always mounted and positioned by hand (see
              the header note): mounting per drag would cost a React render on
              the first move, and a backdrop-filter here would cost a full
              backdrop re-blur on every one. The real blur lands on release. */}
          <div
            ref={draftElRef}
            aria-hidden
            className="pointer-events-none absolute z-10 hidden rounded-sm border-2 border-status-purple bg-status-purple/25"
          />

          {/* Crop handles. The box is the whole frame until a handle is
              dragged; then it shrinks with the drag and dims what will be
              cut away. */}
          {onCropResize && !blurMode && (
            <div
              ref={selElRef}
              data-dragging="false"
              className="pointer-events-none absolute left-0 top-0 z-20 h-full w-full data-[dragging=true]:border-2 data-[dragging=true]:border-primary data-[dragging=true]:shadow-[0_0_0_9999px_hsl(var(--media)/0.55)]"
            >
              {CROP_HANDLES.map((handle) => {
                const place = HANDLE_PLACE[handle];
                const corner = handle.length === 2;
                return (
                  <div
                    key={handle}
                    role="presentation"
                    data-crop-handle={handle}
                    title="Drag to crop"
                    onPointerDown={onHandleDown(handle)}
                    onPointerMove={onHandleMove}
                    onPointerUp={onHandleUp}
                    onPointerCancel={onHandleUp}
                    className={`pointer-events-auto absolute -translate-x-1/2 -translate-y-1/2 rounded-sm border-2 border-primary bg-card shadow ${place.cursor} ${
                      corner ? 'h-3.5 w-3.5' : handle === 'n' || handle === 's' ? 'h-2 w-6' : 'h-6 w-2'
                    }`}
                    style={{ left: `${place.x * 100}%`, top: `${place.y * 100}%` }}
                  />
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
